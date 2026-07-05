package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

func defaultPortsSpec() string {
	return getServerDefaultPorts()
}

func parsePortsSpec(value string) (string, error) {
	parts := strings.Split(value, ",")
	if len(parts) != 3 {
		return "", errors.New("укажите 3 порта через запятую")
	}
	cleaned := make([]string, 3)
	for i, part := range parts {
		portText := strings.TrimSpace(part)
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return "", fmt.Errorf("порт #%d должен быть числом 1..65535", i+1)
		}
		cleaned[i] = strconv.Itoa(port)
	}
	return strings.Join(cleaned, ","), nil
}

func normalizeDNSInput(input string) (string, error) {
	parts := strings.Split(input, ",")
	cleaned := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		if len(value) > 64 {
			return "", fmt.Errorf("DNS %q слишком длинный", value)
		}
		for _, r := range value {
			if !(r == '.' || r == ':' || r == '-' || r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
				return "", fmt.Errorf("DNS %q содержит недопустимые символы", value)
			}
		}
		cleaned = append(cleaned, value)
	}
	if len(cleaned) == 0 {
		return "", errors.New("DNS не должен быть пустым")
	}
	if len(cleaned) > 4 {
		return "", errors.New("укажите не больше 4 DNS через запятую")
	}
	return strings.Join(cleaned, ","), nil
}

func isValidPublicHost(value string) bool {
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/\\:@") {
		return false
	}
	if ip := net.ParseIP(value); ip != nil {
		return true
	}
	if strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || strings.Contains(value, "..") {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func normalizePublicAddressInput(input string) (string, error) {
	value := strings.TrimSpace(input)
	if value == "" || value == "-" || strings.EqualFold(value, "auto") {
		return "", nil
	}
	if !isValidPublicHost(value) {
		return "", errors.New("укажите домен или IPv4 без `http://` и без порта либо выберите автоматическое определение")
	}
	return value, nil
}

func normalizeVKHashesInput(input string) (string, error) {
	raw := strings.FieldsFunc(input, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	hashes := make([]string, 0, len(raw))
	for _, item := range raw {
		hash := stripVkUrl(item)
		if hash == "" {
			continue
		}
		if strings.Contains(hash, "/") || strings.Contains(hash, "\\") {
			return "", fmt.Errorf("не удалось выделить хеш из %q", item)
		}
		hashes = append(hashes, hash)
	}
	if len(hashes) == 0 {
		return "", errors.New("хеш не должен быть пустым")
	}
	return strings.Join(hashes, ","), nil
}

func normalizePasswordLabel(input string) string {
	label := strings.Join(strings.Fields(strings.TrimSpace(input)), " ")
	label = strings.Map(func(r rune) rune {
		switch r {
		case '`', '*', '_', '[', ']', '(', ')', '~', '>', '#', '+', '=', '|', '{', '}', '!':
			return -1
		default:
			return r
		}
	}, label)
	runes := []rune(label)
	if len(runes) > 40 {
		label = string(runes[:40])
	}
	return label
}

func createBotClient(
	wgDev *device.Device,
	requestedPassword string,
	days int,
	expiresAt int64,
	label string,
	vkHash string,
	ports string,
	deactivated bool,
) (string, *PasswordEntry, error) {
	dbMutex.Lock()
	defer dbMutex.Unlock()
	if cleanupExpiredPasswordsLocked(wgDev) > 0 {
		saveDB()
	}
	if len(db.Passwords) >= maxGeneratedPasswords {
		return "", nil, fmt.Errorf("лимит клиентов: максимум %d", maxGeneratedPasswords)
	}
	password := ""
	if strings.TrimSpace(requestedPassword) != "" {
		value, err := normalizeClientPassword(requestedPassword)
		if err != nil {
			return "", nil, err
		}
		if value == db.MainPassword {
			return "", nil, errors.New("пароль клиента не должен совпадать с главным паролем")
		}
		if _, exists := db.Passwords[value]; exists {
			return "", nil, errors.New("клиент с таким паролем уже существует")
		}
		password = value
	} else {
		for i := 0; i < 64; i++ {
			candidate := generatePassword()
			if candidate == db.MainPassword {
				continue
			}
			if _, exists := db.Passwords[candidate]; !exists {
				password = candidate
				break
			}
		}
	}
	if password == "" {
		return "", nil, errors.New("не удалось создать уникальный пароль")
	}
	if expiresAt < 0 {
		if days < 0 || days > 365 {
			return "", nil, errors.New("срок должен быть 0..365 дней")
		}
		if days > 0 {
			expiresAt = time.Now().Add(time.Duration(days) * 24 * time.Hour).Unix()
		} else {
			expiresAt = 0
		}
	} else if expiresAt > 0 && expiresAt <= time.Now().Unix() {
		return "", nil, errors.New("срок переносимого клиента уже истёк")
	}
	normalizedPorts, err := parsePortsSpec(ports)
	if err != nil {
		return "", nil, err
	}
	normalizedHash := ""
	if strings.TrimSpace(vkHash) != "" {
		normalizedHash, err = normalizeVKHashesInput(vkHash)
		if err != nil {
			return "", nil, err
		}
	}
	if !deactivated {
		if err := serverWrapKeys.AddPassword(password); err != nil {
			return "", nil, fmt.Errorf("не удалось добавить WRAP-ключ: %w", err)
		}
	}
	entry := &PasswordEntry{
		ExpiresAt:     expiresAt,
		Label:         normalizePasswordLabel(label),
		VkHash:        normalizedHash,
		Ports:         normalizedPorts,
		IsDeactivated: deactivated,
	}
	db.Passwords[password] = entry
	saveDB()
	return password, entry, nil
}

func changeBotClientPassword(wgDev *device.Device, oldPassword, requested string) (string, error) {
	newPassword, err := normalizeClientPassword(requested)
	if err != nil {
		return "", err
	}
	dbMutex.Lock()
	defer dbMutex.Unlock()
	entry, exists := db.Passwords[oldPassword]
	if !exists || entry == nil {
		return "", errors.New("клиент не найден")
	}
	if newPassword == oldPassword {
		return "", errors.New("новый пароль совпадает с текущим")
	}
	if newPassword == db.MainPassword {
		return "", errors.New("пароль клиента не должен совпадать с главным паролем")
	}
	if _, exists := db.Passwords[newPassword]; exists {
		return "", errors.New("клиент с таким паролем уже существует")
	}
	if !entry.IsDeactivated && !isPasswordExpired(entry) {
		if err := serverWrapKeys.AddPassword(newPassword); err != nil {
			return "", fmt.Errorf("не удалось добавить новый WRAP-ключ: %w", err)
		}
	}
	delete(db.Passwords, oldPassword)
	db.Passwords[newPassword] = entry
	serverWrapKeys.RemovePassword(oldPassword)
	if entry.DeviceID != "" {
		removePeerFromWG(wgDev, db.Devices[entry.DeviceID])
	}
	saveDB()
	return newPassword, nil
}

func mdCode(value string) string {
	return strings.ReplaceAll(value, "`", "'")
}

func inlineKeyboard(rows ...[]map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"inline_keyboard": rows}
}

func inlineButton(text, data string) map[string]interface{} {
	return map[string]interface{}{
		"text":          text,
		"callback_data": data,
	}
}

func inlineUrlButton(text, url string) map[string]interface{} {
	return map[string]interface{}{
		"text": text,
		"url":  url,
	}
}

type trafficTotals struct {
	Down int64
	Up   int64
}

func addTrafficTotals(a, b trafficTotals) trafficTotals {
	return trafficTotals{Down: a.Down + b.Down, Up: a.Up + b.Up}
}

func trafficSince(buckets []TrafficBucket, days int) trafficTotals {
	if days <= 0 {
		total := trafficTotals{}
		for _, bucket := range buckets {
			total.Down += bucket.DownBytes
			total.Up += bucket.UpBytes
		}
		return total
	}
	cutoff := time.Now().AddDate(0, 0, -(days - 1)).Format("2006-01-02")
	total := trafficTotals{}
	for _, bucket := range buckets {
		if bucket.Date >= cutoff {
			total.Down += bucket.DownBytes
			total.Up += bucket.UpBytes
		}
	}
	return total
}

func passwordTrafficTotals(entry *PasswordEntry, days int) trafficTotals {
	if entry == nil {
		return trafficTotals{}
	}
	if days <= 0 {
		return trafficTotals{Down: entry.DownBytes, Up: entry.UpBytes}
	}
	if len(entry.Traffic) == 0 {
		return trafficTotals{}
	}
	return trafficSince(entry.Traffic, days)
}

func adminTrafficTotals(days int) trafficTotals {
	if days <= 0 {
		return trafficTotals{Down: db.AdminDownBytes, Up: db.AdminUpBytes}
	}
	if len(db.AdminTraffic) == 0 {
		return trafficTotals{}
	}
	return trafficSince(db.AdminTraffic, days)
}

func databaseTrafficTotals(days int) trafficTotals {
	total := adminTrafficTotals(days)
	for _, entry := range db.Passwords {
		total = addTrafficTotals(total, passwordTrafficTotals(entry, days))
	}
	return total
}

func formatTrafficTotals(total trafficTotals) string {
	return fmt.Sprintf("↓%.2f MB / ↑%.2f MB", float64(total.Down)/(1024*1024), float64(total.Up)/(1024*1024))
}

func trafficPeriodReport(today, week, month, all trafficTotals) string {
	return fmt.Sprintf(
		"• Сегодня: %s\n• 7 дней: %s\n• 30 дней: %s\n• Всего: %s",
		formatTrafficTotals(today),
		formatTrafficTotals(week),
		formatTrafficTotals(month),
		formatTrafficTotals(all),
	)
}

func botShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func runBotScript(script string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", script)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if ctx.Err() == context.DeadlineExceeded {
		return text, errors.New("таймаут выполнения команды")
	}
	if marker := markerLine(text, "WDTT_ERROR"); marker != "" {
		return text, errors.New(marker)
	}
	if err != nil {
		if text != "" {
			return text, fmt.Errorf("%s", text)
		}
		return text, err
	}
	return text, nil
}

func compactBotRemoteTail(output string) string {
	lines := []string{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "WDTT_PROGRESS|") || strings.HasPrefix(line, "WDTT_ERROR=") {
			continue
		}
		lines = append(lines, line)
	}
	if len(lines) > 4 {
		lines = lines[len(lines)-4:]
	}
	text := strings.Join(lines, " ")
	if len([]rune(text)) > 260 {
		runes := []rune(text)
		text = string(runes[:260])
	}
	return text
}

func botTextWithRemoteTail(message, output string) string {
	tail := compactBotRemoteTail(output)
	if tail == "" {
		return message
	}
	return message + " Последние строки сервера: " + tail
}

func botScriptErrorText(err error, output string) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch msg {
	case "3proxy_not_installed":
		return "Не удалось установить прокси-сервер 3proxy. Проверьте доступ сервера к интернету и пакетному менеджеру."
	case "3proxy_source_no_curl":
		return "Не удалось скачать исходники 3proxy: на сервере нет curl, и пакетный менеджер не смог его поставить."
	case "3proxy_source_no_tar":
		return "Не удалось распаковать исходники 3proxy: на сервере нет tar, и пакетный менеджер не смог его поставить."
	case "3proxy_source_no_gzip":
		return "Не удалось распаковать исходники 3proxy: на сервере нет gzip, и пакетный менеджер не смог его поставить."
	case "3proxy_source_no_make":
		return "Не удалось собрать 3proxy: на сервере нет make, и пакетный менеджер не смог его поставить."
	case "3proxy_source_no_compiler":
		return "Не удалось собрать 3proxy: на сервере нет компилятора gcc/cc, и пакетный менеджер не смог его поставить."
	case "3proxy_source_no_openssl_headers":
		return "Не удалось собрать 3proxy: на сервере нет OpenSSL-заголовков. Нужен пакет libssl-dev, openssl-devel, libopenssl-devel или openssl-dev в зависимости от Linux-дистрибутива."
	case "3proxy_source_download_failed":
		return "Не удалось скачать исходники 3proxy с GitHub. Проверьте, открывается ли github.com с сервера и не блокирует ли сеть исходящие HTTPS-подключения."
	case "3proxy_source_unpack_failed":
		return "Архив 3proxy скачался, но сервер не смог его распаковать. Возможен битый архив, нехватка места или проблема с tar/gzip."
	case "3proxy_source_build_failed":
		return botTextWithRemoteTail("Исходники 3proxy скачались, но сборка на сервере не завершилась. Часто причина в отсутствующих dev-пакетах libc, нестандартной ОС или ошибке компилятора.", output)
	case "3proxy_source_binary_missing":
		return "Сборка 3proxy завершилась без явной ошибки, но готовый файл 3proxy не найден."
	case "3proxy_source_install_failed":
		return "3proxy собрался, но сервер не дал записать файл в /usr/local/bin. Проверьте root-права пользователя и sudo."
	case "3proxy_install_failed":
		return "Не удалось установить 3proxy: пакет не найден в репозиториях сервера, а сборка из исходников не дала готовый файл. Повторите установку: теперь бот покажет конкретный шаг, на котором она сорвалась."
	case "systemd_required":
		return "Для прокси на этом сервере нужна systemd-служба. На сервере не найден systemctl, поэтому бот не может безопасно запустить 3proxy как сервис."
	case "curl_not_installed":
		return "На сервере не найден curl, поэтому проверка внешнего IP не выполнилась. Установите curl или повторите действие после восстановления пакетного менеджера."
	case "external_proxy_check_failed":
		return "Внешний прокси не ответил. Проверьте тип, адрес, порт, логин и пароль."
	case "external_proxy_service_inactive":
		return "Служба перенаправления через внешний прокси не запустилась. Бот откатил правила и вернул прямой выход, чтобы интернет через VPN не остался сломанным."
	case "external_proxy_apply_failed":
		return botTextWithRemoteTail("Внешний прокси отвечает напрямую, но путь WDTT через redsocks не заработал. Бот откатил правила и вернул прямой выход, чтобы VPN-интернет не пропал.", output)
	case "iptables_required":
		return "На сервере не найдены правила межсетевого экрана iptables. Без них нельзя направить подключения WDTT через прокси."
	case "local_proxy_check_failed":
		return "Проверка не устанавливает прокси: она подключается к уже запущенному SOCKS5 на 127.0.0.1 с сохранёнными логином и паролем. Подключение не удалось. Создайте или обновите прокси."
	case "local_proxy_config_not_found":
		return "Настройки прокси на этом сервере не найдены. Сначала создайте прокси."
	case "local_proxy_credentials_missing":
		return "В настройках прокси на этом сервере нет логина или пароля. Создайте или обновите прокси из бота или приложения."
	case "local_proxy_service_inactive":
		return "Служба wdtt-3proxy не запущена. Создайте или обновите прокси на сервере."
	case "local_proxy_service_still_active":
		return "Команда остановки выполнена, но служба wdtt-3proxy всё ещё запущена. Проверьте права пользователя SSH или остановите службу вручную."
	case "redsocks_not_installed":
		return "Не удалось установить компонент перенаправления через внешний прокси. Проверьте доступ сервера к интернету и пакетному менеджеру."
	case "wdtt_iface_not_found":
		return "На сервере не найден сетевой интерфейс WDTT. Сначала запустите установленный WDTT-сервер."
	case "wdtt_test_source_missing":
		return "Интерфейс WDTT не имеет IPv4-адреса, поэтому проверить реальный путь клиентского трафика не получилось."
	case "wireguard_tools_required":
		return "На сервере не найдены инструменты WireGuard. Без них нельзя включить выход через WireGuard."
	case "warp_mode_not_active":
		return "Бесплатный WARP сейчас не выбран как активный выход. Установите или восстановите его из Android-приложения."
	case "warp_account_missing":
		return "Регистрация бесплатного WARP не найдена. Создайте её из Android-приложения с подтверждением условий Cloudflare."
	case "warp_profile_missing":
		return "WireGuard-профиль WARP не найден. Выполните восстановление из Android-приложения."
	case "warp_trace_check_failed":
		return "Cloudflare не подтвердил warp=on/plus. Возможны временный сбой endpoint или региональное ограничение WARP. Попробуйте перезапуск, затем восстановление из приложения."
	default:
		if strings.TrimSpace(output) != "" {
			return strings.TrimSpace(output)
		}
		return msg
	}
}

func isFriendlyBotScriptError(err error) bool {
	if err == nil {
		return false
	}
	switch err.Error() {
	case "3proxy_not_installed",
		"3proxy_source_no_curl",
		"3proxy_source_no_tar",
		"3proxy_source_no_gzip",
		"3proxy_source_no_make",
		"3proxy_source_no_compiler",
		"3proxy_source_no_openssl_headers",
		"3proxy_source_download_failed",
		"3proxy_source_unpack_failed",
		"3proxy_source_build_failed",
		"3proxy_source_binary_missing",
		"3proxy_source_install_failed",
		"3proxy_install_failed",
		"systemd_required",
		"curl_not_installed",
		"external_proxy_check_failed",
		"external_proxy_service_inactive",
		"external_proxy_apply_failed",
		"iptables_required",
		"local_proxy_check_failed",
		"local_proxy_config_not_found",
		"local_proxy_credentials_missing",
		"local_proxy_service_inactive",
		"local_proxy_service_still_active",
		"redsocks_not_installed",
		"wdtt_iface_not_found",
		"wdtt_test_source_missing",
		"wireguard_tools_required",
		"warp_mode_not_active",
		"warp_account_missing",
		"warp_profile_missing",
		"warp_trace_check_failed":
		return true
	default:
		return false
	}
}

func markerLine(output, name string) string {
	prefix := name + "="
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) {
			return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), prefix))
		}
	}
	return ""
}

func outboundBotPrelude() string {
	return `
set -e
WDTT_SUBNET="$(ip -4 route show dev wdtt0 scope link 2>/dev/null | awk '{print $1; exit}')"
[ -n "$WDTT_SUBNET" ] || WDTT_SUBNET="10.66.66.0/24"
WDTT_IFACE="wdtt0"
WDTT_TABLE="100"
WDTT_WG_IFACE="wg-wdtt-exit"
mkdir -p /etc/wdtt /etc/wdtt/outbound /etc/wdtt-plus/wg-exit
wdtt_ext_iface() {
  ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}'
}
wdtt_test_source() {
  ip -4 -o addr show dev "$WDTT_IFACE" scope global 2>/dev/null | awk '{split($4, value, "/"); print value[1]; exit}'
}
wdtt_install_pkg() {
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y "$@" >/dev/null
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "$@" >/dev/null
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install -y "$@" >/dev/null
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache "$@" >/dev/null
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm --needed "$@" >/dev/null
  else
    return 1
  fi
}
wdtt_install_redsocks_tools() {
  if command -v apt-get >/dev/null 2>&1; then
    wdtt_install_pkg redsocks curl iptables psmisc iproute2
  elif command -v dnf >/dev/null 2>&1; then
    wdtt_install_pkg redsocks curl iptables psmisc iproute
  elif command -v yum >/dev/null 2>&1; then
    wdtt_install_pkg redsocks curl iptables psmisc iproute
  elif command -v zypper >/dev/null 2>&1; then
    wdtt_install_pkg redsocks curl iptables psmisc iproute2
  elif command -v apk >/dev/null 2>&1; then
    wdtt_install_pkg redsocks curl iptables psmisc iproute2
  elif command -v pacman >/dev/null 2>&1; then
    wdtt_install_pkg redsocks curl iptables psmisc iproute2
  else
    return 1
  fi
}
wdtt_install_wireguard_tools() {
  if command -v apt-get >/dev/null 2>&1; then
    wdtt_install_pkg wireguard-tools curl ca-certificates iptables iproute2
  elif command -v dnf >/dev/null 2>&1; then
    wdtt_install_pkg wireguard-tools curl ca-certificates iptables iproute
  elif command -v yum >/dev/null 2>&1; then
    wdtt_install_pkg wireguard-tools curl ca-certificates iptables iproute
  elif command -v zypper >/dev/null 2>&1; then
    wdtt_install_pkg wireguard-tools curl ca-certificates iptables iproute2
  elif command -v apk >/dev/null 2>&1; then
    wdtt_install_pkg wireguard-tools curl ca-certificates iptables iproute2
  elif command -v pacman >/dev/null 2>&1; then
    wdtt_install_pkg wireguard-tools curl ca-certificates iptables iproute2
  else
    return 1
  fi
}
wdtt_clear_external_out() {
  systemctl disable --now wdtt-warp-watchdog.timer 2>/dev/null || true
  systemctl disable --now wdtt-wg-exit.service 2>/dev/null || true
  if command -v iptables >/dev/null 2>&1; then
    iptables -t nat -D PREROUTING -i "$WDTT_IFACE" -p tcp -j WDTT_PROXY_OUT 2>/dev/null || true
    iptables -t nat -F WDTT_PROXY_OUT 2>/dev/null || true
    iptables -t nat -X WDTT_PROXY_OUT 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "$WDTT_SUBNET" -o "$WDTT_WG_IFACE" -m comment --comment WDTT_EXIT -j MASQUERADE 2>/dev/null || true
  fi
  ip rule del from "$WDTT_SUBNET" table "$WDTT_TABLE" priority 100 2>/dev/null || true
  ip route flush table "$WDTT_TABLE" 2>/dev/null || true
  systemctl disable --now wdtt-redsocks 2>/dev/null || systemctl stop wdtt-redsocks 2>/dev/null || true
  wdtt_kill_redsocks_listener
  wg-quick down "$WDTT_WG_IFACE" 2>/dev/null || true
}
wdtt_kill_redsocks_listener() {
  rm -f /run/wdtt-redsocks.pid 2>/dev/null || true
  if command -v fuser >/dev/null 2>&1; then
    fuser -k 12345/tcp >/dev/null 2>&1 || true
  elif command -v ss >/dev/null 2>&1; then
    ss -ltnp 2>/dev/null | awk '/127\.0\.0\.1:12345|\*:12345/ {print}' | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | while read -r pid; do
      [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
  fi
  if command -v ss >/dev/null 2>&1 && ss -ltnp 2>/dev/null | grep -q ':12345'; then
    pkill -x redsocks 2>/dev/null || true
  fi
  systemctl reset-failed wdtt-redsocks 2>/dev/null || true
}
wdtt_proxy_reserved_returns() {
  chain="$1"
  proxy_ip="$2"
  for net in 0.0.0.0/8 10.0.0.0/8 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4; do
    iptables -t nat -A "$chain" -d "$net" -j RETURN
  done
  [ -n "$proxy_ip" ] && iptables -t nat -A "$chain" -d "$proxy_ip" -j RETURN 2>/dev/null || true
}
wdtt_cleanup_proxy_test() {
  iptables -t nat -D OUTPUT -p tcp -m owner --uid-owner 0 -j WDTT_PROXY_TEST 2>/dev/null || true
  iptables -t nat -F WDTT_PROXY_TEST 2>/dev/null || true
  iptables -t nat -X WDTT_PROXY_TEST 2>/dev/null || true
}
wdtt_test_redsocks_path() {
  proxy_ip="$1"
  systemctl is-active --quiet wdtt-redsocks || { echo WDTT_ERROR=external_proxy_service_inactive; return 1; }
  command -v curl >/dev/null 2>&1 || { echo WDTT_ERROR=curl_not_installed; return 1; }
  wdtt_cleanup_proxy_test
  iptables -t nat -N WDTT_PROXY_TEST 2>/dev/null || true
  iptables -t nat -F WDTT_PROXY_TEST
  wdtt_proxy_reserved_returns WDTT_PROXY_TEST "$proxy_ip"
  iptables -t nat -A WDTT_PROXY_TEST -p tcp -j REDIRECT --to-ports 12345
  if ! iptables -t nat -I OUTPUT -p tcp -m owner --uid-owner 0 -j WDTT_PROXY_TEST 2>/dev/null; then
    wdtt_cleanup_proxy_test
    return 0
  fi
  test_ip="$(curl -4fsS --connect-timeout 5 --max-time 18 https://api.ipify.org 2>/tmp/wdtt-redsocks-test.err || true)"
  wdtt_cleanup_proxy_test
  [ -n "$test_ip" ] || { echo WDTT_ERROR=external_proxy_apply_failed; tail -n 20 /var/log/wdtt-redsocks.log 2>/dev/null || true; cat /tmp/wdtt-redsocks-test.err 2>/dev/null || true; return 1; }
  echo "Проверка пути через внешний прокси успешна. IP через прокси: $test_ip"
  return 0
}
wdtt_write_mode() {
  mode="$1"
  detail="$2"
  cat >/etc/wdtt/outbound.json <<EOF
{
  "outboundMode": "$mode",
  "detail": "$detail",
  "wdttSubnet": "$WDTT_SUBNET",
  "interface": "$WDTT_IFACE",
  "routingTable": $WDTT_TABLE,
  "updatedAt": "$(date -Is)"
}
EOF
}
`
}

func outboundStatusScript() string {
	return outboundBotPrelude() + `
MODE="direct"
DETAIL="прямой выход через текущий сервер"
if [ -f /etc/wdtt/outbound.json ]; then
  MODE="$(grep -o '"outboundMode"[[:space:]]*:[[:space:]]*"[^"]*"' /etc/wdtt/outbound.json | sed 's/.*"outboundMode"[[:space:]]*:[[:space:]]*"//;s/".*//' | head -1)"
  DETAIL="$(grep -o '"detail"[[:space:]]*:[[:space:]]*"[^"]*"' /etc/wdtt/outbound.json | sed 's/.*"detail"[[:space:]]*:[[:space:]]*"//;s/".*//' | head -1)"
  [ -n "$MODE" ] || MODE="direct"
  [ -n "$DETAIL" ] || DETAIL="прямой выход через текущий сервер"
fi
case "$MODE" in
  direct) MODE_LABEL="прямой выход";;
  external_proxy) MODE_LABEL="внешний прокси";;
  warp_free) MODE_LABEL="бесплатный WARP";;
  imported_wg) MODE_LABEL="готовый WireGuard-файл";;
  wireguard_vps) MODE_LABEL="другой сервер через WireGuard";;
  *) MODE_LABEL="$MODE";;
esac
SERVER_IP="$(curl -4fsS --max-time 8 https://api.ipify.org 2>/dev/null || echo 'не удалось определить')"
echo "Текущий выход WDTT: $MODE_LABEL"
echo "Описание: $DETAIL"
echo "Подсеть клиентов WDTT: $WDTT_SUBNET"
echo "Интерфейс клиентов: $WDTT_IFACE"
echo "Внешний IP самого сервера: $SERVER_IP"
if systemctl is-active wdtt-3proxy >/dev/null 2>&1; then echo "Прокси на этом сервере: служба запущена"; else echo "Прокси на этом сервере: служба остановлена"; fi
EXTERNAL_ACTIVE=0
if systemctl is-active wdtt-redsocks >/dev/null 2>&1; then EXTERNAL_ACTIVE=1; echo "Внешний прокси для WDTT: включён"; else echo "Внешний прокси для WDTT: выключен"; fi
WG_ACTIVE=0
if command -v wg >/dev/null 2>&1 && wg show "$WDTT_WG_IFACE" >/dev/null 2>&1; then
  WG_ACTIVE=1
  echo "WireGuard $WDTT_WG_IFACE:"
  wg show "$WDTT_WG_IFACE" | sed -E 's/(private key: ).*/\1(скрыт)/'
else
  echo "WireGuard $WDTT_WG_IFACE: не запущен"
fi
if [ "$EXTERNAL_ACTIVE" = 1 ] && [ "$WG_ACTIVE" = 1 ]; then
  echo "Внимание: одновременно активны внешний TCP-прокси и WireGuard-выход. Верните прямой выход или выполните диагностику перед новым переключением."
fi
if [ "$MODE" = "warp_free" ]; then
  TEST_SOURCE="$(wdtt_test_source)"
  WARP_TRACE=""
  [ -n "$TEST_SOURCE" ] && WARP_TRACE="$(curl -4fsS --interface "$TEST_SOURCE" --max-time 15 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null || true)"
  WARP_STATE="$(printf '%s\n' "$WARP_TRACE" | sed -n 's/^warp=//p' | head -n 1)"
  echo "Cloudflare WARP: ${WARP_STATE:-проверка не пройдена}"
  echo "MTU WARP: $(sed -n 's/^[[:space:]]*MTU[[:space:]]*=[[:space:]]*//Ip' /etc/wireguard/wg-wdtt-exit.conf 2>/dev/null | head -n 1)"
  echo "Автопроверка WARP: $(systemctl is-active wdtt-warp-watchdog.timer 2>/dev/null || echo не запущена)"
fi
`
}

func outboundDiagnosticsScript() string {
	return outboundStatusScript() + `
echo
echo "Правила, которые выбирают выход для WDTT-пользователей:"
ROUTE_RULES="$(ip rule show | grep -E '100|wdtt|10\.66\.66' || true)"
if [ -n "$ROUTE_RULES" ]; then
  printf '%s\n' "$ROUTE_RULES"
else
  echo "Отдельных правил выбора маршрута для WDTT сейчас нет."
fi
echo
echo "Маршрутная таблица WDTT-пользователей:"
WDTT_ROUTES="$(ip route show table 100 2>/dev/null || true)"
if [ -n "$WDTT_ROUTES" ]; then
  printf '%s\n' "$WDTT_ROUTES"
else
  echo "Маршрутная таблица WDTT сейчас пуста."
fi
echo
echo "Правила перенаправления через прокси или WireGuard:"
REDIRECT_RULES="$(iptables -t nat -S 2>/dev/null | grep -E 'WDTT_PROXY_OUT|WDTT_EXIT|WDTT_LOCAL_PROXY' || true)"
if [ -n "$REDIRECT_RULES" ]; then
  printf '%s\n' "$REDIRECT_RULES"
else
  echo "Правил перенаправления WDTT через прокси или WireGuard сейчас нет."
fi
echo
echo "Служба внешнего прокси WDTT:"
systemctl status wdtt-redsocks --no-pager -l 2>/dev/null | sed -n '1,12p' || echo "Служба wdtt-redsocks не найдена или systemctl недоступен."
echo
echo "Локальный порт redsocks:"
if command -v ss >/dev/null 2>&1; then
  REDSOCKS_LISTEN="$(ss -ltnp 2>/dev/null | grep ':12345' || true)"
  if [ -n "$REDSOCKS_LISTEN" ]; then
    printf '%s\n' "$REDSOCKS_LISTEN"
    if printf '%s\n' "$REDSOCKS_LISTEN" | grep -q '127\.0\.0\.1:12345'; then
      echo "Внимание: redsocks слушает только 127.0.0.1. Для трафика WDTT из PREROUTING нужен 0.0.0.0:12345, иначе пинги могут работать, а сайты у пользователей не открываться."
    fi
  else
    echo "redsocks сейчас не слушает порт 12345."
  fi
else
  echo "Команда ss недоступна."
fi
echo
echo "Последние сообщения redsocks:"
tail -n 20 /var/log/wdtt-redsocks.log 2>/dev/null || echo "Лог redsocks пуст или недоступен."
`
}

func outboundDisableScript() string {
	return outboundBotPrelude() + `
wdtt_clear_external_out
wdtt_write_mode "direct" "прямой выход через текущий сервер"
echo "Внешний прокси или WireGuard-выход отключён. WDTT-пользователи снова идут напрямую через текущий сервер."
`
}

func sendOutboundMenu(token string, adminID int64, messageID int) int {
	out, err := runBotScript(outboundStatusScript(), 20*time.Second)
	if err != nil {
		out = "Не удалось прочитать статус: " + err.Error()
	}
	text := "🌐 *Выходной IP и прокси*\n\n" +
		"Первичная установка сложных режимов выполняется из Android-приложения. В боте можно посмотреть состояние, включить или изменить внешний прокси, управлять локальным прокси и вернуть прямой выход через текущий сервер.\n\n" +
		"`" + mdCode(limitText(out, 1300)) + "`"
	return sendOrEditTelegram(token, adminID, messageID, text, inlineKeyboard(
		[]map[string]interface{}{
			inlineButton("📊 Статус", "out_status"),
			inlineButton("🧪 Диагностика", "out_diag"),
		},
		[]map[string]interface{}{
			inlineButton("🧦 Прокси сервер", "out_local"),
			inlineButton("🌍 Внешний прокси", "out_external"),
		},
		[]map[string]interface{}{
			inlineButton("🔐 Выход WireGuard", "out_wg"),
		},
		[]map[string]interface{}{
			inlineButton("☁️ Бесплатный WARP", "out_warp"),
		},
		[]map[string]interface{}{inlineButton("↩️ Вернуть прямой выход", "out_direct")},
		[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
	))
}

func limitText(text string, max int) string {
	if len([]rune(text)) <= max {
		return text
	}
	r := []rune(text)
	return string(r[:max]) + "\n…"
}

func sendBotCommandResult(token string, adminID int64, messageID int, title, output string, back string) int {
	return sendOrEditTelegram(token, adminID, messageID,
		fmt.Sprintf("%s\n\n`%s`", title, mdCode(limitText(strings.TrimSpace(output), 2800))),
		inlineKeyboard(
			[]map[string]interface{}{inlineButton("◀️ Назад", back)},
			[]map[string]interface{}{inlineButton("◀️ Настройки", "settings")},
		),
	)
}

func sendBotScriptResult(token string, adminID int64, messageID int, title, output string, err error, back string) int {
	if err != nil {
		details := botScriptErrorText(err, output)
		text := fmt.Sprintf("❌ *%s*\n\n%s", title, mdCode(details))
		if !isFriendlyBotScriptError(err) && strings.TrimSpace(output) != "" && details != strings.TrimSpace(output) {
			text += fmt.Sprintf("\n\n`%s`", mdCode(limitText(strings.TrimSpace(output), 1800)))
		}
		return sendOrEditTelegram(token, adminID, messageID, text, inlineKeyboard(
			[]map[string]interface{}{inlineButton("◀️ Назад", back)},
			[]map[string]interface{}{inlineButton("◀️ Настройки", "settings")},
		))
	}
	return sendBotCommandResult(token, adminID, messageID, "✅ "+title, output, back)
}

func savedLocalProxyWebURL() string {
	out, err := runBotScript(`
[ -f /etc/wdtt/local-proxy.json ] || exit 0
HOST="$(grep -o '"host"[[:space:]]*:[[:space:]]*"[^"]*"' /etc/wdtt/local-proxy.json | sed 's/.*"host"[[:space:]]*:[[:space:]]*"//;s/".*//' | head -1)"
WEB_PORT="$(grep -o '"webPort"[[:space:]]*:[[:space:]]*[0-9]*' /etc/wdtt/local-proxy.json | grep -o '[0-9]*' | head -1)"
[ -n "$HOST" ] && [ -n "$WEB_PORT" ] || exit 0
printf 'http://%s:%s/' "$HOST" "$WEB_PORT"
`, 5*time.Second)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func sendLocalProxyMenu(token string, adminID int64, messageID int) int {
	webURL := savedLocalProxyWebURL()
	text := "🧦 *Прокси на этом сервере*\n\n" +
		"Бот может поставить или обновить прокси-сервер 3proxy на текущем сервере. Прокси всегда создаётся с логином и паролем, открытого доступа без пароля не будет.\n\n" +
		"По умолчанию SOCKS5 будет на порту `1080`, HTTP — на порту `1081`, веб-страница 3proxy — на порту `1082`. Кнопка «Проверить» не устанавливает прокси: она проверяет уже сохранённый SOCKS5 на этом сервере."
	rows := [][]map[string]interface{}{
		{inlineButton("✅ Создать/обновить", "out_local_install")},
		{inlineButton("🧪 Проверить", "out_local_check")},
	}
	if webURL != "" {
		rows = append(rows, []map[string]interface{}{inlineUrlButton("🌐 Открыть 3proxy", webURL)})
	}
	rows = append(rows,
		[]map[string]interface{}{
			inlineButton("⏸ Остановить", "out_local_stop"),
			inlineButton("🗑 Удалить", "out_local_remove"),
		},
		[]map[string]interface{}{inlineButton("◀️ Назад", "settings_outbound")},
	)
	return sendOrEditTelegram(token, adminID, messageID, text, inlineKeyboard(rows...))
}

func localProxyInstallScript(login, password string, port int) string {
	httpPort := port + 1
	adminPort := port + 2
	return fmt.Sprintf(`%s
PROXY_PORT=%d
HTTP_PORT=%d
ADMIN_PORT=%d
PROXY_LOGIN=%s
PROXY_PASSWORD=%s
install_pkg() {
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >/dev/null 2>&1
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y "$@" >/dev/null 2>&1
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "$@" >/dev/null 2>&1
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install -y "$@" >/dev/null 2>&1
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache "$@" >/dev/null 2>&1
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm --needed "$@" >/dev/null 2>&1
  else
    return 1
  fi
}
install_3proxy_build_deps() {
  if command -v apt-get >/dev/null 2>&1; then
    install_pkg curl ca-certificates tar gzip make gcc libc6-dev libssl-dev
  elif command -v dnf >/dev/null 2>&1; then
    install_pkg curl ca-certificates tar gzip make gcc glibc-devel openssl-devel
  elif command -v yum >/dev/null 2>&1; then
    install_pkg curl ca-certificates tar gzip make gcc glibc-devel openssl-devel
  elif command -v zypper >/dev/null 2>&1; then
    install_pkg curl ca-certificates tar gzip make gcc glibc-devel libopenssl-devel
  elif command -v apk >/dev/null 2>&1; then
    install_pkg curl ca-certificates tar gzip make gcc musl-dev linux-headers openssl-dev
  elif command -v pacman >/dev/null 2>&1; then
    install_pkg curl ca-certificates tar gzip make gcc glibc openssl
  else
    return 1
  fi
}
install_3proxy_from_source() {
  TMP_DIR="$(mktemp -d)"
  cleanup() { rm -rf "$TMP_DIR"; }
  trap cleanup EXIT
  install_3proxy_build_deps || true
  command -v curl >/dev/null 2>&1 || { echo WDTT_ERROR=3proxy_source_no_curl; exit 2; }
  command -v tar >/dev/null 2>&1 || { echo WDTT_ERROR=3proxy_source_no_tar; exit 2; }
  command -v gzip >/dev/null 2>&1 || { echo WDTT_ERROR=3proxy_source_no_gzip; exit 2; }
  command -v make >/dev/null 2>&1 || { echo WDTT_ERROR=3proxy_source_no_make; exit 2; }
  (command -v gcc >/dev/null 2>&1 || command -v cc >/dev/null 2>&1) || { echo WDTT_ERROR=3proxy_source_no_compiler; exit 2; }
  [ -f /usr/include/openssl/evp.h ] || [ -f /usr/local/include/openssl/evp.h ] || { echo WDTT_ERROR=3proxy_source_no_openssl_headers; exit 2; }
  cd "$TMP_DIR"
  curl -fsSL -o 3proxy.tar.gz https://github.com/3proxy/3proxy/archive/refs/heads/master.tar.gz || { echo WDTT_ERROR=3proxy_source_download_failed; exit 2; }
  tar -xzf 3proxy.tar.gz || { echo WDTT_ERROR=3proxy_source_unpack_failed; exit 2; }
  cd 3proxy-*
  ln -sf Makefile.Linux Makefile
  make >/tmp/wdtt-3proxy-build.log 2>&1 || { echo WDTT_ERROR=3proxy_source_build_failed; tail -n 20 /tmp/wdtt-3proxy-build.log; exit 2; }
  BUILT_BIN="$(find . -type f -name 3proxy -perm -111 | head -n1)"
  [ -n "$BUILT_BIN" ] || { echo WDTT_ERROR=3proxy_source_binary_missing; exit 2; }
  install -m 755 "$BUILT_BIN" /usr/local/bin/3proxy || { echo WDTT_ERROR=3proxy_source_install_failed; exit 2; }
}
command -v systemctl >/dev/null 2>&1 || { echo WDTT_ERROR=systemd_required; exit 2; }
install_pkg curl ca-certificates || true
install_pkg 3proxy || true
THREEPROXY_BIN="$(command -v 3proxy || true)"
if [ -z "$THREEPROXY_BIN" ]; then
  install_3proxy_from_source || true
  THREEPROXY_BIN="$(command -v 3proxy || true)"
fi
[ -n "$THREEPROXY_BIN" ] || { echo WDTT_ERROR=3proxy_install_failed; exit 2; }
cat >/etc/wdtt/3proxy.cfg <<EOF
daemon
nserver 1.1.1.1
nserver 8.8.8.8
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
auth strong
users $PROXY_LOGIN:CL:$PROXY_PASSWORD
allow $PROXY_LOGIN
socks -p$PROXY_PORT -i0.0.0.0 -e0.0.0.0
proxy -p$HTTP_PORT -i0.0.0.0 -e0.0.0.0
admin -p$ADMIN_PORT -i0.0.0.0
EOF
chmod 600 /etc/wdtt/3proxy.cfg
cat >/etc/systemd/system/wdtt-3proxy.service <<EOF
[Unit]
Description=WDTT Plus authenticated proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
ExecStart=$THREEPROXY_BIN /etc/wdtt/3proxy.cfg
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now wdtt-3proxy >/dev/null
systemctl is-active --quiet wdtt-3proxy || { echo WDTT_ERROR=local_proxy_service_inactive; exit 3; }
if command -v iptables >/dev/null 2>&1; then
  iptables -C INPUT -p tcp --dport "$PROXY_PORT" -m comment --comment WDTT_LOCAL_PROXY -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$PROXY_PORT" -m comment --comment WDTT_LOCAL_PROXY -j ACCEPT
  iptables -C INPUT -p tcp --dport "$HTTP_PORT" -m comment --comment WDTT_LOCAL_PROXY -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$HTTP_PORT" -m comment --comment WDTT_LOCAL_PROXY -j ACCEPT
  iptables -C INPUT -p tcp --dport "$ADMIN_PORT" -m comment --comment WDTT_LOCAL_PROXY -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$ADMIN_PORT" -m comment --comment WDTT_LOCAL_PROXY -j ACCEPT
fi
SERVER_IP="$(curl -4fsS --max-time 8 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
cat >/etc/wdtt/local-proxy.json <<EOF
{
  "enabled": true,
  "type": "socks5,http",
  "host": "$SERVER_IP",
  "socks5Port": $PROXY_PORT,
  "httpPort": $HTTP_PORT,
  "webPort": $ADMIN_PORT,
  "login": "$PROXY_LOGIN",
  "password": "$PROXY_PASSWORD"
}
EOF
chmod 600 /etc/wdtt/local-proxy.json
echo "Прокси на этом сервере включён и проверен."
echo "SOCKS5: socks5://$PROXY_LOGIN:$PROXY_PASSWORD@$SERVER_IP:$PROXY_PORT"
echo "HTTP: http://$PROXY_LOGIN:$PROXY_PASSWORD@$SERVER_IP:$HTTP_PORT"
echo "Веб-страница 3proxy: http://$SERVER_IP:$ADMIN_PORT/"
echo "Логин и пароль одинаковые для SOCKS5, HTTP и веб-страницы 3proxy."
`, outboundBotPrelude(), port, httpPort, adminPort, botShellQuote(login), botShellQuote(password))
}

func localProxyCheckScript() string {
	return `
[ -f /etc/wdtt/local-proxy.json ] || { echo WDTT_ERROR=local_proxy_config_not_found; exit 2; }
PROXY_PORT="$(grep -o '"socks5Port"[[:space:]]*:[[:space:]]*[0-9]*' /etc/wdtt/local-proxy.json | grep -o '[0-9]*' | head -1)"
PROXY_LOGIN="$(grep -o '"login"[[:space:]]*:[[:space:]]*"[^"]*"' /etc/wdtt/local-proxy.json | sed 's/.*"login"[[:space:]]*:[[:space:]]*"//;s/".*//' | head -1)"
PROXY_PASSWORD="$(grep -o '"password"[[:space:]]*:[[:space:]]*"[^"]*"' /etc/wdtt/local-proxy.json | sed 's/.*"password"[[:space:]]*:[[:space:]]*"//;s/".*//' | head -1)"
[ -n "$PROXY_PORT" ] && [ -n "$PROXY_LOGIN" ] && [ -n "$PROXY_PASSWORD" ] || { echo WDTT_ERROR=local_proxy_credentials_missing; exit 2; }
command -v curl >/dev/null 2>&1 || { echo WDTT_ERROR=curl_not_installed; exit 2; }
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files wdtt-3proxy.service >/dev/null 2>&1; then
  systemctl is-active --quiet wdtt-3proxy || { echo WDTT_ERROR=local_proxy_service_inactive; exit 3; }
fi
IP="$(curl --socks5-hostname "$PROXY_LOGIN:$PROXY_PASSWORD@127.0.0.1:$PROXY_PORT" -4fsS --max-time 12 https://api.ipify.org 2>/dev/null || true)"
[ -n "$IP" ] || { echo WDTT_ERROR=local_proxy_check_failed; exit 3; }
echo "Проверка успешна: SOCKS5 на 127.0.0.1:$PROXY_PORT отвечает с сохранёнными логином и паролем. Выходной IP: $IP"
`
}

func localProxyRemoveScript(remove bool) string {
	if !remove {
		return `
systemctl stop wdtt-3proxy 2>/dev/null || true
if systemctl is-active --quiet wdtt-3proxy 2>/dev/null; then
  echo WDTT_ERROR=local_proxy_service_still_active
  exit 3
fi
echo "Прокси на этом сервере остановлен. Настройки сохранены, его можно снова включить созданием или обновлением прокси."
`
	}
	return `
systemctl disable --now wdtt-3proxy 2>/dev/null || true
rm -f /etc/systemd/system/wdtt-3proxy.service /etc/wdtt/3proxy.cfg /etc/wdtt/local-proxy.json
systemctl daemon-reload 2>/dev/null || true
if command -v iptables >/dev/null 2>&1; then
  iptables -S INPUT 2>/dev/null | grep WDTT_LOCAL_PROXY | sed 's/^-A /iptables -D /' | while read -r cmd; do $cmd 2>/dev/null || true; done
fi
echo "Прокси на этом сервере удалён: служба, настройки и правила доступа к портам очищены."
`
}

func sendExternalProxyMenu(token string, adminID int64, messageID int) int {
	text := "🌍 *Внешний прокси*\n\n" +
		"Можно проверить или включить внешний прокси как выход только для WDTT-пользователей. Через этот режим перенаправляются обычные подключения; голосовой UDP-трафик может не пройти.\n\n" +
		"Формат ввода:\n`тип адрес порт логин пароль`\n\nПример с паролем:\n`socks5 proxy.example.com 1080 ivan secret123`\n\nПример без пароля:\n`http proxy.example.com 8080 - -`"
	return sendOrEditTelegram(token, adminID, messageID, text, inlineKeyboard(
		[]map[string]interface{}{inlineButton("✏️ Ввести и включить", "out_external_enable")},
		[]map[string]interface{}{inlineButton("🧪 Ввести и проверить", "out_external_check")},
		[]map[string]interface{}{inlineButton("↩️ Вернуть прямой выход", "out_direct")},
		[]map[string]interface{}{inlineButton("◀️ Назад", "settings_outbound")},
	))
}

func parseExternalProxyInput(input string) (kind, host string, port int, login, password string, err error) {
	fields := strings.Fields(input)
	if len(fields) < 3 {
		err = errors.New("укажите тип прокси, адрес и порт")
		return
	}
	kind = strings.ToLower(fields[0])
	if kind != "socks5" && kind != "http" {
		err = errors.New("тип прокси должен быть `socks5` или `http`")
		return
	}
	host = strings.TrimSpace(fields[1])
	if !isValidPublicHost(host) {
		err = errors.New("адрес прокси должен быть доменом или IPv4 без `http://`, без порта и без пути")
		return
	}
	port, err = strconv.Atoi(fields[2])
	if err != nil || port < 1 || port > 65535 {
		err = errors.New("порт должен быть числом от 1 до 65535")
		return
	}
	if len(fields) >= 4 && fields[3] != "-" {
		login = fields[3]
	}
	if len(fields) >= 5 && fields[4] != "-" {
		password = fields[4]
	}
	if (login == "") != (password == "") {
		err = errors.New("если прокси с авторизацией, укажите и логин, и пароль; если без авторизации — используйте `- -`")
		return
	}
	return
}

func proxyKindLabel(kind string) string {
	switch strings.ToLower(kind) {
	case "socks5":
		return "SOCKS5-прокси"
	case "http":
		return "HTTP-прокси"
	default:
		return "прокси"
	}
}

func externalProxyCheckScript(kind, host string, port int, login, password string) string {
	scheme := "http"
	if kind == "socks5" {
		scheme = "socks5h"
	}
	auth := ""
	if login != "" {
		auth = login + ":" + password + "@"
	}
	proxyURI := fmt.Sprintf("%s://%s%s:%d", scheme, auth, host, port)
	return fmt.Sprintf(`
command -v curl >/dev/null 2>&1 || { echo WDTT_ERROR=curl_not_installed; exit 2; }
PROXY_URI=%s
IP="$(curl --proxy "$PROXY_URI" -4fsS --max-time 15 https://api.ipify.org 2>/dev/null || true)"
[ -n "$IP" ] || { echo WDTT_ERROR=external_proxy_check_failed; exit 3; }
echo "Проверка успешна: %s отвечает, сервер смог открыть проверочный сайт через него. IP через прокси: $IP"
`, botShellQuote(proxyURI), proxyKindLabel(kind))
}

func externalProxyEnableScript(kind, host string, port int, login, password string) string {
	redsocksType := "http-connect"
	if kind == "socks5" {
		redsocksType = "socks5"
	}
	return fmt.Sprintf(`%s
PROXY_KIND=%s
REDSOCKS_TYPE=%s
PROXY_HOST=%s
PROXY_PORT=%d
PROXY_LOGIN=%s
PROXY_PASSWORD=%s
wdtt_install_redsocks_tools || true
REDSOCKS_BIN="$(command -v redsocks || true)"
[ -n "$REDSOCKS_BIN" ] || { echo WDTT_ERROR=redsocks_not_installed; exit 2; }
command -v iptables >/dev/null 2>&1 || { echo WDTT_ERROR=iptables_required; exit 2; }
[ -d /sys/class/net/"$WDTT_IFACE" ] || { echo WDTT_ERROR=wdtt_iface_not_found; exit 2; }
PROXY_IP="$(getent ahostsv4 "$PROXY_HOST" | awk '{print $1; exit}')"
[ -n "$PROXY_IP" ] || PROXY_IP="$PROXY_HOST"
wdtt_clear_external_out
cat >/etc/wdtt/redsocks.conf <<EOF
base {
  log_debug = off;
  log_info = on;
  log = "file:/var/log/wdtt-redsocks.log";
  daemon = on;
  redirector = iptables;
}
redsocks {
  local_ip = 0.0.0.0;
  local_port = 12345;
  ip = $PROXY_IP;
  port = $PROXY_PORT;
  type = $REDSOCKS_TYPE;
EOF
if [ -n "$PROXY_LOGIN" ]; then
  printf '  login = "%%s";\n' "$PROXY_LOGIN" >>/etc/wdtt/redsocks.conf
  printf '  password = "%%s";\n' "$PROXY_PASSWORD" >>/etc/wdtt/redsocks.conf
fi
cat >>/etc/wdtt/redsocks.conf <<EOF
}
EOF
chmod 600 /etc/wdtt/redsocks.conf
cat >/etc/systemd/system/wdtt-redsocks.service <<EOF
[Unit]
Description=WDTT Plus external proxy redirector
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
ExecStart=$REDSOCKS_BIN -c /etc/wdtt/redsocks.conf -p /run/wdtt-redsocks.pid
PIDFile=/run/wdtt-redsocks.pid
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now wdtt-redsocks >/dev/null
systemctl is-active --quiet wdtt-redsocks || { echo WDTT_ERROR=external_proxy_service_inactive; journalctl -u wdtt-redsocks -n 30 --no-pager 2>/dev/null || true; exit 3; }
iptables -t nat -N WDTT_PROXY_OUT 2>/dev/null || true
iptables -t nat -F WDTT_PROXY_OUT
wdtt_proxy_reserved_returns WDTT_PROXY_OUT "$PROXY_IP"
iptables -t nat -A WDTT_PROXY_OUT -p tcp -j REDIRECT --to-ports 12345
iptables -t nat -C PREROUTING -i "$WDTT_IFACE" -p tcp -j WDTT_PROXY_OUT 2>/dev/null || iptables -t nat -A PREROUTING -i "$WDTT_IFACE" -p tcp -j WDTT_PROXY_OUT
if ! wdtt_test_redsocks_path "$PROXY_IP"; then
  wdtt_clear_external_out
  wdtt_write_mode "direct" "rollback after external proxy error"
  exit 3
fi
wdtt_write_mode "external_proxy" "$PROXY_KIND://$PROXY_HOST:$PROXY_PORT"
echo "Внешний прокси включён для обычных TCP-подключений WDTT-пользователей. Голосовой UDP-трафик через него не перенаправляется."
echo "Прокси: $PROXY_KIND://$PROXY_HOST:$PROXY_PORT"
`, outboundBotPrelude(), botShellQuote(kind), botShellQuote(redsocksType), botShellQuote(host), port, botShellQuote(login), botShellQuote(password))
}

func sendFreeWarpMenu(token string, adminID int64, messageID int) int {
	text := "☁️ *Бесплатный WARP*\n\n" +
		"WARP скрывает выходной IP VPS для WDTT-пользователей без второго сервера. Регистрация и выбор MTU выполняются в Android-приложении, где администратор подтверждает условия Cloudflare.\n\n" +
		"Бот может проверить уже установленный WARP, перезапустить его или удалить регистрацию. При удалении трафик WDTT вернётся на прямой выход."
	return sendOrEditTelegram(token, adminID, messageID, text, inlineKeyboard(
		[]map[string]interface{}{inlineButton("🧪 Проверить WARP", "out_warp_check")},
		[]map[string]interface{}{inlineButton("🔄 Перезапустить и проверить", "out_warp_restart")},
		[]map[string]interface{}{inlineButton("🗑 Удалить WARP", "out_warp_delete")},
		[]map[string]interface{}{inlineButton("◀️ Назад", "settings_outbound")},
	))
}

func freeWarpCheckScript(restart bool) string {
	restartValue := "0"
	if restart {
		restartValue = "1"
	}
	return fmt.Sprintf(`%s
MODE="$(sed -n 's/.*"outboundMode"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /etc/wdtt/outbound.json 2>/dev/null | head -n 1)"
[ "$MODE" = "warp_free" ] || { echo WDTT_ERROR=warp_mode_not_active; exit 3; }
[ -f /etc/wdtt-plus/warp/wgcf-account.toml ] || { echo WDTT_ERROR=warp_account_missing; exit 3; }
[ -f /etc/wireguard/wg-wdtt-exit.conf ] || { echo WDTT_ERROR=warp_profile_missing; exit 3; }
if [ %s = 1 ]; then
  systemctl restart wdtt-wg-exit.service >/dev/null 2>&1 || { echo WDTT_ERROR=wireguard_not_active; exit 3; }
  sleep 4
fi
wg show "$WDTT_WG_IFACE" >/dev/null 2>&1 || { echo WDTT_ERROR=wireguard_not_active; exit 3; }
TEST_SOURCE="$(wdtt_test_source)"
[ -n "$TEST_SOURCE" ] || { echo WDTT_ERROR=wdtt_test_source_missing; exit 3; }
TRACE="$(curl -4fsS --interface "$TEST_SOURCE" --connect-timeout 8 --max-time 25 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null || true)"
printf '%%s\n' "$TRACE" | grep -Eq '^warp=(on|plus)$' || { echo WDTT_ERROR=warp_trace_check_failed; exit 3; }
EXIT_IP="$(curl -4fsS --interface "$TEST_SOURCE" --connect-timeout 8 --max-time 20 https://api.ipify.org 2>/dev/null || true)"
WARP_STATE="$(printf '%%s\n' "$TRACE" | sed -n 's/^warp=//p' | head -n 1)"
MTU="$(sed -n 's/^[[:space:]]*MTU[[:space:]]*=[[:space:]]*//Ip' /etc/wireguard/wg-wdtt-exit.conf | head -n 1)"
VERSION="$(cat /etc/wdtt-plus/warp/wgcf-version 2>/dev/null || echo неизвестна)"
echo "Cloudflare подтвердил warp=$WARP_STATE."
[ -n "$EXIT_IP" ] && echo "Выходной IP: $EXIT_IP"
echo "MTU: ${MTU:-не указан}"
echo "wgcf: $VERSION"
echo "Автопроверка: $(systemctl is-active wdtt-warp-watchdog.timer 2>/dev/null || echo не запущена)"
`, outboundBotPrelude(), restartValue)
}

func deleteFreeWarpScript() string {
	return outboundBotPrelude() + `
MODE="$(sed -n 's/.*"outboundMode"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /etc/wdtt/outbound.json 2>/dev/null | head -n 1)"
systemctl disable --now wdtt-warp-watchdog.timer wdtt-warp-watchdog.service 2>/dev/null || true
if [ "$MODE" = "warp_free" ]; then
  wdtt_clear_external_out
  rm -f /etc/wireguard/wg-wdtt-exit.conf /etc/wdtt-plus/wg-exit/wg-wdtt-exit.conf
  wdtt_write_mode "direct" "прямой выход"
fi
rm -rf /etc/wdtt-plus/warp
rm -f /usr/local/bin/wgcf /usr/local/bin/wgcf.previous /usr/local/lib/wdtt/warp-watchdog
rm -f /etc/systemd/system/wdtt-warp-watchdog.service /etc/systemd/system/wdtt-warp-watchdog.timer
systemctl daemon-reload 2>/dev/null || true
echo "Бесплатный WARP удалён. Если он был активен, WDTT-пользователи возвращены на прямой выход."
`
}

func sendWireGuardExitMenu(token string, adminID int64, messageID int) int {
	text := "🔐 *Выход через WireGuard*\n\n" +
		"Первичная настройка другого сервера или импорт готового WireGuard-файла, включая собственный WARP/WARP+, выполняется из Android-приложения. В боте можно посмотреть статус, отключить выход через WireGuard или удалить импортированный файл.\n\n" +
		"Отключение возвращает WDTT на прямой выход через текущий сервер и очищает только правила внешнего выхода."
	return sendOrEditTelegram(token, adminID, messageID, text, inlineKeyboard(
		[]map[string]interface{}{inlineButton("📊 Статус WireGuard", "out_wg_status")},
		[]map[string]interface{}{inlineButton("⏸ Отключить выход", "out_direct")},
		[]map[string]interface{}{inlineButton("🗑 Удалить WireGuard-файл", "out_wg_delete_import")},
		[]map[string]interface{}{inlineButton("◀️ Назад", "settings_outbound")},
	))
}

func deleteImportedWGScript() string {
	return outboundBotPrelude() + `
wdtt_clear_external_out
rm -f /etc/wdtt-plus/wg-exit/wg-wdtt-exit.conf /etc/wireguard/wg-wdtt-exit.conf
if [ -f /etc/wdtt/outbound-profile.env ]; then
  tmp_profile=/etc/wdtt/outbound-profile.env.tmp
  grep -v '^IMPORTED_WG_CONFIG_B64=' /etc/wdtt/outbound-profile.env >"$tmp_profile" 2>/dev/null || true
  chmod 600 "$tmp_profile"
  mv "$tmp_profile" /etc/wdtt/outbound-profile.env
fi
wdtt_write_mode "direct" "прямой выход через текущий сервер"
echo "Готовый WireGuard-файл и его сохранённая копия удалены, выход WDTT возвращён напрямую через текущий сервер."
`
}

func sendMainMenu(token string, adminID int64, messageID int) int {
	dbMutex.Lock()
	passwords := len(db.Passwords)
	devices := len(db.Devices)
	dnsValue := db.DNS
	defaultPorts := db.DefaultPorts
	publicIPValue := db.PublicIP
	dbMutex.Unlock()
	if dnsValue == "" {
		dnsValue = getServerDNS()
	}
	if defaultPorts == "" {
		defaultPorts = defaultPortsSpec()
	}
	if publicIPValue == "" {
		publicIPValue = "автоматически: " + getPublicIP()
	} else {
		publicIPValue = "задан вручную: " + publicIPValue
	}
	text := fmt.Sprintf(
		"🤖 *WDTT VPN Manager*\n\nПароли: %d/%d\nУстройства: %d\nDNS: `%s`\nПорты ссылок: `%s`\nАдрес сервера для ссылок: `%s`",
		passwords, maxGeneratedPasswords, devices, mdCode(dnsValue), mdCode(defaultPorts), mdCode(publicIPValue),
	)
	return sendOrEditTelegram(token, adminID, messageID, text, inlineKeyboard(
		[]map[string]interface{}{inlineButton("➕ Новый пароль", "menu_new")},
		[]map[string]interface{}{inlineButton("🔐 Управление доступами", "backlist")},
		[]map[string]interface{}{inlineButton("⚙️ Настройки сервера", "settings")},
	))
}

func sendSettingsMenu(token string, adminID int64, messageID int) int {
	dbMutex.Lock()
	dnsValue := db.DNS
	defaultPorts := db.DefaultPorts
	publicIPValue := db.PublicIP
	passwords := len(db.Passwords)
	devices := len(db.Devices)
	expired := 0
	orphanDevices := 0
	usedDevices := make(map[string]struct{})
	for _, entry := range db.Passwords {
		if entry == nil {
			continue
		}
		if isPasswordExpired(entry) {
			expired++
		}
		if entry.DeviceID != "" {
			usedDevices[entry.DeviceID] = struct{}{}
		}
	}
	for deviceID := range adminDeviceIDSet(db) {
		usedDevices[deviceID] = struct{}{}
	}
	totalTraffic := databaseTrafficTotals(0)
	for devID := range db.Devices {
		if _, ok := usedDevices[devID]; !ok {
			orphanDevices++
		}
	}
	dbMutex.Unlock()
	if dnsValue == "" {
		dnsValue = getServerDNS()
	}
	if defaultPorts == "" {
		defaultPorts = defaultPortsSpec()
	}
	publicIPLabel := publicIPValue
	if publicIPLabel == "" {
		publicIPLabel = "определён автоматически: " + getPublicIP()
	} else {
		publicIPLabel = "задан вручную: " + publicIPLabel
	}
	text := fmt.Sprintf(
		"⚙️ *Настройки сервера*\n\nDNS WG-клиентов: `%s`\nЛимит ключей: `%d`\nПорты быстрых ссылок: `%s`\nАдрес сервера для ссылок: `%s`\n\nПароли: %d/%d\nУстройства: %d\nИстёкших ключей: %d\nЗабытых устройств: %d\nТрафик всего: %.2f MB ↓ / %.2f MB ↑\n\nИзменения DNS применятся к новым конфигам клиентов. Сетевые порты самого сервера меняются через systemd/флаги и требуют перезапуска.",
		mdCode(dnsValue), maxGeneratedPasswords, mdCode(defaultPorts), mdCode(publicIPLabel),
		passwords, maxGeneratedPasswords, devices, expired, orphanDevices,
		float64(totalTraffic.Down)/(1024*1024), float64(totalTraffic.Up)/(1024*1024),
	)
	return sendOrEditTelegram(token, adminID, messageID, text, inlineKeyboard(
		[]map[string]interface{}{
			inlineButton("🌐 DNS", "settings_dns"),
			inlineButton("🔢 Лимит ключей", "settings_limit"),
		},
		[]map[string]interface{}{
			inlineButton("⚙️ Порты ссылок", "settings_ports"),
			inlineButton("📍 Адрес сервера для ссылок", "settings_ip"),
		},
		[]map[string]interface{}{
			inlineButton("👤 Профиль владельца", "settings_owner_profile"),
		},
		[]map[string]interface{}{
			inlineButton("🧹 Очистить истёкшие", "settings_cleanup_expired"),
			inlineButton("📱 Забытые устройства", "settings_cleanup_orphans"),
		},
		[]map[string]interface{}{
			inlineButton("📊 Трафик", "settings_traffic"),
			inlineButton("📊 Сбросить трафик", "settings_reset_traffic"),
		},
		[]map[string]interface{}{
			inlineButton("🌐 Выходной IP и прокси", "settings_outbound"),
		},
		[]map[string]interface{}{inlineButton("🔄 Перезапустить WDTT", "restart_server")},
		[]map[string]interface{}{inlineButton("◀️ Главное меню", "mainmenu")},
	))
}

func collectOrphanDevicesLocked() []*ClientDevice {
	usedDevices := make(map[string]struct{})
	for _, entry := range db.Passwords {
		if entry != nil && entry.DeviceID != "" {
			usedDevices[entry.DeviceID] = struct{}{}
		}
	}
	for deviceID := range adminDeviceIDSet(db) {
		usedDevices[deviceID] = struct{}{}
	}
	orphanDevices := make([]*ClientDevice, 0)
	for devID, dev := range db.Devices {
		if _, used := usedDevices[devID]; used || dev == nil {
			continue
		}
		orphanDevices = append(orphanDevices, dev)
	}
	return orphanDevices
}

func sendOrphanDevicesMenu(token string, adminID int64, messageID int) int {
	dbMutex.Lock()
	devices := collectOrphanDevicesLocked()
	dbMutex.Unlock()

	if len(devices) == 0 {
		return sendOrEditTelegram(token, adminID, messageID,
			"📱 *Забытые устройства*\n\nТаких устройств нет.\n\nЗабытое устройство — это запись в базе устройств, которая больше не привязана ни к одному паролю. Обычно появляется после удаления, истечения или отвязки ключа.",
			inlineKeyboard(
				[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
			),
		)
	}

	lines := make([]string, 0, len(devices))
	for i, dev := range devices {
		if i >= 20 {
			lines = append(lines, fmt.Sprintf("…и ещё %d", len(devices)-i))
			break
		}
		name := deviceDisplayName(dev)
		if name != "" && name != dev.DeviceID {
			lines = append(lines, fmt.Sprintf("%d. `%s` — `%s` — `%s`", i+1, mdCode(name), mdCode(dev.DeviceID), mdCode(dev.IP)))
		} else {
			lines = append(lines, fmt.Sprintf("%d. `%s` — `%s`", i+1, mdCode(dev.DeviceID), mdCode(dev.IP)))
		}
	}
	text := fmt.Sprintf(
		"📱 *Забытые устройства: %d*\n\n%s\n\nЭто устройства из базы `devices`, которые не привязаны ни к одному текущему паролю. Если удалить их, при следующем подключении клиент получит новое устройство/IP.",
		len(devices), strings.Join(lines, "\n"),
	)
	return sendOrEditTelegram(token, adminID, messageID, text, inlineKeyboard(
		[]map[string]interface{}{inlineButton("🗑 Удалить все забытые", "confirm_cleanup_orphans")},
		[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
	))
}

func sendExpiredPasswordsMenu(token string, adminID int64, messageID int) int {
	dbMutex.Lock()
	expired := make([]string, 0)
	for pass, entry := range db.Passwords {
		if entry != nil && isPasswordExpired(entry) {
			label := entry.Label
			if label == "" {
				label = "без имени"
			}
			expired = append(expired, fmt.Sprintf("`%s` — `%s`", mdCode(label), mdCode(pass)))
		}
	}
	dbMutex.Unlock()

	if len(expired) == 0 {
		return sendOrEditTelegram(token, adminID, messageID,
			"🧹 *Истёкшие ключи*\n\nИстёкших ключей нет.",
			inlineKeyboard(
				[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
			),
		)
	}

	lines := expired
	if len(lines) > 20 {
		lines = append(lines[:20], fmt.Sprintf("…и ещё %d", len(lines)-20))
	}
	text := fmt.Sprintf("🧹 *Истёкшие ключи: %d*\n\n%s\n\nУдалить эти ключи и связанные с ними устройства?", len(expired), strings.Join(lines, "\n"))
	return sendOrEditTelegram(token, adminID, messageID, text, inlineKeyboard(
		[]map[string]interface{}{inlineButton("🗑 Удалить истёкшие", "confirm_cleanup_expired")},
		[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
	))
}

func sendDNSSettingsMenu(token string, adminID int64, messageID int) int {
	dbMutex.Lock()
	dnsValue := db.DNS
	dbMutex.Unlock()
	if dnsValue == "" {
		dnsValue = getServerDNS()
	}
	text := fmt.Sprintf(
		"🌐 *DNS WireGuard-клиентов*\n\nТекущее значение: `%s`\n\nЭтот DNS попадёт в новые WireGuard-конфиги, которые клиенты получают при подключении. Уже выданный конфиг на телефоне обновится после переподключения/перезапуска туннеля.",
		mdCode(dnsValue),
	)
	return sendOrEditTelegram(token, adminID, messageID, text, inlineKeyboard(
		[]map[string]interface{}{inlineButton("✏️ Изменить DNS", "settings_dns_edit")},
		[]map[string]interface{}{inlineButton("Поставить 1.1.1.1", "set_dns_1.1.1.1")},
		[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
	))
}

func sendLimitSettingsMenu(token string, adminID int64, messageID int) int {
	dbMutex.Lock()
	passwords := len(db.Passwords)
	dbMutex.Unlock()
	text := fmt.Sprintf(
		"🔢 *Лимит ключей*\n\nТекущий лимит: `%d`\nСейчас ключей: `%d`\n\nЛимит ограничивает создание новых временных ключей через бота. Уже созданные ключи не удаляются, даже если поставить лимит ниже текущего количества.",
		maxGeneratedPasswords, passwords,
	)
	return sendOrEditTelegram(token, adminID, messageID, text, inlineKeyboard(
		[]map[string]interface{}{inlineButton("✏️ Ввести лимит", "settings_limit_edit")},
		[]map[string]interface{}{
			inlineButton("50", "set_limit_50"),
			inlineButton("100", "set_limit_100"),
		},
		[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
	))
}

func sendDefaultPortsSettingsMenu(token string, adminID int64, messageID int) int {
	dbMutex.Lock()
	ports := db.DefaultPorts
	dbMutex.Unlock()
	if ports == "" {
		ports = defaultPortsSpec()
	}
	text := fmt.Sprintf(
		"⚙️ *Порты быстрых ссылок*\n\nТекущее значение: `%s`\n\nЭти порты используются только при генерации новых быстрых ссылок `wdtt://...`. Они не меняют реальные порты запущенного сервера. Реальные DTLS/WG-порты меняются через systemd/флаги и требуют перезапуска сервиса.",
		mdCode(ports),
	)
	return sendOrEditTelegram(token, adminID, messageID, text, inlineKeyboard(
		[]map[string]interface{}{inlineButton("✏️ Изменить порты ссылок", "settings_ports_edit")},
		[]map[string]interface{}{inlineButton("56000,56001,9000", "set_default_ports_56000,56001,9000")},
		[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
	))
}

func sendOwnerProfileMenu(token string, adminID int64, messageID int) int {
	dbMutex.Lock()
	profile := normalizeAdminProfileForView(db.AdminProfile, db.DefaultPorts)
	dbMutex.Unlock()

	text := fmt.Sprintf(
		"👤 *Профиль владельца*\n\nЭтот профиль принадлежит главному паролю и хранится отдельно от клиентов. Он не виден в списке доступов, не занимает лимит клиентов и используется для восстановления полей владельца в Android-приложении.\n\nVK-хеши: `%s`\nРезервный VK-хеш: `%s`\nНазвание профиля: `%s`\nПорты ссылки: `%s`\nПотоки на хеш: `%d`\nПротокол: `%s`\nSNI: `%s`\nNo DNS: `%s`\nОбновлён: `%s`",
		mdCode(ownerSecretPresenceLabel(profile.VkHashes)),
		mdCode(ownerSecretPresenceLabel(profile.SecondaryVkHash)),
		mdCode(emptyLabel(profile.ProfileName, "стандартное")),
		mdCode(profile.Ports),
		profile.WorkersPerHash,
		mdCode(profile.Protocol),
		mdCode(emptyLabel(profile.SNI, "не задан")),
		mdCode(boolOnOff(profile.NoDNS)),
		mdCode(formatOwnerUpdatedAt(profile.UpdatedAt)),
	)
	rows := [][]map[string]interface{}{
		{inlineButton("🔗 Ссылка владельца", "owner_link")},
		{inlineButton("🔑 Обновить VK-хеши", "owner_hash_edit")},
		{inlineButton("⚙️ Порты владельца", "owner_ports_edit")},
	}
	if strings.TrimSpace(profile.VkHashes) != "" || strings.TrimSpace(profile.SecondaryVkHash) != "" {
		rows = append(rows, []map[string]interface{}{inlineButton("🧹 Очистить VK-хеши", "owner_hash_clear")})
	}
	rows = append(rows, []map[string]interface{}{inlineButton("◀️ Назад", "settings")})
	return sendOrEditTelegram(token, adminID, messageID, text, inlineKeyboard(rows...))
}

func ownerSecretPresenceLabel(value string) string {
	count := 0
	for _, item := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t'
	}) {
		if strings.TrimSpace(item) != "" {
			count++
		}
	}
	if count == 0 {
		return "не заданы"
	}
	return fmt.Sprintf("заданы (%d)", count)
}

func emptyLabel(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func boolOnOff(value bool) string {
	if value {
		return "включено"
	}
	return "выключено"
}

func formatOwnerUpdatedAt(ts int64) string {
	if ts <= 0 {
		return "неизвестно"
	}
	return time.Unix(ts, 0).Format("02.01.2006 15:04")
}

func ownerProfileLink() (string, error) {
	dbMutex.Lock()
	profile := normalizeAdminProfileForView(db.AdminProfile, db.DefaultPorts)
	mainPassword := db.MainPassword
	publicHost := db.PublicIP
	dbMutex.Unlock()
	if strings.TrimSpace(profile.VkHashes) == "" {
		return "", errors.New("в профиле владельца не задан VK-хеш")
	}
	if strings.TrimSpace(mainPassword) == "" {
		return "", errors.New("главный пароль не задан")
	}
	if strings.TrimSpace(publicHost) == "" {
		publicHost = getPublicIP()
	}
	pts := strings.Split(profile.Ports, ",")
	if len(pts) != 3 {
		return "", errors.New("порты владельца повреждены")
	}
	return fmt.Sprintf("wdtt://%s:%s:%s:%s:%s:%s", publicHost, pts[0], pts[1], pts[2], mainPassword, profile.VkHashes), nil
}

func sendPublicIPSettingsMenu(token string, adminID int64, messageID int) int {
	dbMutex.Lock()
	ip := db.PublicIP
	dbMutex.Unlock()
	label := ip
	if label == "" {
		label = "определён автоматически: " + getPublicIP()
	} else {
		label = "задан вручную: " + label
	}
	text := fmt.Sprintf(
		"📍 *Адрес сервера для ссылок*\n\nТекущее значение: `%s`\n\nЭтот адрес добавляется в новые `wdtt://` ссылки. Можно задать домен или IP вручную либо разрешить серверу автоматически определять свой публичный IP. Для бесшовного переезда лучше использовать домен: при смене сервера достаточно обновить DNS-запись.",
		mdCode(label),
	)
	modeButton := inlineButton("🔎 Определять автоматически", "set_public_ip_auto")
	if ip == "" {
		modeButton = inlineButton("🔎 Проверить текущий IP", "settings_refresh_ip")
	}
	return sendOrEditTelegram(token, adminID, messageID, text, inlineKeyboard(
		[]map[string]interface{}{inlineButton("✏️ Ввести адрес", "settings_ip_edit")},
		[]map[string]interface{}{modeButton},
		[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
	))
}

func sendRefreshIPMenu(token string, adminID int64, messageID int) int {
	dbMutex.Lock()
	manualIP := db.PublicIP
	dbMutex.Unlock()
	current := getPublicIP()
	mode := "автоматическое определение"
	if manualIP != "" {
		mode = "задан вручную"
	}
	text := fmt.Sprintf(
		"🔎 *Определить публичный IP заново*\n\nСейчас определён IP: `%s`\nРежим адреса для ссылок: `%s`\n\nСервер повторно запросит свой публичный IP. Если домен или IP задан вручную, он останется приоритетным.",
		mdCode(current), mdCode(mode),
	)
	return sendOrEditTelegram(token, adminID, messageID, text, inlineKeyboard(
		[]map[string]interface{}{inlineButton("🔎 Определить IP", "confirm_refresh_ip")},
		[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
	))
}

func sendResetTrafficMenu(token string, adminID int64, messageID int) int {
	dbMutex.Lock()
	passwords := len(db.Passwords)
	total := databaseTrafficTotals(0)
	dbMutex.Unlock()
	text := fmt.Sprintf(
		"📊 *Сбросить статистику трафика*\n\nКлючей: `%d`\nСейчас учтено: %s\n\nЭто обнулит только счётчики в базе WDTT. Сами ключи, устройства и WireGuard-пиры не удаляются.",
		passwords, formatTrafficTotals(total),
	)
	return sendOrEditTelegram(token, adminID, messageID, text, inlineKeyboard(
		[]map[string]interface{}{inlineButton("📊 Сбросить счётчики", "confirm_reset_traffic")},
		[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
	))
}

func sendTrafficMenu(token string, adminID int64, messageID int) int {
	dbMutex.Lock()
	totalToday := databaseTrafficTotals(1)
	totalWeek := databaseTrafficTotals(7)
	totalMonth := databaseTrafficTotals(30)
	totalAll := databaseTrafficTotals(0)
	adminToday := adminTrafficTotals(1)
	adminWeek := adminTrafficTotals(7)
	adminMonth := adminTrafficTotals(30)
	adminAll := adminTrafficTotals(0)
	clientCount := len(db.Passwords)
	dbMutex.Unlock()

	text := "📊 *Трафик сервера*\n\n"
	text += "*Все клиенты вместе:*\n" + trafficPeriodReport(totalToday, totalWeek, totalMonth, totalAll)
	text += "\n\n*Администратор:*\n" + trafficPeriodReport(adminToday, adminWeek, adminMonth, adminAll)
	text += fmt.Sprintf("\n\nКлиентских паролей: `%d`\nПодробности по каждому клиенту доступны в карточке пароля.", clientCount)

	return sendOrEditTelegram(token, adminID, messageID, text, inlineKeyboard(
		[]map[string]interface{}{inlineButton("🔐 К доступам", "backlist")},
		[]map[string]interface{}{inlineButton("📊 Сбросить трафик", "settings_reset_traffic")},
		[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
	))
}

func sendRestartServerMenu(token string, adminID int64, messageID int) int {
	return sendOrEditTelegram(token, adminID, messageID,
		"🔄 *Перезапуск сервера*\n\nКоманда выполнит `systemctl restart wdtt`.\n\nТекущие подключения оборвутся и клиенты переподключатся заново. Используйте после обновления бинарника или изменения systemd-флагов.",
		inlineKeyboard(
			[]map[string]interface{}{inlineButton("🔄 Перезапустить", "confirm_restart_server")},
			[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
		),
	)
}

func formatUnixTime(ts int64) string {
	if ts <= 0 {
		return "неизвестно"
	}
	return time.Unix(ts, 0).Format("02.01.2006 15:04")
}

func deviceSummary(dev *ClientDevice) string {
	if dev == nil {
		return ""
	}
	lines := []string{
		fmt.Sprintf("• ID: `%s`", mdCode(dev.DeviceID)),
		fmt.Sprintf("• WG IP: `%s`", mdCode(dev.IP)),
	}
	if name := deviceDisplayName(dev); name != "" && name != dev.DeviceID {
		lines = append(lines, fmt.Sprintf("• Название: `%s`", mdCode(name)))
	}
	if dev.Manufacturer != "" || dev.Model != "" {
		model := strings.TrimSpace(strings.Join([]string{dev.Manufacturer, dev.Model}, " "))
		lines = append(lines, fmt.Sprintf("• Модель: `%s`", mdCode(model)))
	}
	if dev.AndroidVersion != "" || dev.SDK > 0 {
		android := dev.AndroidVersion
		if dev.SDK > 0 {
			android = fmt.Sprintf("%s (SDK %d)", android, dev.SDK)
		}
		lines = append(lines, fmt.Sprintf("• Android: `%s`", mdCode(strings.TrimSpace(android))))
	}
	if dev.Country != "" || dev.Locale != "" {
		regionParts := []string{}
		if dev.Country != "" {
			regionParts = append(regionParts, dev.Country)
		}
		if dev.Locale != "" {
			regionParts = append(regionParts, dev.Locale)
		}
		region := strings.Join(regionParts, " / ")
		lines = append(lines, fmt.Sprintf("• Регион: `%s`", mdCode(region)))
	}
	if dev.RemoteIP != "" {
		lines = append(lines, fmt.Sprintf("• Внешний IP: `%s`", mdCode(dev.RemoteIP)))
	}
	if dev.LastSeenAt > 0 {
		lines = append(lines, fmt.Sprintf("• Последний GETCONF: `%s`", mdCode(formatUnixTime(dev.LastSeenAt))))
	}
	return strings.Join(lines, "\n")
}

func compactDeviceSummary(entry *PasswordEntry, dev *ClientDevice) string {
	if entry == nil || entry.DeviceID == "" {
		return "_Ожидает первого подключения..._\n"
	}
	name := entry.DeviceID
	lastSeenAt := int64(0)
	if dev != nil {
		if display := deviceDisplayName(dev); display != "" {
			name = display
		}
		lastSeenAt = dev.LastSeenAt
	}
	mismatchCount := 0
	for _, h := range entry.BindHistory {
		if h.Status == "denied_mismatch" {
			mismatchCount++
		}
	}
	lines := []string{
		fmt.Sprintf("• Активное: `%s`", mdCode(name)),
		fmt.Sprintf("• ID: `%s`", mdCode(entry.DeviceID)),
	}
	if lastSeenAt > 0 {
		lines = append(lines, fmt.Sprintf("• Последний GETCONF: `%s`", mdCode(formatUnixTime(lastSeenAt))))
	}
	if mismatchCount > 0 {
		lines = append(lines, fmt.Sprintf("• Попыток с других устройств: `%d`", mismatchCount))
	}
	return strings.Join(lines, "\n") + "\n"
}

func sendDeviceDetailsMenu(token string, adminID int64, messageID int, pass string) int {
	dbMutex.Lock()
	entry, exists := db.Passwords[pass]
	if !exists || entry == nil {
		dbMutex.Unlock()
		return sendOrEditTelegram(token, adminID, messageID, "❌ Пароль не найден", inlineKeyboard(
			[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
		))
	}
	deviceID := entry.DeviceID
	dev := db.Devices[deviceID]
	dbMutex.Unlock()

	if deviceID == "" || dev == nil {
		return sendOrEditTelegram(token, adminID, messageID,
			fmt.Sprintf("📱 *Устройство для `%s`*\n\nАктивного устройства нет.", mdCode(pass)),
			inlineKeyboard(
				[]map[string]interface{}{inlineButton("◀️ Назад", "viewpass_"+pass)},
				[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
			),
		)
	}
	text := fmt.Sprintf("📱 *Устройство для `%s`*\n\n%s", mdCode(pass), deviceSummary(dev))
	return sendOrEditTelegram(token, adminID, messageID, text, inlineKeyboard(
		[]map[string]interface{}{inlineButton("🕓 История устройств", "bindhist_"+pass)},
		[]map[string]interface{}{inlineButton("◀️ Назад", "viewpass_"+pass)},
		[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
	))
}

func bindStatusLabel(status string) string {
	switch status {
	case "active":
		return "активно"
	case "unbound":
		return "отвязано"
	case "denied_mismatch":
		return "отказано: другое устройство"
	default:
		return status
	}
}

func sendBindHistoryMenu(token string, adminID int64, messageID int, pass string) int {
	dbMutex.Lock()
	entry, exists := db.Passwords[pass]
	if !exists || entry == nil {
		dbMutex.Unlock()
		return sendOrEditTelegram(token, adminID, messageID, "❌ Пароль не найден", inlineKeyboard(
			[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
		))
	}
	activeDeviceID := entry.DeviceID
	history := append([]BindHistoryEntry(nil), entry.BindHistory...)
	dbMutex.Unlock()

	text := fmt.Sprintf("🕓 *История устройств для `%s`*\n\n", mdCode(pass))
	if activeDeviceID != "" {
		text += fmt.Sprintf("Активное устройство сейчас: `%s`\n\n", mdCode(activeDeviceID))
	} else {
		text += "Активного устройства сейчас нет.\n\n"
	}
	if len(history) == 0 {
		text += "_Истории пока нет. Она появится после подключения APK с новой версией клиента._"
	} else {
		start := 0
		if len(history) > 15 {
			start = len(history) - 15
			text += fmt.Sprintf("_Показаны последние 15 из %d событий._\n\n", len(history))
		}
		for i := len(history) - 1; i >= start; i-- {
			h := history[i]
			eventTime := h.EventAt
			if eventTime == 0 {
				eventTime = h.BoundAt
			}
			activeMark := ""
			if h.DeviceID == activeDeviceID && h.Status == "active" && h.UnboundAt == 0 {
				activeMark = " · сейчас активно"
			}
			text += fmt.Sprintf(
				"*%s%s*\n• Когда: `%s`\n• Устройство: `%s`\n",
				bindStatusLabel(h.Status), activeMark, mdCode(formatUnixTime(eventTime)), mdCode(h.DeviceID),
			)
			if h.DeviceName != "" {
				text += fmt.Sprintf("• Название: `%s`\n", mdCode(h.DeviceName))
			}
			if h.DeviceIP != "" {
				text += fmt.Sprintf("• WG IP: `%s`\n", mdCode(h.DeviceIP))
			}
			if h.RemoteIP != "" {
				text += fmt.Sprintf("• Внешний IP: `%s`\n", mdCode(h.RemoteIP))
			}
			if h.Country != "" {
				text += fmt.Sprintf("• Страна/регион: `%s`\n", mdCode(h.Country))
			}
			if h.UnboundAt > 0 {
				text += fmt.Sprintf("• Отвязано: `%s`\n", mdCode(formatUnixTime(h.UnboundAt)))
			}
			if h.Note != "" {
				text += fmt.Sprintf("• Примечание: `%s`\n", mdCode(h.Note))
			}
			text += "\n"
		}
	}
	return sendOrEditTelegram(token, adminID, messageID, text, inlineKeyboard(
		[]map[string]interface{}{inlineButton("◀️ Назад", "viewpass_"+pass)},
		[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
	))
}

func showNewPasswordDaysMenu(token string, adminID int64, messageID int) int {
	return sendOrEditTelegram(token, adminID, messageID,
		"📅 Выберите срок действия нового пароля:",
		inlineKeyboard(
			[]map[string]interface{}{
				inlineButton("7 дней", "new_days_7"),
				inlineButton("30 дней", "new_days_30"),
			},
			[]map[string]interface{}{
				inlineButton("90 дней", "new_days_90"),
				inlineButton("365 дней", "new_days_365"),
			},
			[]map[string]interface{}{
				inlineButton("∞ Бессрочно", "new_days_0"),
				inlineButton("Ввести вручную", "new_days_custom"),
			},
			[]map[string]interface{}{inlineButton("◀️ Назад", "mainmenu")},
		),
	)
}

func showPortsMenu(token string, adminID int64, messageID int, mainPassword bool) int {
	label := "⚙️ Использовать стандартные порты (56000, 56001, 9000)?"
	if mainPassword {
		label = "⚙️ Использовать стандартные порты для главного пароля (56000, 56001, 9000)?"
	}
	return sendOrEditTelegram(token, adminID, messageID, label, inlineKeyboard(
		[]map[string]interface{}{
			inlineButton("Да", "ports_def"),
			inlineButton("Указать свои", "ports_custom"),
		},
		[]map[string]interface{}{inlineButton("◀️ Назад", "mainmenu")},
	))
}

func showNewClientPasswordMode(token string, adminID int64, messageID int) int {
	return sendOrEditTelegram(token, adminID, messageID,
		"🔐 *Пароль клиента*\n\nАвтоматический пароль безопаснее. Ручной режим нужен, например, чтобы перенести существующего клиента с другого сервера.",
		inlineKeyboard(
			[]map[string]interface{}{inlineButton("🎲 Создать автоматически", "new_password_auto")},
			[]map[string]interface{}{inlineButton("⌨️ Задать вручную", "new_password_manual")},
			[]map[string]interface{}{inlineButton("◀️ Отмена", "mainmenu")},
		),
	)
}

func sendBotClientCreated(token string, adminID int64, messageID int, password string, entry *PasswordEntry, imported bool) int {
	title := "✅ *Клиент создан*"
	if imported {
		title = "✅ *Клиент импортирован без перезапуска сервера*"
	}
	ttlText := "⏰ Бессрочный доступ"
	if entry.ExpiresAt > 0 {
		ttlText = fmt.Sprintf("⏰ Действует до %s", time.Unix(entry.ExpiresAt, 0).Format("02.01.2006"))
	}
	statusText := "📱 Ожидает первого подключения"
	if entry.IsDeactivated {
		statusText = "⏸ Доступ импортирован отключённым"
	}
	labelText := ""
	if entry.Label != "" {
		labelText = fmt.Sprintf("🏷 %s\n", mdCode(entry.Label))
	}
	linkText := ""
	if entry.VkHash != "" {
		pts := strings.Split(entry.Ports, ",")
		if len(pts) == 3 {
			link := fmt.Sprintf("wdtt://%s:%s:%s:%s:%s:%s", getPublicIP(), pts[0], pts[1], pts[2], password, entry.VkHash)
			linkText = fmt.Sprintf("\n\n🔗 *Быстрая ссылка:* `%s`", mdCode(link))
		}
	}
	return sendOrEditTelegram(token, adminID, messageID,
		fmt.Sprintf("%s\n\n🔑 Пароль: `%s`\n%s%s\n%s%s", title, mdCode(password), labelText, ttlText, statusText, linkText),
		inlineKeyboard(
			[]map[string]interface{}{inlineButton("🔍 Открыть клиента", "viewpass_"+password)},
			[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
			[]map[string]interface{}{inlineButton("◀️ Главное меню", "mainmenu")},
		),
	)
}

func showBotClientImportPreview(token string, adminID int64, messageID int, payload clientTransferPayload) int {
	label := payload.Label
	if label == "" {
		label = "Без имени"
	}
	status := "активен"
	if payload.Deactivated {
		status = "отключён"
	}
	expires := "бессрочно"
	if payload.ExpiresAt > 0 {
		expires = time.Unix(payload.ExpiresAt, 0).Format("02.01.2006 15:04")
	}
	return sendOrEditTelegram(token, adminID, messageID,
		fmt.Sprintf(
			"📥 *Проверка импорта клиента*\n\nНазвание: `%s`\nПароль: `%s`\nСрок: `%s`\nСостояние: `%s`\nVK-хеши: `%s`\nПорты нового сервера: `%s`\n\nУстройство, WireGuard-ключи, трафик, история, адрес и старые порты не переносятся. Клиент будет добавлен наживую без перезапуска; старый сервер не изменится.",
			mdCode(label), mdCode(maskPassword(payload.Password)), mdCode(expires), mdCode(status),
			map[bool]string{true: "заданы", false: "не заданы"}[payload.VkHash != ""], mdCode(defaultPortsSpec()),
		),
		inlineKeyboard(
			[]map[string]interface{}{inlineButton("📥 Импортировать", "confirm_import_client")},
			[]map[string]interface{}{inlineButton("Отмена", "backlist")},
		),
	)
}

func showLabelMenu(token string, adminID int64, messageID int) int {
	return sendOrEditTelegram(token, adminID, messageID,
		"🏷 Название ключа\n\nМожно оставить без имени или ввести короткое название, например `Дом`, `Друг`, `Ноутбук`.",
		inlineKeyboard(
			[]map[string]interface{}{inlineButton("Без имени", "label_skip")},
			[]map[string]interface{}{inlineButton("Ввести название", "label_custom")},
			[]map[string]interface{}{inlineButton("◀️ Назад", "mainmenu")},
		),
	)
}

func showPasswordEditMenu(token string, adminID int64, messageID int, pass string) int {
	dbMutex.Lock()
	entry, exists := db.Passwords[pass]
	dbMutex.Unlock()
	if !exists || entry == nil {
		return sendOrEditTelegram(token, adminID, messageID, "❌ Пароль не найден", inlineKeyboard(
			[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
		))
	}

	label := entry.Label
	if label == "" {
		label = "без имени"
	}
	ports := entry.Ports
	if ports == "" {
		ports = defaultPortsSpec()
	}
	hash := entry.VkHash
	if hash == "" {
		hash = "не задан"
	}
	ttl := "бессрочно"
	if entry.ExpiresAt > 0 {
		ttl = time.Unix(entry.ExpiresAt, 0).Format("02.01.2006")
	}

	text := fmt.Sprintf(
		"✏️ *Редактирование ключа*\n\nПароль: `%s`\nНазвание: `%s`\nСрок: `%s`\nПорты: `%s`\nVK: `%s`",
		mdCode(pass), mdCode(label), mdCode(ttl), mdCode(ports), mdCode(hash),
	)
	return sendOrEditTelegram(token, adminID, messageID, text, inlineKeyboard(
		[]map[string]interface{}{inlineButton("🔐 Пароль", "edit_password_"+pass)},
		[]map[string]interface{}{inlineButton("🏷 Название", "edit_label_"+pass)},
		[]map[string]interface{}{inlineButton("⏰ Срок действия", "edit_exp_"+pass)},
		[]map[string]interface{}{inlineButton("🔑 VK-хеш/ссылка", "edit_hash_"+pass)},
		[]map[string]interface{}{inlineButton("⚙️ Порты ссылки", "edit_ports_"+pass)},
		[]map[string]interface{}{inlineButton("◀️ Назад", "viewpass_"+pass)},
	))
}

func showEditExpiryMenu(token string, adminID int64, messageID int, pass string) int {
	return sendOrEditTelegram(token, adminID, messageID,
		fmt.Sprintf("⏰ Новый срок действия для `%s`:", mdCode(pass)),
		inlineKeyboard(
			[]map[string]interface{}{
				inlineButton("+7 дней", "set_exp_7_"+pass),
				inlineButton("+30 дней", "set_exp_30_"+pass),
			},
			[]map[string]interface{}{
				inlineButton("+90 дней", "set_exp_90_"+pass),
				inlineButton("+365 дней", "set_exp_365_"+pass),
			},
			[]map[string]interface{}{
				inlineButton("∞ Бессрочно", "set_exp_0_"+pass),
				inlineButton("Ввести вручную", "edit_exp_custom_"+pass),
			},
			[]map[string]interface{}{inlineButton("◀️ Назад", "editpass_"+pass)},
		),
	)
}

func startNewPasswordFlow(token string, adminID int64, wgDev *device.Device, waitingForDays *bool, messageID int) int {
	dbMutex.Lock()
	if cleanupExpiredPasswordsLocked(wgDev) > 0 {
		saveDB()
	}
	limitReached := len(db.Passwords) >= maxGeneratedPasswords
	dbMutex.Unlock()
	if limitReached {
		return sendOrEditTelegram(token, adminID, messageID, fmt.Sprintf("❌ Лимит паролей: максимум %d активных. Удалите ненужный пароль через список доступов.", maxGeneratedPasswords), inlineKeyboard(
			[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
			[]map[string]interface{}{inlineButton("◀️ Главное меню", "mainmenu")},
		))
	}
	*waitingForDays = false
	return showNewPasswordDaysMenu(token, adminID, messageID)
}

func botLoop(token string, adminIDstr string, wgDev *device.Device) {
	if token == "" || adminIDstr == "" {
		return
	}
	adminID, _ := strconv.ParseInt(adminIDstr, 10, 64)
	if adminID == 0 {
		return
	}

	// Устанавливаем команды для синей кнопки Menu
	go func() {
		cmds := `{"commands":[{"command":"start","description":"Главное меню"},{"command":"new","description":"Создать временный пароль"},{"command":"list","description":"Управление доступами"},{"command":"settings","description":"Настройки сервера"}]}`
		resp, err := http.Post(fmt.Sprintf("https://api.telegram.org/bot%s/setMyCommands", token), "application/json", strings.NewReader(cmds))
		if err == nil {
			resp.Body.Close()
		}
	}()

	offset := 0
	client := &http.Client{Timeout: 65 * time.Second}

	// Состояние ожидания ввода
	var waitingForDays bool
	var waitingForPorts bool
	var waitingForHash bool
	var waitingForLabel bool
	var waitingForNewClientPassword bool
	var waitingForClientImport bool
	var waitingForSetting string
	var editMode string
	var editPassword string
	var targetPassword string

	var tempDays int
	var tempLabel string
	var tempPorts string // "dtls,wg,tun"
	var tempHash string
	var pendingClientImport *clientTransferPayload
	var pendingPasswordChangeOld string
	var pendingPasswordChangeNew string
	var promptMessageID int

	for {
		url := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?timeout=60&offset=%d", token, offset)
		resp, err := client.Get(url)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}

		var res struct {
			Ok     bool `json:"ok"`
			Result []struct {
				UpdateID int `json:"update_id"`
				Message  *struct {
					MessageID int `json:"message_id"`
					Chat      struct {
						ID int64 `json:"id"`
					} `json:"chat"`
					Text string `json:"text"`
				} `json:"message"`
				CallbackQuery *struct {
					ID      string `json:"id"`
					Data    string `json:"data"`
					Message struct {
						MessageID int `json:"message_id"`
						Chat      struct {
							ID int64 `json:"id"`
						} `json:"chat"`
					} `json:"message"`
				} `json:"callback_query"`
			} `json:"result"`
		}

		err = json.NewDecoder(resp.Body).Decode(&res)
		resp.Body.Close()
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}

		for _, u := range res.Result {
			offset = u.UpdateID + 1

			// ═══ Callback кнопки ═══
			if u.CallbackQuery != nil && u.CallbackQuery.Message.Chat.ID == adminID {
				data := u.CallbackQuery.Data
				answerCallback(token, u.CallbackQuery.ID)

				menuMessageID := u.CallbackQuery.Message.MessageID

				if strings.HasPrefix(data, "viewpass_") {
					// Просмотр деталей пароля
					pass := strings.TrimPrefix(data, "viewpass_")
					dbMutex.Lock()
					entry, exists := db.Passwords[pass]
					if !exists || entry == nil {
						dbMutex.Unlock()
						sendOrEditTelegram(token, adminID, menuMessageID, "❌ Пароль не найден", inlineKeyboard(
							[]map[string]interface{}{inlineButton("◀️ К списку", "backlist")},
						))
						continue
					}
					title := pass
					if entry.Label != "" {
						title = fmt.Sprintf("%s — %s", entry.Label, pass)
					}
					txt := fmt.Sprintf("🔑 *Пароль:* `%s`\n", mdCode(title))
					if entry.VkHash != "" {
						pts := strings.Split(entry.Ports, ",")
						if len(pts) < 3 {
							pts = []string{"56000", "56001", "9000"}
						}
						srvIP := getPublicIP()
						link := fmt.Sprintf("wdtt://%s:%s:%s:%s:%s:%s", srvIP, pts[0], pts[1], pts[2], pass, entry.VkHash)
						txt += fmt.Sprintf("🔗 *Быстрая ссылка:* `%s`\n", mdCode(link))
					}
					if entry.IsDeactivated {
						txt += "🔴 Статус: *ДЕАКТИВИРОВАН*\n"
					} else {
						txt += "🟢 Статус: *АКТИВЕН*\n"
					}

					if entry.ExpiresAt > 0 {
						expireTime := time.Unix(entry.ExpiresAt, 0)
						remaining := time.Until(expireTime)
						if remaining > 0 {
							txt += fmt.Sprintf("⏰ Истекает: %s (через %dd)\n", expireTime.Format("02.01.2006"), int(remaining.Hours()/24))
						} else {
							txt += "⏰ *ИСТЁК* ❌\n"
						}
					} else {
						txt += "⏰ Бессрочный ♾\n"
					}

					txt += "\n📊 *Трафик:*\n" + trafficPeriodReport(
						passwordTrafficTotals(entry, 1),
						passwordTrafficTotals(entry, 7),
						passwordTrafficTotals(entry, 30),
						passwordTrafficTotals(entry, 0),
					) + "\n"
					txt += "\n📱 *Привязанное устройство:*\n"
					var kb []map[string]interface{}
					if entry.DeviceID == "" {
						txt += "_Ожидает первого подключения..._\n"
					} else {
						dev, devExists := db.Devices[entry.DeviceID]
						if devExists {
							txt += compactDeviceSummary(entry, dev)
							kb = append(kb, map[string]interface{}{
								"text":          "📱 Данные устройства",
								"callback_data": "devinfo_" + pass,
							})
						} else {
							txt += fmt.Sprintf("• ID: `%s` (устройство удалено)\n", mdCode(entry.DeviceID))
						}
						kb = append(kb, map[string]interface{}{
							"text":          "🗑 Отвязать устройство",
							"callback_data": "unbind_" + pass,
						})
					}
					if len(entry.BindHistory) > 0 {
						kb = append(kb, map[string]interface{}{
							"text":          "🕓 История устройств",
							"callback_data": "bindhist_" + pass,
						})
					}
					dbMutex.Unlock()
					if entry.IsDeactivated {
						kb = append(kb, map[string]interface{}{
							"text":          "✅ Активировать",
							"callback_data": "react_" + pass,
						})
					} else {
						kb = append(kb, map[string]interface{}{
							"text":          "⏸ Деактивировать",
							"callback_data": "deact_" + pass,
						})
					}
					kb = append(kb, map[string]interface{}{
						"text":          "❌ Удалить пароль",
						"callback_data": "delpass_" + pass,
					})
					kb = append(kb, map[string]interface{}{
						"text":          "✏️ Изменить",
						"callback_data": "editpass_" + pass,
					})
					kb = append(kb, map[string]interface{}{
						"text":          "📤 Экспорт клиента",
						"callback_data": "exportclient_" + pass,
					})
					kb = append(kb, map[string]interface{}{
						"text":          "◀️ Назад к списку",
						"callback_data": "backlist",
					})
					var keyboard [][]map[string]interface{}
					for _, btn := range kb {
						keyboard = append(keyboard, []map[string]interface{}{btn})
					}
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, txt, map[string]interface{}{"inline_keyboard": keyboard})

				} else if data == "mainmenu" {
					waitingForDays = false
					waitingForPorts = false
					waitingForHash = false
					waitingForLabel = false
					waitingForNewClientPassword = false
					waitingForClientImport = false
					waitingForSetting = ""
					targetPassword = ""
					tempDays = 0
					tempLabel = ""
					tempPorts = ""
					tempHash = ""
					pendingClientImport = nil
					pendingPasswordChangeOld = ""
					pendingPasswordChangeNew = ""
					editMode = ""
					editPassword = ""
					promptMessageID = sendMainMenu(token, adminID, menuMessageID)
				} else if data == "settings" {
					waitingForDays = false
					waitingForPorts = false
					waitingForHash = false
					waitingForLabel = false
					waitingForNewClientPassword = false
					waitingForClientImport = false
					waitingForSetting = ""
					editMode = ""
					editPassword = ""
					promptMessageID = sendSettingsMenu(token, adminID, menuMessageID)
				} else if data == "menu_new" {
					waitingForDays = false
					waitingForPorts = false
					waitingForHash = false
					waitingForLabel = false
					waitingForNewClientPassword = false
					waitingForClientImport = false
					waitingForSetting = ""
					editMode = ""
					editPassword = ""
					targetPassword = ""
					tempDays = 0
					tempLabel = ""
					tempPorts = ""
					tempHash = ""
					pendingClientImport = nil
					promptMessageID = startNewPasswordFlow(token, adminID, wgDev, &waitingForDays, menuMessageID)
				} else if strings.HasPrefix(data, "new_days_") {
					value := strings.TrimPrefix(data, "new_days_")
					waitingForPorts = false
					waitingForHash = false
					waitingForLabel = false
					waitingForNewClientPassword = false
					waitingForClientImport = false
					waitingForSetting = ""
					if value == "custom" {
						waitingForDays = true
						promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "📅 Введите срок действия в днях.\n\n`0` — бессрочно, `1..365` — количество дней.", inlineKeyboard(
							[]map[string]interface{}{inlineButton("◀️ Назад", "mainmenu")},
						))
						continue
					}
					days, parseErr := strconv.Atoi(value)
					if parseErr != nil || days < 0 || days > 365 {
						promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "❌ Неверный срок действия.", inlineKeyboard(
							[]map[string]interface{}{inlineButton("Выбрать заново", "menu_new")},
						))
						continue
					}
					tempDays = days
					waitingForDays = false
					promptMessageID = showLabelMenu(token, adminID, menuMessageID)
				} else if data == "new_password_auto" {
					waitingForNewClientPassword = false
					password, entry, err := createBotClient(wgDev, "", tempDays, -1, tempLabel, tempHash, tempPorts, false)
					if err != nil {
						promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "❌ "+mdCode(err.Error()), inlineKeyboard(
							[]map[string]interface{}{inlineButton("Повторить", "menu_new")},
							[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
						))
						continue
					}
					promptMessageID = sendBotClientCreated(token, adminID, menuMessageID, password, entry, false)
				} else if data == "new_password_manual" {
					waitingForNewClientPassword = true
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID,
						"⌨️ Введите пароль клиента из 16 символов. Допустимы безопасные латинские буквы и цифры без неоднозначных `0`, `1`, `I`, `i`, `O`, `o` и `l`.\n\nСервер проверит формат, уникальность и совпадение с главным паролем.",
						inlineKeyboard([]map[string]interface{}{inlineButton("◀️ Отмена", "mainmenu")}),
					)
				} else if data == "import_client" {
					waitingForClientImport = true
					pendingClientImport = nil
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID,
						"📥 *Импорт клиента*\n\nОтправьте текстовый код переноса, созданный в приложении или другом WDTT Plus-боте. Перед записью я проверю пароль, срок, лимит и покажу данные нового сервера.",
						inlineKeyboard([]map[string]interface{}{inlineButton("Отмена", "backlist")}),
					)
				} else if data == "confirm_import_client" {
					if pendingClientImport == nil {
						promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "❌ Данные импорта потеряны. Отправьте код ещё раз.", inlineKeyboard(
							[]map[string]interface{}{inlineButton("📥 Импорт", "import_client")},
							[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
						))
						continue
					}
					payload := *pendingClientImport
					password, entry, err := createBotClient(wgDev, payload.Password, 0, payload.ExpiresAt, payload.Label, payload.VkHash, defaultPortsSpec(), payload.Deactivated)
					pendingClientImport = nil
					if err != nil {
						promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "❌ Импорт отменён: "+mdCode(err.Error()), inlineKeyboard(
							[]map[string]interface{}{inlineButton("📥 Другой клиент", "import_client")},
							[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
						))
						continue
					}
					promptMessageID = sendBotClientCreated(token, adminID, menuMessageID, password, entry, true)
				} else if strings.HasPrefix(data, "exportclient_") {
					pass := strings.TrimPrefix(data, "exportclient_")
					dbMutex.Lock()
					entry := db.Passwords[pass]
					transfer, err := encodeClientTransfer(pass, entry)
					dbMutex.Unlock()
					if err != nil {
						promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "❌ Экспорт не выполнен: "+mdCode(err.Error()), inlineKeyboard(
							[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
						))
						continue
					}
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID,
						fmt.Sprintf("📤 *Код переноса клиента*\n\n`%s`\n\nСодержит рабочий пароль, название, VK-хеши, срок и состояние. Устройство, ключи, адрес, порты, трафик и история не переносятся. Отправляйте код только себе или доверенному администратору.", mdCode(transfer)),
						inlineKeyboard(
							[]map[string]interface{}{inlineButton("◀️ К клиенту", "viewpass_"+pass)},
							[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
						),
					)
				} else if strings.HasPrefix(data, "edit_password_") {
					pass := strings.TrimPrefix(data, "edit_password_")
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID,
						fmt.Sprintf("🔐 *Смена пароля `%s`*\n\nСтарые ссылки перестанут работать, а текущее соединение клиента завершится. Название, срок, VK-хеши и привязка сохранятся. Изменение применяется без перезапуска сервера.", mdCode(pass)),
						inlineKeyboard(
							[]map[string]interface{}{inlineButton("🎲 Новый автоматически", "change_pass_auto_"+pass)},
							[]map[string]interface{}{inlineButton("⌨️ Ввести вручную", "change_pass_manual_"+pass)},
							[]map[string]interface{}{inlineButton("◀️ Назад", "editpass_"+pass)},
						),
					)
				} else if strings.HasPrefix(data, "change_pass_auto_") {
					pendingPasswordChangeOld = strings.TrimPrefix(data, "change_pass_auto_")
					pendingPasswordChangeNew = ""
					dbMutex.Lock()
					for i := 0; i < 64; i++ {
						candidate := generatePassword()
						if candidate == db.MainPassword || candidate == pendingPasswordChangeOld {
							continue
						}
						if _, exists := db.Passwords[candidate]; !exists {
							pendingPasswordChangeNew = candidate
							break
						}
					}
					dbMutex.Unlock()
					if pendingPasswordChangeNew == "" {
						promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "❌ Не удалось создать уникальный пароль.", inlineKeyboard(
							[]map[string]interface{}{inlineButton("Повторить", "edit_password_"+pendingPasswordChangeOld)},
							[]map[string]interface{}{inlineButton("Отмена", "editpass_"+pendingPasswordChangeOld)},
						))
						continue
					}
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID,
						fmt.Sprintf("⚠️ Заменить пароль клиента `%s` на `%s`?\n\nТекущее соединение этого клиента завершится, старые ссылки перестанут работать. Остальные клиенты не затрагиваются.", mdCode(pendingPasswordChangeOld), mdCode(pendingPasswordChangeNew)),
						inlineKeyboard(
							[]map[string]interface{}{inlineButton("Изменить", "confirm_change_password")},
							[]map[string]interface{}{inlineButton("Отмена", "editpass_"+pendingPasswordChangeOld)},
						),
					)
				} else if strings.HasPrefix(data, "change_pass_manual_") {
					editMode = "password"
					editPassword = strings.TrimPrefix(data, "change_pass_manual_")
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID,
						"⌨️ Введите новый пароль из 16 разрешённых символов. После проверки бот отдельно попросит подтверждение.",
						inlineKeyboard([]map[string]interface{}{inlineButton("Отмена", "editpass_"+editPassword)}),
					)
				} else if data == "confirm_change_password" {
					if pendingPasswordChangeOld == "" || pendingPasswordChangeNew == "" {
						promptMessageID = sendPasswordList(token, adminID, wgDev, menuMessageID)
						continue
					}
					oldPassword := pendingPasswordChangeOld
					newPassword, err := changeBotClientPassword(wgDev, oldPassword, pendingPasswordChangeNew)
					pendingPasswordChangeOld = ""
					pendingPasswordChangeNew = ""
					if err != nil {
						promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "❌ Пароль не изменён: "+mdCode(err.Error()), inlineKeyboard(
							[]map[string]interface{}{inlineButton("◀️ К клиенту", "viewpass_"+oldPassword)},
							[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
						))
						continue
					}
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID,
						fmt.Sprintf("✅ Пароль изменён без перезапуска сервера.\n\nНовый пароль: `%s`\nСтарые ссылки больше не работают.", mdCode(newPassword)),
						inlineKeyboard(
							[]map[string]interface{}{inlineButton("🔍 Открыть клиента", "viewpass_"+newPassword)},
							[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
						),
					)
				} else if strings.HasPrefix(data, "editpass_") {
					editMode = ""
					editPassword = ""
					promptMessageID = showPasswordEditMenu(token, adminID, menuMessageID, strings.TrimPrefix(data, "editpass_"))
				} else if strings.HasPrefix(data, "edit_label_") {
					pass := strings.TrimPrefix(data, "edit_label_")
					editMode = "label"
					editPassword = pass
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, fmt.Sprintf("🏷 Введите новое название для `%s`.\n\nОтправьте `-`, чтобы очистить название.", mdCode(pass)), inlineKeyboard(
						[]map[string]interface{}{inlineButton("Очистить", "clear_label_"+pass)},
						[]map[string]interface{}{inlineButton("◀️ Назад", "editpass_"+pass)},
					))
				} else if strings.HasPrefix(data, "clear_label_") {
					pass := strings.TrimPrefix(data, "clear_label_")
					dbMutex.Lock()
					entry, exists := db.Passwords[pass]
					if exists && entry != nil {
						entry.Label = ""
						saveDB()
					}
					dbMutex.Unlock()
					promptMessageID = showPasswordEditMenu(token, adminID, menuMessageID, pass)
				} else if strings.HasPrefix(data, "edit_exp_custom_") {
					pass := strings.TrimPrefix(data, "edit_exp_custom_")
					editMode = "expires"
					editPassword = pass
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, fmt.Sprintf("⏰ Введите новый срок для `%s`.\n\n`0` — бессрочно, `1..365` — продлить от текущего момента на указанное число дней.", mdCode(pass)), inlineKeyboard(
						[]map[string]interface{}{inlineButton("◀️ Назад", "edit_exp_"+pass)},
					))
				} else if strings.HasPrefix(data, "edit_exp_") {
					editMode = ""
					editPassword = ""
					promptMessageID = showEditExpiryMenu(token, adminID, menuMessageID, strings.TrimPrefix(data, "edit_exp_"))
				} else if strings.HasPrefix(data, "set_exp_") {
					rest := strings.TrimPrefix(data, "set_exp_")
					parts := strings.SplitN(rest, "_", 2)
					if len(parts) != 2 {
						continue
					}
					days, err := strconv.Atoi(parts[0])
					pass := parts[1]
					if err != nil || days < 0 || days > 365 {
						promptMessageID = showEditExpiryMenu(token, adminID, menuMessageID, pass)
						continue
					}
					dbMutex.Lock()
					entry, exists := db.Passwords[pass]
					if exists && entry != nil {
						if days == 0 {
							entry.ExpiresAt = 0
						} else {
							entry.ExpiresAt = time.Now().Add(time.Duration(days) * 24 * time.Hour).Unix()
						}
						saveDB()
					}
					dbMutex.Unlock()
					promptMessageID = showPasswordEditMenu(token, adminID, menuMessageID, pass)
				} else if strings.HasPrefix(data, "edit_hash_") {
					pass := strings.TrimPrefix(data, "edit_hash_")
					editMode = "hash"
					editPassword = pass
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, fmt.Sprintf("🔑 Отправьте новый VK-хеш или ссылку для `%s`.", mdCode(pass)), inlineKeyboard(
						[]map[string]interface{}{inlineButton("◀️ Назад", "editpass_"+pass)},
					))
				} else if strings.HasPrefix(data, "edit_ports_") {
					pass := strings.TrimPrefix(data, "edit_ports_")
					editMode = "ports"
					editPassword = pass
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, fmt.Sprintf("⚙️ Укажите новые порты ссылки для `%s`.\n\nФормат: `DTLS,WG,TUN`, например `56000,56001,9000`.", mdCode(pass)), inlineKeyboard(
						[]map[string]interface{}{inlineButton("Стандартные", "set_ports_def_"+pass)},
						[]map[string]interface{}{inlineButton("◀️ Назад", "editpass_"+pass)},
					))
				} else if strings.HasPrefix(data, "set_ports_def_") {
					pass := strings.TrimPrefix(data, "set_ports_def_")
					dbMutex.Lock()
					entry, exists := db.Passwords[pass]
					if exists && entry != nil {
						entry.Ports = defaultPortsSpec()
						saveDB()
					}
					dbMutex.Unlock()
					promptMessageID = showPasswordEditMenu(token, adminID, menuMessageID, pass)
				} else if data == "label_skip" {
					waitingForDays = false
					waitingForPorts = false
					waitingForHash = false
					waitingForLabel = false
					tempLabel = ""
					promptMessageID = showPortsMenu(token, adminID, menuMessageID, false)
				} else if data == "label_custom" {
					waitingForDays = false
					waitingForPorts = false
					waitingForHash = false
					waitingForLabel = true
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "🏷 Введите название ключа одним сообщением.\n\nДо 40 символов. Команда `/new` начнёт заново.", inlineKeyboard(
						[]map[string]interface{}{inlineButton("Без имени", "label_skip")},
						[]map[string]interface{}{inlineButton("◀️ Назад", "mainmenu")},
					))
				} else if data == "settings_dns" {
					promptMessageID = sendDNSSettingsMenu(token, adminID, menuMessageID)
				} else if data == "settings_owner_profile" {
					promptMessageID = sendOwnerProfileMenu(token, adminID, menuMessageID)
				} else if data == "owner_link" {
					link, err := ownerProfileLink()
					if err != nil {
						promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, fmt.Sprintf("❌ %s.\n\nСначала обновите VK-хеши владельца в этом меню.", err.Error()), inlineKeyboard(
							[]map[string]interface{}{inlineButton("🔑 Обновить VK-хеши", "owner_hash_edit")},
							[]map[string]interface{}{inlineButton("◀️ Назад", "settings_owner_profile")},
						))
						continue
					}
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, fmt.Sprintf("🔗 *Ссылка владельца:*\n`%s`\n\nЭта ссылка использует главный пароль и профиль владельца. Не пересылайте её как клиентский доступ.", mdCode(link)), inlineKeyboard(
						[]map[string]interface{}{inlineButton("◀️ Профиль владельца", "settings_owner_profile")},
						[]map[string]interface{}{inlineButton("◀️ Главное меню", "mainmenu")},
					))
				} else if data == "owner_hash_edit" {
					waitingForSetting = "owner_hash"
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "🔑 Отправьте VK-хеши владельца или ссылки приглашения.\n\nМожно несколько значений через пробел, запятую или новую строку.", inlineKeyboard(
						[]map[string]interface{}{inlineButton("◀️ Назад", "settings_owner_profile")},
					))
				} else if data == "owner_hash_clear" {
					dbMutex.Lock()
					db.AdminProfile.VkHashes = ""
					db.AdminProfile.SecondaryVkHash = ""
					db.AdminProfile.UpdatedAt = time.Now().Unix()
					saveDB()
					dbMutex.Unlock()
					promptMessageID = sendOwnerProfileMenu(token, adminID, menuMessageID)
				} else if data == "owner_ports_edit" {
					waitingForSetting = "owner_ports"
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "⚙️ Укажите порты ссылки владельца.\n\nФормат: `DTLS,WG,TUN`, например `56000,56001,9000`.", inlineKeyboard(
						[]map[string]interface{}{inlineButton("Стандартные", "owner_ports_default")},
						[]map[string]interface{}{inlineButton("◀️ Назад", "settings_owner_profile")},
					))
				} else if data == "owner_ports_default" {
					ports := defaultPortsSpec()
					dbMutex.Lock()
					db.AdminProfile.Ports = ports
					db.AdminProfile.ListenPort = adminProfileDefaultListenPort(ports)
					db.AdminProfile.UpdatedAt = time.Now().Unix()
					saveDB()
					dbMutex.Unlock()
					promptMessageID = sendOwnerProfileMenu(token, adminID, menuMessageID)
				} else if data == "settings_dns_edit" {
					waitingForSetting = "dns"
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "🌐 Введите DNS для WireGuard-клиентов.\n\nМожно несколько через запятую, например: `1.1.1.1,8.8.8.8`.", inlineKeyboard(
						[]map[string]interface{}{inlineButton("1.1.1.1", "set_dns_1.1.1.1")},
						[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
					))
				} else if strings.HasPrefix(data, "set_dns_") {
					dnsValue := strings.TrimPrefix(data, "set_dns_")
					normalized, err := normalizeDNSInput(dnsValue)
					if err != nil {
						promptMessageID = sendSettingsMenu(token, adminID, menuMessageID)
						continue
					}
					dbMutex.Lock()
					db.DNS = normalized
					setServerDNS(normalized)
					saveDB()
					dbMutex.Unlock()
					promptMessageID = sendSettingsMenu(token, adminID, menuMessageID)
				} else if data == "settings_limit" {
					promptMessageID = sendLimitSettingsMenu(token, adminID, menuMessageID)
				} else if data == "settings_limit_edit" {
					waitingForSetting = "limit"
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "🔢 Введите лимит активных ключей.\n\nДопустимо `1..500`. Уже созданные ключи не удаляются.", inlineKeyboard(
						[]map[string]interface{}{
							inlineButton("50", "set_limit_50"),
							inlineButton("100", "set_limit_100"),
						},
						[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
					))
				} else if strings.HasPrefix(data, "set_limit_") {
					limit, err := strconv.Atoi(strings.TrimPrefix(data, "set_limit_"))
					if err != nil || limit < 1 || limit > 500 {
						promptMessageID = sendSettingsMenu(token, adminID, menuMessageID)
						continue
					}
					dbMutex.Lock()
					maxGeneratedPasswords = limit
					db.MaxPasswords = limit
					saveDB()
					dbMutex.Unlock()
					promptMessageID = sendSettingsMenu(token, adminID, menuMessageID)
				} else if data == "settings_ports" {
					promptMessageID = sendDefaultPortsSettingsMenu(token, adminID, menuMessageID)
				} else if data == "settings_ports_edit" {
					waitingForSetting = "default_ports"
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "⚙️ Введите порты быстрых ссылок по умолчанию.\n\nФормат: `DTLS,WG,TUN`, например `56000,56001,9000`.", inlineKeyboard(
						[]map[string]interface{}{inlineButton("56000,56001,9000", "set_default_ports_56000,56001,9000")},
						[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
					))
				} else if strings.HasPrefix(data, "set_default_ports_") {
					ports, err := parsePortsSpec(strings.TrimPrefix(data, "set_default_ports_"))
					if err != nil {
						promptMessageID = sendSettingsMenu(token, adminID, menuMessageID)
						continue
					}
					dbMutex.Lock()
					db.DefaultPorts = ports
					setServerDefaultPorts(ports)
					saveDB()
					dbMutex.Unlock()
					promptMessageID = sendSettingsMenu(token, adminID, menuMessageID)
				} else if data == "settings_ip" {
					promptMessageID = sendPublicIPSettingsMenu(token, adminID, menuMessageID)
				} else if data == "settings_ip_edit" {
					waitingForSetting = "public_ip"
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "📍 Введите адрес сервера для новых ссылок.\n\nМожно указать домен или IP без `http://` и без порта, например `site.ru`. Либо нажмите кнопку автоматического определения ниже.", inlineKeyboard(
						[]map[string]interface{}{inlineButton("Определять автоматически", "set_public_ip_auto")},
						[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
					))
				} else if data == "set_public_ip_auto" {
					dbMutex.Lock()
					db.PublicIP = ""
					setServerPublicIPOverride("")
					publicIP = ""
					saveDB()
					dbMutex.Unlock()
					promptMessageID = sendSettingsMenu(token, adminID, menuMessageID)
				} else if data == "settings_refresh_ip" {
					promptMessageID = sendRefreshIPMenu(token, adminID, menuMessageID)
				} else if data == "confirm_refresh_ip" {
					publicIP = ""
					ip := getPublicIP()
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, fmt.Sprintf("🔎 Публичный IP сервера определён: `%s`", mdCode(ip)), inlineKeyboard(
						[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
						[]map[string]interface{}{inlineButton("◀️ Главное меню", "mainmenu")},
					))
				} else if data == "settings_outbound" {
					waitingForSetting = ""
					promptMessageID = sendOutboundMenu(token, adminID, menuMessageID)
				} else if data == "out_status" {
					out, err := runBotScript(outboundStatusScript(), 25*time.Second)
					promptMessageID = sendBotScriptResult(token, adminID, menuMessageID, "Статус внешнего выхода", out, err, "settings_outbound")
				} else if data == "out_diag" {
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "🧪 Выполняю диагностику маршрутизации...", nil)
					out, err := runBotScript(outboundDiagnosticsScript(), 35*time.Second)
					promptMessageID = sendBotScriptResult(token, adminID, promptMessageID, "Диагностика выхода WDTT", out, err, "settings_outbound")
				} else if data == "out_direct" {
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID,
						"↩️ *Вернуть прямой выход?*\n\nЭто отключит внешний прокси или выход через WireGuard и вернёт трафик WDTT-пользователей напрямую через текущий сервер. Прокси на этом сервере не удаляется.",
						inlineKeyboard(
							[]map[string]interface{}{inlineButton("Да, вернуть прямой выход", "confirm_out_direct")},
							[]map[string]interface{}{inlineButton("◀️ Назад", "settings_outbound")},
						),
					)
				} else if data == "confirm_out_direct" {
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "↩️ Возвращаю прямой выход...", nil)
					out, err := runBotScript(outboundDisableScript(), 30*time.Second)
					promptMessageID = sendBotScriptResult(token, adminID, promptMessageID, "Прямой выход включён", out, err, "settings_outbound")
				} else if data == "out_local" {
					waitingForSetting = ""
					promptMessageID = sendLocalProxyMenu(token, adminID, menuMessageID)
				} else if data == "out_local_install" {
					login := "wdtt" + strings.ToLower(generatePassword()[:8])
					password := generatePassword()
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "🧦 Создаю или обновляю SOCKS5/HTTP-прокси на этом сервере. Если пакета 3proxy нет, попробую собрать его из исходников...", nil)
					out, err := runBotScript(localProxyInstallScript(login, password, 1080), 5*time.Minute)
					promptMessageID = sendBotScriptResult(token, adminID, promptMessageID, "Прокси на сервере готов", out, err, "out_local")
				} else if data == "out_local_check" {
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "🧪 Проверяю уже установленный SOCKS5-прокси на 127.0.0.1 с сохранённым логином и паролем...", nil)
					out, err := runBotScript(localProxyCheckScript(), 20*time.Second)
					promptMessageID = sendBotScriptResult(token, adminID, promptMessageID, "Проверка прокси на этом сервере", out, err, "out_local")
				} else if data == "out_local_stop" {
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "⏸ Останавливаю службу прокси на этом сервере. Настройки останутся на месте...", nil)
					out, err := runBotScript(localProxyRemoveScript(false), 20*time.Second)
					promptMessageID = sendBotScriptResult(token, adminID, promptMessageID, "Прокси на сервере остановлен", out, err, "out_local")
				} else if data == "out_local_remove" {
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID,
						"🗑 *Удалить прокси на этом сервере?*\n\nБудут остановлены служба прокси, её настройки и правила доступа к портам SOCKS5/HTTP.",
						inlineKeyboard(
							[]map[string]interface{}{inlineButton("Да, удалить", "confirm_out_local_remove")},
							[]map[string]interface{}{inlineButton("◀️ Назад", "out_local")},
						),
					)
				} else if data == "confirm_out_local_remove" {
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "🗑 Удаляю службу, настройки и правила доступа прокси на этом сервере...", nil)
					out, err := runBotScript(localProxyRemoveScript(true), 25*time.Second)
					promptMessageID = sendBotScriptResult(token, adminID, promptMessageID, "Прокси на сервере удалён", out, err, "out_local")
				} else if data == "out_external" {
					waitingForSetting = ""
					promptMessageID = sendExternalProxyMenu(token, adminID, menuMessageID)
				} else if data == "out_external_enable" {
					waitingForSetting = "outbound_external_enable"
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID,
						"🌍 Введите внешний прокси для включения.\n\nФормат:\n`тип адрес порт логин пароль`\n\nПример с паролем:\n`socks5 proxy.example.com 1080 ivan secret123`\n\nПример без пароля:\n`http proxy.example.com 8080 - -`\n\nАдрес должен быть доменом или IP без `http://` и без лишнего пути.",
						inlineKeyboard(
							[]map[string]interface{}{inlineButton("◀️ Назад", "out_external")},
						),
					)
				} else if data == "out_external_check" {
					waitingForSetting = "outbound_external_check"
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID,
						"🧪 Введите внешний прокси для проверки.\n\nФормат:\n`тип адрес порт логин пароль`\n\nПример с паролем:\n`socks5 proxy.example.com 1080 ivan secret123`\n\nПример без пароля:\n`http proxy.example.com 8080 - -`",
						inlineKeyboard(
							[]map[string]interface{}{inlineButton("◀️ Назад", "out_external")},
						),
					)
				} else if data == "out_warp" {
					promptMessageID = sendFreeWarpMenu(token, adminID, menuMessageID)
				} else if data == "out_warp_check" {
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "🧪 Проверяю Cloudflare WARP и выходной IP...", nil)
					out, err := runBotScript(freeWarpCheckScript(false), 35*time.Second)
					promptMessageID = sendBotScriptResult(token, adminID, promptMessageID, "Проверка бесплатного WARP", out, err, "out_warp")
				} else if data == "out_warp_restart" {
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "🔄 Перезапускаю WireGuard-выход и проверяю WARP...", nil)
					out, err := runBotScript(freeWarpCheckScript(true), 45*time.Second)
					promptMessageID = sendBotScriptResult(token, adminID, promptMessageID, "WARP перезапущен и проверен", out, err, "out_warp")
				} else if data == "out_warp_delete" {
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID,
						"🗑 *Удалить бесплатный WARP?*\n\nБудут удалены регистрация, ключи, профиль и автоматическая проверка. Если WARP активен, WDTT вернётся на прямой выход через VPS.",
						inlineKeyboard(
							[]map[string]interface{}{inlineButton("Да, удалить WARP", "confirm_out_warp_delete")},
							[]map[string]interface{}{inlineButton("◀️ Назад", "out_warp")},
						),
					)
				} else if data == "confirm_out_warp_delete" {
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "🗑 Удаляю WARP и возвращаю безопасный выход...", nil)
					out, err := runBotScript(deleteFreeWarpScript(), 45*time.Second)
					promptMessageID = sendBotScriptResult(token, adminID, promptMessageID, "Бесплатный WARP удалён", out, err, "settings_outbound")
				} else if data == "out_wg" {
					promptMessageID = sendWireGuardExitMenu(token, adminID, menuMessageID)
				} else if data == "out_wg_status" {
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "📊 Читаю режим выхода, службы прокси и WireGuard...", nil)
					out, err := runBotScript(outboundStatusScript(), 25*time.Second)
					promptMessageID = sendBotScriptResult(token, adminID, promptMessageID, "Статус выхода через WireGuard", out, err, "out_wg")
				} else if data == "out_wg_delete_import" {
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID,
						"🗑 *Удалить готовый WireGuard-файл?*\n\nБудут удалены рабочие файлы WireGuard и сохранённая копия импортированного конфига, а выход WDTT вернётся напрямую через текущий сервер. Первичная настройка другого сервера из приложения не удаляется.",
						inlineKeyboard(
							[]map[string]interface{}{inlineButton("Да, удалить файл", "confirm_out_wg_delete_import")},
							[]map[string]interface{}{inlineButton("◀️ Назад", "out_wg")},
						),
					)
				} else if data == "confirm_out_wg_delete_import" {
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "🗑 Удаляю сохранённый WireGuard-файл и возвращаю прямой выход WDTT...", nil)
					out, err := runBotScript(deleteImportedWGScript(), 30*time.Second)
					promptMessageID = sendBotScriptResult(token, adminID, promptMessageID, "Выход через WireGuard очищен", out, err, "out_wg")
				} else if data == "settings_cleanup_expired" {
					promptMessageID = sendExpiredPasswordsMenu(token, adminID, menuMessageID)
				} else if data == "confirm_cleanup_expired" {
					removed := cleanupExpiredPasswords(wgDev)
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, fmt.Sprintf("🧹 Удалено истёкших ключей: `%d`", removed), inlineKeyboard(
						[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
					))
				} else if data == "settings_cleanup_orphans" {
					promptMessageID = sendOrphanDevicesMenu(token, adminID, menuMessageID)
				} else if data == "confirm_cleanup_orphans" {
					dbMutex.Lock()
					usedDevices := make(map[string]struct{})
					for _, entry := range db.Passwords {
						if entry != nil && entry.DeviceID != "" {
							usedDevices[entry.DeviceID] = struct{}{}
						}
					}
					removed := 0
					for devID, dev := range db.Devices {
						if _, used := usedDevices[devID]; used {
							continue
						}
						removePeerFromWG(wgDev, dev)
						delete(db.Devices, devID)
						removed++
					}
					if removed > 0 {
						saveDB()
					}
					dbMutex.Unlock()
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, fmt.Sprintf("📱 Удалено забытых устройств: `%d`", removed), inlineKeyboard(
						[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
					))
				} else if data == "settings_traffic" {
					promptMessageID = sendTrafficMenu(token, adminID, menuMessageID)
				} else if data == "settings_reset_traffic" {
					promptMessageID = sendResetTrafficMenu(token, adminID, menuMessageID)
				} else if data == "confirm_reset_traffic" {
					dbMutex.Lock()
					db.AdminDownBytes = 0
					db.AdminUpBytes = 0
					db.AdminTraffic = nil
					for _, entry := range db.Passwords {
						if entry == nil {
							continue
						}
						entry.DownBytes = 0
						entry.UpBytes = 0
						entry.Traffic = nil
					}
					saveDB()
					dbMutex.Unlock()
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "📊 Счётчики трафика сброшены", inlineKeyboard(
						[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
					))
				} else if data == "restart_server" {
					promptMessageID = sendRestartServerMenu(token, adminID, menuMessageID)
				} else if data == "confirm_restart_server" {
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "🔄 Перезапускаю wdtt.service...", nil)
					go func() {
						out, err := runCmd("systemctl", "restart", "wdtt")
						if err != nil {
							sendOrEditTelegram(token, adminID, menuMessageID, fmt.Sprintf("❌ Не удалось перезапустить сервис:\n`%s`", mdCode(strings.TrimSpace(out))), inlineKeyboard(
								[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
								[]map[string]interface{}{inlineButton("◀️ Главное меню", "mainmenu")},
							))
							return
						}
						sendOrEditTelegram(token, adminID, menuMessageID, "✅ wdtt.service перезапущен", inlineKeyboard(
							[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
							[]map[string]interface{}{inlineButton("◀️ Главное меню", "mainmenu")},
						))
					}()
				} else if strings.HasPrefix(data, "deact_") {
					pass := strings.TrimPrefix(data, "deact_")
					dbMutex.Lock()
					entry, exists := db.Passwords[pass]
					if !exists || entry == nil {
						dbMutex.Unlock()
						promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "❌ Пароль не найден", inlineKeyboard(
							[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
						))
						continue
					}
					entry.IsDeactivated = true
					serverWrapKeys.RemovePassword(pass)
					// Отключаем активное устройство от WG если нужно
					if entry.DeviceID != "" {
						if dev, devExists := db.Devices[entry.DeviceID]; devExists {
							if pubHex, err := b64ToHex(dev.PubKey); err == nil && pubHex != "" {
								wgDev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", pubHex))
							}
						}
					}
					saveDB()
					dbMutex.Unlock()
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, fmt.Sprintf("⏸ Пароль `%s` деактивирован", mdCode(pass)), inlineKeyboard(
						[]map[string]interface{}{inlineButton("◀️ Назад", "viewpass_"+pass)},
						[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
					))

				} else if strings.HasPrefix(data, "react_") {
					pass := strings.TrimPrefix(data, "react_")
					dbMutex.Lock()
					entry, exists := db.Passwords[pass]
					if !exists || entry == nil {
						dbMutex.Unlock()
						promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "❌ Пароль не найден", inlineKeyboard(
							[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
						))
						continue
					}
					if isPasswordExpired(entry) {
						dbMutex.Unlock()
						promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, fmt.Sprintf("❌ Пароль `%s` уже истёк", mdCode(pass)), inlineKeyboard(
							[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
						))
						continue
					}
					if err := serverWrapKeys.AddPassword(pass); err != nil {
						dbMutex.Unlock()
						promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "❌ Не удалось вернуть WRAP-ключ в память", inlineKeyboard(
							[]map[string]interface{}{inlineButton("◀️ Назад", "viewpass_"+pass)},
							[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
						))
						continue
					}
					entry.IsDeactivated = false
					if entry.DeviceID != "" {
						upsertPeerInWG(wgDev, db.Devices[entry.DeviceID])
					}
					saveDB()
					dbMutex.Unlock()
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, fmt.Sprintf("✅ Пароль `%s` активирован", mdCode(pass)), inlineKeyboard(
						[]map[string]interface{}{inlineButton("◀️ Назад", "viewpass_"+pass)},
						[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
					))

				} else if data == "mainlink" {
					waitingForDays = false
					waitingForPorts = false
					waitingForHash = false
					waitingForLabel = false
					waitingForSetting = ""
					targetPassword = "main"
					promptMessageID = showPortsMenu(token, adminID, menuMessageID, true)

				} else if strings.HasPrefix(data, "devinfo_") {
					pass := strings.TrimPrefix(data, "devinfo_")
					promptMessageID = sendDeviceDetailsMenu(token, adminID, menuMessageID, pass)

				} else if strings.HasPrefix(data, "bindhist_") {
					pass := strings.TrimPrefix(data, "bindhist_")
					promptMessageID = sendBindHistoryMenu(token, adminID, menuMessageID, pass)

				} else if strings.HasPrefix(data, "unbind_") {
					pass := strings.TrimPrefix(data, "unbind_")
					dbMutex.Lock()
					entry, exists := db.Passwords[pass]
					if exists && entry != nil && entry.DeviceID != "" {
						// Удаляем устройство из WG и из хранилища
						oldDeviceID := entry.DeviceID
						markActiveBindUnbound(entry, oldDeviceID, time.Now().Unix())
						dev, devExists := db.Devices[entry.DeviceID]
						if devExists {
							pubHex, _ := b64ToHex(dev.PubKey)
							wgDev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", pubHex))
							delete(db.Devices, oldDeviceID)
						}
						entry.DeviceID = ""
						saveDB()
					}
					dbMutex.Unlock()
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, fmt.Sprintf("✅ Устройство отвязано от пароля `%s`", mdCode(pass)), inlineKeyboard(
						[]map[string]interface{}{inlineButton("◀️ Назад", "viewpass_"+pass)},
						[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
					))

				} else if strings.HasPrefix(data, "delpass_") {
					pass := strings.TrimPrefix(data, "delpass_")
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, fmt.Sprintf("⚠️ Удалить пароль `%s`?", mdCode(pass)), inlineKeyboard(
						[]map[string]interface{}{inlineButton("Да, удалить", "confirmdel_"+pass)},
						[]map[string]interface{}{inlineButton("◀️ Назад", "viewpass_"+pass)},
					))
				} else if strings.HasPrefix(data, "confirmdel_") {
					pass := strings.TrimPrefix(data, "confirmdel_")
					dbMutex.Lock()
					entry, exists := db.Passwords[pass]
					if exists && entry != nil && entry.DeviceID != "" {
						markActiveBindUnbound(entry, entry.DeviceID, time.Now().Unix())
						dev, devExists := db.Devices[entry.DeviceID]
						if devExists {
							pubHex, _ := b64ToHex(dev.PubKey)
							wgDev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", pubHex))
							delete(db.Devices, entry.DeviceID)
						}
					}
					delete(db.Passwords, pass)
					serverWrapKeys.RemovePassword(pass)
					saveDB()
					dbMutex.Unlock()
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, fmt.Sprintf("✅ Пароль `%s` и его устройство удалены", mdCode(pass)), inlineKeyboard(
						[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
					))

				} else if strings.HasPrefix(data, "deldev_") {
					devID := strings.TrimPrefix(data, "deldev_")
					dbMutex.Lock()
					dev, exists := db.Devices[devID]
					if exists {
						delete(db.Devices, devID)
						pubHex, _ := b64ToHex(dev.PubKey)
						wgDev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", pubHex))
						// Очищаем привязку из пароля
						for _, entry := range db.Passwords {
							if entry != nil && entry.DeviceID == devID {
								markActiveBindUnbound(entry, devID, time.Now().Unix())
								entry.DeviceID = ""
							}
						}
						saveDB()
					}
					dbMutex.Unlock()
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, fmt.Sprintf("✅ Устройство `%s` удалено", mdCode(devID)), inlineKeyboard(
						[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
					))

				} else if data == "backlist" {
					waitingForDays = false
					waitingForPorts = false
					waitingForHash = false
					waitingForLabel = false
					waitingForNewClientPassword = false
					waitingForClientImport = false
					waitingForSetting = ""
					pendingClientImport = nil
					pendingPasswordChangeOld = ""
					pendingPasswordChangeNew = ""
					promptMessageID = sendPasswordList(token, adminID, wgDev, menuMessageID)
				} else if data == "ports_def" {
					waitingForDays = false
					waitingForPorts = false
					waitingForLabel = false
					waitingForNewClientPassword = false
					waitingForSetting = ""
					tempPorts = defaultPortsSpec()
					waitingForHash = true
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "🔑 Отправьте VK-хеш или ссылку приглашения.\n\nМожно несколько значений через пробел, запятую или новую строку.", inlineKeyboard(
						[]map[string]interface{}{inlineButton("◀️ Назад", "mainmenu")},
					))
				} else if data == "ports_custom" {
					waitingForDays = false
					waitingForPorts = true
					waitingForHash = false
					waitingForLabel = false
					waitingForNewClientPassword = false
					waitingForSetting = ""
					promptMessageID = sendOrEditTelegram(token, adminID, menuMessageID, "⚙️ Укажите через запятую 3 порта (DTLS,WG,TUN):\n\nНапример: `56000,56001,9000`", inlineKeyboard(
						[]map[string]interface{}{inlineButton("Стандартные порты", "ports_def")},
						[]map[string]interface{}{inlineButton("◀️ Назад", "mainmenu")},
					))
				}
			}

			// ═══ Текстовые команды ═══
			msg := u.Message
			if msg == nil || msg.Chat.ID != adminID {
				continue
			}

			cmd := strings.TrimSpace(msg.Text)

			if strings.HasPrefix(cmd, "/") {
				commandName := strings.Fields(cmd)[0]
				deleteTelegramMessage(token, adminID, msg.MessageID)
				waitingForDays = false
				waitingForPorts = false
				waitingForHash = false
				waitingForLabel = false
				waitingForNewClientPassword = false
				waitingForClientImport = false
				waitingForSetting = ""
				editMode = ""
				editPassword = ""
				targetPassword = ""
				tempDays = 0
				tempLabel = ""
				tempPorts = ""
				tempHash = ""
				pendingClientImport = nil
				pendingPasswordChangeOld = ""
				pendingPasswordChangeNew = ""

				if commandName == "/start" || commandName == "/help" {
					promptMessageID = sendMainMenu(token, adminID, promptMessageID)
				} else if commandName == "/new" {
					promptMessageID = startNewPasswordFlow(token, adminID, wgDev, &waitingForDays, promptMessageID)
				} else if commandName == "/list" {
					promptMessageID = sendPasswordList(token, adminID, wgDev, promptMessageID)
				} else if commandName == "/settings" {
					promptMessageID = sendSettingsMenu(token, adminID, promptMessageID)
				}
				continue
			}

			if waitingForClientImport {
				deleteTelegramMessage(token, adminID, msg.MessageID)
				payload, err := decodeClientTransfer(cmd)
				if err != nil {
					promptMessageID = sendOrEditTelegram(token, adminID, promptMessageID, "❌ "+mdCode(err.Error())+"\n\nОтправьте корректный код переноса клиента.", inlineKeyboard(
						[]map[string]interface{}{inlineButton("Отмена", "backlist")},
					))
					continue
				}
				dbMutex.Lock()
				if cleanupExpiredPasswordsLocked(wgDev) > 0 {
					saveDB()
				}
				_, duplicate := db.Passwords[payload.Password]
				mainConflict := payload.Password == db.MainPassword
				limitReached := len(db.Passwords) >= maxGeneratedPasswords
				dbMutex.Unlock()
				if duplicate || mainConflict || limitReached {
					reason := "на новом сервере уже есть клиент с таким паролем"
					if mainConflict {
						reason = "пароль клиента совпадает с главным паролем нового сервера"
					} else if limitReached {
						reason = "на новом сервере достигнут лимит клиентов"
					}
					promptMessageID = sendOrEditTelegram(token, adminID, promptMessageID, "❌ Импорт невозможен: "+reason+".", inlineKeyboard(
						[]map[string]interface{}{inlineButton("📥 Другой клиент", "import_client")},
						[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
					))
					continue
				}
				waitingForClientImport = false
				pendingClientImport = &payload
				promptMessageID = showBotClientImportPreview(token, adminID, promptMessageID, payload)
				continue
			}

			if waitingForNewClientPassword {
				deleteTelegramMessage(token, adminID, msg.MessageID)
				if _, err := normalizeClientPassword(cmd); err != nil {
					promptMessageID = sendOrEditTelegram(token, adminID, promptMessageID, "❌ "+mdCode(err.Error())+"\n\nВведите пароль ещё раз.", inlineKeyboard(
						[]map[string]interface{}{inlineButton("◀️ Отмена", "mainmenu")},
					))
					continue
				}
				password, entry, err := createBotClient(wgDev, cmd, tempDays, -1, tempLabel, tempHash, tempPorts, false)
				if err != nil {
					promptMessageID = sendOrEditTelegram(token, adminID, promptMessageID, "❌ Клиент не создан: "+mdCode(err.Error()), inlineKeyboard(
						[]map[string]interface{}{inlineButton("Повторить", "menu_new")},
						[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
					))
					continue
				}
				waitingForNewClientPassword = false
				promptMessageID = sendBotClientCreated(token, adminID, promptMessageID, password, entry, false)
				continue
			}

			if waitingForSetting != "" {
				deleteTelegramMessage(token, adminID, msg.MessageID)
				mode := waitingForSetting
				waitingForSetting = ""

				switch mode {
				case "dns":
					dnsValue, err := normalizeDNSInput(cmd)
					if err != nil {
						waitingForSetting = "dns"
						promptMessageID = sendOrEditTelegram(token, adminID, promptMessageID, fmt.Sprintf("❌ %s.\n\nВведите DNS ещё раз, например: `1.1.1.1,8.8.8.8`.", err.Error()), inlineKeyboard(
							[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
						))
						continue
					}
					dbMutex.Lock()
					db.DNS = dnsValue
					setServerDNS(dnsValue)
					saveDB()
					dbMutex.Unlock()
					promptMessageID = sendSettingsMenu(token, adminID, promptMessageID)
					continue
				case "limit":
					limit, err := strconv.Atoi(cmd)
					if err != nil || limit < 1 || limit > 500 {
						waitingForSetting = "limit"
						promptMessageID = sendOrEditTelegram(token, adminID, promptMessageID, "❌ Введите число от `1` до `500`.", inlineKeyboard(
							[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
						))
						continue
					}
					dbMutex.Lock()
					maxGeneratedPasswords = limit
					db.MaxPasswords = limit
					saveDB()
					dbMutex.Unlock()
					promptMessageID = sendSettingsMenu(token, adminID, promptMessageID)
					continue
				case "default_ports":
					ports, err := parsePortsSpec(cmd)
					if err != nil {
						waitingForSetting = "default_ports"
						promptMessageID = sendOrEditTelegram(token, adminID, promptMessageID, fmt.Sprintf("❌ %s.\n\nФормат: `56000,56001,9000`.", err.Error()), inlineKeyboard(
							[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
						))
						continue
					}
					dbMutex.Lock()
					db.DefaultPorts = ports
					setServerDefaultPorts(ports)
					saveDB()
					dbMutex.Unlock()
					promptMessageID = sendSettingsMenu(token, adminID, promptMessageID)
					continue
				case "public_ip":
					ip, err := normalizePublicAddressInput(cmd)
					if err != nil {
						waitingForSetting = "public_ip"
						promptMessageID = sendOrEditTelegram(token, adminID, promptMessageID, fmt.Sprintf("❌ %s.", err.Error()), inlineKeyboard(
							[]map[string]interface{}{inlineButton("Определять автоматически", "set_public_ip_auto")},
							[]map[string]interface{}{inlineButton("◀️ Назад", "settings")},
						))
						continue
					}
					dbMutex.Lock()
					db.PublicIP = ip
					setServerPublicIPOverride(ip)
					publicIP = ""
					saveDB()
					dbMutex.Unlock()
					promptMessageID = sendSettingsMenu(token, adminID, promptMessageID)
					continue
				case "owner_hash":
					hash, err := normalizeVKHashesInput(cmd)
					if err != nil {
						waitingForSetting = "owner_hash"
						promptMessageID = sendOrEditTelegram(token, adminID, promptMessageID, fmt.Sprintf("❌ %s\n\nОтправьте VK-хеши владельца ещё раз.", err.Error()), inlineKeyboard(
							[]map[string]interface{}{inlineButton("◀️ Назад", "settings_owner_profile")},
						))
						continue
					}
					dbMutex.Lock()
					db.AdminProfile.VkHashes = hash
					db.AdminProfile.UpdatedAt = time.Now().Unix()
					saveDB()
					dbMutex.Unlock()
					promptMessageID = sendOwnerProfileMenu(token, adminID, promptMessageID)
					continue
				case "owner_ports":
					ports, err := parsePortsSpec(cmd)
					if err != nil {
						waitingForSetting = "owner_ports"
						promptMessageID = sendOrEditTelegram(token, adminID, promptMessageID, fmt.Sprintf("❌ %s.\n\nУкажите 3 порта через запятую, например: `56000,56001,9000`.", err.Error()), inlineKeyboard(
							[]map[string]interface{}{inlineButton("Стандартные", "owner_ports_default")},
							[]map[string]interface{}{inlineButton("◀️ Назад", "settings_owner_profile")},
						))
						continue
					}
					dbMutex.Lock()
					db.AdminProfile.Ports = ports
					db.AdminProfile.ListenPort = adminProfileDefaultListenPort(ports)
					db.AdminProfile.UpdatedAt = time.Now().Unix()
					saveDB()
					dbMutex.Unlock()
					promptMessageID = sendOwnerProfileMenu(token, adminID, promptMessageID)
					continue
				case "outbound_external_check", "outbound_external_enable":
					kind, host, port, login, password, err := parseExternalProxyInput(cmd)
					if err != nil {
						waitingForSetting = mode
						promptMessageID = sendOrEditTelegram(token, adminID, promptMessageID, fmt.Sprintf("❌ %s.\n\nПример с паролем: `socks5 proxy.example.com 1080 ivan secret123`\nПример без пароля: `http proxy.example.com 8080 - -`.", err.Error()), inlineKeyboard(
							[]map[string]interface{}{inlineButton("◀️ Назад", "out_external")},
						))
						continue
					}
					if mode == "outbound_external_check" {
						promptMessageID = sendOrEditTelegram(token, adminID, promptMessageID, "🧪 Проверяю внешний прокси...", nil)
						out, err := runBotScript(externalProxyCheckScript(kind, host, port, login, password), 25*time.Second)
						promptMessageID = sendBotScriptResult(token, adminID, promptMessageID, "Проверка внешнего прокси", out, err, "out_external")
						continue
					}
					promptMessageID = sendOrEditTelegram(token, adminID, promptMessageID, "🌍 Проверяю и включаю внешний прокси для WDTT-пользователей...", nil)
					checkOut, checkErr := runBotScript(externalProxyCheckScript(kind, host, port, login, password), 25*time.Second)
					if checkErr != nil {
						promptMessageID = sendBotScriptResult(token, adminID, promptMessageID, "Внешний прокси не включён", checkOut, checkErr, "out_external")
						continue
					}
					out, err := runBotScript(externalProxyEnableScript(kind, host, port, login, password), 180*time.Second)
					if strings.TrimSpace(checkOut) != "" {
						out = strings.TrimSpace(checkOut) + "\n" + strings.TrimSpace(out)
					}
					promptMessageID = sendBotScriptResult(token, adminID, promptMessageID, "Внешний прокси включён", out, err, "settings_outbound")
					continue
				}
			}

			// Обработка ввода количества дней
			if editMode != "" {
				deleteTelegramMessage(token, adminID, msg.MessageID)
				pass := editPassword
				mode := editMode
				editMode = ""
				editPassword = ""
				if mode == "password" {
					newPassword, err := normalizeClientPassword(cmd)
					if err != nil {
						editMode = "password"
						editPassword = pass
						promptMessageID = sendOrEditTelegram(token, adminID, promptMessageID, "❌ "+mdCode(err.Error())+"\n\nВведите новый пароль ещё раз.", inlineKeyboard(
							[]map[string]interface{}{inlineButton("Отмена", "editpass_"+pass)},
						))
						continue
					}
					dbMutex.Lock()
					_, oldExists := db.Passwords[pass]
					_, duplicate := db.Passwords[newPassword]
					mainConflict := newPassword == db.MainPassword
					dbMutex.Unlock()
					if !oldExists || duplicate || mainConflict || newPassword == pass {
						reason := "новый пароль совпадает с текущим"
						if !oldExists {
							reason = "клиент не найден"
						} else if duplicate {
							reason = "клиент с таким паролем уже существует"
						} else if mainConflict {
							reason = "пароль совпадает с главным паролем"
						}
						promptMessageID = sendOrEditTelegram(token, adminID, promptMessageID, "❌ "+reason+".", inlineKeyboard(
							[]map[string]interface{}{inlineButton("Попробовать снова", "change_pass_manual_"+pass)},
							[]map[string]interface{}{inlineButton("Отмена", "editpass_"+pass)},
						))
						continue
					}
					pendingPasswordChangeOld = pass
					pendingPasswordChangeNew = newPassword
					promptMessageID = sendOrEditTelegram(token, adminID, promptMessageID,
						fmt.Sprintf("⚠️ Заменить пароль клиента `%s` на `%s`?\n\nТекущее соединение завершится, старые ссылки перестанут работать. Остальные клиенты не затрагиваются.", mdCode(pass), mdCode(newPassword)),
						inlineKeyboard(
							[]map[string]interface{}{inlineButton("Изменить", "confirm_change_password")},
							[]map[string]interface{}{inlineButton("Отмена", "editpass_"+pass)},
						),
					)
					continue
				}

				dbMutex.Lock()
				entry, exists := db.Passwords[pass]
				if !exists || entry == nil {
					dbMutex.Unlock()
					promptMessageID = sendOrEditTelegram(token, adminID, promptMessageID, "❌ Пароль не найден", inlineKeyboard(
						[]map[string]interface{}{inlineButton("🔐 К списку", "backlist")},
					))
					continue
				}

				switch mode {
				case "label":
					if strings.TrimSpace(cmd) == "-" {
						entry.Label = ""
					} else {
						entry.Label = normalizePasswordLabel(cmd)
					}
					saveDB()
					dbMutex.Unlock()
					promptMessageID = showPasswordEditMenu(token, adminID, promptMessageID, pass)
					continue
				case "expires":
					days, err := strconv.Atoi(cmd)
					if err != nil || days < 0 || days > 365 {
						dbMutex.Unlock()
						editMode = "expires"
						editPassword = pass
						promptMessageID = sendOrEditTelegram(token, adminID, promptMessageID, "❌ Неверное значение.\n\nВведите `0` для бессрочного срока или число от `1` до `365`.", inlineKeyboard(
							[]map[string]interface{}{inlineButton("◀️ Назад", "edit_exp_"+pass)},
						))
						continue
					}
					if days == 0 {
						entry.ExpiresAt = 0
					} else {
						entry.ExpiresAt = time.Now().Add(time.Duration(days) * 24 * time.Hour).Unix()
					}
					saveDB()
					dbMutex.Unlock()
					promptMessageID = showPasswordEditMenu(token, adminID, promptMessageID, pass)
					continue
				case "hash":
					hash, err := normalizeVKHashesInput(cmd)
					if err != nil {
						dbMutex.Unlock()
						editMode = "hash"
						editPassword = pass
						promptMessageID = sendOrEditTelegram(token, adminID, promptMessageID, fmt.Sprintf("❌ %s\n\nОтправьте VK-хеш или ссылку ещё раз.", err.Error()), inlineKeyboard(
							[]map[string]interface{}{inlineButton("◀️ Назад", "editpass_"+pass)},
						))
						continue
					}
					entry.VkHash = hash
					saveDB()
					dbMutex.Unlock()
					promptMessageID = showPasswordEditMenu(token, adminID, promptMessageID, pass)
					continue
				case "ports":
					ports, err := parsePortsSpec(cmd)
					if err != nil {
						dbMutex.Unlock()
						editMode = "ports"
						editPassword = pass
						promptMessageID = sendOrEditTelegram(token, adminID, promptMessageID, fmt.Sprintf("❌ %s.\n\nУкажите 3 порта через запятую, например: `56000,56001,9000`", err.Error()), inlineKeyboard(
							[]map[string]interface{}{inlineButton("Стандартные", "set_ports_def_"+pass)},
							[]map[string]interface{}{inlineButton("◀️ Назад", "editpass_"+pass)},
						))
						continue
					}
					entry.Ports = ports
					saveDB()
					dbMutex.Unlock()
					promptMessageID = showPasswordEditMenu(token, adminID, promptMessageID, pass)
					continue
				default:
					dbMutex.Unlock()
				}
			}

			if waitingForDays {
				waitingForDays = false
				deleteTelegramMessage(token, adminID, msg.MessageID)
				days, parseErr := strconv.Atoi(cmd)
				if parseErr != nil || days < 0 || days > 365 {
					waitingForDays = true
					promptMessageID = sendOrEditTelegram(token, adminID, promptMessageID, "❌ Неверное значение.\n\nВведите `0` для бессрочного пароля или число от `1` до `365`.", inlineKeyboard(
						[]map[string]interface{}{inlineButton("Выбрать срок кнопкой", "menu_new")},
						[]map[string]interface{}{inlineButton("◀️ Назад", "mainmenu")},
					))
					continue
				}
				tempDays = days

				promptMessageID = showLabelMenu(token, adminID, promptMessageID)
				continue
			}

			if waitingForLabel {
				waitingForLabel = false
				deleteTelegramMessage(token, adminID, msg.MessageID)
				tempLabel = normalizePasswordLabel(cmd)
				promptMessageID = showPortsMenu(token, adminID, promptMessageID, false)
				continue
			}

			if waitingForPorts {
				deleteTelegramMessage(token, adminID, msg.MessageID)
				ports, err := parsePortsSpec(cmd)
				if err != nil {
					promptMessageID = sendOrEditTelegram(token, adminID, promptMessageID, fmt.Sprintf("❌ %s.\n\nУкажите 3 порта через запятую, например: `56000,56001,9000`", err.Error()), inlineKeyboard(
						[]map[string]interface{}{inlineButton("Стандартные порты", "ports_def")},
						[]map[string]interface{}{inlineButton("◀️ Назад", "mainmenu")},
					))
					continue
				}

				waitingForPorts = false
				waitingForLabel = false
				tempPorts = ports
				waitingForHash = true
				promptMessageID = sendOrEditTelegram(token, adminID, promptMessageID, "🔑 Отправьте VK-хеш или ссылку приглашения.\n\nМожно несколько значений через пробел, запятую или новую строку.", inlineKeyboard(
					[]map[string]interface{}{inlineButton("◀️ Назад", "mainmenu")},
				))
				continue
			}

			if waitingForHash {
				deleteTelegramMessage(token, adminID, msg.MessageID)
				hash, err := normalizeVKHashesInput(cmd)
				if err != nil {
					promptMessageID = sendOrEditTelegram(token, adminID, promptMessageID, fmt.Sprintf("❌ %s\n\nОтправьте VK-хеш или ссылку приглашения ещё раз.", err.Error()), inlineKeyboard(
						[]map[string]interface{}{inlineButton("◀️ Назад", "mainmenu")},
					))
					continue
				}
				waitingForHash = false

				if targetPassword == "main" {
					targetPassword = ""
					srvIP := getPublicIP()
					pts := strings.Split(tempPorts, ",")
					dbMutex.Lock()
					db.AdminProfile.VkHashes = hash
					db.AdminProfile.Ports = tempPorts
					db.AdminProfile.ListenPort = adminProfileDefaultListenPort(tempPorts)
					db.AdminProfile.UpdatedAt = time.Now().Unix()
					mainPassword := db.MainPassword
					saveDB()
					dbMutex.Unlock()
					link := fmt.Sprintf("wdtt://%s:%s:%s:%s:%s:%s", srvIP, pts[0], pts[1], pts[2], mainPassword, hash)
					promptMessageID = sendOrEditTelegram(token, adminID, promptMessageID, fmt.Sprintf("🔗 *Ссылка для главного пароля:*\n`%s`", mdCode(link)), inlineKeyboard(
						[]map[string]interface{}{inlineButton("👤 Профиль владельца", "settings_owner_profile")},
						[]map[string]interface{}{inlineButton("◀️ Главное меню", "mainmenu")},
					))
					continue
				}

				tempHash = hash
				promptMessageID = showNewClientPasswordMode(token, adminID, promptMessageID)
				continue
			}
		}
	}
}

func sendPasswordList(token string, adminID int64, wgDev *device.Device, messageID int) int {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	// Очистка истёкших
	if cleanupExpiredPasswordsLocked(wgDev) > 0 {
		saveDB()
	}

	txt := "🔐 *Клиентские доступы:*\n\n"

	var inlineKb []map[string]interface{}

	if len(db.Passwords) == 0 {
		txt += "_Нет сгенерированных паролей._\n"
	} else {
		txt += fmt.Sprintf("_Активно: %d/%d_\n\n", len(db.Passwords), maxGeneratedPasswords)
		for p, entry := range db.Passwords {
			status := "🟢"
			if entry.DeviceID != "" {
				status = "🔗"
			}
			expiry := "♾"
			if entry.ExpiresAt > 0 {
				remaining := time.Until(time.Unix(entry.ExpiresAt, 0))
				if remaining > 0 {
					expiry = fmt.Sprintf("%dd", int(remaining.Hours()/24)+1)
				} else {
					expiry = "❌"
				}
			}
			label := p
			if entry.Label != "" {
				label = fmt.Sprintf("%s — %s", entry.Label, p)
			}
			txt += fmt.Sprintf("%s `%s` (%s)\n", status, mdCode(label), expiry)
			buttonText := "🔍 " + p
			if entry.Label != "" {
				buttonText = "🔍 " + entry.Label
			}
			inlineKb = append(inlineKb, map[string]interface{}{
				"text":          buttonText,
				"callback_data": "viewpass_" + p,
			})
		}
	}

	txt += "\n🟢 = свободен | 🔗 = привязан"

	var keyboard [][]map[string]interface{}
	if len(inlineKb) > 0 {
		for _, btn := range inlineKb {
			keyboard = append(keyboard, []map[string]interface{}{btn})
		}
	}
	keyboard = append(keyboard, []map[string]interface{}{inlineButton("➕ Новый пароль", "menu_new")})
	keyboard = append(keyboard, []map[string]interface{}{inlineButton("📥 Импорт клиента", "import_client")})
	keyboard = append(keyboard, []map[string]interface{}{inlineButton("◀️ Главное меню", "mainmenu")})
	replyMarkup := map[string]interface{}{"inline_keyboard": keyboard}
	return sendOrEditTelegram(token, adminID, messageID, txt, replyMarkup)
}

func answerCallback(token, callbackID string) {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/answerCallbackQuery", token)
	payload := map[string]interface{}{"callback_query_id": callbackID}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err == nil && resp != nil {
		resp.Body.Close()
	}
}

func maskPassword(pass string) string {
	if len(pass) <= 3 {
		return pass
	}
	return pass[:3] + "****"
}

func sendTelegram(token string, chatID int64, text string, replyMarkup interface{}) {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "Markdown",
	}
	if replyMarkup != nil {
		payload["reply_markup"] = replyMarkup
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err == nil && resp != nil {
		resp.Body.Close()
	}
}

func sendTelegramWithMessageID(token string, chatID int64, text string, replyMarkup interface{}) int {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "Markdown",
	}
	if replyMarkup != nil {
		payload["reply_markup"] = replyMarkup
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil || resp == nil {
		return 0
	}
	defer resp.Body.Close()

	var result struct {
		Ok     bool `json:"ok"`
		Result struct {
			MessageID int `json:"message_id"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || !result.Ok {
		return 0
	}
	return result.Result.MessageID
}

func sendOrEditTelegram(token string, chatID int64, messageID int, text string, replyMarkup interface{}) int {
	if messageID <= 0 {
		return sendTelegramWithMessageID(token, chatID, text, replyMarkup)
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/editMessageText", token)
	payload := map[string]interface{}{
		"chat_id":    chatID,
		"message_id": messageID,
		"text":       text,
		"parse_mode": "Markdown",
	}
	if replyMarkup != nil {
		payload["reply_markup"] = replyMarkup
	} else {
		payload["reply_markup"] = map[string]interface{}{"inline_keyboard": []interface{}{}}
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil || resp == nil {
		return sendTelegramWithMessageID(token, chatID, text, replyMarkup)
	}
	defer resp.Body.Close()

	var result struct {
		Ok          bool   `json:"ok"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return sendTelegramWithMessageID(token, chatID, text, replyMarkup)
	}
	if result.Ok || strings.Contains(result.Description, "message is not modified") {
		return messageID
	}
	return sendTelegramWithMessageID(token, chatID, text, replyMarkup)
}

func deleteTelegramMessage(token string, chatID int64, messageID int) {
	if messageID <= 0 {
		return
	}
	url := fmt.Sprintf("https://api.telegram.org/bot%s/deleteMessage", token)
	payload := map[string]interface{}{
		"chat_id":    chatID,
		"message_id": messageID,
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err == nil && resp != nil {
		resp.Body.Close()
	}
}
