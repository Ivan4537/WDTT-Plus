package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type CaptchaResult struct {
	RequestID string
	Value     string
}

// CaptchaResultChan — канал для получения токена капчи из внешнего решателя (WebView)
var CaptchaResultChan = make(chan CaptchaResult, 8)
var captchaRequestSequence atomic.Uint64
var captchaResultWaiters = struct {
	sync.Mutex
	byRequestID map[string]chan CaptchaResult
}{
	byRequestID: make(map[string]chan CaptchaResult),
}

var captchaModeValue atomic.Value
var vkCallsPreflightEnabled atomic.Bool
var vkCallsDeviceID atomic.Value

func init() {
	captchaModeValue.Store("auto")
	vkCallsPreflightEnabled.Store(true)
	vkCallsDeviceID.Store("unknown")
}

func normalizeCaptchaMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "auto", "rjs", "wv":
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return "auto"
	}
}

func setCaptchaMode(mode string) string {
	normalized := normalizeCaptchaMode(mode)
	captchaModeValue.Store(normalized)
	return normalized
}

func getCaptchaMode() string {
	mode, _ := captchaModeValue.Load().(string)
	if mode == "" {
		return "auto"
	}
	return mode
}

func setVKCallsPreflight(enabled bool, deviceID string) {
	vkCallsPreflightEnabled.Store(enabled)
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		deviceID = "unknown"
	}
	vkCallsDeviceID.Store(deviceID)
}

func getVKCallsDeviceID() string {
	deviceID, _ := vkCallsDeviceID.Load().(string)
	if deviceID == "" {
		return "unknown"
	}
	return deviceID
}

func normalizeBooleanFlagArgs(args []string, flagName string) []string {
	result := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == flagName && i+1 < len(args) {
			value := strings.ToLower(strings.TrimSpace(args[i+1]))
			if value == "true" || value == "false" {
				result = append(result, flagName+"="+value)
				i++
				continue
			}
		}
		result = append(result, args[i])
	}
	return result
}

func runHashChecks(ctx context.Context, hashes []string) {
	log.Printf("[CHECK] Проверка VK-хешей: %d", len(hashes))
	for i, hash := range hashes {
		fmt.Printf("HASH_CHECK_START|%d|%s\n", i+1, hash)
		checkCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		_, _, turnURLs, err := GetCreds(checkCtx, hash, 9000+i)
		cancel()

		status, message := classifyHashCheckError(err)
		if err == nil {
			status = "ok"
			message = fmt.Sprintf("TURN urls=%d", len(turnURLs))
		}
		fmt.Printf("HASH_CHECK|%d|%s|%s|%s\n", i+1, hash, status, sanitizeHashCheckMessage(message))
	}
}

func classifyHashCheckError(err error) (string, string) {
	if err == nil {
		return "ok", ""
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "captcha_required") || strings.Contains(text, "captcha_wait_required"):
		return "captcha", "VK просит капчу"
	case strings.Contains(text, "call not found") ||
		strings.Contains(text, "joinconversationbylink") ||
		strings.Contains(text, "missing turn_server") ||
		strings.Contains(text, "9000"):
		return "dead", "Звонок не найден или закрыт"
	case strings.Contains(text, "flood") || strings.Contains(text, "rate limit") || strings.Contains(text, "error_code:29"):
		return "limited", "VK временно ограничил запросы"
	case strings.Contains(text, "timeout") || strings.Contains(text, "deadline") || strings.Contains(text, "lookup") || strings.Contains(text, "network"):
		return "network", "Сетевая ошибка"
	default:
		return "error", err.Error()
	}
}

func sanitizeHashCheckMessage(message string) string {
	message = strings.ReplaceAll(message, "\n", " ")
	message = strings.ReplaceAll(message, "\r", " ")
	message = strings.ReplaceAll(message, "|", "/")
	if len(message) > 180 {
		return message[:180]
	}
	return message
}

func nextCaptchaRequestID(streamID int) string {
	return fmt.Sprintf("%d-%d", streamID, captchaRequestSequence.Add(1))
}

func parseCaptchaResultPayload(payload string) CaptchaResult {
	parts := strings.SplitN(payload, "|", 2)
	if len(parts) == 2 && strings.TrimSpace(parts[0]) != "" {
		return CaptchaResult{RequestID: strings.TrimSpace(parts[0]), Value: strings.TrimSpace(parts[1])}
	}
	return CaptchaResult{Value: strings.TrimSpace(payload)}
}

func captchaResultMatchesRequest(result CaptchaResult, requestID string) bool {
	return result.RequestID == "" || result.RequestID == requestID
}

func registerCaptchaResultWaiter(requestID string) (<-chan CaptchaResult, func()) {
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return CaptchaResultChan, func() {}
	}

	ch := make(chan CaptchaResult, 1)
	captchaResultWaiters.Lock()
	captchaResultWaiters.byRequestID[requestID] = ch
	captchaResultWaiters.Unlock()

	cleanup := func() {
		captchaResultWaiters.Lock()
		if captchaResultWaiters.byRequestID[requestID] == ch {
			delete(captchaResultWaiters.byRequestID, requestID)
		}
		captchaResultWaiters.Unlock()
	}
	return ch, cleanup
}

func deliverCaptchaResult(ch chan CaptchaResult, result CaptchaResult) bool {
	select {
	case ch <- result:
		return true
	default:
		return false
	}
}

func enqueueCaptchaResult(result CaptchaResult) {
	if result.RequestID != "" {
		captchaResultWaiters.Lock()
		ch := captchaResultWaiters.byRequestID[result.RequestID]
		captchaResultWaiters.Unlock()
		if ch == nil {
			log.Printf("[КАПЧА] Запоздалый результат без активного ожидателя request=%q", result.RequestID)
			return
		}
		if !deliverCaptchaResult(ch, result) {
			log.Printf("[КАПЧА] Очередь результата заполнена request=%q", result.RequestID)
		}
		return
	}

	select {
	case CaptchaResultChan <- result:
		return
	default:
	}
	select {
	case <-CaptchaResultChan:
	default:
	}
	select {
	case CaptchaResultChan <- result:
	default:
	}
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	os.Args = normalizeBooleanFlagArgs(os.Args, "-vkcalls-preflight")

	setupGlobalResolver()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Сигналы
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		select {
		case s := <-sig:
			log.Printf("[КЛИЕНТ] Сигнал %v, завершаю...", s)
			cancel()
		case <-ctx.Done():
			return
		}
		select {
		case s := <-sig:
			log.Printf("[КЛИЕНТ] Повторный %v, принудительный выход", s)
			os.Exit(1)
		case <-ctx.Done():
		}
	}()

	var pauseFlag int32

	// STDIN для PAUSE/RESUME/STOP и CAPTCHA_RESULT
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if !strings.Contains(line, "error:tunnel stopped") {
				log.Printf("[STDIN] %s", line)
			}
			switch {
			case line == "PAUSE":
				atomic.StoreInt32(&pauseFlag, 1)
			case line == "RESUME":
				atomic.StoreInt32(&pauseFlag, 0)
			case line == "STOP":
				cancel()
				return
			case strings.HasPrefix(line, "CAPTCHA_RESULT|"):
				result := parseCaptchaResultPayload(strings.TrimPrefix(line, "CAPTCHA_RESULT|"))
				enqueueCaptchaResult(result)
				log.Printf("[КАПЧА] Результат от Kotlin принят (request=%q)", result.RequestID)
			}
		}
	}()

	ppid := os.Getppid()
	go func() {
		for {
			time.Sleep(2 * time.Second)
			if os.Getppid() != ppid {
				os.Exit(0)
			}
		}
	}()

	host := flag.String("turn", "", "переопределить IP TURN")
	port := flag.String("port", "", "переопределить порт TURN")
	listen := flag.String("listen", "127.0.0.1:9000", "локальный адрес")
	vkHash := flag.String("vk", "", "хеши VK-звонков (через запятую)")
	peerAddr := flag.String("peer", "", "адрес:порт VPS сервера")
	numW := flag.Int("n", 24, "количество воркеров (кратно 9)")
	checkHashes := flag.Bool("check-hashes", false, "проверить VK-хеши и выйти")

	deviceID := flag.String("device-id", "unknown", "уникальный ID устройства")
	deviceInfo := flag.String("device-info", "", "JSON с безопасной информацией об устройстве")
	connPassword := flag.String("password", "", "пароль подключения")
	captchaMode := flag.String("captcha-mode", "auto", "режим обхода капчи (auto/wv/rjs)")
	vkCallsPreflight := flag.Bool("vkcalls-preflight", true, "пробовать VKCalls до captcha-цепочки")
	fingerprint := flag.String("fingerprint", "firefox", "браузерный фингерпринт (firefox, chrome, safari, ios, android)")
	clientIdsFlag := flag.String("client-ids", "", "ID клиентов VK через запятую")

	flag.Parse()
	activeCaptchaMode := setCaptchaMode(*captchaMode)
	setVKCallsPreflight(*vkCallsPreflight, *deviceID)

	if *vkHash == "" {
		log.Fatal("[КЛИЕНТ] Нужен -vk")
	}

	if *fingerprint != "" {
		SetActiveFingerprint(*fingerprint)
	}
	if *clientIdsFlag != "" {
		SetActiveClientIds(*clientIdsFlag)
	}

	hashes := ParseHashes(*vkHash)
	if len(hashes) == 0 {
		log.Fatal("[КЛИЕНТ] Нет хешей VK")
	}

	if *checkHashes {
		SetHashCheckMode(true)
		runHashChecks(ctx, hashes)
		return
	}

	if *peerAddr == "" {
		log.Fatal("[КЛИЕНТ] Нужен -peer")
	}

	cleanPeerAddr := strings.TrimSpace(*peerAddr)
	var err error
	var peer *net.UDPAddr
	for i := 0; i < 15; i++ {
		peer, err = net.ResolveUDPAddr("udp", cleanPeerAddr)
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		log.Fatalf("[КЛИЕНТ] Ошибка разбора пира: %v", err)
	}

	if *connPassword == "" {
		log.Fatal("[КЛИЕНТ] Нужен -password: WRAP ключ теперь выводится из пароля подключения")
	}

	// WRAP key
	wrapKey, err := deriveWrapKey(*connPassword)
	if err != nil {
		log.Fatalf("[КЛИЕНТ] WRAP key derive: %v", err)
	}

	// Лимит воркеров
	maxWorkers := 108
	if *numW > maxWorkers {
		*numW = maxWorkers
	}
	if *numW < workersPerGroup {
		*numW = workersPerGroup
	}
	*numW = (*numW / workersPerGroup) * workersPerGroup

	tp := &TurnParams{
		Host:    *host,
		Port:    *port,
		Hashes:  hashes,
		WrapKey: wrapKey,
	}

	// Слушаем локально с ожиданием (если старый процесс еще не убит Parent Watcher'ом)
	var localConn net.PacketConn
	actualListenAddr := *listen
	for i := 0; i < 5; i++ {
		localConn, err = net.ListenPacket("udp", actualListenAddr)
		if err == nil {
			break
		}
		log.Printf("[ОЖИДАНИЕ] Порт %s занят (возможно, старый процесс завершается). Жду... (%d/5)", actualListenAddr, i+1)
		time.Sleep(1 * time.Second)
	}

	if err != nil {
		log.Printf("[АВТО-ПОРТ] Порт %s всё ещё занят. Пробую случайный динамический порт...", actualListenAddr)
		actualListenAddr = "127.0.0.1:0"
		localConn, err = net.ListenPacket("udp", actualListenAddr)
		if err != nil {
			log.Fatalf("[ФАТАЛ] Ошибка бинда динамического порта: %v", err)
		}
	}
	if uc, ok := localConn.(*net.UDPConn); ok {
		_ = uc.SetReadBuffer(socketBufSize)
		_ = uc.SetWriteBuffer(socketBufSize)
	}
	stopLocalConn := context.AfterFunc(ctx, func() { _ = localConn.Close() })
	defer stopLocalConn()

	_, localPort, _ := net.SplitHostPort(localConn.LocalAddr().String())
	if localPort == "" {
		localPort = "9000"
	}

	numGroups := *numW / workersPerGroup

	wrapStatus := "OFF"
	if len(wrapKey) == wrapKeyLen {
		wrapStatus = "ON (password HKDF + RTP AEAD)"
	}

	captchaStatus := "AUTO: each fresh challenge starts with WBV Auto -> Go v2 -> Manual WBV"
	switch activeCaptchaMode {
	case "wv":
		captchaStatus = "WBV selected in Android"
	case "rjs":
		captchaStatus = "RJS: each fresh challenge starts with WBV Auto -> Go v2 -> Manual WBV"
	}

	log.Println("[КЛИЕНТ] ═══════════════════════════════════════")
	log.Printf("[КЛИЕНТ] VK Creds: Client IDs: %s", GetActiveClientIdsString())
	log.Printf("[КЛИЕНТ] TLS: %s fingerprint", GetActiveFingerprint())
	log.Printf("[КЛИЕНТ] Воркеров: %d (групп: %d, по %d)", *numW, numGroups, workersPerGroup)
	log.Printf("[КЛИЕНТ] Хешей: %d", len(hashes))
	log.Printf("[КЛИЕНТ] Слушаю: %s | Пир: %s", *listen, cleanPeerAddr)
	log.Printf("[КЛИЕНТ] Протокол: UDP")
	log.Printf("[КЛИЕНТ] WRAP: %s", wrapStatus)
	log.Printf("[WRAP] Ключ выведен из пароля, режим RTP AEAD активен")
	log.Printf("[КЛИЕНТ] Device ID: %s", *deviceID)
	log.Printf("[КЛИЕНТ] Captcha: %s", captchaStatus)
	log.Println("[КЛИЕНТ] ═══════════════════════════════════════")

	stats := NewStats()
	shutdownCh := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(shutdownCh)
	}()
	go stats.RunLoop(shutdownCh)

	disp := NewDispatcher(ctx, localConn, stats)
	defer disp.Shutdown()

	configCh := make(chan string, 1)
	configDone := make(chan struct{})
	go func() {
		defer close(configDone)
		select {
		case rawConf, ok := <-configCh:
			if !ok || rawConf == "" {
				return
			}
			finalConf := rawConf
			if !strings.Contains(finalConf, "MTU =") {
				lines := strings.Split(finalConf, "\n")
				var newLines []string
				for _, line := range lines {
					newLines = append(newLines, line)
					if strings.TrimSpace(line) == "[Interface]" {
						newLines = append(newLines, "MTU = 1280")
					}
				}
				finalConf = strings.Join(newLines, "\n")
			}
			fmt.Println()
			fmt.Println("╔══════════════ WireGuard Конфиг ══════════════╗")
			for _, line := range strings.Split(finalConf, "\n") {
				fmt.Printf("║ %-44s ║\n", line)
			}
			fmt.Println("╚══════════════════════════════════════════════╝")
			if err := os.WriteFile("wg-turn.conf", []byte(finalConf+"\n"), 0600); err != nil {
				log.Printf("[КОНФИГ] Ошибка сохранения: %v", err)
			} else {
				log.Println("[КОНФИГ] Сохранён в wg-turn.conf")
			}
		case <-ctx.Done():
		}
	}()

	var wg sync.WaitGroup
	workerIDCounter := 1

	var prevWaitReady <-chan struct{}

	for g := 0; g < numGroups; g++ {
		isFirst := (g == 0)

		var myWaitReady <-chan struct{}
		var mySignalReady chan<- struct{}

		if g > 0 {
			myWaitReady = prevWaitReady
		}
		if g < numGroups-1 {
			ch := make(chan struct{})
			mySignalReady = ch
			prevWaitReady = ch
		}

		ids := make([]int, workersPerGroup)
		for i := range ids {
			ids[i] = workerIDCounter
			workerIDCounter++
		}

		gID := g + 1
		var cc chan<- string
		if isFirst {
			cc = configCh
		}

		wg.Add(1)
		go func(groupID int, isFirstGroup bool, configChan chan<- string, workerIds []int, startHashIndex int, waitR <-chan struct{}, sigR chan<- struct{}) {
			defer wg.Done()
			WorkerGroup(ctx, cancel, groupID, startHashIndex, tp, peer, disp, localPort,
				isFirstGroup, configChan, workerIds, &pauseFlag, *deviceID, *connPassword, *deviceInfo, stats, waitR, sigR)
		}(gID, isFirst, cc, ids, g, myWaitReady, mySignalReady)
	}

	wg.Wait()
	close(configCh)
	<-configDone
	log.Println("[КЛИЕНТ] Все воркеры завершены")
}
