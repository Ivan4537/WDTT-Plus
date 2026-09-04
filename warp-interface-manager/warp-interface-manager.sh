#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

VERSION="1.3.2"
PROGRAM_NAME="Менеджер WARP-маршрутизации"

INSTALL_BIN="/usr/local/sbin/warp-interface-manager"
CONFIG_DIR="/etc/warp-interface-manager"
STATE_FILE="${CONFIG_DIR}/state.env"
OWNER_FILE="${CONFIG_DIR}/owner"
ACCOUNT_FILE="${CONFIG_DIR}/wgcf-account.toml"
RAW_PROFILE="${CONFIG_DIR}/wgcf-profile.raw.conf"
WG_CONFIG="/etc/wireguard/warp-selective.conf"
WG_IFACE="warp-selective"
DATA_DIR="/var/lib/warp-interface-manager"
HEALTH_FILE="${DATA_DIR}/health.env"
LOG_DIR="/var/log/warp-interface-manager"
EVENT_LOG="${LOG_DIR}/events.log"
INSTALL_LOG="${LOG_DIR}/install.log"
RUNTIME_DIR="/run/warp-interface-manager"
RUNTIME_FILE="${RUNTIME_DIR}/runtime.env"
LOCK_FILE="/run/lock/warp-interface-manager.lock"
SYSCTL_FILE="/etc/sysctl.d/90-warp-interface-manager.conf"
SERVICE="warp-interface-manager.service"
CHECK_SERVICE="warp-interface-manager-check.service"
CHECK_TIMER="warp-interface-manager-check.timer"
UNIT_DIR="/etc/systemd/system"
OWNER_VALUE="warp-interface-manager-v1"
RULE_COMMENT="WARP_INTERFACE_MANAGER"
DEFAULT_MTU=1280
SYS_CLASS_NET_ROOT="/sys/class/net"
PROC_SYS_IPV4_CONF_ROOT="/proc/sys/net/ipv4/conf"
WIREGUARD_CONFIG_ROOT="/etc/wireguard"

if [[ ${WIM_TEST_MODE:-0} == "1" ]]; then
    SYS_CLASS_NET_ROOT="${WIM_SYS_CLASS_NET_ROOT:-$SYS_CLASS_NET_ROOT}"
    PROC_SYS_IPV4_CONF_ROOT="${WIM_PROC_SYS_IPV4_CONF_ROOT:-$PROC_SYS_IPV4_CONF_ROOT}"
    WIREGUARD_CONFIG_ROOT="${WIM_WIREGUARD_CONFIG_ROOT:-$WIREGUARD_CONFIG_ROOT}"
fi

WGCF_BIN="/usr/local/lib/warp-interface-manager/wgcf"
WGCF_VERSION_FILE="${CONFIG_DIR}/wgcf-version"
WGCF_REPOSITORY="ViRb3/wgcf"
WGCF_LATEST_API="https://api.github.com/repos/${WGCF_REPOSITORY}/releases/latest"

if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'
    C_BOLD=$'\033[1m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_RED=$'\033[31m'
    C_CYAN=$'\033[36m'
else
    C_RESET=""
    C_BOLD=""
    C_GREEN=""
    C_YELLOW=""
    C_RED=""
    C_CYAN=""
fi

say() { printf '%s\n' "$*"; }
info() { printf '%s%s%s\n' "$C_CYAN" "$*" "$C_RESET"; }
ok() { printf '%s%s%s\n' "$C_GREEN" "$*" "$C_RESET"; }
warn() { printf '%sПредупреждение: %s%s\n' "$C_YELLOW" "$*" "$C_RESET" >&2; }
die() { printf '%sОшибка: %s%s\n' "$C_RED" "$*" "$C_RESET" >&2; exit 1; }

format_server_datetime() {
    local value=${1:-}
    [[ -n "$value" ]] || { printf '—'; return 0; }
    date -d "$value" '+%d.%m.%Y %H:%M:%S %Z (%:z)' 2>/dev/null || printf '%s' "$value"
}

current_log_timestamp() {
    date '+%d.%m.%Y %H:%M:%S %Z (%:z)'
}

format_journal_output() {
    local line timestamp rest
    while IFS= read -r line; do
        timestamp="${line%% *}"
        if [[ "$timestamp" =~ ^[0-9]+([.][0-9]+)?$ && "$line" == *" "* ]]; then
            rest="${line#* }"
            printf '%s %s\n' "$(format_server_datetime "@$timestamp")" "$rest"
        else
            printf '%s\n' "$line"
        fi
    done
}

format_manager_log_output() {
    local line timestamp rest
    while IFS= read -r line; do
        timestamp="${line%% *}"
        if [[ "$timestamp" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[^[:space:]]+$ && "$line" == *" "* ]]; then
            rest="${line#* }"
            printf '%s %s\n' "$(format_server_datetime "$timestamp")" "$rest"
        else
            printf '%s\n' "$line"
        fi
    done
}

init_logging() {
    mkdir -p "$LOG_DIR"
    chmod 700 "$LOG_DIR"
    touch "$EVENT_LOG" "$INSTALL_LOG"
    chmod 600 "$EVENT_LOG" "$INSTALL_LOG"
    if [[ "$(wc -c <"$EVENT_LOG")" -gt 1048576 ]]; then
        mv -f "$EVENT_LOG" "${EVENT_LOG}.1"
        : >"$EVENT_LOG"
        chmod 600 "$EVENT_LOG"
    fi
    if [[ "$(wc -c <"$INSTALL_LOG")" -gt 4194304 ]]; then
        mv -f "$INSTALL_LOG" "${INSTALL_LOG}.1"
        : >"$INSTALL_LOG"
        chmod 600 "$INSTALL_LOG"
    fi
}

log_event() {
    local category=${1:-INFO} message=${2:-}
    [[ ${EUID:-$(id -u)} -eq 0 ]] || return 0
    init_logging
    printf '%s [%s] %s\n' "$(current_log_timestamp)" "$category" "${message//$'\n'/ }" >>"$EVENT_LOG"
}

log_install_header() {
    init_logging
    printf '\n%s [%s] %s\n' "$(current_log_timestamp)" "$PROGRAM_NAME" "$*" >>"$INSTALL_LOG"
}

run_install_logged() {
    local title=$1
    shift
    info "$title"
    log_install_header "$title"
    if "$@" >>"$INSTALL_LOG" 2>&1; then
        log_event "INSTALL" "$title: успешно"
        return 0
    fi
    log_event "ERROR" "$title: ошибка; подробности в $INSTALL_LOG"
    warn "$title — не удалось. Подробности: $INSTALL_LOG"
    return 1
}

usage() {
    cat <<'EOF'
Менеджер WARP-маршрутизации

Использование:
  sudo ./warp-interface-manager.sh
  sudo ./warp-interface-manager.sh install
  sudo warp-interface-manager enable
  sudo warp-interface-manager disable
  sudo warp-interface-manager reconfigure
  sudo warp-interface-manager check
  sudo warp-interface-manager check --repair
  sudo warp-interface-manager status
  sudo warp-interface-manager stats
  sudo warp-interface-manager update-wgcf
  sudo warp-interface-manager remove

Команды:
  scan          Показать доступные и защищённые интерфейсы без изменений.
  install       Установить WARP: один входной интерфейс или весь IPv4 хоста.
  enable        Включить ранее сохранённую конфигурацию.
  disable       Безопасно отключить WARP, сохранив профиль и регистрацию.
  reconfigure   Изменить режим маршрутизации или входной интерфейс.
  check         Проверить конфигурацию и фактический выход через WARP.
  status        Краткое состояние служб и маршрутизации.
  stats         Трафик, рукопожатие, внешний IP и состояние проверки.
  update-wgcf   Найти и безопасно установить последний стабильный wgcf.
  logs          Просмотр событий, установки, службы и автопроверок.
  remove        Полностью удалить созданные WARP-файлы, правила и службы.
  self-test     Локальная самопроверка без изменения системы.

Без параметров открывается русское интерактивное меню.
Доступны выборочная маршрутизация одного ingress-интерфейса и режим всего IPv4 хоста.
Нерекомендуемый интерфейс требует точного подтверждения; lo и warp-selective выбрать нельзя.
EOF
}

require_linux() {
    [[ "$(uname -s)" == "Linux" ]] || die "поддерживается только Linux."
}

require_root() {
    [[ ${EUID:-$(id -u)} -eq 0 ]] || die "эта операция требует root. Запустите через sudo."
}

require_systemd() {
    command -v systemctl >/dev/null 2>&1 || die "systemd не найден."
    [[ -d /run/systemd/system ]] || die "systemd не является активной системой инициализации."
}

acquire_lock() {
    mkdir -p "$(dirname "$LOCK_FILE")"
    if command -v flock >/dev/null 2>&1; then
        exec 9>"$LOCK_FILE"
        flock -n 9 || die "другая операция менеджера уже выполняется."
    else
        mkdir "${LOCK_FILE}.d" 2>/dev/null || die "другая операция менеджера уже выполняется."
        trap 'rmdir "${LOCK_FILE}.d" 2>/dev/null || true' EXIT
    fi
}

is_safe_iface_name() {
    [[ ${1:-} =~ ^[A-Za-z0-9_.-]{1,15}$ ]]
}

is_ipv4_address() {
    local value=${1:-}
    awk -F. '
        NF != 4 { exit 1 }
        {
            for (i=1; i<=4; i++) {
                if ($i !~ /^[0-9]+$/ || $i < 0 || $i > 255) exit 1
            }
        }
    ' <<<"$value"
}

validate_ipv4_list() {
    local value=${1:-} address count=0
    local -a addresses=()
    [[ -n "$value" ]] || return 1
    IFS=',' read -r -a addresses <<<"$value"
    ((${#addresses[@]} >= 1 && ${#addresses[@]} <= 16)) || return 1
    for address in "${addresses[@]}"; do
        is_ipv4_address "$address" || return 1
        count=$((count + 1))
    done
    ((count > 0))
}

default_iface() {
    ip -4 route show table main default 2>/dev/null |
        awk '$1 == "default" { for (i=1; i<=NF; i++) if ($i == "dev") { print $(i+1); exit } }'
}

ssh_iface() {
    local remote route
    remote="${SSH_CONNECTION:-}"
    remote="${remote%% *}"
    [[ -n "$remote" ]] || return 0
    if [[ "$remote" == *:* ]]; then
        route="$(ip -6 route get "$remote" 2>/dev/null | head -n 1 || true)"
    else
        route="$(ip -4 route get "$remote" 2>/dev/null | head -n 1 || true)"
    fi
    awk '{ for (i=1; i<=NF; i++) if ($i == "dev") { print $(i+1); exit } }' <<<"$route"
}

current_ssh_server_port() {
    local connection port
    connection="${SSH_CONNECTION:-}"
    [[ -n "$connection" ]] || return 0
    port="$(awk '{print $4}' <<<"$connection")"
    [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]] && printf '%s\n' "$port"
}

detect_ssh_ports() {
    local unit
    {
        current_ssh_server_port
        if command -v sshd >/dev/null 2>&1; then
            sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' || true
        fi
        if command -v ss >/dev/null 2>&1; then
            ss -H -ltnp 2>/dev/null |
                awk '/users:\(\("sshd"/ { value=$4; sub(/^.*:/, "", value); print value }' || true
        fi
        if command -v systemctl >/dev/null 2>&1; then
            for unit in ssh.socket sshd.socket; do
                systemctl show "$unit" --property=Listen --value 2>/dev/null |
                    tr ' ' '\n' |
                    awk '/^[0-9]+$/ {print; next} /:[0-9]+$/ {sub(/^.*:/, ""); print}' || true
            done
        fi
    } | awk '$1 ~ /^[0-9]+$/ && $1 >= 1 && $1 <= 65535 && !seen[$1]++ {print $1}' |
        sort -n | paste -sd ',' -
}

validate_ssh_ports() {
    local value=$1 port count=0
    local -a ports=()
    [[ "$value" =~ ^[0-9]+(,[0-9]+)*$ ]] || return 1
    IFS=',' read -r -a ports <<<"$value"
    ((${#ports[@]} >= 1 && ${#ports[@]} <= 16)) || return 1
    for port in "${ports[@]}"; do
        [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]] || return 1
        count=$((count + 1))
    done
    ((count > 0))
}

ssh_ports_cover_detected() {
    local detected port
    local -a detected_list=()
    detected="$(detect_ssh_ports)"
    validate_ssh_ports "$detected" || return 1
    IFS=',' read -r -a detected_list <<<"$detected"
    for port in "${detected_list[@]}"; do
        [[ ",$SSH_PORTS," == *",$port,"* ]] || return 1
    done
}

ip_rule_supports_ports() {
    local help
    help="$(ip rule help 2>&1 || true)"
    grep -Eq '(^|[[:space:]])sport([[:space:]]|$)' <<<"$help"
}

foreign_warp_evidence() {
    local unit path config iface lower trace own_profile=0
    if [[ -n ${WIM_TEST_FOREIGN_WARP_EVIDENCE:-} ]]; then
        say "$WIM_TEST_FOREIGN_WARP_EVIDENCE"
    fi
    if [[ -f "$OWNER_FILE" && ! -L "$OWNER_FILE" && "$(<"$OWNER_FILE")" == "$OWNER_VALUE" &&
          -f "$WG_CONFIG" && ! -L "$WG_CONFIG" ]] &&
       grep -q '^# Managed by warp-interface-manager\.' "$WG_CONFIG" 2>/dev/null; then
        own_profile=1
    fi
    if [[ ${WIM_TEST_MODE:-0} != "1" ]]; then
        if command -v warp-cli >/dev/null 2>&1; then
            say "найдена команда warp-cli"
        fi
        if command -v systemctl >/dev/null 2>&1; then
            for unit in warp-svc.service cloudflare-warp.service; do
                if systemctl cat "$unit" >/dev/null 2>&1; then
                    say "найдена сторонняя служба $unit"
                fi
            done
        fi
        if command -v pgrep >/dev/null 2>&1 && pgrep -x warp-svc >/dev/null 2>&1; then
            say "запущен сторонний процесс warp-svc"
        fi
        for path in /etc/cloudflare-warp /var/lib/cloudflare-warp; do
            [[ -e "$path" || -L "$path" ]] && say "найдены данные стороннего клиента: $path"
        done
    fi
    for config in "$WIREGUARD_CONFIG_ROOT"/*.conf; do
        [[ -f "$config" ]] || continue
        if ((own_profile == 1)) && [[ "$config" == "$WG_CONFIG" ]]; then
            continue
        fi
        if [[ "${config##*/}" =~ [Ww][Aa][Rr][Pp]|[Ww][Gg][Cc][Ff] ]] ||
           grep -Eqi 'generated by wgcf|engage\.cloudflareclient\.com|api\.cloudflareclient\.com' "$config" 2>/dev/null; then
            say "найден возможный сторонний WARP-профиль: $config"
        fi
    done
    for path in "$SYS_CLASS_NET_ROOT"/*; do
        [[ -e "$path" ]] || continue
        iface="${path##*/}"
        [[ "$iface" == "$WG_IFACE" && "$own_profile" == "1" ]] && continue
        lower="${iface,,}"
        if [[ "$lower" == *warp* || "$lower" == *wgcf* || "$lower" == cloudflare* ]]; then
            say "найден возможный сторонний WARP-интерфейс: $iface"
        fi
    done
    if [[ ${WIM_TEST_MODE:-0} != "1" ]] && ! is_installed && command -v curl >/dev/null 2>&1; then
        trace="$(curl -4fsS --connect-timeout 3 --max-time 6 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null || true)"
        if grep -Eq '^warp=(on|plus)$' <<<"$trace"; then
            say "текущий общий IPv4-выход уже определяется Cloudflare как WARP"
        fi
    fi
}

assert_no_foreign_warp() {
    local evidence
    evidence="$(foreign_warp_evidence | awk '!seen[$0]++')"
    [[ -z "$evidence" ]] || {
        warn "обнаружена существующая сторонняя установка или активный выход WARP:"
        while IFS= read -r line; do
            say "  • $line"
        done <<<"$evidence"
        die "создание второго WARP-туннеля остановлено. Сначала отключите или удалите сторонний WARP вручную."
    }
}

iface_has_foreign_policy_rules() {
    local iface=$1 own_table="" own_priority=""
    if is_installed; then
        own_table="$(state_get TABLE_ID)"
        own_priority="$(state_get RULE_PRIORITY)"
    fi
    ip -4 rule show 2>/dev/null |
        awk -v iface="$iface" -v own_table="$own_table" -v own_priority="$own_priority" '
            {
                priority=$1; sub(/:$/, "", priority)
                table=""; matched=0
                for (i=1; i<=NF; i++) {
                    if (($i == "iif" || $i == "oif") && $(i+1) == iface) matched=1
                    if ($i == "lookup") table=$(i+1)
                }
                if (!matched) next
                if (own_table ~ /^[0-9]+$/ && own_priority ~ /^[0-9]+$/ &&
                    priority == own_priority + 1 && table == own_table) next
                found=1; exit
            }
            END { exit !found }
        '
}

iface_has_foreign_firewall_rules() {
    local iface=$1
    if command -v iptables-save >/dev/null 2>&1 &&
       iptables-save 2>/dev/null |
           awk -v iface="$iface" -v marker="$RULE_COMMENT" '
               index($0, marker) { next }
               {
                   for (i=1; i<=NF; i++) {
                       if (($i == "-i" || $i == "-o") && $(i+1) == iface) { found=1; exit }
                   }
               }
               END { exit !found }
           '; then
        return 0
    fi
    if command -v nft >/dev/null 2>&1 &&
       nft list ruleset 2>/dev/null |
           awk -v iface="$iface" -v marker="$RULE_COMMENT" '
               index($0, marker) { next }
               {
                   line=$0; gsub(/"/, "", line); count=split(line, values, /[[:space:]]+/)
                   for (i=1; i<=count; i++) {
                       if ((values[i] == "iifname" || values[i] == "oifname") && values[i+1] == iface) {
                           found=1; exit
                       }
                   }
               }
               END { exit !found }
           '; then
        return 0
    fi
    return 1
}

full_host_routing_conflicts() {
    local own_table="" own_priority=""
    if is_installed; then
        own_table="$(state_get TABLE_ID)"
        own_priority="$(state_get RULE_PRIORITY)"
    fi
    ip -4 rule show 2>/dev/null |
        awk -v own_table="$own_table" -v own_priority="$own_priority" '
            {
                priority=$1; sub(/:$/, "", priority)
                table=""
                for (i=1; i<=NF; i++) if ($i == "lookup") table=$(i+1)
                if (priority == 0 || priority == 32766 || priority == 32767) next
                if (own_table ~ /^[0-9]+$/ && own_priority ~ /^[0-9]+$/ && table == own_table &&
                    priority >= own_priority && priority <= own_priority + 1) next
                if (own_table ~ /^[0-9]+$/ && own_priority ~ /^[0-9]+$/ && table == "main" &&
                    priority >= own_priority - 2 && priority <= own_priority - 1) next
                print "существующее IPv4 policy rule с приоритетом " priority
            }
        '
    ip -4 route show table all 2>/dev/null |
        awk -v own_table="$own_table" -v own_iface="$WG_IFACE" '
            $1 == "default" {
                table="main"; dev=""
                for (i=1; i<=NF; i++) {
                    if ($i == "table") table=$(i+1)
                    if ($i == "dev") dev=$(i+1)
                }
                if (table == "main" || table == "default" || table == "local") next
                if (own_table ~ /^[0-9]+$/ && table == own_table && dev == own_iface) next
                print "существующий default route в таблице " table (dev ? " через " dev : "")
            }
        '
}

check_full_host_routing_is_clear() {
    local conflicts
    conflicts="$(full_host_routing_conflicts | awk '!seen[$0]++')"
    [[ -z "$conflicts" ]] || {
        warn "режим всего сервера конфликтует с уже существующей policy routing:"
        while IFS= read -r line; do
            say "  • $line"
        done <<<"$conflicts"
        warn "режим всего сервера остановлен без изменений. Сторонние правила автоматически не удаляются."
        return 1
    }
}

is_default_iface() {
    local iface=$1
    ip -4 route show table all 2>/dev/null |
        awk '$1 == "default" { for (i=1; i<=NF; i++) if ($i == "dev") print $(i+1) }' |
        grep -Fxq "$iface"
}

is_active_wireguard_iface() {
    local iface=$1 peers listen_port
    command -v wg >/dev/null 2>&1 || return 1
    wg show "$iface" >/dev/null 2>&1 || return 1
    peers="$(wg show "$iface" peers 2>/dev/null || true)"
    listen_port="$(wg show "$iface" listen-port 2>/dev/null || true)"
    [[ -n "$peers" || ("$listen_port" =~ ^[0-9]+$ && "$listen_port" -gt 0) ]]
}

iface_master() {
    local iface=$1 master_path details
    master_path="$SYS_CLASS_NET_ROOT/$iface/master"
    if [[ -L "$master_path" ]]; then
        basename "$(readlink -f "$master_path")"
        return 0
    fi
    details="$(ip -o link show dev "$iface" 2>/dev/null | head -n 1 || true)"
    awk '{ for (i=1; i<=NF; i++) if ($i == "master") { print $(i+1); exit } }' <<<"$details"
}

iface_dependents() {
    local iface=$1 path master found=""
    for path in "$SYS_CLASS_NET_ROOT"/*/master; do
        [[ -L "$path" ]] || continue
        master="$(basename "$(readlink -f "$path")")"
        if [[ "$master" == "$iface" ]]; then
            found+="${found:+,}${path%/master}"
        fi
    done
    if [[ -n "$found" ]]; then
        tr ',' '\n' <<<"$found" | sed 's#.*/##' | paste -sd ',' -
        return 0
    fi
    ip -o link show master "$iface" 2>/dev/null |
        awk -F': ' '{print $2}' | awk '{print $1}' | paste -sd ',' -
}

iface_kind_id() {
    local iface=$1 path details ifindex iflink
    [[ -d "$SYS_CLASS_NET_ROOT/$iface" ]] || { printf 'unavailable'; return 0; }
    path="$(readlink -f "$SYS_CLASS_NET_ROOT/$iface" 2>/dev/null || true)"
    details="$(ip -d -o link show dev "$iface" 2>/dev/null | head -n 1 || true)"
    if [[ -e "$SYS_CLASS_NET_ROOT/$iface/tun_flags" ]]; then
        printf 'tuntap'
    elif wg show "$iface" >/dev/null 2>&1 || grep -Eq '(^|[[:space:]])wireguard([[:space:]]|$)' <<<"$details"; then
        printf 'wireguard'
    elif [[ -d "$SYS_CLASS_NET_ROOT/$iface/bridge" ]] || grep -Eq '(^|[[:space:]])bridge([[:space:]]|$)' <<<"$details"; then
        printf 'bridge'
    elif [[ -d "$SYS_CLASS_NET_ROOT/$iface/bonding" ]] || grep -Eq '(^|[[:space:]])bond([[:space:]]|$)' <<<"$details"; then
        printf 'bond'
    elif grep -Eq '(^|[[:space:]])vrf([[:space:]]|$)' <<<"$details"; then
        printf 'vrf'
    elif grep -Eq '(^|[[:space:]])veth([[:space:]]|$)' <<<"$details"; then
        printf 'veth'
    elif [[ "$path" == *'/virtual/'* ]]; then
        ifindex=""
        iflink=""
        [[ ! -r "$SYS_CLASS_NET_ROOT/$iface/ifindex" ]] || ifindex="$(<"$SYS_CLASS_NET_ROOT/$iface/ifindex")"
        [[ ! -r "$SYS_CLASS_NET_ROOT/$iface/iflink" ]] || iflink="$(<"$SYS_CLASS_NET_ROOT/$iface/iflink")"
        if [[ "$ifindex" =~ ^[0-9]+$ && "$iflink" =~ ^[0-9]+$ && "$ifindex" != "$iflink" ]]; then
            printf 'veth'
        else
            printf 'virtual'
        fi
    else
        printf 'physical'
    fi
}

iface_route_summary() {
    local iface=$1
    ip -4 route show table all dev "$iface" 2>/dev/null |
        awk '
            $1 == "local" || $1 == "broadcast" { next }
            NF {
                line=$0
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
                gsub(/[[:space:]]+/, " ", line)
                count++
                if (count <= 2) {
                    if (shown) printf "; "
                    printf "%s", line
                    shown=1
                }
            }
            END {
                if (count == 0) printf "нет"
                else if (count > 2) printf "; +%d", count-2
            }
        '
}

iface_has_custom_ipv4_routes() {
    local iface=$1
    ip -4 route show table all dev "$iface" 2>/dev/null |
        awk '
            $1 == "local" || $1 == "broadcast" { next }
            $1 == "default" { found=1; exit }
            /(^|[[:space:]])proto[[:space:]]+kernel([[:space:]]|$)/ && /(^|[[:space:]])scope[[:space:]]+link([[:space:]]|$)/ { next }
            NF { found=1; exit }
            END { exit !found }
        '
}

iface_is_up() {
    ip link show dev "$1" 2>/dev/null | head -n 1 | grep -Eq '<[^>]*UP[^>]*>'
}

iface_addresses() {
    local value
    value="$(ip -o -4 addr show dev "$1" scope global 2>/dev/null | awk '{print $4}' | paste -sd ',' -)"
    printf '%s' "${value:--}"
}

iface_kind() {
    case "$(iface_kind_id "$1")" in
        tuntap) printf 'TUN/TAP' ;;
        wireguard) printf 'WireGuard' ;;
        veth) printf 'veth' ;;
        bridge) printf 'bridge' ;;
        bond) printf 'bond' ;;
        vrf) printf 'VRF' ;;
        virtual) printf 'виртуальный' ;;
        physical) printf 'физический' ;;
        *) printf 'недоступен' ;;
    esac
}

interface_protection_reason() {
    local iface=$1 ssh_if master dependents kind
    ssh_if="$(ssh_iface)"
    master="$(iface_master "$iface")"
    dependents="$(iface_dependents "$iface")"
    kind="$(iface_kind_id "$iface")"
    if [[ "$iface" == "$WG_IFACE" ]]; then
        printf 'служебный интерфейс WARP'
    elif [[ "$iface" == "lo" ]]; then
        printf 'локальный интерфейс'
    elif is_default_iface "$iface"; then
        printf 'маршрут по умолчанию в одной из таблиц'
    elif [[ -n "$ssh_if" && "$iface" == "$ssh_if" ]]; then
        printf 'текущая SSH-сессия'
    elif is_active_wireguard_iface "$iface"; then
        printf 'действующий WireGuard-интерфейс с пирами или портом'
    elif iface_has_foreign_policy_rules "$iface"; then
        printf 'уже участвует в сторонней policy routing'
    elif iface_has_foreign_firewall_rules "$iface"; then
        printf 'уже участвует в сторонних firewall-правилах'
    elif [[ -n "$master" ]]; then
        printf 'подчинён интерфейсу %s' "$master"
    elif [[ -n "$dependents" ]]; then
        printf 'имеет подчинённые интерфейсы: %s' "$dependents"
    elif iface_has_custom_ipv4_routes "$iface"; then
        printf 'имеет пользовательские IPv4-маршруты'
    else
        case "$kind" in
            physical) printf 'физический интерфейс' ;;
            bridge) printf 'сетевой мост'
                ;;
            bond) printf 'агрегированный bond-интерфейс'
                ;;
            vrf) printf 'интерфейс VRF'
                ;;
            virtual) printf 'виртуальный интерфейс неизвестного назначения'
                ;;
        esac
    fi
}

declare -a SELECTABLE_IFACES=()

scan_interfaces() {
    local include_risky=${1:-0} path iface reason state kind addresses routes number decision hidden_risky_count=0
    SELECTABLE_IFACES=()
    printf '%s\n' "${C_BOLD}$([[ "$include_risky" == "1" ]] && echo 'Все активные интерфейсы' || echo 'Рекомендуемые интерфейсы')${C_RESET}"
    printf '%-4s %-16s %-14s %-8s %s\n' "№" "Интерфейс" "Тип" "Состояние" "IPv4"
    printf '%-4s %-16s %-14s %-8s %s\n' "--" "---------" "---" "---------" "----"
    for path in "$SYS_CLASS_NET_ROOT"/*; do
        [[ -e "$path" ]] || continue
        iface="${path##*/}"
        is_safe_iface_name "$iface" || continue
        reason="$(interface_protection_reason "$iface")"
        state="DOWN"
        iface_is_up "$iface" && state="UP"
        kind="$(iface_kind "$iface")"
        addresses="$(iface_addresses "$iface")"
        routes="$(iface_route_summary "$iface")"
        if [[ -n "$reason" ]]; then
            if [[ "$include_risky" == "1" && "$state" == "UP" && "$iface" != "lo" && "$iface" != "$WG_IFACE" ]]; then
                SELECTABLE_IFACES+=("$iface")
                number="${#SELECTABLE_IFACES[@]}"
                decision="ОПАСНО: $reason"
                printf '%-4s %-16s %-14s %-8s %s  [%s]\n' "$number" "$iface" "$kind" "$state" "$addresses" "$decision"
            elif [[ "$include_risky" == "1" ]]; then
                decision="не рекомендуется: $reason"
                printf '%-4s %-16s %-14s %-8s %s  [%s]\n' "—" "$iface" "$kind" "$state" "$addresses" "$decision"
            else
                if [[ "$state" == "UP" && "$iface" != "lo" && "$iface" != "$WG_IFACE" ]]; then
                    hidden_risky_count=$((hidden_risky_count + 1))
                fi
                continue
            fi
        elif [[ "$state" == "UP" ]]; then
            SELECTABLE_IFACES+=("$iface")
            decision="рекомендуется: системных рисков не обнаружено"
            printf '%-4s %-16s %-14s %-8s %s  [%s]\n' "${#SELECTABLE_IFACES[@]}" "$iface" "$kind" "$state" "$addresses" "$decision"
        else
            if [[ "$include_risky" == "1" ]]; then
                decision="неактивен"
                printf '%-4s %-16s %-14s %-8s %s  [%s]\n' "—" "$iface" "$kind" "$state" "$addresses" "$decision"
            else
                continue
            fi
        fi
        printf '     Маршруты IPv4: %s\n' "$routes"
    done
    say
    if [[ "$include_risky" == "0" ]] && ((${#SELECTABLE_IFACES[@]} == 0)); then
        say "Рекомендуемых активных интерфейсов не найдено."
    fi
    if [[ "$include_risky" == "1" ]]; then
        say "Пронумерованы только доступные для выбора интерфейсы: ${#SELECTABLE_IFACES[@]}. Строки без номера показаны справочно."
        say "Опасные интерфейсы доступны только по осознанному решению администратора."
    else
        say "Рекомендуемый означает: скрипт не обнаружил системных признаков риска."
        ((hidden_risky_count == 0)) || say "Скрыто рискованных интерфейсов, доступных в полном списке: $hidden_risky_count."
    fi
}

offer_all_interfaces() {
    local answer
    say
    warn "рекомендуемых активных интерфейсов не найдено. Это не запрещает ручной выбор."
    say "1) Показать все активные интерфейсы"
    say "0) Отменить установку"
    read -r -p "Выберите действие [0]: " answer
    say
    [[ "$answer" == "1" ]]
}

validate_target_iface() {
    local iface=$1 allow_risky=${2:-0} reason
    is_safe_iface_name "$iface" || die "недопустимое имя интерфейса."
    [[ -d "$SYS_CLASS_NET_ROOT/$iface" ]] || die "интерфейс $iface не существует."
    iface_is_up "$iface" || die "интерфейс $iface не поднят."
    reason="$(interface_protection_reason "$iface")"
    [[ -z "$reason" || "$allow_risky" == "1" ]] || die "интерфейс $iface защищён: $reason."
}

choose_interface() {
    local answer index mode=0 reason confirm
    [[ -t 0 ]] || die "для выбора интерфейса нужен интерактивный терминал."
    say "Режим списка интерфейсов:"
    say "1) Только рекомендуемые — системных рисков не обнаружено [по умолчанию]"
    say "2) Все активные — ручное решение администратора"
    say "0) Назад"
    read -r -p "Выберите режим [1]: " answer
    say
    [[ "$answer" == "0" ]] && return 2
    if [[ "$answer" == "2" ]]; then
        mode=1
        warn "в полном списке можно выбрать основной, SSH- или уже используемый выходной интерфейс."
        warn "ошибка выбора способна создать петлю маршрутизации или оборвать доступ к серверу."
    fi
    scan_interfaces "$mode"
    if ((${#SELECTABLE_IFACES[@]} == 0)) && [[ "$mode" == "0" ]]; then
        offer_all_interfaces || return 2
        mode=1
        warn "в полном списке администратор самостоятельно принимает риск потери доступа или петли маршрутизации."
        scan_interfaces 1
    fi
    ((${#SELECTABLE_IFACES[@]} > 0)) || die "нет активных интерфейсов, которые можно выбрать."
    while true; do
        read -r -p "Выберите номер интерфейса [0 — назад]: " answer
        say
        [[ "$answer" == "0" ]] && return 2
        if [[ "$answer" =~ ^[0-9]+$ ]]; then
            index=$((answer - 1))
            if ((index >= 0 && index < ${#SELECTABLE_IFACES[@]})); then
                CHOSEN_IFACE="${SELECTABLE_IFACES[$index]}"
                CHOSEN_ALLOW_RISKY=0
                reason="$(interface_protection_reason "$CHOSEN_IFACE")"
                if [[ -n "$reason" ]]; then
                    [[ "$mode" == "1" ]] || die "внутренняя ошибка режима выбора."
                    say
                    warn "$CHOSEN_IFACE защищён: $reason."
                    read -r -p "Чтобы всё равно выбрать его, введите РИСК $CHOSEN_IFACE: " confirm
                    say
                    [[ "$confirm" == "РИСК $CHOSEN_IFACE" ]] || { warn "опасный выбор отменён."; continue; }
                    CHOSEN_ALLOW_RISKY=1
                fi
                validate_target_iface "$CHOSEN_IFACE" "$CHOSEN_ALLOW_RISKY"
                ok "Выбран интерфейс: $CHOSEN_IFACE ($(iface_kind "$CHOSEN_IFACE"), IPv4: $(iface_addresses "$CHOSEN_IFACE"))"
                return 0
            fi
        fi
        warn "укажите номер из списка."
    done
}

choose_routing_mode() {
    local answer confirm ports
    while true; do
        CHOSEN_ROUTING_MODE="interface"
        CHOSEN_SSH_PORTS=""
        say "Что направлять через WARP:"
        say "1) Трафик с одного выбранного входного интерфейса [по умолчанию]"
        say "2) Весь исходящий IPv4-трафик сервера"
        say "0) Вернуться в главное меню"
        read -r -p "Выберите режим [1]: " answer
        say
        [[ "$answer" == "0" ]] && return 2
        if [[ "$answer" != "2" ]]; then
            if choose_interface; then
                return 0
            fi
            say
            continue
        fi

        if ! check_full_host_routing_is_clear; then
            say
            continue
        fi
        ports="$(detect_ssh_ports)"
        validate_ssh_ports "$ports" || die "не удалось надёжно определить ни одного порта SSH. Режим всего хоста запрещён."
        ip_rule_supports_ports || die "ядро или iproute2 не поддерживает правила по TCP-порту; сохранить SSH автоматически нельзя."
        say
        warn "весь исходящий IPv4-трафик сервера будет направлен через WARP."
        say "Обнаруженные и защищаемые порты SSH: $ports"
        say "Ответы SSH с этих портов и соединение с endpoint WARP останутся в основной таблице маршрутов."
        say "IPv6 этим скриптом не переключается."
        read -r -p "Для продолжения введите ВЕСЬ ТРАФИК: " confirm
        say
        if [[ "$confirm" != "ВЕСЬ ТРАФИК" ]]; then
            warn "режим всего хоста не подтверждён."
            say
            continue
        fi
        CHOSEN_ROUTING_MODE="host"
        CHOSEN_IFACE="-"
        CHOSEN_ALLOW_RISKY=0
        CHOSEN_SSH_PORTS="$ports"
        return 0
    done
}

state_get() {
    local key=$1 file=${2:-$STATE_FILE}
    [[ -f "$file" ]] || return 0
    awk -F= -v wanted="$key" '$1 == wanted { sub(/^[^=]*=/, ""); print; exit }' "$file"
}

load_state() {
    [[ -f "$OWNER_FILE" && "$(<"$OWNER_FILE")" == "$OWNER_VALUE" ]] || die "установка не найдена или не принадлежит этому менеджеру."
    [[ -f "$STATE_FILE" && ! -L "$STATE_FILE" ]] || die "файл состояния отсутствует или небезопасен."
    TARGET_IFACE="$(state_get TARGET_IFACE)"
    TABLE_ID="$(state_get TABLE_ID)"
    RULE_PRIORITY="$(state_get RULE_PRIORITY)"
    INSTALLED_AT="$(state_get INSTALLED_AT)"
    PREVIOUS_IP_FORWARD="$(state_get PREVIOUS_IP_FORWARD)"
    ALLOW_RISKY="$(state_get ALLOW_RISKY)"
    ROUTING_MODE="$(state_get ROUTING_MODE)"
    SSH_PORTS="$(state_get SSH_PORTS)"
    [[ -n "$ROUTING_MODE" ]] || ROUTING_MODE="interface"
    [[ "$ROUTING_MODE" == "interface" || "$ROUTING_MODE" == "host" ]] || die "повреждён режим маршрутизации."
    if [[ "$ROUTING_MODE" == "interface" ]]; then
        is_safe_iface_name "$TARGET_IFACE" || die "повреждено имя интерфейса в состоянии."
        SSH_PORTS=""
    else
        [[ "$TARGET_IFACE" == "-" ]] || die "повреждена цель режима всего хоста."
        validate_ssh_ports "$SSH_PORTS" || die "повреждён список защищённых SSH-портов."
    fi
    [[ "$TABLE_ID" =~ ^[0-9]+$ && "$TABLE_ID" -ge 1000 && "$TABLE_ID" -le 65000 ]] || die "повреждён номер таблицы маршрутизации."
    [[ "$RULE_PRIORITY" =~ ^[0-9]+$ && "$RULE_PRIORITY" -ge 1000 && "$RULE_PRIORITY" -le 32000 ]] || die "повреждён приоритет правила."
    [[ "$PREVIOUS_IP_FORWARD" == "0" || "$PREVIOUS_IP_FORWARD" == "1" ]] || PREVIOUS_IP_FORWARD=1
    [[ "$ALLOW_RISKY" == "0" || "$ALLOW_RISKY" == "1" ]] || ALLOW_RISKY=0
}

write_state() {
    local target=$1 table=$2 priority=$3 installed_at=$4 previous_forward=$5 allow_risky=${6:-0}
    local routing_mode=${7:-interface} ssh_ports=${8:-} tmp
    [[ "$routing_mode" == "interface" || "$routing_mode" == "host" ]] || die "недопустимый режим маршрутизации."
    if [[ "$routing_mode" == "host" ]]; then
        [[ "$target" == "-" ]] || die "неверная цель режима всего хоста."
        validate_ssh_ports "$ssh_ports" || die "нет корректных SSH-портов для защиты."
    else
        ssh_ports=""
    fi
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    tmp="$(mktemp "${CONFIG_DIR}/state.XXXXXX")"
    printf 'TARGET_IFACE=%s\nTABLE_ID=%s\nRULE_PRIORITY=%s\nINSTALLED_AT=%s\nPREVIOUS_IP_FORWARD=%s\nALLOW_RISKY=%s\nROUTING_MODE=%s\nSSH_PORTS=%s\n' \
        "$target" "$table" "$priority" "$installed_at" "$previous_forward" "$allow_risky" "$routing_mode" "$ssh_ports" >"$tmp"
    chmod 600 "$tmp"
    mv -f "$tmp" "$STATE_FILE"
}

is_installed() {
    [[ -f "$OWNER_FILE" && "$(<"$OWNER_FILE")" == "$OWNER_VALUE" && -f "$STATE_FILE" ]]
}

allocate_table_id() {
    local id
    for id in $(seq 51880 51930); do
        if ! ip -4 rule show 2>/dev/null | grep -Eq "(^|[[:space:]])lookup[[:space:]]+$id([[:space:]]|$)" &&
           [[ -z "$(ip -4 route show table "$id" 2>/dev/null)" ]]; then
            printf '%s' "$id"
            return 0
        fi
    done
    return 1
}

allocate_rule_priority() {
    local priority
    for priority in $(seq 18000 18080); do
        if ! ip -4 rule show 2>/dev/null | grep -Eq "^$((priority - 2)):" &&
           ! ip -4 rule show 2>/dev/null | grep -Eq "^$((priority - 1)):" &&
           ! ip -4 rule show 2>/dev/null | grep -Eq "^${priority}:" &&
           ! ip -4 rule show 2>/dev/null | grep -Eq "^$((priority + 1)):"; then
            printf '%s' "$priority"
            return 0
        fi
    done
    return 1
}

install_dependencies() {
    local missing=0 cmd
    for cmd in curl jq ip wg wg-quick iptables systemctl sha256sum awk sed grep flock; do
        command -v "$cmd" >/dev/null 2>&1 || missing=1
    done
    ((missing == 1)) || { ok "Необходимые системные инструменты уже установлены."; return 0; }

    init_logging
    if command -v apt-get >/dev/null 2>&1; then
        run_install_logged "Обновляю каталог пакетов" env DEBIAN_FRONTEND=noninteractive apt-get update || die "не удалось обновить каталог пакетов."
        run_install_logged "Устанавливаю системные инструменты" env DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard-tools curl jq ca-certificates iproute2 iptables util-linux coreutils || die "не удалось установить зависимости."
    elif command -v dnf >/dev/null 2>&1; then
        run_install_logged "Устанавливаю системные инструменты" dnf install -y wireguard-tools curl jq ca-certificates iproute iptables util-linux coreutils || die "не удалось установить зависимости."
    elif command -v yum >/dev/null 2>&1; then
        run_install_logged "Устанавливаю системные инструменты" yum install -y wireguard-tools curl jq ca-certificates iproute iptables util-linux coreutils || die "не удалось установить зависимости."
    elif command -v zypper >/dev/null 2>&1; then
        run_install_logged "Устанавливаю системные инструменты" zypper --non-interactive install wireguard-tools curl jq ca-certificates iproute2 iptables util-linux coreutils || die "не удалось установить зависимости."
    elif command -v apk >/dev/null 2>&1; then
        run_install_logged "Устанавливаю системные инструменты" apk add --no-cache wireguard-tools curl jq ca-certificates iproute2 iptables util-linux coreutils || die "не удалось установить зависимости."
    elif command -v pacman >/dev/null 2>&1; then
        run_install_logged "Устанавливаю системные инструменты" pacman -Sy --noconfirm --needed wireguard-tools curl jq ca-certificates iproute2 iptables util-linux coreutils || die "не удалось установить зависимости."
    else
        die "не найден поддерживаемый менеджер пакетов. Установите WireGuard, curl, jq, iproute2, iptables и util-linux вручную."
    fi

    for cmd in curl jq ip wg wg-quick iptables systemctl sha256sum awk sed grep flock; do
        command -v "$cmd" >/dev/null 2>&1 || die "после установки не найдена команда $cmd."
    done
}

wgcf_arch_suffix() {
    case "${1:-}" in
        x86_64|amd64) printf 'amd64' ;;
        aarch64|arm64) printf 'arm64' ;;
        *) return 1 ;;
    esac
}

parse_wgcf_release_metadata() {
    local metadata=$1 arch=$2 suffix tag version asset asset_count checksum_count
    local asset_url checksum_url asset_digest expected_prefix
    [[ -f "$metadata" && ! -L "$metadata" ]] || return 1
    jq -e 'type == "object" and .draft == false and .prerelease == false and (.assets | type == "array")' \
        "$metadata" >/dev/null 2>&1 || return 1
    tag="$(jq -er '.tag_name' "$metadata" 2>/dev/null)" || return 1
    [[ "$tag" =~ ^v?([0-9]+\.[0-9]+\.[0-9]+)$ ]] || return 1
    version="${BASH_REMATCH[1]}"
    suffix="$(wgcf_arch_suffix "$arch")" || return 1
    asset="wgcf_${version}_linux_${suffix}"
    asset_count="$(jq -r --arg name "$asset" '[.assets[] | select(.name == $name and .state == "uploaded")] | length' "$metadata" 2>/dev/null)" || return 1
    checksum_count="$(jq -r '[.assets[] | select(.name == "checksums.txt" and .state == "uploaded")] | length' "$metadata" 2>/dev/null)" || return 1
    [[ "$asset_count" == "1" && "$checksum_count" == "1" ]] || return 1
    asset_url="$(jq -er --arg name "$asset" '.assets[] | select(.name == $name and .state == "uploaded") | .browser_download_url' "$metadata" 2>/dev/null)" || return 1
    checksum_url="$(jq -er '.assets[] | select(.name == "checksums.txt" and .state == "uploaded") | .browser_download_url' "$metadata" 2>/dev/null)" || return 1
    asset_digest="$(jq -er --arg name "$asset" '.assets[] | select(.name == $name and .state == "uploaded") | .digest' "$metadata" 2>/dev/null)" || return 1
    expected_prefix="https://github.com/${WGCF_REPOSITORY}/releases/download/${tag}"
    [[ "$asset_url" == "${expected_prefix}/${asset}" ]] || return 1
    [[ "$checksum_url" == "${expected_prefix}/checksums.txt" ]] || return 1
    [[ "$asset_digest" =~ ^sha256:([a-fA-F0-9]{64})$ ]] || return 1

    WGCF_RELEASE_VERSION="$version"
    WGCF_RELEASE_ASSET="$asset"
    WGCF_RELEASE_ASSET_URL="$asset_url"
    WGCF_RELEASE_CHECKSUM_URL="$checksum_url"
    WGCF_RELEASE_API_SHA256="${BASH_REMATCH[1],,}"
}

download_latest_stable_wgcf() {
    local destination=$1 metadata="$1/release.json" checksums="$1/checksums.txt"
    local expected actual matches size
    run_install_logged "Определяю последний стабильный релиз wgcf" \
        curl --fail --location --silent --show-error --retry 3 --connect-timeout 15 --max-time 120 \
        --max-filesize 2097152 --proto '=https' --proto-redir '=https' \
        -H 'Accept: application/vnd.github+json' -H "User-Agent: warp-interface-manager/${VERSION}" \
        "$WGCF_LATEST_API" -o "$metadata" || die "не удалось получить сведения о стабильном релизе wgcf."
    size="$(wc -c <"$metadata")"
    ((size > 0 && size <= 2097152)) || die "GitHub вернул данные релиза неожиданного размера."
    parse_wgcf_release_metadata "$metadata" "$(uname -m)" || \
        die "последний релиз wgcf не прошёл проверку: допускается только опубликованный стабильный SemVer-релиз."

    run_install_logged "Скачиваю контрольные суммы wgcf ${WGCF_RELEASE_VERSION}" \
        curl --fail --location --silent --show-error --retry 3 --connect-timeout 15 --max-time 120 \
        --max-filesize 1048576 --proto '=https' --proto-redir '=https' \
        "$WGCF_RELEASE_CHECKSUM_URL" -o "$checksums" || die "не удалось загрузить контрольные суммы wgcf."
    run_install_logged "Скачиваю стабильный wgcf ${WGCF_RELEASE_VERSION}" \
        curl --fail --location --silent --show-error --retry 3 --connect-timeout 15 --max-time 300 \
        --max-filesize 67108864 --proto '=https' --proto-redir '=https' \
        "$WGCF_RELEASE_ASSET_URL" -o "$destination/wgcf" || die "загрузка wgcf не удалась."
    size="$(wc -c <"$destination/wgcf")"
    ((size >= 1048576 && size <= 67108864)) || die "скачанный wgcf имеет неожиданный размер."
    matches="$(awk -v wanted="$WGCF_RELEASE_ASSET" '$2 == wanted || $2 == "*" wanted { count++ } END { print count+0 }' "$checksums")"
    [[ "$matches" == "1" ]] || die "в файле контрольных сумм нет одной точной записи для выбранного wgcf."
    expected="$(awk -v wanted="$WGCF_RELEASE_ASSET" '$2 == wanted || $2 == "*" wanted { print tolower($1); exit }' "$checksums")"
    [[ "$expected" =~ ^[a-f0-9]{64}$ ]] || die "контрольная сумма wgcf имеет неверный формат."
    [[ "$expected" == "$WGCF_RELEASE_API_SHA256" ]] || die "контрольные суммы wgcf в метаданных и checksums.txt не совпали."
    actual="$(sha256sum "$destination/wgcf" | awk '{print tolower($1)}')"
    [[ "$actual" == "$expected" ]] || die "контрольная сумма скачанного wgcf не совпала. Файл не установлен."
    chmod 700 "$destination/wgcf"
    "$destination/wgcf" --help 2>&1 | grep -q 'Available Commands:' || die "скачанный файл не похож на совместимый wgcf."
    "$destination/wgcf" register --help 2>&1 | grep -q -- '--accept-tos' || die "скачанный wgcf несовместим с регистрацией."
    "$destination/wgcf" generate --help 2>&1 | grep -q -- '--profile' || die "скачанный wgcf несовместим с генерацией профиля."
    WGCF_RELEASE_SHA256="$actual"
}

write_wgcf_version() {
    local version=$1 tmp
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    tmp="$(mktemp "${CONFIG_DIR}/wgcf-version.XXXXXX")"
    printf '%s\n' "$version" >"$tmp"
    chmod 600 "$tmp"
    mv -f "$tmp" "$WGCF_VERSION_FILE"
}

installed_wgcf_version() {
    local version
    if [[ -f "$WGCF_VERSION_FILE" && ! -L "$WGCF_VERSION_FILE" ]]; then
        version="$(head -n 1 "$WGCF_VERSION_FILE" 2>/dev/null || true)"
        [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && { printf '%s' "$version"; return 0; }
    fi
    return 1
}

install_wgcf() {
    local tmp bin_dir staged changed=1 current_sha compatibility_profile
    tmp="$(mktemp -d)"
    trap 'rm -rf -- "$tmp"' RETURN
    download_latest_stable_wgcf "$tmp"
    bin_dir="$(dirname "$WGCF_BIN")"
    mkdir -p "$bin_dir"
    chmod 700 "$bin_dir"
    if [[ -f "$ACCOUNT_FILE" && ! -L "$ACCOUNT_FILE" ]]; then
        compatibility_profile="$tmp/compatibility.conf"
        info "Проверяю новый wgcf на сохранённой регистрации без её изменения..."
        log_install_header "проверка совместимости wgcf ${WGCF_RELEASE_VERSION} с сохранённой регистрацией"
        if ! "$tmp/wgcf" --config "$ACCOUNT_FILE" generate --profile "$compatibility_profile" >>"$INSTALL_LOG" 2>&1; then
            die "новый wgcf не смог прочитать сохранённую регистрацию; текущая версия оставлена без изменений."
        fi
        validate_raw_profile "$compatibility_profile"
    fi
    current_sha=""
    if [[ -f "$WGCF_BIN" && ! -L "$WGCF_BIN" ]]; then
        current_sha="$(sha256sum "$WGCF_BIN" 2>/dev/null | awk '{print tolower($1)}' || true)"
    fi
    if [[ "$current_sha" == "$WGCF_RELEASE_SHA256" ]]; then
        changed=0
    else
        staged="$(mktemp "${bin_dir}/wgcf.XXXXXX")"
        install -m 700 "$tmp/wgcf" "$staged"
        mv -f "$staged" "$WGCF_BIN"
    fi
    chmod 700 "$WGCF_BIN"
    write_wgcf_version "$WGCF_RELEASE_VERSION"
    trap - RETURN
    rm -rf -- "$tmp"
    if ((changed == 1)); then
        ok "Установлен последний стабильный wgcf ${WGCF_RELEASE_VERSION}; SHA-256 проверен по двум источникам релиза."
        log_event "INSTALL" "wgcf ${WGCF_RELEASE_VERSION}: стабильный релиз, SHA-256 проверен"
    else
        ok "Уже используется последний стабильный wgcf ${WGCF_RELEASE_VERSION}; SHA-256 повторно проверен."
        log_event "INSTALL" "wgcf ${WGCF_RELEASE_VERSION}: актуальность и SHA-256 повторно проверены"
    fi
}

validate_raw_profile() {
    local input=$1 size
    [[ -f "$input" && ! -L "$input" ]] || die "wgcf не создал безопасный файл профиля."
    size="$(wc -c <"$input")"
    ((size > 0 && size <= 65536)) || die "неожиданный размер профиля WARP."
    [[ "$(grep -Eic '^[[:space:]]*\[Interface\][[:space:]]*$' "$input")" -eq 1 ]] || die "в профиле должна быть одна секция Interface."
    [[ "$(grep -Eic '^[[:space:]]*\[Peer\][[:space:]]*$' "$input")" -eq 1 ]] || die "в профиле должна быть одна секция Peer."
    grep -Eqi '^[[:space:]]*PrivateKey[[:space:]]*=' "$input" || die "в профиле нет приватного ключа."
    grep -Eqi '^[[:space:]]*Address[[:space:]]*=.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$input" || die "в профиле нет IPv4-адреса."
    grep -Eqi '^[[:space:]]*PublicKey[[:space:]]*=' "$input" || die "в профиле нет публичного ключа узла."
    grep -Eqi '^[[:space:]]*AllowedIPs[[:space:]]*=.*0\.0\.0\.0/0' "$input" || die "в профиле нет IPv4-маршрута WARP."
    grep -Eqi '^[[:space:]]*Endpoint[[:space:]]*=' "$input" || die "в профиле нет endpoint."
    if grep -Eqi '^[[:space:]]*(PreUp|PostUp|PreDown|PostDown|SaveConfig)[[:space:]]*=' "$input"; then
        die "профиль содержит исполняемые или изменяющие конфигурацию директивы."
    fi
    awk '
        BEGIN { section=""; bad=0 }
        /^[[:space:]]*($|#|;)/ { next }
        /^[[:space:]]*\[Interface\][[:space:]]*$/ { section="interface"; next }
        /^[[:space:]]*\[Peer\][[:space:]]*$/ { section="peer"; next }
        /=/ {
            key=$0; sub(/[[:space:]]*=.*/, "", key); gsub(/[[:space:]]/, "", key); key=tolower(key)
            if (section == "interface" && key !~ /^(privatekey|address|dns|mtu|table)$/) bad=1
            else if (section == "peer" && key !~ /^(publickey|presharedkey|allowedips|endpoint|persistentkeepalive)$/) bad=1
            else if (section == "") bad=1
            next
        }
        { bad=1 }
        END { exit bad }
    ' "$input" || die "профиль содержит неизвестные параметры и отклонён."
}

sanitize_profile_file() {
    local input=$1 output=$2 mtu=$3
    awk -v mtu="$mtu" '
        BEGIN { inserted=0 }
        tolower($0) ~ /^[[:space:]]*\[interface\][[:space:]]*$/ {
            print "# Managed by warp-interface-manager. Do not edit while active."
            print "[Interface]"
            print "Table = off"
            print "MTU = " mtu
            inserted=1
            next
        }
        tolower($0) ~ /^[[:space:]]*(dns|table|mtu|preup|postup|predown|postdown|saveconfig)[[:space:]]*=/ { next }
        { print }
        END { if (!inserted) exit 1 }
    ' "$input" >"$output"
    chmod 600 "$output"
}

register_and_generate_profile() {
    local log tmp_profile
    mkdir -p "$CONFIG_DIR" /etc/wireguard
    chmod 700 "$CONFIG_DIR"
    umask 077
    log="$(mktemp "${CONFIG_DIR}/wgcf.XXXXXX.log")"
    tmp_profile="$(mktemp "${CONFIG_DIR}/profile.XXXXXX")"
    if [[ -f "$ACCOUNT_FILE" ]]; then
        info "Проверяю сохранённую регистрацию WARP..."
        if ! "$WGCF_BIN" --config "$ACCOUNT_FILE" status >"$log" 2>&1; then
            warn "Cloudflare не подтвердил статус сохранённой регистрации; повторная регистрация автоматически не создаётся."
        fi
    fi
    if [[ ! -f "$ACCOUNT_FILE" ]]; then
        info "Регистрирую бесплатный профиль Cloudflare WARP..."
        if ! "$WGCF_BIN" --config "$ACCOUNT_FILE" register --accept-tos \
            --name "Selective WARP" --model "Linux Server" >"$log" 2>&1; then
            if [[ ! -f "$ACCOUNT_FILE" ]] || ! "$WGCF_BIN" --config "$ACCOUNT_FILE" status >/dev/null 2>&1; then
                rm -f "$log" "$tmp_profile"
                die "регистрация WARP не удалась. Проверьте доступ VPS к API Cloudflare."
            fi
        fi
        log_event "REGISTER" "создана одна новая бесплатная регистрация WARP"
    fi
    info "Создаю и проверяю WireGuard-профиль..."
    if ! "$WGCF_BIN" --config "$ACCOUNT_FILE" generate --profile "$RAW_PROFILE" >"$log" 2>&1; then
        rm -f "$log" "$tmp_profile"
        die "не удалось создать WireGuard-профиль WARP."
    fi
    rm -f "$log"
    validate_raw_profile "$RAW_PROFILE"
    sanitize_profile_file "$RAW_PROFILE" "$tmp_profile" "$DEFAULT_MTU"
    validate_raw_profile "$tmp_profile"
    if [[ -e "$WG_CONFIG" ]] && ! grep -q '^# Managed by warp-interface-manager\.' "$WG_CONFIG" 2>/dev/null; then
        rm -f "$tmp_profile"
        die "$WG_CONFIG уже существует и не принадлежит этому менеджеру."
    fi
    install -m 600 "$tmp_profile" "$WG_CONFIG"
    rm -f "$tmp_profile"
    chmod 600 "$ACCOUNT_FILE" "$RAW_PROFILE" "$WG_CONFIG"
    ok "Профиль создан с Table = off: основной маршрут сервера не изменяется."
    log_event "PROFILE" "создан безопасный профиль WARP с Table=off"
}

profile_ipv4() {
    awk -F= '
        tolower($1) ~ /^[[:space:]]*address[[:space:]]*$/ {
            count=split($2, values, ",")
            for (i=1; i<=count; i++) {
                gsub(/[[:space:]]/, "", values[i])
                if (values[i] ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\//) {
                    sub(/\/.*/, "", values[i]); print values[i]; exit
                }
            }
        }
    ' "$WG_CONFIG" 2>/dev/null
}

profile_endpoint() {
    awk -F= 'tolower($1) ~ /^[[:space:]]*endpoint[[:space:]]*$/ { gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit }' "$WG_CONFIG" 2>/dev/null
}

resolve_warp_endpoint_ipv4() {
    local endpoint host count
    endpoint="$(profile_endpoint)"
    [[ -n "$endpoint" ]] || return 1
    if [[ "$endpoint" =~ ^\[([^]]+)\]:[0-9]+$ ]]; then
        host="${BASH_REMATCH[1]}"
    else
        host="${endpoint%:*}"
    fi
    if is_ipv4_address "$host"; then
        printf '%s' "$host"
        return 0
    fi
    command -v getent >/dev/null 2>&1 || return 1
    count=0
    while read -r host; do
        is_ipv4_address "$host" || continue
        ((count == 0)) || printf ','
        printf '%s' "$host"
        count=$((count + 1))
        ((count < 16)) || break
    done < <(getent ahostsv4 "$host" 2>/dev/null | awk '!seen[$1]++ {print $1}')
    ((count > 0))
}

write_health() {
    local status=$1 detail=${2:-} tmp
    mkdir -p "$DATA_DIR"
    chmod 700 "$DATA_DIR"
    tmp="$(mktemp "${DATA_DIR}/health.XXXXXX")"
    printf 'STATUS=%s\nCHECKED_AT=%s\nDETAIL=%s\n' "$status" "$(date -Is)" "${detail//$'\n'/ }" >"$tmp"
    chmod 600 "$tmp"
    mv -f "$tmp" "$HEALTH_FILE"
}

save_runtime_state() {
    local prior_rp=$1 endpoint_ips=${2:-} tmp
    [[ -z "$endpoint_ips" ]] || validate_ipv4_list "$endpoint_ips" || return 1
    mkdir -p "$RUNTIME_DIR"
    chmod 700 "$RUNTIME_DIR"
    tmp="$(mktemp "${RUNTIME_DIR}/runtime.XXXXXX")"
    printf 'PRIOR_RP_FILTER=%s\nSTARTED_AT=%s\nENDPOINT_IPS=%s\n' "$prior_rp" "$(date +%s)" "$endpoint_ips" >"$tmp"
    chmod 600 "$tmp"
    mv -f "$tmp" "$RUNTIME_FILE"
}

remove_exact_firewall_rules() {
    local target=$1
    while iptables -t nat -C POSTROUTING -o "$WG_IFACE" -m comment --comment "$RULE_COMMENT" -j MASQUERADE >/dev/null 2>&1; do
        iptables -t nat -D POSTROUTING -o "$WG_IFACE" -m comment --comment "$RULE_COMMENT" -j MASQUERADE >/dev/null 2>&1 || break
    done
    while iptables -C FORWARD -i "$target" -o "$WG_IFACE" -m comment --comment "$RULE_COMMENT" -j ACCEPT >/dev/null 2>&1; do
        iptables -D FORWARD -i "$target" -o "$WG_IFACE" -m comment --comment "$RULE_COMMENT" -j ACCEPT >/dev/null 2>&1 || break
    done
    while iptables -C FORWARD -i "$WG_IFACE" -o "$target" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$RULE_COMMENT" -j ACCEPT >/dev/null 2>&1; do
        iptables -D FORWARD -i "$WG_IFACE" -o "$target" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$RULE_COMMENT" -j ACCEPT >/dev/null 2>&1 || break
    done
}

runtime_down() {
    local warp_ip source_priority prior_rp current_rp endpoint_ips endpoint port
    local -a endpoint_list=() port_list=()
    if ! is_installed; then
        return 0
    fi
    load_state
    source_priority="$RULE_PRIORITY"
    warp_ip="$(profile_ipv4)"
    if [[ "$ROUTING_MODE" == "interface" ]]; then
        remove_exact_firewall_rules "$TARGET_IFACE"
        while ip -4 rule del iif "$TARGET_IFACE" table "$TABLE_ID" priority "$((RULE_PRIORITY + 1))" >/dev/null 2>&1; do :; done
    else
        while ip -4 rule del table "$TABLE_ID" priority "$((RULE_PRIORITY + 1))" >/dev/null 2>&1; do :; done
        IFS=',' read -r -a port_list <<<"$SSH_PORTS"
        for port in "${port_list[@]}"; do
            while ip -4 rule del ipproto tcp sport "$port" table main priority "$((RULE_PRIORITY - 1))" >/dev/null 2>&1; do :; done
        done
        endpoint_ips="$(state_get ENDPOINT_IPS "$RUNTIME_FILE")"
        if ! validate_ipv4_list "$endpoint_ips"; then
            endpoint_ips="$(ip -4 rule show 2>/dev/null |
                awk -v wanted="$((RULE_PRIORITY - 2)):" '
                    $1 == wanted {
                        destination=""; main=0
                        for (i=1; i<=NF; i++) {
                            if ($i == "to") destination=$(i+1)
                            if ($i == "lookup" && $(i+1) == "main") main=1
                        }
                        if (main && destination ~ /^[0-9.]+(\/32)?$/) {
                            sub(/\/32$/, "", destination); print destination
                        }
                    }
                ' | awk '!seen[$1]++' | paste -sd ',' -)"
        fi
        if validate_ipv4_list "$endpoint_ips"; then
            IFS=',' read -r -a endpoint_list <<<"$endpoint_ips"
            for endpoint in "${endpoint_list[@]}"; do
                while ip -4 rule del to "${endpoint}/32" table main priority "$((RULE_PRIORITY - 2))" >/dev/null 2>&1; do :; done
            done
        fi
    fi
    if [[ -n "$warp_ip" ]]; then
        while ip -4 rule del from "${warp_ip}/32" table "$TABLE_ID" priority "$source_priority" >/dev/null 2>&1; do :; done
    fi
    while ip -4 route del default dev "$WG_IFACE" table "$TABLE_ID" >/dev/null 2>&1; do :; done
    if [[ -f "$WG_CONFIG" && "$(head -n 1 "$WG_CONFIG" 2>/dev/null)" == "# Managed by warp-interface-manager. Do not edit while active." ]]; then
        wg-quick down "$WG_CONFIG" >/dev/null 2>&1 || true
    fi
    if [[ "$ROUTING_MODE" == "interface" && -f "$RUNTIME_FILE" && -e "$PROC_SYS_IPV4_CONF_ROOT/${TARGET_IFACE}/rp_filter" ]]; then
        prior_rp="$(state_get PRIOR_RP_FILTER "$RUNTIME_FILE")"
        current_rp="$(<"$PROC_SYS_IPV4_CONF_ROOT/${TARGET_IFACE}/rp_filter")"
        if [[ "$prior_rp" =~ ^[0-2]$ && "$current_rp" == "0" ]]; then
            printf '%s' "$prior_rp" >"$PROC_SYS_IPV4_CONF_ROOT/${TARGET_IFACE}/rp_filter" || true
        fi
    fi
    rm -f "$RUNTIME_FILE"
    write_health "disabled" "Маршрутизация через WARP отключена"
    log_event "ROUTING" "маршрутизация WARP отключена; режим $ROUTING_MODE; цель $TARGET_IFACE"
    return 0
}

perform_warp_test() {
    local warp_ip trace exit_ip handshake
    warp_ip="$(profile_ipv4)"
    [[ -n "$warp_ip" ]] || return 1
    ip -4 route get 1.1.1.1 from "$warp_ip" 2>/dev/null | grep -qw "dev $WG_IFACE" || return 1
    trace="$(curl -4fsS --interface "$warp_ip" --connect-timeout 8 --max-time 25 \
        https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null || true)"
    grep -Eq '^warp=(on|plus)$' <<<"$trace" || return 1
    handshake="$(wg show "$WG_IFACE" latest-handshakes 2>/dev/null | awk '{ if ($2 > max) max=$2 } END { print max+0 }')"
    [[ "$handshake" =~ ^[0-9]+$ && "$handshake" -gt 0 ]] || return 1
    exit_ip="$(awk -F= '$1 == "ip" {print $2; exit}' <<<"$trace")"
    write_health "healthy" "WARP работает; выходной IP ${exit_ip:-не определён}"
    return 0
}

perform_full_host_test() {
    local trace
    ip -4 route get 1.1.1.1 2>/dev/null | grep -qw "dev $WG_IFACE" || return 1
    trace="$(curl -4fsS --connect-timeout 8 --max-time 25 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null || true)"
    grep -Eq '^warp=(on|plus)$' <<<"$trace"
}

service_up_steps() {
    local waited=0 prior_rp warp_ip main_routes endpoint_ips endpoint port foreign_evidence
    local -a endpoint_list=() port_list=()
    load_state
    foreign_evidence="$(foreign_warp_evidence | awk '!seen[$0]++')"
    if [[ -n "$foreign_evidence" ]]; then
        warn "обнаружен сторонний WARP. Запуск второго туннеля запрещён: $(awk 'NR == 1 {print; exit}' <<<"$foreign_evidence")"
        return 1
    fi
    if [[ "$ROUTING_MODE" == "interface" ]]; then
        is_safe_iface_name "$TARGET_IFACE" || { warn "недопустимое имя сохранённого интерфейса."; return 1; }
    else
        validate_ssh_ports "$SSH_PORTS" || { warn "нет корректного списка SSH-портов."; return 1; }
        ssh_ports_cover_detected || { warn "настройка SSH изменилась: сохранённые защитные порты больше не полны."; return 1; }
        ip_rule_supports_ports || { warn "система не поддерживает защитные правила по SSH-порту."; return 1; }
        check_full_host_routing_is_clear || return 1
    fi
    [[ -f "$WG_CONFIG" && ! -L "$WG_CONFIG" ]] || { warn "защищённый профиль WARP не найден."; return 1; }
    grep -q '^# Managed by warp-interface-manager\.' "$WG_CONFIG" || { warn "профиль WARP больше не принадлежит менеджеру."; return 1; }
    grep -Eqi '^[[:space:]]*Table[[:space:]]*=[[:space:]]*off[[:space:]]*$' "$WG_CONFIG" || { warn "в профиле отсутствует обязательный Table = off."; return 1; }

    if [[ "$ROUTING_MODE" == "interface" ]]; then
        while { [[ ! -d "$SYS_CLASS_NET_ROOT/$TARGET_IFACE" ]] || ! iface_is_up "$TARGET_IFACE"; } && ((waited < 60)); do
            sleep 2
            waited=$((waited + 2))
        done
        iface_is_up "$TARGET_IFACE" || { warn "интерфейс $TARGET_IFACE не поднялся за 60 секунд."; return 1; }
        validate_target_iface "$TARGET_IFACE" "$ALLOW_RISKY"
        endpoint_ips=""
    else
        endpoint_ips="$(resolve_warp_endpoint_ipv4)" || { warn "не удалось определить IPv4 endpoint WARP для защиты от маршрутной петли."; return 1; }
        validate_ipv4_list "$endpoint_ips" || return 1
    fi

    if ip link show dev "$WG_IFACE" >/dev/null 2>&1; then
        warn "интерфейс $WG_IFACE уже существует; запуск остановлен без его удаления."
        return 1
    fi

    prior_rp=0
    if [[ "$ROUTING_MODE" == "interface" && -e "$PROC_SYS_IPV4_CONF_ROOT/${TARGET_IFACE}/rp_filter" ]]; then
        prior_rp="$(<"$PROC_SYS_IPV4_CONF_ROOT/${TARGET_IFACE}/rp_filter")"
        [[ "$prior_rp" =~ ^[0-2]$ ]] || prior_rp=0
        printf '0' >"$PROC_SYS_IPV4_CONF_ROOT/${TARGET_IFACE}/rp_filter" || return 1
    fi
    save_runtime_state "$prior_rp" "$endpoint_ips"
    if [[ "$ROUTING_MODE" == "interface" ]]; then
        sysctl -q -w net.ipv4.ip_forward=1 >/dev/null || return 1
    fi

    wg-quick up "$WG_CONFIG" >/dev/null || return 1
    main_routes="$(ip -4 route show table main 2>/dev/null)"
    if grep -Eq "(^|[[:space:]])dev[[:space:]]+$WG_IFACE([[:space:]]|$)" <<<"$main_routes"; then
        warn "WARP неожиданно появился в основной таблице маршрутов."
        return 1
    fi
    warp_ip="$(profile_ipv4)"
    [[ -n "$warp_ip" ]] || return 1

    ip -4 route add default dev "$WG_IFACE" table "$TABLE_ID" || return 1
    ip -4 rule add from "${warp_ip}/32" table "$TABLE_ID" priority "$RULE_PRIORITY" || return 1
    if [[ "$ROUTING_MODE" == "interface" ]]; then
        ip -4 rule add iif "$TARGET_IFACE" table "$TABLE_ID" priority "$((RULE_PRIORITY + 1))" || return 1
        iptables -t nat -A POSTROUTING -o "$WG_IFACE" -m comment --comment "$RULE_COMMENT" -j MASQUERADE || return 1
        iptables -I FORWARD 1 -i "$TARGET_IFACE" -o "$WG_IFACE" -m comment --comment "$RULE_COMMENT" -j ACCEPT || return 1
        iptables -I FORWARD 1 -i "$WG_IFACE" -o "$TARGET_IFACE" -m conntrack --ctstate RELATED,ESTABLISHED \
            -m comment --comment "$RULE_COMMENT" -j ACCEPT || return 1
    else
        IFS=',' read -r -a endpoint_list <<<"$endpoint_ips"
        for endpoint in "${endpoint_list[@]}"; do
            ip -4 rule add to "${endpoint}/32" table main priority "$((RULE_PRIORITY - 2))" || return 1
        done
        IFS=',' read -r -a port_list <<<"$SSH_PORTS"
        for port in "${port_list[@]}"; do
            ip -4 rule add ipproto tcp sport "$port" table main priority "$((RULE_PRIORITY - 1))" || return 1
        done
        ip -4 rule add table "$TABLE_ID" priority "$((RULE_PRIORITY + 1))" || return 1
    fi

    if ! perform_warp_test; then
        warn "WARP не прошёл фактическую проверку."
        return 1
    fi
    if [[ "$ROUTING_MODE" == "host" ]] && ! perform_full_host_test; then
        warn "весь трафик сервера не перешёл через WARP; выполняется откат."
        return 1
    fi
    return 0
}

service_up() {
    local rc=0
    if service_up_steps; then
        if [[ "$ROUTING_MODE" == "host" ]]; then
            log_event "ROUTING" "весь исходящий IPv4-трафик сервера направлен через WARP; SSH-порты $SSH_PORTS защищены"
        else
            log_event "ROUTING" "WARP включён только для входного интерфейса $TARGET_IFACE"
        fi
        return 0
    else
        rc=$?
        runtime_down || true
        write_health "failed" "Запуск или проверка WARP не удались; выполнен откат"
        log_event "ERROR" "запуск WARP в режиме $ROUTING_MODE для $TARGET_IFACE не прошёл проверку; выполнен откат"
        ((rc != 0)) || rc=1
        return "$rc"
    fi
}

write_units() {
    local tmpdir
    tmpdir="$(mktemp -d)"
    trap 'rm -rf -- "$tmpdir"' RETURN
    cat >"$tmpdir/$SERVICE" <<EOF
# Managed by warp-interface-manager
[Unit]
Description=Managed selective or full-host IPv4 routing through WARP
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=3

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$INSTALL_BIN _service-up
ExecStop=$INSTALL_BIN _service-down
TimeoutStartSec=120
TimeoutStopSec=30
Restart=on-failure
RestartSec=20

[Install]
WantedBy=multi-user.target
EOF
    cat >"$tmpdir/$CHECK_SERVICE" <<EOF
# Managed by warp-interface-manager
[Unit]
Description=Health check for managed WARP routing
After=$SERVICE

[Service]
Type=oneshot
ExecStart=$INSTALL_BIN _health-check --repair
EOF
    cat >"$tmpdir/$CHECK_TIMER" <<EOF
# Managed by warp-interface-manager
[Unit]
Description=Periodic health check for managed WARP routing

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
RandomizedDelaySec=30s
Persistent=true

[Install]
WantedBy=timers.target
EOF
    install -m 644 "$tmpdir/$SERVICE" "$UNIT_DIR/$SERVICE"
    install -m 644 "$tmpdir/$CHECK_SERVICE" "$UNIT_DIR/$CHECK_SERVICE"
    install -m 644 "$tmpdir/$CHECK_TIMER" "$UNIT_DIR/$CHECK_TIMER"
    trap - RETURN
    rm -rf -- "$tmpdir"
    systemctl daemon-reload >>"$INSTALL_LOG" 2>&1
}

ensure_owned_paths_are_safe() {
    local path owner_present=0
    [[ -e "$OWNER_FILE" ]] && owner_present=1
    for path in "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR" "$RUNTIME_DIR" /usr/local/lib/warp-interface-manager; do
        [[ ! -L "$path" ]] || die "$path является символической ссылкой; работа остановлена."
    done
    if [[ -e "$OWNER_FILE" && (! -f "$OWNER_FILE" || -L "$OWNER_FILE" || "$(<"$OWNER_FILE")" != "$OWNER_VALUE") ]]; then
        die "$CONFIG_DIR уже используется и не имеет правильного маркера владельца."
    fi
    if ((owner_present == 0)); then
        for path in "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR" /usr/local/lib/warp-interface-manager "$INSTALL_BIN" "$WG_CONFIG" "$SYSCTL_FILE" \
            "$UNIT_DIR/$SERVICE" "$UNIT_DIR/$CHECK_SERVICE" "$UNIT_DIR/$CHECK_TIMER"; do
            [[ ! -e "$path" && ! -L "$path" ]] || die "$path уже существует. Автоматическое перезаписывание запрещено."
        done
        return 0
    fi

    if [[ -e "$INSTALL_BIN" || -L "$INSTALL_BIN" ]]; then
        [[ -f "$INSTALL_BIN" && ! -L "$INSTALL_BIN" ]] || die "$INSTALL_BIN имеет небезопасный тип."
        grep -q '^PROGRAM_NAME="Менеджер WARP-маршрутизации"$' "$INSTALL_BIN" || die "$INSTALL_BIN не принадлежит этому менеджеру."
    fi
    if [[ -e "$WGCF_BIN" || -L "$WGCF_BIN" ]]; then
        [[ -f "$WGCF_BIN" && ! -L "$WGCF_BIN" ]] || die "$WGCF_BIN имеет небезопасный тип."
    fi
    if [[ -e "$WGCF_VERSION_FILE" || -L "$WGCF_VERSION_FILE" ]]; then
        [[ -f "$WGCF_VERSION_FILE" && ! -L "$WGCF_VERSION_FILE" ]] || die "$WGCF_VERSION_FILE имеет небезопасный тип."
        [[ "$(head -n 1 "$WGCF_VERSION_FILE" 2>/dev/null || true)" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
            die "$WGCF_VERSION_FILE повреждён."
    fi
    for path in "$STATE_FILE" "$ACCOUNT_FILE" "$RAW_PROFILE"; do
        if [[ -e "$path" || -L "$path" ]]; then
            [[ -f "$path" && ! -L "$path" ]] || die "$path имеет небезопасный тип."
        fi
    done
    if [[ -e "$WG_CONFIG" || -L "$WG_CONFIG" ]]; then
        [[ -f "$WG_CONFIG" && ! -L "$WG_CONFIG" ]] || die "$WG_CONFIG имеет небезопасный тип."
        grep -q '^# Managed by warp-interface-manager\.' "$WG_CONFIG" || die "$WG_CONFIG не принадлежит этому менеджеру."
    fi
    if [[ -e "$SYSCTL_FILE" || -L "$SYSCTL_FILE" ]]; then
        [[ -f "$SYSCTL_FILE" && ! -L "$SYSCTL_FILE" ]] || die "$SYSCTL_FILE имеет небезопасный тип."
        grep -q '^# Managed by warp-interface-manager$' "$SYSCTL_FILE" || die "$SYSCTL_FILE не принадлежит этому менеджеру."
    fi
    for path in "$UNIT_DIR/$SERVICE" "$UNIT_DIR/$CHECK_SERVICE" "$UNIT_DIR/$CHECK_TIMER"; do
        if [[ -e "$path" || -L "$path" ]]; then
            [[ -f "$path" && ! -L "$path" ]] || die "$path имеет небезопасный тип."
            grep -q '^# Managed by warp-interface-manager$' "$path" || die "$path не принадлежит этому менеджеру."
        fi
    done
}

write_sysctl_config() {
    cat >"$SYSCTL_FILE" <<'EOF'
# Managed by warp-interface-manager
net.ipv4.ip_forward=1
EOF
    chmod 644 "$SYSCTL_FILE"
    sysctl -q -w net.ipv4.ip_forward=1 >/dev/null
}

remove_managed_sysctl_config() {
    local previous_forward=$1
    if [[ -f "$SYSCTL_FILE" ]] && grep -q '^# Managed by warp-interface-manager$' "$SYSCTL_FILE"; then
        rm -f "$SYSCTL_FILE"
    fi
    restore_forwarding_after_remove "$previous_forward"
}

accept_terms() {
    local answer
    [[ -t 0 ]] || die "для принятия условий Cloudflare нужен интерактивный терминал."
    say
    say "Будет создана бесплатная регистрация WARP через неофициальный wgcf."
    say "Условия Cloudflare: https://www.cloudflare.com/terms/"
    read -r -p "Для продолжения введите ПРИНИМАЮ: " answer
    say
    [[ "$answer" == "ПРИНИМАЮ" ]] || { info "Условия не приняты. Установка отменена без изменений."; return 2; }
}

install_manager() {
    local table priority previous_forward self_path installed_at rc
    require_root
    require_systemd
    is_installed && die "менеджер уже установлен. Используйте reconfigure, enable или меню."
    assert_no_foreign_warp
    if choose_routing_mode; then
        :
    else
        rc=$?
        ((rc == 2)) && { info "Установка отменена. Возврат в главное меню."; return 2; }
        return "$rc"
    fi
    if accept_terms; then
        :
    else
        rc=$?
        ((rc == 2)) && return 2
        return "$rc"
    fi
    acquire_lock
    if [[ "$CHOSEN_ROUTING_MODE" == "interface" ]]; then
        validate_target_iface "$CHOSEN_IFACE" "$CHOSEN_ALLOW_RISKY"
    fi
    ensure_owned_paths_are_safe
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    printf '%s\n' "$OWNER_VALUE" >"$OWNER_FILE"
    chmod 600 "$OWNER_FILE"
    init_logging
    log_install_header "начало установки версии $VERSION; режим $CHOSEN_ROUTING_MODE; цель $CHOSEN_IFACE"
    previous_forward="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)"
    [[ "$previous_forward" == "0" || "$previous_forward" == "1" ]] || previous_forward=0
    table="$(allocate_table_id)" || die "не удалось найти свободную таблицу маршрутизации."
    priority="$(allocate_rule_priority)" || die "не удалось найти свободные приоритеты ip rule."
    install_dependencies
    install_wgcf
    register_and_generate_profile
    mkdir -p "$DATA_DIR"
    chmod 700 "$CONFIG_DIR" "$DATA_DIR"
    installed_at="$(date +%s)"
    write_state "$CHOSEN_IFACE" "$table" "$priority" "$installed_at" "$previous_forward" "$CHOSEN_ALLOW_RISKY" \
        "$CHOSEN_ROUTING_MODE" "$CHOSEN_SSH_PORTS"
    [[ "$CHOSEN_ROUTING_MODE" == "host" ]] || write_sysctl_config
    self_path="$(readlink -f "${BASH_SOURCE[0]}")"
    [[ -f "$self_path" ]] || die "не удалось определить исходный файл скрипта."
    install -m 700 "$self_path" "$INSTALL_BIN"
    write_units
    systemctl enable "$SERVICE" >>"$INSTALL_LOG" 2>&1
    info "Запускаю WARP и выполняю фактическую проверку..."
    if ! systemctl start "$SERVICE" >>"$INSTALL_LOG" 2>&1; then
        systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
        runtime_down || true
        warn "установка сохранена, но WARP отключён из-за ошибки проверки."
        die "посмотрите: journalctl -u $SERVICE -n 50 --no-pager"
    fi
    systemctl enable --now "$CHECK_TIMER" >/dev/null 2>&1
    log_event "INSTALL" "установка завершена; режим $CHOSEN_ROUTING_MODE; цель $CHOSEN_IFACE; риск $CHOSEN_ALLOW_RISKY"
    if [[ "$CHOSEN_ROUTING_MODE" == "host" ]]; then
        ok "Готово: исходящий IPv4-трафик сервера направляется через WARP."
        say "Ответы SSH с портов $CHOSEN_SSH_PORTS и endpoint WARP оставлены в основной таблице."
    else
        ok "Готово: только IPv4-трафик с интерфейса $CHOSEN_IFACE направляется через WARP."
        say "Основной маршрут сервера не изменён."
    fi
    say "Автопроверка выполняется каждые 5 минут."
    say "Журналы: $LOG_DIR (доступны также через пункт меню «Журналы»)."
    show_status
}

enable_manager() {
    require_root
    require_systemd
    acquire_lock
    ensure_owned_paths_are_safe
    load_state
    assert_no_foreign_warp
    if [[ "$ROUTING_MODE" == "interface" ]]; then
        validate_target_iface "$TARGET_IFACE" "$ALLOW_RISKY"
        write_sysctl_config
    else
        validate_ssh_ports "$SSH_PORTS" || die "не удалось защитить SSH-порты."
        ip_rule_supports_ports || die "система не поддерживает защитные правила по SSH-порту."
    fi
    systemctl enable "$SERVICE" >/dev/null 2>&1
    if ! systemctl restart "$SERVICE" >/dev/null 2>&1; then
        systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
        runtime_down || true
        die "WARP не прошёл проверку и оставлен отключённым."
    fi
    systemctl enable --now "$CHECK_TIMER" >/dev/null 2>&1
    log_event "ACTION" "WARP включён пользователем; режим $ROUTING_MODE; цель $TARGET_IFACE"
    if [[ "$ROUTING_MODE" == "host" ]]; then
        ok "WARP включён для исходящего IPv4-трафика сервера."
    else
        ok "WARP включён для интерфейса $TARGET_IFACE."
    fi
}

disable_manager() {
    require_root
    require_systemd
    acquire_lock
    ensure_owned_paths_are_safe
    load_state
    systemctl disable --now "$CHECK_TIMER" >/dev/null 2>&1 || true
    systemctl disable --now "$SERVICE" >/dev/null 2>&1 || runtime_down
    runtime_down
    log_event "ACTION" "WARP отключён пользователем с сохранением настроек"
    ok "WARP безопасно отключён. Регистрация, профиль и выбранный режим сохранены."
}

update_wgcf() {
    require_root
    is_installed || die "сначала установите менеджер WARP."
    acquire_lock
    ensure_owned_paths_are_safe
    install_dependencies
    install_wgcf
    say "Работающая маршрутизация не перезапускалась; профиль и регистрация не изменялись."
}

reconfigure_manager() {
    local was_active old_target old_allow_risky old_mode old_ssh_ports rc
    require_root
    require_systemd
    load_state
    ensure_owned_paths_are_safe
    assert_no_foreign_warp
    old_target="$TARGET_IFACE"
    old_allow_risky="$ALLOW_RISKY"
    old_mode="$ROUTING_MODE"
    old_ssh_ports="$SSH_PORTS"
    if choose_routing_mode; then
        :
    else
        rc=$?
        ((rc == 2)) && { info "Изменение отменено. Возврат в главное меню."; return 0; }
        return "$rc"
    fi
    if [[ "$CHOSEN_IFACE" == "$old_target" && "$CHOSEN_ROUTING_MODE" == "$old_mode" && "$CHOSEN_SSH_PORTS" == "$old_ssh_ports" ]]; then
        info "Эта конфигурация уже выбрана."
        return 0
    fi
    acquire_lock
    ensure_owned_paths_are_safe
    load_state
    was_active=0
    systemctl is-active --quiet "$SERVICE" && was_active=1
    systemctl stop "$SERVICE" >/dev/null 2>&1 || runtime_down
    write_state "$CHOSEN_IFACE" "$TABLE_ID" "$RULE_PRIORITY" "$INSTALLED_AT" "$PREVIOUS_IP_FORWARD" "$CHOSEN_ALLOW_RISKY" \
        "$CHOSEN_ROUTING_MODE" "$CHOSEN_SSH_PORTS"
    if [[ "$CHOSEN_ROUTING_MODE" == "interface" ]]; then
        write_sysctl_config
    elif [[ "$old_mode" == "interface" ]]; then
        remove_managed_sysctl_config "$PREVIOUS_IP_FORWARD"
    fi
    if ((was_active == 1)); then
        if ! systemctl start "$SERVICE" >/dev/null 2>&1; then
            systemctl stop "$SERVICE" >/dev/null 2>&1 || true
            runtime_down || true
            write_state "$old_target" "$TABLE_ID" "$RULE_PRIORITY" "$INSTALLED_AT" "$PREVIOUS_IP_FORWARD" "$old_allow_risky" \
                "$old_mode" "$old_ssh_ports"
            if [[ "$old_mode" == "host" ]]; then
                remove_managed_sysctl_config "$PREVIOUS_IP_FORWARD"
            else
                write_sysctl_config
            fi
            die "новая конфигурация не прошла проверку. WARP отключён, прежний выбор восстановлен в настройках."
        fi
    fi
    log_event "ACTION" "изменена конфигурация; режим $CHOSEN_ROUTING_MODE; цель $CHOSEN_IFACE; риск $CHOSEN_ALLOW_RISKY"
    if [[ "$CHOSEN_ROUTING_MODE" == "host" ]]; then
        ok "Теперь весь исходящий IPv4-трафик сервера направляется через WARP."
    else
        ok "Теперь выбран интерфейс $CHOSEN_IFACE."
    fi
}

health_is_good() {
    perform_warp_test || return 1
    if [[ "$ROUTING_MODE" == "host" ]]; then
        ssh_ports_cover_detected || return 1
        perform_full_host_test
    fi
}

health_check() {
    local repair=${1:-0}
    require_root
    load_state
    if ! systemctl is-active --quiet "$SERVICE"; then
        write_health "disabled" "Служба WARP не активна"
        warn "WARP отключён."
        return 1
    fi
    if health_is_good; then
        if [[ "$ROUTING_MODE" == "host" ]]; then
            ok "Проверка успешна: исходящий IPv4-трафик сервера идёт через WARP."
        else
            ok "Проверка успешна: WARP работает для $TARGET_IFACE."
        fi
        return 0
    fi
    write_health "failed" "Фактическая проверка WARP не прошла"
    warn "проверка WARP не прошла."
    if [[ "$repair" == "1" ]]; then
        info "Выполняю один безопасный перезапуск..."
        if systemctl restart "$SERVICE" >/dev/null 2>&1 && health_is_good; then
            ok "WARP восстановлен."
            log_event "RECOVERY" "WARP восстановлен одним перезапуском"
            return 0
        fi
        systemctl stop "$SERVICE" >/dev/null 2>&1 || true
        runtime_down || true
        write_health "failed" "Восстановление не удалось; WARP отключён"
        log_event "ERROR" "автовосстановление не удалось; маршрутизация WARP отключена"
        warn "восстановление не удалось. Маршрутизация WARP отключена, настройки сохранены."
    fi
    return 1
}

human_bytes() {
    local value=${1:-0}
    awk -v n="$value" 'BEGIN {
        split("Б КБ МБ ГБ ТБ", u, " "); i=1;
        while (n >= 1024 && i < 5) { n/=1024; i++ }
        if (i == 1) printf "%.0f %s", n, u[i]; else printf "%.2f %s", n, u[i]
    }'
}

format_time() {
    local epoch=${1:-0}
    if [[ "$epoch" =~ ^[0-9]+$ && "$epoch" -gt 0 ]]; then
        format_server_datetime "@$epoch"
    else
        printf 'нет данных'
    fi
}

show_status() {
    local active enabled timer target="—" health="неизвестно" checked="—" checked_display="—" main_safe="да" wgcf_version="—" mode_text
    if ! is_installed; then
        say "Состояние: не установлен"
        return 0
    fi
    load_state
    if [[ "$ROUTING_MODE" == "host" ]]; then
        target="весь хост"
        mode_text="весь исходящий IPv4-трафик; SSH-порты $SSH_PORTS защищены"
    else
        target="$TARGET_IFACE ($(iface_kind "$TARGET_IFACE" 2>/dev/null || echo недоступен))"
        mode_text="$([[ "$ALLOW_RISKY" == "1" ]] && echo 'один интерфейс, расширенный выбор' || echo 'один рекомендуемый интерфейс')"
    fi
    active="нет"
    enabled="нет"
    timer="нет"
    systemctl is-active --quiet "$SERVICE" 2>/dev/null && active="да"
    systemctl is-enabled --quiet "$SERVICE" 2>/dev/null && enabled="да"
    systemctl is-active --quiet "$CHECK_TIMER" 2>/dev/null && timer="да"
    health="$(state_get STATUS "$HEALTH_FILE")"
    checked="$(state_get CHECKED_AT "$HEALTH_FILE")"
    checked_display="$(format_server_datetime "$checked")"
    wgcf_version="$(installed_wgcf_version || true)"
    ip -4 route show table main 2>/dev/null | grep -Eq "(^|[[:space:]])dev[[:space:]]+$WG_IFACE([[:space:]]|$)" && main_safe="НЕТ"
    say "Состояние: установлен"
    say "Цель маршрутизации: $target"
    say "Режим: $mode_text"
    say "WARP активен: $active; автозапуск: $enabled; автопроверка: $timer"
    say "Установленный wgcf: ${wgcf_version:--}"
    say "Последняя проверка: ${health:-неизвестно}; $checked_display"
    say "Основная таблица маршрутов не содержит $WG_IFACE: $main_safe"
    if [[ "$ROUTING_MODE" == "host" ]] && ! ssh_ports_cover_detected; then
        warn "обнаруженные настройки SSH отличаются от защищённых портов. Отключите WARP и выполните reconfigure."
    fi
}

show_stats() {
    local rx=0 tx=0 target_rx=0 target_tx=0 handshake=0 warp_ip exit_ip endpoint detail
    require_root
    load_state
    show_status
    say
    if [[ -r "/sys/class/net/$WG_IFACE/statistics/rx_bytes" ]]; then
        rx="$(<"/sys/class/net/$WG_IFACE/statistics/rx_bytes")"
        tx="$(<"/sys/class/net/$WG_IFACE/statistics/tx_bytes")"
    fi
    if [[ "$ROUTING_MODE" == "interface" && -r "/sys/class/net/$TARGET_IFACE/statistics/rx_bytes" ]]; then
        target_rx="$(<"/sys/class/net/$TARGET_IFACE/statistics/rx_bytes")"
        target_tx="$(<"/sys/class/net/$TARGET_IFACE/statistics/tx_bytes")"
    fi
    handshake="$(wg show "$WG_IFACE" latest-handshakes 2>/dev/null | awk '{ if ($2 > max) max=$2 } END { print max+0 }')"
    warp_ip="$(profile_ipv4)"
    endpoint="$(profile_endpoint)"
    exit_ip=""
    if systemctl is-active --quiet "$SERVICE" 2>/dev/null && [[ -n "$warp_ip" ]]; then
        detail="$(curl -4fsS --interface "$warp_ip" --connect-timeout 5 --max-time 15 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null || true)"
        exit_ip="$(awk -F= '$1 == "ip" {print $2; exit}' <<<"$detail")"
    fi
    say "Статистика текущего запуска:"
    say "  WARP получено: $(human_bytes "$rx"); отправлено: $(human_bytes "$tx")"
    if [[ "$ROUTING_MODE" == "interface" ]]; then
        say "  $TARGET_IFACE получено: $(human_bytes "$target_rx"); отправлено: $(human_bytes "$target_tx")"
    fi
    say "  Последнее WireGuard-рукопожатие: $(format_time "$handshake")"
    say "  Endpoint WARP: ${endpoint:--}"
    say "  Выходной IP WARP: ${exit_ip:--}"
    say "  MTU: $(awk -F= 'tolower($1) ~ /^[[:space:]]*mtu[[:space:]]*$/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' "$WG_CONFIG" 2>/dev/null || true)"
}

show_logs() {
    local answer
    require_root
    init_logging
    if [[ ! -t 0 ]]; then
        say "Последние события:"
        tail -n 80 "$EVENT_LOG" 2>/dev/null | format_manager_log_output || true
        say
        say "Подробные журналы находятся в $LOG_DIR"
        return 0
    fi
    while true; do
        say
        say "${C_BOLD}Журналы и диагностика${C_RESET}"
        say "1) События менеджера"
        say "2) Подробности установки и пакетов"
        say "3) Служба маршрутизации"
        say "4) Автоматические проверки"
        say "5) Показать расположение журналов"
        say "0) Назад"
        read -r -p "Выберите категорию: " answer
        say
        case "$answer" in
            1) tail -n 100 "$EVENT_LOG" 2>/dev/null | format_manager_log_output || true ;;
            2) tail -n 160 "$INSTALL_LOG" 2>/dev/null | format_manager_log_output || true ;;
            3) journalctl -u "$SERVICE" -n 100 -o short-unix --no-pager 2>/dev/null | format_journal_output || say "Записей пока нет." ;;
            4) journalctl -u "$CHECK_SERVICE" -n 100 -o short-unix --no-pager 2>/dev/null | format_journal_output || say "Записей пока нет." ;;
            5)
                say "События: $EVENT_LOG"
                say "Установка: $INSTALL_LOG"
                say "Служба: journalctl -u $SERVICE"
                say "Проверки: journalctl -u $CHECK_SERVICE"
                ;;
            0) return 0 ;;
            *) warn "неизвестный пункт." ;;
        esac
        [[ "$answer" == "5" ]] || { say; read -r -p "Нажмите Enter для продолжения..." _; }
    done
}

restore_forwarding_after_remove() {
    local previous=$1 other_enable=0 file
    [[ "$previous" == "0" ]] || return 0
    for file in /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
        [[ -f "$file" && "$file" != "$SYSCTL_FILE" ]] || continue
        if grep -Eq '^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=[[:space:]]*1([[:space:]]|$)' "$file"; then
            other_enable=1
            break
        fi
    done
    if ((other_enable == 0)) && [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 1)" == "1" ]]; then
        sysctl -q -w net.ipv4.ip_forward=0 >/dev/null || true
    fi
}

remove_manager() {
    local answer previous_forward
    require_root
    require_systemd
    load_state
    previous_forward="$PREVIOUS_IP_FORWARD"
    [[ -t 0 ]] || die "полное удаление требует интерактивного подтверждения."
    say "Будут локально удалены регистрация WARP, ключи, профиль, правила, службы и статистика этого менеджера."
    say "Системные пакеты WireGuard/curl/jq не удаляются, поскольку могут использоваться другими программами."
    read -r -p "Для полного удаления введите УДАЛИТЬ: " answer
    say
    [[ "$answer" == "УДАЛИТЬ" ]] || { info "Удаление отменено."; return 0; }
    acquire_lock
    ensure_owned_paths_are_safe
    systemctl disable --now "$CHECK_TIMER" >/dev/null 2>&1 || true
    systemctl disable --now "$SERVICE" >/dev/null 2>&1 || runtime_down
    runtime_down || true
    for unit in "$SERVICE" "$CHECK_SERVICE" "$CHECK_TIMER"; do
        if [[ -f "$UNIT_DIR/$unit" ]] && grep -q '^# Managed by warp-interface-manager$' "$UNIT_DIR/$unit"; then
            rm -f "$UNIT_DIR/$unit"
        fi
    done
    if [[ -f "$WG_CONFIG" ]] && grep -q '^# Managed by warp-interface-manager\.' "$WG_CONFIG"; then
        rm -f "$WG_CONFIG"
    fi
    if [[ -f "$SYSCTL_FILE" ]] && grep -q '^# Managed by warp-interface-manager$' "$SYSCTL_FILE"; then
        rm -f "$SYSCTL_FILE"
    fi
    log_event "REMOVE" "начато полное удаление менеджера"
    rm -rf -- "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR" "$RUNTIME_DIR" /usr/local/lib/warp-interface-manager
    systemctl daemon-reload >/dev/null 2>&1
    systemctl reset-failed "$SERVICE" "$CHECK_SERVICE" >/dev/null 2>&1 || true
    [[ "$ROUTING_MODE" == "host" ]] || restore_forwarding_after_remove "$previous_forward"
    if [[ -f "$INSTALL_BIN" ]] && grep -q '^PROGRAM_NAME="Менеджер WARP-маршрутизации"$' "$INSTALL_BIN" 2>/dev/null; then
        rm -f "$INSTALL_BIN"
    fi
    ok "Локальная установка WARP и все объекты этого менеджера полностью удалены."
}

self_test() {
    local tmp raw safe metadata prerelease disguised_prerelease wrong_url
    command -v jq >/dev/null 2>&1 || die "для самопроверки метаданных релиза требуется jq."
    tmp="$(mktemp -d)"
    trap 'rm -rf -- "$tmp"' RETURN
    raw="$tmp/raw.conf"
    safe="$tmp/safe.conf"
    cat >"$raw" <<'EOF'
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 172.16.0.2/32
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = engage.cloudflareclient.com:2408
PersistentKeepalive = 25
EOF
    validate_raw_profile "$raw"
    sanitize_profile_file "$raw" "$safe" 1280
    grep -q '^Table = off$' "$safe" || die "самопроверка: Table = off не добавлен."
    grep -q '^MTU = 1280$' "$safe" || die "самопроверка: MTU не применён."
    ! grep -Eqi '^[[:space:]]*DNS[[:space:]]*=' "$safe" || die "самопроверка: DNS не удалён."
    is_safe_iface_name "tun0" || die "самопроверка имени интерфейса не прошла."
    ! is_safe_iface_name "bad iface" || die "самопроверка отклонения имени не прошла."
    [[ "$WG_IFACE" != "$(default_iface)" ]] || die "служебное имя конфликтует с основным интерфейсом."
    metadata="$tmp/release.json"
    prerelease="$tmp/prerelease.json"
    disguised_prerelease="$tmp/disguised-prerelease.json"
    wrong_url="$tmp/wrong-url.json"
    cat >"$metadata" <<'EOF'
{
  "tag_name": "v9.8.7",
  "draft": false,
  "prerelease": false,
  "assets": [
    {
      "name": "checksums.txt",
      "state": "uploaded",
      "browser_download_url": "https://github.com/ViRb3/wgcf/releases/download/v9.8.7/checksums.txt"
    },
    {
      "name": "wgcf_9.8.7_linux_amd64",
      "state": "uploaded",
      "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "browser_download_url": "https://github.com/ViRb3/wgcf/releases/download/v9.8.7/wgcf_9.8.7_linux_amd64"
    }
  ]
}
EOF
    parse_wgcf_release_metadata "$metadata" amd64 || die "самопроверка стабильного релиза не прошла."
    [[ "$WGCF_RELEASE_VERSION" == "9.8.7" ]] || die "самопроверка выбрала неверную версию релиза."
    jq '.prerelease = true | .tag_name = "v9.8.7-beta.1"' "$metadata" >"$prerelease"
    if parse_wgcf_release_metadata "$prerelease" amd64; then
        die "самопроверка ошибочно приняла предварительный релиз."
    fi
    jq '.prerelease = false | .tag_name = "v9.8.7-rc.1"' "$metadata" >"$disguised_prerelease"
    if parse_wgcf_release_metadata "$disguised_prerelease" amd64; then
        die "самопроверка ошибочно приняла RC с неверным флагом prerelease."
    fi
    jq '.assets[1].browser_download_url = "https://example.invalid/wgcf"' "$metadata" >"$wrong_url"
    if parse_wgcf_release_metadata "$wrong_url" amd64; then
        die "самопроверка ошибочно приняла посторонний адрес бинарника."
    fi
    trap - RETURN
    rm -rf -- "$tmp"
    ok "Самопроверка пройдена; система не изменялась."
}

interactive_menu() {
    local answer rc
    [[ -t 0 ]] || { usage; exit 1; }
    while true; do
        clear 2>/dev/null || true
        say "${C_BOLD}${PROGRAM_NAME} ${VERSION}${C_RESET}"
        say "Управляемая маршрутизация IPv4 отдельного интерфейса или всего сервера"
        say
        show_status 2>/dev/null || true
        say
        if is_installed; then
            say "1) Включить WARP"
            say "2) Отключить с сохранением"
            say "3) Изменить режим или интерфейс"
            say "4) Проверить"
            say "5) Проверить и восстановить"
            say "6) Статистика и информация"
            say "7) Показать интерфейсы"
            say "8) Обновить wgcf до последнего стабильного"
            say "9) Журналы"
            say "10) Полностью удалить"
            say "0) Выход"
            read -r -p "Выберите действие: " answer
            say
            case "$answer" in
                1) enable_manager ;;
                2) disable_manager ;;
                3) reconfigure_manager ;;
                4) health_check 0 || true ;;
                5) health_check 1 || true ;;
                6) show_stats ;;
                7) scan_interfaces 0 ;;
                8) update_wgcf ;;
                9) show_logs ;;
                10) remove_manager; is_installed || return 0 ;;
                0) return 0 ;;
                *) warn "неизвестный пункт." ;;
            esac
        else
            say "1) Найти интерфейс и установить WARP"
            say "2) Только показать интерфейсы"
            say "3) Самопроверка скрипта"
            say "0) Выход"
            read -r -p "Выберите действие: " answer
            say
            case "$answer" in
                1)
                    if install_manager; then
                        :
                    else
                        rc=$?
                        ((rc == 2)) || return "$rc"
                    fi
                    ;;
                2) scan_interfaces ;;
                3) self_test ;;
                0) return 0 ;;
                *) warn "неизвестный пункт." ;;
            esac
        fi
        say
        read -r -p "Нажмите Enter для продолжения..." _
    done
}

main() {
    local command=${1:-menu} repair=0
    require_linux
    case "$command" in
        menu) interactive_menu ;;
        scan) scan_interfaces ;;
        install) install_manager ;;
        enable) enable_manager ;;
        disable) disable_manager ;;
        reconfigure) reconfigure_manager ;;
        check)
            [[ ${2:-} == "--repair" ]] && repair=1
            health_check "$repair"
            ;;
        status) show_status ;;
        stats) show_stats ;;
        update-wgcf) update_wgcf ;;
        logs) show_logs ;;
        remove) remove_manager ;;
        self-test) self_test ;;
        --version|-V) printf '%s %s\n' "$PROGRAM_NAME" "$VERSION" ;;
        --help|-h|help) usage ;;
        _service-up) require_root; service_up ;;
        _service-down) require_root; runtime_down ;;
        _health-check)
            require_root
            [[ ${2:-} == "--repair" ]] && repair=1
            health_check "$repair"
            ;;
        *) usage; die "неизвестная команда: $command" ;;
    esac
}

if [[ ${WIM_SOURCE_ONLY:-0} != "1" ]]; then
    main "$@"
fi
