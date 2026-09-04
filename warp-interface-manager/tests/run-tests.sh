#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/warp-interface-manager.sh"

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

bash -n "$SCRIPT"
bash -n "$0"

version_output="$(bash "$SCRIPT" --version)"
[[ "$version_output" == *"1.3.2"* ]] || fail "неверная версия"

help_output="$(bash "$SCRIPT" --help)"
for command in install enable disable reconfigure check status stats update-wgcf logs remove self-test; do
    [[ "$help_output" == *"$command"* ]] || fail "в справке нет команды $command"
done

bash "$SCRIPT" self-test >/dev/null
bash "$SCRIPT" scan >/dev/null

grep -q 'Table = off' "$SCRIPT" || fail "нет защиты Table = off"
grep -q 'interface_protection_reason' "$SCRIPT" || fail "нет защиты интерфейсов"
grep -q 'runtime_down' "$SCRIPT" || fail "нет отката"
grep -q 'WARP_INTERFACE_MANAGER' "$SCRIPT" || fail "нет маркера firewall"
grep -q 'WGCF_LATEST_API=.*releases/latest' "$SCRIPT" || fail "нет динамического поиска последнего релиза wgcf"
grep -q '.prerelease == false' "$SCRIPT" || fail "нет отклонения предварительных релизов wgcf"
grep -q 'checksums.txt' "$SCRIPT" || fail "нет проверки релизной контрольной суммы wgcf"
! grep -q '^WGCF_VERSION=' "$SCRIPT" || fail "осталась фиксированная версия wgcf"
[[ -f "$ROOT_DIR/README.md" && ! -e "$ROOT_DIR/README.txt" ]] || fail "README должен быть в формате Markdown"

if grep -Rqs --exclude-dir=.git 'warp-interface-manager' \
    "$ROOT_DIR/../settings.gradle" "$ROOT_DIR/../settings.gradle.kts" \
    "$ROOT_DIR/../app/build.gradle" "$ROOT_DIR/../app/build.gradle.kts" 2>/dev/null; then
    fail "подпроект неожиданно подключён к Gradle/Android"
fi

mock_root="$(mktemp -d)"
trap 'rm -rf -- "$mock_root"' EXIT
mkdir -p "$mock_root/bin" "$mock_root/sys/tun-test" "$mock_root/proc/tun-test"
: >"$mock_root/sys/tun-test/tun_flags"
printf '2' >"$mock_root/proc/tun-test/rp_filter"
mock_log="$mock_root/calls.log"
mock_wg_marker="$mock_root/warp-up"
: >"$mock_log"

cat >"$mock_root/bin/ip" <<'EOF'
#!/usr/bin/env bash
printf 'ip %s\n' "$*" >>"$WIM_MOCK_LOG"
if [[ ${1:-} == "-4" && ${2:-} == "rule" && ${3:-} == "show" ]]; then
    printf '17998: from all to 162.159.192.1 lookup main\n'
    [[ -z ${WIM_MOCK_POLICY_IFACE:-} ]] || printf '17000: from all iif %s lookup 51999\n' "$WIM_MOCK_POLICY_IFACE"
    [[ ${WIM_MOCK_GLOBAL_CONFLICT:-0} != "1" ]] || printf '12000: from all fwmark 0x1 lookup 52000\n'
    exit 0
fi
case "$*" in
    "link show dev tun-test")
        printf '10: tun-test: <POINTOPOINT,UP,LOWER_UP> mtu 1500 state UNKNOWN\n'
        exit 0
        ;;
    "link show dev physical-test")
        printf '11: physical-test: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n'
        exit 0
        ;;
    "link show dev warp-selective")
        [[ -f "$WIM_MOCK_WG_MARKER" ]]
        exit
        ;;
    "-4 route show table main default"|"-4 route show table main"|"-4 route show table all")
        printf 'default via 192.0.2.1 dev eth0\n'
        exit 0
        ;;
    "-4 route get 1.1.1.1 from 172.16.0.2")
        printf '1.1.1.1 dev warp-selective src 172.16.0.2\n'
        exit 0
        ;;
    "-4 route get 1.1.1.1")
        printf '1.1.1.1 dev warp-selective src 172.16.0.2\n'
        exit 0
        ;;
    "rule help")
        printf 'Usage: ip rule { add | del } [ ipproto PROTOCOL ] [ sport [ NUMBER | NUMBER-NUMBER ] ]\n'
        exit 0
        ;;
    "-d -o link show dev veth-test")
        printf '12: veth-test@if13: <BROADCAST,UP> mtu 1500 veth\n'
        exit 0
        ;;
    *" rule del "*|*" route del "*) exit 1 ;;
    *) exit 0 ;;
esac
EOF

cat >"$mock_root/bin/iptables" <<'EOF'
#!/usr/bin/env bash
printf 'iptables %s\n' "$*" >>"$WIM_MOCK_LOG"
for value in "$@"; do
    [[ "$value" == "-C" ]] && exit 1
done
exit 0
EOF

cat >"$mock_root/bin/wg-quick" <<'EOF'
#!/usr/bin/env bash
printf 'wg-quick %s\n' "$*" >>"$WIM_MOCK_LOG"
case "${1:-}" in
    up) : >"$WIM_MOCK_WG_MARKER" ;;
    down) rm -f "$WIM_MOCK_WG_MARKER" ;;
esac
EOF

cat >"$mock_root/bin/wg" <<'EOF'
#!/usr/bin/env bash
printf 'wg %s\n' "$*" >>"$WIM_MOCK_LOG"
case "$*" in
    "show warp-selective latest-handshakes") printf 'peer 1700000000\n' ;;
    "show tun-test"|"show eth0") exit 1 ;;
    *) exit 1 ;;
esac
EOF

cat >"$mock_root/bin/getent" <<'EOF'
#!/usr/bin/env bash
if [[ ${1:-} == "ahostsv4" && ${2:-} == "engage.cloudflareclient.com" ]]; then
    printf '162.159.192.1 STREAM engage.cloudflareclient.com\n'
    printf '162.159.192.1 DGRAM engage.cloudflareclient.com\n'
    exit 0
fi
exit 2
EOF

cat >"$mock_root/bin/curl" <<'EOF'
#!/usr/bin/env bash
printf 'curl %s\n' "$*" >>"$WIM_MOCK_LOG"
[[ ${WIM_MOCK_FAIL_CURL:-0} == "1" ]] && exit 28
printf 'warp=on\nip=203.0.113.8\n'
EOF

cat >"$mock_root/bin/sysctl" <<'EOF'
#!/usr/bin/env bash
printf 'sysctl %s\n' "$*" >>"$WIM_MOCK_LOG"
[[ "${1:-}" == "-n" ]] && printf '0\n'
exit 0
EOF

chmod +x "$mock_root/bin/"*

(
    export WIM_TEST_MODE=1
    export WIM_SOURCE_ONLY=1
    export WIM_SYS_CLASS_NET_ROOT="$mock_root/sys"
    export WIM_PROC_SYS_IPV4_CONF_ROOT="$mock_root/proc"
    export WIM_WIREGUARD_CONFIG_ROOT="$mock_root/etc/wireguard"
    export WIM_MOCK_LOG="$mock_log"
    export WIM_MOCK_WG_MARKER="$mock_wg_marker"
    # shellcheck source=../warp-interface-manager.sh
    # shellcheck disable=SC1091
    source "$SCRIPT"
    PATH="$mock_root/bin:$PATH"
    CONFIG_DIR="$mock_root/etc/warp-interface-manager"
    STATE_FILE="$CONFIG_DIR/state.env"
    OWNER_FILE="$CONFIG_DIR/owner"
    WG_CONFIG="$mock_root/etc/wireguard/warp-selective.conf"
    DATA_DIR="$mock_root/var/lib/warp-interface-manager"
    HEALTH_FILE="$DATA_DIR/health.env"
    RUNTIME_DIR="$mock_root/run/warp-interface-manager"
    # Используется функциями из подключённого основного скрипта.
    # shellcheck disable=SC2034
    RUNTIME_FILE="$RUNTIME_DIR/runtime.env"
    mkdir -p "$CONFIG_DIR" "$(dirname "$WG_CONFIG")" "$DATA_DIR"
    formatted_time="$(TZ=Etc/UTC format_server_datetime '2026-09-03T18:29:15+00:00')"
    [[ "$formatted_time" == "03.09.2026 18:29:15 UTC (+00:00)" ]] || fail "российский формат времени неверен: $formatted_time"
    journal_time="$(printf '178845?\n' | format_journal_output)"
    [[ "$journal_time" == "178845?" ]] || fail "неизвестная строка журнала была изменена"
    journal_time="$(printf '1700000000.000000 host service: сообщение\n' | TZ=Etc/UTC format_journal_output)"
    [[ "$journal_time" == "14.11.2023 22:13:20 UTC (+00:00) host service: сообщение" ]] || fail "время journalctl отформатировано неверно: $journal_time"
    legacy_log_time="$(printf '2026-09-03T18:29:15+00:00 [INFO] сообщение\n' | TZ=Etc/UTC format_manager_log_output)"
    [[ "$legacy_log_time" == "03.09.2026 18:29:15 UTC (+00:00) [INFO] сообщение" ]] || fail "старое ISO-время журнала отформатировано неверно: $legacy_log_time"
    printf '%s\n' "$OWNER_VALUE" >"$OWNER_FILE"
    printf 'TARGET_IFACE=tun-test\nTABLE_ID=51880\nRULE_PRIORITY=18000\nINSTALLED_AT=1700000000\nPREVIOUS_IP_FORWARD=0\n' >"$STATE_FILE"
    cat >"$WG_CONFIG" <<'EOF'
# Managed by warp-interface-manager. Do not edit while active.
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 172.16.0.2/32
Table = off
MTU = 1280

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
AllowedIPs = 0.0.0.0/0
Endpoint = engage.cloudflareclient.com:2408
EOF
    service_up
    [[ -f "$mock_wg_marker" ]] || fail "модель: WARP-интерфейс не поднят"
    [[ "$(state_get STATUS "$HEALTH_FILE")" == "healthy" ]] || fail "модель: проверка не стала healthy"
    [[ "$(interface_protection_reason eth0)" == "маршрут по умолчанию в одной из таблиц" ]] || fail "модель: основной интерфейс не защищён"
    WIM_TEST_WG_IFACE=wdtt-test
    mkdir -p "$mock_root/sys/$WIM_TEST_WG_IFACE"
    # shellcheck disable=SC2329
    wg() {
        if [[ ${1:-} == "show" && ${2:-} == "wdtt-test" && ${3:-} == "peers" ]]; then
            printf 'peer-key\n'
        elif [[ ${1:-} == "show" && ${2:-} == "wdtt-test" && ${3:-} == "listen-port" ]]; then
            printf '51820\n'
        elif [[ ${1:-} == "show" && ${2:-} == "wdtt-test" && -z ${3:-} ]]; then
            return 0
        else
            command "$mock_root/bin/wg" "$@"
        fi
    }
    [[ "$(interface_protection_reason "$WIM_TEST_WG_IFACE")" == "действующий WireGuard-интерфейс с пирами или портом" ]] || fail "модель: действующий WireGuard-интерфейс не защищён"
    unset -f wg
    mkdir -p "$mock_root/sys/physical-test" "$mock_root/sys/veth-test" "$mock_root/sys/br-test/bridge" "$mock_root/sys/slave-test"
    ln -s ../br-test "$mock_root/sys/slave-test/master"
    [[ "$(interface_protection_reason physical-test)" == "физический интерфейс" ]] || fail "модель: физический интерфейс не защищён"
    [[ -z "$(interface_protection_reason veth-test)" ]] || fail "модель: свободный veth ошибочно защищён"
    [[ -n "$(interface_protection_reason br-test)" ]] || fail "модель: bridge не защищён"
    [[ "$(interface_protection_reason slave-test)" == "подчинён интерфейсу br-test" ]] || fail "модель: slave-интерфейс не защищён"
    recommended_output="$(scan_interfaces 0)"
    [[ "$recommended_output" == *"tun-test"* ]] || fail "рекомендуемый список скрыл безопасный интерфейс"
    [[ "$recommended_output" != *"physical-test"* ]] || fail "рекомендуемый список показывает нерекомендуемый интерфейс"
    [[ "$recommended_output" == *"Скрыто рискованных интерфейсов, доступных в полном списке"* ]] || fail "нет точной сводки скрытых интерфейсов"
    all_output="$(scan_interfaces 1)"
    [[ "$all_output" == *"physical-test"* ]] || fail "полный список скрыл интерфейс"
    export WIM_MOCK_POLICY_IFACE=tun-test
    [[ "$(interface_protection_reason tun-test)" == "уже участвует в сторонней policy routing" ]] || fail "существующая policy routing интерфейса не обнаружена"
    unset WIM_MOCK_POLICY_IFACE
    grep -q 'rule add iif tun-test table 51880 priority 18001' "$mock_log" || fail "модель: нет точного правила входного интерфейса"
    ! grep -q 'route add default.*table main' "$mock_log" || fail "модель: изменена основная таблица"
    runtime_down
    [[ ! -e "$mock_wg_marker" ]] || fail "модель: WARP-интерфейс не опущен"
    [[ "$(<"$mock_root/proc/tun-test/rp_filter")" == "2" ]] || fail "модель: rp_filter не восстановлен"
    export WIM_MOCK_FAIL_CURL=1
    if service_up; then
        fail "модель: запуск ошибочно успешен при недоступном WARP"
    fi
    [[ ! -e "$mock_wg_marker" ]] || fail "модель: после ошибки WARP-интерфейс не очищен"
    [[ "$(state_get STATUS "$HEALTH_FILE")" == "failed" ]] || fail "модель: ошибка проверки не сохранена"
    unset WIM_MOCK_FAIL_CURL

    : >"$mock_log"
    printf 'TARGET_IFACE=-\nTABLE_ID=51880\nRULE_PRIORITY=18000\nINSTALLED_AT=1700000000\nPREVIOUS_IP_FORWARD=0\nALLOW_RISKY=0\nROUTING_MODE=host\nSSH_PORTS=2222\n' >"$STATE_FILE"
    # shellcheck disable=SC2329
    detect_ssh_ports() { printf '2222'; }
    service_up
    [[ -f "$mock_wg_marker" ]] || fail "модель всего хоста: WARP-интерфейс не поднят"
    grep -q 'rule add to 162.159.192.1/32 table main priority 17998' "$mock_log" || fail "модель всего хоста: endpoint WARP не защищён"
    grep -q 'rule add ipproto tcp sport 2222 table main priority 17999' "$mock_log" || fail "модель всего хоста: нестандартный SSH-порт не защищён"
    grep -q 'rule add table 51880 priority 18001' "$mock_log" || fail "модель всего хоста: нет общего правила WARP"
    ! grep -q 'iptables .* -A\|iptables .* -I' "$mock_log" || fail "модель всего хоста: неожиданно изменён FORWARD/NAT"
    rm -f "$RUNTIME_FILE"
    runtime_down
    [[ ! -e "$mock_wg_marker" ]] || fail "модель всего хоста: WARP-интерфейс не опущен"
    grep -q 'rule del to 162.159.192.1/32 table main priority 17998' "$mock_log" || fail "модель всего хоста: endpoint не очищен без runtime-файла"
    detect_ssh_ports() { printf '3333'; }
    if service_up; then
        fail "модель всего хоста: запуск не остановлен после изменения SSH-порта"
    fi
    [[ ! -e "$mock_wg_marker" ]] || fail "модель всего хоста: после изменения SSH-порта WARP не очищен"
    unset -f detect_ssh_ports
    export WIM_MOCK_GLOBAL_CONFLICT=1
    [[ -n "$(full_host_routing_conflicts)" ]] || fail "конфликт общей policy routing не обнаружен"
    if check_full_host_routing_is_clear >/dev/null 2>&1; then
        fail "режим всего хоста разрешён при сторонней policy routing"
    fi
    unset WIM_MOCK_GLOBAL_CONFLICT
    export WIM_TEST_FOREIGN_WARP_EVIDENCE='тестовый сторонний WARP'
    if (assert_no_foreign_warp >/dev/null 2>&1); then
        fail "сторонний WARP не заблокировал установку"
    fi
    unset WIM_TEST_FOREIGN_WARP_EVIDENCE
    export SSH_CONNECTION='198.51.100.10 54321 192.0.2.10 2222'
    [[ "$(current_ssh_server_port)" == "2222" ]] || fail "модель всего хоста: порт текущего SSH определён неверно"
    validate_ssh_ports '22,2222' || fail "модель всего хоста: корректные SSH-порты отклонены"
    ! validate_ssh_ports '0,70000' || fail "модель всего хоста: некорректные SSH-порты приняты"
    is_ipv4_address '162.159.192.1' || fail "корректный IPv4 endpoint отклонён"
    ! is_ipv4_address '999.159.192.1' || fail "некорректный IPv4 endpoint принят"
    offer_all_interfaces <<<"1" >/dev/null 2>&1 || fail "переход к полному списку не сработал"
    if offer_all_interfaces <<<"0" >/dev/null 2>&1; then
        fail "отмена перехода к полному списку не сработала"
    fi
    # shellcheck disable=SC2329
    choose_interface() { return 2; }
    if choose_routing_mode <<< $'1\n0\n' >/dev/null 2>&1; then
        fail "возврат из выбора интерфейса завершился успехом вместо перехода назад"
    else
        [[ "$?" == "2" ]] || fail "возврат в главное меню имеет неверный код"
    fi
)

printf 'OK: все безопасные локальные проверки пройдены.\n'
