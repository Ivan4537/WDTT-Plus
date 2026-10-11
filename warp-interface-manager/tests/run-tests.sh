#!/usr/bin/env bash
# Globals and callbacks below are consumed by the sourced manager.
# shellcheck disable=SC2034,SC2317
set -euo pipefail
IFS=$'\n\t'
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/warp-interface-manager.sh"
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
bash -n "$SCRIPT"
bash -n "$0"
[[ "$(bash "$SCRIPT" --version)" == *1.4.0* ]] || fail 'неверная версия'
bash "$SCRIPT" self-test >/dev/null
bash "$SCRIPT" scan >/dev/null
help_output="$(bash "$SCRIPT" --help)"
for command in scan install enable disable reconfigure check status stats update-wgcf logs remove self-test; do
    [[ "$help_output" == *"$command"* ]] || fail "в справке нет команды $command"
done
if grep -Rqs 'warp-interface-manager' "$ROOT_DIR/../app/build.gradle.kts" "$ROOT_DIR/../settings.gradle.kts" 2>/dev/null; then
    fail 'подпроект подключён к Android'
fi
mock_root="$(mktemp -d)"
trap 'rm -rf -- "$mock_root"' EXIT
mkdir -p "$mock_root/bin" "$mock_root/sys" "$mock_root/proc" "$mock_root/etc/wireguard"
for command in ip wg wg-quick iptables iptables-save nft curl getent sysctl; do
    ln -s "$ROOT_DIR/tests/mock-command.py" "$mock_root/bin/$command"
done
[[ -x "$ROOT_DIR/tests/mock-command.py" ]] || fail 'mock-command.py должен быть исполняемым'
export WIM_MOCK_ROOT="$mock_root" WIM_TEST_MODE=1 WIM_SOURCE_ONLY=1
export WIM_SYS_CLASS_NET_ROOT="$mock_root/sys" WIM_PROC_SYS_IPV4_CONF_ROOT="$mock_root/proc" WIM_WIREGUARD_CONFIG_ROOT="$mock_root/etc/wireguard"
# shellcheck source=../warp-interface-manager.sh
# shellcheck disable=SC1091
source "$SCRIPT"
PATH="$mock_root/bin:$PATH"
CONFIG_DIR="$mock_root/etc/warp-interface-manager"
STATE_FILE="$CONFIG_DIR/state.env"; OWNER_FILE="$CONFIG_DIR/owner"
WG_CONFIG="$mock_root/etc/wireguard/warp-selective.conf"
DATA_DIR="$mock_root/data"; HEALTH_FILE="$DATA_DIR/health.env"
RUNTIME_DIR="$mock_root/run"; RUNTIME_FILE="$RUNTIME_DIR/runtime.env"
SYSCTL_FILE="$mock_root/sysctl.conf"
LOG_DIR="$mock_root/log"; EVENT_LOG="$LOG_DIR/events.log"; INSTALL_LOG="$LOG_DIR/install.log"
mock_log="$mock_root/calls.log"; mock_wg_marker="$mock_root/warp-up"
mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$RUNTIME_DIR"
printf '%s\n' "$OWNER_VALUE" >"$OWNER_FILE"
for iface in tun-test tun-second tun-other eth0; do
    mkdir -p "$mock_root/sys/$iface" "$mock_root/proc/$iface"
    : >"$mock_root/sys/$iface/tun_flags"
    printf '2' >"$mock_root/proc/$iface/rp_filter"
done
cat >"$WG_CONFIG" <<'PROFILE'
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
PROFILE
printf 'registration fixture\n' >"$CONFIG_DIR/wgcf-account.toml"
chmod 600 "$WG_CONFIG" "$OWNER_FILE" "$CONFIG_DIR/wgcf-account.toml"
profile_hash="$(sha256sum "$WG_CONFIG")"
account_hash="$(sha256sum "$CONFIG_DIR/wgcf-account.toml")"
# These overrides are scoped to this temporary-root test process.
require_root() { :; }
require_systemd() { :; }
acquire_lock() { :; }
ensure_owned_paths_are_safe() { :; }
sleep() { :; }
detect_ssh_ports() { printf '2222'; }
systemctl() {
    printf 'systemctl %s\n' "$*" >>"$mock_log"
    case "${1:-}" in
        is-active) [[ -f "$mock_root/service-active" ]] ;;
        is-enabled|enable|daemon-reload|reset-failed) return 0 ;;
        disable)
            if [[ "$*" == *--now* && "${!#}" == "$SERVICE" ]]; then systemctl stop "$SERVICE"; fi
            return 0
            ;;
        cat) return 1 ;;
        stop)
            if [[ -f "$mock_root/service-active" ]]; then runtime_down || return 1; fi
            rm -f "$mock_root/service-active"
            ;;
        start|restart)
            if [[ "$1" == restart && -f "$mock_root/service-active" ]]; then runtime_down || return 1; fi
            rm -f "$mock_root/service-active"
            if [[ "${MOCK_FAIL_MODE:-}" == "$(state_get ROUTING_MODE)" ]]; then return 1; fi
            service_up || return 1
            : >"$mock_root/service-active"
            ;;
        *) return 1 ;;
    esac
}
assert_clean() {
    [[ ! -e "$mock_wg_marker" && ! -e "$RUNTIME_FILE" ]] || fail 'интерфейс/runtime остались'
    python3 - "$mock_root/kernel.json" <<'PY'
import json,sys
s=json.load(open(sys.argv[1]))
assert not s['rules'] and not s['routes'] and not s['firewall'],s
PY
}
route_dev() { ip -4 route get 1.1.1.1 "$@" | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}'; }
select_state() { write_state "$1" 51880 18000 1700000000 0 "${4:-0}" "${2:-interface}" "${3:-}"; load_state; }

# Legacy single-interface configuration is accepted without rewriting or losing risk consent.
printf 'TARGET_IFACE=tun-test\nTABLE_ID=51880\nRULE_PRIORITY=18000\nINSTALLED_AT=1700000000\nPREVIOUS_IP_FORWARD=0\nALLOW_RISKY=1\n' >"$STATE_FILE"
legacy_hash="$(sha256sum "$STATE_FILE")"
load_state
[[ "$TARGET_IFACES" == tun-test && "$RISKY_IFACES" == tun-test ]] || fail 'миграция старого выбора'
[[ "$(sha256sum "$STATE_FILE")" == "$legacy_hash" ]] || fail 'чтение изменило старое состояние'
service_up
health_is_good || fail 'старая конфигурация не работает'
[[ "$(state_get WG_IFINDEX "$RUNTIME_FILE")" == 42 ]] || fail 'нет runtime index'
runtime_down
assert_clean
[[ "$(<"$mock_root/proc/tun-test/rp_filter")" == 2 ]] || fail 'старый rp_filter потерян'

# Existing interface safety and foreign-install detection remain enforced.
[[ -z "$(interface_protection_reason tun-test)" ]] || fail 'свободный TUN защищён'
[[ -n "$(interface_protection_reason eth0)" ]] || fail 'основной интерфейс не защищён'
ip -4 rule add iif tun-test table 51999 priority 17000
[[ "$(interface_protection_reason tun-test)" == 'уже участвует в сторонней policy routing' ]] || fail 'не обнаружена чужая policy routing'
ip -4 rule del iif tun-test table 51999 priority 17000
iptables -A FORWARD -i tun-test -m comment --comment FOREIGN_TEST_RULE -j ACCEPT
[[ "$(interface_protection_reason tun-test)" == 'уже участвует в сторонних firewall-правилах' ]] || fail 'не обнаружен чужой firewall'
iptables -D FORWARD -i tun-test -m comment --comment FOREIGN_TEST_RULE -j ACCEPT
export WIM_TEST_FOREIGN_WARP_EVIDENCE='тестовый сторонний WARP'
if (assert_no_foreign_warp >/dev/null 2>&1); then fail 'разрешён сторонний WARP'; fi
unset WIM_TEST_FOREIGN_WARP_EVIDENCE
export SSH_CONNECTION='198.51.100.10 54321 192.0.2.10 2222'
[[ "$(current_ssh_server_port)" == 2222 ]] || fail 'неверный порт текущего SSH'
unset SSH_CONNECTION
validate_ssh_ports 22,2222 || fail 'отклонён список SSH-портов'
! validate_ssh_ports 0,70000 || fail 'приняты недопустимые SSH-порты'

if validate_iface_list '.' || validate_iface_list '..'; then fail 'принят путь вместо интерфейса'; fi
for invalid in 'tun-test,tun-test' 'tun-test,' ',tun-test' 'tun-test,,tun-second' lo warp-selective 'bad name'; do
    ! validate_iface_list "$invalid" || fail "принят неправильный набор $invalid"
done
! validate_risky_subset tun-test tun-second || fail 'риск для чужого интерфейса'
! validate_ipv4_list '162.159.192.1,' || fail 'повреждённый endpoint'

# Two ingress interfaces share one tunnel. Unselected traffic retains its route.
printf '1' >"$mock_root/proc/tun-second/rp_filter"
select_state tun-test,tun-second
: >"$mock_log"
service_up
[[ "$(route_dev from 10.70.0.2 iif tun-test)" == warp-selective ]] || fail 'первый ingress не переключён'
[[ "$(route_dev from 10.71.0.2 iif tun-second)" == warp-selective ]] || fail 'второй ingress не переключён'
[[ "$(route_dev from 10.72.0.2 iif tun-other)" == eth0 ]] || fail 'посторонний ingress переключён'
[[ "$(route_dev)" == eth0 ]] || fail 'хост переключён в режиме интерфейсов'
[[ "$(grep -c '^wg-quick up ' "$mock_log")" == 1 ]] || fail 'созданы два туннеля'
export WIM_MOCK_MISSING_SECOND_IIF=1
if health_is_good; then fail 'здоровье без второго ingress rule'; fi
unset WIM_MOCK_MISSING_SECOND_IIF
export WIM_MOCK_MISSING_NAT=1
if health_is_good; then fail 'здоровье без NAT'; fi
unset WIM_MOCK_MISSING_NAT
export WIM_MOCK_FORWARD_OFF=1
if health_is_good; then fail 'здоровье без forwarding'; fi
unset WIM_MOCK_FORWARD_OFF
export WIM_MOCK_MISSING_TABLE_ROUTE=1
if health_is_good; then fail 'здоровье без маршрута'; fi
unset WIM_MOCK_MISSING_TABLE_ROUTE
health_is_good || fail 'два ingress не прошли проверку'
: >"$mock_root/service-active"
: >"$mock_log"
enable_manager
! grep -q '^systemctl restart ' "$mock_log" || fail 'повторный enable перезапустил здоровый туннель'
: >"$mock_root/curl-fail-once"
health_check 1 >/dev/null
! grep -q '^systemctl restart ' "$mock_log" || fail 'краткий сбой вызвал restart'
disable_manager
assert_clean
[[ "$(<"$mock_root/proc/tun-test/rp_filter")" == 2 && "$(<"$mock_root/proc/tun-second/rp_filter")" == 1 ]] || fail 'разные исходные rp_filter потеряны'

# Recovery uses profile identity even when old runtime has no index or is absent.
for legacy in no-index no-runtime; do
    select_state tun-test
    service_up
    if [[ "$legacy" == no-index ]]; then sed -i '/^WG_IFINDEX=/d' "$RUNTIME_FILE"; else rm -f "$RUNTIME_FILE"; fi
    export WIM_MOCK_FAIL_DOWN=1
    : >"$mock_log"
    service_up
    grep -q '^ip link delete dev warp-selective$' "$mock_log" || fail 'старый собственный интерфейс не восстановлен'
    health_is_good || fail 'восстановленный туннель не healthy'
    unset WIM_MOCK_FAIL_DOWN
    runtime_down
    assert_clean
    # No-runtime cannot restore an unknown prior rp_filter; preserve current value.
    printf '2' >"$mock_root/proc/tun-test/rp_filter"
done

# An interface of another identity/type is untouched, even if its index matches.
for identity in foreign type; do
    select_state tun-test
    wg-quick up "$WG_CONFIG"
    if [[ "$identity" == foreign ]]; then printf 'foreign-key' >"$mock_wg_marker"; else export WIM_MOCK_NOT_WG=1; fi
    : >"$mock_log"
    if service_up; then fail 'чужой интерфейс принят'; fi
    if runtime_down; then fail 'чужой интерфейс назван очищенным'; fi
    if managed_routing_is_good; then fail 'чужой интерфейс признан исправным'; fi
    [[ -f "$mock_wg_marker" ]] || fail 'чужой интерфейс удалён'
    ! grep -q '^wg-quick down\|^ip link delete\|^ip -4 rule del\|^iptables .* -D' "$mock_log" || fail 'чужая маршрутизация изменена'
    unset WIM_MOCK_NOT_WG
    rm -f "$mock_wg_marker" "$mock_root/sys/warp-selective/ifindex"
done

# Identity can change during failed down: do not delete a replacement interface.
select_state tun-test
service_up
export WIM_MOCK_SWAP_DURING_DOWN=1
: >"$mock_log"
if runtime_down; then fail 'подмена при остановке не обнаружена'; fi
[[ -f "$mock_wg_marker" && -f "$RUNTIME_FILE" ]] || fail 'потеряно состояние неполной остановки'
! grep -q '^ip link delete ' "$mock_log" || fail 'удалён подменённый интерфейс'
unset WIM_MOCK_SWAP_DURING_DOWN
rm -f "$mock_wg_marker" "$mock_root/sys/warp-selective/ifindex"
runtime_down
assert_clean

select_state tun-test,tun-second
service_up
export WIM_MOCK_FAIL_FIREWALL_DELETE=1
if runtime_down; then fail 'ошибка очистки firewall скрыта'; fi
[[ -f "$RUNTIME_FILE" ]] || fail 'потерян runtime неполной очистки'
unset WIM_MOCK_FAIL_FIREWALL_DELETE
runtime_down
assert_clean
service_up
export WIM_MOCK_FAIL_RULE_DELETE=1
if runtime_down; then fail 'ошибка удаления policy rule скрыта'; fi
[[ -f "$RUNTIME_FILE" ]] || fail 'потерян runtime при ошибке удаления rule'
unset WIM_MOCK_FAIL_RULE_DELETE
runtime_down
assert_clean

# Host mode has local-only routing, reply protection, and NAT; no unselected transit.
select_state - host 2222
service_up
[[ "$(route_dev)" == warp-selective ]] || fail 'локальный выход не переключён'
[[ "$(route_dev from 10.70.0.2 iif tun-test)" == eth0 ]] || fail 'хост захватил невыбранный transit'
[[ "$(route_dev mark 0x40000000)" == eth0 ]] || fail 'ответ входящей службы переключён'
export WIM_MOCK_ROTATED_ENDPOINT=1
if health_is_good; then fail 'смена endpoint без защиты пропущена'; fi
runtime_down
service_up
ip_rule_has 17998 main to 162.159.192.99 || fail 'фактический endpoint не защищён после DNS-ротации'
unset WIM_MOCK_ROTATED_ENDPOINT
for flag in WRONG_LOCAL_RULE MISSING_REPLY_RULE MISSING_REPLY_FIREWALL MISSING_SSH_RULE MISSING_ENDPOINT_RULE; do
    export "WIM_MOCK_$flag=1"
    if health_is_good; then fail "здоровье без защиты $flag"; fi
    unset "WIM_MOCK_$flag"
done
runtime_down
assert_clean
select_state tun-test,tun-second host 2222
service_up
[[ "$(route_dev)" == warp-selective && "$(route_dev from 10.71.0.2 iif tun-second)" == warp-selective ]] || fail 'совмещённый режим не работает'
runtime_down
assert_clean

# Update from legacy host mode clears its global transit rule.
printf 'TARGET_IFACE=-\nTABLE_ID=51880\nRULE_PRIORITY=18000\nINSTALLED_AT=1700000000\nPREVIOUS_IP_FORWARD=0\nROUTING_MODE=host\nSSH_PORTS=2222\n' >"$STATE_FILE"
wg-quick up "$WG_CONFIG"
ip -4 rule add table 51880 priority 18001
service_up
[[ "$(route_dev from 10.70.0.2 iif tun-test)" == eth0 ]] || fail 'старое общее правило осталось'
runtime_down
assert_clean

# Failures after partial replacement leave no active routes or rules.
select_state tun-test,tun-second host 2222
export WIM_MOCK_FAIL_CURL=1
if service_up; then fail 'провал trace принят'; fi
unset WIM_MOCK_FAIL_CURL
assert_clean
export WIM_MOCK_FAIL_OUTPUT_ADD=1
if service_up; then fail 'провал защитного mangle-правила принят'; fi
unset WIM_MOCK_FAIL_OUTPUT_ADD
assert_clean
for flag in FAIL_RULE_SHOW FAIL_ROUTE_SHOW FAIL_IPTABLES_SAVE FAIL_NFT FOREIGN_MARK GLOBAL_CONFLICT; do
    export "WIM_MOCK_$flag=1"
    if check_full_host_routing_is_clear >/dev/null 2>&1; then fail "пропущен конфликт $flag"; fi
    unset "WIM_MOCK_$flag"
done

# Reconfigure validates all new targets before stopping the working configuration.
select_state tun-test
systemctl start "$SERVICE"
choose_routing_mode() { CHOSEN_IFACE=tun-test,tun-second; CHOSEN_RISKY_IFACES=''; CHOSEN_ROUTING_MODE=interface; CHOSEN_SSH_PORTS=''; }
export WIM_MOCK_SECOND_DOWN=1
: >"$mock_log"
if (reconfigure_manager >/dev/null 2>&1); then fail 'принят отсутствующий второй интерфейс'; fi
unset WIM_MOCK_SECOND_DOWN
! grep -q '^systemctl stop ' "$mock_log" || fail 'старый туннель остановлен до проверки нового набора'
reconfigure_manager
load_state
[[ "$TARGET_IFACES" == tun-test,tun-second ]] || fail 'новый набор не сохранён'
health_is_good || fail 'новый набор не запущен'
choose_routing_mode() { CHOSEN_IFACE='-'; CHOSEN_RISKY_IFACES=''; CHOSEN_ROUTING_MODE=host; CHOSEN_SSH_PORTS=2222; }
export MOCK_FAIL_MODE=host
if (reconfigure_manager >/dev/null 2>&1); then fail 'ошибка нового режима принята'; fi
unset MOCK_FAIL_MODE
load_state
[[ "$ROUTING_MODE" == interface && "$TARGET_IFACES" == tun-test,tun-second ]] || fail 'прежний набор потерян'
[[ -f "$mock_root/service-active" ]] || fail 'прежний рабочий туннель не восстановлен'
health_is_good || fail 'восстановленный прежний набор нездоров'
disable_manager
reconfigure_manager
load_state
[[ "$ROUTING_MODE" == host && ! -f "$mock_root/service-active" ]] || fail 'смена выключенного режима запустила службу'

# A failed atomic sysctl replacement must retain the old file and report failure.
(
    printf 'previous sysctl fixture\n' >"$SYSCTL_FILE"
    mv() { return 1; }
    if write_sysctl_config; then fail 'ошибка записи sysctl скрыта'; fi
    [[ "$(<"$SYSCTL_FILE")" == 'previous sysctl fixture' ]] || fail 'sysctl потерян при ошибке замены'
)

[[ "$(sha256sum "$WG_CONFIG")" == "$profile_hash" ]] || fail 'профиль переписан'
[[ "$(sha256sum "$CONFIG_DIR/wgcf-account.toml")" == "$account_hash" ]] || fail 'регистрация переписана'
! grep -q 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' "$mock_log" || fail 'ключ попал в argv/log'
[[ "$(TZ=UTC format_server_datetime '2026-10-10T22:28:57+00:00')" == '10.10.2026 22:28:57 UTC (+00:00)' ]] || fail 'формат времени'

# Multi-selection and separate risk consent (including duplicate/oversized input).
scan_interfaces() { SELECTABLE_IFACES=(tun-test tun-second); }
interface_protection_reason() { [[ "$1" != tun-second ]] || printf 'тестовый риск'; }
choose_interface <<< $'2\n1 1\n999999999999999999\n1 2\nРИСК tun-second\n' >/dev/null
[[ "$CHOSEN_IFACE" == tun-test,tun-second && "$CHOSEN_RISKY_IFACES" == tun-second ]] || fail 'выбор набора/отдельный риск'
(
    # shellcheck source=../warp-interface-manager.sh disable=SC1091
    source "$SCRIPT"
    choose_interface() { return 2; }
    if choose_routing_mode <<< $'1\n0\n' >/dev/null 2>&1; then fail 'возврат из выбора интерфейсов потерян'; else
        [[ "$?" == 2 ]] || fail 'неверный код возврата в меню'
    fi
)
printf 'OK: безопасные проверки 1.4.0 пройдены.\n'
