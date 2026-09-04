#!/usr/bin/env bash
#
# Isolated manual installer for the public WDTT Plus self-hosted server.
# It intentionally has no dependency on Android, Gradle, APK assets, or the
# application's deploy workflow.

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

ensure_utf8_locale() {
    case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
        *UTF-8*|*utf8*) return ;;
    esac
    local candidate
    for candidate in C.UTF-8 C.utf8; do
        if locale -a 2>/dev/null | grep -Fxq "$candidate"; then
            export LC_ALL="$candidate"
            return
        fi
    done
}

ensure_utf8_locale

readonly INSTALLER_VERSION="0.19.0"
readonly SUPPORTED_SERVER_VERSION="16"
readonly DEPLOY_COMPATIBILITY_VERSION="1"
readonly MANAGED_MARKER="Managed by WDTT Plus standalone server installer"
readonly ANDROID_DEPLOY_MARKER="Managed by WDTT Plus Android deploy"
readonly ANDROID_DEPLOY_COMPATIBILITY_MARKER="WDTT deploy compatibility: $DEPLOY_COMPATIBILITY_VERSION"
readonly STATE_MARKER="$MANAGED_MARKER state"
readonly TRANSACTION_MARKER="$MANAGED_MARKER transaction"
readonly FIREWALL_STATE_MARKER="$MANAGED_MARKER firewall"
readonly BACKUP_MANIFEST_VERSION="1"
readonly DEFAULT_DTLS_PORT=56000
readonly DEFAULT_WG_PORT=56001
readonly DEFAULT_CLIENT_PORT=9000
readonly DEFAULT_DNS="1.1.1.1"
readonly DEFAULT_MAX_PASSWORDS=50
readonly DEFAULT_MAX_WORKERS=0
readonly DEFAULT_MAX_HANDSHAKES=32
readonly DEFAULT_HANDSHAKE_RATE=24
readonly DEFAULT_MAX_CLIENT_MBPS=0
readonly DEFAULT_WG_BACKEND="auto"
readonly WDTT_SUBNET="10.66.66.0/24"
readonly MIN_FREE_BYTES=$((20 * 1024 * 1024))
readonly MAX_DATABASE_BYTES=$((64 * 1024 * 1024))

TEST_MODE="${WDTT_INSTALLER_TEST_MODE:-0}"
TEST_ROOT="${WDTT_INSTALLER_TEST_ROOT:-}"

if [[ -n "$TEST_ROOT" ]]; then
    if [[ "$TEST_MODE" != "1" || "$TEST_ROOT" != /tmp/* || "$TEST_ROOT" == "/tmp/" ]]; then
        printf 'Ошибка: тестовый корень разрешён только в явном режиме и внутри /tmp.\n' >&2
        exit 2
    fi
    TEST_ROOT="${TEST_ROOT%/}"
    if [[ ! -d "$TEST_ROOT" || -L "$TEST_ROOT" ]]; then
        printf 'Ошибка: тестовый корень должен быть существующим обычным каталогом.\n' >&2
        exit 2
    fi
    CANONICAL_TEST_ROOT="$(readlink -f -- "$TEST_ROOT")"
    if [[ "$CANONICAL_TEST_ROOT" != "$TEST_ROOT" || "$CANONICAL_TEST_ROOT" != /tmp/* ]]; then
        printf 'Ошибка: тестовый корень не должен проходить через символические ссылки.\n' >&2
        exit 2
    fi
fi

root_path() {
    printf '%s%s' "$TEST_ROOT" "$1"
}

managed_owner_pair() {
    if [[ "$TEST_MODE" == "1" ]]; then
        printf '%s:%s' "$(id -u)" "$(id -g)"
    else
        printf '0:0'
    fi
}

readonly BINARY_PATH="$(root_path /usr/local/bin/wdtt-server)"
readonly UNIT_PATH="$(root_path /etc/systemd/system/wdtt.service)"
readonly CONFIG_DIR="$(root_path /etc/wdtt)"
readonly DATABASE_PATH="$CONFIG_DIR/passwords.json"
readonly FIRST_INSTALL_MARKER="$CONFIG_DIR/.standalone-installing"
readonly STATE_DIR="$(root_path /var/lib/wdtt-server-installer)"
readonly STATE_CLAIM_PATH="$STATE_DIR/.standalone-state"
readonly OWNERSHIP_PATH="$STATE_DIR/ownership"
readonly BACKUP_ROOT="$STATE_DIR/backups"
readonly USER_BACKUP_ROOT="$BACKUP_ROOT/user"
readonly STAGING_ROOT="$STATE_DIR/staging"
readonly LOCK_PATH="$STATE_DIR/installer.lock"
readonly TRANSACTION_PATH="$STATE_DIR/transaction"
readonly NETWORK_HELPER_PATH="$STATE_DIR/network-runtime.sh"
readonly FIREWALL_STATE_PATH="$STATE_DIR/firewall-state"
readonly NETWORK_RUNTIME_DIR="$(root_path /run/wdtt-server-installer-network)"

COMMAND=""
COMPATIBILITY_MACHINE=0
SOURCE_BINARY=""
INITIAL_CONFIG=""
OUTPUT_CONFIG=""
PASSWORD_FILE=""
EXPECTED_SHA256=""
DTLS_PORT="$DEFAULT_DTLS_PORT"
WG_PORT="$DEFAULT_WG_PORT"
CLIENT_PORT="$DEFAULT_CLIENT_PORT"
DNS_VALUE="$DEFAULT_DNS"
MAX_PASSWORDS="$DEFAULT_MAX_PASSWORDS"
MAX_WORKERS="$DEFAULT_MAX_WORKERS"
MAX_HANDSHAKES="$DEFAULT_MAX_HANDSHAKES"
HANDSHAKE_RATE="$DEFAULT_HANDSHAKE_RATE"
MAX_CLIENT_MBPS="$DEFAULT_MAX_CLIENT_MBPS"
WG_BACKEND="$DEFAULT_WG_BACKEND"
FIREWALL_MODE="ask"
ASSUME_YES=0
DRY_RUN=0
ADVANCED_REQUESTED=0
MIGRATE_PORTS=0

CURRENT_DTLS_PORT=""
CURRENT_WG_PORT=""
CURRENT_CLIENT_PORT=""
CURRENT_DNS_VALUE=""
CURRENT_MAX_PASSWORDS=""
INSTALLED_INSTALLER_VERSION=""
INSTALLED_SERVER_VERSION=""
INSTALLED_SERVER_SHA256=""
INSTALL_KIND=""
ACTIVE_BACKUP=""
STAGING_DIR=""
TRANSACTION_ID=""
TRANSACTION_PHASE=""
SERVICE_WAS_ACTIVE=0
SERVICE_WAS_ENABLED=0
TRANSACTION_ACTIVE=0
LOCK_HELD=0
SOURCE_BINARY_SHA256=""
SOURCE_BINARY_VERSION=""
INITIAL_CONFIG_SHA256=""
JOURNAL_BINARY_SHA256=""
MAIN_PASSWORD_RESULT=""
RECOVERY_RESULT_KIND=""
FIREWALL_MANAGER="none"
FIREWALL_CHANGE="none"
FIREWALL_MARKER=""
FIREWALL_BASELINE_RUNTIME=0
FIREWALL_BASELINE_PERMANENT=0
RUNTIME_HEALTH_ERROR=""
FIREWALL_PORT=""
STAGED_DATABASE_UPDATE=0
PORTS_CHANGED=0
EXISTING_WG_KEYS_SHA256=""
PREVIOUS_FIREWALL_OWNED=0
PREVIOUS_FIREWALL_MANAGER="none"
PREVIOUS_FIREWALL_PORT=0
PREVIOUS_FIREWALL_MARKER=""
PREVIOUS_FIREWALL_REMOVED=0

declare -A OPTION_SET=()

log() {
    printf '%s\n' "$*"
}

warn() {
    printf 'Предупреждение: %s\n' "$*" >&2
}

die() {
    printf 'Ошибка: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Ручной установщик сервера WDTT Plus

Использование:
  install.sh [menu] [--binary ПУТЬ] [--config ПУТЬ]
  install.sh wizard [--binary ПУТЬ] [параметры]
  install.sh init-config [--output ПУТЬ] [параметры]
  install.sh check [параметры]
  install.sh install [--binary ПУТЬ] [--config ПУТЬ] [параметры]
  install.sh adopt-android [--binary ПУТЬ] [параметры]
  install.sh handoff-android [--dry-run] [--yes]
  install.sh status
  install.sh monitor
  install.sh doctor
  install.sh compatibility
  install.sh version | --version

Команды:
  menu        Главное текстовое меню. Это действие по умолчанию, если
              запустить install.sh без команды. Переходы выполняются одной
              клавишей без Enter; ввод путей и паролей остаётся обычным текстовым
              вводом. Критические действия всё равно требуют подтверждения.
  wizard      Понятный мастер: проверит совместимость, создаст начальный
              конфиг на чистом сервере, покажет план и запустит установку
              только после подтверждения словом УСТАНОВИТЬ.
  init-config Создать новый закрытый passwords.json, не перезаписывая файлы.
              В интерактивном режиме можно ввести главный пароль вручную или
              сгенерировать новый стойкий пароль и сразу сохранить его.
  check       Проверить VPS, бинарник, конфигурацию и показать план установки
              или обновления без изменений на сервере.
  install     Выполнить первую установку или транзакционное обновление своей
              ранее созданной ручной установки.
  adopt-android
              Явно и транзакционно принять установку, созданную Android-
              деплоем с совместимой меткой. Данные и WireGuard-ключи
              сохраняются. Эта команда никогда не принимает неизвестный
              сервер и не запускается автоматически командой install.
  handoff-android
              Транзакционно передать собственную ручную установку обратно
              Android-деплою. Бинарник, /etc/wdtt, клиенты и WireGuard-ключи
              сохраняются; при ошибке восстанавливается ручное управление.
  status      Кратко показать тип установки, версии, наличие файлов,
              транзакцию и состояние службы без чтения секретов.
  monitor     Показать безопасный серверный мониторинг: службу, порты,
              интерфейс, межсетевой экран, агрегаты клиентов и трафика без паролей,
              VK-хешей и WireGuard-ключей.
  doctor      Выполнить расширенную диагностику уже установленного сервера
              без изменений.
  compatibility
              Показать контракт совместимости с Android-деплоем.
  version     Показать версию этого файла установщика.

Совместимые алиасы:
  start       То же самое, что wizard. Оставлен для старых инструкций.
  -V          То же самое, что --version.

Параметры:
  --binary ПУТЬ             Локальный бинарник wdtt-server.
  --config ПУТЬ             Закрытый начальный passwords.json. Обязателен
                            только при первой установке.
  --output ПУТЬ             Новый файл для команды init-config.
  --password-file ПУТЬ      Закрытый файл с паролем в первой строке для
                            неинтерактивного init-config.
  --sha256 HEX              Ожидаемый SHA-256 локального бинарника.
  --dtls-port ПОРТ          Публичный DTLS-порт (по умолчанию 56000).
  --wg-port ПОРТ            Внутренний WG-порт (по умолчанию 56001).
  --client-port ПОРТ        Локальный порт Android (по умолчанию 9000).
  --dns ЗНАЧЕНИЕ            DNS для клиентов (по умолчанию 1.1.1.1).
  --max-passwords N         Начальный максимум клиентов, 1..500
                            (по умолчанию 50).
  --max-workers N           Лимит воркеров доступа, 0..128.
  --max-handshakes N        Одновременные рукопожатия, 1..256.
  --handshake-rate N        Рукопожатий в секунду, 1..1000.
  --max-client-mbps N       Лимит Мбит/с доступа, 0..1000.
  --wg-backend MODE         Режим WireGuard: auto, kernel или userspace.
  --migrate-ports           При обновлении явно подтвердить смену портов и
                            обновить сохранённые порты владельца и клиентов.
  --firewall MODE           Режим межсетевого экрана: ask, none или open.
                            Автоматическое открытие
                            поддерживается только для одного активного
                            UFW/firewalld и только после отдельного согласия.
  --advanced                Показывать расширенные вопросы мастера.
  --dry-run                 Показать план действия без изменений.
  --yes                     Не задавать вопросы и принять план установки
                            либо передачи управления.
  --machine                 Машинный вывод key=value для compatibility.
  -h, --help                Показать эту справку.

Пустой ответ в интерактивном мастере принимает значение в квадратных
скобках. У главного пароля значения по умолчанию нет.

Установщик не скачивает файлы и не устанавливает пакеты. Входящий межсетевой
экран меняется только после отдельного согласия и только для распознанного
UFW/firewalld. Сам wdtt-server создаёт wdtt0, временно меняет сетевые sysctl,
включает IPv4 forwarding и добавляет правила NAT/FORWARD. Закрытый сетевой
скрипт standalone-службы удаляет только точные WDTT NAT/FORWARD-правила и
возвращает исходные sysctl после остановки.
EOF
}

print_compatibility() {
    local mode="${1:-full}"
    if [[ "$COMPATIBILITY_MACHINE" == "1" ]]; then
        printf 'contract_version=%s\nserver_version=%s\nbinary=%s\nunit=%s\nconfig=%s\ndatabase=%s\nwg_keys=%s\n' \
            "$DEPLOY_COMPATIBILITY_VERSION" "$SUPPORTED_SERVER_VERSION" \
            "/usr/local/bin/wdtt-server" "/etc/systemd/system/wdtt.service" \
            "/etc/wdtt" "passwords.json" "wg-keys.dat"
        return
    fi
    cat <<EOF
✓ Скрипт совместим с текущим WDTT-деплоем.

Что будет использоваться на сервере:
  - версия контракта: $DEPLOY_COMPATIBILITY_VERSION
  - версия wdtt-server: $SUPPORTED_SERVER_VERSION
  - бинарник: /usr/local/bin/wdtt-server
  - служба systemd: /etc/systemd/system/wdtt.service
  - данные сервера: /etc/wdtt
  - база клиентов: passwords.json
  - WireGuard-ключи: wg-keys.dat
EOF
    [[ "$mode" == "summary" ]] && return
    cat <<EOF

Для обычной ручной установки запустите мастер:
  sudo bash /tmp/install.sh wizard --binary /tmp/wdtt-server

Если хотите пройти всё по шагам:
  sudo bash /tmp/install.sh init-config --output /root/wdtt-initial.json
  sudo bash /tmp/install.sh check --binary /tmp/wdtt-server --config /root/wdtt-initial.json
  sudo bash /tmp/install.sh install --binary /tmp/wdtt-server --config /root/wdtt-initial.json
EOF
}

print_compatibility_brief() {
    printf '✓ Совместимость подтверждена: контракт %s, wdtt-server %s.\n' \
        "$DEPLOY_COMPATIBILITY_VERSION" "$SUPPORTED_SERVER_VERSION"
}

parse_uint() {
    local name="$1"
    local value="$2"
    local minimum="$3"
    local maximum="$4"
    [[ "$value" =~ ^[0-9]+$ ]] || die "$name должен быть целым числом."
    (( value >= minimum && value <= maximum )) ||
        die "$name должен быть в диапазоне $minimum..$maximum."
}

parse_number() {
    local name="$1"
    local value="$2"
    local minimum="$3"
    local maximum="$4"
    [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "$name должен быть числом."
    awk -v value="$value" -v min="$minimum" -v max="$maximum" \
        'BEGIN { exit !(value >= min && value <= max) }' ||
        die "$name должен быть в диапазоне $minimum..$maximum."
}

require_option_value() {
    local option="$1"
    local remaining="$2"
    (( remaining >= 2 )) || die "Для $option требуется значение."
}

mark_option() {
    OPTION_SET["$1"]=1
}

option_is_set() {
    [[ "${OPTION_SET[$1]:-0}" == "1" ]]
}

parse_args() {
    if (($# == 0)); then
        COMMAND="menu"
        return
    fi
    COMMAND="$1"
    shift

    case "$COMMAND" in
        menu|wizard|start|init-config|check|install|adopt-android|handoff-android|status|monitor|doctor) ;;
        compatibility)
            if (($# > 0)); then
                [[ "$#" == "1" && "$1" == "--machine" ]] ||
                    die "compatibility принимает только необязательный --machine."
                COMPATIBILITY_MACHINE=1
            fi
            print_compatibility
            exit 0
            ;;
        version|--version|-V)
            printf '%s\n' "$INSTALLER_VERSION"
            exit 0
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "Неизвестная команда: $COMMAND"
            ;;
    esac

    while (($# > 0)); do
        case "$1" in
            --binary)
                require_option_value "$1" "$#"
                SOURCE_BINARY="$2"
                mark_option binary
                shift 2
                ;;
            --config)
                require_option_value "$1" "$#"
                INITIAL_CONFIG="$2"
                mark_option config
                shift 2
                ;;
            --output)
                require_option_value "$1" "$#"
                OUTPUT_CONFIG="$2"
                mark_option output
                shift 2
                ;;
            --password-file)
                require_option_value "$1" "$#"
                PASSWORD_FILE="$2"
                mark_option password_file
                shift 2
                ;;
            --sha256)
                require_option_value "$1" "$#"
                EXPECTED_SHA256="${2,,}"
                mark_option sha256
                shift 2
                ;;
            --dtls-port)
                require_option_value "$1" "$#"
                DTLS_PORT="$2"
                mark_option dtls_port
                shift 2
                ;;
            --wg-port)
                require_option_value "$1" "$#"
                WG_PORT="$2"
                mark_option wg_port
                shift 2
                ;;
            --client-port)
                require_option_value "$1" "$#"
                CLIENT_PORT="$2"
                mark_option client_port
                shift 2
                ;;
            --dns)
                require_option_value "$1" "$#"
                DNS_VALUE="$2"
                mark_option dns
                shift 2
                ;;
            --max-passwords)
                require_option_value "$1" "$#"
                MAX_PASSWORDS="$2"
                mark_option max_passwords
                shift 2
                ;;
            --max-workers)
                require_option_value "$1" "$#"
                MAX_WORKERS="$2"
                mark_option max_workers
                shift 2
                ;;
            --max-handshakes)
                require_option_value "$1" "$#"
                MAX_HANDSHAKES="$2"
                mark_option max_handshakes
                shift 2
                ;;
            --handshake-rate)
                require_option_value "$1" "$#"
                HANDSHAKE_RATE="$2"
                mark_option handshake_rate
                shift 2
                ;;
            --max-client-mbps)
                require_option_value "$1" "$#"
                MAX_CLIENT_MBPS="$2"
                mark_option max_client_mbps
                shift 2
                ;;
            --wg-backend)
                require_option_value "$1" "$#"
                WG_BACKEND="$2"
                mark_option wg_backend
                shift 2
                ;;
            --migrate-ports)
                MIGRATE_PORTS=1
                mark_option migrate_ports
                shift
                ;;
            --firewall)
                require_option_value "$1" "$#"
                FIREWALL_MODE="$2"
                mark_option firewall
                shift 2
                ;;
            --advanced)
                ADVANCED_REQUESTED=1
                shift
                ;;
            --dry-run)
                DRY_RUN=1
                shift
                ;;
            --yes)
                ASSUME_YES=1
                shift
                ;;
            --machine)
                die "--machine поддерживается только командой compatibility."
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "Неизвестный параметр: $1"
                ;;
        esac
    done
}

validate_option_scope() {
    case "$COMMAND" in
        init-config)
            [[ -z "$SOURCE_BINARY" && -z "$INITIAL_CONFIG" && -z "$EXPECTED_SHA256" ]] ||
                die "init-config не принимает --binary, --config или --sha256."
            [[ "$DRY_RUN" == "0" ]] || die "init-config не принимает --dry-run."
            ! option_is_set firewall ||
                die "init-config не принимает --firewall."
            [[ "$ADVANCED_REQUESTED" == "0" ]] &&
                ! option_is_set max_workers &&
                ! option_is_set max_handshakes &&
                ! option_is_set handshake_rate &&
                ! option_is_set max_client_mbps &&
                ! option_is_set wg_backend &&
                ! option_is_set migrate_ports ||
                die "init-config не принимает расширенные лимиты запуска."
            ;;
        menu|wizard|start|check|install|adopt-android)
            [[ -z "$OUTPUT_CONFIG" && -z "$PASSWORD_FILE" ]] ||
                die "$COMMAND не принимает --output или --password-file."
            if [[ "$COMMAND" == "adopt-android" ]]; then
                [[ -z "$INITIAL_CONFIG" ]] ||
                    die "adopt-android всегда сохраняет текущий /etc/wdtt и не принимает --config."
            fi
            ;;
        handoff-android)
            ((${#OPTION_SET[@]} == 0)) &&
                [[ -z "$SOURCE_BINARY" && -z "$INITIAL_CONFIG" && -z "$OUTPUT_CONFIG" &&
                    -z "$PASSWORD_FILE" && -z "$EXPECTED_SHA256" &&
                    "$ADVANCED_REQUESTED" == "0" ]] ||
                die "handoff-android принимает только --dry-run и --yes."
            ;;
        status|monitor|doctor)
            ((${#OPTION_SET[@]} == 0)) &&
                [[ "$ASSUME_YES" == "0" && "$DRY_RUN" == "0" && "$ADVANCED_REQUESTED" == "0" ]] ||
                die "$COMMAND не принимает параметры установки."
            ;;
    esac
}

validate_dns_value() {
    local value="$1"
    [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || return 1
    (( ${#value} >= 1 && ${#value} <= 256 )) || return 1

    local old_ifs="$IFS"
    local -a parts=()
    IFS=',' read -r -a parts <<<"$value"
    IFS="$old_ifs"
    ((${#parts[@]} >= 1 && ${#parts[@]} <= 4)) || return 1

    local part
    for part in "${parts[@]}"; do
        [[ -n "$part" && ${#part} -le 64 ]] || return 1
        [[ "$part" =~ ^[0-9A-Za-z.:_-]+$ ]] || return 1
    done
}

validate_options() {
    parse_uint "DTLS-порт" "$DTLS_PORT" 1 65535
    parse_uint "WG-порт" "$WG_PORT" 1 65535
    parse_uint "локальный порт Android" "$CLIENT_PORT" 1 65535
    [[ "$DTLS_PORT" != "$WG_PORT" ]] || die "DTLS- и WG-порты должны различаться."
    parse_uint "max-passwords" "$MAX_PASSWORDS" 1 500
    parse_uint "max-workers" "$MAX_WORKERS" 0 128
    parse_uint "max-handshakes" "$MAX_HANDSHAKES" 1 256
    parse_number "handshake-rate" "$HANDSHAKE_RATE" 1 1000
    parse_number "max-client-mbps" "$MAX_CLIENT_MBPS" 0 1000
    validate_dns_value "$DNS_VALUE" ||
        die "DNS должен содержать 1–4 значения до 64 символов через запятую."
    case "$WG_BACKEND" in
        auto|kernel|userspace) ;;
        *) die "wg-backend должен быть auto, kernel или userspace." ;;
    esac
    case "$FIREWALL_MODE" in
        ask|none|open) ;;
        *) die "Режим межсетевого экрана должен быть ask, none или open." ;;
    esac
    if [[ -n "$EXPECTED_SHA256" && ! "$EXPECTED_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
        die "SHA-256 должен содержать ровно 64 шестнадцатеричных символа."
    fi
}

prompt_uint_value() {
    local variable="$1"
    local label="$2"
    local default_value="$3"
    local minimum="$4"
    local maximum="$5"
    local answer
    while true; do
        read -r -p "$label [$default_value]: " answer
        [[ -n "$answer" ]] || answer="$default_value"
        if [[ "$answer" =~ ^[0-9]+$ ]] &&
            (( answer >= minimum && answer <= maximum )); then
            printf -v "$variable" '%s' "$answer"
            return
        fi
        warn "Введите целое число от $minimum до $maximum."
    done
}

prompt_number_value() {
    local variable="$1"
    local label="$2"
    local default_value="$3"
    local minimum="$4"
    local maximum="$5"
    local answer
    while true; do
        read -r -p "$label [$default_value]: " answer
        [[ -n "$answer" ]] || answer="$default_value"
        if [[ "$answer" =~ ^[0-9]+([.][0-9]+)?$ ]] &&
            awk -v value="$answer" -v min="$minimum" -v max="$maximum" \
                'BEGIN { exit !(value >= min && value <= max) }'; then
            printf -v "$variable" '%s' "$answer"
            return
        fi
        warn "Введите число от $minimum до $maximum."
    done
}

prompt_dns_value() {
    local default_value="$DNS_VALUE"
    local answer
    while true; do
        read -r -p "DNS для клиентов [$default_value]: " answer
        [[ -n "$answer" ]] || answer="$default_value"
        if validate_dns_value "$answer"; then
            DNS_VALUE="$answer"
            return
        fi
        warn "Укажите 1–4 DNS до 64 символов через запятую, без пробелов."
    done
}

prompt_backend_value() {
    local default_value="$WG_BACKEND"
    local answer default_choice
    case "$default_value" in
        auto) default_choice=1 ;;
        kernel) default_choice=2 ;;
        userspace) default_choice=3 ;;
        *) default_choice=1 ;;
    esac
    while true; do
        cat <<EOF
Режим WireGuard:
  1 · Автоматически выбрать доступный режим
  2 · Использовать модуль ядра Linux
  3 · Использовать пользовательский режим
EOF
        read -r -p "Выбор [$default_choice]: " answer
        [[ -n "$answer" ]] || answer="$default_choice"
        case "$answer" in
            1|авто|автоматически)
                WG_BACKEND="auto"
                return
                ;;
            2|ядро)
                WG_BACKEND="kernel"
                return
                ;;
            3|пользовательский|пользовательский\ режим)
                WG_BACKEND="userspace"
                return
                ;;
            *)
                warn "Введите 1, 2 или 3."
                ;;
        esac
    done
}

prompt_firewall_value() {
    local default_value="$FIREWALL_MODE"
    local answer default_choice
    case "$default_value" in
        ask) default_choice=1 ;;
        none) default_choice=2 ;;
        open) default_choice=3 ;;
        *) default_choice=1 ;;
    esac
    while true; do
        cat <<EOF
Поведение межсетевого экрана:
  1 · Спрашивать отдельно перед изменением
  2 · Не менять автоматически
  3 · Открыть выбранный UDP-порт после безопасной проверки
EOF
        read -r -p "Выбор [$default_choice]: " answer
        [[ -n "$answer" ]] || answer="$default_choice"
        case "$answer" in
            1|спросить)
                FIREWALL_MODE="ask"
                return
                ;;
            2|нет|не|не\ менять)
                FIREWALL_MODE="none"
                return
                ;;
            3|открыть)
                FIREWALL_MODE="open"
                return
                ;;
            *)
                warn "Введите 1, 2 или 3."
                ;;
        esac
    done
}

prompt_required_path() {
    local variable="$1"
    local label="$2"
    local answer
    while true; do
        read -r -p "$label: " answer
        if [[ -n "$answer" ]]; then
            printf -v "$variable" '%s' "$answer"
            return
        fi
        warn "Путь нельзя оставить пустым."
    done
}

prompt_yes_no() {
    local label="$1"
    local default_answer="$2"
    local answer
    while true; do
        if [[ "$default_answer" == "yes" ]]; then
            read -r -p "$label [Д/н]: " answer
            case "${answer,,}" in
                ""|д|да|yes) return 0 ;;
                н|нет|no) return 1 ;;
                *) warn "Введите да или нет. Одиночные латинские y/n не принимаются, чтобы не перепутать раскладку." ;;
            esac
        else
            read -r -p "$label [д/Н]: " answer
            case "${answer,,}" in
                д|да|yes) return 0 ;;
                ""|н|нет|no) return 1 ;;
                *) warn "Введите да или нет. Одиночные латинские y/n не принимаются, чтобы не перепутать раскладку." ;;
            esac
        fi
    done
}

generate_secure_password() {
    local length="${1:-32}"
    local alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~!@#%^+=-'
    local alphabet_len="${#alphabet}"
    local limit=$((256 / alphabet_len * alphabet_len))
    local password="" byte index

    while ((${#password} < length)); do
        byte="$(od -An -N1 -tu1 /dev/urandom | tr -d '[:space:]')"
        [[ "$byte" =~ ^[0-9]+$ ]] || continue
        (( byte < limit )) || continue
        index=$((byte % alphabet_len))
        password+="${alphabet:index:1}"
    done
    printf '%s' "$password"
}

read_manual_hidden_password() {
    local first second
    while true; do
        read -r -s -p "Главный пароль (8–80 символов, без пробелов и |): " first
        printf '\n'
        read -r -s -p "Повторите главный пароль: " second
        printf '\n'
        [[ "$first" == "$second" ]] || {
            warn "Пароли не совпадают."
            continue
        }
        validate_main_password "$first" || continue
        MAIN_PASSWORD_RESULT="$first"
        return
    done
}

read_generated_password() {
    local generated answer
    generated="$(generate_secure_password 32)"
    validate_main_password "$generated" || {
        warn "Не удалось сгенерировать корректный пароль, попробуйте ещё раз."
        generated=""
        return 1
    }

    cat <<EOF

Сгенерирован новый главный пароль. Он будет показан только сейчас.
Сохраните его в менеджер паролей или другое защищённое место:

$generated

EOF
    while true; do
        read -r -p "Использовать этот пароль? [Д/н]: " answer
        case "${answer,,}" in
            ""|д|да|yes)
                MAIN_PASSWORD_RESULT="$generated"
                generated=""
                return 0
                ;;
            н|нет|no)
                generated=""
                return 1
                ;;
            *)
                warn "Введите да или нет. Одиночные латинские y/n не принимаются, чтобы не перепутать раскладку."
                ;;
        esac
    done
}

read_hidden_password() {
    local answer
    while true; do
        cat <<'EOF'

Главный пароль:
  1 · Ввести вручную
  2 · Сгенерировать безопасный пароль

EOF
        read -r -p "Выберите способ [1]: " answer
        answer="${answer:-1}"
        case "$answer" in
            1)
                read_manual_hidden_password
                return
                ;;
            2)
                read_generated_password && return
                ;;
            *)
                warn "Введите 1 или 2."
                ;;
        esac
    done
}

validate_main_password() {
    local value="$1"
    if (( ${#value} < 8 || ${#value} > 80 )); then
        warn "Пароль должен содержать от 8 до 80 символов."
        return 1
    fi
    if [[ "$value" == *[[:space:]\|]* || "$value" == *CHANGE_ME* ]]; then
        warn "Пароль содержит запрещённый пробел, | или шаблон CHANGE_ME."
        return 1
    fi
    return 0
}

collect_install_questions() {
    local kind="$1"
    [[ "$ASSUME_YES" == "0" && -t 0 ]] || return 0

    log ""
    log "Интерактивная настройка. Пустой ответ принимает значение в скобках."
    [[ -n "$SOURCE_BINARY" ]] ||
        prompt_required_path SOURCE_BINARY "Путь к локальному wdtt-server"

    if [[ "$kind" == "new" ]]; then
        [[ -n "$INITIAL_CONFIG" ]] ||
            prompt_required_path INITIAL_CONFIG "Путь к закрытому passwords.json"
        if ! option_is_set dtls_port; then
            prompt_uint_value DTLS_PORT "Публичный DTLS-порт" "$DTLS_PORT" 1 65535
            mark_option dtls_port
        fi
        if ! option_is_set wg_port; then
            prompt_uint_value WG_PORT "Внутренний WireGuard-порт" "$WG_PORT" 1 65535
            mark_option wg_port
        fi
        if ! option_is_set client_port; then
            prompt_uint_value CLIENT_PORT "Локальный порт Android" "$CLIENT_PORT" 1 65535
            mark_option client_port
        fi
        if ! option_is_set dns; then
            prompt_dns_value
            mark_option dns
        fi
        if ! option_is_set max_passwords; then
            prompt_uint_value MAX_PASSWORDS "Максимум клиентских паролей" "$MAX_PASSWORDS" 1 500
            mark_option max_passwords
        fi
    else
        if ! option_is_set dtls_port; then
            prompt_uint_value DTLS_PORT "Публичный DTLS-порт" "$DTLS_PORT" 1 65535
            mark_option dtls_port
        fi
        if ! option_is_set wg_port; then
            prompt_uint_value WG_PORT "Внутренний WireGuard-порт" "$WG_PORT" 1 65535
            mark_option wg_port
        fi
        if ! option_is_set client_port; then
            prompt_uint_value CLIENT_PORT "Локальный порт Android" "$CLIENT_PORT" 1 65535
            mark_option client_port
        fi
        if ! option_is_set dns; then
            prompt_dns_value
            mark_option dns
        fi
        if ! option_is_set max_passwords; then
            prompt_uint_value MAX_PASSWORDS "Максимум клиентских паролей" "$MAX_PASSWORDS" 1 500
            mark_option max_passwords
        fi
    fi

    detect_port_change "$kind"
    if [[ "$PORTS_CHANGED" == "1" && "$MIGRATE_PORTS" == "0" ]]; then
        warn "Смена портов разорвёт существующие подключения Android до обновления профилей."
        if prompt_yes_no \
            "Обновить сохранённые порты владельца и всех клиентов и продолжить" \
            "no"; then
            MIGRATE_PORTS=1
            mark_option migrate_ports
        else
            die "Смена портов отменена."
        fi
    fi

    if [[ "$ADVANCED_REQUESTED" == "1" ]] ||
        option_is_set max_workers ||
        option_is_set max_handshakes ||
        option_is_set handshake_rate ||
        option_is_set max_client_mbps ||
        option_is_set wg_backend ||
        prompt_yes_no "Настроить расширенные лимиты" "no"; then
        if ! option_is_set max_workers; then
            prompt_uint_value MAX_WORKERS "Рабочих потоков на один доступ (0 = без лимита)" "$MAX_WORKERS" 0 128
            mark_option max_workers
        fi
        if ! option_is_set max_handshakes; then
            prompt_uint_value MAX_HANDSHAKES "Одновременных рукопожатий" "$MAX_HANDSHAKES" 1 256
            mark_option max_handshakes
        fi
        if ! option_is_set handshake_rate; then
            prompt_number_value HANDSHAKE_RATE "Рукопожатий в секунду" "$HANDSHAKE_RATE" 1 1000
            mark_option handshake_rate
        fi
        if ! option_is_set max_client_mbps; then
            prompt_number_value MAX_CLIENT_MBPS "Мбит/с на доступ (0 = без лимита)" "$MAX_CLIENT_MBPS" 0 1000
            mark_option max_client_mbps
        fi
        if ! option_is_set wg_backend; then
            prompt_backend_value
            mark_option wg_backend
        fi
    fi

    if ! option_is_set firewall; then
        local detected_firewall
        detected_firewall="$(detect_firewall_manager)"
        case "$detected_firewall" in
            ufw|firewalld)
                if prompt_yes_no \
                    "Разрешить входящий ${DTLS_PORT}/udp через $detected_firewall" \
                    "no"; then
                    FIREWALL_MODE="open"
                else
                    FIREWALL_MODE="none"
                fi
                mark_option firewall
                ;;
            *)
                FIREWALL_MODE="none"
                mark_option firewall
                ;;
        esac
    fi
}

detect_port_change() {
    local kind="$1"
    PORTS_CHANGED=0
    [[ "$kind" == "owned" || "$kind" == "android" || "$kind" == "adopt" ]] || return 0
    if [[ -n "$CURRENT_DTLS_PORT" && "$DTLS_PORT" != "$CURRENT_DTLS_PORT" ]] ||
        [[ -n "$CURRENT_WG_PORT" && "$WG_PORT" != "$CURRENT_WG_PORT" ]] ||
        [[ -n "$CURRENT_CLIENT_PORT" && "$CLIENT_PORT" != "$CURRENT_CLIENT_PORT" ]]; then
        PORTS_CHANGED=1
    fi
}

validate_port_migration_choice() {
    local kind="$1"
    detect_port_change "$kind"
    if [[ "$kind" != "owned" && "$kind" != "android" && "$kind" != "adopt" && "$MIGRATE_PORTS" == "1" ]]; then
        die "--migrate-ports применяется только при смене портов существующей ручной установки или при явном принятии Android-установки."
    fi
    if [[ "$PORTS_CHANGED" == "1" && "$MIGRATE_PORTS" != "1" ]]; then
        die "Смена портов требует явного --migrate-ports; существующие Android-профили нужно будет обновить."
    fi
    if [[ "$PORTS_CHANGED" == "0" && "$MIGRATE_PORTS" == "1" ]]; then
        die "--migrate-ports указан, но выбранные порты не изменились."
    fi
}

assert_no_symlink_components() {
    local path="$1"
    if [[ "$path" != /* ]]; then
        path="$PWD/$path"
    fi
    local current="$path"
    while [[ "$current" != "/" && "$current" != "." ]]; do
        [[ ! -L "$current" ]] || die "Путь проходит через символическую ссылку: $current"
        current="$(dirname -- "$current")"
    done
}

state_claim_is_valid() {
    local expected_owner
    expected_owner="$(managed_owner_pair)"
    [[ -d "$STATE_DIR" && ! -L "$STATE_DIR" &&
        "$(stat -c '%a' "$STATE_DIR")" == "700" &&
        "$(stat -c '%u:%g' "$STATE_DIR")" == "$expected_owner" &&
        -f "$STATE_CLAIM_PATH" && ! -L "$STATE_CLAIM_PATH" &&
        "$(stat -c '%a' "$STATE_CLAIM_PATH")" == "600" &&
        "$(stat -c '%u:%g' "$STATE_CLAIM_PATH")" == "$expected_owner" &&
        "$(stat -c '%h' "$STATE_CLAIM_PATH")" == "1" ]] ||
        return 1
    grep -Fxq "$STATE_MARKER" "$STATE_CLAIM_PATH"
}

state_is_clean_claim() {
    state_claim_is_valid || return 1
    [[ ! -e "$TRANSACTION_PATH" && ! -e "$OWNERSHIP_PATH" ]] || return 1
    [[ ! -e "$BINARY_PATH" && ! -e "$UNIT_PATH" && ! -e "$CONFIG_DIR" ]] || return 1
    local unexpected
    unexpected="$(
        find "$STATE_DIR" -mindepth 1 -maxdepth 1 \
            ! -name '.standalone-state' \
            ! -name 'installer.lock' \
            ! -name 'backups' \
            -print -quit 2>/dev/null || true
    )"
    [[ -z "$unexpected" ]] && user_backup_tree_is_safe
}

user_backup_tree_is_safe() {
    [[ ! -e "$BACKUP_ROOT" || ( -d "$BACKUP_ROOT" && ! -L "$BACKUP_ROOT" ) ]] || return 1
    [[ ! -e "$USER_BACKUP_ROOT" || ( -d "$USER_BACKUP_ROOT" && ! -L "$USER_BACKUP_ROOT" ) ]] || return 1
    [[ -z "$(
        if [[ -d "$BACKUP_ROOT" ]]; then
            find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 \
                ! -name 'user' -print -quit 2>/dev/null || true
        fi
    )" ]] || return 1
    [[ -z "$(
        if [[ -d "$USER_BACKUP_ROOT" ]]; then
            find "$USER_BACKUP_ROOT" -mindepth 1 \
                \( -type l -o ! \( -type f -o -type d \) \) \
                -print -quit 2>/dev/null || true
        fi
    )" ]]
}

android_backup_state_is_safe() {
    local expected_owner
    expected_owner="$(managed_owner_pair)"
    [[ -d "$STATE_DIR" && ! -L "$STATE_DIR" &&
        "$(stat -c '%a' "$STATE_DIR")" == "700" &&
        "$(stat -c '%u:%g' "$STATE_DIR")" == "$expected_owner" &&
        ! -e "$TRANSACTION_PATH" && ! -e "$OWNERSHIP_PATH" ]] ||
        return 1
    [[ ! -e "$STATE_CLAIM_PATH" ]] || state_claim_is_valid || return 1
    if [[ -e "$FIREWALL_STATE_PATH" ]]; then
        (load_firewall_state) >/dev/null 2>&1 || return 1
    fi
    local unexpected
    if [[ "$TEST_MODE" == "1" ]]; then
        unexpected="$({
            find "$STATE_DIR" -mindepth 1 -maxdepth 1 \
                ! -name 'backups' \
                ! -name 'installer.lock' \
                ! -name '.standalone-state' \
                ! -name 'firewall-state' \
                ! -name '.test-service-active' \
                ! -name '.test-service-enabled' \
                ! -name '.test-firewall-*' \
                -print -quit 2>/dev/null || true
        })"
    else
        unexpected="$({
            find "$STATE_DIR" -mindepth 1 -maxdepth 1 \
                ! -name 'backups' \
                ! -name 'installer.lock' \
                ! -name '.standalone-state' \
                ! -name 'firewall-state' \
                -print -quit 2>/dev/null || true
        })"
    fi
    [[ -z "$unexpected" ]] || return 1
    user_backup_tree_is_safe
}

is_owned_install() {
    [[ -f "$UNIT_PATH" && ! -L "$UNIT_PATH" ]] || return 1
    [[ -f "$OWNERSHIP_PATH" && ! -L "$OWNERSHIP_PATH" ]] || return 1
    state_claim_is_valid || return 1
    grep -Fqx "# $MANAGED_MARKER" "$UNIT_PATH" &&
        grep -Fxq "$MANAGED_MARKER" "$OWNERSHIP_PATH"
}

is_android_deploy_install() {
    [[ (! -e "$STATE_DIR" || state_is_clean_claim || android_backup_state_is_safe) &&
        -f "$BINARY_PATH" && ! -L "$BINARY_PATH" &&
        -f "$UNIT_PATH" && ! -L "$UNIT_PATH" &&
        -d "$CONFIG_DIR" && ! -L "$CONFIG_DIR" ]] || return 1
    grep -Fqx "# $ANDROID_DEPLOY_MARKER" "$UNIT_PATH" &&
        grep -Fqx "# $ANDROID_DEPLOY_COMPATIBILITY_MARKER" "$UNIT_PATH"
}

validate_owned_managed_files() {
    local expected_owner
    expected_owner="$(managed_owner_pair)"
    [[ -d "$STATE_DIR" && ! -L "$STATE_DIR" &&
        "$(stat -c '%a' "$STATE_DIR")" == "700" &&
        "$(stat -c '%u:%g' "$STATE_DIR")" == "$expected_owner" ]] ||
        die "Каталог состояния ручного установщика имеет небезопасные права или владельца."

    local spec path expected_mode
    for spec in \
        "$BINARY_PATH:755" \
        "$UNIT_PATH:644" \
        "$OWNERSHIP_PATH:600" \
        "$STATE_CLAIM_PATH:600"; do
        path="${spec%:*}"
        expected_mode="${spec##*:}"
        [[ -f "$path" && ! -L "$path" &&
            "$(stat -c '%a' "$path")" == "$expected_mode" &&
            "$(stat -c '%u:%g' "$path")" == "$expected_owner" &&
            "$(stat -c '%h' "$path")" == "1" ]] ||
            die "Управляемый файл $path имеет небезопасный тип, права, владельца или hardlink."
    done
    if [[ -e "$NETWORK_HELPER_PATH" ]]; then
        [[ -f "$NETWORK_HELPER_PATH" && ! -L "$NETWORK_HELPER_PATH" &&
            "$(stat -c '%a' "$NETWORK_HELPER_PATH")" == "700" &&
            "$(stat -c '%u:%g' "$NETWORK_HELPER_PATH")" == "$expected_owner" &&
            "$(stat -c '%h' "$NETWORK_HELPER_PATH")" == "1" ]] ||
            die "Сетевой скрипт ручной установки имеет небезопасный тип, права или владельца."
    fi
}

has_any_install_state() {
    [[ -e "$UNIT_PATH" || -e "$BINARY_PATH" || -e "$CONFIG_DIR" || -e "$STATE_DIR" ]]
}

detect_install_kind() {
    if state_claim_is_valid && [[ -e "$TRANSACTION_PATH" ]]; then
        printf 'interrupted'
    elif is_owned_install; then
        printf 'owned'
    elif is_android_deploy_install; then
        printf 'android'
    elif state_is_clean_claim; then
        printf 'new'
    elif has_any_install_state; then
        printf 'foreign'
    else
        printf 'new'
    fi
}

friendly_install_kind() {
    case "$1" in
        new) printf 'чистый сервер, установка ещё не выполнялась' ;;
        owned) printf 'ручная установка WDTT Plus' ;;
        android) printf 'совместимая установка из Android-деплоя' ;;
        foreign) printf 'неизвестная или вручную изменённая установка' ;;
        interrupted) printf 'незавершённая транзакция, требуется восстановление' ;;
        adopt) printf 'передача совместимой Android-установки под ручное управление' ;;
        handoff) printf 'передача ручной установки под управление Android-деплоя' ;;
        *) printf '%s' "$1" ;;
    esac
}

friendly_service_state() {
    case "$1" in
        active) printf 'активна' ;;
        inactive) printf 'остановлена' ;;
        failed) printf 'ошибка запуска' ;;
        activating) printf 'запускается' ;;
        deactivating) printf 'останавливается' ;;
        unknown|"") printf 'не определена' ;;
        *) printf '%s' "$1" ;;
    esac
}

friendly_firewall_mode() {
    case "$1" in
        open) printf 'открыть выбранный UDP-порт, если межсетевой экран распознан безопасно' ;;
        none) printf 'не менять межсетевой экран автоматически' ;;
        ask) printf 'спросить отдельно перед изменением межсетевого экрана' ;;
        *) printf '%s' "$1" ;;
    esac
}

friendly_firewall_manager() {
    case "$1" in
        ufw) printf 'UFW' ;;
        firewalld) printf 'firewalld' ;;
        nftables) printf 'nftables' ;;
        iptables) printf 'iptables' ;;
        multiple) printf 'несколько менеджеров межсетевого экрана' ;;
        none|"") printf 'не обнаружен' ;;
        *) printf '%s' "$1" ;;
    esac
}

friendly_wg_backend() {
    case "$1" in
        auto) printf 'авто' ;;
        kernel) printf 'ядро Linux' ;;
        userspace) printf 'пользовательский режим' ;;
        *) printf '%s' "$1" ;;
    esac
}

load_installed_installer_version() {
    INSTALLED_INSTALLER_VERSION="$(
        awk -F= '$1 == "installer_version" {print $2; exit}' "$OWNERSHIP_PATH" 2>/dev/null ||
            true
    )"
    [[ "$INSTALLED_INSTALLER_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
        INSTALLED_INSTALLER_VERSION="unknown"
    INSTALLED_SERVER_VERSION="$(
        awk -F= '$1 == "server_version" {print $2; exit}' "$OWNERSHIP_PATH" 2>/dev/null ||
            true
    )"
    [[ "$INSTALLED_SERVER_VERSION" =~ ^[0-9][0-9A-Za-z._-]*$ ]] ||
        INSTALLED_SERVER_VERSION="unknown"
    INSTALLED_SERVER_SHA256="$(
        awk -F= '$1 == "server_sha256" {print $2; exit}' "$OWNERSHIP_PATH" 2>/dev/null ||
            true
    )"
    [[ "$INSTALLED_SERVER_SHA256" =~ ^[0-9a-f]{64}$ ]] ||
        INSTALLED_SERVER_SHA256="unknown"
}

load_owned_runtime_defaults() {
    local line stored_ports stored_dns stored_max
    [[ -f "$UNIT_PATH" && ! -L "$UNIT_PATH" ]] || return 0
    load_installed_installer_version
    line="$(grep -m1 '^ExecStart=' "$UNIT_PATH" || true)"

    if [[ "$line" =~ -listen[[:space:]]+[^[:space:]]*:([0-9]+) ]]; then
        CURRENT_DTLS_PORT="${BASH_REMATCH[1]}"
        option_is_set dtls_port || DTLS_PORT="$CURRENT_DTLS_PORT"
    fi
    if [[ "$line" =~ -wg-port[[:space:]]+([0-9]+) ]]; then
        CURRENT_WG_PORT="${BASH_REMATCH[1]}"
        option_is_set wg_port || WG_PORT="${BASH_REMATCH[1]}"
    fi
    if [[ "$line" =~ -max-workers-per-access[[:space:]]+([0-9]+) ]]; then
        option_is_set max_workers || MAX_WORKERS="${BASH_REMATCH[1]}"
    fi
    if [[ "$line" =~ -max-handshakes[[:space:]]+([0-9]+) ]]; then
        option_is_set max_handshakes || MAX_HANDSHAKES="${BASH_REMATCH[1]}"
    fi
    if [[ "$line" =~ -handshake-rate[[:space:]]+([0-9]+([.][0-9]+)?) ]]; then
        option_is_set handshake_rate || HANDSHAKE_RATE="${BASH_REMATCH[1]}"
    fi
    if [[ "$line" =~ -max-client-mbps[[:space:]]+([0-9]+([.][0-9]+)?) ]]; then
        option_is_set max_client_mbps || MAX_CLIENT_MBPS="${BASH_REMATCH[1]}"
    fi
    if [[ "$line" =~ -wg-backend[[:space:]]+(auto|kernel|userspace) ]]; then
        option_is_set wg_backend || WG_BACKEND="${BASH_REMATCH[1]}"
    fi

    if [[ -f "$DATABASE_PATH" && ! -L "$DATABASE_PATH" ]] &&
        jq -e 'type == "object"' "$DATABASE_PATH" >/dev/null 2>&1; then
        stored_dns="$(jq -r '.dns // empty' "$DATABASE_PATH")"
        stored_max="$(jq -r '.max_passwords // empty' "$DATABASE_PATH")"
        stored_ports="$(jq -r '.default_ports // empty' "$DATABASE_PATH")"
        CURRENT_DNS_VALUE="$stored_dns"
        [[ -z "$stored_dns" ]] || option_is_set dns || DNS_VALUE="$stored_dns"
        if [[ "$stored_max" =~ ^[0-9]+$ ]]; then
            CURRENT_MAX_PASSWORDS="$stored_max"
            option_is_set max_passwords || MAX_PASSWORDS="$stored_max"
        fi
        if [[ "$stored_ports" =~ ^([0-9]+),([0-9]+),([0-9]+)$ ]]; then
            CURRENT_CLIENT_PORT="${BASH_REMATCH[3]}"
            option_is_set client_port || CLIENT_PORT="${BASH_REMATCH[3]}"
        fi
    fi
}

validate_host() {
    [[ "$(uname -s)" == "Linux" ]] || die "Поддерживается только Linux."
    if [[ "$TEST_MODE" != "1" ]]; then
        case "$(uname -m)" in
            x86_64|amd64) ;;
            *) die "Установщик поддерживает только Linux amd64." ;;
        esac
        command -v systemctl >/dev/null 2>&1 || die "Не найден systemctl."
        [[ -d /run/systemd/system ]] || die "systemd не запущен."
        command -v systemd-analyze >/dev/null 2>&1 ||
            die "Не найден systemd-analyze."
        command -v ip >/dev/null 2>&1 || die "Не найдена команда ip."
        command -v ss >/dev/null 2>&1 || die "Не найдена команда ss."
    fi

    local missing=()
    local utility
    for utility in \
        jq sha256sum stat awk find cp mv install flock df du cmp sed od tr \
        wc grep head date readlink dirname mktemp base64 sort sync; do
        command -v "$utility" >/dev/null 2>&1 || missing+=("$utility")
    done
    ((${#missing[@]} == 0)) ||
        die "Не найдены обязательные утилиты: ${missing[*]}. Установите их вручную."

    if [[ "$COMMAND" == "check" || "$COMMAND" == "install" || "$COMMAND" == "adopt-android" ]]; then
        validate_network_prerequisites
    fi
}

default_ipv4_interface() {
    if [[ "$TEST_MODE" == "1" ]]; then
        printf '%s' "${WDTT_INSTALLER_TEST_DEFAULT_INTERFACE:-eth0}"
        return
    fi
    ip -4 route show default 2>/dev/null |
        awk '
            $1 == "default" {
                for (i = 1; i <= NF; i++) {
                    if ($i == "dev" && i < NF) {
                        print $(i + 1)
                        exit
                    }
                }
            }
        '
}

validate_network_prerequisites() {
    if [[ "$TEST_MODE" == "1" ]]; then
        [[ "${WDTT_INSTALLER_TEST_NO_NAT_BACKEND:-0}" != "1" ]] ||
            die "Не найдены iptables или nftables для NAT."
        [[ "${WDTT_INSTALLER_TEST_NO_DEFAULT_ROUTE:-0}" != "1" ]] ||
            die "Не найден рабочий IPv4-маршрут по умолчанию."
        return 0
    fi

    if ! command -v iptables >/dev/null 2>&1 &&
        ! command -v nft >/dev/null 2>&1; then
        die "Не найдены iptables или nftables для NAT."
    fi
    command -v sysctl >/dev/null 2>&1 ||
        die "Не найдена команда sysctl."

    local ext_iface
    ext_iface="$(default_ipv4_interface)"
    [[ "$ext_iface" =~ ^[0-9A-Za-z_.:-]+$ &&
        -e "/sys/class/net/$ext_iface" ]] ||
        die "Не найден рабочий IPv4-маршрут по умолчанию и внешний интерфейс."

    case "$WG_BACKEND" in
        kernel)
            command -v wg >/dev/null 2>&1 ||
                die "Для wg-backend=kernel требуется команда wg."
            ;;
        userspace)
            [[ -c /dev/net/tun && -r /dev/net/tun && -w /dev/net/tun ]] ||
                die "Для wg-backend=userspace требуется доступный /dev/net/tun."
            ;;
        auto)
            if ! command -v wg >/dev/null 2>&1 &&
                [[ ! -c /dev/net/tun || ! -r /dev/net/tun || ! -w /dev/net/tun ]]; then
                die "Для wg-backend=auto требуется kernel WireGuard с wg или доступный /dev/net/tun."
            fi
            ;;
    esac
}

validate_nat_backend_access() {
    [[ "$TEST_MODE" == "1" ]] && return 0
    if command -v iptables >/dev/null 2>&1; then
        iptables -t nat -S POSTROUTING >/dev/null 2>&1 &&
            iptables -S FORWARD >/dev/null 2>&1 ||
            die "wdtt-server выберет iptables, но root не может читать его NAT/FORWARD-цепочки."
        return 0
    fi
    command -v nft >/dev/null 2>&1 &&
        nft list ruleset >/dev/null 2>&1 ||
        die "nftables недоступен для настройки и проверки NAT от root."
}

validate_binary() {
    [[ -n "$SOURCE_BINARY" ]] || die "Укажите локальный бинарник через --binary."
    assert_no_symlink_components "$SOURCE_BINARY"
    [[ -f "$SOURCE_BINARY" && ! -L "$SOURCE_BINARY" ]] ||
        die "Бинарник должен быть обычным файлом, а не ссылкой."
    [[ -x "$SOURCE_BINARY" ]] || die "Бинарник не исполняемый: $SOURCE_BINARY"

    local version
    version="$("$SOURCE_BINARY" --version 2>/dev/null | head -n 1 || true)"
    [[ "$version" =~ ^[0-9][0-9A-Za-z._-]*$ ]] ||
        die "Файл не подтвердил версию wdtt-server."
    [[ "$version" == "$SUPPORTED_SERVER_VERSION" ]] ||
        die "Поддерживается wdtt-server версии $SUPPORTED_SERVER_VERSION, получена версия $version."
    SOURCE_BINARY_VERSION="$version"

    local actual_sha256
    actual_sha256="$(sha256sum "$SOURCE_BINARY" | awk '{print $1}')"
    if [[ -n "$EXPECTED_SHA256" && "$actual_sha256" != "$EXPECTED_SHA256" ]]; then
        die "SHA-256 бинарника не совпадает с ожидаемым."
    fi
    SOURCE_BINARY_SHA256="$actual_sha256"
    log "Бинарник: совместимая версия $version, SHA-256 $actual_sha256"
}

validate_private_file_permissions() {
    local path="$1"
    local description="$2"
    local mode
    mode="$(stat -c '%a' "$path")"
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] ||
        die "Не удалось определить права: $description."
    local numeric_mode=$((8#$mode))
    (( (numeric_mode & 8#077) == 0 )) ||
        die "$description доступен группе или другим пользователям. Выполните chmod 600."
}

validate_initial_config() {
    [[ -n "$INITIAL_CONFIG" ]] || die "Для первой установки укажите --config."
    assert_no_symlink_components "$INITIAL_CONFIG"
    [[ -f "$INITIAL_CONFIG" && ! -L "$INITIAL_CONFIG" ]] ||
        die "Начальная конфигурация должна быть обычным файлом, а не ссылкой."
    validate_private_file_permissions "$INITIAL_CONFIG" "Начальная конфигурация"

    local size
    size="$(stat -c '%s' "$INITIAL_CONFIG")"
    (( size > 0 && size <= 1048576 )) ||
        die "Размер начальной конфигурации должен быть от 1 байта до 1 МиБ."

    local expected_ports="${DTLS_PORT},${WG_PORT},${CLIENT_PORT}"
    jq -e \
        --arg expected_ports "$expected_ports" \
        --arg expected_dns "$DNS_VALUE" \
        --argjson expected_max_passwords "$MAX_PASSWORDS" '
        type == "object" and
        ((keys_unsorted - [
            "main_password", "admin_id", "bot_token", "dns",
            "max_passwords", "default_ports", "passwords", "devices"
        ]) | length == 0) and
        (.main_password | type == "string" and length >= 8 and length <= 80) and
        (.main_password | contains("CHANGE_ME") | not) and
        (.main_password | test("[[:space:]|]") | not) and
        (.admin_id == "") and
        (.bot_token == "") and
        (.dns == $expected_dns) and
        (.max_passwords == $expected_max_passwords) and
        (.default_ports == $expected_ports) and
        (.passwords | type == "object" and length == 0) and
        (.devices | type == "object" and length == 0)
    ' "$INITIAL_CONFIG" >/dev/null ||
        die "Начальная конфигурация не прошла проверку структуры или не совпадает с выбранными параметрами."
    INITIAL_CONFIG_SHA256="$(sha256sum "$INITIAL_CONFIG" | awk '{print $1}')"
}

validate_config_tree() {
    local legacy_android_permissions="${1:-0}"
    [[ "$legacy_android_permissions" == "0" || "$legacy_android_permissions" == "1" ]] ||
        die "Некорректный режим проверки /etc/wdtt."
    [[ -d "$CONFIG_DIR" && ! -L "$CONFIG_DIR" ]] ||
        die "Каталог /etc/wdtt отсутствует или является ссылкой."

    local unsafe
    unsafe="$(
        find "$CONFIG_DIR" -mindepth 1 \
            \( -type l -o ! \( -type f -o -type d \) \) \
            -print -quit 2>/dev/null || true
    )"
    [[ -z "$unsafe" ]] ||
        die "В /etc/wdtt найден небезопасный объект или символическая ссылка."

    local open_path=""
    while IFS= read -r -d '' path; do
        local mode numeric_mode
        mode="$(stat -c '%a' "$path")"
        numeric_mode=$((8#$mode))
        if [[ "$legacy_android_permissions" == "0" ]] &&
            (( (numeric_mode & 8#077) != 0 )); then
            open_path="$path"
            break
        fi
        if [[ "$legacy_android_permissions" == "1" ]]; then
            if (( (numeric_mode & 8#022) != 0 )); then
                open_path="$path"
                break
            fi
            if [[ -f "$path" ]] && (( (numeric_mode & 8#111) != 0 )); then
                open_path="$path"
                break
            fi
        fi
    done < <(find "$CONFIG_DIR" \( -type f -o -type d \) -print0)
    [[ -z "$open_path" ]] ||
        die "Объект в /etc/wdtt имеет небезопасные права."

    local unsafe_owner=""
    local expected_owner
    expected_owner="$(managed_owner_pair)"
    while IFS= read -r -d '' path; do
        if [[ "$(stat -c '%u:%g' "$path")" != "$expected_owner" ]]; then
            unsafe_owner="$path"
            break
        fi
        if [[ -f "$path" && "$(stat -c '%h' "$path")" != "1" ]]; then
            unsafe_owner="$path"
            break
        fi
    done < <(find "$CONFIG_DIR" \( -type f -o -type d \) -print0)
    [[ -z "$unsafe_owner" ]] ||
        die "Объект в /etc/wdtt имеет чужого владельца или является жёсткой ссылкой."

    local unsafe_name=""
    while IFS= read -r -d '' path; do
        if [[ "$path" == *$'\n'* || "$path" == *$'\r'* ]]; then
            unsafe_name="$path"
            break
        fi
    done < <(find "$CONFIG_DIR" -mindepth 1 -print0)
    [[ -z "$unsafe_name" ]] ||
        die "Имя объекта в /etc/wdtt содержит управляющий перевод строки."
}

validate_database_schema() {
    local path="$1"
    jq -e '
        def integer:
            type == "number" and floor == .;
        def nonnegative_integer:
            integer and . >= 0;
        def ports:
            type == "string" and
            test("^[0-9]+,[0-9]+,[0-9]+$") and
            (split(",") | length == 3 and
                all(.[]; (tonumber >= 1 and tonumber <= 65535)));
        def traffic_bucket:
            type == "object" and
            (.date | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$")) and
            ((.down_bytes // 0) | nonnegative_integer) and
            ((.up_bytes // 0) | nonnegative_integer);
        def bind_history:
            type == "object" and
            all([
                .device_id, .device_name, .device_ip, .remote_ip,
                .country, .status, .note
            ][]; . == null or type == "string") and
            all([.bound_at, .unbound_at, .event_at][]; . == null or nonnegative_integer);
        def password_entry:
            type == "object" and
            ((.device_id // "") | type == "string") and
            ((.expires_at // 0) | nonnegative_integer) and
            ((.purge_after // 0) | nonnegative_integer) and
            ((.down_bytes // 0) | nonnegative_integer) and
            ((.up_bytes // 0) | nonnegative_integer) and
            ((.label // "") | type == "string") and
            ((.vk_hash // "") | type == "string") and
            ((.ports // "56000,56001,9000") | ports) and
            ((.is_deactivated // false) | type == "boolean") and
            ((.traffic // []) | type == "array" and length <= 400 and all(.[]; traffic_bucket)) and
            ((.traffic_imports // {}) | type == "object" and
                all(.[]; type == "object" and
                    ((.down_bytes // 0) | nonnegative_integer) and
                    ((.up_bytes // 0) | nonnegative_integer) and
                    ((.applied_at // 0) | nonnegative_integer))) and
            ((.bind_history // []) | type == "array" and length <= 50 and all(.[]; bind_history));
        def device_entry:
            type == "object" and
            ((.device_id // "") | type == "string") and
            ((.ip // "") | type == "string") and
            ((.priv_key // "") | type == "string") and
            ((.pub_key // "") | type == "string") and
            all([
                .name, .manufacturer, .brand, .model, .android_version,
                .abi, .app_version, .locale, .country, .time_zone,
                .remote_ip
            ][]; . == null or type == "string") and
            ((.sdk // 0) | nonnegative_integer) and
            ((.last_seen_at // 0) | nonnegative_integer);
        def admin_profile:
            type == "object" and
            all([
                .vk_hashes, .secondary_vk_hash, .profile_name,
                .protocol, .sni
            ][]; . == null or type == "string") and
            ((.workers_per_hash // 16) | integer and . >= 1 and . <= 128) and
            ((.listen_port // 9000) | integer and . >= 1 and . <= 65535) and
            ((.no_dns // false) | type == "boolean") and
            ((.ports // "56000,56001,9000") | ports) and
            ((.device_ids // []) | type == "array" and all(.[]; type == "string")) and
            ((.updated_at // 0) | nonnegative_integer);

        type == "object" and
        (.main_password | type == "string" and length >= 1 and length <= 256) and
        ((.admin_id // "") | type == "string") and
        ((.bot_token // "") | type == "string") and
        ((.dns // "1.1.1.1") | type == "string") and
        ((.max_passwords // 50) | integer and . >= 1 and . <= 500) and
        ((.default_ports // "56000,56001,9000") | ports) and
        ((.public_ip // "") | type == "string") and
        ((.admin_profile // {}) | admin_profile) and
        ((.admin_down_bytes // 0) | nonnegative_integer) and
        ((.admin_up_bytes // 0) | nonnegative_integer) and
        ((.admin_traffic // []) | type == "array" and length <= 400 and all(.[]; traffic_bucket)) and
        (.passwords | type == "object" and all(to_entries[]; (.key | length > 0) and (.value | password_entry))) and
        (.devices | type == "object" and all(to_entries[]; (.key | length > 0) and (.value | device_entry))) and
        (([.devices[].ip | select(length > 0)] | length) ==
            ([.devices[].ip | select(length > 0)] | unique | length))
    ' "$path" >/dev/null
}

validate_wg_keys_file() {
    local path="$CONFIG_DIR/wg-keys.dat"
    [[ -f "$path" && ! -L "$path" ]] ||
        die "WireGuard-ключи отсутствуют или являются ссылкой."
    [[ "$(stat -c '%a' "$path")" == "600" &&
        "$(stat -c '%u:%g' "$path")" == "$(managed_owner_pair)" &&
        "$(stat -c '%h' "$path")" == "1" ]] ||
        die "WireGuard-ключи должны принадлежать root, иметь права 600 и не быть жёсткой ссылкой."

    local line_count=0 key decoded_size
    while IFS= read -r key || [[ -n "$key" ]]; do
        line_count=$((line_count + 1))
        (( line_count <= 4 )) ||
            die "Файл WireGuard-ключей содержит лишние строки."
        [[ "$key" =~ ^[A-Za-z0-9+/]{43}=$ ]] ||
            die "Файл WireGuard-ключей имеет некорректный формат."
        decoded_size="$(printf '%s' "$key" | base64 -d 2>/dev/null | wc -c)"
        [[ "$decoded_size" == "32" ]] ||
            die "Файл WireGuard-ключей содержит ключ неверной длины."
    done <"$path"
    [[ "$line_count" == "4" ]] ||
        die "Файл WireGuard-ключей должен содержать четыре ключа."
    EXISTING_WG_KEYS_SHA256="$(sha256sum "$path" | awk '{print $1}')"
}

validate_existing_database() {
    local legacy_android_permissions="${1:-0}"
    [[ -f "$DATABASE_PATH" && ! -L "$DATABASE_PATH" ]] ||
        die "Существующая база должна быть обычным файлом, а не ссылкой."
    local mode size
    mode="$(stat -c '%a' "$DATABASE_PATH")"
    [[ "$mode" == "600" ]] ||
        die "Существующая база должна иметь права 600."
    size="$(stat -c '%s' "$DATABASE_PATH")"
    (( size > 0 && size <= MAX_DATABASE_BYTES )) ||
        die "Существующая база пуста или превышает 64 МиБ."
    validate_database_schema "$DATABASE_PATH" ||
        die "Существующая база WDTT имеет некорректную или несовместимую структуру."
    local stored_dns
    stored_dns="$(jq -r '.dns // "1.1.1.1"' "$DATABASE_PATH")"
    validate_dns_value "$stored_dns" ||
        die "Существующая база содержит некорректный DNS."
    validate_config_tree "$legacy_android_permissions"
    validate_wg_keys_file
}

harden_config_tree() {
    [[ -d "$CONFIG_DIR" && ! -L "$CONFIG_DIR" ]] || return 1
    local path
    while IFS= read -r -d '' path; do
        chmod 0700 "$path" || return 1
    done < <(find "$CONFIG_DIR" -type d -print0)
    while IFS= read -r -d '' path; do
        chmod 0600 "$path" || return 1
    done < <(find "$CONFIG_DIR" -type f -print0)
    validate_config_tree
}

port_is_busy() {
    local port="$1"
    if [[ "$TEST_MODE" == "1" ]]; then
        [[ ",${WDTT_INSTALLER_TEST_BUSY_PORTS:-}," == *",$port,"* ]]
        return
    fi
    ss -H -lun 2>/dev/null |
        awk '{print $4}' |
        grep -Eq "(^|:)$port$"
}

config_directory_write_probe() {
    [[ "$TEST_MODE" == "1" ]] && return 0
    local probe moved
    probe="$(mktemp "$CONFIG_DIR/.installer-write-test.XXXXXX")" || return 1
    moved="$probe.moved"
    chmod 0600 "$probe" || {
        rm -f "$probe"
        return 1
    }
    printf 'wdtt-installer-write-probe\n' >"$probe" || {
        rm -f "$probe"
        return 1
    }
    sync -f "$probe" >/dev/null 2>&1 || {
        rm -f "$probe"
        return 1
    }
    mv "$probe" "$moved" || {
        rm -f "$probe"
        return 1
    }
    rm -f "$moved"
}

iptables_runtime_rules_are_healthy() {
    local ext_iface="$1"
    local nat_count forward_count
    nat_count="$(
        iptables -t nat -S POSTROUTING 2>/dev/null |
            grep -F -- "--comment WDTT_MANAGED" |
            grep -F -- "-s $WDTT_SUBNET" |
            wc -l || true
    )"
    forward_count="$(
        iptables -S FORWARD 2>/dev/null |
            grep -F -- "--comment WDTT_MANAGED" |
            grep -F -- "wdtt0" |
            wc -l || true
    )"
    [[ "$nat_count" == "1" && "$forward_count" == "2" ]] &&
        iptables -t nat -C POSTROUTING -s "$WDTT_SUBNET" -o "$ext_iface" \
        -m comment --comment WDTT_MANAGED -j MASQUERADE >/dev/null 2>&1 &&
        iptables -C FORWARD -i wdtt0 \
            -m comment --comment WDTT_MANAGED -j ACCEPT >/dev/null 2>&1 &&
        iptables -C FORWARD -o wdtt0 \
            -m comment --comment WDTT_MANAGED -j ACCEPT >/dev/null 2>&1
}

nft_runtime_rules_are_healthy() {
    local ext_iface="$1"
    local nat_rules forward_rules nat_count inbound_count outbound_count
    nat_rules="$(nft list table ip wdtt 2>/dev/null)" || return 1
    forward_rules="$(nft list table inet wdtt 2>/dev/null)" || return 1
    nat_count="$(
        grep -F "10.66.66.0/24" <<<"$nat_rules" |
            grep -F "$ext_iface" |
            grep -c "masquerade" || true
    )"
    inbound_count="$(
        grep -F "wdtt0" <<<"$forward_rules" |
            grep -F "iifname" |
            grep -c "accept" || true
    )"
    outbound_count="$(
        grep -F "wdtt0" <<<"$forward_rules" |
            grep -F "oifname" |
            grep -c "accept" || true
    )"
    [[ "$nat_count" == "1" && "$inbound_count" == "1" &&
        "$outbound_count" == "1" ]] &&
        grep -Fq "hook postrouting" <<<"$nat_rules" &&
        grep -Fq "10.66.66.0/24" <<<"$nat_rules" &&
        grep -Fq "$ext_iface" <<<"$nat_rules" &&
        grep -Fq "masquerade" <<<"$nat_rules" &&
        grep -Fq "hook forward" <<<"$forward_rules" &&
        grep -Fq "wdtt0" <<<"$forward_rules" &&
        grep -Fq "accept" <<<"$forward_rules"
}

runtime_network_rules_are_healthy() {
    if [[ "$TEST_MODE" == "1" ]]; then
        [[ "${WDTT_INSTALLER_TEST_FAIL_NETWORK_HEALTH:-0}" != "1" ]]
        return
    fi
    local ext_iface
    ext_iface="$(default_ipv4_interface)"
    [[ -n "$ext_iface" ]] || return 1
    if command -v iptables >/dev/null 2>&1; then
        iptables_runtime_rules_are_healthy "$ext_iface"
    elif command -v nft >/dev/null 2>&1; then
        nft_runtime_rules_are_healthy "$ext_iface"
    else
        return 1
    fi
}

verify_runtime_health() {
    if [[ "$TEST_MODE" == "1" ]]; then
        [[ "${WDTT_INSTALLER_TEST_FAIL_HEALTH:-0}" != "1" &&
            "${WDTT_INSTALLER_TEST_FAIL_NETWORK_HEALTH:-0}" != "1" ]]
        return
    fi
    RUNTIME_HEALTH_ERROR=""
    service_is_active || {
        RUNTIME_HEALTH_ERROR="wdtt.service не подтверждена как активная"
        return 1
    }
    [[ -S /run/wdtt/admin.sock ]] || {
        RUNTIME_HEALTH_ERROR="admin-сокет /run/wdtt/admin.sock отсутствует"
        return 1
    }
    [[ -e /sys/class/net/wdtt0 ]] || {
        RUNTIME_HEALTH_ERROR="интерфейс wdtt0 отсутствует"
        return 1
    }
    ip -4 address show dev wdtt0 2>/dev/null |
        grep -Fq "10.66.66.1/24" || {
        RUNTIME_HEALTH_ERROR="адрес интерфейса wdtt0 не равен 10.66.66.1/24"
        return 1
    }
    port_is_busy "$DTLS_PORT" || {
        RUNTIME_HEALTH_ERROR="DTLS UDP-порт $DTLS_PORT не прослушивается"
        return 1
    }
    port_is_busy "$WG_PORT" || {
        RUNTIME_HEALTH_ERROR="внутренний WG UDP-порт $WG_PORT не прослушивается"
        return 1
    }
    [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || true)" == "1" ]] ||
        {
            RUNTIME_HEALTH_ERROR="IPv4 forwarding не включён"
            return 1
        }
    runtime_network_rules_are_healthy || {
        RUNTIME_HEALTH_ERROR="NAT/FORWARD-правила WDTT не подтверждены"
        return 1
    }
    config_directory_write_probe || {
        RUNTIME_HEALTH_ERROR="закрытый каталог /etc/wdtt недоступен для безопасной записи"
        return 1
    }
    validate_existing_database >/dev/null 2>&1 || {
        RUNTIME_HEALTH_ERROR="/etc/wdtt не прошёл итоговую безопасную проверку"
        return 1
    }
    return 0
}

subnet_route_conflicts() {
    local route_table
    if [[ "$TEST_MODE" == "1" ]]; then
        if [[ "${WDTT_INSTALLER_TEST_ROUTE_CONFLICT:-0}" == "1" ]]; then
            return 0
        fi
        route_table="${WDTT_INSTALLER_TEST_ROUTE_TABLE:-}"
        [[ -n "$route_table" ]] || return 1
    else
        route_table="$(ip -4 route show table all 2>/dev/null)"
    fi
    printf '%s\n' "$route_table" |
        awk '
        function ipnum(ip, a) {
            split(ip, a, ".")
            return (((a[1] * 256 + a[2]) * 256 + a[3]) * 256 + a[4])
        }
        function overlaps(cidr, parts, base, bits, size, first, last) {
            split(cidr, parts, "/")
            if (parts[1] !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return 0
            bits = (parts[2] == "" ? 32 : parts[2] + 0)
            if (bits < 0 || bits > 32) return 0
            size = 2 ^ (32 - bits)
            base = ipnum(parts[1])
            first = int(base / size) * size
            last = first + size - 1
            return first <= 172114687 && last >= 172114432
        }
        $0 !~ /(^|[[:space:]])dev[[:space:]]+wdtt0([[:space:]]|$)/ &&
        $1 != "default" && $1 != "broadcast" && $1 != "local" &&
        $1 != "unreachable" && $1 != "prohibit" && $1 != "blackhole" {
            if (overlaps($1)) {
                found=1
                exit
            }
        }
        END { exit !found }
        '
}

foreign_wdtt_network_rules_exist() {
    if [[ "$TEST_MODE" == "1" ]]; then
        [[ "${WDTT_INSTALLER_TEST_FOREIGN_RULES:-0}" == "1" ]]
        return
    fi
    if command -v iptables-save >/dev/null 2>&1 &&
        iptables-save 2>/dev/null | grep -Fq "WDTT_MANAGED"; then
        return 0
    fi
    if command -v nft >/dev/null 2>&1 &&
        {
            nft list ruleset 2>/dev/null | grep -Fq "WDTT_MANAGED" ||
                nft list table ip wdtt >/dev/null 2>&1 ||
                nft list table inet wdtt >/dev/null 2>&1
        }; then
        return 0
    fi
    return 1
}

validate_target_state() {
    local kind="$1"
    case "$kind" in
        new)
            validate_initial_config
            if [[ "$TEST_MODE" != "1" && -e /sys/class/net/wdtt0 ]]; then
                die "Интерфейс wdtt0 уже существует, но ручная установка не зарегистрирована."
            fi
            [[ "${WDTT_INSTALLER_TEST_INTERFACE_CONFLICT:-0}" != "1" ]] ||
                die "Интерфейс wdtt0 уже существует."
            subnet_route_conflicts &&
                die "Маршрут хоста пересекается с внутренней подсетью $WDTT_SUBNET."
            foreign_wdtt_network_rules_exist &&
                die "Найдены сетевые правила WDTT_MANAGED без собственной установки."
            port_is_busy "$DTLS_PORT" && die "DTLS-порт $DTLS_PORT уже занят."
            port_is_busy "$WG_PORT" && die "WG-порт $WG_PORT уже занят."
            ;;
        owned)
            [[ -z "$INITIAL_CONFIG" ]] ||
                die "Обновление не принимает --config и всегда сохраняет весь /etc/wdtt."
            [[ -f "$BINARY_PATH" && ! -L "$BINARY_PATH" ]] ||
                die "Бинарник собственной установки отсутствует или является ссылкой."
            validate_owned_managed_files
            validate_existing_database
            subnet_route_conflicts &&
                die "Маршрут хоста пересекается с внутренней подсетью $WDTT_SUBNET."
            if [[ -n "$CURRENT_DTLS_PORT" && "$DTLS_PORT" != "$CURRENT_DTLS_PORT" ]]; then
                port_is_busy "$DTLS_PORT" && die "Новый DTLS-порт $DTLS_PORT уже занят."
            fi
            if [[ -n "$CURRENT_WG_PORT" && "$WG_PORT" != "$CURRENT_WG_PORT" ]]; then
                port_is_busy "$WG_PORT" && die "Новый WG-порт $WG_PORT уже занят."
            fi
            ;;
        android)
            [[ -z "$INITIAL_CONFIG" ]] ||
                die "Принятие Android-установки всегда сохраняет текущий /etc/wdtt и не принимает --config."
            [[ -f "$BINARY_PATH" && ! -L "$BINARY_PATH" ]] ||
                die "Бинарник Android-установки отсутствует или является ссылкой."
            [[ -f "$UNIT_PATH" && ! -L "$UNIT_PATH" ]] ||
                die "unit Android-установки отсутствует или является ссылкой."
            grep -Fqx "# $ANDROID_DEPLOY_MARKER" "$UNIT_PATH" ||
                die "unit не содержит совместимую метку Android-деплоя."
            grep -Fqx "# $ANDROID_DEPLOY_COMPATIBILITY_MARKER" "$UNIT_PATH" ||
                die "unit Android-деплоя не содержит подтверждённую версию контракта совместимости."
            validate_existing_database 1
            subnet_route_conflicts &&
                die "Маршрут хоста пересекается с внутренней подсетью $WDTT_SUBNET."
            if [[ -n "$CURRENT_DTLS_PORT" && "$DTLS_PORT" != "$CURRENT_DTLS_PORT" ]]; then
                port_is_busy "$DTLS_PORT" && die "Новый DTLS-порт $DTLS_PORT уже занят."
            fi
            if [[ -n "$CURRENT_WG_PORT" && "$WG_PORT" != "$CURRENT_WG_PORT" ]]; then
                port_is_busy "$WG_PORT" && die "Новый WG-порт $WG_PORT уже занят."
            fi
            ;;
        foreign)
            die "Найдены существующие файлы WDTT без полной метки ручного установщика. Автоматическая перезапись запрещена."
            ;;
        *)
            die "Неизвестное состояние установки."
            ;;
    esac
    return 0
}

required_space_bytes() {
    local kind="$1"
    local source_size config_size=0
    source_size="$(stat -c '%s' "$SOURCE_BINARY")"
    if [[ "$kind" == "owned" || "$kind" == "android" || "$kind" == "adopt" || "$kind" == "handoff" ]]; then
        config_size="$(du -sb "$CONFIG_DIR" | awk '{print $1}')"
    fi
    printf '%s' $((MIN_FREE_BYTES + source_size * 3 + config_size * 3))
}

validate_disk_space() {
    local kind="$1"
    local required available probe
    required="$(required_space_bytes "$kind")"
    probe="$STATE_DIR"
    [[ -d "$probe" ]] || probe="$(dirname "$STATE_DIR")"
    while [[ ! -d "$probe" && "$probe" != "/" ]]; do
        probe="$(dirname "$probe")"
    done
    available="$(df -Pk "$probe" | awk 'NR == 2 {print $4 * 1024}')"
    [[ "$available" =~ ^[0-9]+$ ]] || die "Не удалось проверить свободное место."
    (( available >= required )) ||
        die "Недостаточно свободного места для staging, полной копии и отката."
}

detect_firewall_manager() {
    local ufw_active=0 firewalld_active=0
    if [[ "$TEST_MODE" == "1" ]]; then
        printf '%s' "${WDTT_INSTALLER_TEST_FIREWALL:-none}"
        return
    fi
    if command -v ufw >/dev/null 2>&1; then
        if LC_ALL=C ufw status 2>/dev/null | head -n 1 | grep -Fq "Status: active"; then
            ufw_active=1
        elif [[ -r /etc/ufw/ufw.conf ]] &&
            grep -Eq '^[[:space:]]*ENABLED[[:space:]]*=[[:space:]]*yes' /etc/ufw/ufw.conf; then
            ufw_active=1
        fi
    fi
    if command -v firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --state >/dev/null 2>&1 ||
            systemctl is-active --quiet firewalld.service 2>/dev/null; then
            firewalld_active=1
        fi
    fi
    if (( ufw_active + firewalld_active > 1 )); then
        printf 'multiple'
    elif (( ufw_active == 1 )); then
        printf 'ufw'
    elif (( firewalld_active == 1 )); then
        printf 'firewalld'
    elif command -v nft >/dev/null 2>&1 &&
        [[ -n "$(nft list ruleset 2>/dev/null || true)" ]]; then
        printf 'nftables'
    elif command -v iptables-save >/dev/null 2>&1 &&
        [[ -n "$(iptables-save 2>/dev/null || true)" ]]; then
        printf 'iptables'
    else
        printf 'none'
    fi
}

resolve_firewall_choice() {
    if [[ "$FIREWALL_MODE" == "ask" ]]; then
        FIREWALL_MODE="none"
    fi
    FIREWALL_MANAGER="$(detect_firewall_manager)"
    if [[ "$FIREWALL_MODE" == "open" ]]; then
        case "$FIREWALL_MANAGER" in
            ufw|firewalld) ;;
            multiple)
                die "Автоматическое правило запрещено: одновременно активны UFW и firewalld."
                ;;
            *)
                die "Автоматическое правило поддерживается только для одного активного UFW или firewalld."
                ;;
        esac
    fi
}

firewall_port_is_allowed() {
    local manager="$1"
    local port="${2:-${FIREWALL_PORT:-$DTLS_PORT}}"
    if [[ "$TEST_MODE" == "1" ]]; then
        [[ -f "$STATE_DIR/.test-firewall-${port}" ]]
        return
    fi
    case "$manager" in
        ufw)
            LC_ALL=C ufw status 2>/dev/null |
                awk -v port="${port}/udp" '
                    $1 == port && $2 != "(v6)" && $0 ~ /ALLOW/ {found=1}
                    END {exit !found}
                '
            ;;
        firewalld)
            firewall-cmd --query-port="${port}/udp" >/dev/null 2>&1 ||
                firewall-cmd --permanent --query-port="${port}/udp" >/dev/null 2>&1
            ;;
        *)
            return 1
            ;;
    esac
}

print_firewall_guidance() {
    local manager
    manager="$(detect_firewall_manager)"
    if [[ "$FIREWALL_MODE" == "open" ]]; then
        log "Межсетевой экран: ${DTLS_PORT}/udp будет разрешён через $(friendly_firewall_manager "$manager") как отдельный подтверждённый шаг."
        return
    fi
    case "$manager" in
        ufw)
            log "Межсетевой экран: активен UFW. После установки отдельно выполните:"
            log "  sudo ufw allow ${DTLS_PORT}/udp comment 'WDTT standalone'"
            ;;
        firewalld)
            log "Межсетевой экран: активен firewalld. После установки отдельно выполните:"
            log "  sudo firewall-cmd --permanent --add-port=${DTLS_PORT}/udp"
            log "  sudo firewall-cmd --reload"
            ;;
        nftables)
            log "Межсетевой экран: обнаружен nftables. Добавьте ${DTLS_PORT}/udp во входящие правила вручную."
            ;;
        iptables)
            log "Межсетевой экран: обнаружен iptables. Добавьте ${DTLS_PORT}/udp через используемый на сервере механизм сохранения правил."
            ;;
        multiple)
            warn "Одновременно обнаружены UFW и firewalld; установщик не предлагает команду, пока конфликт не устранён."
            ;;
        none)
            log "Межсетевой экран: активный менеджер не обнаружен. Проверьте доступность ${DTLS_PORT}/udp у VPS-провайдера."
            ;;
    esac
}

print_runtime_notice() {
    cat <<EOF

Сетевые изменения самого wdtt-server:
  - создаётся интерфейс wdtt0 и используется подсеть $WDTT_SUBNET;
  - включается IPv4 forwarding;
  - временно меняются сетевые sysctl для буферов, qdisc и BBR;
  - добавляются точечные NAT/FORWARD-правила WDTT;
  - сетевой скрипт ручной службы возвращает исходные sysctl и очищает временное состояние WDTT
    после остановки или неудачного запуска;
  - входящие правила межсетевого экрана меняются только после отдельного согласия для
    распознанного UFW/firewalld.
EOF
}

print_plan() {
    local kind="$1"
    local operation="первая установка"
    [[ "$kind" == "owned" ]] && operation="обновление собственной установки"
    [[ "$kind" == "android" || "$kind" == "adopt" ]] &&
        operation="явное принятие Android-установки с сохранением данных"
    cat <<EOF

План: $operation
  установщик:  $INSTALLER_VERSION
  установлен:  ${INSTALLED_INSTALLER_VERSION:-не установлен}
  бинарник:    $BINARY_PATH
  unit:        $UNIT_PATH
  данные:      $CONFIG_DIR
  состояние:  $STATE_DIR
  DTLS:        0.0.0.0:$DTLS_PORT/udp
  WG:          $WG_PORT/udp (внутренний транспорт)
  порт Android:$CLIENT_PORT/udp (на телефоне)
  DNS:         $DNS_VALUE
  WireGuard:   $(friendly_wg_backend "$WG_BACKEND")
  воркеры:     $MAX_WORKERS на доступ (0 = без лимита)
  handshakes:  $MAX_HANDSHAKES одновременно, rate $HANDSHAKE_RATE/с
  скорость:    $MAX_CLIENT_MBPS Мбит/с на доступ (0 = без лимита)
  firewall:    $(friendly_firewall_mode "$FIREWALL_MODE") ($(friendly_firewall_manager "${FIREWALL_MANAGER:-none}"))

Перед обновлением служба будет остановлена, а бинарник, unit, метка владения
и весь /etc/wdtt будут скопированы в закрытую резервную копию. При любой
ошибке они будут восстановлены.

Установщик не меняет SSH, пакеты, чужие службы или репозитории. Он не
отключает и не очищает чужой firewall; отдельное согласие добавляет только
${DTLS_PORT}/udp, а сетевой скрипт службы удаляет только временные правила WDTT.
EOF
    if [[ "$PORTS_CHANGED" == "1" ]]; then
        cat <<EOF

Порты существующей установки изменяются. В базе будут обновлены default_ports,
профиль владельца и порты всех клиентских ссылок. Уже импортированные профили
Android не меняются удалённо: их необходимо обновить вручную или импортировать
заново после установки.
EOF
    fi
    print_runtime_notice
    print_firewall_guidance
}

confirm_install() {
    [[ "$ASSUME_YES" == "1" ]] && return 0
    [[ -t 0 ]] || die "Для неинтерактивной установки добавьте --yes."
    local answer
    read -r -p "Для применения введите УСТАНОВИТЬ: " answer
    [[ "$answer" == "УСТАНОВИТЬ" ]] || die "Установка отменена."
}

print_handoff_plan() {
    cat <<EOF

План: передача ручной установки Android-деплою
  установщик:  $INSTALLER_VERSION
  бинарник:    $BINARY_PATH (сохраняется без замены)
  unit:        $UNIT_PATH (получит Android ownership-маркер)
  данные:      $CONFIG_DIR (сохраняются без изменения)
  DTLS:        0.0.0.0:$DTLS_PORT/udp
  WG:          $WG_PORT/udp
  порт Android:$CLIENT_PORT/udp
  DNS:         $DNS_VALUE

Перед изменением будут остановлены только wdtt.service и создана проверенная
полная копия бинарника, unit, метки владения, сетевого helper-а, firewall-
состояния и всего /etc/wdtt. Новый Android-совместимый unit будет запущен и
проверен. При любой ошибке ручная установка и состояние службы восстановятся.

После успешной передачи собственные unit-helper и ownership-файл standalone
будут удалены, а пользовательские резервные копии сохранятся. Если установщик
ранее добавил точное правило UFW/firewalld для текущего DTLS-порта, оно и его
защищённая метка сохранятся, чтобы сервер не потерял внешнюю доступность.
Правила других служб и настройки SSH не изменяются.
EOF
}

confirm_handoff() {
    [[ "$ASSUME_YES" == "1" ]] && return 0
    [[ -t 0 ]] || die "Для неинтерактивной передачи добавьте --yes."
    local answer
    read -r -p "Для передачи управления введите ПЕРЕДАТЬ: " answer
    [[ "$answer" == "ПЕРЕДАТЬ" ]] || die "Передача отменена."
}

write_unit() {
    local target="$1"
    cat >"$target" <<EOF
# $MANAGED_MARKER
[Unit]
Description=WDTT Plus standalone server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/var/lib/wdtt-server-installer/network-runtime.sh prepare
ExecStart=/usr/local/bin/wdtt-server -listen 0.0.0.0:$DTLS_PORT -wg-port $WG_PORT -config-dir /etc/wdtt -dns $DNS_VALUE -max-workers-per-access $MAX_WORKERS -max-handshakes $MAX_HANDSHAKES -handshake-rate $HANDSHAKE_RATE -max-client-mbps $MAX_CLIENT_MBPS -wg-backend $WG_BACKEND
ExecStopPost=/var/lib/wdtt-server-installer/network-runtime.sh cleanup
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$target"
}

write_android_handoff_unit() {
    local target="$1"
    cat >"$target" <<EOF
# $ANDROID_DEPLOY_MARKER
# $ANDROID_DEPLOY_COMPATIBILITY_MARKER
[Unit]
Description=WDTT Plus Server
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wdtt-server -listen 0.0.0.0:$DTLS_PORT -wg-port $WG_PORT -config-dir /etc/wdtt -max-passwords $MAX_PASSWORDS -max-workers-per-access $MAX_WORKERS -max-handshakes $MAX_HANDSHAKES -handshake-rate $HANDSHAKE_RATE -max-client-mbps $MAX_CLIENT_MBPS -wg-backend $WG_BACKEND
Restart=always
RestartSec=5
LimitNOFILE=65535
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$target"
}

write_network_helper() {
    local target="$1"
    cat >"$target" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly RUNTIME_DIR="/run/wdtt-server-installer-network"
readonly BASELINE_PATH="$RUNTIME_DIR/sysctl-baseline"
readonly WDTT_SUBNET="10.66.66.0/24"
readonly WDTT_IFACE="wdtt0"

readonly -a SYSCTL_KEYS=(
    net.ipv4.ip_forward
    net.core.default_qdisc
    net.core.rmem_max
    net.core.wmem_max
    net.core.rmem_default
    net.core.wmem_default
    net.core.netdev_max_backlog
    net.ipv4.udp_rmem_min
    net.ipv4.udp_wmem_min
    net.ipv4.tcp_rmem
    net.ipv4.tcp_wmem
    net.ipv4.tcp_congestion_control
)

key_is_allowed() {
    local requested="$1" key
    for key in "${SYSCTL_KEYS[@]}"; do
        [[ "$requested" == "$key" ]] && return 0
    done
    return 1
}

delete_tagged_iptables_rules() {
    local table="$1"
    local chain="$2"
    local required="$3"
    local count=0
    local line
    while true; do
        line="$(
            iptables -t "$table" -S "$chain" 2>/dev/null |
                grep -F -- "--comment WDTT_MANAGED" |
                grep -F -- "$required" |
                head -n 1 || true
        )"
        [[ -n "$line" ]] || break
        local -a args=()
        local old_ifs="$IFS"
        IFS=' ' read -r -a args <<<"$line"
        IFS="$old_ifs"
        ((${#args[@]} > 1)) || return 1
        args[0]="-D"
        iptables -t "$table" "${args[@]}" >/dev/null
        count=$((count + 1))
        (( count <= 128 )) || return 1
    done
}

cleanup_rules() {
    if command -v iptables >/dev/null 2>&1; then
        delete_tagged_iptables_rules nat POSTROUTING "-s $WDTT_SUBNET"
        delete_tagged_iptables_rules filter FORWARD "$WDTT_IFACE"
    fi
    if command -v nft >/dev/null 2>&1; then
        nft delete table ip wdtt >/dev/null 2>&1 || true
        nft delete table inet wdtt >/dev/null 2>&1 || true
    fi
    if ip link show "$WDTT_IFACE" >/dev/null 2>&1; then
        ip link delete "$WDTT_IFACE"
    fi
}

restore_baseline() {
    [[ -e "$BASELINE_PATH" ]] || return 0
    [[ -f "$BASELINE_PATH" && ! -L "$BASELINE_PATH" ]] || return 1
    local key value failed=0
    while IFS='=' read -r key value; do
        [[ -n "$key" ]] || continue
        key_is_allowed "$key" || return 1
        sysctl -w "$key=$value" >/dev/null 2>&1 || failed=1
    done <"$BASELINE_PATH"
    rm -f "$BASELINE_PATH"
    rmdir "$RUNTIME_DIR" 2>/dev/null || true
    return "$failed"
}

snapshot_baseline() {
    install -d -m 0700 "$RUNTIME_DIR"
    local pending="$BASELINE_PATH.new.$$"
    : >"$pending"
    chmod 0600 "$pending"
    local key value
    for key in "${SYSCTL_KEYS[@]}"; do
        value="$(sysctl -n "$key" 2>/dev/null || true)"
        [[ -n "$value" ]] || continue
        [[ "$value" != *$'\n'* ]] || return 1
        printf '%s=%s\n' "$key" "$value" >>"$pending"
    done
    mv -f "$pending" "$BASELINE_PATH"
}

case "${1:-}" in
    prepare)
        cleanup_rules
        restore_baseline
        snapshot_baseline
        ;;
    cleanup)
        cleanup_rules
        restore_baseline
        ;;
    *)
        printf 'usage: %s prepare|cleanup\n' "$0" >&2
        exit 2
        ;;
esac
EOF
    chmod 0700 "$target"
}

write_ownership() {
    local target="$1"
    cat >"$target" <<EOF
$MANAGED_MARKER
installer_version=$INSTALLER_VERSION
deploy_compatibility=$DEPLOY_COMPATIBILITY_VERSION
server_version=$SOURCE_BINARY_VERSION
server_sha256=$SOURCE_BINARY_SHA256
binary=/usr/local/bin/wdtt-server
unit=/etc/systemd/system/wdtt.service
config=/etc/wdtt
state=/var/lib/wdtt-server-installer
network_helper=/var/lib/wdtt-server-installer/network-runtime.sh
EOF
    chmod 0600 "$target"
}

write_state_claim() {
    local pending="$STATE_CLAIM_PATH.new.$$"
    printf '%s\n' "$STATE_MARKER" >"$pending"
    chmod 0600 "$pending"
    mv -f "$pending" "$STATE_CLAIM_PATH"
}

prepare_state_and_lock() {
    local created=0
    if [[ ! -e "$STATE_DIR" ]]; then
        install -d -m 0700 "$STATE_DIR"
        created=1
    fi
    [[ -d "$STATE_DIR" && ! -L "$STATE_DIR" ]] ||
        die "Каталог состояния отсутствует или является ссылкой."
    if [[ "$created" == "1" ]]; then
        write_state_claim
    elif ! state_claim_is_valid && [[ "$COMMAND" == "adopt-android" ]] && android_backup_state_is_safe; then
        write_state_claim
    fi
    state_claim_is_valid ||
        die "Каталог состояния не принадлежит ручному установщику."

    if [[ -e "$LOCK_PATH" ]]; then
        [[ -f "$LOCK_PATH" && ! -L "$LOCK_PATH" &&
            "$(stat -c '%u:%g' "$LOCK_PATH")" == "$(managed_owner_pair)" &&
            "$(stat -c '%h' "$LOCK_PATH")" == "1" ]] ||
            die "Файл блокировки ручного установщика имеет небезопасный тип или владельца."
    fi
    exec 9>"$LOCK_PATH"
    chmod 0600 "$LOCK_PATH"
    flock -n 9 || die "Другой экземпляр установщика уже выполняет изменения."
    LOCK_HELD=1
}

journal_value() {
    local key="$1"
    awk -F= -v key="$key" '$1 == key {sub(/^[^=]*=/, ""); print; exit}' "$TRANSACTION_PATH"
}

write_journal() {
    local pending="$TRANSACTION_PATH.new.$$"
    cat >"$pending" <<EOF
marker=$TRANSACTION_MARKER
transaction_id=$TRANSACTION_ID
kind=$INSTALL_KIND
phase=$TRANSACTION_PHASE
backup=$ACTIVE_BACKUP
staging=$STAGING_DIR
service_was_active=$SERVICE_WAS_ACTIVE
service_was_enabled=$SERVICE_WAS_ENABLED
binary_sha256=${SOURCE_BINARY_SHA256:-}
firewall_manager=$FIREWALL_MANAGER
firewall_change=$FIREWALL_CHANGE
firewall_marker=$FIREWALL_MARKER
firewall_baseline_runtime=$FIREWALL_BASELINE_RUNTIME
firewall_baseline_permanent=$FIREWALL_BASELINE_PERMANENT
firewall_port=${FIREWALL_PORT:-$DTLS_PORT}
previous_firewall_owned=$PREVIOUS_FIREWALL_OWNED
previous_firewall_manager=$PREVIOUS_FIREWALL_MANAGER
previous_firewall_port=$PREVIOUS_FIREWALL_PORT
previous_firewall_marker=$PREVIOUS_FIREWALL_MARKER
previous_firewall_removed=$PREVIOUS_FIREWALL_REMOVED
EOF
    chmod 0600 "$pending"
    mv -f "$pending" "$TRANSACTION_PATH"
}

load_and_validate_journal() {
    [[ -f "$TRANSACTION_PATH" && ! -L "$TRANSACTION_PATH" ]] ||
        die "Журнал незавершённой транзакции повреждён или является ссылкой."
    [[ "$(stat -c '%a' "$TRANSACTION_PATH")" == "600" &&
        "$(stat -c '%u:%g' "$TRANSACTION_PATH")" == "$(managed_owner_pair)" &&
        "$(stat -c '%h' "$TRANSACTION_PATH")" == "1" ]] ||
        die "Журнал транзакции имеет небезопасные права, владельца или hardlink."
    [[ "$(journal_value marker)" == "$TRANSACTION_MARKER" ]] ||
        die "Журнал транзакции не принадлежит ручному установщику."

    TRANSACTION_ID="$(journal_value transaction_id)"
    INSTALL_KIND="$(journal_value kind)"
    TRANSACTION_PHASE="$(journal_value phase)"
    ACTIVE_BACKUP="$(journal_value backup)"
    STAGING_DIR="$(journal_value staging)"
    SERVICE_WAS_ACTIVE="$(journal_value service_was_active)"
    SERVICE_WAS_ENABLED="$(journal_value service_was_enabled)"
    JOURNAL_BINARY_SHA256="$(journal_value binary_sha256)"
    FIREWALL_MANAGER="$(journal_value firewall_manager)"
    FIREWALL_CHANGE="$(journal_value firewall_change)"
    FIREWALL_MARKER="$(journal_value firewall_marker)"
    FIREWALL_BASELINE_RUNTIME="$(journal_value firewall_baseline_runtime)"
    FIREWALL_BASELINE_PERMANENT="$(journal_value firewall_baseline_permanent)"
    FIREWALL_PORT="$(journal_value firewall_port)"
    PREVIOUS_FIREWALL_OWNED="$(journal_value previous_firewall_owned)"
    PREVIOUS_FIREWALL_MANAGER="$(journal_value previous_firewall_manager)"
    PREVIOUS_FIREWALL_PORT="$(journal_value previous_firewall_port)"
    PREVIOUS_FIREWALL_MARKER="$(journal_value previous_firewall_marker)"
    PREVIOUS_FIREWALL_REMOVED="$(journal_value previous_firewall_removed)"

    [[ "$TRANSACTION_ID" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+-[0-9a-f]{8}$ ]] ||
        die "Идентификатор транзакции повреждён."
    [[ "$INSTALL_KIND" == "new" || "$INSTALL_KIND" == "owned" ||
        "$INSTALL_KIND" == "adopt" || "$INSTALL_KIND" == "handoff" ]] ||
        die "Тип транзакции повреждён."
    [[ "$TRANSACTION_PHASE" =~ ^(prepared|service_stopped|backup_complete|files_replacing|files_replaced|service_started|firewall_applying|firewall_applied|committed)$ ]] ||
        die "Фаза транзакции повреждена."
    [[ "$SERVICE_WAS_ACTIVE" =~ ^[01]$ && "$SERVICE_WAS_ENABLED" =~ ^[01]$ ]] ||
        die "Состояние службы в журнале повреждено."
    [[ -z "$JOURNAL_BINARY_SHA256" || "$JOURNAL_BINARY_SHA256" =~ ^[0-9a-f]{64}$ ]] ||
        die "SHA-256 в журнале повреждён."
    [[ "$FIREWALL_MANAGER" =~ ^(none|ufw|firewalld|nftables|iptables|multiple)$ ]] ||
        die "Менеджер межсетевого экрана в журнале повреждён."
    [[ "$FIREWALL_CHANGE" =~ ^(none|intent|added)$ ]] ||
        die "Состояние межсетевого экрана в журнале повреждено."
    [[ "$FIREWALL_BASELINE_RUNTIME" =~ ^[01]$ &&
        "$FIREWALL_BASELINE_PERMANENT" =~ ^[01]$ ]] ||
        die "Исходное состояние межсетевого экрана в журнале повреждено."
    [[ "$FIREWALL_PORT" =~ ^[0-9]+$ ]] &&
        (( FIREWALL_PORT >= 1 && FIREWALL_PORT <= 65535 )) ||
        die "Порт межсетевого экрана в журнале повреждён."
    [[ "$PREVIOUS_FIREWALL_OWNED" =~ ^[01]$ &&
        "$PREVIOUS_FIREWALL_REMOVED" =~ ^[01]$ ]] ||
        die "Предыдущее состояние межсетевого экрана в журнале повреждено."
    [[ "$PREVIOUS_FIREWALL_MANAGER" =~ ^(none|ufw|firewalld)$ ]] ||
        die "Предыдущий менеджер межсетевого экрана в журнале повреждён."
    [[ "$PREVIOUS_FIREWALL_PORT" =~ ^[0-9]+$ ]] &&
        (( PREVIOUS_FIREWALL_PORT >= 0 && PREVIOUS_FIREWALL_PORT <= 65535 )) ||
        die "Предыдущий порт межсетевого экрана в журнале повреждён."
    [[ -z "$PREVIOUS_FIREWALL_MARKER" ||
        "$PREVIOUS_FIREWALL_MARKER" =~ ^WDTT[[:space:]]standalone[[:space:]][0-9]{8}T[0-9]{6}Z-[0-9]+-[0-9a-f]{8}$ ]] ||
        die "Предыдущая метка межсетевого экрана в журнале повреждена."
    [[ -z "$FIREWALL_MARKER" ||
        "$FIREWALL_MARKER" == "WDTT standalone $TRANSACTION_ID" ]] ||
        die "Метка межсетевого экрана в журнале повреждена."
    [[ "$STAGING_DIR" == "$STAGING_ROOT/$TRANSACTION_ID" ]] ||
        die "Путь staging в журнале выходит за управляемый каталог."
    if [[ "$INSTALL_KIND" == "owned" || "$INSTALL_KIND" == "adopt" ||
        "$INSTALL_KIND" == "handoff" ]]; then
        [[ "$ACTIVE_BACKUP" == "$BACKUP_ROOT/$TRANSACTION_ID" ]] ||
            die "Путь резервной копии в журнале выходит за управляемый каталог."
    else
        [[ -z "$ACTIVE_BACKUP" ]] ||
            die "У новой установки не должно быть пути резервной копии."
    fi
}

load_firewall_state() {
    PREVIOUS_FIREWALL_OWNED=0
    PREVIOUS_FIREWALL_MANAGER="none"
    PREVIOUS_FIREWALL_PORT=0
    PREVIOUS_FIREWALL_MARKER=""
    PREVIOUS_FIREWALL_REMOVED=0
    [[ -e "$FIREWALL_STATE_PATH" ]] || return 0
    [[ -f "$FIREWALL_STATE_PATH" && ! -L "$FIREWALL_STATE_PATH" &&
        "$(stat -c '%a' "$FIREWALL_STATE_PATH")" == "600" &&
        "$(stat -c '%u:%g' "$FIREWALL_STATE_PATH")" == "$(managed_owner_pair)" &&
        "$(stat -c '%h' "$FIREWALL_STATE_PATH")" == "1" ]] ||
        die "Состояние межсетевого экрана повреждено или имеет небезопасные права."
    local state_marker
    state_marker="$(
        awk -F= '$1 == "marker" {sub(/^[^=]*=/, ""); print; exit}' "$FIREWALL_STATE_PATH"
    )"
    [[ "$state_marker" == "$FIREWALL_STATE_MARKER" ]] ||
        die "Состояние межсетевого экрана не принадлежит ручному установщику."
    PREVIOUS_FIREWALL_MANAGER="$(
        awk -F= '$1 == "manager" {print $2; exit}' "$FIREWALL_STATE_PATH"
    )"
    PREVIOUS_FIREWALL_PORT="$(
        awk -F= '$1 == "port" {print $2; exit}' "$FIREWALL_STATE_PATH"
    )"
    PREVIOUS_FIREWALL_MARKER="$(
        awk -F= '$1 == "rule_marker" {sub(/^[^=]*=/, ""); print; exit}' "$FIREWALL_STATE_PATH"
    )"
    [[ "$PREVIOUS_FIREWALL_MANAGER" =~ ^(ufw|firewalld)$ &&
        "$PREVIOUS_FIREWALL_PORT" =~ ^[0-9]+$ ]] &&
        (( PREVIOUS_FIREWALL_PORT >= 1 && PREVIOUS_FIREWALL_PORT <= 65535 )) ||
        die "Состояние межсетевого экрана содержит некорректный менеджер или порт."
    if [[ "$PREVIOUS_FIREWALL_MANAGER" == "ufw" ]]; then
        [[ "$PREVIOUS_FIREWALL_MARKER" =~ ^WDTT[[:space:]]standalone[[:space:]][0-9]{8}T[0-9]{6}Z-[0-9]+-[0-9a-f]{8}$ ]] ||
            die "Состояние UFW содержит некорректную метку."
    else
        [[ -z "$PREVIOUS_FIREWALL_MARKER" ]] ||
            die "Состояние firewalld не должно содержать текстовую метку."
    fi
    PREVIOUS_FIREWALL_OWNED=1
}

write_firewall_state() {
    local manager="$1"
    local port="$2"
    local rule_marker="$3"
    local pending="$FIREWALL_STATE_PATH.new.$TRANSACTION_ID"
    cat >"$pending" <<EOF
marker=$FIREWALL_STATE_MARKER
manager=$manager
port=$port
rule_marker=$rule_marker
EOF
    chmod 0600 "$pending"
    mv -f "$pending" "$FIREWALL_STATE_PATH"
}

service_is_active() {
    if [[ "$TEST_MODE" == "1" ]]; then
        [[ -f "$STATE_DIR/.test-service-active" ]]
    else
        systemctl is-active --quiet wdtt.service 2>/dev/null
    fi
}

service_is_enabled() {
    if [[ "$TEST_MODE" == "1" ]]; then
        [[ -f "$STATE_DIR/.test-service-enabled" ]]
    else
        systemctl is-enabled --quiet wdtt.service
    fi
}

stop_owned_service() {
    if [[ "$TEST_MODE" == "1" ]]; then
        rm -f "$STATE_DIR/.test-service-active"
    else
        systemctl stop wdtt.service
    fi
}

start_owned_service() {
    if [[ "$TEST_MODE" == "1" ]]; then
        if [[ -d "$CONFIG_DIR" && ! -e "$CONFIG_DIR/wg-keys.dat" ]]; then
            printf '%s\n%s\n%s\n%s\n' \
                'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
                'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
                'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
                'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
                >"$CONFIG_DIR/wg-keys.dat"
            chmod 0600 "$CONFIG_DIR/wg-keys.dat"
        fi
        : >"$STATE_DIR/.test-service-active"
    else
        systemctl restart wdtt.service
    fi
}

enable_owned_service() {
    if [[ "$TEST_MODE" == "1" ]]; then
        : >"$STATE_DIR/.test-service-enabled"
    else
        systemctl enable wdtt.service >/dev/null
    fi
}

disable_owned_service() {
    if [[ "$TEST_MODE" == "1" ]]; then
        rm -f "$STATE_DIR/.test-service-enabled"
    else
        systemctl disable wdtt.service >/dev/null 2>&1 || true
    fi
}

daemon_reload() {
    [[ "$TEST_MODE" == "1" ]] || systemctl daemon-reload
}

expected_managed_files_match() {
    local compare_dir result=0
    compare_dir="$(mktemp -d /tmp/wdtt-installer-compare.XXXXXX)" || return 1
    chmod 0700 "$compare_dir"
    if ! write_unit "$compare_dir/wdtt.service" ||
        ! write_network_helper "$compare_dir/network-runtime.sh" ||
        ! write_ownership "$compare_dir/ownership"; then
        result=1
    elif ! cmp -s "$UNIT_PATH" "$compare_dir/wdtt.service" ||
        ! cmp -s "$NETWORK_HELPER_PATH" "$compare_dir/network-runtime.sh" ||
        ! cmp -s "$OWNERSHIP_PATH" "$compare_dir/ownership"; then
        result=1
    fi
    find "$compare_dir" -mindepth 1 -delete 2>/dev/null || result=1
    rmdir "$compare_dir" 2>/dev/null || result=1
    return "$result"
}

database_settings_match() {
    local desired_ports="${DTLS_PORT},${WG_PORT},${CLIENT_PORT}"
    jq -e \
        --arg default_ports "$desired_ports" \
        --arg dns "$DNS_VALUE" \
        --argjson max_passwords "$MAX_PASSWORDS" '
        .default_ports == $default_ports and
        .dns == $dns and
        .max_passwords == $max_passwords
    ' "$DATABASE_PATH" >/dev/null
}

service_state_is_current() {
    if service_is_active; then
        if [[ "$TEST_MODE" == "1" ]]; then
            verify_runtime_health
            return
        fi
        verify_runtime_health
        return
    fi

    # Disabled and stopped is treated as an intentional operator state.
    # Enabled but stopped is unhealthy and must be repaired.
    ! service_is_enabled
}

installation_is_current() {
    is_owned_install || return 1
    [[ -x "$BINARY_PATH" && ! -L "$BINARY_PATH" ]] || return 1
    [[ "$(sha256sum "$BINARY_PATH" | awk '{print $1}')" == "$SOURCE_BINARY_SHA256" ]] ||
        return 1
    expected_managed_files_match || return 1
    database_settings_match || return 1
    service_state_is_current || return 1
    if [[ "$FIREWALL_MODE" == "open" ]]; then
        firewall_port_is_allowed "$FIREWALL_MANAGER" "$DTLS_PORT" || return 1
    fi
    return 0
}

print_current_installation() {
    log ""
    log "Установка уже актуальна:"
    log "  версия установщика: $INSTALLER_VERSION;"
    log "  бинарник и SHA-256 совпадают;"
    log "  systemd unit и метка установщика совпадают;"
    log "  порты, DNS и лимит клиентов совпадают;"
    if service_is_active; then
        log "  служба активна и локальные проверки работоспособности пройдены."
    else
        log "  служба остановлена и отключена; это состояние сохранено."
    fi
    if [[ "$FIREWALL_MODE" == "open" ]]; then
        log "  ${DTLS_PORT}/udp уже разрешён через $FIREWALL_MANAGER."
    fi
}

verify_tree_copy() {
    local source="$1"
    local copy="$2"
    local relative
    while IFS= read -r -d '' path; do
        relative="${path#"$source"/}"
        [[ -f "$copy/$relative" && ! -L "$copy/$relative" ]] || return 1
        cmp -s "$path" "$copy/$relative" || return 1
        [[ "$(stat -c '%a:%u:%g:%s' "$path")" == "$(stat -c '%a:%u:%g:%s' "$copy/$relative")" ]] ||
            return 1
    done < <(find "$source" -type f -print0)

    while IFS= read -r -d '' path; do
        relative="${path#"$source"/}"
        [[ -d "$copy/$relative" && ! -L "$copy/$relative" ]] || return 1
        [[ "$(stat -c '%a:%u:%g' "$path")" == "$(stat -c '%a:%u:%g' "$copy/$relative")" ]] ||
            return 1
    done < <(find "$source" -mindepth 1 -type d -print0)

    local source_file_count copy_file_count source_dir_count copy_dir_count
    source_file_count="$(find "$source" -type f | wc -l)"
    copy_file_count="$(find "$copy" -type f | wc -l)"
    source_dir_count="$(find "$source" -mindepth 1 -type d | wc -l)"
    copy_dir_count="$(find "$copy" -mindepth 1 -type d | wc -l)"
    [[ "$source_file_count" == "$copy_file_count" &&
        "$source_dir_count" == "$copy_dir_count" ]]
}

write_backup_manifest() {
    local backup="$1"
    local output="$2"
    local path relative type mode uid gid links size sha encoded
    printf 'manifest_version=%s\n' "$BACKUP_MANIFEST_VERSION" >"$output"
    chmod 0600 "$output"
    while IFS= read -r -d '' path; do
        relative="${path#"$backup"/}"
        case "$relative" in
            MANIFEST|COMPLETE) continue ;;
        esac
        if [[ -f "$path" && ! -L "$path" ]]; then
            type="f"
            size="$(stat -c '%s' "$path")"
            sha="$(sha256sum "$path" | awk '{print $1}')"
        elif [[ -d "$path" && ! -L "$path" ]]; then
            type="d"
            size="-"
            sha="-"
        else
            return 1
        fi
        mode="$(stat -c '%a' "$path")"
        uid="$(stat -c '%u' "$path")"
        gid="$(stat -c '%g' "$path")"
        links="$(stat -c '%h' "$path")"
        encoded="$(printf '%s' "$relative" | base64 -w 0)"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$type" "$mode" "$uid" "$gid" "$links" "$size" "$sha" "$encoded" >>"$output"
    done < <(find "$backup" -mindepth 1 -print0 | LC_ALL=C sort -z)
}

verify_backup_manifest() {
    local backup="$1"
    [[ -f "$backup/MANIFEST" && ! -L "$backup/MANIFEST" ]] || return 1
    local actual
    actual="$(mktemp "$STATE_DIR/.manifest-check.XXXXXX")" || return 1
    chmod 0600 "$actual"
    if ! write_backup_manifest "$backup" "$actual" ||
        ! cmp -s "$backup/MANIFEST" "$actual"; then
        rm -f "$actual"
        return 1
    fi
    rm -f "$actual"
}

create_full_backup() {
    [[ "$INSTALL_KIND" == "owned" || "$INSTALL_KIND" == "adopt" ||
        "$INSTALL_KIND" == "handoff" ]] || return 0
    [[ "$ACTIVE_BACKUP" == "$BACKUP_ROOT/$TRANSACTION_ID" ]] ||
        {
            warn "Путь резервной копии транзакции повреждён."
            return 1
        }
    install -d -m 0700 "$BACKUP_ROOT" "$ACTIVE_BACKUP"
    install -m 0755 "$BINARY_PATH" "$ACTIVE_BACKUP/wdtt-server"
    install -m 0644 "$UNIT_PATH" "$ACTIVE_BACKUP/wdtt.service"
    if [[ "$INSTALL_KIND" == "owned" || "$INSTALL_KIND" == "handoff" ]]; then
        install -m 0600 "$OWNERSHIP_PATH" "$ACTIVE_BACKUP/ownership"
        printf 'present\n' >"$ACTIVE_BACKUP/ownership.state"
    else
        printf 'absent\n' >"$ACTIVE_BACKUP/ownership.state"
    fi
    chmod 0600 "$ACTIVE_BACKUP/ownership.state"
    if [[ -f "$NETWORK_HELPER_PATH" && ! -L "$NETWORK_HELPER_PATH" ]]; then
        install -m 0700 "$NETWORK_HELPER_PATH" "$ACTIVE_BACKUP/network-runtime.sh"
        printf 'present\n' >"$ACTIVE_BACKUP/network-runtime.state"
    else
        printf 'absent\n' >"$ACTIVE_BACKUP/network-runtime.state"
    fi
    chmod 0600 "$ACTIVE_BACKUP/network-runtime.state"
    if [[ -f "$FIREWALL_STATE_PATH" && ! -L "$FIREWALL_STATE_PATH" ]]; then
        install -m 0600 "$FIREWALL_STATE_PATH" "$ACTIVE_BACKUP/firewall-state"
        printf 'present\n' >"$ACTIVE_BACKUP/firewall-state.state"
    else
        printf 'absent\n' >"$ACTIVE_BACKUP/firewall-state.state"
    fi
    chmod 0600 "$ACTIVE_BACKUP/firewall-state.state"
    cp -a "$CONFIG_DIR" "$ACTIVE_BACKUP/config"

    cmp -s "$BINARY_PATH" "$ACTIVE_BACKUP/wdtt-server" ||
        {
            warn "Не удалось проверить резервную копию бинарника."
            return 1
        }
    cmp -s "$UNIT_PATH" "$ACTIVE_BACKUP/wdtt.service" ||
        {
            warn "Не удалось проверить резервную копию unit."
            return 1
        }
    if [[ "$INSTALL_KIND" == "owned" || "$INSTALL_KIND" == "handoff" ]]; then
        cmp -s "$OWNERSHIP_PATH" "$ACTIVE_BACKUP/ownership" ||
            {
                warn "Не удалось проверить резервную копию метки владения."
                return 1
            }
    fi
    if [[ -f "$NETWORK_HELPER_PATH" ]]; then
        cmp -s "$NETWORK_HELPER_PATH" "$ACTIVE_BACKUP/network-runtime.sh" ||
            return 1
    fi
    if [[ -f "$FIREWALL_STATE_PATH" ]]; then
        cmp -s "$FIREWALL_STATE_PATH" "$ACTIVE_BACKUP/firewall-state" ||
            return 1
    fi
    verify_tree_copy "$CONFIG_DIR" "$ACTIVE_BACKUP/config" ||
        {
            warn "Не удалось проверить полную резервную копию /etc/wdtt."
            return 1
        }
    local pending_manifest="$STAGING_DIR/backup-manifest"
    write_backup_manifest "$ACTIVE_BACKUP" "$pending_manifest" || return 1
    atomic_install_file "$pending_manifest" "$ACTIVE_BACKUP/MANIFEST" 0600 ||
        return 1
    verify_backup_manifest "$ACTIVE_BACKUP" || {
        warn "Манифест резервной копии не прошёл проверку."
        return 1
    }
    printf '%s\n' "$TRANSACTION_MARKER complete $TRANSACTION_ID" >"$ACTIVE_BACKUP/COMPLETE"
    chmod 0600 "$ACTIVE_BACKUP/COMPLETE"
}

validate_backup() {
    [[ -n "$ACTIVE_BACKUP" && -d "$ACTIVE_BACKUP" && ! -L "$ACTIVE_BACKUP" ]] ||
        return 1
    [[ -f "$ACTIVE_BACKUP/COMPLETE" && ! -L "$ACTIVE_BACKUP/COMPLETE" ]] ||
        return 1
    grep -Fxq "$TRANSACTION_MARKER complete $TRANSACTION_ID" "$ACTIVE_BACKUP/COMPLETE" ||
        return 1
    [[ "$(stat -c '%a' "$ACTIVE_BACKUP")" == "700" &&
        "$(stat -c '%u:%g' "$ACTIVE_BACKUP")" == "$(managed_owner_pair)" &&
        "$(stat -c '%a' "$ACTIVE_BACKUP/MANIFEST")" == "600" &&
        "$(stat -c '%u:%g' "$ACTIVE_BACKUP/MANIFEST")" == "$(managed_owner_pair)" ]] ||
        return 1
    [[ -f "$ACTIVE_BACKUP/wdtt-server" && -f "$ACTIVE_BACKUP/wdtt.service" &&
        -f "$ACTIVE_BACKUP/ownership.state" &&
        -f "$ACTIVE_BACKUP/network-runtime.state" &&
        -f "$ACTIVE_BACKUP/firewall-state.state" &&
        -d "$ACTIVE_BACKUP/config" ]] ||
        return 1
    [[ -z "$(
        find "$ACTIVE_BACKUP/config" -mindepth 1 \
            \( -type l -o ! \( -type f -o -type d \) \) \
            -print -quit 2>/dev/null || true
    )" ]] || return 1
    case "$(tr -d '\r\n' <"$ACTIVE_BACKUP/ownership.state")" in
        present) [[ -f "$ACTIVE_BACKUP/ownership" && ! -L "$ACTIVE_BACKUP/ownership" ]] ;;
        absent) [[ ! -e "$ACTIVE_BACKUP/ownership" ]] ;;
        *) return 1 ;;
    esac
    verify_backup_manifest "$ACTIVE_BACKUP"
}

stage_owned_database_settings() {
    [[ "$INSTALL_KIND" == "owned" || "$INSTALL_KIND" == "adopt" ]] || return 0
    local desired_ports="${DTLS_PORT},${WG_PORT},${CLIENT_PORT}"
    local current_ports current_dns current_max
    current_ports="$(jq -r '.default_ports // ""' "$DATABASE_PATH")"
    current_dns="$(jq -r '.dns // ""' "$DATABASE_PATH")"
    current_max="$(jq -r '.max_passwords // 0' "$DATABASE_PATH")"
    if [[ "$current_ports" == "$desired_ports" &&
        "$current_dns" == "$DNS_VALUE" &&
        "$current_max" == "$MAX_PASSWORDS" ]]; then
        STAGED_DATABASE_UPDATE=0
        return 0
    fi

    local updated_at
    updated_at="$(date +%s)"
    jq \
        --arg default_ports "$desired_ports" \
        --arg dns "$DNS_VALUE" \
        --argjson max_passwords "$MAX_PASSWORDS" \
        --argjson migrate_ports "$MIGRATE_PORTS" \
        --argjson updated_at "$updated_at" '
        .default_ports = $default_ports |
        .dns = $dns |
        .max_passwords = $max_passwords |
        if $migrate_ports == 1 then
            .admin_profile = (.admin_profile // {}) |
            .admin_profile.ports = $default_ports |
            .admin_profile.listen_port = ($default_ports | split(",")[2] | tonumber) |
            .admin_profile.updated_at = $updated_at |
            .passwords |= with_entries(
                if (.value | type) == "object" then
                    .value.ports = $default_ports
                else
                    .
                end
            )
        else
            .
        end
    ' "$DATABASE_PATH" >"$STAGING_DIR/passwords.updated.json"
    chmod 0600 "$STAGING_DIR/passwords.updated.json"
    validate_database_schema "$STAGING_DIR/passwords.updated.json"
    STAGED_DATABASE_UPDATE=1
}

stage_installation() {
    STAGING_DIR="$STAGING_ROOT/$TRANSACTION_ID"
    install -d -m 0700 "$STAGING_ROOT" "$STAGING_DIR"
    install -m 0755 "$SOURCE_BINARY" "$STAGING_DIR/wdtt-server"
    if [[ "$INSTALL_KIND" == "new" ]]; then
        install -m 0600 "$INITIAL_CONFIG" "$STAGING_DIR/passwords.json"
        local source_config_sha staged_config_sha
        source_config_sha="$(sha256sum "$INITIAL_CONFIG" | awk '{print $1}')"
        staged_config_sha="$(sha256sum "$STAGING_DIR/passwords.json" | awk '{print $1}')"
        if [[ -z "$INITIAL_CONFIG_SHA256" ||
            "$source_config_sha" != "$INITIAL_CONFIG_SHA256" ||
            "$staged_config_sha" != "$INITIAL_CONFIG_SHA256" ]]; then
            warn "Начальная конфигурация изменилась после проверки."
            return 1
        fi
    fi
    if [[ "$INSTALL_KIND" == "handoff" ]]; then
        write_android_handoff_unit "$STAGING_DIR/wdtt.service"
    else
        write_unit "$STAGING_DIR/wdtt.service"
        write_network_helper "$STAGING_DIR/network-runtime.sh"
        bash -n "$STAGING_DIR/network-runtime.sh" || {
            warn "Сетевой скрипт не прошёл проверку синтаксиса."
            return 1
        }
        write_ownership "$STAGING_DIR/ownership"
    fi
    [[ "$(sha256sum "$STAGING_DIR/wdtt-server" | awk '{print $1}')" == "$SOURCE_BINARY_SHA256" ]] ||
        {
            warn "SHA-256 подготовленного бинарника изменился."
            return 1
        }
    local staged_server_version
    staged_server_version="$("$STAGING_DIR/wdtt-server" --version 2>/dev/null | head -n 1 || true)"
    [[ "$staged_server_version" == "$SUPPORTED_SERVER_VERSION" ]] ||
        {
            warn "Подготовленный бинарник не запускается."
            return 1
        }

    if command -v systemd-analyze >/dev/null 2>&1; then
        local verify_unit="$STAGING_DIR/wdtt-verify.service"
        if [[ "$INSTALL_KIND" == "handoff" ]]; then
            sed \
                -e "s#ExecStart=/usr/local/bin/wdtt-server#ExecStart=$STAGING_DIR/wdtt-server#" \
                "$STAGING_DIR/wdtt.service" >"$verify_unit"
        else
            sed \
                -e "s#ExecStart=/usr/local/bin/wdtt-server#ExecStart=$STAGING_DIR/wdtt-server#" \
                -e "s#/var/lib/wdtt-server-installer/network-runtime.sh#$STAGING_DIR/network-runtime.sh#g" \
                "$STAGING_DIR/wdtt.service" >"$verify_unit"
        fi
        if ! systemd-analyze verify "$verify_unit" >"$STAGING_DIR/systemd-verify.log" 2>&1; then
            warn "systemd отклонил подготовленный unit."
            return 1
        fi
        rm -f "$verify_unit" "$STAGING_DIR/systemd-verify.log"
    fi
}

atomic_install_file() {
    local source="$1"
    local target="$2"
    local mode="$3"
    local pending="$target.new.$TRANSACTION_ID"
    install -m "$mode" "$source" "$pending"
    mv -f "$pending" "$target"
}

replace_managed_files() {
    install -d -m 0755 "$(dirname "$BINARY_PATH")" "$(dirname "$UNIT_PATH")"
    if [[ "$INSTALL_KIND" == "handoff" ]]; then
        atomic_install_file "$STAGING_DIR/wdtt.service" "$UNIT_PATH" 0644
        maybe_fail_at unit_replaced || return 1
        return 0
    fi
    if [[ "$INSTALL_KIND" == "owned" || "$INSTALL_KIND" == "adopt" ]]; then
        install -d -m 0700 "$CONFIG_DIR"
    fi
    atomic_install_file "$STAGING_DIR/wdtt-server" "$BINARY_PATH" 0755
    maybe_fail_at binary_replaced || return 1
    atomic_install_file "$STAGING_DIR/network-runtime.sh" "$NETWORK_HELPER_PATH" 0700
    maybe_fail_at network_helper_replaced || return 1
    atomic_install_file "$STAGING_DIR/wdtt.service" "$UNIT_PATH" 0644
    maybe_fail_at unit_replaced || return 1
    atomic_install_file "$STAGING_DIR/ownership" "$OWNERSHIP_PATH" 0600
    maybe_fail_at ownership_replaced || return 1

    if [[ "$INSTALL_KIND" == "new" ]]; then
        install -d -m 0700 "$CONFIG_DIR"
        printf '%s\n%s\n' "$MANAGED_MARKER" "$TRANSACTION_ID" >"$FIRST_INSTALL_MARKER"
        chmod 0600 "$FIRST_INSTALL_MARKER"
        atomic_install_file "$STAGING_DIR/passwords.json" "$DATABASE_PATH" 0600
        maybe_fail_at database_replaced || return 1
    elif [[ "$STAGED_DATABASE_UPDATE" == "1" ]]; then
        atomic_install_file "$STAGING_DIR/passwords.updated.json" "$DATABASE_PATH" 0600
        maybe_fail_at database_replaced || return 1
    fi
}

verify_installed_files() {
    [[ -x "$BINARY_PATH" && ! -L "$BINARY_PATH" ]] || return 1
    if [[ "$INSTALL_KIND" == "handoff" ]]; then
        [[ -f "$UNIT_PATH" && ! -L "$UNIT_PATH" &&
            -f "$DATABASE_PATH" && ! -L "$DATABASE_PATH" ]] || return 1
        grep -Fqx "# $ANDROID_DEPLOY_MARKER" "$UNIT_PATH" || return 1
        grep -Fqx "# $ANDROID_DEPLOY_COMPATIBILITY_MARKER" "$UNIT_PATH" || return 1
        cmp -s "$STAGING_DIR/wdtt.service" "$UNIT_PATH" || return 1
        [[ "$(sha256sum "$BINARY_PATH" | awk '{print $1}')" == "$SOURCE_BINARY_SHA256" ]] ||
            return 1
        verify_tree_copy "$ACTIVE_BACKUP/config" "$CONFIG_DIR" || return 1
        [[ "$("$BINARY_PATH" --version 2>/dev/null | head -n 1 || true)" == "$SUPPORTED_SERVER_VERSION" ]] ||
            return 1
        return 0
    fi
    [[ -f "$UNIT_PATH" && -f "$OWNERSHIP_PATH" ]] || return 1
    [[ -x "$NETWORK_HELPER_PATH" && ! -L "$NETWORK_HELPER_PATH" ]] || return 1
    [[ "$(stat -c '%a' "$NETWORK_HELPER_PATH")" == "700" ]] || return 1
    [[ -f "$DATABASE_PATH" && ! -L "$DATABASE_PATH" ]] || return 1
    is_owned_install || return 1
    [[ "$(stat -c '%a' "$DATABASE_PATH")" == "600" ]] || return 1
    [[ "$(sha256sum "$BINARY_PATH" | awk '{print $1}')" == "$SOURCE_BINARY_SHA256" ]] ||
        return 1
    if [[ "$INSTALL_KIND" == "new" ]]; then
        cmp -s "$STAGING_DIR/passwords.json" "$DATABASE_PATH" || return 1
    elif [[ "$STAGED_DATABASE_UPDATE" == "1" ]]; then
        cmp -s "$STAGING_DIR/passwords.updated.json" "$DATABASE_PATH" || return 1
    fi
    local installed_server_version
    installed_server_version="$("$BINARY_PATH" --version 2>/dev/null | head -n 1 || true)"
    [[ "$installed_server_version" == "$SUPPORTED_SERVER_VERSION" ]] || return 1
}

start_and_verify_service() {
    local expected_existing_keys_sha256="$EXISTING_WG_KEYS_SHA256"
    daemon_reload
    if [[ "$INSTALL_KIND" == "new" ]]; then
        enable_owned_service
    fi
    start_owned_service

    if [[ "$TEST_MODE" == "1" ]]; then
        if [[ "${WDTT_INSTALLER_TEST_MUTATE_CONFIG:-0}" == "1" ]]; then
            printf 'changed-by-new-server\n' >"$CONFIG_DIR/runtime-mutated"
            chmod 0600 "$CONFIG_DIR/runtime-mutated"
        fi
        verify_runtime_health || return 1
        if [[ ( "$INSTALL_KIND" == "owned" || "$INSTALL_KIND" == "adopt" || "$INSTALL_KIND" == "handoff" ) &&
            "$SERVICE_WAS_ACTIVE" == "0" &&
            "$SERVICE_WAS_ENABLED" == "0" ]]; then
            stop_owned_service
        fi
        return 0
    fi

    local attempt
    for attempt in {1..20}; do
        if verify_runtime_health; then
            local post_start_keys_sha256="$EXISTING_WG_KEYS_SHA256"
            if [[ ( "$INSTALL_KIND" == "owned" || "$INSTALL_KIND" == "adopt" || "$INSTALL_KIND" == "handoff" ) &&
                -n "$expected_existing_keys_sha256" &&
                "$expected_existing_keys_sha256" != "$post_start_keys_sha256" ]]; then
                return 1
            fi
            if [[ "$INSTALL_KIND" == "new" ]]; then
                start_owned_service
                local restart_attempt
                for restart_attempt in {1..20}; do
                    if verify_runtime_health &&
                        [[ "$EXISTING_WG_KEYS_SHA256" == "$post_start_keys_sha256" ]]; then
                        break
                    fi
                    sleep 1
                done
                [[ "$EXISTING_WG_KEYS_SHA256" == "$post_start_keys_sha256" ]] ||
                    return 1
                verify_runtime_health || return 1
            fi
            if [[ ( "$INSTALL_KIND" == "owned" || "$INSTALL_KIND" == "adopt" || "$INSTALL_KIND" == "handoff" ) &&
                "$SERVICE_WAS_ACTIVE" == "0" &&
                "$SERVICE_WAS_ENABLED" == "0" ]]; then
                stop_owned_service
            fi
            return 0
        fi
        sleep 1
    done
    warn "Итоговая проверка службы не прошла: ${RUNTIME_HEALTH_ERROR:-неизвестная причина}."
    return 1
}

verify_handoff_source_health() {
    [[ "$INSTALL_KIND" == "handoff" ]] || return 0
    local started_for_check=0 attempt
    if ! service_is_active; then
        start_owned_service
        started_for_check=1
    fi
    for attempt in {1..20}; do
        if verify_runtime_health; then
            if [[ "$started_for_check" == "1" ]]; then
                stop_owned_service
            fi
            return 0
        fi
        [[ "$TEST_MODE" == "1" ]] || sleep 1
    done
    if [[ "$started_for_check" == "1" ]]; then
        stop_owned_service >/dev/null 2>&1 || true
    fi
    warn "Исходная standalone-служба не прошла проверку: ${RUNTIME_HEALTH_ERROR:-неизвестная причина}."
    return 1
}

remove_config_created_by_transaction() {
    [[ -f "$FIRST_INSTALL_MARKER" && ! -L "$FIRST_INSTALL_MARKER" ]] || return 0
    grep -Fxq "$MANAGED_MARKER" "$FIRST_INSTALL_MARKER" || return 0
    grep -Fxq "$TRANSACTION_ID" "$FIRST_INSTALL_MARKER" || return 0
    find "$CONFIG_DIR" -mindepth 1 -delete 2>/dev/null || true
    rmdir "$CONFIG_DIR" 2>/dev/null || true
}

restore_full_backup() {
    validate_backup || {
        warn "Полная резервная копия не прошла проверку; автоматический откат остановлен."
        return 1
    }

    install -d -m 0700 "$STAGING_DIR" || return 1
    [[ -d "$STAGING_DIR" && ! -L "$STAGING_DIR" ]] || return 1
    local failed_config="$STAGING_DIR/failed-config"
    if [[ -e "$failed_config" ]]; then
        find "$failed_config" -mindepth 1 -delete 2>/dev/null || true
        rmdir "$failed_config" 2>/dev/null || true
    fi
    if [[ -d "$CONFIG_DIR" && ! -L "$CONFIG_DIR" ]]; then
        mv "$CONFIG_DIR" "$failed_config"
    fi
    if [[ "$TEST_MODE" == "1" &&
        "${WDTT_INSTALLER_TEST_FAIL_RESTORE_AFTER_CONFIG_MOVE:-0}" == "1" ]]; then
        warn "Тестовый обрыв восстановления после перемещения текущей конфигурации."
        return 1
    fi
    install -d -m 0700 "$CONFIG_DIR" || return 1
    cp -a "$ACTIVE_BACKUP/config/." "$CONFIG_DIR/" || return 1
    chown --reference="$ACTIVE_BACKUP/config" "$CONFIG_DIR" || return 1
    chmod --reference="$ACTIVE_BACKUP/config" "$CONFIG_DIR" || return 1
    atomic_install_file "$ACTIVE_BACKUP/wdtt-server" "$BINARY_PATH" 0755 || return 1
    atomic_install_file "$ACTIVE_BACKUP/wdtt.service" "$UNIT_PATH" 0644 || return 1
    case "$(tr -d '\r\n' <"$ACTIVE_BACKUP/ownership.state")" in
        present)
            atomic_install_file "$ACTIVE_BACKUP/ownership" "$OWNERSHIP_PATH" 0600 || return 1
            ;;
        absent)
            rm -f "$OWNERSHIP_PATH"
            ;;
        *)
            return 1
            ;;
    esac
    case "$(tr -d '\r\n' <"$ACTIVE_BACKUP/network-runtime.state")" in
        present)
            atomic_install_file "$ACTIVE_BACKUP/network-runtime.sh" \
                "$NETWORK_HELPER_PATH" 0700 || return 1
            ;;
        absent)
            rm -f "$NETWORK_HELPER_PATH"
            ;;
        *)
            return 1
            ;;
    esac
    case "$(tr -d '\r\n' <"$ACTIVE_BACKUP/firewall-state.state")" in
        present)
            atomic_install_file "$ACTIVE_BACKUP/firewall-state" \
                "$FIREWALL_STATE_PATH" 0600 || return 1
            ;;
        absent)
            rm -f "$FIREWALL_STATE_PATH"
            ;;
        *)
            return 1
            ;;
    esac
    verify_tree_copy "$ACTIVE_BACKUP/config" "$CONFIG_DIR" || return 1
}

cleanup_staging() {
    if [[ -n "$STAGING_DIR" && "$STAGING_DIR" == "$STAGING_ROOT/"* &&
        -d "$STAGING_DIR" && ! -L "$STAGING_DIR" ]]; then
        find "$STAGING_DIR" -mindepth 1 -delete 2>/dev/null || true
        rmdir "$STAGING_DIR" 2>/dev/null || true
    fi
    rmdir "$STAGING_ROOT" 2>/dev/null || true
}

apply_ufw_rule() {
    FIREWALL_MARKER="WDTT standalone $TRANSACTION_ID"
    if firewall_port_is_allowed ufw; then
        FIREWALL_CHANGE="none"
        write_journal
        log "UFW уже разрешает ${FIREWALL_PORT}/udp; новое правило не требуется."
        return 0
    fi

    FIREWALL_CHANGE="intent"
    write_journal
    if [[ "$TEST_MODE" == "1" ]]; then
        : >"$STATE_DIR/.test-firewall-${FIREWALL_PORT}"
    else
        ufw allow "${FIREWALL_PORT}/udp" comment "$FIREWALL_MARKER" >/dev/null
        LC_ALL=C ufw status numbered 2>/dev/null |
            grep -Fq "$FIREWALL_MARKER" ||
            return 1
    fi
    FIREWALL_CHANGE="added"
    write_journal
}

apply_firewalld_rule() {
    FIREWALL_MARKER="WDTT standalone $TRANSACTION_ID"
    if [[ "$TEST_MODE" == "1" ]]; then
        if [[ -f "$STATE_DIR/.test-firewall-${FIREWALL_PORT}" ]]; then
            FIREWALL_BASELINE_RUNTIME=1
            FIREWALL_BASELINE_PERMANENT=1
            FIREWALL_CHANGE="none"
            write_journal
            return 0
        fi
        FIREWALL_CHANGE="intent"
        write_journal
        : >"$STATE_DIR/.test-firewall-${FIREWALL_PORT}"
        FIREWALL_CHANGE="added"
        write_journal
        return 0
    fi

    firewall-cmd --query-port="${FIREWALL_PORT}/udp" >/dev/null 2>&1 &&
        FIREWALL_BASELINE_RUNTIME=1
    firewall-cmd --permanent --query-port="${FIREWALL_PORT}/udp" >/dev/null 2>&1 &&
        FIREWALL_BASELINE_PERMANENT=1
    if [[ "$FIREWALL_BASELINE_RUNTIME" == "1" &&
        "$FIREWALL_BASELINE_PERMANENT" == "1" ]]; then
        FIREWALL_CHANGE="none"
        write_journal
        log "firewalld уже разрешает ${FIREWALL_PORT}/udp; новое правило не требуется."
        return 0
    fi

    FIREWALL_CHANGE="intent"
    write_journal
    if [[ "$FIREWALL_BASELINE_PERMANENT" == "0" ]]; then
        firewall-cmd --permanent --add-port="${FIREWALL_PORT}/udp" >/dev/null
    fi
    if [[ "$FIREWALL_BASELINE_RUNTIME" == "0" ]]; then
        firewall-cmd --add-port="${FIREWALL_PORT}/udp" >/dev/null
    fi
    FIREWALL_CHANGE="added"
    write_journal
}

apply_firewall_rule() {
    [[ "$FIREWALL_MODE" == "open" ]] || return 0
    case "$FIREWALL_MANAGER" in
        ufw)
            apply_ufw_rule
            ;;
        firewalld)
            apply_firewalld_rule
            ;;
        *)
            return 1
            ;;
    esac
}

rollback_ufw_rule() {
    [[ "$FIREWALL_CHANGE" == "none" ]] && return 0
    if [[ "$TEST_MODE" == "1" ]]; then
        rm -f "$STATE_DIR/.test-firewall-${FIREWALL_PORT}"
        return 0
    fi

    ufw_remove_rule_by_marker "$FIREWALL_MARKER"
}

ufw_remove_rule_by_marker() {
    local marker="$1"
    local number
    while true; do
        number="$(
            LC_ALL=C ufw status numbered 2>/dev/null |
                awk -v marker="$marker" '
                    index($0, marker) {
                        if (match($0, /\[[[:space:]]*[0-9]+\]/)) {
                            value=substr($0, RSTART + 1, RLENGTH - 2)
                            gsub(/[[:space:]]/, "", value)
                            print value
                            exit
                        }
                    }
                '
        )"
        [[ -n "$number" ]] || break
        ufw --force delete "$number" >/dev/null || return 1
    done
}

rollback_firewalld_rule() {
    [[ "$FIREWALL_CHANGE" == "none" ]] && return 0
    if [[ "$TEST_MODE" == "1" ]]; then
        if [[ "$FIREWALL_BASELINE_RUNTIME" == "0" &&
            "$FIREWALL_BASELINE_PERMANENT" == "0" ]]; then
            rm -f "$STATE_DIR/.test-firewall-${FIREWALL_PORT}"
        fi
        return 0
    fi

    if [[ "$FIREWALL_BASELINE_RUNTIME" == "0" ]] &&
        firewall-cmd --query-port="${FIREWALL_PORT}/udp" >/dev/null 2>&1; then
        firewall-cmd --remove-port="${FIREWALL_PORT}/udp" >/dev/null || return 1
    fi
    if [[ "$FIREWALL_BASELINE_PERMANENT" == "0" ]] &&
        firewall-cmd --permanent --query-port="${FIREWALL_PORT}/udp" >/dev/null 2>&1; then
        firewall-cmd --permanent --remove-port="${FIREWALL_PORT}/udp" >/dev/null || return 1
    fi
}

rollback_firewall_change() {
    case "$FIREWALL_MANAGER" in
        ufw)
            rollback_ufw_rule
            ;;
        firewalld)
            rollback_firewalld_rule
            ;;
        *)
            :
            ;;
    esac
    restore_previous_firewall_rule
}

remove_previous_firewall_rule() {
    [[ "$PREVIOUS_FIREWALL_OWNED" == "1" &&
        "$PORTS_CHANGED" == "1" &&
        "$PREVIOUS_FIREWALL_PORT" != "$DTLS_PORT" ]] || return 0
    PREVIOUS_FIREWALL_REMOVED=1
    write_journal
    if [[ "$TEST_MODE" == "1" ]]; then
        rm -f "$STATE_DIR/.test-firewall-${PREVIOUS_FIREWALL_PORT}"
        return 0
    fi
    case "$PREVIOUS_FIREWALL_MANAGER" in
        ufw)
            ufw_remove_rule_by_marker "$PREVIOUS_FIREWALL_MARKER"
            ;;
        firewalld)
            firewall-cmd --query-port="${PREVIOUS_FIREWALL_PORT}/udp" >/dev/null 2>&1 &&
                firewall-cmd --remove-port="${PREVIOUS_FIREWALL_PORT}/udp" >/dev/null
            firewall-cmd --permanent --query-port="${PREVIOUS_FIREWALL_PORT}/udp" >/dev/null 2>&1 &&
                firewall-cmd --permanent --remove-port="${PREVIOUS_FIREWALL_PORT}/udp" >/dev/null
            ;;
        *)
            return 1
            ;;
    esac
}

restore_previous_firewall_rule() {
    [[ "$PREVIOUS_FIREWALL_OWNED" == "1" &&
        "$PREVIOUS_FIREWALL_REMOVED" == "1" ]] || return 0
    if [[ "$TEST_MODE" == "1" ]]; then
        : >"$STATE_DIR/.test-firewall-${PREVIOUS_FIREWALL_PORT}"
        return 0
    fi
    case "$PREVIOUS_FIREWALL_MANAGER" in
        ufw)
            if ! LC_ALL=C ufw status 2>/dev/null |
                grep -Fq "$PREVIOUS_FIREWALL_MARKER"; then
                ufw allow "${PREVIOUS_FIREWALL_PORT}/udp" \
                    comment "$PREVIOUS_FIREWALL_MARKER" >/dev/null
            fi
            ;;
        firewalld)
            firewall-cmd --query-port="${PREVIOUS_FIREWALL_PORT}/udp" >/dev/null 2>&1 ||
                firewall-cmd --add-port="${PREVIOUS_FIREWALL_PORT}/udp" >/dev/null
            firewall-cmd --permanent --query-port="${PREVIOUS_FIREWALL_PORT}/udp" >/dev/null 2>&1 ||
                firewall-cmd --permanent --add-port="${PREVIOUS_FIREWALL_PORT}/udp" >/dev/null
            ;;
        *)
            return 1
            ;;
    esac
}

persist_transaction_firewall_state() {
    if [[ "$FIREWALL_CHANGE" == "added" ]]; then
        local persisted_marker=""
        [[ "$FIREWALL_MANAGER" != "ufw" ]] || persisted_marker="$FIREWALL_MARKER"
        write_firewall_state "$FIREWALL_MANAGER" "$FIREWALL_PORT" "$persisted_marker"
    elif [[ "$PREVIOUS_FIREWALL_OWNED" == "1" &&
        "$PREVIOUS_FIREWALL_REMOVED" == "0" ]]; then
        :
    else
        rm -f "$FIREWALL_STATE_PATH"
    fi
}

cleanup_managed_network_runtime() {
    [[ "$TEST_MODE" == "1" ]] && return 0
    local helper=""
    if [[ -f "$NETWORK_HELPER_PATH" && ! -L "$NETWORK_HELPER_PATH" &&
        -x "$NETWORK_HELPER_PATH" ]]; then
        helper="$NETWORK_HELPER_PATH"
    elif [[ -n "$STAGING_DIR" && -f "$STAGING_DIR/network-runtime.sh" &&
        ! -L "$STAGING_DIR/network-runtime.sh" ]]; then
        helper="$STAGING_DIR/network-runtime.sh"
    fi
    [[ -n "$helper" ]] || {
        warn "Не найден проверенный helper для очистки сетевого состояния."
        return 1
    }
    "$helper" cleanup
}

rollback_loaded_transaction() {
    warn "Выполняю откат транзакции $TRANSACTION_ID ($TRANSACTION_PHASE)."

    rollback_firewall_change || {
        warn "Не удалось безопасно откатить добавленное firewall-правило."
        return 1
    }

    if [[ "$INSTALL_KIND" == "owned" || "$INSTALL_KIND" == "adopt" ||
        "$INSTALL_KIND" == "handoff" ]]; then
        if is_owned_install || [[ -f "$ACTIVE_BACKUP/wdtt.service" ]]; then
            stop_owned_service >/dev/null 2>&1 || true
        fi
        cleanup_managed_network_runtime || return 1
        case "$TRANSACTION_PHASE" in
            backup_complete|files_replacing|files_replaced|service_started|firewall_applying|firewall_applied)
                restore_full_backup || return 1
                daemon_reload >/dev/null 2>&1 || true
                ;;
        esac
        if [[ "$SERVICE_WAS_ACTIVE" == "1" ]]; then
            start_owned_service >/dev/null 2>&1 || {
                warn "Файлы восстановлены, но прежнюю службу не удалось запустить."
                return 1
            }
        else
            stop_owned_service >/dev/null 2>&1 || true
        fi
        if [[ "$SERVICE_WAS_ENABLED" == "1" ]]; then
            enable_owned_service >/dev/null 2>&1 || true
        else
            disable_owned_service >/dev/null 2>&1 || true
        fi
    else
        if [[ -f "$UNIT_PATH" ]] && grep -Fqx "# $MANAGED_MARKER" "$UNIT_PATH"; then
            stop_owned_service >/dev/null 2>&1 || true
            disable_owned_service >/dev/null 2>&1 || true
        fi
        cleanup_managed_network_runtime || return 1
        remove_config_created_by_transaction
        if [[ -f "$OWNERSHIP_PATH" ]] &&
            grep -Fxq "$MANAGED_MARKER" "$OWNERSHIP_PATH"; then
            rm -f "$BINARY_PATH" "$UNIT_PATH" "$OWNERSHIP_PATH" \
                "$NETWORK_HELPER_PATH" "$FIREWALL_STATE_PATH"
        elif [[ "$TRANSACTION_PHASE" == "files_replacing" ||
            "$TRANSACTION_PHASE" == "files_replaced" ||
            "$TRANSACTION_PHASE" == "service_started" ||
            "$TRANSACTION_PHASE" == "firewall_applying" ||
            "$TRANSACTION_PHASE" == "firewall_applied" ]]; then
            local unsafe_partial=0
            if [[ -f "$BINARY_PATH" && ! -L "$BINARY_PATH" &&
                -n "$JOURNAL_BINARY_SHA256" &&
                "$(sha256sum "$BINARY_PATH" | awk '{print $1}')" == "$JOURNAL_BINARY_SHA256" ]]; then
                rm -f "$BINARY_PATH"
            elif [[ -e "$BINARY_PATH" ]]; then
                unsafe_partial=1
            fi
            if [[ -f "$UNIT_PATH" && ! -L "$UNIT_PATH" ]] &&
                grep -Fqx "# $MANAGED_MARKER" "$UNIT_PATH"; then
                rm -f "$UNIT_PATH"
            elif [[ -e "$UNIT_PATH" ]]; then
                unsafe_partial=1
            fi
            if [[ -f "$NETWORK_HELPER_PATH" && ! -L "$NETWORK_HELPER_PATH" &&
                -f "$STAGING_DIR/network-runtime.sh" ]] &&
                cmp -s "$NETWORK_HELPER_PATH" "$STAGING_DIR/network-runtime.sh"; then
                rm -f "$NETWORK_HELPER_PATH"
            elif [[ -e "$NETWORK_HELPER_PATH" ]]; then
                unsafe_partial=1
            fi
            [[ "$unsafe_partial" == "0" ]] || {
                warn "Часть файлов первой установки изменилась вне транзакции; они оставлены для ручной проверки."
                return 1
            }
        fi
        daemon_reload >/dev/null 2>&1 || true
    fi

    if [[ "$INSTALL_KIND" == "adopt" || "$INSTALL_KIND" == "handoff" ]]; then
        [[ "$ACTIVE_BACKUP" == "$BACKUP_ROOT/$TRANSACTION_ID" ]] || return 1
        if [[ -d "$ACTIVE_BACKUP" && ! -L "$ACTIVE_BACKUP" ]]; then
            find "$ACTIVE_BACKUP" -mindepth 1 -delete 2>/dev/null || return 1
            rmdir "$ACTIVE_BACKUP" 2>/dev/null || return 1
        elif [[ -e "$ACTIVE_BACKUP" || -L "$ACTIVE_BACKUP" ]]; then
            return 1
        fi
        rmdir "$BACKUP_ROOT" 2>/dev/null || true
    fi
    cleanup_staging
    rm -f "$TRANSACTION_PATH"
    TRANSACTION_ACTIVE=0
    log "Откат завершён."
}

recover_interrupted_transaction() {
    [[ -e "$TRANSACTION_PATH" ]] || return 0
    warn "Найдена незавершённая транзакция; сначала восстанавливаю прежнее состояние."
    load_and_validate_journal
    if [[ "$TRANSACTION_PHASE" == "committed" ]]; then
        finish_transaction
        log "Уже проверенная транзакция завершена без повторной установки."
        return 0
    fi
    rollback_loaded_transaction ||
        die "Автоматическое восстановление не завершено. Не изменяйте файлы и запустите doctor."
}

maybe_fail_at() {
    local point="$1"
    if [[ "$TEST_MODE" == "1" && "${WDTT_INSTALLER_TEST_FAIL_AT:-}" == "$point" ]]; then
        warn "Тестовая ошибка в точке $point."
        return 1
    fi
    return 0
}

begin_transaction() {
    local random_suffix
    random_suffix="$(od -An -N4 -tx4 /dev/urandom | tr -d ' ')"
    TRANSACTION_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$-$random_suffix"
    STAGING_DIR="$STAGING_ROOT/$TRANSACTION_ID"
    if [[ "$INSTALL_KIND" == "owned" || "$INSTALL_KIND" == "adopt" ||
        "$INSTALL_KIND" == "handoff" ]]; then
        ACTIVE_BACKUP="$BACKUP_ROOT/$TRANSACTION_ID"
    else
        ACTIVE_BACKUP=""
    fi
    SERVICE_WAS_ACTIVE=0
    SERVICE_WAS_ENABLED=0
    FIREWALL_CHANGE="none"
    FIREWALL_MARKER=""
    FIREWALL_BASELINE_RUNTIME=0
    FIREWALL_BASELINE_PERMANENT=0
    FIREWALL_PORT="$DTLS_PORT"
    STAGED_DATABASE_UPDATE=0
    load_firewall_state
    service_is_active && SERVICE_WAS_ACTIVE=1
    service_is_enabled && SERVICE_WAS_ENABLED=1
    TRANSACTION_PHASE="prepared"
    write_journal
    TRANSACTION_ACTIVE=1
}

apply_transaction() {
    stage_installation
    maybe_fail_at prepared

    if [[ ( "$INSTALL_KIND" == "owned" || "$INSTALL_KIND" == "adopt" || "$INSTALL_KIND" == "handoff" ) && "$SERVICE_WAS_ACTIVE" == "1" ]]; then
        stop_owned_service
    fi
    TRANSACTION_PHASE="service_stopped"
    write_journal
    maybe_fail_at service_stopped

    create_full_backup
    TRANSACTION_PHASE="backup_complete"
    write_journal
    if [[ "$INSTALL_KIND" == "adopt" ]]; then
        harden_config_tree || die "Не удалось безопасно ужесточить права /etc/wdtt после резервного копирования."
    fi
    stage_owned_database_settings
    maybe_fail_at backup_complete

    TRANSACTION_PHASE="files_replacing"
    write_journal
    replace_managed_files
    verify_installed_files
    TRANSACTION_PHASE="files_replaced"
    write_journal
    maybe_fail_at files_replaced

    start_and_verify_service
    TRANSACTION_PHASE="service_started"
    write_journal
    maybe_fail_at service_started

    if [[ "$FIREWALL_MODE" == "open" ]]; then
        TRANSACTION_PHASE="firewall_applying"
        write_journal
        apply_firewall_rule
    fi
    remove_previous_firewall_rule
    persist_transaction_firewall_state
    TRANSACTION_PHASE="firewall_applied"
    write_journal
    maybe_fail_at firewall_applied

    TRANSACTION_PHASE="committed"
    write_journal
    maybe_fail_at committed
}

cleanup_handoff_state() {
    [[ "$INSTALL_KIND" == "handoff" ]] || return 0
    [[ -f "$UNIT_PATH" && ! -L "$UNIT_PATH" ]] || return 1
    grep -Fqx "# $ANDROID_DEPLOY_MARKER" "$UNIT_PATH" || return 1
    grep -Fqx "# $ANDROID_DEPLOY_COMPATIBILITY_MARKER" "$UNIT_PATH" || return 1
    [[ -f "$OWNERSHIP_PATH" && ! -L "$OWNERSHIP_PATH" ]] || return 1
    grep -Fxq "$MANAGED_MARKER" "$OWNERSHIP_PATH" || return 1
    validate_backup || return 1

    rm -f "$OWNERSHIP_PATH" "$NETWORK_HELPER_PATH"
    [[ "$ACTIVE_BACKUP" == "$BACKUP_ROOT/$TRANSACTION_ID" ]] || return 1
    find "$ACTIVE_BACKUP" -mindepth 1 -delete 2>/dev/null || return 1
    rmdir "$ACTIVE_BACKUP" 2>/dev/null || return 1
    rmdir "$BACKUP_ROOT" 2>/dev/null || true
}

finish_transaction() {
    if [[ "$INSTALL_KIND" == "new" ]]; then
        rm -f "$FIRST_INSTALL_MARKER"
    fi
    cleanup_handoff_state
    cleanup_staging
    rm -f "$TRANSACTION_PATH"
    TRANSACTION_ACTIVE=0
}

handle_transaction_failure() {
    if [[ "$TEST_MODE" == "1" &&
        "${WDTT_INSTALLER_TEST_LEAVE_TRANSACTION:-0}" == "1" ]]; then
        warn "Тестовый режим оставил журнал для проверки восстановления."
        TRANSACTION_ACTIVE=0
        return 1
    fi
    load_and_validate_journal
    if [[ "$TRANSACTION_PHASE" == "committed" ]]; then
        finish_transaction
        return 0
    fi
    rollback_loaded_transaction || return 1
    return 0
}

handle_signal() {
    local signal="$1"
    trap - INT TERM HUP
    warn "Получен сигнал $signal."
    if [[ "$TRANSACTION_ACTIVE" == "1" && -f "$TRANSACTION_PATH" ]]; then
        if load_and_validate_journal; then
            if [[ "$TRANSACTION_PHASE" == "committed" ]]; then
                finish_transaction || true
            else
                rollback_loaded_transaction || true
            fi
        fi
    fi
    exit 130
}

handle_transaction_error() {
    local status="$1"
    trap - ERR
    if handle_transaction_failure; then
        if [[ "$TRANSACTION_PHASE" == "committed" ]]; then
            warn "Проверенная транзакция была завершена после поздней ошибки."
            exit 0
        fi
        die "Установка не прошла итоговую проверку; прежнее состояние восстановлено."
    fi
    warn "Исходный код ошибки транзакции: $status."
    die "Установка прервана; автоматический откат требует проверки через doctor."
}

perform_install() {
    local initial_kind="$1"
    local preflight_current=0
    local confirmation_done=0
    [[ -n "$SOURCE_BINARY" ]] || die "Для $COMMAND обязателен локальный бинарник."
    validate_binary
    validate_options
    validate_network_prerequisites
    resolve_firewall_choice
    if [[ "$initial_kind" == "interrupted" ]]; then
        [[ -n "$RECOVERY_RESULT_KIND" ]] ||
            die "Не удалось определить результат восстановления."
        if [[ "$RECOVERY_RESULT_KIND" == "new" ]]; then
            validate_initial_config
        else
            [[ -z "$INITIAL_CONFIG" ]] ||
                die "После восстановления это будет обновление; --config не принимается."
        fi
        warn "Перед установкой будет восстановлена незавершённая транзакция."
        print_plan "$RECOVERY_RESULT_KIND"
    else
        validate_port_migration_choice "$initial_kind"
        validate_target_state "$initial_kind"
        if [[ "$initial_kind" == "owned" ]] && installation_is_current; then
            preflight_current=1
            print_current_installation
        else
            validate_disk_space "$initial_kind"
            print_plan "$initial_kind"
        fi
    fi
    [[ "$DRY_RUN" == "1" ]] && {
        if [[ "$preflight_current" == "1" ]]; then
            log "Проверка без изменений завершена: обновление не требуется."
        else
            log "Проверка без изменений завершена: сервер не изменён."
        fi
        return 0
    }

    if [[ "$TEST_MODE" != "1" ]]; then
        [[ "$(id -u)" -eq 0 ]] ||
            die "Установка требует root. Сначала используйте check или --dry-run."
        validate_nat_backend_access
    fi
    if [[ "$preflight_current" == "0" ]]; then
        confirm_install
        confirmation_done=1
    fi

    prepare_state_and_lock
    recover_interrupted_transaction
    resolve_firewall_choice

    local locked_kind
    locked_kind="$(detect_install_kind)"
    if [[ "$initial_kind" == "interrupted" ]]; then
        [[ "$locked_kind" == "$RECOVERY_RESULT_KIND" ]] ||
            die "После восстановления получено неожиданное состояние: $locked_kind."
    else
        [[ "$locked_kind" == "$initial_kind" ]] ||
        die "Состояние установки изменилось после предварительной проверки: было «$(friendly_install_kind "$initial_kind")», стало «$(friendly_install_kind "$locked_kind")». Запустите команду заново."
    fi
    local locked_target_kind="$locked_kind"
    INSTALL_KIND="$locked_kind"
    [[ "$INSTALL_KIND" != "android" ]] || INSTALL_KIND="adopt"
    load_owned_runtime_defaults
    validate_options
    validate_network_prerequisites
    validate_port_migration_choice "$locked_target_kind"
    validate_target_state "$locked_target_kind"
    if [[ "$INSTALL_KIND" == "owned" ]] && installation_is_current; then
        if [[ "$preflight_current" == "0" ]]; then
            print_current_installation
        fi
        log "Повторная проверка под блокировкой завершена: изменений и перезапуска не будет."
        return 0
    fi
    validate_disk_space "$INSTALL_KIND"
    if [[ "$confirmation_done" == "0" ]]; then
        warn "После получения блокировки состояние изменилось; теперь требуется обновление."
        print_plan "$INSTALL_KIND"
        confirm_install
    fi

    begin_transaction
    trap 'handle_signal INT' INT
    trap 'handle_signal TERM' TERM
    trap 'handle_signal HUP' HUP
    trap 'handle_transaction_error $?' ERR

    apply_transaction
    trap - ERR
    finish_transaction
    trap - INT TERM HUP

    log "Сервер WDTT Plus установлен и проверен."
    print_firewall_guidance
    log "SSH-данные Android-приложению для обычного подключения не требуются."
}

perform_handoff_android() {
    local initial_kind="$1"
    local lock_already_held=0
    local recovered_transaction_kind=""

    if [[ "$initial_kind" == "interrupted" ]]; then
        [[ "$DRY_RUN" == "0" ]] ||
            die "Незавершённую транзакцию нельзя восстановить в режиме --dry-run. Запустите doctor."
        [[ "$TEST_MODE" == "1" || "$(id -u)" -eq 0 ]] ||
            die "Восстановление транзакции требует root."
        prepare_state_and_lock
        load_and_validate_journal
        recovered_transaction_kind="$INSTALL_KIND"
        recover_interrupted_transaction
        lock_already_held=1
        initial_kind="$(detect_install_kind)"
        if [[ "$initial_kind" == "android" && "$recovered_transaction_kind" == "handoff" ]]; then
            log "Передача Android-деплою уже была проверена и завершена."
            return 0
        fi
    fi

    [[ "$initial_kind" == "owned" ]] ||
        die "handoff-android требует собственную ручную установку; текущее состояние: $(friendly_install_kind "$initial_kind")."

    FIREWALL_MODE="none"
    load_owned_runtime_defaults
    SOURCE_BINARY="$BINARY_PATH"
    validate_binary
    validate_options
    validate_network_prerequisites
    validate_target_state owned
    validate_disk_space handoff
    if service_is_active; then
        verify_runtime_health ||
            die "Активная standalone-служба не прошла проверку: ${RUNTIME_HEALTH_ERROR:-неизвестная причина}."
    else
        warn "Служба остановлена; после подтверждения она будет временно запущена для проверки, а исходное состояние запуска сохранится."
    fi
    print_handoff_plan
    [[ "$DRY_RUN" == "0" ]] || {
        log "Проверка передачи без изменений завершена: сервер не изменён."
        return 0
    }

    [[ "$TEST_MODE" == "1" || "$(id -u)" -eq 0 ]] ||
        die "Передача управления требует root."
    confirm_handoff
    if [[ "$lock_already_held" == "0" ]]; then
        prepare_state_and_lock
        recover_interrupted_transaction
    fi

    local locked_kind
    locked_kind="$(detect_install_kind)"
    [[ "$locked_kind" == "owned" ]] ||
        die "Состояние изменилось после проверки: ожидалась ручная установка, получено «$(friendly_install_kind "$locked_kind")»."

    load_owned_runtime_defaults
    SOURCE_BINARY="$BINARY_PATH"
    validate_binary
    validate_options
    validate_network_prerequisites
    validate_nat_backend_access
    validate_target_state owned
    validate_disk_space handoff

    INSTALL_KIND="handoff"
    begin_transaction
    trap 'handle_signal INT' INT
    trap 'handle_signal TERM' TERM
    trap 'handle_signal HUP' HUP
    trap 'handle_transaction_error $?' ERR

    verify_handoff_source_health
    apply_transaction
    finish_transaction
    trap - ERR
    trap - INT TERM HUP

    [[ "$(detect_install_kind)" == "android" ]] ||
        die "Передача завершилась без подтверждённой Android ownership-метки."
    log "Управление сервером безопасно передано Android-деплою."
    log "Теперь в WDTT Plus можно выполнить «Обновить с сохранением»; данные и WireGuard-ключи сохранены."
}

perform_check() {
    local kind="$1"
    if [[ -n "$SOURCE_BINARY" ]]; then
        validate_binary
    else
        warn "Бинарник не указан; его версия и SHA-256 не проверены."
    fi
    validate_options
    validate_network_prerequisites
    resolve_firewall_choice
    validate_port_migration_choice "$kind"
    case "$kind" in
        new)
            [[ -n "$INITIAL_CONFIG" ]] && validate_initial_config
            if [[ -n "$SOURCE_BINARY" && -n "$INITIAL_CONFIG" ]]; then
                validate_target_state "$kind"
                validate_disk_space "$kind"
            fi
            ;;
        owned)
            [[ -z "$INITIAL_CONFIG" ]] ||
                die "У собственной установки начальная конфигурация не заменяется."
            validate_target_state "$kind"
            if [[ -n "$SOURCE_BINARY" ]] && installation_is_current; then
                print_current_installation
                log "Проверка завершена: обновление не требуется."
                return 0
            fi
            ;;
        android)
            [[ -z "$INITIAL_CONFIG" ]] ||
                die "Android-установка сохраняет текущий /etc/wdtt; --config не принимается."
            validate_target_state "$kind"
            log "Обнаружена совместимая Android-установка. Для передачи под транзакционное управление запустите adopt-android с явным подтверждением."
            ;;
        foreign)
            die "Обнаружена неизвестная или незавершённая установка; автоматические действия запрещены."
            ;;
        interrupted)
            die "Обнаружена незавершённая транзакция. Запустите doctor, затем повторите install для автоматического восстановления."
            ;;
    esac
    print_plan "$kind"
    log "Проверка завершена без изменений."
}

read_password_file() {
    local path="$1"
    assert_no_symlink_components "$path"
    [[ -f "$path" && ! -L "$path" ]] ||
        die "Файл пароля должен быть обычным файлом, а не ссылкой."
    validate_private_file_permissions "$path" "Файл пароля"
    IFS= read -r MAIN_PASSWORD_RESULT <"$path" || true
    validate_main_password "$MAIN_PASSWORD_RESULT" ||
        die "Пароль из защищённого файла не прошёл проверку."
}

perform_init_config() {
    if [[ -z "$OUTPUT_CONFIG" ]]; then
        [[ -t 0 ]] || die "Для неинтерактивного init-config укажите --output."
        prompt_required_path OUTPUT_CONFIG "Путь нового passwords.json"
    fi

    assert_no_symlink_components "$OUTPUT_CONFIG"
    [[ ! -e "$OUTPUT_CONFIG" ]] ||
        die "Файл уже существует; init-config никогда его не перезаписывает."
    local parent
    parent="$(dirname "$OUTPUT_CONFIG")"
    [[ -d "$parent" && ! -L "$parent" ]] ||
        die "Родительский каталог для конфигурации должен существовать и не быть ссылкой."

    if [[ -n "$PASSWORD_FILE" ]]; then
        read_password_file "$PASSWORD_FILE"
    else
        [[ -t 0 ]] ||
            die "Без терминала передайте пароль через закрытый --password-file."
        read_hidden_password
    fi

    if [[ -t 0 && "$ASSUME_YES" == "0" ]]; then
        if ! option_is_set dtls_port; then
            prompt_uint_value DTLS_PORT "Публичный DTLS-порт" "$DTLS_PORT" 1 65535
            mark_option dtls_port
        fi
        if ! option_is_set wg_port; then
            prompt_uint_value WG_PORT "Внутренний WireGuard-порт" "$WG_PORT" 1 65535
            mark_option wg_port
        fi
        if ! option_is_set client_port; then
            prompt_uint_value CLIENT_PORT "Локальный порт Android" "$CLIENT_PORT" 1 65535
            mark_option client_port
        fi
        if ! option_is_set dns; then
            prompt_dns_value
            mark_option dns
        fi
        if ! option_is_set max_passwords; then
            prompt_uint_value MAX_PASSWORDS "Максимум клиентских паролей" "$MAX_PASSWORDS" 1 500
            mark_option max_passwords
        fi
    fi
    validate_options

    local pending="$OUTPUT_CONFIG.new.$$"
    if ! printf '%s' "$MAIN_PASSWORD_RESULT" |
        jq -n \
            --rawfile main_password /dev/stdin \
            --arg dns "$DNS_VALUE" \
            --arg default_ports "${DTLS_PORT},${WG_PORT},${CLIENT_PORT}" \
            --argjson max_passwords "$MAX_PASSWORDS" '
            {
                main_password: $main_password,
                admin_id: "",
                bot_token: "",
                dns: $dns,
                max_passwords: $max_passwords,
                default_ports: $default_ports,
                passwords: {},
                devices: {}
            }
        ' >"$pending"; then
        rm -f "$pending"
        MAIN_PASSWORD_RESULT=""
        die "Не удалось создать начальную конфигурацию."
    fi
    chmod 0600 "$pending"
    mv "$pending" "$OUTPUT_CONFIG"
    MAIN_PASSWORD_RESULT=""
    log "Закрытая начальная конфигурация создана: $OUTPUT_CONFIG"
    log "Файл не перезаписывается автоматически; сохраните его в защищённом месте."
}

status_line() {
    local label="$1"
    local value="$2"
    printf '%s: %s\n' "$label" "$value"
}

format_bytes() {
    local bytes="${1:-0}"
    awk -v bytes="$bytes" '
        BEGIN {
            split("Б КиБ МиБ ГиБ ТиБ", units, " ")
            value = bytes + 0
            unit = 1
            while (value >= 1024 && unit < 5) {
                value = value / 1024
                unit++
            }
            if (unit == 1) {
                printf "%.0f %s", value, units[unit]
            } else {
                printf "%.2f %s", value, units[unit]
            }
        }
    '
}

format_traffic_pair() {
    local down="$1"
    local up="$2"
    printf '↓%s / ↑%s' "$(format_bytes "$down")" "$(format_bytes "$up")"
}

service_main_pid() {
    [[ "$TEST_MODE" == "1" ]] && {
        printf '0'
        return
    }
    systemctl show -p MainPID --value wdtt.service 2>/dev/null || printf '0'
}

monitor_runtime() {
    local kind="$1"
    local manager
    manager="$(detect_firewall_manager)"

    printf '\nСлужба и сеть\n'
    status_line "Состояние установки" "$(friendly_install_kind "$kind")"
    if [[ "$TEST_MODE" != "1" && -f "$UNIT_PATH" ]]; then
        status_line "Служба" "$(friendly_service_state "$(systemctl is-active wdtt.service 2>/dev/null || true)")"
    elif [[ "$TEST_MODE" == "1" && "$kind" == "owned" ]]; then
        service_is_active &&
            status_line "Служба" "активна" || status_line "Служба" "остановлена"
    else
        status_line "Служба" "не проверялась"
    fi

    local pid
    pid="$(service_main_pid)"
    if [[ "$TEST_MODE" != "1" && "$pid" =~ ^[0-9]+$ && "$pid" != "0" ]]; then
        local cpu mem rss elapsed
        IFS=$'\t' read -r cpu mem rss elapsed < <(
            ps -p "$pid" -o %cpu= -o %mem= -o rss= -o etime= 2>/dev/null |
                awk '{
                    cpu=$1
                    mem=$2
                    rss=$3
                    $1=$2=$3=""
                    sub(/^[[:space:]]+/, "")
                    print cpu "\t" mem "\t" rss "\t" $0
                }'
        ) || true
        status_line "PID" "$pid"
        status_line "CPU" "${cpu:-н/д}%"
        status_line "Память процесса" "${mem:-н/д}% / $(format_bytes "$((${rss:-0} * 1024))")"
        status_line "Время работы процесса" "${elapsed:-н/д}"
    fi

    if [[ "$TEST_MODE" != "1" ]]; then
        if [[ -e /sys/class/net/wdtt0 ]]; then
            local wdtt_addr
            wdtt_addr="$(
                ip -4 -o address show dev wdtt0 2>/dev/null |
                    awk '{print $4; exit}'
            )"
            status_line "Интерфейс wdtt0" "${wdtt_addr:-есть, IPv4 не найден}"
        else
            status_line "Интерфейс wdtt0" "не найден"
        fi
        status_line "IPv4 forwarding" "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || printf 'н/д')"
    fi

    local monitor_dtls="${CURRENT_DTLS_PORT:-$DTLS_PORT}"
    local monitor_wg="${CURRENT_WG_PORT:-$WG_PORT}"
    port_is_busy "$monitor_dtls" &&
        status_line "DTLS UDP-порт" "$monitor_dtls прослушивается" ||
        status_line "DTLS UDP-порт" "$monitor_dtls не прослушивается"
    port_is_busy "$monitor_wg" &&
        status_line "WireGuard UDP-порт" "$monitor_wg прослушивается" ||
        status_line "WireGuard UDP-порт" "$monitor_wg не прослушивается"

    status_line "Межсетевой экран" "$(friendly_firewall_manager "$manager")"
    if [[ "$manager" == "ufw" || "$manager" == "firewalld" ]]; then
        firewall_port_is_allowed "$manager" "$monitor_dtls" &&
            status_line "DTLS в межсетевом экране" "$monitor_dtls/udp разрешён" ||
            status_line "DTLS в межсетевом экране" "$monitor_dtls/udp не подтверждён"
    fi
}

monitor_database() {
    printf '\nБаза, клиенты и трафик\n'
    if [[ ! -e "$DATABASE_PATH" ]]; then
        status_line "База" "не найдена"
        return 0
    fi
    if [[ ! -f "$DATABASE_PATH" || -L "$DATABASE_PATH" ]]; then
        status_line "База" "небезопасный тип файла"
        return 1
    fi
    if [[ ! -r "$DATABASE_PATH" ]]; then
        status_line "База" "нет прав на чтение; запустите monitor через sudo"
        return 0
    fi

    local today week month now_epoch metrics
    today="$(date +%F)"
    week="$(date -d '6 days ago' +%F)"
    month="$(date -d '29 days ago' +%F)"
    now_epoch="$(date +%s)"
    metrics="$(
        jq -r \
            --arg today "$today" \
            --arg week "$week" \
            --arg month "$month" \
            --argjson now_epoch "$now_epoch" '
            def num($x): try (($x // 0) | tonumber) catch 0;
            def passwords: (.passwords // {} | to_entries | map(.value // {}));
            def sum_buckets($arr; $cutoff):
                reduce ($arr[]? | select((.date // "") >= $cutoff)) as $bucket
                    ({down:0, up:0};
                        .down += num($bucket.down_bytes) |
                        .up += num($bucket.up_bytes));
            def period($items; $cutoff):
                (sum_buckets((.admin_traffic // []); $cutoff)) as $admin |
                reduce $items[] as $entry
                    ($admin;
                        (sum_buckets(($entry.traffic // []); $cutoff)) as $client |
                        .down += $client.down |
                        .up += $client.up);
            def all_period($items):
                {
                    down: (num(.admin_down_bytes) + (reduce $items[] as $entry (0; . + num($entry.down_bytes)))),
                    up: (num(.admin_up_bytes) + (reduce $items[] as $entry (0; . + num($entry.up_bytes))))
                };
            passwords as $items |
            (reduce (($items[] | .device_id? // empty), ((.admin_profile.device_ids // [])[]?)) as $id
                ({};
                    if (($id | type) == "string" and ($id | length) > 0) then
                        .[$id] = true
                    else
                        .
                    end)) as $refs |
            (period($items; $today)) as $today_period |
            (period($items; $week)) as $week_period |
            (period($items; $month)) as $month_period |
            (all_period($items)) as $all_period |
            [
                (.dns // ""),
                (.default_ports // ""),
                (num(.max_passwords)),
                ($items | length),
                ($items | map(select(((.is_deactivated // false) | not) and (num(.expires_at) == 0 or num(.expires_at) > $now_epoch))) | length),
                ($items | map(select((.is_deactivated // false) == true)) | length),
                ($items | map(select(num(.expires_at) > 0 and num(.expires_at) <= $now_epoch)) | length),
                ($items | map(select(num(.expires_at) > 0 and num(.expires_at) <= $now_epoch and num(.purge_after) > $now_epoch)) | length),
                ($items | map(select(((.device_id // "") | length) > 0)) | length),
                ((.devices // {}) | length),
                ((.devices // {}) | to_entries | map(select(($refs[.key] // false) != true)) | length),
                $today_period.down, $today_period.up,
                $week_period.down, $week_period.up,
                $month_period.down, $month_period.up,
                $all_period.down, $all_period.up
            ] | @tsv
        ' "$DATABASE_PATH"
    )" || {
        status_line "База" "не удалось прочитать структуру"
        return 1
    }

    local dns ports max_passwords total active deactivated expired retained bound devices orphans
    local today_down today_up week_down week_up month_down month_up all_down all_up
    IFS=$'\t' read -r dns ports max_passwords total active deactivated expired retained \
        bound devices orphans today_down today_up week_down week_up month_down month_up \
        all_down all_up <<<"$metrics"

    status_line "DNS" "${dns:-не задан}"
    status_line "Порты по умолчанию" "${ports:-не заданы}"
    status_line "Лимит клиентов" "${max_passwords:-0}"
    status_line "Клиенты" "всего ${total:-0}, активных ${active:-0}, отключённых ${deactivated:-0}, истёкших ${expired:-0}, удерживаются до очистки ${retained:-0}"
    status_line "Привязки устройств" "клиентов с устройством ${bound:-0}, устройств ${devices:-0}, сиротских ${orphans:-0}"
    status_line "Трафик сегодня" "$(format_traffic_pair "${today_down:-0}" "${today_up:-0}")"
    status_line "Трафик 7 дней" "$(format_traffic_pair "${week_down:-0}" "${week_up:-0}")"
    status_line "Трафик 30 дней" "$(format_traffic_pair "${month_down:-0}" "${month_up:-0}")"
    status_line "Трафик всего" "$(format_traffic_pair "${all_down:-0}" "${all_up:-0}")"
}

perform_monitor() {
    local kind
    kind="$(detect_install_kind)"
    if [[ "$kind" == "owned" || "$kind" == "android" ]]; then
        load_owned_runtime_defaults
    fi

    printf 'Мониторинг WDTT Plus\n'
    status_line "Версия установщика" "$INSTALLER_VERSION"
    if [[ -x "$BINARY_PATH" && ! -L "$BINARY_PATH" ]]; then
        local live_server_version
        live_server_version="$("$BINARY_PATH" --version 2>/dev/null | head -n 1 || true)"
        status_line "Версия wdtt-server" "${live_server_version:-не определена}"
    fi

    monitor_runtime "$kind"
    monitor_database

    printf '\nСекреты не показаны: главный пароль, клиентские пароли, VK-хеши и WireGuard-ключи скрыты.\n'
}

perform_status() {
    local kind
    kind="$(detect_install_kind)"
    status_line "Версия этого установщика" "$INSTALLER_VERSION"
    if [[ -f "$OWNERSHIP_PATH" && ! -L "$OWNERSHIP_PATH" ]]; then
        load_installed_installer_version
        status_line "Установлено версией" "$INSTALLED_INSTALLER_VERSION"
        status_line "Заявленная версия wdtt-server" "$INSTALLED_SERVER_VERSION"
        if [[ "$INSTALLED_INSTALLER_VERSION" == "$INSTALLER_VERSION" ]]; then
            status_line "Версии установщика" "совпадают"
        else
            status_line "Версии установщика" "различаются"
        fi
    fi
    status_line "Состояние установки" "$(friendly_install_kind "$kind")"
    [[ -x "$BINARY_PATH" ]] &&
        status_line "Бинарник" "есть" || status_line "Бинарник" "отсутствует"
    if [[ -x "$BINARY_PATH" && ! -L "$BINARY_PATH" ]]; then
        local live_server_version
        live_server_version="$("$BINARY_PATH" --version 2>/dev/null | head -n 1 || true)"
        status_line "Фактическая версия wdtt-server" "${live_server_version:-не определена}"
    fi
    [[ -f "$DATABASE_PATH" ]] &&
        status_line "База" "есть" || status_line "База" "отсутствует"
    [[ -f "$UNIT_PATH" ]] &&
        status_line "Unit" "есть" || status_line "Unit" "отсутствует"
    [[ -f "$TRANSACTION_PATH" ]] &&
        status_line "Транзакция" "требует восстановления" ||
        status_line "Транзакция" "нет"
    if [[ "$TEST_MODE" != "1" && -f "$UNIT_PATH" ]]; then
        status_line "Служба" "$(friendly_service_state "$(systemctl is-active wdtt.service 2>/dev/null || true)")"
    elif [[ "$TEST_MODE" == "1" && "$kind" == "owned" ]]; then
        service_is_active &&
            status_line "Служба" "активна" || status_line "Служба" "остановлена"
    fi
}

DOCTOR_ERRORS=0
DOCTOR_WARNINGS=0

doctor_ok() {
    printf '✓ %s\n' "$1"
}

doctor_warn() {
    printf '⚠ %s\n' "$1"
    DOCTOR_WARNINGS=$((DOCTOR_WARNINGS + 1))
}

doctor_error() {
    printf '✗ %s\n' "$1"
    DOCTOR_ERRORS=$((DOCTOR_ERRORS + 1))
}

perform_doctor() {
    local kind manager
    kind="$(detect_install_kind)"
    manager="$(detect_firewall_manager)"

    case "$kind" in
        owned)
            doctor_ok "установка имеет полные метки ручного управления"
            ;;
        android)
            doctor_warn "состояние установки: совместимый Android-деплой; для полного ручного управления используйте adopt-android"
            ;;
        new)
            doctor_warn "состояние установки: чистый сервер, WDTT Plus ещё не установлен"
            ;;
        *)
            doctor_error "состояние установки: $(friendly_install_kind "$kind")"
            ;;
    esac

    if [[ -f "$TRANSACTION_PATH" ]]; then
        if (load_and_validate_journal) >/dev/null 2>&1; then
            doctor_error "есть незавершённая транзакция $(journal_value transaction_id) ($(journal_value phase))"
        else
            doctor_error "журнал незавершённой транзакции повреждён"
        fi
    else
        doctor_ok "незавершённых транзакций нет"
    fi

    if [[ "$kind" == "owned" ]]; then
        if [[ "$INSTALLED_INSTALLER_VERSION" == "$INSTALLER_VERSION" ]]; then
            doctor_ok "версия установщика совпадает: $INSTALLER_VERSION"
        else
            doctor_warn "установлено версией $INSTALLED_INSTALLER_VERSION, запущена $INSTALLER_VERSION"
        fi
        local doctor_server_version=""
        if [[ -x "$BINARY_PATH" && ! -L "$BINARY_PATH" ]]; then
            doctor_server_version="$("$BINARY_PATH" --version 2>/dev/null | head -n 1 || true)"
        fi
        if [[ "$doctor_server_version" == "$SUPPORTED_SERVER_VERSION" ]]; then
            doctor_ok "бинарник запускается и имеет совместимую версию $SUPPORTED_SERVER_VERSION"
        else
            doctor_error "бинарник отсутствует, не запускается или имеет несовместимую версию"
        fi

        if (validate_owned_managed_files) >/dev/null 2>&1; then
            doctor_ok "управляемые файлы имеют безопасные права и владельца"
        else
            doctor_error "управляемые файлы имеют небезопасный тип, права или владельца"
        fi

        if (validate_existing_database) >/dev/null 2>&1; then
            doctor_ok "/etc/wdtt и passwords.json прошли безопасную проверку"
        else
            doctor_error "/etc/wdtt или passwords.json не прошли безопасную проверку"
        fi

        if [[ "$TEST_MODE" == "1" ]]; then
            service_is_active &&
                doctor_ok "служба активна" || doctor_error "служба не активна"
        else
            systemctl is-active --quiet wdtt.service &&
                doctor_ok "wdtt.service активна" || doctor_error "wdtt.service не активна"
            [[ -S /run/wdtt/admin.sock ]] &&
                doctor_ok "admin-сокет доступен" || doctor_error "admin-сокет отсутствует"
            [[ -e /sys/class/net/wdtt0 ]] &&
                doctor_ok "интерфейс wdtt0 существует" || doctor_error "интерфейс wdtt0 отсутствует"
            ip -4 address show dev wdtt0 2>/dev/null |
                grep -Fq "10.66.66.1/24" &&
                doctor_ok "адрес wdtt0 корректен" || doctor_error "адрес wdtt0 не равен 10.66.66.1/24"
            port_is_busy "${CURRENT_DTLS_PORT:-$DEFAULT_DTLS_PORT}" &&
                doctor_ok "DTLS UDP-порт прослушивается" || doctor_error "DTLS UDP-порт не прослушивается"
            port_is_busy "${CURRENT_WG_PORT:-$DEFAULT_WG_PORT}" &&
                doctor_ok "WireGuard UDP-порт прослушивается" || doctor_error "WireGuard UDP-порт не прослушивается"
            [[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || true)" == "1" ]] &&
                doctor_ok "IPv4 forwarding включён" || doctor_error "IPv4 forwarding выключен"
            runtime_network_rules_are_healthy &&
                doctor_ok "NAT/FORWARD-правила WDTT подтверждены" ||
                doctor_error "NAT/FORWARD-правила WDTT отсутствуют или некорректны"
        fi
    fi

    case "$manager" in
        multiple)
            doctor_warn "одновременно активны UFW и firewalld"
            ;;
        none)
            doctor_warn "активный менеджер межсетевого экрана не обнаружен"
            ;;
        ufw|firewalld)
            doctor_ok "обнаружен межсетевой экран: $(friendly_firewall_manager "$manager")"
            if firewall_port_is_allowed "$manager"; then
                doctor_ok "межсетевой экран разрешает ${CURRENT_DTLS_PORT:-$DTLS_PORT}/udp"
            else
                doctor_warn "межсетевой экран может не разрешать ${CURRENT_DTLS_PORT:-$DTLS_PORT}/udp"
            fi
            ;;
        *)
            doctor_ok "обнаружен межсетевой экран: $(friendly_firewall_manager "$manager")"
            doctor_warn "правило DTLS нужно проверить в существующей конфигурации вручную"
            ;;
    esac

    printf '\nИтог диагностики: ошибок %d, предупреждений %d.\n' \
        "$DOCTOR_ERRORS" "$DOCTOR_WARNINGS"
    (( DOCTOR_ERRORS == 0 ))
}

wizard_default_initial_config_path() {
    local candidate="/root/wdtt-initial.json"
    [[ "$TEST_MODE" == "1" ]] && candidate="$TEST_ROOT/root/wdtt-initial.json"
    if [[ ! -e "$candidate" ]]; then
        printf '%s' "$candidate"
        return
    fi
    printf '%s' "${candidate%.json}-$(date +%Y%m%d-%H%M%S).json"
}

perform_wizard() {
    [[ "$ASSUME_YES" == "0" && -t 0 ]] ||
        die "Мастер установки требует интерактивный терминал. Для автоматизации используйте init-config/check/install."

    local kind
    kind="$(detect_install_kind)"
    if [[ "$kind" == "interrupted" ]]; then
        if ! (load_and_validate_journal) >/dev/null 2>&1; then
            die "Найдена незавершённая транзакция, но её журнал повреждён. Запустите doctor."
        fi
    fi
    if [[ "$kind" == "owned" || "$kind" == "android" ]]; then
        load_owned_runtime_defaults
    fi

    cat <<EOF
Мастер установки WDTT Plus

Он выполнит безопасный сценарий:
  1) проверит совместимость скрипта с Android-деплоем;
  2) на чистом сервере создаст защищённый начальный конфиг;
  3) проверит VPS, бинарник, порты, межсетевой экран и существующую установку;
  4) покажет план;
  5) изменит сервер только после подтверждения словом УСТАНОВИТЬ.

Скрипт не скачивает файлы из интернета, не меняет SSH и не трогает чужие службы.
EOF

    if [[ "$kind" == "android" ]]; then
        print_compatibility_brief
        cat <<EOF

На сервере уже обнаружен совместимый Android-деплой.
Мастер чистой ручной установки здесь не запускается: он не должен неявно
захватывать установку, созданную приложением.

Что можно сделать:
  1) оставить управление из WDTT Plus для Android и обновлять сервер из вкладки «Деплой»;
  2) если хотите дальше управлять сервером этим скриптом — вернитесь в меню и
     выберите «Принять совместимый Android-деплой под ручное управление».

Сейчас изменений на сервере не выполнено.
EOF
        return 0
    fi

    print_compatibility summary

    [[ -n "$SOURCE_BINARY" ]] ||
        prompt_required_path SOURCE_BINARY "Путь к локальному wdtt-server"

    if [[ "$kind" == "new" && -z "$INITIAL_CONFIG" ]]; then
        local default_config answer
        default_config="$(wizard_default_initial_config_path)"
        read -r -p "Создать начальный конфиг с главным паролем [$default_config]: " answer
        OUTPUT_CONFIG="${answer:-$default_config}"
        perform_init_config
        INITIAL_CONFIG="$OUTPUT_CONFIG"
        mark_option config
    fi

    collect_install_questions "$kind"
    perform_install "$kind"
}

script_self_path() {
    local self="${BASH_SOURCE[0]}"
    if [[ "$self" == /* ]]; then
        printf '%s' "$self"
    else
        printf '%s/%s' "$PWD" "$self"
    fi
}

menu_clear() {
    [[ -t 1 ]] && printf '\033[H\033[2J'
}

menu_pause() {
    local _
    printf '\nНажмите любую клавишу, чтобы вернуться в меню...'
    IFS= read -r -s -n 1 _ || true
    printf '\n'
}

menu_key() {
    MENU_KEY=""
    if ! IFS= read -r -s -n 1 MENU_KEY; then
        MENU_KEY=""
        printf '\nВвод закрыт, выхожу из меню.\n'
        return 1
    fi
}

menu_key_is_back() {
    case "${1,,}" in
        н|y|h|b|в|n) return 0 ;;
        *) return 1 ;;
    esac
}

menu_title() {
    local title="$1"
    local kind
    kind="$(detect_install_kind)"
    menu_clear
    cat <<EOF
WDTT Plus · ручной установщик $INSTALLER_VERSION
$title

Состояние сервера: $(friendly_install_kind "$kind")
Бинарник для установки: ${SOURCE_BINARY:-не выбран}
Начальный конфиг: ${INITIAL_CONFIG:-не выбран}
EOF
}

menu_script_args() {
    MENU_SCRIPT_ARGS=()
MENU_LAST_STATUS=0
ADMIN_RESPONSE=""
    [[ -n "$SOURCE_BINARY" ]] && MENU_SCRIPT_ARGS+=(--binary "$SOURCE_BINARY")
    [[ -n "$INITIAL_CONFIG" ]] && MENU_SCRIPT_ARGS+=(--config "$INITIAL_CONFIG")
    [[ -n "$EXPECTED_SHA256" ]] && MENU_SCRIPT_ARGS+=(--sha256 "$EXPECTED_SHA256")
    option_is_set dtls_port && MENU_SCRIPT_ARGS+=(--dtls-port "$DTLS_PORT")
    option_is_set wg_port && MENU_SCRIPT_ARGS+=(--wg-port "$WG_PORT")
    option_is_set client_port && MENU_SCRIPT_ARGS+=(--client-port "$CLIENT_PORT")
    option_is_set dns && MENU_SCRIPT_ARGS+=(--dns "$DNS_VALUE")
    option_is_set max_passwords && MENU_SCRIPT_ARGS+=(--max-passwords "$MAX_PASSWORDS")
    option_is_set max_workers && MENU_SCRIPT_ARGS+=(--max-workers "$MAX_WORKERS")
    option_is_set max_handshakes && MENU_SCRIPT_ARGS+=(--max-handshakes "$MAX_HANDSHAKES")
    option_is_set handshake_rate && MENU_SCRIPT_ARGS+=(--handshake-rate "$HANDSHAKE_RATE")
    option_is_set max_client_mbps && MENU_SCRIPT_ARGS+=(--max-client-mbps "$MAX_CLIENT_MBPS")
    option_is_set wg_backend && MENU_SCRIPT_ARGS+=(--wg-backend "$WG_BACKEND")
    [[ "$MIGRATE_PORTS" == "1" ]] && MENU_SCRIPT_ARGS+=(--migrate-ports)
    option_is_set firewall && MENU_SCRIPT_ARGS+=(--firewall "$FIREWALL_MODE")
    [[ "$ADVANCED_REQUESTED" == "1" ]] && MENU_SCRIPT_ARGS+=(--advanced)
    return 0
}

menu_run_script() {
    local command="$1"
    shift || true
    local self
    self="$(script_self_path)"
    menu_clear
    set +e
    bash "$self" "$command" "$@"
    MENU_LAST_STATUS=$?
    set -e
    if (( MENU_LAST_STATUS != 0 )); then
        printf '\n✗ Действие завершилось с ошибкой, код %d.\n' "$MENU_LAST_STATUS"
    fi
    menu_pause
    return 0
}

menu_run_with_common_args() {
    local command="$1"
    menu_script_args
    menu_run_script "$command" "${MENU_SCRIPT_ARGS[@]}"
}

menu_create_initial_config() {
    local default_config output_path
    default_config="${INITIAL_CONFIG:-$(wizard_default_initial_config_path)}"
    read -r -p "Куда создать начальный passwords.json [$default_config]: " output_path
    output_path="${output_path:-$default_config}"
    menu_run_script init-config --output "$output_path"
    if (( MENU_LAST_STATUS == 0 )); then
        INITIAL_CONFIG="$output_path"
        mark_option config
    fi
}

menu_prompt_path_value() {
    local variable="$1"
    local label="$2"
    local current="$3"
    local answer
    if [[ -n "$current" ]]; then
        read -r -p "$label [$current]: " answer
        answer="${answer:-$current}"
    else
        read -r -p "$label: " answer
    fi
    [[ -n "$answer" ]] || {
        warn "Путь не изменён."
        menu_pause
        return
    }
    printf -v "$variable" '%s' "$answer"
}

menu_paths() {
    while true; do
        menu_title "Пути и параметры"
        cat <<EOF

1 · Указать путь к wdtt-server
2 · Указать путь к начальному passwords.json
3 · Очистить путь к начальному конфигу
4 · Настроить основные порты и DNS
5 · Настроить расширенные лимиты
6 · Настроить межсетевой экран

Н · Назад
0 · Выход
EOF
        menu_key
        case "${MENU_KEY,,}" in
            1)
                menu_prompt_path_value SOURCE_BINARY "Путь к локальному wdtt-server" "$SOURCE_BINARY"
                ;;
            2)
                menu_prompt_path_value INITIAL_CONFIG "Путь к начальному passwords.json" "$INITIAL_CONFIG"
                mark_option config
                ;;
            3)
                INITIAL_CONFIG=""
                unset 'OPTION_SET[config]'
                printf '\n✓ Путь к начальному конфигу очищен.\n'
                menu_pause
                ;;
            4)
                printf '\n'
                prompt_uint_value DTLS_PORT "Публичный DTLS-порт" "$DTLS_PORT" 1 65535
                mark_option dtls_port
                prompt_uint_value WG_PORT "Внутренний WireGuard-порт" "$WG_PORT" 1 65535
                mark_option wg_port
                prompt_uint_value CLIENT_PORT "Локальный порт Android" "$CLIENT_PORT" 1 65535
                mark_option client_port
                prompt_dns_value
                mark_option dns
                prompt_uint_value MAX_PASSWORDS "Максимум клиентских паролей" "$MAX_PASSWORDS" 1 500
                mark_option max_passwords
                printf '\n✓ Основные параметры сохранены для текущего запуска меню.\n'
                menu_pause
                ;;
            5)
                printf '\n'
                ADVANCED_REQUESTED=1
                prompt_uint_value MAX_WORKERS "Рабочих потоков на один доступ (0 = без лимита)" "$MAX_WORKERS" 0 128
                mark_option max_workers
                prompt_uint_value MAX_HANDSHAKES "Одновременных рукопожатий" "$MAX_HANDSHAKES" 1 256
                mark_option max_handshakes
                prompt_number_value HANDSHAKE_RATE "Рукопожатий в секунду" "$HANDSHAKE_RATE" 1 1000
                mark_option handshake_rate
                prompt_number_value MAX_CLIENT_MBPS "Мбит/с на доступ (0 = без лимита)" "$MAX_CLIENT_MBPS" 0 1000
                mark_option max_client_mbps
                prompt_backend_value
                mark_option wg_backend
                printf '\n✓ Расширенные параметры сохранены для текущего запуска меню.\n'
                menu_pause
                ;;
            6)
                printf '\n'
                prompt_firewall_value
                mark_option firewall
                printf '\n✓ Поведение межсетевого экрана сохранено для текущего запуска меню.\n'
                menu_pause
                ;;
            0)
                exit 0
                ;;
            *)
                if menu_key_is_back "$MENU_KEY"; then
                    return
                fi
                ;;
        esac
    done
}

menu_installation() {
    while true; do
        menu_title "Установка и обновление"
        cat <<EOF

1 · Мастер установки или обновления
2 · Создать начальный passwords.json
3 · Установить или обновить ручную установку
4 · Принять совместимый Android-деплой под ручное управление
5 · Передать ручную установку обратно Android-деплою

Н · Назад
0 · Выход

Опасные действия не выполняются сразу: перед изменениями будет план и
точное подтверждение словом УСТАНОВИТЬ или ПЕРЕДАТЬ.
EOF
        menu_key
        case "${MENU_KEY,,}" in
            1) menu_run_with_common_args wizard ;;
            2) menu_create_initial_config ;;
            3) menu_run_with_common_args install ;;
            4)
                menu_script_args
                local adopt_args=()
                local item
                for item in "${MENU_SCRIPT_ARGS[@]}"; do
                    [[ "$item" == "--config" || "$item" == "$INITIAL_CONFIG" ]] && continue
                    adopt_args+=("$item")
                done
                menu_run_script adopt-android "${adopt_args[@]}"
                ;;
            5) menu_run_script handoff-android ;;
            0) exit 0 ;;
            *)
                if menu_key_is_back "$MENU_KEY"; then
                    return
                fi
                ;;
        esac
    done
}

menu_checks() {
    while true; do
        menu_title "Проверки и состояние"
        cat <<EOF

1 · Краткий статус
2 · Подробная диагностика
3 · Проверить VPS и план без изменений
4 · Проверить совместимость с Android-деплоем

Н · Назад
0 · Выход
EOF
        menu_key
        case "${MENU_KEY,,}" in
            1) menu_run_script status ;;
            2) menu_run_script doctor ;;
            3) menu_run_with_common_args check ;;
            4) menu_run_script compatibility ;;
            0) exit 0 ;;
            *)
                if menu_key_is_back "$MENU_KEY"; then
                    return
                fi
                ;;
        esac
    done
}

admin_request() {
    local main_password="$1"
    shift
    local output status
    set +e
    output="$({
        printf '%s\n' "$main_password"
        printf '%s\n' "$@"
    } | jq -Rsc '
        split("\n")
        | if .[-1] == "" then .[:-1] else . end
        | {main_password: .[0], args: .[1:]}
    ' | "$BINARY_PATH" admin --config-dir "$CONFIG_DIR" --request-stdin 2>/dev/null)"
    status=$?
    set -e
    ADMIN_RESPONSE="$output"
    [[ -n "$output" ]] && jq -e 'type == "object"' <<<"$output" >/dev/null 2>&1 || {
        warn "Сервер не вернул корректный ответ управления."
        return 1
    }
    if (( status != 0 )) || ! jq -e '.ok == true' <<<"$output" >/dev/null 2>&1; then
        warn "$(jq -r '.message // "операция не выполнена"' <<<"$output")"
        return 1
    fi
    return 0
}

menu_clients_ready() {
    local kind
    kind="$(detect_install_kind)"
    [[ "$kind" == "owned" || "$kind" == "android" ]] || {
        warn "Управление клиентами доступно только после установки WDTT Plus."
        return 1
    }
    [[ "$TEST_MODE" == "1" || "$EUID" == "0" ]] || {
        warn "Управление клиентами требует root для доступа к закрытому admin-сокету."
        return 1
    }
    [[ -x "$BINARY_PATH" && ! -L "$BINARY_PATH" ]] || {
        warn "Не найден безопасный исполняемый wdtt-server."
        return 1
    }
    service_is_active || {
        warn "Служба wdtt.service не активна. Сначала выполните диагностику или обновление."
        return 1
    }
    [[ "$TEST_MODE" == "1" || -S /run/wdtt/admin.sock ]] || {
        warn "Admin-сокет /run/wdtt/admin.sock недоступен."
        return 1
    }
}

menu_read_admin_password() {
    local value
    read -r -s -p "Главный пароль администратора: " value
    printf '\n'
    [[ -n "$value" ]] || {
        warn "Главный пароль не введён."
        return 1
    }
    ADMIN_MAIN_PASSWORD="$value"
}

menu_client_list() {
    local main_password="$1"
    admin_request "$main_password" list || return 1
    jq -r '
        if (.passwords | length) == 0 then
            "Клиентов пока нет."
        else
            .passwords
            | to_entries[]
            | (.value.label // "" | if . == "" then "без названия" else . end) as $label
            | (.value.status // "unknown") as $raw_status
            | ($raw_status | if . == "active" then "активен"
                elif . == "deactivated" then "приостановлен"
                elif . == "expired" then "истёк"
                elif . == "expired_retained" then "истёк, сохранён до очистки"
                else "неизвестно" end) as $status
            | (.value.expires_at // 0) as $expires
            | "\(.key + 1). \($label) · статус: \($status)" +
              (if $expires > 0 then " · срок unix: \($expires)" else " · бессрочно" end)
        end
    ' <<<"$ADMIN_RESPONSE"
}

menu_client_print_connection() {
    jq -r '
        .password as $client
        | (.server.effective_public_ip // .server.public_ip // "") as $host
        | ($client.ports // .server.default_ports // "56000,56001,9000" | split(",")) as $ports
        | "\nКлиент готов. Сохраните данные сейчас в защищённом месте:\n" +
          "Название: \($client.label // "")\n" +
          "Сервер: \($host)\n" +
          "DTLS-порт: \($ports[0])\n" +
          "WireGuard-порт: \($ports[1])\n" +
          "Локальный порт: \($ports[2])\n" +
          "Пароль клиента: \($client.password)\n" +
          "VK-хеш: \($client.vk_hash // "")\n" +
          "Ссылка WDTT:\nwdtt://connect?v=1&host=\($host|@uri)&dtls=\($ports[0]|@uri)&wg=\($ports[1]|@uri)&local=\($ports[2]|@uri)&password=\($client.password|@uri)&hashes=\(($client.vk_hash // "")|@uri)" +
          (if ($client.label // "") != "" then "&name=\($client.label|@uri)" else "" end)
    ' <<<"$ADMIN_RESPONSE"
}

menu_client_create() {
    local main_password="$1"
    local label days vk_hash ports password_choice client_password first second
    read -r -p "Название клиента [Тестовый клиент]: " label
    label="${label:-Тестовый клиент}"
    while true; do
        read -r -p "Срок действия в днях, 0 = бессрочно [30]: " days
        days="${days:-30}"
        [[ "$days" =~ ^[0-9]+$ ]] && (( days <= 365 )) && break
        warn "Введите число от 0 до 365."
    done
    read -r -p "VK-хеш или ссылка VK-звонка (можно оставить пустым): " vk_hash
    read -r -p "Порты DTLS,WG,локальный [как на сервере]: " ports
    cat <<EOF

Пароль клиента:
1 · Сгенерировать безопасный уникальный пароль на сервере
2 · Ввести пароль вручную
EOF
    while true; do
        read -r -p "Выбор [1]: " password_choice
        password_choice="${password_choice:-1}"
        case "$password_choice" in
            1) client_password=""; break ;;
            2)
                read -r -s -p "Пароль клиента: " first
                printf '\n'
                read -r -s -p "Повторите пароль клиента: " second
                printf '\n'
                [[ "$first" == "$second" ]] || { warn "Пароли не совпадают."; continue; }
                client_password="$first"
                break
                ;;
            *) warn "Введите 1 или 2." ;;
        esac
    done

    local args=(create --days "$days" --label "$label")
    [[ -n "$vk_hash" ]] && args+=(--vk-hash "$vk_hash")
    [[ -n "$ports" ]] && args+=(--ports "$ports")
    [[ -n "$client_password" ]] && args+=(--client-password "$client_password")
    admin_request "$main_password" "${args[@]}" || return 1
    menu_client_print_connection
}

menu_client_details() {
    local main_password="$1" password
    read -r -s -p "Пароль клиента: " password
    printf '\n'
    [[ -n "$password" ]] || { warn "Пароль клиента не введён."; return 1; }
    admin_request "$main_password" details --password "$password" || return 1
    menu_client_print_connection
}

menu_client_simple_action() {
    local main_password="$1" command="$2" description="$3" critical="${4:-0}" success_message="${5:-}"
    local password confirmation
    read -r -s -p "Пароль клиента: " password
    printf '\n'
    [[ -n "$password" ]] || { warn "Пароль клиента не введён."; return 1; }
    if [[ "$critical" == "1" ]]; then
        read -r -p "Для удаления без возможности восстановления введите УДАЛИТЬ: " confirmation
        [[ "$confirmation" == "УДАЛИТЬ" ]] || { warn "Удаление отменено."; return 1; }
    elif ! prompt_yes_no "$description" "no"; then
        warn "Действие отменено."
        return 1
    fi
    admin_request "$main_password" "$command" --password "$password" || return 1
    [[ -n "$success_message" ]] || success_message="$(jq -r '.message // "Действие выполнено"' <<<"$ADMIN_RESPONSE")"
    printf '✓ %s\n' "$success_message"
}

menu_clients() {
    menu_clients_ready || { menu_pause; return; }
    ADMIN_MAIN_PASSWORD=""
    menu_read_admin_password || { menu_pause; return; }
    if ! admin_request "$ADMIN_MAIN_PASSWORD" list; then
        ADMIN_MAIN_PASSWORD=""
        menu_pause
        return
    fi
    while true; do
        menu_title "Управление клиентами"
        cat <<EOF

1 · Показать список клиентов без паролей
2 · Создать клиента
3 · Показать данные подключения клиента
4 · Активировать клиента
5 · Приостановить клиента
6 · Отвязать устройство клиента
7 · Удалить клиента

Н · Назад
0 · Выход
EOF
        menu_key
        case "${MENU_KEY,,}" in
            1) menu_clear; menu_client_list "$ADMIN_MAIN_PASSWORD"; menu_pause ;;
            2) menu_clear; menu_client_create "$ADMIN_MAIN_PASSWORD"; menu_pause ;;
            3) menu_clear; menu_client_details "$ADMIN_MAIN_PASSWORD"; menu_pause ;;
            4) menu_clear; menu_client_simple_action "$ADMIN_MAIN_PASSWORD" activate "Активировать этого клиента" 0 "Клиент активирован"; menu_pause ;;
            5) menu_clear; menu_client_simple_action "$ADMIN_MAIN_PASSWORD" deactivate "Приостановить этого клиента" 0 "Клиент приостановлен"; menu_pause ;;
            6) menu_clear; menu_client_simple_action "$ADMIN_MAIN_PASSWORD" unbind "Отвязать текущее устройство клиента" 0 "Устройство клиента отвязано"; menu_pause ;;
            7) menu_clear; menu_client_simple_action "$ADMIN_MAIN_PASSWORD" delete "" 1 "Клиент удалён"; menu_pause ;;
            0) ADMIN_MAIN_PASSWORD=""; exit 0 ;;
            *)
                if menu_key_is_back "$MENU_KEY"; then
                    ADMIN_MAIN_PASSWORD=""
                    return
                fi
                ;;
        esac
    done
}

perform_menu() {
    [[ -t 0 && -t 1 ]] ||
        die "Главное меню требует интерактивный терминал. Для автоматизации используйте команды --help."
    while true; do
        menu_title "Главное меню"
        cat <<EOF

1 · Установка и обновление
2 · Проверки и состояние
3 · Пути и параметры
4 · Мониторинг сервера
5 · Управление клиентами
6 · Справка
7 · Версия установщика

0 · Выход

Выберите действие одной клавишей, Enter не нужен.
EOF
        menu_key
        case "${MENU_KEY,,}" in
            1) menu_installation ;;
            2) menu_checks ;;
            3) menu_paths ;;
            4) menu_run_script monitor ;;
            5) menu_clients ;;
            6) menu_run_script --help ;;
            7) menu_run_script --version ;;
            0|q|й) exit 0 ;;
        esac
    done
}

main() {
    parse_args "$@"
    validate_option_scope
    validate_host

    case "$COMMAND" in
        menu)
            perform_menu
            ;;
        wizard|start)
            perform_wizard
            ;;
        init-config)
            perform_init_config
            ;;
        status)
            perform_status
            ;;
        monitor)
            perform_monitor
            ;;
        doctor)
            load_owned_runtime_defaults
            perform_doctor
            ;;
        handoff-android)
            local_kind="$(detect_install_kind)"
            perform_handoff_android "$local_kind"
            ;;
        check|install|adopt-android)
            local_kind="$(detect_install_kind)"
            question_kind="$local_kind"
            if [[ "$local_kind" == "interrupted" ]]; then
                if ! (load_and_validate_journal) >/dev/null 2>&1; then
                    die "Журнал незавершённой транзакции повреждён; запустите doctor."
                fi
                journal_kind="$(journal_value kind)"
                journal_phase="$(journal_value phase)"
                if [[ "$COMMAND" == "install" && "$journal_kind" == "handoff" &&
                    "$journal_phase" == "committed" ]]; then
                    perform_handoff_android "$local_kind"
                    return 0
                fi
                if [[ "$journal_phase" == "committed" ]]; then
                    if [[ "$journal_kind" == "handoff" ]]; then
                        RECOVERY_RESULT_KIND="android"
                    else
                        RECOVERY_RESULT_KIND="owned"
                    fi
                elif [[ "$journal_kind" == "adopt" ]]; then
                    RECOVERY_RESULT_KIND="android"
                elif [[ "$journal_kind" == "handoff" ]]; then
                    RECOVERY_RESULT_KIND="owned"
                else
                    RECOVERY_RESULT_KIND="$journal_kind"
                fi
                question_kind="$RECOVERY_RESULT_KIND"
            fi
            if [[ "$question_kind" == "owned" || "$question_kind" == "android" ]]; then
                load_owned_runtime_defaults
            fi
            if [[ "$COMMAND" == "install" || "$COMMAND" == "adopt-android" ]]; then
                if [[ "$COMMAND" == "install" && "$question_kind" == "android" ]]; then
                    die "Сервер установлен Android-деплоем. Для безопасной передачи управления используйте adopt-android; обычный install не захватывает такие установки."
                fi
                if [[ "$COMMAND" == "adopt-android" && "$question_kind" != "android" ]]; then
                    die "adopt-android требует совместимую Android-установку; текущее состояние: $(friendly_install_kind "$question_kind")."
                fi
                collect_install_questions "$question_kind"
                perform_install "$local_kind"
            else
                perform_check "$local_kind"
            fi
            ;;
    esac
}

main "$@"
