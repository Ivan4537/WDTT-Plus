#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

readonly TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly INSTALLER="$(cd "$TEST_DIR/.." && pwd)/install.sh"
readonly REPOSITORY_ROOT="$(cd "$TEST_DIR/../.." && pwd)"

declare -a SANDBOXES=()
TESTS_RUN=0
NEW_SANDBOX=""

cleanup() {
    local sandbox
    for sandbox in "${SANDBOXES[@]}"; do
        [[ "$sandbox" == /tmp/* && "$sandbox" != "/tmp/" ]] || continue
        rm -rf -- "$sandbox"
    done
}
trap cleanup EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

pass() {
    TESTS_RUN=$((TESTS_RUN + 1))
    printf 'ok %d - %s\n' "$TESTS_RUN" "$1"
}

new_sandbox() {
    NEW_SANDBOX="$(mktemp -d /tmp/wdtt-installer-test.XXXXXX)"
    SANDBOXES+=("$NEW_SANDBOX")
}

make_fake_binary() {
    local target="$1"
    local build_id="$2"
    local reported_version="${3:-17}"
    cat >"$target" <<EOF
#!/usr/bin/env bash
if [[ "\${1:-}" == "--version" ]]; then
    printf '%s\n' "$reported_version"
    exit 0
fi
if [[ "\${1:-}" == "--build-id" ]]; then
    printf '%s\n' "$build_id"
    exit 0
fi
exit 0
EOF
    chmod 0755 "$target"
}

make_config() {
    local target="$1"
    local password="$2"
    cat >"$target" <<EOF
{
  "main_password": "$password",
  "admin_id": "",
  "bot_token": "",
  "dns": "1.1.1.1",
  "max_passwords": 50,
  "default_ports": "56000,56001,9000",
  "passwords": {},
  "devices": {}
}
EOF
    chmod 0600 "$target"
}

make_config_with_settings() {
    local target="$1"
    local password="$2"
    local dns="$3"
    local max_passwords="$4"
    local ports="$5"
    cat >"$target" <<EOF
{
  "main_password": "$password",
  "admin_id": "",
  "bot_token": "",
  "dns": "$dns",
  "max_passwords": $max_passwords,
  "default_ports": "$ports",
  "passwords": {},
  "devices": {}
}
EOF
    chmod 0600 "$target"
}

make_android_deploy_install() {
    local root="$1"
    local binary="$2"
    local password="$3"
    mkdir -p "$root/usr/local/bin" "$root/etc/systemd/system" "$root/etc/wdtt"
    chmod 0755 "$root/etc/wdtt"
    install -m 0755 "$binary" "$root/usr/local/bin/wdtt-server"
    make_config "$root/etc/wdtt/passwords.json" "$password"
    printf '%s\n%s\n%s\n%s\n' \
        'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
        'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
        'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
        'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
        >"$root/etc/wdtt/wg-keys.dat"
    chmod 0600 "$root/etc/wdtt/wg-keys.dat"
    printf 'legacy server log\n' >"$root/etc/wdtt/server.log"
    chmod 0644 "$root/etc/wdtt/server.log"
    cat >"$root/etc/systemd/system/wdtt.service" <<'EOF'
# Managed by WDTT Plus Android deploy
# WDTT deploy compatibility: 1
[Service]
ExecStart=/usr/local/bin/wdtt-server -listen 0.0.0.0:56000 -wg-port 56001 -config-dir /etc/wdtt -max-workers-per-access 0 -max-handshakes 32 -handshake-rate 24 -max-client-mbps 0 -wg-backend auto
EOF
    chmod 0644 "$root/etc/systemd/system/wdtt.service"
}

run_installer() {
    local root="$1"
    shift
    WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        "$INSTALLER" "$@"
}

expect_failure() {
    local output_file="$1"
    shift
    if "$@" >"$output_file" 2>&1; then
        fail "команда неожиданно завершилась успешно"
    fi
}

test_help_and_syntax() {
    local output
    output="$(mktemp /tmp/wdtt-installer-menu.XXXXXX)"
    bash -n "$INSTALLER"
    "$INSTALLER" --help >"$output"
    [[ "$("$INSTALLER" --version)" == "0.19.1" ]] ||
        fail "команда --version вернула неожиданный результат"
    ! grep -Fq "install.sh start" "$output" ||
        fail "справка показывает alias start как отдельный основной сценарий"
    grep -Fq "start       То же самое, что wizard. Оставлен для старых инструкций." "$output" ||
        fail "справка не поясняет совместимый alias start"
    grep -Fq "install.sh [menu]" "$output" ||
        fail "справка не показывает меню как действие по умолчанию"
    grep -Fq "install.sh handoff-android [--dry-run] [--yes]" "$output" ||
        fail "справка не показывает безопасную передачу Android-деплою"
    expect_failure "$output" "$INSTALLER"
    grep -Fq "Главное меню требует интерактивный терминал" "$output" ||
        fail "запуск меню без терминала не дал понятную ошибку"
    if grep -Fq -- '--arg main_password' "$INSTALLER"; then
        fail "главный пароль передаётся дочернему процессу через argv"
    fi
    grep -Fq -- '--request-stdin' "$INSTALLER" ||
        fail "управление клиентами не использует закрытый admin-запрос через stdin"
    grep -Fq "5 · Управление клиентами" "$INSTALLER" ||
        fail "главное меню не показывает управление клиентами"
    printf '%s\n' 'UNCONN 0 0 *:56000 *:*' |
        awk '{print $4}' |
        grep -Eq '(^|:)56000$' ||
        fail "формат ss не позволяет проверить локальный UDP-порт"
    pass "синтаксис и справка"
}

test_menu_stays_open_after_failed_doctor() {
    command -v script >/dev/null ||
        fail "утилита script нужна для проверки интерактивного меню"
    local sandbox root output clean count status
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    output="$sandbox/menu.out"
    clean="$sandbox/menu.clean"
    mkdir -p "$root/etc/wdtt"
    printf 'foreign\n' >"$root/etc/wdtt/foreign-marker"

    set +e
    printf '22x0' |
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        script -qfec "$INSTALLER" "$output" >/dev/null 2>&1
    status=$?
    set -e
    (( status == 0 )) ||
        fail "меню завершилось с ошибкой после неуспешного doctor"

    tr -d '\r' <"$output" >"$clean"
    grep -Fq "✗ состояние установки: неизвестная или вручную изменённая установка" "$clean" ||
        fail "doctor не показал ошибку неизвестной установки"
    grep -Fq "✗ Действие завершилось с ошибкой, код 1." "$clean" ||
        fail "меню не показало код ошибки вложенной диагностики"
    ! grep -Fq "✓ Действие завершено." "$clean" ||
        fail "меню добавило лишний успешный хвост к экрану просмотра"
    count="$(grep -F "Проверки и состояние" "$clean" | wc -l | tr -d ' ')"
    (( count >= 2 )) ||
        fail "после ошибки doctor меню не вернулось в раздел проверок"
    grep -Fq "Н · Назад" "$clean" ||
        fail "меню не показывает русскую клавишу возврата"
    ! grep -Fq "B · Назад" "$clean" ||
        fail "меню всё ещё показывает английскую клавишу возврата"
    pass "меню остаётся открытым после диагностик с ошибками"
}

test_menu_firewall_settings_are_russian() {
    command -v script >/dev/null ||
        fail "утилита script нужна для проверки интерактивного меню"
    local sandbox root output clean
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    output="$sandbox/menu-firewall.out"
    clean="$sandbox/menu-firewall.clean"
    mkdir -p "$root"

    set +e
    set +o pipefail
    printf '36\n' |
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        timeout 5s script -qfec "$INSTALLER" "$output" >/dev/null 2>&1
    local status=$?
    set -o pipefail
    set -e
    (( status == 0 || status == 124 )) ||
        fail "проверка меню межсетевого экрана завершилась неожиданным кодом $status"

    tr -d '\r' <"$output" >"$clean"
    grep -Fq "6 · Настроить межсетевой экран" "$clean" ||
        fail "пункт меню firewall не русифицирован"
    grep -Fq "Поведение межсетевого экрана:" "$clean" ||
        fail "экран настройки firewall не русифицирован"
    ! grep -Fq "ask" "$clean" ||
        fail "интерактивное меню межсетевого экрана показывает английский alias ask"
    ! grep -Fq "none" "$clean" ||
        fail "интерактивное меню межсетевого экрана показывает английский alias none"
    ! grep -Fq "open" "$clean" ||
        fail "интерактивное меню межсетевого экрана показывает английский alias open"
    grep -Fq "✓ Поведение межсетевого экрана сохранено для текущего запуска меню." "$clean" ||
        fail "подтверждение настройки firewall не русифицировано"
    ! grep -Fq "Firewall:" "$clean" ||
        fail "в меню остался английский prompt Firewall"
    pass "настройка межсетевого экрана в меню русифицирована"
}

test_menu_russian_back_key_works() {
    command -v script >/dev/null ||
        fail "утилита script нужна для проверки интерактивного меню"
    local sandbox root output clean status count
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    output="$sandbox/menu-back.out"
    clean="$sandbox/menu-back.clean"
    mkdir -p "$root"

    set +e
    set +o pipefail
    printf '2\nн\n0\n' |
        LC_ALL=C \
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        timeout 5s script -qfec "$INSTALLER" "$output" >/dev/null 2>&1
    status=$?
    set -o pipefail
    set -e
    (( status == 0 )) ||
        fail "русская клавиша Назад не вернула в главное меню, код $status"

    tr -d '\r' <"$output" >"$clean"
    grep -Fq "Н · Назад" "$clean" ||
        fail "меню не показывает русскую кнопку Назад"
    count="$(grep -F "Главное меню" "$clean" | wc -l | tr -d ' ')"
    (( count >= 2 )) ||
        fail "после русской клавиши Назад главное меню не появилось повторно"
    pass "русская клавиша Назад возвращает в родительское меню"
}

test_single_latin_y_is_not_yes_confirmation() {
    grep -Fq '""|д|да|yes) return 0' "$INSTALLER" ||
        fail "ответ по умолчанию да не содержит ожидаемые безопасные варианты"
    grep -Fq 'д|да|yes) return 0' "$INSTALLER" ||
        fail "ответ по умолчанию нет не содержит ожидаемые безопасные варианты"
    grep -Fq 'н|нет|no) return 1' "$INSTALLER" ||
        fail "отказ не содержит ожидаемые безопасные варианты"
    ! grep -Fq 'y|yes|д|да) return 0' "$INSTALLER" ||
        fail "одиночная латинская y всё ещё считается согласием"
    ! grep -Fq 'n|no|н|нет)' "$INSTALLER" ||
        fail "одиночная латинская n всё ещё считается отказом"
    grep -Fq 'Одиночные латинские y/n не принимаются' "$INSTALLER" ||
        fail "нет явного предупреждения о латинских y/n"
    pass "одиночная латинская y не считается согласием"
}

test_deploy_compatibility_contract() {
    bash "$TEST_DIR/compatibility_test.sh" >/dev/null ||
        fail "контракт Android-деплоя и standalone-установщика расходится"
    pass "контракт Android-деплоя и standalone-установщика совпадает"
}

test_wizard_on_android_deploy_is_guidance_not_failure() {
    command -v script >/dev/null ||
        fail "утилита script нужна для проверки интерактивного мастера"
    local sandbox root old_binary output clean status
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    old_binary="$sandbox/android-server"
    output="$sandbox/wizard-android.out"
    clean="$sandbox/wizard-android.clean"
    mkdir -p "$root"
    make_fake_binary "$old_binary" "android-old"
    make_android_deploy_install "$root" "$old_binary" "SafeOwnerPassword42"

    set +e
    set +o pipefail
    WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        timeout 5s script -qfec "$INSTALLER wizard" "$output" >/dev/null 2>&1
    status=$?
    set -o pipefail
    set -e
    (( status == 0 )) ||
        fail "мастер на Android-деплое завершился ошибкой $status"

    tr -d '\r' <"$output" >"$clean"
    grep -Fq "На сервере уже обнаружен совместимый Android-деплой." "$clean" ||
        fail "мастер не объяснил найденный Android-деплой"
    grep -Fq "✓ Совместимость подтверждена: контракт 1, wdtt-server 17." "$clean" ||
        fail "мастер не показал краткую совместимость"
    grep -Fq "Сейчас изменений на сервере не выполнено." "$clean" ||
        fail "мастер не подтвердил отсутствие изменений"
    ! grep -Fq "Что будет использоваться на сервере:" "$clean" ||
        fail "мастер Android-деплоя показывает лишний список путей"
    ! grep -Fq "Для обычной ручной установки запустите мастер" "$clean" ||
        fail "мастер Android-деплоя показывает лишнюю инструкцию чистой установки"
    ! grep -Fq "Ошибка:" "$clean" ||
        fail "мастер Android-деплоя ошибочно помечает безопасную остановку как ошибку"
    ! grep -Fq "firewall" "$clean" ||
        fail "мастер Android-деплоя содержит английское слово firewall"
    pass "мастер на Android-деплое показывает понятное направление без ошибки"
}

test_rejects_open_config_permissions() {
    local sandbox root binary config output
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/output"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"
    chmod 0644 "$config"

    expect_failure "$output" run_installer "$root" check --binary "$binary" --config "$config"
    grep -Fq "chmod 600" "$output" || fail "нет понятной ошибки о правах"
    pass "отклоняется конфигурация с открытыми правами"
}

test_dry_run_does_not_write() {
    local sandbox root binary config
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"

    run_installer "$root" install --binary "$binary" --config "$config" --dry-run >/dev/null
    [[ ! -e "$root/usr/local/bin/wdtt-server" ]] || fail "dry-run записал бинарник"
    [[ ! -e "$root/etc/systemd/system/wdtt.service" ]] || fail "dry-run записал unit"
    pass "dry-run не изменяет файловую систему"
}

test_first_install_keeps_secrets_out_of_unit() {
    local sandbox root binary config output secret
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/output"
    secret="SafeOwnerPassword42"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "$secret"

    run_installer "$root" install --binary "$binary" --config "$config" --yes >"$output"

    [[ -x "$root/usr/local/bin/wdtt-server" ]] || fail "бинарник не установлен"
    [[ -f "$root/etc/systemd/system/wdtt.service" ]] || fail "unit не установлен"
    [[ -f "$root/etc/wdtt/passwords.json" ]] || fail "база не установлена"
    [[ -x "$root/var/lib/wdtt-server-installer/network-runtime.sh" ]] ||
        fail "закрытый сетевой скрипт не установлен"
    [[ "$(stat -c '%a' "$root/var/lib/wdtt-server-installer/network-runtime.sh")" == "700" ]] ||
        fail "неверные права сетевого скрипта"
    grep -Fq "ExecStopPost=/var/lib/wdtt-server-installer/network-runtime.sh cleanup" \
        "$root/etc/systemd/system/wdtt.service" ||
        fail "unit не очищает сетевое состояние после остановки"
    grep -Fq "IFS='=' read -r key value" \
        "$root/var/lib/wdtt-server-installer/network-runtime.sh" ||
        fail "сетевой скрипт не сохраняет sysctl в формате ключ=значение"
    grep -Fq -- "-dns 1.1.1.1" "$root/etc/systemd/system/wdtt.service" ||
        fail "unit не передаёт DNS серверу"
    [[ "$(stat -c '%a' "$root/etc/wdtt/passwords.json")" == "600" ]] ||
        fail "неверные права базы"
    grep -Fq "Managed by WDTT Plus standalone server installer" \
        "$root/etc/systemd/system/wdtt.service" || fail "нет метки владения"
    if grep -Fq "$secret" "$root/etc/systemd/system/wdtt.service" "$output"; then
        fail "секрет попал в unit или вывод"
    fi
    [[ "$(jq -r '.main_password' "$root/etc/wdtt/passwords.json")" == "$secret" ]] ||
        fail "пароль не перенесён в закрытую базу"
    pass "первая установка изолирует секреты"
}

test_owned_update_preserves_database() {
    local sandbox root binary config before
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"

    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null
    before="$(sha256sum "$root/etc/wdtt/passwords.json" | awk '{print $1}')"
    make_fake_binary "$binary" "12"
    run_installer "$root" install --binary "$binary" --yes >/dev/null

    [[ "$("$root/usr/local/bin/wdtt-server" --build-id)" == "12" ]] ||
        fail "бинарник не обновлён"
    [[ "$(sha256sum "$root/etc/wdtt/passwords.json" | awk '{print $1}')" == "$before" ]] ||
        fail "обновление изменило базу"
    find "$root/var/lib/wdtt-server-installer/backups" -mindepth 1 -maxdepth 1 \
        -type d | grep -q . || fail "резервная копия не создана"
    pass "собственное обновление сохраняет базу"
}

test_refuses_foreign_install() {
    local sandbox root binary config output
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/output"
    mkdir -p "$root/etc/systemd/system"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"
    printf '%s\n' "[Service]" >"$root/etc/systemd/system/wdtt.service"

    expect_failure "$output" run_installer "$root" install \
        --binary "$binary" --config "$config" --yes
    grep -Fq "Автоматическая перезапись запрещена" "$output" ||
        fail "нет отказа от неизвестной установки"
    pass "неизвестная установка не перезаписывается"
}

test_android_deploy_requires_explicit_adoption() {
    local sandbox root old_binary new_binary output before before_wg
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    old_binary="$sandbox/android-server"
    new_binary="$sandbox/standalone-server"
    output="$sandbox/output"
    mkdir -p "$root"
    make_fake_binary "$old_binary" "android-old"
    make_fake_binary "$new_binary" "standalone-new"
    make_android_deploy_install "$root" "$old_binary" "SafeOwnerPassword42"
    before="$(sha256sum "$root/etc/wdtt/passwords.json" | awk '{print $1}')"
    before_wg="$(sha256sum "$root/etc/wdtt/wg-keys.dat" | awk '{print $1}')"

    expect_failure "$output" run_installer "$root" install --binary "$new_binary" --yes
    grep -Fq "adopt-android" "$output" || fail "обычный install не потребовал явного принятия Android-установки"

    run_installer "$root" adopt-android --binary "$new_binary" --yes >/dev/null
    grep -Fq "Managed by WDTT Plus standalone server installer" \
        "$root/etc/systemd/system/wdtt.service" || fail "принятая Android-установка не получила standalone unit"
    [[ "$("$root/usr/local/bin/wdtt-server" --build-id)" == "standalone-new" ]] ||
        fail "после принятия не заменён бинарник"
    [[ "$(sha256sum "$root/etc/wdtt/passwords.json" | awk '{print $1}')" == "$before" ]] ||
        fail "принятие Android-установки изменило базу"
    [[ -f "$root/var/lib/wdtt-server-installer/ownership" ]] ||
        fail "после принятия нет метки владения"
    [[ "$(stat -c '%a' "$root/etc/wdtt")" == "700" ]] ||
        fail "принятие не ужесточило права каталога конфигурации"
    [[ "$(stat -c '%a' "$root/etc/wdtt/server.log")" == "600" ]] ||
        fail "принятие не ужесточило права файлов конфигурации"

    # После принятия обновления выполняются только самим ручным установщиком.
    make_fake_binary "$new_binary" "standalone-manual-update"
    run_installer "$root" install --binary "$new_binary" \
        --dtls-port 56000 --wg-port 56001 --client-port 9000 --dns 1.1.1.1 \
        --firewall none --yes >/dev/null
    [[ "$("$root/usr/local/bin/wdtt-server" --build-id)" == "standalone-manual-update" ]] ||
        fail "ручное обновление после принятия не заменило бинарник"
    [[ "$(sha256sum "$root/etc/wdtt/passwords.json" | awk '{print $1}')" == "$before" ]] ||
        fail "ручное обновление после принятия изменило базу"
    [[ "$(sha256sum "$root/etc/wdtt/wg-keys.dat" | awk '{print $1}')" == "$before_wg" ]] ||
        fail "ручное обновление после принятия изменило WireGuard-ключи"
    grep -Fqx "Managed by WDTT Plus standalone server installer" \
        "$root/var/lib/wdtt-server-installer/ownership" ||
        fail "ручное обновление утратило standalone-владение"
    pass "Android-установка принимается явно и затем обновляется ручным установщиком"
}

test_android_backup_history_survives_adoption() {
    local sandbox root old_binary new_binary snapshot before
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    old_binary="$sandbox/android-server"
    new_binary="$sandbox/standalone-server"
    snapshot="$root/var/lib/wdtt-server-installer/backups/user/snapshots/20260902T120000Z-abcdef123456.wdtt-snapshot"
    mkdir -p "$root"
    make_fake_binary "$old_binary" "android-old"
    make_fake_binary "$new_binary" "standalone-new"
    make_android_deploy_install "$root" "$old_binary" "SafeOwnerPassword42"
    mkdir -p "$(dirname "$snapshot")"
    chmod 0700 \
        "$root/var/lib/wdtt-server-installer" \
        "$root/var/lib/wdtt-server-installer/backups" \
        "$root/var/lib/wdtt-server-installer/backups/user" \
        "$(dirname "$snapshot")"
    printf '%s\n' '{"format":"wdtt-server-snapshot"}' >"$snapshot"
    chmod 0600 "$snapshot"
    before="$(sha256sum "$snapshot" | awk '{print $1}')"

    run_installer "$root" adopt-android --binary "$new_binary" --yes >/dev/null

    [[ -f "$snapshot" ]] || fail "история автоматических копий удалена при принятии Android-деплоя"
    [[ "$(sha256sum "$snapshot" | awk '{print $1}')" == "$before" ]] ||
        fail "история автоматических копий изменена при принятии Android-деплоя"
    pass "автоматические копии Android-деплоя сохраняются при принятии установщиком"
}

test_android_adoption_requires_current_contract_marker() {
    local sandbox root old_binary new_binary output
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    old_binary="$sandbox/android-server"
    new_binary="$sandbox/standalone-server"
    output="$sandbox/output"
    mkdir -p "$root"
    make_fake_binary "$old_binary" "android-old"
    make_fake_binary "$new_binary" "standalone-new"
    make_android_deploy_install "$root" "$old_binary" "SafeOwnerPassword42"
    sed -i '/^# WDTT deploy compatibility:/d' "$root/etc/systemd/system/wdtt.service"

    expect_failure "$output" run_installer "$root" adopt-android --binary "$new_binary" --yes
    grep -Fq "совместимую Android-установку" "$output" ||
        fail "устаревший Android unit был принят без версии контракта"
    [[ "$("$root/usr/local/bin/wdtt-server" --build-id)" == "android-old" ]] ||
        fail "отказ принятия изменил Android-бинарник"
    [[ ! -e "$root/var/lib/wdtt-server-installer/ownership" ]] ||
        fail "отказ принятия создал standalone-метку"
    pass "Android-установка без версии контракта не принимается"
}

test_failed_android_adoption_restores_legacy_owner() {
    local sandbox root old_binary new_binary output before
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    old_binary="$sandbox/android-server"
    new_binary="$sandbox/standalone-server"
    output="$sandbox/output"
    mkdir -p "$root"
    make_fake_binary "$old_binary" "android-old"
    make_fake_binary "$new_binary" "standalone-new"
    make_android_deploy_install "$root" "$old_binary" "SafeOwnerPassword42"
    before="$(sha256sum "$root/etc/wdtt/passwords.json" | awk '{print $1}')"

    expect_failure "$output" env \
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_FAIL_AT=files_replaced \
        "$INSTALLER" adopt-android --binary "$new_binary" --yes
    grep -Fq "Managed by WDTT Plus Android deploy" "$root/etc/systemd/system/wdtt.service" ||
        fail "откат не вернул Android unit"
    [[ "$("$root/usr/local/bin/wdtt-server" --build-id)" == "android-old" ]] ||
        fail "откат не вернул исходный Android-бинарник"
    [[ "$(sha256sum "$root/etc/wdtt/passwords.json" | awk '{print $1}')" == "$before" ]] ||
        fail "откат принятия изменил базу"
    [[ ! -e "$root/var/lib/wdtt-server-installer/ownership" ]] ||
        fail "откат принятия оставил standalone-метку"
    [[ "$(stat -c '%a' "$root/etc/wdtt")" == "755" ]] ||
        fail "откат принятия не вернул исходные права каталога"
    [[ "$(stat -c '%a' "$root/etc/wdtt/server.log")" == "644" ]] ||
        fail "откат принятия не вернул исходные права файла"
    run_installer "$root" check --binary "$new_binary" >/dev/null ||
        fail "после отката Android-установка больше не распознаётся"
    pass "неуспешное принятие возвращает Android-установку"
}

test_handoff_android_preserves_data_and_allows_roundtrip() {
    local sandbox root binary config snapshot database_before keys_before snapshot_before
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    snapshot="$root/var/lib/wdtt-server-installer/backups/user/snapshots/manual-test.wdtt-snapshot"
    mkdir -p "$root"
    make_fake_binary "$binary" "standalone-source"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null

    mkdir -p "$(dirname "$snapshot")"
    chmod 0700 \
        "$root/var/lib/wdtt-server-installer/backups" \
        "$root/var/lib/wdtt-server-installer/backups/user" \
        "$(dirname "$snapshot")"
    printf '%s\n' '{"format":"wdtt-server-snapshot","source":"handoff-test"}' >"$snapshot"
    chmod 0600 "$snapshot"
    database_before="$(sha256sum "$root/etc/wdtt/passwords.json" | awk '{print $1}')"
    keys_before="$(sha256sum "$root/etc/wdtt/wg-keys.dat" | awk '{print $1}')"
    snapshot_before="$(sha256sum "$snapshot" | awk '{print $1}')"

    run_installer "$root" handoff-android --yes >/dev/null

    grep -Fqx '# Managed by WDTT Plus Android deploy' \
        "$root/etc/systemd/system/wdtt.service" ||
        fail "передача не записала Android ownership-маркер"
    grep -Fqx '# WDTT deploy compatibility: 1' \
        "$root/etc/systemd/system/wdtt.service" ||
        fail "передача не записала версию Android-контракта"
    ! grep -Fq 'standalone server installer' "$root/etc/systemd/system/wdtt.service" ||
        fail "после передачи в unit осталась standalone-метка"
    [[ ! -e "$root/var/lib/wdtt-server-installer/ownership" ]] ||
        fail "после передачи осталась standalone-метка владения"
    [[ ! -e "$root/var/lib/wdtt-server-installer/network-runtime.sh" ]] ||
        fail "после передачи остался standalone network helper"
    [[ -f "$root/var/lib/wdtt-server-installer/.standalone-state" ]] ||
        fail "после передачи потеряна безопасная метка каталога резервных копий"
    [[ "$(sha256sum "$root/etc/wdtt/passwords.json" | awk '{print $1}')" == "$database_before" ]] ||
        fail "передача изменила базу"
    [[ "$(sha256sum "$root/etc/wdtt/wg-keys.dat" | awk '{print $1}')" == "$keys_before" ]] ||
        fail "передача изменила WireGuard-ключи"
    [[ "$(sha256sum "$snapshot" | awk '{print $1}')" == "$snapshot_before" ]] ||
        fail "передача изменила пользовательскую резервную копию"
    [[ "$("$root/usr/local/bin/wdtt-server" --build-id)" == "standalone-source" ]] ||
        fail "передача заменила серверный бинарник"

    run_installer "$root" check --binary "$binary" >/dev/null ||
        fail "результат передачи не распознаётся как совместимый Android-деплой"
    run_installer "$root" adopt-android --binary "$binary" --yes >/dev/null
    grep -Fqx 'Managed by WDTT Plus standalone server installer' \
        "$root/var/lib/wdtt-server-installer/ownership" ||
        fail "обратное принятие Android-деплоя не восстановило standalone-владение"
    [[ "$(sha256sum "$snapshot" | awk '{print $1}')" == "$snapshot_before" ]] ||
        fail "обратное принятие изменило пользовательскую резервную копию"
    pass "ручная установка передаётся Android-деплою без потери данных и принимается обратно"
}

test_handoff_android_rejects_non_owned_install() {
    local sandbox root binary output
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/android-server"
    output="$sandbox/handoff.out"
    mkdir -p "$root"
    make_fake_binary "$binary" "android-owned"
    make_android_deploy_install "$root" "$binary" "SafeOwnerPassword42"

    expect_failure "$output" run_installer "$root" handoff-android --yes
    grep -Fq "требует собственную ручную установку" "$output" ||
        fail "handoff-android не объяснил отказ для Android-владения"
    [[ "$("$root/usr/local/bin/wdtt-server" --build-id)" == "android-owned" ]] ||
        fail "отказ handoff-android изменил Android-бинарник"
    [[ ! -e "$root/var/lib/wdtt-server-installer/ownership" ]] ||
        fail "отказ handoff-android создал standalone-владение"
    pass "передача Android-деплою доступна только для собственной ручной установки"
}

test_failed_handoff_android_rolls_back_owner_and_data() {
    local sandbox root binary config output unit_before database_before keys_before
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/handoff.out"
    mkdir -p "$root"
    make_fake_binary "$binary" "standalone-source"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null
    unit_before="$(sha256sum "$root/etc/systemd/system/wdtt.service" | awk '{print $1}')"
    database_before="$(sha256sum "$root/etc/wdtt/passwords.json" | awk '{print $1}')"
    keys_before="$(sha256sum "$root/etc/wdtt/wg-keys.dat" | awk '{print $1}')"

    expect_failure "$output" env \
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_FAIL_AT=files_replaced \
        "$INSTALLER" handoff-android --yes

    [[ "$(sha256sum "$root/etc/systemd/system/wdtt.service" | awk '{print $1}')" == "$unit_before" ]] ||
        fail "откат передачи не вернул standalone unit"
    grep -Fqx 'Managed by WDTT Plus standalone server installer' \
        "$root/var/lib/wdtt-server-installer/ownership" ||
        fail "откат передачи не вернул standalone-владение"
    [[ -x "$root/var/lib/wdtt-server-installer/network-runtime.sh" ]] ||
        fail "откат передачи не вернул network helper"
    [[ "$(sha256sum "$root/etc/wdtt/passwords.json" | awk '{print $1}')" == "$database_before" ]] ||
        fail "откат передачи изменил базу"
    [[ "$(sha256sum "$root/etc/wdtt/wg-keys.dat" | awk '{print $1}')" == "$keys_before" ]] ||
        fail "откат передачи изменил WireGuard-ключи"
    [[ ! -e "$root/var/lib/wdtt-server-installer/transaction" ]] ||
        fail "после отката передачи остался журнал"
    run_installer "$root" check --binary "$binary" >/dev/null ||
        fail "после отката ручная установка не проходит проверку"
    pass "ошибка передачи полностью возвращает ручного владельца и данные"
}

test_handoff_android_preserves_owned_firewall_rule() {
    local sandbox root binary config rule
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    rule="$root/var/lib/wdtt-server-installer/.test-firewall-56000"
    mkdir -p "$root"
    make_fake_binary "$binary" "standalone-source"
    make_config "$config" "SafeOwnerPassword42"
    WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_FIREWALL=ufw \
        "$INSTALLER" install --binary "$binary" --config "$config" \
        --firewall open --yes >/dev/null
    [[ -f "$rule" ]] || fail "подготовка не создала собственное firewall-правило"

    WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_FIREWALL=ufw \
        "$INSTALLER" handoff-android --yes >/dev/null

    [[ -f "$rule" ]] || fail "передача удалила рабочее firewall-правило DTLS-порта"
    grep -Fxq 'manager=ufw' "$root/var/lib/wdtt-server-installer/firewall-state" ||
        fail "передача потеряла безопасную метку firewall-правила"
    run_installer "$root" check --binary "$binary" >/dev/null ||
        fail "сохранённая firewall-метка мешает распознать Android-деплой"
    pass "передача сохраняет рабочее firewall-правило и его безопасную метку"
}

test_failed_handoff_preserves_owned_firewall_rule() {
    local sandbox root binary config output rule firewall_state
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/handoff.out"
    rule="$root/var/lib/wdtt-server-installer/.test-firewall-56000"
    firewall_state="$root/var/lib/wdtt-server-installer/firewall-state"
    mkdir -p "$root"
    make_fake_binary "$binary" "standalone-source"
    make_config "$config" "SafeOwnerPassword42"
    WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_FIREWALL=ufw \
        "$INSTALLER" install --binary "$binary" --config "$config" \
        --firewall open --yes >/dev/null

    expect_failure "$output" env \
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_FIREWALL=ufw \
        WDTT_INSTALLER_TEST_FAIL_AT=firewall_applied \
        "$INSTALLER" handoff-android --yes

    [[ -f "$rule" ]] || fail "ошибка передачи удалила собственное firewall-правило"
    grep -Fxq 'manager=ufw' "$firewall_state" ||
        fail "откат передачи не вернул состояние владельца firewall"
    grep -Fxq 'port=56000' "$firewall_state" ||
        fail "откат передачи вернул firewall-состояние с неверным портом"
    grep -Fqx 'Managed by WDTT Plus standalone server installer' \
        "$root/var/lib/wdtt-server-installer/ownership" ||
        fail "откат firewall-этапа не вернул standalone-владение"
    pass "ошибка передачи сохраняет firewall-правило, метку и владельца"
}

test_handoff_preserves_disabled_and_stopped_service() {
    local sandbox root binary config
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    mkdir -p "$root"
    make_fake_binary "$binary" "standalone-source"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null
    rm -f \
        "$root/var/lib/wdtt-server-installer/.test-service-active" \
        "$root/var/lib/wdtt-server-installer/.test-service-enabled"

    run_installer "$root" handoff-android --yes >/dev/null

    [[ ! -e "$root/var/lib/wdtt-server-installer/.test-service-active" ]] ||
        fail "передача самовольно оставила остановленную службу активной"
    [[ ! -e "$root/var/lib/wdtt-server-installer/.test-service-enabled" ]] ||
        fail "передача самовольно включила отключённую службу"
    grep -Fqx '# Managed by WDTT Plus Android deploy' \
        "$root/etc/systemd/system/wdtt.service" ||
        fail "остановленная служба не была передана Android-деплою"
    pass "передача проверяет, но сохраняет отключённое и остановленное состояние службы"
}

test_interrupted_committed_handoff_finishes_safely() {
    local sandbox root binary config output database_before
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/handoff.out"
    mkdir -p "$root"
    make_fake_binary "$binary" "standalone-source"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null
    database_before="$(sha256sum "$root/etc/wdtt/passwords.json" | awk '{print $1}')"

    expect_failure "$output" env \
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_FAIL_AT=committed \
        WDTT_INSTALLER_TEST_LEAVE_TRANSACTION=1 \
        "$INSTALLER" handoff-android --yes
    [[ -f "$root/var/lib/wdtt-server-installer/transaction" ]] ||
        fail "тестовый обрыв не оставил журнал завершённой передачи"

    run_installer "$root" handoff-android --yes >"$output"
    grep -Fq "Передача Android-деплою уже была проверена и завершена" "$output" ||
        fail "повтор не распознал проверенную передачу"
    grep -Fqx '# Managed by WDTT Plus Android deploy' \
        "$root/etc/systemd/system/wdtt.service" ||
        fail "восстановление завершённой передачи не сохранило Android-владение"
    [[ ! -e "$root/var/lib/wdtt-server-installer/transaction" ]] ||
        fail "после завершения передачи остался журнал"
    [[ ! -e "$root/var/lib/wdtt-server-installer/ownership" ]] ||
        fail "после завершения передачи осталась standalone-метка"
    [[ "$(sha256sum "$root/etc/wdtt/passwords.json" | awk '{print $1}')" == "$database_before" ]] ||
        fail "завершение прерванной передачи изменило базу"
    pass "проверенная прерванная передача безопасно завершается повторным запуском"
}

test_regular_install_finishes_committed_handoff_recovery() {
    local sandbox root binary config output
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/recovery.out"
    mkdir -p "$root"
    make_fake_binary "$binary" "standalone-source"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null

    expect_failure "$output" env \
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_FAIL_AT=committed \
        WDTT_INSTALLER_TEST_LEAVE_TRANSACTION=1 \
        "$INSTALLER" handoff-android --yes

    run_installer "$root" install --binary "$binary" --yes >"$output"
    grep -Fq "Передача Android-деплою уже была проверена и завершена" "$output" ||
        fail "обычный install не завершил проверенную передачу"
    [[ ! -e "$root/var/lib/wdtt-server-installer/transaction" ]] ||
        fail "обычный install оставил журнал завершённой передачи"
    grep -Fqx '# Managed by WDTT Plus Android deploy' \
        "$root/etc/systemd/system/wdtt.service" ||
        fail "обычный install неверно вернул standalone-владение после commit"
    pass "обычный install завершает прерванную после commit передачу без повторной установки"
}

test_failed_health_check_rolls_back_first_install() {
    local sandbox root binary config output
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/output"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"

    expect_failure "$output" env \
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_FAIL_HEALTH=1 \
        "$INSTALLER" install --binary "$binary" --config "$config" --yes

    [[ ! -e "$root/usr/local/bin/wdtt-server" ]] || fail "откат оставил бинарник"
    [[ ! -e "$root/etc/systemd/system/wdtt.service" ]] || fail "откат оставил unit"
    [[ ! -e "$root/etc/wdtt/passwords.json" ]] || fail "откат оставил созданную базу"

    run_installer "$root" install --binary "$binary" --config "$config" --dry-run >/dev/null ||
        fail "после отката установка ошибочно считается чужой"
    pass "неуспешная первая установка откатывается"
}

test_rejects_malformed_config() {
    local sandbox root binary config output
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/output"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    printf '%s\n' '{"main_password":' >"$config"
    chmod 0600 "$config"

    expect_failure "$output" run_installer "$root" check --binary "$binary" --config "$config"
    grep -Fq "не прошла проверку структуры" "$output" ||
        fail "нет понятной ошибки структуры JSON"
    pass "повреждённая конфигурация отклоняется"
}

test_failed_update_restores_previous_binary() {
    local sandbox root binary config output before
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/output"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null
    before="$(sha256sum "$root/etc/wdtt/passwords.json" | awk '{print $1}')"

    make_fake_binary "$binary" "12"
    expect_failure "$output" env \
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_FAIL_HEALTH=1 \
        "$INSTALLER" install --binary "$binary" --yes

    [[ "$("$root/usr/local/bin/wdtt-server" --build-id)" == "11" ]] ||
        fail "откат обновления не вернул прежний бинарник"
    [[ "$(sha256sum "$root/etc/wdtt/passwords.json" | awk '{print $1}')" == "$before" ]] ||
        fail "неуспешное обновление изменило базу"
    local status_output
    status_output="$(run_installer "$root" status)"
    grep -Fq "Состояние установки: ручная установка WDTT Plus" <<<"$status_output" ||
        fail "после отката потеряна метка владения: $status_output"
    pass "неуспешное обновление возвращает прежнюю версию"
}

test_real_server_binary_passes_preflight() {
    local sandbox root binary config
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    mkdir -p "$root"
    (
        cd "$REPOSITORY_ROOT"
        GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
            go build -trimpath -o "$binary" .
    )
    make_config "$config" "SafeOwnerPassword42"

    run_installer "$root" install --binary "$binary" --config "$config" --dry-run >/dev/null
    pass "реальный wdtt-server проходит preflight"
}

test_rejects_symlinked_test_root() {
    local sandbox target linked output
    new_sandbox
    sandbox="$NEW_SANDBOX"
    target="$sandbox/target"
    linked="$sandbox/linked"
    output="$sandbox/output"
    mkdir -p "$target"
    ln -s "$target" "$linked"

    expect_failure "$output" env \
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$linked" \
        "$INSTALLER" status
    grep -Fq "обычным каталогом" "$output" ||
        fail "символическая ссылка тестового корня не отклонена"
    pass "тестовый корень через symlink запрещён"
}

test_init_config_creates_protected_file() {
    local sandbox root password_file output_config output secret
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    password_file="$sandbox/password"
    output_config="$sandbox/generated.json"
    output="$sandbox/output"
    secret="AnotherSafeOwner42"
    mkdir -p "$root"
    printf '%s\n' "$secret" >"$password_file"
    chmod 0600 "$password_file"

    run_installer "$root" init-config \
        --output "$output_config" \
        --password-file "$password_file" \
        --yes >"$output"

    [[ -f "$output_config" && "$(stat -c '%a' "$output_config")" == "600" ]] ||
        fail "init-config не создал закрытый файл"
    [[ "$(jq -r '.main_password' "$output_config")" == "$secret" ]] ||
        fail "init-config записал неверный пароль"
    grep -Fq "$secret" "$output" &&
        fail "init-config раскрыл пароль в выводе"
    pass "init-config безопасно создаёт закрытую конфигурацию"
}

test_init_config_never_overwrites() {
    local sandbox root password_file output_config output before
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    password_file="$sandbox/password"
    output_config="$sandbox/generated.json"
    output="$sandbox/output"
    mkdir -p "$root"
    printf '%s\n' "AnotherSafeOwner42" >"$password_file"
    chmod 0600 "$password_file"
    printf '%s\n' "keep-me" >"$output_config"
    chmod 0600 "$output_config"
    before="$(sha256sum "$output_config" | awk '{print $1}')"

    expect_failure "$output" run_installer "$root" init-config \
        --output "$output_config" \
        --password-file "$password_file" \
        --yes
    [[ "$(sha256sum "$output_config" | awk '{print $1}')" == "$before" ]] ||
        fail "init-config перезаписал существующий файл"
    pass "init-config не перезаписывает существующий файл"
}

test_monitor_reports_safe_aggregates() {
    local sandbox root binary config database pending output
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/monitor.out"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null

    database="$root/etc/wdtt/passwords.json"
    pending="$sandbox/passwords.json"
    jq '
        .passwords.alpha = {
            label: "secret label",
            vk_hash: "SECRET_HASH",
            ports: "56000,56001,9000",
            status: "active",
            expires_at: 0,
            purge_after: 0,
            down_bytes: 1048576,
            up_bytes: 524288,
            traffic: [{date: "2026-08-28", down_bytes: 1024, up_bytes: 2048}],
            device_id: "dev1"
        } |
        .devices.dev1 = {device_id: "dev1", ip: "10.66.66.2"}
    ' "$database" >"$pending"
    chmod 0600 "$pending"
    mv "$pending" "$database"

    run_installer "$root" monitor >"$output"
    grep -Fq "Мониторинг WDTT Plus" "$output" ||
        fail "monitor не показал заголовок"
    grep -Fq "Клиенты: всего 1, активных 1" "$output" ||
        fail "monitor не показал агрегаты клиентов"
    grep -Fq "Трафик всего: ↓1.00 МиБ / ↑512.00 КиБ" "$output" ||
        fail "monitor не показал общий трафик"
    if grep -Eq "SafeOwnerPassword42|SECRET_HASH" "$output"; then
        fail "monitor раскрыл секреты"
    fi
    pass "monitor показывает безопасные агрегаты без секретов"
}

test_update_preserves_custom_runtime_defaults() {
    local sandbox root binary config unit
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    unit="$root/etc/systemd/system/wdtt.service"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config_with_settings \
        "$config" "SafeOwnerPassword42" "9.9.9.9" 25 "56100,56101,9100"

    run_installer "$root" install \
        --binary "$binary" \
        --config "$config" \
        --dtls-port 56100 \
        --wg-port 56101 \
        --client-port 9100 \
        --dns 9.9.9.9 \
        --max-passwords 25 \
        --yes >/dev/null
    make_fake_binary "$binary" "12"
    run_installer "$root" install --binary "$binary" --yes >/dev/null

    grep -Fq -- "-listen 0.0.0.0:56100" "$unit" ||
        fail "обновление сбросило нестандартный DTLS-порт"
    grep -Fq -- "-wg-port 56101" "$unit" ||
        fail "обновление сбросило нестандартный WG-порт"
    grep -Fq -- "-dns 9.9.9.9" "$unit" ||
        fail "обновление сбросило нестандартный DNS"
    [[ "$(jq -r '.default_ports' "$root/etc/wdtt/passwords.json")" == "56100,56101,9100" ]] ||
        fail "обновление изменило сохранённые порты"
    pass "обновление сохраняет нестандартные текущие параметры"
}

test_failed_update_restores_entire_config_tree() {
    local sandbox root binary config output protected_file before
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/output"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null
    protected_file="$root/etc/wdtt/operator-state"
    printf '%s\n' "protected-runtime-state" >"$protected_file"
    chmod 0600 "$protected_file"
    before="$(sha256sum "$protected_file" | awk '{print $1}')"

    make_fake_binary "$binary" "12"
    expect_failure "$output" env \
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_MUTATE_CONFIG=1 \
        WDTT_INSTALLER_TEST_FAIL_HEALTH=1 \
        "$INSTALLER" install --binary "$binary" --yes

    [[ "$(sha256sum "$protected_file" | awk '{print $1}')" == "$before" ]] ||
        fail "откат не восстановил дополнительный файл /etc/wdtt"
    [[ ! -e "$root/etc/wdtt/runtime-mutated" ]] ||
        fail "откат оставил файл, созданный новой версией"
    pass "откат восстанавливает весь /etc/wdtt"
}

test_interrupted_update_recovers_before_retry() {
    local sandbox root binary config output
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/output"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null

    make_fake_binary "$binary" "12"
    expect_failure "$output" env \
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_FAIL_AT=files_replaced \
        WDTT_INSTALLER_TEST_LEAVE_TRANSACTION=1 \
        "$INSTALLER" install --binary "$binary" --yes
    [[ -f "$root/var/lib/wdtt-server-installer/transaction" ]] ||
        fail "тест не оставил журнал транзакции"

    make_fake_binary "$binary" "13"
    run_installer "$root" install --binary "$binary" --yes >/dev/null
    [[ "$("$root/usr/local/bin/wdtt-server" --build-id)" == "13" ]] ||
        fail "повтор не завершил обновление после восстановления"
    [[ ! -e "$root/var/lib/wdtt-server-installer/transaction" ]] ||
        fail "после восстановления остался журнал"
    pass "прерванная транзакция автоматически восстанавливается"
}

test_parallel_installer_is_rejected() {
    local sandbox root binary config output locker lock_path lock_ready attempt
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/output"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null
    lock_path="$root/var/lib/wdtt-server-installer/installer.lock"
    lock_ready="$sandbox/installer-lock-ready"

    (
        exec 8>"$lock_path"
        flock -x 8
        printf 'locked\n' >"$lock_ready"
        # Keep the lock long enough for slow/loaded CI hosts to reach the
        # competing invocation without turning this into a timing race.
        sleep 10
    ) &
    locker=$!
    for ((attempt = 0; attempt < 100; attempt++)); do
        [[ -f "$lock_ready" ]] && break
        kill -0 "$locker" 2>/dev/null ||
            fail "процесс проверки завершился до захвата блокировки"
        sleep 0.02
    done
    [[ -f "$lock_ready" ]] || fail "не удалось дождаться захвата блокировки"
    make_fake_binary "$binary" "12"
    expect_failure "$output" run_installer "$root" install --binary "$binary" --yes
    wait "$locker"
    grep -Fq "Другой экземпляр установщика" "$output" ||
        fail "нет понятной ошибки блокировки"
    pass "параллельный установщик отклоняется"
}

test_route_collision_is_rejected() {
    local sandbox root binary config output
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/output"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"

    expect_failure "$output" env \
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_ROUTE_TABLE="10.0.0.0/8 dev eth0" \
        "$INSTALLER" check --binary "$binary" --config "$config"
    grep -Fq "пересекается с внутренней подсетью" "$output" ||
        fail "нет ошибки о конфликте маршрута"
    pass "конфликт внутренней подсети отклоняется"
}

test_symlink_inside_config_is_rejected() {
    local sandbox root binary config output
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/output"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null
    ln -s /tmp "$root/etc/wdtt/unsafe-link"
    make_fake_binary "$binary" "12"

    expect_failure "$output" run_installer "$root" install --binary "$binary" --yes
    grep -Fq "небезопасный объект" "$output" ||
        fail "нет ошибки о ссылке внутри конфигурации"
    [[ "$("$root/usr/local/bin/wdtt-server" --build-id)" == "11" ]] ||
        fail "проверка ссылки успела заменить бинарник"
    pass "символическая ссылка внутри /etc/wdtt отклоняется"
}

test_doctor_reports_healthy_install() {
    local sandbox root binary config output
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/output"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null

    run_installer "$root" doctor >"$output"
    grep -Fq "Итог диагностики: ошибок 0" "$output" ||
        fail "doctor не подтвердил здоровую установку"
    pass "doctor проверяет здоровую установку без изменений"
}

test_firewall_opt_in_adds_only_dtls_rule() {
    local sandbox root binary config
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"

    env \
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_FIREWALL=ufw \
        "$INSTALLER" install \
        --binary "$binary" \
        --config "$config" \
        --firewall open \
        --yes >/dev/null

    [[ -f "$root/var/lib/wdtt-server-installer/.test-firewall-56000" ]] ||
        fail "отдельное согласие не добавило тестовое DTLS-правило"
    [[ ! -e "$root/var/lib/wdtt-server-installer/.test-firewall-56001" ]] ||
        fail "установщик открыл внутренний WG-порт"
    pass "firewall по отдельному согласию добавляет только публичный DTLS-порт"
}

test_firewall_default_does_not_change_rules() {
    local sandbox root binary config
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"

    env \
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_FIREWALL=ufw \
        "$INSTALLER" install \
        --binary "$binary" \
        --config "$config" \
        --yes >/dev/null

    [[ ! -e "$root/var/lib/wdtt-server-installer/.test-firewall-56000" ]] ||
        fail "режим по умолчанию изменил firewall"
    pass "firewall по умолчанию остаётся без изменений"
}

test_firewall_rule_rolls_back_on_failure() {
    local sandbox root binary config output
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/output"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"

    expect_failure "$output" env \
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_FIREWALL=ufw \
        WDTT_INSTALLER_TEST_FAIL_AT=firewall_applied \
        "$INSTALLER" install \
        --binary "$binary" \
        --config "$config" \
        --firewall open \
        --yes

    [[ ! -e "$root/var/lib/wdtt-server-installer/.test-firewall-56000" ]] ||
        fail "откат оставил добавленное firewall-правило"
    [[ ! -e "$root/usr/local/bin/wdtt-server" ]] ||
        fail "откат firewall-ошибки оставил бинарник первой установки"
    pass "добавленное firewall-правило входит в транзакционный откат"
}

test_partial_first_replacement_rolls_back() {
    local sandbox root binary config output
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/output"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"

    expect_failure "$output" env \
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_FAIL_AT=binary_replaced \
        "$INSTALLER" install \
        --binary "$binary" \
        --config "$config" \
        --yes

    [[ ! -e "$root/usr/local/bin/wdtt-server" ]] ||
        fail "частичный откат оставил бинарник"
    [[ ! -e "$root/etc/systemd/system/wdtt.service" ]] ||
        fail "частичный откат оставил unit"
    [[ ! -e "$root/var/lib/wdtt-server-installer/transaction" ]] ||
        fail "частичный откат оставил журнал"
    run_installer "$root" install \
        --binary "$binary" \
        --config "$config" \
        --dry-run >/dev/null ||
        fail "после частичного отката нельзя повторить установку"
    pass "частичная замена первого файла безопасно откатывается"
}

test_owned_update_applies_selected_settings_atomically() {
    local sandbox root binary config database unit
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    database="$root/etc/wdtt/passwords.json"
    unit="$root/etc/systemd/system/wdtt.service"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null

    make_fake_binary "$binary" "12"
    run_installer "$root" install \
        --binary "$binary" \
        --dtls-port 56200 \
        --wg-port 56201 \
        --client-port 9200 \
        --dns 9.9.9.9 \
        --max-passwords 75 \
        --migrate-ports \
        --yes >/dev/null

    grep -Fq -- "-listen 0.0.0.0:56200" "$unit" ||
        fail "новый DTLS-порт не попал в unit"
    grep -Fq -- "-wg-port 56201" "$unit" ||
        fail "новый WG-порт не попал в unit"
    [[ "$(jq -r '.default_ports' "$database")" == "56200,56201,9200" ]] ||
        fail "новые порты не попали в базу"
    [[ "$(jq -r '.dns' "$database")" == "9.9.9.9" ]] ||
        fail "новый DNS не попал в базу"
    [[ "$(jq -r '.max_passwords' "$database")" == "75" ]] ||
        fail "новый лимит не попал в базу"
    pass "выбранные настройки обновляются вместе с транзакцией"
}

test_existing_firewall_rule_survives_rollback() {
    local sandbox root binary config output rule
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/output"
    rule="$root/var/lib/wdtt-server-installer/.test-firewall-56000"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null
    : >"$rule"

    make_fake_binary "$binary" "12"
    expect_failure "$output" env \
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_FIREWALL=ufw \
        WDTT_INSTALLER_TEST_FAIL_AT=firewall_applied \
        "$INSTALLER" install \
        --binary "$binary" \
        --firewall open \
        --yes

    [[ -f "$rule" ]] ||
        fail "откат удалил существовавшее до транзакции firewall-правило"
    [[ "$("$root/usr/local/bin/wdtt-server" --build-id)" == "11" ]] ||
        fail "откат не восстановил прежний бинарник"
    pass "откат не удаляет существующее firewall-правило"
}

test_identical_repeat_is_noop() {
    local sandbox root binary config output unit_before database_before service_before
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/output"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null
    unit_before="$(sha256sum "$root/etc/systemd/system/wdtt.service" | awk '{print $1}')"
    database_before="$(sha256sum "$root/etc/wdtt/passwords.json" | awk '{print $1}')"
    service_before="$(stat -c '%y' "$root/var/lib/wdtt-server-installer/.test-service-active")"

    run_installer "$root" install --binary "$binary" --yes >"$output"

    grep -Fq "Установка уже актуальна" "$output" ||
        fail "повтор не сообщил об актуальной установке"
    grep -Fq "изменений и перезапуска не будет" "$output" ||
        fail "повтор не подтвердил no-op"
    [[ "$(sha256sum "$root/etc/systemd/system/wdtt.service" | awk '{print $1}')" == "$unit_before" ]] ||
        fail "no-op изменил unit"
    [[ "$(sha256sum "$root/etc/wdtt/passwords.json" | awk '{print $1}')" == "$database_before" ]] ||
        fail "no-op изменил базу"
    [[ "$(stat -c '%y' "$root/var/lib/wdtt-server-installer/.test-service-active")" == "$service_before" ]] ||
        fail "no-op перезапустил службу"
    [[ ! -d "$root/var/lib/wdtt-server-installer/backups" ]] ||
        fail "no-op создал резервную копию"

    run_installer "$root" check --binary "$binary" >"$output"
    grep -Fq "обновление не требуется" "$output" ||
        fail "check не распознал актуальную установку"
    pass "идентичный повтор завершается без изменений и перезапуска"
}

test_enabled_but_stopped_service_is_repaired() {
    local sandbox root binary config
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null
    rm -f "$root/var/lib/wdtt-server-installer/.test-service-active"

    run_installer "$root" install --binary "$binary" --yes >/dev/null

    [[ -f "$root/var/lib/wdtt-server-installer/.test-service-active" ]] ||
        fail "повтор не запустил включённую, но остановившуюся службу"
    find "$root/var/lib/wdtt-server-installer/backups" -mindepth 1 -maxdepth 1 \
        -type d | grep -q . ||
        fail "восстановление службы прошло вне транзакции"
    pass "включённая, но остановившаяся служба восстанавливается"
}

test_disabled_and_stopped_service_remains_noop() {
    local sandbox root binary config output
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/output"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null
    rm -f \
        "$root/var/lib/wdtt-server-installer/.test-service-active" \
        "$root/var/lib/wdtt-server-installer/.test-service-enabled"

    run_installer "$root" install --binary "$binary" --yes >"$output"

    grep -Fq "служба остановлена и отключена" "$output" ||
        fail "no-op не объяснил сохранённое состояние службы"
    [[ ! -e "$root/var/lib/wdtt-server-installer/.test-service-active" ]] ||
        fail "no-op самовольно запустил отключённую службу"
    [[ ! -d "$root/var/lib/wdtt-server-installer/backups" ]] ||
        fail "no-op отключённой службы создал backup"
    pass "явно отключённая служба остаётся остановленной без обновления"
}

test_installer_version_difference_triggers_update() {
    local sandbox root binary config output ownership
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/output"
    ownership="$root/var/lib/wdtt-server-installer/ownership"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null
    sed -i 's/^installer_version=.*/installer_version=0.2.0/' "$ownership"

    run_installer "$root" install --binary "$binary" --yes >"$output"

    grep -Fq "установщик:  0.19.1" "$output" ||
        fail "план не показал версию запущенного установщика"
    grep -Fq "установлен:  0.2.0" "$output" ||
        fail "план не показал прежнюю установленную версию"
    grep -Fxq "installer_version=0.19.1" "$ownership" ||
        fail "повтор не обновил версию в метке владения"
    find "$root/var/lib/wdtt-server-installer/backups" -mindepth 1 -maxdepth 1 \
        -type d | grep -q . ||
        fail "различие версий ошибочно обработано как no-op"

    run_installer "$root" status >"$output"
    grep -Fq "Версия этого установщика: 0.19.1" "$output" ||
        fail "status не показывает версию файла"
    grep -Fq "Установлено версией: 0.19.1" "$output" ||
        fail "status не показывает установленную версию"
    grep -Fq "Версии установщика: совпадают" "$output" ||
        fail "status не сравнивает версии"
    pass "различие версий установщика видно и запускает обновление"
}

test_rejects_incompatible_server_version() {
    local sandbox root binary config output
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/output"
    mkdir -p "$root"
    make_fake_binary "$binary" "old-build" "14"
    make_config "$config" "SafeOwnerPassword42"

    expect_failure "$output" run_installer "$root" check --binary "$binary" --config "$config"
    grep -Fq "Поддерживается wdtt-server версии 17" "$output" ||
        fail "несовместимая версия сервера отклонена без понятной ошибки"
    pass "несовместимая версия wdtt-server отклоняется"
}

test_network_preflight_requires_nat_and_default_route() {
    local sandbox root binary config output
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/output"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"

    expect_failure "$output" env \
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_NO_NAT_BACKEND=1 \
        "$INSTALLER" check --binary "$binary" --config "$config"
    grep -Fq "iptables или nftables" "$output" ||
        fail "нет понятной ошибки об отсутствии NAT-механизма"

    expect_failure "$output" env \
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_NO_DEFAULT_ROUTE=1 \
        "$INSTALLER" check --binary "$binary" --config "$config"
    grep -Fq "IPv4-маршрут по умолчанию" "$output" ||
        fail "нет понятной ошибки об отсутствии IPv4-маршрута по умолчанию"
    pass "предварительная проверка требует NAT-механизм и IPv4-маршрут по умолчанию"
}

test_nested_database_corruption_blocks_update() {
    local sandbox root binary config database pending output
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    database="$root/etc/wdtt/passwords.json"
    pending="$sandbox/database.json"
    output="$sandbox/output"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null

    jq '.passwords.broken = {expires_at: "not-a-number"}' "$database" >"$pending"
    chmod 0600 "$pending"
    mv "$pending" "$database"
    make_fake_binary "$binary" "12"

    expect_failure "$output" run_installer "$root" install --binary "$binary" --yes
    grep -Fq "некорректную или несовместимую структуру" "$output" ||
        fail "повреждение вложенной записи базы не объяснено"
    [[ "$("$root/usr/local/bin/wdtt-server" --build-id)" == "11" ]] ||
        fail "проверка повреждённой базы успела заменить сервер"
    pass "повреждение вложенной структуры базы блокирует обновление"
}

test_missing_wg_keys_blocks_update() {
    local sandbox root binary config output
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/output"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null
    rm -f "$root/etc/wdtt/wg-keys.dat"
    make_fake_binary "$binary" "12"

    expect_failure "$output" run_installer "$root" install --binary "$binary" --yes
    grep -Fq "WireGuard-ключи отсутствуют" "$output" ||
        fail "нет понятной ошибки об отсутствующих WG-ключах"
    [[ "$("$root/usr/local/bin/wdtt-server" --build-id)" == "11" ]] ||
        fail "обновление без WG-ключей изменило бинарник"
    pass "обновление без сохранённых WG-ключей запрещено"
}

test_port_change_requires_explicit_migration() {
    local sandbox root binary config output
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/output"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null
    make_fake_binary "$binary" "12"

    expect_failure "$output" run_installer "$root" install \
        --binary "$binary" \
        --dtls-port 56200 \
        --wg-port 56201 \
        --client-port 9200 \
        --yes
    grep -Fq "требует явного --migrate-ports" "$output" ||
        fail "смена портов не потребовала явной миграции"
    pass "смена портов требует явного подтверждения миграции"
}

test_port_migration_updates_owner_and_clients() {
    local sandbox root binary config database pending
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    database="$root/etc/wdtt/passwords.json"
    pending="$sandbox/database.json"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null

    jq '
        .admin_profile = {
            workers_per_hash: 16,
            protocol: "udp",
            listen_port: 9000,
            ports: "56000,56001,9000"
        } |
        .passwords.client = {
            expires_at: 0,
            ports: "56000,56001,9000"
        }
    ' "$database" >"$pending"
    chmod 0600 "$pending"
    mv "$pending" "$database"
    make_fake_binary "$binary" "12"

    run_installer "$root" install \
        --binary "$binary" \
        --dtls-port 56200 \
        --wg-port 56201 \
        --client-port 9200 \
        --migrate-ports \
        --yes >/dev/null

    [[ "$(jq -r '.default_ports' "$database")" == "56200,56201,9200" ]] ||
        fail "default_ports не мигрированы"
    [[ "$(jq -r '.admin_profile.ports' "$database")" == "56200,56201,9200" &&
        "$(jq -r '.admin_profile.listen_port' "$database")" == "9200" ]] ||
        fail "порты владельца не мигрированы"
    [[ "$(jq -r '.passwords.client.ports' "$database")" == "56200,56201,9200" ]] ||
        fail "порты клиента не мигрированы"
    pass "миграция обновляет default, владельца и клиентские ссылки"
}

test_network_health_failure_rolls_back() {
    local sandbox root binary config output
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/output"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"

    expect_failure "$output" env \
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_FAIL_NETWORK_HEALTH=1 \
        "$INSTALLER" install --binary "$binary" --config "$config" --yes
    [[ ! -e "$root/usr/local/bin/wdtt-server" &&
        ! -e "$root/etc/systemd/system/wdtt.service" &&
        ! -e "$root/var/lib/wdtt-server-installer/network-runtime.sh" ]] ||
        fail "сетевая проверка оставила частичную установку"
    pass "ошибка сетевой проверки полностью откатывает установку"
}

test_tampered_backup_manifest_blocks_recovery() {
    local sandbox root binary config output backup
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/output"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null
    make_fake_binary "$binary" "12"

    expect_failure "$output" env \
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_FAIL_AT=files_replaced \
        WDTT_INSTALLER_TEST_LEAVE_TRANSACTION=1 \
        "$INSTALLER" install --binary "$binary" --yes
    backup="$(
        find "$root/var/lib/wdtt-server-installer/backups" \
            -mindepth 1 -maxdepth 1 -type d | head -n 1
    )"
    [[ -n "$backup" && -f "$backup/MANIFEST" ]] ||
        fail "тест не создал манифест резервной копии"
    printf '\n' >>"$backup/config/passwords.json"

    expect_failure "$output" run_installer "$root" install --binary "$binary" --yes
    grep -Fq "резервная копия не прошла проверку" "$output" ||
        fail "повреждённый backup отклонён без понятной ошибки"
    [[ -f "$root/var/lib/wdtt-server-installer/transaction" ]] ||
        fail "журнал удалён несмотря на повреждённый backup"
    pass "повреждение манифеста или backup блокирует восстановление"
}

test_database_larger_than_old_limit_is_accepted() {
    local sandbox root binary config database pending
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    database="$root/etc/wdtt/passwords.json"
    pending="$sandbox/database.json"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null

    jq '.passwords.large = {expires_at: 0, label: ("x" * 6000000)}' \
        "$database" >"$pending"
    chmod 0600 "$pending"
    mv "$pending" "$database"
    (( $(stat -c '%s' "$database") > 5 * 1024 * 1024 )) ||
        fail "тестовая база не превысила старый лимит"

    run_installer "$root" check --binary "$binary" >/dev/null
    pass "валидная база больше 5 МиБ принимается"
}

test_owned_firewall_rule_moves_with_port() {
    local sandbox root binary config firewall_state
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    firewall_state="$root/var/lib/wdtt-server-installer/firewall-state"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"

    WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_FIREWALL=ufw \
        "$INSTALLER" install \
        --binary "$binary" \
        --config "$config" \
        --firewall open \
        --yes >/dev/null
    [[ -f "$root/var/lib/wdtt-server-installer/.test-firewall-56000" &&
        -f "$firewall_state" ]] ||
        fail "первое собственное firewall-правило не записано"

    make_fake_binary "$binary" "12"
    WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_FIREWALL=ufw \
        "$INSTALLER" install \
        --binary "$binary" \
        --dtls-port 56200 \
        --wg-port 56201 \
        --client-port 9200 \
        --migrate-ports \
        --firewall open \
        --yes >/dev/null

    [[ ! -e "$root/var/lib/wdtt-server-installer/.test-firewall-56000" &&
        -f "$root/var/lib/wdtt-server-installer/.test-firewall-56200" ]] ||
        fail "собственное firewall-правило не перенесено на новый порт"
    grep -Fxq "port=56200" "$firewall_state" ||
        fail "новый собственный firewall-порт не сохранён"
    pass "собственное firewall-правило переносится вместе с DTLS-портом"
}

test_managed_file_permissions_are_checked() {
    local sandbox root binary config output
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/check.out"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null

    chmod 0666 "$root/etc/systemd/system/wdtt.service"
    expect_failure "$output" run_installer "$root" check --binary "$binary"
    grep -Fq "небезопасный тип, права, владельца или hardlink" "$output" ||
        fail "check не объяснил небезопасные права управляемого unit"
    pass "check блокирует обновление при небезопасных правах управляемых файлов"
}

test_firewall_port_migration_rollback_restores_old_rule() {
    local sandbox root binary config output firewall_state
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/update.out"
    firewall_state="$root/var/lib/wdtt-server-installer/firewall-state"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"

    WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_FIREWALL=ufw \
        "$INSTALLER" install \
        --binary "$binary" \
        --config "$config" \
        --firewall open \
        --yes >/dev/null

    make_fake_binary "$binary" "12"
    expect_failure "$output" env \
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_FIREWALL=ufw \
        WDTT_INSTALLER_TEST_FAIL_AT=firewall_applied \
        "$INSTALLER" install \
        --binary "$binary" \
        --dtls-port 56300 \
        --wg-port 56301 \
        --client-port 9300 \
        --migrate-ports \
        --firewall open \
        --yes

    [[ -f "$root/var/lib/wdtt-server-installer/.test-firewall-56000" &&
        ! -e "$root/var/lib/wdtt-server-installer/.test-firewall-56300" ]] ||
        fail "откат миграции firewall не вернул старое правило"
    grep -Fxq "port=56000" "$firewall_state" ||
        fail "откат миграции firewall не вернул прежнее состояние владения"
    [[ "$(jq -r '.default_ports' "$root/etc/wdtt/passwords.json")" == "56000,56001,9000" ]] ||
        fail "откат миграции firewall не вернул прежние порты базы"
    pass "откат миграции порта возвращает прежнее firewall-правило"
}

test_interrupted_restore_can_resume() {
    local sandbox root binary config output
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/recovery.out"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null

    make_fake_binary "$binary" "12"
    expect_failure "$output" env \
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_FAIL_AT=files_replaced \
        WDTT_INSTALLER_TEST_LEAVE_TRANSACTION=1 \
        "$INSTALLER" install --binary "$binary" --yes

    make_fake_binary "$binary" "13"
    expect_failure "$output" env \
        WDTT_INSTALLER_TEST_MODE=1 \
        WDTT_INSTALLER_TEST_ROOT="$root" \
        WDTT_INSTALLER_TEST_FAIL_RESTORE_AFTER_CONFIG_MOVE=1 \
        "$INSTALLER" install --binary "$binary" --yes
    [[ -f "$root/var/lib/wdtt-server-installer/transaction" ]] ||
        fail "оборванное восстановление потеряло журнал"

    run_installer "$root" install --binary "$binary" --yes >/dev/null
    [[ "$("$root/usr/local/bin/wdtt-server" --build-id)" == "13" ]] ||
        fail "повтор не продолжил оборванное восстановление и обновление"
    [[ ! -e "$root/var/lib/wdtt-server-installer/transaction" ]] ||
        fail "после повторного восстановления остался журнал"
    [[ -z "$(find "$root/var/lib/wdtt-server-installer/backups" \
        -mindepth 2 -name failed-config -print -quit)" ]] ||
        fail "в подписанную резервную копию попало временное состояние"
    pass "оборванный откат безопасно продолжается следующим запуском"
}

test_state_directory_permissions_are_checked() {
    local sandbox root binary config output
    new_sandbox
    sandbox="$NEW_SANDBOX"
    root="$sandbox/root"
    binary="$sandbox/wdtt-server"
    config="$sandbox/initial.json"
    output="$sandbox/check.out"
    mkdir -p "$root"
    make_fake_binary "$binary" "11"
    make_config "$config" "SafeOwnerPassword42"
    run_installer "$root" install --binary "$binary" --config "$config" --yes >/dev/null

    chmod 0755 "$root/var/lib/wdtt-server-installer"
    expect_failure "$output" run_installer "$root" check --binary "$binary"
    grep -Fq "неизвестная или незавершённая установка" "$output" ||
        fail "небезопасный каталог состояния не перевёл установку в fail-closed"
    pass "небезопасные права каталога состояния блокируют действия"
}

printf '1..63\n'
test_help_and_syntax
test_menu_stays_open_after_failed_doctor
test_menu_firewall_settings_are_russian
test_menu_russian_back_key_works
test_single_latin_y_is_not_yes_confirmation
test_deploy_compatibility_contract
test_wizard_on_android_deploy_is_guidance_not_failure
test_rejects_open_config_permissions
test_dry_run_does_not_write
test_first_install_keeps_secrets_out_of_unit
test_owned_update_preserves_database
test_refuses_foreign_install
test_android_deploy_requires_explicit_adoption
test_android_backup_history_survives_adoption
test_android_adoption_requires_current_contract_marker
test_failed_android_adoption_restores_legacy_owner
test_handoff_android_preserves_data_and_allows_roundtrip
test_handoff_android_rejects_non_owned_install
test_failed_handoff_android_rolls_back_owner_and_data
test_handoff_android_preserves_owned_firewall_rule
test_failed_handoff_preserves_owned_firewall_rule
test_handoff_preserves_disabled_and_stopped_service
test_interrupted_committed_handoff_finishes_safely
test_regular_install_finishes_committed_handoff_recovery
test_failed_health_check_rolls_back_first_install
test_rejects_malformed_config
test_failed_update_restores_previous_binary
test_real_server_binary_passes_preflight
test_rejects_symlinked_test_root
test_init_config_creates_protected_file
test_init_config_never_overwrites
test_monitor_reports_safe_aggregates
test_update_preserves_custom_runtime_defaults
test_failed_update_restores_entire_config_tree
test_interrupted_update_recovers_before_retry
test_parallel_installer_is_rejected
test_route_collision_is_rejected
test_symlink_inside_config_is_rejected
test_doctor_reports_healthy_install
test_firewall_opt_in_adds_only_dtls_rule
test_firewall_default_does_not_change_rules
test_firewall_rule_rolls_back_on_failure
test_partial_first_replacement_rolls_back
test_owned_update_applies_selected_settings_atomically
test_existing_firewall_rule_survives_rollback
test_identical_repeat_is_noop
test_enabled_but_stopped_service_is_repaired
test_disabled_and_stopped_service_remains_noop
test_installer_version_difference_triggers_update
test_rejects_incompatible_server_version
test_network_preflight_requires_nat_and_default_route
test_nested_database_corruption_blocks_update
test_missing_wg_keys_blocks_update
test_port_change_requires_explicit_migration
test_port_migration_updates_owner_and_clients
test_network_health_failure_rolls_back
test_tampered_backup_manifest_blocks_recovery
test_database_larger_than_old_limit_is_accepted
test_owned_firewall_rule_moves_with_port
test_managed_file_permissions_are_checked
test_firewall_port_migration_rollback_restores_old_rule
test_interrupted_restore_can_resume
test_state_directory_permissions_are_checked
