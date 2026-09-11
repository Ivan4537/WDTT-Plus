#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

readonly TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPOSITORY_ROOT="$(cd "$TEST_DIR/../.." && pwd)"
readonly CONTRACT="$REPOSITORY_ROOT/server-installer/compatibility-contract.env"
readonly INSTALLER="$REPOSITORY_ROOT/server-installer/install.sh"
readonly STANDALONE_BINARY="$REPOSITORY_ROOT/server-installer/wdtt-server"
readonly RELEASE_CHECKSUMS="$REPOSITORY_ROOT/server-installer/SHA256SUMS"
readonly RELEASE_BUNDLE="$REPOSITORY_ROOT/server-installer/release_bundle.sh"
readonly DEPLOY="$REPOSITORY_ROOT/app/src/main/assets/deploy.sh"
readonly DEPLOY_TAB="$REPOSITORY_ROOT/app/src/main/java/com/wdtt/plus/ui/DeployTab.kt"
readonly ANDROID_BUILD="$REPOSITORY_ROOT/app/build.gradle.kts"
readonly PACKAGED_INSTALLER="$REPOSITORY_ROOT/app/src/main/assets/server-installer.sh"
readonly SERVER="$REPOSITORY_ROOT/server.go"

fail() {
    printf 'FAIL: совместимость Android-деплоя и standalone: %s\n' "$*" >&2
    exit 1
}

require_exact_line() {
    local file="$1" expected="$2"
    grep -Fqx "$expected" "$file" ||
        fail "в $(basename "$file") нет обязательной строки: $expected"
}

require_text() {
    local file="$1" expected="$2"
    grep -Fq "$expected" "$file" ||
        fail "в $(basename "$file") отсутствует обязательная защита: $expected"
}

reject_text() {
    local file="$1" unexpected="$2"
    if grep -Fq "$unexpected" "$file"; then
        fail "в $(basename "$file") найдена запрещённая связь Android со standalone: $unexpected"
    fi
}

[[ -f "$CONTRACT" && ! -L "$CONTRACT" ]] || fail "нет канонического compatibility-contract.env"
# shellcheck source=/dev/null
source "$CONTRACT"

for key in \
    WDTT_DEPLOY_CONTRACT_VERSION \
    WDTT_SERVER_VERSION \
    WDTT_SERVER_BINARY_PATH \
    WDTT_SYSTEMD_UNIT_PATH \
    WDTT_CONFIG_DIRECTORY \
    WDTT_ACCESS_DATABASE \
    WDTT_WG_KEYS_FILE \
    WDTT_ANDROID_DEPLOY_MARKER \
    WDTT_ANDROID_CONTRACT_MARKER \
    WDTT_ANDROID_PRESERVED_MARKER; do
    [[ -n "${!key:-}" ]] || fail "в контракте пустое поле $key"
done

require_exact_line "$INSTALLER" "readonly SUPPORTED_SERVER_VERSION=\"$WDTT_SERVER_VERSION\""
require_exact_line "$INSTALLER" "readonly DEPLOY_COMPATIBILITY_VERSION=\"$WDTT_DEPLOY_CONTRACT_VERSION\""
require_exact_line "$INSTALLER" "readonly ANDROID_DEPLOY_MARKER=\"$WDTT_ANDROID_DEPLOY_MARKER\""
require_exact_line "$INSTALLER" "readonly ANDROID_PRESERVED_MARKER=\"$WDTT_ANDROID_PRESERVED_MARKER\""
require_exact_line "$INSTALLER" \
    "readonly ANDROID_DEPLOY_COMPATIBILITY_MARKER=\"WDTT deploy compatibility: \$DEPLOY_COMPATIBILITY_VERSION\""
require_text "$INSTALLER" 'install.sh handoff-android [--dry-run] [--yes]'
require_text "$INSTALLER" 'write_android_handoff_unit()'
require_text "$INSTALLER" '# $ANDROID_DEPLOY_MARKER'
require_text "$INSTALLER" '# $ANDROID_DEPLOY_COMPATIBILITY_MARKER'
require_text "$INSTALLER" '[[ "$initial_kind" == "owned" ]]'
require_text "$INSTALLER" 'confirm_handoff'
[[ -f "$RELEASE_BUNDLE" && ! -L "$RELEASE_BUNDLE" && -x "$RELEASE_BUNDLE" ]] ||
    fail "нет безопасного исполняемого release_bundle.sh"
bash -n "$RELEASE_BUNDLE" || fail "release_bundle.sh содержит синтаксическую ошибку"
require_text "$RELEASE_BUNDLE" 'cmp -s "$reference" "$SERVER_ASSET"'
require_text "$RELEASE_BUNDLE" 'cmp -s "$reference" "$LOCAL_SERVER"'
require_text "$RELEASE_BUNDLE" 'cmp -s "$LOCAL_SERVER" "$extracted_server"'
require_text "$RELEASE_BUNDLE" 'verify_exact_release_file_set'
require_text "$RELEASE_BUNDLE" 'sha256sum "$ARCHIVE_NAME" >"$ARCHIVE_SUM_NAME"'

require_exact_line "$DEPLOY" "readonly WDTT_DEPLOY_CONTRACT_VERSION=\"$WDTT_DEPLOY_CONTRACT_VERSION\""
require_exact_line "$DEPLOY" "readonly WDTT_SERVER_VERSION=\"$WDTT_SERVER_VERSION\""
require_exact_line "$DEPLOY" "readonly WDTT_SERVER_BINARY_PATH=\"$WDTT_SERVER_BINARY_PATH\""
require_exact_line "$DEPLOY" "readonly WDTT_SYSTEMD_UNIT_PATH=\"$WDTT_SYSTEMD_UNIT_PATH\""
require_exact_line "$DEPLOY" "readonly WDTT_CONFIG_DIR=\"$WDTT_CONFIG_DIRECTORY\""
require_exact_line "$DEPLOY" "readonly WDTT_ACCESS_DB=\"$WDTT_ACCESS_DATABASE\""
require_exact_line "$DEPLOY" "readonly WDTT_WG_KEYS=\"$WDTT_WG_KEYS_FILE\""
require_exact_line "$DEPLOY" "readonly WDTT_ANDROID_DEPLOY_MARKER=\"$WDTT_ANDROID_DEPLOY_MARKER\""
require_exact_line "$DEPLOY" "readonly WDTT_ANDROID_CONTRACT_MARKER=\"$WDTT_ANDROID_CONTRACT_MARKER\""
require_exact_line "$DEPLOY" "readonly WDTT_ANDROID_PRESERVED_MARKER=\"$WDTT_ANDROID_PRESERVED_MARKER\""

grep -Fq 'ExecStart=${WDTT_SERVER_BINARY_PATH} -listen ' "$DEPLOY" ||
    fail "Android unit не запускает бинарник из контракта"
grep -Fq '# ${WDTT_ANDROID_DEPLOY_MARKER}' "$DEPLOY" ||
    fail "Android unit не записывает метку владельца"
grep -Fq '# ${WDTT_ANDROID_CONTRACT_MARKER}' "$DEPLOY" ||
    fail "Android unit не записывает версию контракта"
grep -Fq 'server_version="$("$WDTT_SERVER_BINARY_PATH" --version' "$DEPLOY" ||
    fail "Android-деплой не проверяет версию установленного бинарника"
grep -Fq '[ "$server_version" = "$WDTT_SERVER_VERSION" ]' "$DEPLOY" ||
    fail "Android-деплой не сравнивает версию бинарника с контрактом"

grep -Eq "wdttServerVersion[[:space:]]*=[[:space:]]*\"$WDTT_SERVER_VERSION\"" "$SERVER" ||
    fail "Go-сервер не соответствует версии из контракта"

# Готовый standalone-комплект должен соответствовать текущему корневому Go-коду,
# а не только сообщать тот же номер версии.
temporary_binary="$(mktemp)"
trap 'rm -f "$temporary_binary"' EXIT
(
    cd "$REPOSITORY_ROOT"
    env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
        go build -buildvcs=false -trimpath -ldflags="-s -w" -o "$temporary_binary" .
) || fail "не удалось пересобрать корневой wdtt-server для сверки"
if [[ -e "$STANDALONE_BINARY" || -L "$STANDALONE_BINARY" || -e "$RELEASE_CHECKSUMS" || -L "$RELEASE_CHECKSUMS" ]]; then
    [[ -f "$STANDALONE_BINARY" && ! -L "$STANDALONE_BINARY" && -x "$STANDALONE_BINARY" ]] ||
        fail "локальный release-комплект неполон: нет безопасного исполняемого wdtt-server"
    [[ -f "$RELEASE_CHECKSUMS" && ! -L "$RELEASE_CHECKSUMS" ]] ||
        fail "локальный release-комплект неполон: нет SHA256SUMS"
    cmp -s "$temporary_binary" "$STANDALONE_BINARY" ||
        fail "готовый standalone-бинарник отстал от корневого Go-кода; пересоберите комплект"
    (
        cd "$REPOSITORY_ROOT/server-installer"
        sha256sum -c SHA256SUMS >/dev/null
    ) || fail "SHA256SUMS не соответствует текущим install.sh и wdtt-server"
fi

# Standalone остаётся отдельным операторским инструментом: Android обязан
# распознать его владение и остановить изменение, но не должен упаковывать,
# загружать или запускать install.sh из APK.
[[ -f "$DEPLOY_TAB" && ! -L "$DEPLOY_TAB" ]] ||
    fail "не найден исходник вкладки Android-деплоя"
[[ -f "$ANDROID_BUILD" && ! -L "$ANDROID_BUILD" ]] ||
    fail "не найден Android build.gradle.kts"
[[ ! -e "$PACKAGED_INSTALLER" && ! -L "$PACKAGED_INSTALLER" ]] ||
    fail "standalone install.sh не должен находиться в Android assets"
reject_text "$ANDROID_BUILD" 'buildStandaloneInstallerAsset'
reject_text "$ANDROID_BUILD" 'verifyDeployInstallerCompatibility'
reject_text "$ANDROID_BUILD" 'src/main/assets/server-installer.sh'
require_text "$ANDROID_BUILD" 'rootProject.file("server-installer/release_bundle.sh")'
require_text "$ANDROID_BUILD" 'tasks.register<Exec>("invalidateGithubReleaseArtifacts")'
require_text "$ANDROID_BUILD" 'tasks.register<Exec>("prepareGithubReleaseArtifacts")'
require_text "$ANDROID_BUILD" 'tasks.register<Exec>("verifyGithubReleaseArtifacts")'
require_text "$ANDROID_BUILD" 'dependsOn(invalidateGithubReleaseArtifacts, "assembleRelease", "auditReleaseApks")'
require_text "$ANDROID_BUILD" 'finalizedBy(auditReleaseApks)'
require_text "$ANDROID_BUILD" 'tasks.configureEach {'
require_text "$ANDROID_BUILD" 'name != "invalidateGithubReleaseArtifacts"'
require_text "$ANDROID_BUILD" 'mustRunAfter(invalidateGithubReleaseArtifacts)'
reject_text "$DEPLOY_TAB" 'context.assets.open("server-installer.sh")'
reject_text "$DEPLOY_TAB" 'ssh.upload(installerFile, "/tmp/wdtt-server-installer.sh"'
reject_text "$DEPLOY_TAB" '"bash /tmp/wdtt-server-installer.sh install "'
require_text "$DEPLOY_TAB" 'ownership == DeploymentOwnership.StandaloneInstaller -> throw IllegalStateException('
require_text "$DEPLOY_TAB" 'Android-приложение не обновляет'
require_text "$DEPLOY_TAB" 'используйте server-installer/install.sh на VPS'
require_text "$DEPLOY_TAB" 'assertAndroidDeployMayManageServer(ssh, "удаления")'
require_text "$DEPLOY_TAB" 'enabled = resetAllowed'
require_text "$DEPLOY_TAB" 'checkSucceeded && ownership in setOf('
require_text "$DEPLOY_TAB" 'DeploymentOwnership.IncompleteAndroidDeploy'
require_text "$DEPLOY_TAB" 'DeploymentOwnership.PreservedAndroidData'
require_text "$DEPLOY_TAB" "'Preserved by WDTT Plus Android deploy'"
require_text "$DEPLOY_TAB" 'incompleteAndroidDeployCandidate'
require_text "$INSTALLER" 'is_preserved_android_data()'
require_text "$INSTALLER" 'android-preserved)'
require_text "$INSTALLER" 'adopt-preserved'

probe_source="$(
    sed -n \
        '/internal fun standaloneInstallerOwnershipProbeScript/,/^internal fun deploymentOwnershipFromProbe/p' \
        "$DEPLOY_TAB"
)"
grep -Fq "printf 'WDTT_STANDALONE_MANAGED=1\n'" <<<"$probe_source" ||
    fail "проверка владельца не разделяет machine-маркеры настоящими строками"
if grep -Fq '\\n' <<<"$probe_source"; then
    fail "raw-строка проверки владельца печатает буквальный \\n вместо перевода строки"
fi

actual_contract="$($INSTALLER compatibility --machine)"
grep -Fxq "contract_version=$WDTT_DEPLOY_CONTRACT_VERSION" <<<"$actual_contract" ||
    fail "standalone не сообщает версию контракта"
grep -Fxq "server_version=$WDTT_SERVER_VERSION" <<<"$actual_contract" ||
    fail "standalone сообщает другую версию сервера"
grep -Fxq "binary=$WDTT_SERVER_BINARY_PATH" <<<"$actual_contract" ||
    fail "standalone сообщает другой путь бинарника"
grep -Fxq "unit=$WDTT_SYSTEMD_UNIT_PATH" <<<"$actual_contract" ||
    fail "standalone сообщает другой путь unit"
grep -Fxq "config=$WDTT_CONFIG_DIRECTORY" <<<"$actual_contract" ||
    fail "standalone сообщает другой каталог конфигурации"
grep -Fxq "database=$WDTT_ACCESS_DATABASE" <<<"$actual_contract" ||
    fail "standalone сообщает другую базу"
grep -Fxq "wg_keys=$WDTT_WG_KEYS_FILE" <<<"$actual_contract" ||
    fail "standalone сообщает другой файл ключей"
grep -Fxq "preserved_marker=$WDTT_ANDROID_PRESERVED_MARKER" <<<"$actual_contract" ||
    fail "standalone сообщает другую метку сохранённых Android-данных"

printf 'Контракт совместимости %s согласован: Android-деплой, standalone-установщик и wdtt-server v%s.\n' \
    "$WDTT_DEPLOY_CONTRACT_VERSION" "$WDTT_SERVER_VERSION"
