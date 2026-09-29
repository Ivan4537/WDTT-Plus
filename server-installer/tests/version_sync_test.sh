#!/usr/bin/env bash

set -euo pipefail

readonly TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPOSITORY_ROOT="$(cd "$TEST_DIR/../.." && pwd)"
readonly CONTRACT="$REPOSITORY_ROOT/server-installer/compatibility-contract.env"
readonly ANDROID_BUILD="$REPOSITORY_ROOT/app/build.gradle.kts"
readonly SERVER="$REPOSITORY_ROOT/server.go"
readonly DEPLOY="$REPOSITORY_ROOT/app/src/main/assets/deploy.sh"
readonly INSTALLER="$REPOSITORY_ROOT/server-installer/install.sh"
readonly INSTALLER_README="$REPOSITORY_ROOT/server-installer/README.md"
readonly CHANGELOG="$REPOSITORY_ROOT/CHANGELOG.md"

fail() {
    printf 'FAIL: синхронизация версий: %s\n' "$*" >&2
    exit 1
}

read_kotlin_string() {
    local name="$1" value
    value="$(sed -n "s/^[[:space:]]*val[[:space:]]\+$name[[:space:]]*=[[:space:]]*\"\([0-9][0-9]*\)\"[[:space:]]*$/\1/p" "$ANDROID_BUILD")"
    [[ -n "$value" && "$value" != *$'\n'* ]] || fail "не удалось прочитать $name"
    printf '%s' "$value"
}

read_kotlin_integer() {
    local name="$1" value
    value="$(sed -n "s/^[[:space:]]*val[[:space:]]\+$name[[:space:]]*=[[:space:]]*\([0-9][0-9]*\)[[:space:]]*$/\1/p" "$ANDROID_BUILD")"
    [[ -n "$value" && "$value" != *$'\n'* ]] || fail "не удалось прочитать $name"
    printf '%s' "$value"
}

read_android_version_code() {
    local value
    value="$(sed -n 's/^[[:space:]]*versionCode[[:space:]]*=[[:space:]]*\([0-9][0-9]*\)[[:space:]]*$/\1/p' "$ANDROID_BUILD")"
    [[ -n "$value" && "$value" != *$'\n'* ]] || fail "не удалось прочитать Android versionCode"
    printf '%s' "$value"
}

[[ -f "$CONTRACT" && ! -L "$CONTRACT" ]] || fail "нет канонического контракта"
# shellcheck source=/dev/null
source "$CONTRACT"
[[ "${WDTT_SERVER_VERSION:-}" =~ ^[0-9]+$ ]] || fail "в контракте некорректна версия сервера"

app_name="$(read_kotlin_string appVersionName)"
app_code="$(read_kotlin_integer appVersionCode)"
android_code="$(read_android_version_code)"
[[ "$app_name" == "$WDTT_SERVER_VERSION" ]] ||
    fail "appVersionName=$app_name, сервер=$WDTT_SERVER_VERSION"
[[ "$app_code" == "$WDTT_SERVER_VERSION" ]] ||
    fail "appVersionCode=$app_code, сервер=$WDTT_SERVER_VERSION"
[[ "$android_code" == "$app_code" ]] ||
    fail "Android versionCode=$android_code, appVersionCode=$app_code"

grep -Eq "wdttServerVersion[[:space:]]*=[[:space:]]*\"$WDTT_SERVER_VERSION\"" "$SERVER" ||
    fail "server.go не соответствует версии $WDTT_SERVER_VERSION"
grep -Fxq "readonly WDTT_SERVER_VERSION=\"$WDTT_SERVER_VERSION\"" "$DEPLOY" ||
    fail "Android-установщик не соответствует версии $WDTT_SERVER_VERSION"
grep -Fxq "readonly SUPPORTED_SERVER_VERSION=\"$WDTT_SERVER_VERSION\"" "$INSTALLER" ||
    fail "ручной установщик не соответствует версии $WDTT_SERVER_VERSION"

installer_version="$(sed -n 's/^readonly INSTALLER_VERSION="\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)"$/\1/p' "$INSTALLER")"
[[ -n "$installer_version" && "$installer_version" != *$'\n'* ]] ||
    fail "не удалось прочитать отдельную версию ручного установщика"
installer_intro="$(sed -n '1,16p' "$INSTALLER_README")"
grep -Fq "\`wdtt-server\` версии \`$WDTT_SERVER_VERSION\`" <<<"$installer_intro" ||
    fail "инструкция ручной установки указывает другую версию сервера"
grep -Fq "автономный установщик \`$installer_version\`" <<<"$installer_intro" ||
    fail "инструкция ручной установки указывает другую версию скрипта"
bundle_name="WDTT-Plus-server-v${WDTT_SERVER_VERSION}-installer-${installer_version}-linux-amd64.tar.gz"
grep -Fxq "$bundle_name" "$INSTALLER_README" ||
    fail "имя серверного архива в инструкции не соответствует выпуску"
grep -Fxq "$bundle_name.sha256" "$INSTALLER_README" ||
    fail "имя контрольной суммы в инструкции не соответствует выпуску"

first_changelog_version="$(sed -n 's/^## v\([0-9][0-9]*\).*/\1/p' "$CHANGELOG" | head -n 1)"
[[ "$first_changelog_version" == "$WDTT_SERVER_VERSION" ]] ||
    fail "верхняя версия CHANGELOG=$first_changelog_version, ожидается $WDTT_SERVER_VERSION"

printf 'Совместимость версий подтверждена: приложение и сервер v%s, ручной установщик %s.\n' \
    "$WDTT_SERVER_VERSION" "$installer_version"
