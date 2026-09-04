#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly INSTALLER="$SCRIPT_DIR/install.sh"
readonly CONTRACT="$SCRIPT_DIR/compatibility-contract.env"
readonly LOCAL_SERVER="$SCRIPT_DIR/wdtt-server"
readonly LOCAL_SUMS="$SCRIPT_DIR/SHA256SUMS"
readonly SERVER_ASSET="$REPOSITORY_ROOT/app/src/main/assets/server"
readonly WARP_DIR="$REPOSITORY_ROOT/warp-interface-manager"
readonly WARP_SCRIPT="$WARP_DIR/warp-interface-manager.sh"
readonly WARP_README="$WARP_DIR/README.md"
readonly APK_DIR="$REPOSITORY_ROOT/app/build/outputs/apk/release/named"
readonly OUTPUTS_ROOT="$REPOSITORY_ROOT/app/build/outputs"
readonly READY_DIR="$OUTPUTS_ROOT/release-ready"
readonly LOCK_PATH="$OUTPUTS_ROOT/.server-installer-release.lock"

TEMP_ROOT=""

die() {
    printf 'Ошибка подготовки серверного комплекта: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    if [[ -n "$TEMP_ROOT" && "$TEMP_ROOT" == /tmp/wdtt-server-release.* &&
        -d "$TEMP_ROOT" && ! -L "$TEMP_ROOT" ]]; then
        find "$TEMP_ROOT" -mindepth 1 -delete 2>/dev/null || true
        rmdir "$TEMP_ROOT" 2>/dev/null || true
    fi
}
trap cleanup EXIT

usage() {
    cat <<'EOF'
Подготовка релизного комплекта WDTT Plus

Использование:
  release_bundle.sh prepare  Пересобрать локальный standalone-комплект,
                             создать единый каталог готовых файлов релиза и
                             сразу проверить его вместе со всеми APK.
  release_bundle.sh verify   Ничего не изменять; проверить уже подготовленный
                             каталог, архив, исходники и сервер внутри APK.
  release_bundle.sh invalidate
                             Удалить прежний каталог готового релиза перед
                             началом новой предрелизной сборки.

Готовые для загрузки на GitHub файлы появляются только в:
  app/build/outputs/release-ready/
EOF
}

require_commands() {
    local command_name
    for command_name in \
        awk basename cmp dirname file find flock git go grep gzip head install \
        mktemp mv readlink sed sha256sum sort stat tar tr unzip wc; do
        command -v "$command_name" >/dev/null 2>&1 ||
            die "не найдена обязательная команда $command_name"
    done
}

require_regular_file() {
    local path="$1"
    [[ -f "$path" && ! -L "$path" && "$(stat -c '%h' "$path")" == "1" ]] ||
        die "ожидался обычный файл без symlink/hardlink: $path"
}

read_single_assignment() {
    local path="$1" variable="$2" value
    value="$(
        awk -v variable="$variable" '
            $0 ~ "^[[:space:]]*val[[:space:]]+" variable "[[:space:]]*=" {
                line=$0
                sub(/^[^=]*=[[:space:]]*\"/, "", line)
                sub(/\"[[:space:]]*$/, "", line)
                print line
            }
        ' "$path"
    )"
    [[ -n "$value" && "$value" != *$'\n'* ]] ||
        die "не удалось однозначно прочитать $variable из $path"
    printf '%s' "$value"
}

validate_versions() {
    require_regular_file "$INSTALLER"
    require_regular_file "$CONTRACT"
    # shellcheck source=/dev/null
    source "$CONTRACT"
    [[ "${WDTT_SERVER_VERSION:-}" =~ ^[0-9]+$ ]] ||
        die "в compatibility-contract.env некорректна версия сервера"
    INSTALLER_VERSION="$($INSTALLER --version)"
    [[ "$INSTALLER_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
        die "install.sh сообщил некорректную версию: $INSTALLER_VERSION"
    APP_VERSION="$(read_single_assignment "$REPOSITORY_ROOT/app/build.gradle.kts" appVersionName)"
    [[ "$APP_VERSION" =~ ^[0-9]+$ ]] ||
        die "версия Android-приложения должна быть целым числом"
    BUNDLE_NAME="WDTT-Plus-server-v${WDTT_SERVER_VERSION}-installer-${INSTALLER_VERSION}-linux-amd64"
    ARCHIVE_NAME="$BUNDLE_NAME.tar.gz"
    ARCHIVE_SUM_NAME="$ARCHIVE_NAME.sha256"
    require_regular_file "$WARP_SCRIPT"
    require_regular_file "$WARP_README"
    WARP_VERSION="$(sed -n 's/^VERSION="\([0-9][0-9.]*\)"$/\1/p' "$WARP_SCRIPT")"
    [[ "$WARP_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
        die "не удалось однозначно прочитать версию WARP-менеджера"
    grep -Fqx "Документация соответствует версии скрипта \`$WARP_VERSION\`." "$WARP_README" ||
        die "README WARP-менеджера не соответствует версии $WARP_VERSION"
    WARP_BUNDLE_NAME="warp-interface-manager-v${WARP_VERSION}"
    WARP_ARCHIVE_NAME="$WARP_BUNDLE_NAME.tar.gz"
}

validate_linux_server() {
    local binary="$1" description version
    require_regular_file "$binary"
    [[ -x "$binary" ]] || die "серверный бинарник не исполняемый: $binary"
    description="$(file -b "$binary")"
    [[ "$description" == *"ELF 64-bit LSB"* && "$description" == *"x86-64"* ]] ||
        die "сервер должен быть Linux amd64 ELF: $description"
    [[ "$description" == *"statically linked"* ]] ||
        die "серверный бинарник должен быть статически слинкован"
    version="$($binary --version 2>/dev/null | head -n 1 || true)"
    [[ "$version" == "$WDTT_SERVER_VERSION" ]] ||
        die "сервер сообщил версию $version вместо $WDTT_SERVER_VERSION"
}

build_reference_server() {
    local target="$1"
    (
        cd "$REPOSITORY_ROOT"
        env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
            go build -buildvcs=false -trimpath -ldflags="-s -w" -o "$target" .
    )
    chmod 0755 "$target"
    validate_linux_server "$target"
}

verify_source_and_local_files() {
    local reference="$TEMP_ROOT/reference-wdtt-server"
    validate_linux_server "$SERVER_ASSET"
    validate_linux_server "$LOCAL_SERVER"
    build_reference_server "$reference"
    cmp -s "$reference" "$SERVER_ASSET" ||
        die "assets/server не совпадает с сервером, заново собранным из текущих исходников"
    cmp -s "$reference" "$LOCAL_SERVER" ||
        die "server-installer/wdtt-server не совпадает с текущими исходниками и Android-деплоем"
    require_regular_file "$LOCAL_SUMS"
    (
        cd "$SCRIPT_DIR"
        sha256sum -c SHA256SUMS >/dev/null
    ) || die "внутренний SHA256SUMS не соответствует install.sh и wdtt-server"
}

expected_release_files() {
    printf '%s\n' \
        "WDTT-Plus-v${APP_VERSION}-arm64-v8a-release.apk" \
        "WDTT-Plus-v${APP_VERSION}-armeabi-v7a-release.apk" \
        "WDTT-Plus-v${APP_VERSION}-universal-release.apk" \
        "WDTT-Plus-v${APP_VERSION}-x86_64-release.apk" \
        "$ARCHIVE_NAME" \
        "$ARCHIVE_SUM_NAME" \
        "$WARP_ARCHIVE_NAME" |
        LC_ALL=C sort
}

verify_exact_release_file_set() {
    local directory="$1" actual expected
    [[ -d "$directory" && ! -L "$directory" ]] ||
        die "нет каталога готового релиза: $directory"
    [[ -z "$(find "$directory" -mindepth 1 -maxdepth 1 ! -type f -print -quit)" ]] ||
        die "в каталоге релиза найдены не обычные файлы"
    actual="$(find "$directory" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort)"
    expected="$(expected_release_files)"
    [[ "$actual" == "$expected" ]] || {
        printf 'Ожидались файлы:\n%s\nНайдены файлы:\n%s\n' "$expected" "$actual" >&2
        die "каталог релиза содержит неполный, лишний или устаревший набор файлов"
    }
}

verify_archive() {
    local release_dir="$1"
    local archive="$release_dir/$ARCHIVE_NAME"
    local archive_sum="$release_dir/$ARCHIVE_SUM_NAME"
    local members expected_members extract_root extracted
    require_regular_file "$archive"
    require_regular_file "$archive_sum"
    [[ "$(wc -l <"$archive_sum" | tr -d ' ')" == "1" ]] ||
        die "внешняя контрольная сумма должна содержать ровно одну строку"
    (
        cd "$release_dir"
        sha256sum -c "$ARCHIVE_SUM_NAME" >/dev/null
    ) || die "внешняя контрольная сумма архива не совпала"

    members="$(tar -tzf "$archive")"
    expected_members="$(printf '%s\n' \
        "$BUNDLE_NAME/" \
        "$BUNDLE_NAME/SHA256SUMS" \
        "$BUNDLE_NAME/install.sh" \
        "$BUNDLE_NAME/wdtt-server")"
    [[ "$members" == "$expected_members" ]] ||
        die "архив содержит неожиданные пути или неполный комплект"

    extract_root="$TEMP_ROOT/extracted"
    install -d -m 0700 "$extract_root"
    tar --no-same-owner --same-permissions -xzf "$archive" -C "$extract_root"
    extracted="$extract_root/$BUNDLE_NAME"
    [[ -d "$extracted" && ! -L "$extracted" ]] || die "архив не создал ожидаемый каталог"
    [[ "$(stat -c '%a' "$extracted")" == "755" ]] || die "у каталога архива неверные права"
    require_regular_file "$extracted/install.sh"
    require_regular_file "$extracted/wdtt-server"
    require_regular_file "$extracted/SHA256SUMS"
    [[ "$(stat -c '%a' "$extracted/install.sh")" == "755" ]] ||
        die "у install.sh в архиве должны быть права 755"
    [[ "$(stat -c '%a' "$extracted/wdtt-server")" == "755" ]] ||
        die "у wdtt-server в архиве должны быть права 755"
    [[ "$(stat -c '%a' "$extracted/SHA256SUMS")" == "644" ]] ||
        die "у SHA256SUMS в архиве должны быть права 644"
    cmp -s "$INSTALLER" "$extracted/install.sh" || die "в архив попал другой install.sh"
    cmp -s "$LOCAL_SERVER" "$extracted/wdtt-server" || die "в архив попал другой wdtt-server"
    cmp -s "$LOCAL_SUMS" "$extracted/SHA256SUMS" || die "в архив попал другой SHA256SUMS"
    (
        cd "$extracted"
        sha256sum -c SHA256SUMS >/dev/null
    ) || die "внутренние суммы распакованного комплекта не совпали"
    [[ "$($extracted/install.sh --version)" == "$INSTALLER_VERSION" ]] ||
        die "версия install.sh изменилась внутри архива"
    validate_linux_server "$extracted/wdtt-server"
}

verify_warp_archive() {
    local release_dir="$1"
    local archive="$release_dir/$WARP_ARCHIVE_NAME"
    local members expected_members extract_root extracted
    require_regular_file "$archive"
    members="$(tar -tzf "$archive")"
    expected_members="$(printf '%s\n' \
        "$WARP_BUNDLE_NAME/" \
        "$WARP_BUNDLE_NAME/README.md" \
        "$WARP_BUNDLE_NAME/SHA256SUMS" \
        "$WARP_BUNDLE_NAME/warp-interface-manager.sh")"
    [[ "$members" == "$expected_members" ]] ||
        die "архив WARP-менеджера содержит неожиданные пути или неполный комплект"

    extract_root="$TEMP_ROOT/warp-extracted"
    install -d -m 0700 "$extract_root"
    tar --no-same-owner --same-permissions -xzf "$archive" -C "$extract_root"
    extracted="$extract_root/$WARP_BUNDLE_NAME"
    [[ -d "$extracted" && ! -L "$extracted" ]] ||
        die "архив WARP-менеджера не создал ожидаемый каталог"
    require_regular_file "$extracted/README.md"
    require_regular_file "$extracted/SHA256SUMS"
    require_regular_file "$extracted/warp-interface-manager.sh"
    [[ "$(stat -c '%a' "$extracted/README.md")" == "644" ]] ||
        die "у README.md в WARP-архиве должны быть права 644"
    [[ "$(stat -c '%a' "$extracted/SHA256SUMS")" == "644" ]] ||
        die "у SHA256SUMS в WARP-архиве должны быть права 644"
    [[ "$(stat -c '%a' "$extracted/warp-interface-manager.sh")" == "755" ]] ||
        die "у WARP-скрипта в архиве должны быть права 755"
    cmp -s "$WARP_README" "$extracted/README.md" ||
        die "в WARP-архив попал другой README.md"
    cmp -s "$WARP_SCRIPT" "$extracted/warp-interface-manager.sh" ||
        die "в WARP-архив попал другой скрипт"
    (
        cd "$extracted"
        sha256sum -c SHA256SUMS >/dev/null
    ) || die "внутренние суммы WARP-архива не совпали"
    [[ "$("$extracted/warp-interface-manager.sh" --version | awk '{ print $NF }')" == "$WARP_VERSION" ]] ||
        die "версия WARP-скрипта изменилась внутри архива"
}

verify_apks() {
    local release_dir="$1" abi apk extracted_server
    for abi in arm64-v8a armeabi-v7a x86_64 universal; do
        extracted_server="$TEMP_ROOT/apk-server-$abi"
        apk="$release_dir/WDTT-Plus-v${APP_VERSION}-${abi}-release.apk"
        require_regular_file "$apk"
        unzip -p "$apk" assets/server >"$extracted_server" ||
            die "в APK $abi отсутствует assets/server"
        chmod 0755 "$extracted_server"
        cmp -s "$LOCAL_SERVER" "$extracted_server" ||
            die "сервер в APK $abi не совпадает со standalone-комплектом"
        validate_linux_server "$extracted_server"
        if unzip -Z1 "$apk" | grep -Eq '(^|/)server-installer(\.sh|/|$)'; then
            die "standalone-установщик ошибочно попал внутрь APK $abi"
        fi
        if unzip -Z1 "$apk" | grep -Eq '(^|/)warp-interface-manager(\.sh|/|$)'; then
            die "WARP-менеджер ошибочно попал внутрь APK $abi"
        fi
    done
}

verify_release_set() {
    local release_dir="$1"
    verify_source_and_local_files
    verify_exact_release_file_set "$release_dir"
    verify_archive "$release_dir"
    verify_warp_archive "$release_dir"
    verify_apks "$release_dir"
}

write_local_standalone_files() {
    local pending_server="$SCRIPT_DIR/.wdtt-server.new.$$"
    local pending_sums="$SCRIPT_DIR/.SHA256SUMS.new.$$"
    install -m 0755 "$SERVER_ASSET" "$pending_server"
    cmp -s "$SERVER_ASSET" "$pending_server" || die "не удалось проверить копию серверного бинарника"
    mv -f "$pending_server" "$LOCAL_SERVER"
    (
        cd "$SCRIPT_DIR"
        sha256sum install.sh wdtt-server >"$pending_sums"
    )
    chmod 0644 "$pending_sums"
    mv -f "$pending_sums" "$LOCAL_SUMS"
}

create_archive() {
    local release_stage="$1"
    local content_root="$TEMP_ROOT/content"
    local bundle_dir="$content_root/$BUNDLE_NAME"
    local archive_pending="$release_stage/$ARCHIVE_NAME.new"
    local epoch
    epoch="${SOURCE_DATE_EPOCH:-$(git -C "$REPOSITORY_ROOT" log -1 --format=%ct)}"
    [[ "$epoch" =~ ^[0-9]+$ ]] || die "SOURCE_DATE_EPOCH должен быть Unix-временем"
    install -d -m 0755 "$bundle_dir"
    install -m 0755 "$INSTALLER" "$bundle_dir/install.sh"
    install -m 0755 "$LOCAL_SERVER" "$bundle_dir/wdtt-server"
    install -m 0644 "$LOCAL_SUMS" "$bundle_dir/SHA256SUMS"
    (
        cd "$content_root"
        LC_ALL=C tar \
            --sort=name \
            --mtime="@$epoch" \
            --owner=0 \
            --group=0 \
            --numeric-owner \
            --format=posix \
            --pax-option=delete=atime,delete=ctime \
            -cf - "$BUNDLE_NAME" | gzip -n >"$archive_pending"
    )
    mv -f "$archive_pending" "$release_stage/$ARCHIVE_NAME"
    (
        cd "$release_stage"
        sha256sum "$ARCHIVE_NAME" >"$ARCHIVE_SUM_NAME"
    )
    chmod 0644 "$release_stage/$ARCHIVE_NAME" "$release_stage/$ARCHIVE_SUM_NAME"
}

create_warp_archive() {
    local release_stage="$1"
    local content_root="$TEMP_ROOT/warp-content"
    local bundle_dir="$content_root/$WARP_BUNDLE_NAME"
    local archive_pending="$release_stage/$WARP_ARCHIVE_NAME.new"
    local epoch
    epoch="${SOURCE_DATE_EPOCH:-$(git -C "$REPOSITORY_ROOT" log -1 --format=%ct)}"
    [[ "$epoch" =~ ^[0-9]+$ ]] || die "SOURCE_DATE_EPOCH должен быть Unix-временем"
    install -d -m 0755 "$bundle_dir"
    install -m 0644 "$WARP_README" "$bundle_dir/README.md"
    install -m 0755 "$WARP_SCRIPT" "$bundle_dir/warp-interface-manager.sh"
    (
        cd "$bundle_dir"
        sha256sum README.md warp-interface-manager.sh >SHA256SUMS
    )
    chmod 0644 "$bundle_dir/SHA256SUMS"
    (
        cd "$content_root"
        LC_ALL=C tar \
            --sort=name \
            --mtime="@$epoch" \
            --owner=0 \
            --group=0 \
            --numeric-owner \
            --format=posix \
            --pax-option=delete=atime,delete=ctime \
            -cf - "$WARP_BUNDLE_NAME" | gzip -n >"$archive_pending"
    )
    mv -f "$archive_pending" "$release_stage/$WARP_ARCHIVE_NAME"
    chmod 0644 "$release_stage/$WARP_ARCHIVE_NAME"
}

copy_release_apks() {
    local release_stage="$1" abi source target
    for abi in arm64-v8a armeabi-v7a x86_64 universal; do
        source="$APK_DIR/WDTT-Plus-v${APP_VERSION}-${abi}-release.apk"
        target="$release_stage/$(basename "$source")"
        require_regular_file "$source"
        install -m 0644 "$source" "$target"
        cmp -s "$source" "$target" || die "не удалось проверить копию APK $abi"
    done
}

replace_ready_directory() {
    local stage="$1" old="$OUTPUTS_ROOT/.release-ready.old.$$"
    [[ "$READY_DIR" == "$REPOSITORY_ROOT/app/build/outputs/release-ready" ]] ||
        die "небезопасный путь итогового каталога"
    if [[ -e "$READY_DIR" || -L "$READY_DIR" ]]; then
        [[ -d "$READY_DIR" && ! -L "$READY_DIR" ]] ||
            die "существующий release-ready имеет небезопасный тип"
        mv "$READY_DIR" "$old"
    fi
    if ! mv "$stage" "$READY_DIR"; then
        [[ ! -d "$old" ]] || mv "$old" "$READY_DIR"
        die "не удалось атомарно установить каталог release-ready"
    fi
    if [[ -d "$old" && ! -L "$old" ]]; then
        find "$old" -mindepth 1 -delete
        rmdir "$old"
    fi
}

invalidate_ready_directory() {
    [[ "$READY_DIR" == "$REPOSITORY_ROOT/app/build/outputs/release-ready" ]] ||
        die "небезопасный путь итогового каталога"
    [[ ! -e "$READY_DIR" && ! -L "$READY_DIR" ]] && return 0
    [[ -d "$READY_DIR" && ! -L "$READY_DIR" ]] ||
        die "существующий release-ready имеет небезопасный тип"
    find "$READY_DIR" -mindepth 1 -delete
    rmdir "$READY_DIR"
}

prepare_release() {
    invalidate_ready_directory
    require_regular_file "$SERVER_ASSET"
    [[ -d "$APK_DIR" && ! -L "$APK_DIR" ]] ||
        die "сначала должна успешно завершиться release-сборка APK"
    validate_linux_server "$SERVER_ASSET"
    write_local_standalone_files
    verify_source_and_local_files

    local release_stage="$OUTPUTS_ROOT/.release-ready.stage.$$"
    [[ ! -e "$release_stage" && ! -L "$release_stage" ]] ||
        die "временный каталог уже существует"
    install -d -m 0755 "$release_stage"
    create_archive "$release_stage"
    create_warp_archive "$release_stage"
    copy_release_apks "$release_stage"
    verify_release_set "$release_stage"
    replace_ready_directory "$release_stage"
    printf 'Готовый проверенный набор релиза: %s\n' "$READY_DIR"
    expected_release_files | sed 's/^/  /'
}

main() {
    local mode="${1:-}"
    [[ $# -eq 1 ]] || { usage; exit 2; }
    case "$mode" in
        prepare|verify|invalidate) ;;
        -h|--help|help) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
    require_commands
    validate_versions
    install -d -m 0755 "$OUTPUTS_ROOT"
    exec 9>"$LOCK_PATH"
    if [[ "$mode" == "prepare" || "$mode" == "invalidate" ]]; then
        flock -n 9 || die "другая подготовка релиза уже выполняется"
    else
        flock -s -n 9 || die "комплект сейчас изменяется другой подготовкой релиза"
    fi
    TEMP_ROOT="$(mktemp -d /tmp/wdtt-server-release.XXXXXX)"
    chmod 0700 "$TEMP_ROOT"
    case "$mode" in
        prepare)
            prepare_release
            ;;
        verify)
            verify_release_set "$READY_DIR"
            printf 'Релизный набор проверен: APK и standalone содержат один wdtt-server v%s.\n' \
                "$WDTT_SERVER_VERSION"
            ;;
        invalidate)
            invalidate_ready_directory
            printf 'Прежний каталог release-ready удалён перед новой сборкой.\n'
            ;;
    esac
}

main "$@"
