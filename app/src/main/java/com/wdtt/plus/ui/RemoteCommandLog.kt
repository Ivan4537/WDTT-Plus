package com.wdtt.plus.ui

internal enum class RemoteLogCategory { Info, Warning, Error, Technical }
internal data class RemoteLogEvent(val category: RemoteLogCategory, val message: String)

private val machineMarker = Regex("^[A-Z][A-Z0-9_]*=.*$")
private val systemdLink = Regex("""^Created symlink .+ (?:→|->) .+\.$""")
private val systemdRemoved = Regex("""^Removed ["']?.+["']?\.$""")
private val warningMessage = Regex("""(?i)(^|\s)(warning:|warn:|W:|предупреждение:)|deprecated|deprecat(?:ion|ed)|The unit files have no installation config|not meant to be enabled|non-existent unit|debconf: delaying package configuration""")
private val errorMessage = Regex("""(?i)^\s*(?:\[✗]|FAIL:|E:|error:|fatal:|ошибка:)|\b(?:error|failed|failure|fatal)\b|permission denied|access denied|not found|no such file|cannot |could not |не удалось|отказано в доступе""")

/** stderr is an output channel, not a severity. Unknown text follows the command result. */
internal fun classifyRemoteCommandLine(line: String, exitStatus: Int = 0, stderr: Boolean = false): RemoteLogEvent {
    val clean = line.replace(Regex("\u001B\\[[;\\d]*[A-Za-z]"), "").trim()
    fun event(category: RemoteLogCategory, message: String = clean) = RemoteLogEvent(category, message)
    if (clean.isBlank() || machineMarker.matches(clean) || clean.startsWith("WDTT_PROGRESS|") ||
        clean.startsWith("[#] ") || clean.contains("2>/dev/null") || clean.contains("password for") ||
        Regex("""^\s*\d+(?:\.\d+)?%.*$""").matches(clean)
    ) return event(RemoteLogCategory.Technical)
    if (systemdLink.matches(clean)) return event(RemoteLogCategory.Info, if (".wants/" in clean) "systemd: автозапуск службы включён." else "systemd: служебная ссылка создана.")
    if (systemdRemoved.matches(clean)) return event(RemoteLogCategory.Info, if (".wants/" in clean) "systemd: автозапуск службы отключён." else "systemd: служебная ссылка удалена.")
    if (warningMessage.containsMatchIn(clean)) return event(RemoteLogCategory.Warning)
    if (errorMessage.containsMatchIn(clean)) {
        val detail = clean.removePrefix("FAIL:").removePrefix("[✗]").trim()
        return event(RemoteLogCategory.Error, "Ошибка на сервере: $detail")
    }
    if (stderr && exitStatus != 0) return event(RemoteLogCategory.Error, "Ошибка на сервере: $clean")
    return event(RemoteLogCategory.Info)
}

internal fun shouldWriteRemoteErrorToUserLog(line: String): Boolean =
    classifyRemoteCommandLine(line).category == RemoteLogCategory.Error

internal fun remoteErrorMessageForUserLog(line: String): String? =
    classifyRemoteCommandLine(line).takeIf { it.category == RemoteLogCategory.Error }?.message

/** Only command output is captured, never SSH commands, stdin or credentials. */
internal val remoteCommandOutputCapture = ThreadLocal<RemoteCommandCapture?>()

internal class RemoteCommandCapture(private val secrets: List<String> = emptyList()) {
    fun sanitize(text: String): String = secrets.filter { it.isNotBlank() }.fold(redactRemoteDiagnostics(text)) { value, secret -> value.replace(secret, "[скрыто]") }
    private val output = StringBuilder()
    @Synchronized fun append(text: String) {
        if (text.isBlank()) return
        output.appendLine(sanitize(text))
        if (output.length > 256 * 1024) {
            output.delete(0, output.length - 256 * 1024)
            output.insert(0, "[Начало длинного вывода сокращено]\n")
        }
    }
    @Synchronized fun text(): String = output.toString().trim()
}

internal fun redactRemoteDiagnostics(text: String): String {
    var result = text.replace(Regex("""(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----"""), "[приватный ключ скрыт]")
    result = result.replace(Regex("""(?i)([a-z][a-z0-9+.-]*://)[^\s/@]+:[^\s/@]+@"""), "$1[скрыто]@")
    result = result.replace(Regex("""(?im)^([^\n]*(?:password|passwd|token|secret|private[ _-]?key|preshared[ _-]?key|authorization)[^\n:=]*[:=])[^\n]*$"""), "$1 [скрыто]")
    result = result.replace(Regex("""(?m)^([A-Z][A-Z0-9_]*_B64=).*$"""), "$1[скрыто]")
    return result
}

internal fun remoteEventUserText(event: RemoteLogEvent): String {
    val text = event.message
    if (Regex("^[А-Яа-яЁё]").containsMatchIn(text) &&
        !text.startsWith("Ошибка на сервере:")
    ) return text
    val detail = text.removePrefix("Ошибка на сервере:").trim()
    if (Regex("^[А-Яа-яЁё]").containsMatchIn(detail)) return detail
    val lower = text.lowercase()
    return when {
        text.startsWith("systemd:") -> text
        "permission denied" in lower || "access denied" in lower -> "На сервере недостаточно прав для выполнения команды."
        "failed to enable" in lower || "failed to disable" in lower -> "Не удалось изменить автозапуск службы на сервере."
        "job for" in lower && "failed" in lower -> "Служба на сервере не запустилась. Подробности — в результате действия."
        "no installation config" in lower || "not meant to be enabled" in lower -> "Для этой службы не предусмотрено включение автозапуска."
        "non-existent unit" in lower -> "Служба ссылается на отсутствующую системную цель. Проверьте настройки автозапуска."
        "debconf:" in lower -> "Настройка пакета отложена до завершения установки."
        "deprecated" in lower -> "Сервер сообщил об устаревшем параметре. Подробности — в результате действия."
        event.category == RemoteLogCategory.Error -> "Сервер сообщил об ошибке. Подробности — в результате действия."
        event.category == RemoteLogCategory.Warning -> "Сервер сообщил о предупреждении. Подробности — в результате действия."
        else -> "Служебное сообщение сервера сохранено в подробностях действия."
    }
}
