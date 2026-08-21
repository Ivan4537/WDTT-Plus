package com.wdtt.plus

import android.content.Context
import android.os.Build
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

import androidx.compose.runtime.Stable

@Stable
enum class LogSeverity {
    Info,
    Warning,
    Error
}

@Stable
data class LogEntry(
    val key: String,
    val message: String,
    val count: Int = 1,
    val priority: Int = 99, // 0 - Creds, 1 - DTLS, 2 - Ready, 3 - Stats, 99 - Errors/Other
    val severity: LogSeverity = LogSeverity.Info
) {
    val isError: Boolean get() = severity == LogSeverity.Error
}

internal fun addPhoneTimeToSleepLog(
    message: String,
    nowMs: Long = System.currentTimeMillis(),
    timeZone: TimeZone = TimeZone.getDefault(),
): String {
    val prefix = "[СОН] "
    if (!message.startsWith(prefix)) return message
    val body = message.removePrefix(prefix)
    if (body.isBlank()) return message

    val formatter = SimpleDateFormat("HH:mm:ss", Locale.ROOT).apply {
        this.timeZone = timeZone
    }
    val phoneTime = formatter.format(Date(nowMs))
    val boundary = body.indexOfAny(charArrayOf(';', '.', ':', '!', '?'))
    return if (boundary > 0) {
        "$prefix${body.substring(0, boundary)} в $phoneTime${body.substring(boundary)}"
    } else {
        "$prefix$body в $phoneTime"
    }
}

internal fun shouldUseVkCallsPreflight(
    enabledByUser: Boolean,
    cooldownUntilMs: Long,
    nowMs: Long = System.currentTimeMillis(),
): Boolean = enabledByUser && nowMs >= cooldownUntilMs

internal fun vkCallsPreflightCooldownForLog(line: String): Long = when {
    line.contains("[VKCalls] VK временно ограничил анонимный вход", true) -> 60_000L
    line.contains("[VKCalls] VKCalls запросил CAPTCHA", true) -> 120_000L
    line.contains("[VKCalls] preflight не сработал", true) &&
        line.contains("временно не повторяем", true) -> 45_000L
    else -> 0L
}

internal fun boundedVkCallsPreflightCooldownUntil(
    untilMs: Long,
    nowMs: Long = System.currentTimeMillis(),
    maxDurationMs: Long = 2 * 60_000L,
): Long = if (untilMs > nowMs && untilMs - nowMs <= maxDurationMs) untilMs else 0L

@Stable
enum class ConnectionIssueKind {
    GENERAL,
    ACCESS,
}

@Stable
data class ConnectionIssue(
    val title: String,
    val action: String,
    val isError: Boolean = true,
    val kind: ConnectionIssueKind = ConnectionIssueKind.GENERAL,
)

internal val ConnectionIssue.isStandaloneUiIssue: Boolean
    get() = kind != ConnectionIssueKind.ACCESS

enum class NetworkRecoveryAction {
    SoftRestart,
    StopVpn
}

internal fun stableNetworkRecoveryAction(@Suppress("UNUSED_PARAMETER") completedAttempts: Int): NetworkRecoveryAction =
    NetworkRecoveryAction.SoftRestart

internal fun shouldBlockVpnStart(vpnSlotYieldRequested: Boolean): Boolean =
    vpnSlotYieldRequested

internal fun confirmedFailureRecoveryAction(
    hardFailure: Boolean,
    completedAttempts: Int,
): NetworkRecoveryAction = if (hardFailure) {
    if (completedAttempts == 0) {
        NetworkRecoveryAction.SoftRestart
    } else {
        NetworkRecoveryAction.StopVpn
    }
} else {
    stableNetworkRecoveryAction(completedAttempts)
}

internal fun hasConfirmedNetworkFailureAtOrAfter(
    running: Boolean,
    hardNetworkErrorAtMs: Long,
    sinceMs: Long,
): Boolean = running && hardNetworkErrorAtMs > 0L && hardNetworkErrorAtMs >= sinceMs

internal fun shouldResetNetworkRecoveryFromStats(
    downstreamChanged: Boolean,
    hardNetworkFailure: Boolean,
    trafficChanged: Boolean,
    statsTrafficStagnant: Boolean,
): Boolean {
    if (downstreamChanged) return true
    return !hardNetworkFailure &&
        (trafficChanged || !statsTrafficStagnant)
}

internal fun hasFreshTransportHeartbeat(
    running: Boolean,
    activeWorkers: Int,
    lastInboundTrafficAtMs: Long,
    sinceMs: Long,
    nowMs: Long,
    freshnessMs: Long = 90_000L,
): Boolean {
    if (!running || activeWorkers <= 0) return false
    return lastInboundTrafficAtMs >= sinceMs && nowMs - lastInboundTrafficAtMs < freshnessMs
}

internal fun hasFreshTransportPath(
    running: Boolean,
    activeWorkers: Int,
    lastInboundTrafficAtMs: Long,
    lastKeepaliveResponseAtMs: Long,
    sinceMs: Long,
    nowMs: Long,
    freshnessMs: Long = 90_000L,
): Boolean {
    if (!running || activeWorkers <= 0) return false
    val lastResponseAtMs = maxOf(lastInboundTrafficAtMs, lastKeepaliveResponseAtMs)
    return lastResponseAtMs >= sinceMs && nowMs - lastResponseAtMs < freshnessMs
}

internal fun stableRecoveryGraceMs(hardFailure: Boolean): Long =
    if (hardFailure) 30_000L else 10 * 60_000L

internal fun stableRecoveryRetryMs(hardFailure: Boolean): Long =
    if (hardFailure) 2 * 60_000L else 10 * 60_000L

internal fun isConfirmedUserTrafficFailure(userTrafficStalled: Boolean): Boolean =
    userTrafficStalled

internal fun shouldDeferConnectionIssueNotification(
    confirmedUserTrafficFailure: Boolean,
    recoverableNetworkErrorAtMs: Long,
    recoveryAttempts: Int,
    nowMs: Long,
    firstGraceMs: Long,
): Boolean = !confirmedUserTrafficFailure &&
    recoverableNetworkErrorAtMs > 0L &&
    recoveryAttempts == 0 &&
    nowMs - recoverableNetworkErrorAtMs < firstGraceMs

internal fun isTransportHealthRecovery(message: String): Boolean =
    message.contains("снова получает ответы", ignoreCase = true)

internal fun shouldReconnectTunnelAfterWake(
    activeWorkers: Int,
    confirmedNetworkFailure: Boolean,
): Boolean = activeWorkers <= 0 || confirmedNetworkFailure

internal fun shouldObserveTunnelHealth(
    deviceInteractive: Boolean,
    wakeRecoveryGraceActive: Boolean,
): Boolean = deviceInteractive && !wakeRecoveryGraceActive

internal fun shouldReloadWireGuardRouting(
    tunnelRunning: Boolean,
    activeTunnelProfile: Int?,
    changedProfile: Int,
): Boolean =
    tunnelRunning &&
        changedProfile in 0..2 &&
        activeTunnelProfile == changedProfile

enum class TunnelStopReason(val displayText: String) {
    User("отключено пользователем"),
    VpnSlotTransferred("VPN-слот передан другому приложению"),
    VpnStoppedExternally("Android отключил VPN или передал слот другому приложению"),
    VpnInterfaceLost("системный VPN-интерфейс потерян"),
    NetworkRecoveryFailed("связь не восстановилась после ошибки сети"),
    WakeRecoveryFailed("VPN не восстановился после пробуждения"),
    CriticalError("критическая ошибка подключения"),
    CaptchaCancelled("проверка отменена пользователем"),
    TrustedWifi("подключена доверенная сеть Wi-Fi"),
    RestoreFailed("не удалось восстановить VPN"),
    ServiceDestroyed("служба VPN остановлена системой"),
    AccessExpired("срок доступа закончился")
}

enum class TunnelTransition {
    IDLE,
    STARTING,
    STOPPING,
}

private val stoppedStatsTrafficPairRegex = Regex(
    "↓\\s*[0-9]+(?:[.,][0-9]+)?\\s*МБ\\s*/\\s*↑\\s*[0-9]+(?:[.,][0-9]+)?\\s*МБ"
)

internal fun buildStoppedSessionStats(previousStats: String, reason: TunnelStopReason): String {
    val traffic = stoppedStatsTrafficPairRegex.find(previousStats)?.value
    return buildString {
        append(
            if (reason == TunnelStopReason.TrustedWifi) {
                "VPN в ожидании · Причина: "
            } else {
                "VPN отключён · Причина: "
            }
        )
        append(reason.displayText)
        append(" · Активных: 0")
        if (!traffic.isNullOrBlank()) {
            append(" · ")
            append(traffic)
        }
    }
}

internal fun classifyRecoverableWorkerRetry(
    line: String,
    activeWorkerCount: Int = 0
): Pair<String, String>? {
    if (!line.contains("[ВОРКЕР #", true) || !line.contains("Ошибка (попытка", true)) return null
    if (line.contains("фаталь", true) || line.contains("невосстановим", true) || line.contains("FATAL_AUTH", true)) {
        return null
    }
    val activeSuffix = activeWorkerCount
        .takeIf { it > 0 }
        ?.let { "; активных=$it" }
        .orEmpty()
    return when {
        line.contains("TURN Allocate", true) && line.contains("all retransmissions failed", true) ->
            "worker_turn_allocate_retry" to
                "[TURN] Отдельные каналы не получили ответ на Allocate; выполняются повторы$activeSuffix"
        line.contains("TURN Allocate", true) ->
            "worker_turn_allocate_retry" to
                "[TURN] Отдельные каналы не прошли Allocate; выполняются повторы$activeSuffix"
        line.contains("DTLS", true) ->
            "worker_dtls_retry" to
                "[DTLS] Отдельные каналы не прошли рукопожатие; выполняются повторы$activeSuffix"
        line.contains("timeout", true) || line.contains("deadline", true) ->
            "worker_timeout_retry" to
                "[ПОТОК] Отдельные каналы не ответили вовремя; выполняются повторы$activeSuffix"
        else ->
            "worker_retry" to
                "[ПОТОК] Отдельные каналы пока не подключились; выполняются повторы$activeSuffix"
    }
}

internal fun isExpiredAccessAuthFailure(line: String): Boolean =
    line.contains("DENIED:expired", ignoreCase = true) ||
        line.contains("срок действия пароля истёк", ignoreCase = true)

internal const val WRAP_HANDSHAKE_RETRY_MESSAGE =
    "[WRAP] Отдельные каналы не ответили, выполняется повтор"
internal const val RT_MASQUE_CONFIG_FILE_NAME = "rt-masque-v1.json"

internal fun shouldUseRtMasque(rtNetwork: Boolean, rtMasque: Boolean): Boolean =
    rtNetwork && rtMasque

internal fun shouldUseRtMasqueServerBootstrap(
    rtNetwork: Boolean,
    rtMasque: Boolean,
    serverBootstrap: Boolean,
): Boolean = rtNetwork && rtMasque && serverBootstrap

internal data class MasqueLogPresentation(
    val key: String,
    val message: String,
    val warning: Boolean = false,
    val startsDtls: Boolean = false,
)

internal fun classifyMasqueLog(line: String): MasqueLogPresentation? {
    val hasTag = line.contains("[MASQUE]", ignoreCase = true)
    val mentionsSelectedPath = line.contains("внутри MASQUE", ignoreCase = true)
    val mentionsUdpFallback = line.contains("после MASQUE", ignoreCase = true)
    if (!hasTag && !mentionsSelectedPath && !mentionsUdpFallback) return null
    val text = if (hasTag) line.substringAfter("[MASQUE]", line).trim() else line.trim()
    val h2 = text.contains("HTTP/2", ignoreCase = true)
    val h3 = text.contains("HTTP/3", ignoreCase = true)
    val registrationProblem =
        text.contains("конфигурация WARP повреждена", ignoreCase = true) ||
            text.contains("публичный ключ WARP endpoint не совпал", ignoreCase = true) ||
            text.contains("access denied", ignoreCase = true)
    val httpStatus = Regex("HTTP\\s+(\\d{3})", RegexOption.IGNORE_CASE)
        .find(text)
        ?.groupValues
        ?.getOrNull(1)
        ?.toIntOrNull()
    val apiCode = Regex("code=(\\d+)", RegexOption.IGNORE_CASE)
        .find(text)
        ?.groupValues
        ?.getOrNull(1)
    val enrollmentStage = when {
        text.contains("этап 1/4", ignoreCase = true) ||
            text.contains("регистрация WARP:", ignoreCase = true) ->
            "создания устройства WARP (этап 1/4)"
        text.contains("этап 2/4", ignoreCase = true) ||
            text.contains("enrollment WARP", ignoreCase = true) ->
            "включения MASQUE в Cloudflare (этап 2/4)"
        text.contains("этап 3/4", ignoreCase = true) ||
            text.contains("неполную конфигурацию", ignoreCase = true) ->
            "проверки конфигурации MASQUE (этап 3/4)"
        text.contains("этап 4/4", ignoreCase = true) ||
            text.contains("сохранение регистрации", ignoreCase = true) ->
            "сохранения регистрации на устройстве (этап 4/4)"
        else -> "подготовки WARP"
    }
    val pathFailureReason = when {
        text.contains("timeout", ignoreCase = true) ||
            text.contains("deadline exceeded", ignoreCase = true) ||
            text.contains("тайм-аут", ignoreCase = true) -> "таймаут"
        text.contains("refused", ignoreCase = true) -> "соединение отклонено"
        text.contains("unreachable", ignoreCase = true) ||
            text.contains("no route", ignoreCase = true) -> "маршрут недоступен"
        text.contains("lookup", ignoreCase = true) ||
            text.contains("DNS", ignoreCase = true) -> "ошибка DNS внутри WARP"
        text.contains("handshake", ignoreCase = true) -> "ошибка рукопожатия"
        else -> "CONNECT-IP или TURN не ответил"
    }
    val enrollmentFailureReason = when {
        httpStatus == 429 -> "Cloudflare ограничил частоту регистраций (HTTP 429)"
        httpStatus == 403 -> "Cloudflare отклонил запрос (HTTP 403)"
        httpStatus != null && httpStatus >= 500 -> "временная ошибка Cloudflare (HTTP $httpStatus)"
        text.contains("тайм-аут TLS-рукопожатия", ignoreCase = true) ->
            "TLS-рукопожатие с API Cloudflare не завершилось после успешного TCP/443"
        text.contains("не прислал заголовки ответа", ignoreCase = true) ||
            text.contains("не прислал ответ", ignoreCase = true) ->
            "Cloudflare не ответил на уже отправленный HTTPS-запрос"
        text.contains("тайм-аут подключения TCP/443", ignoreCase = true) ->
            "не установилось TCP/443-соединение с API Cloudflare"
        text.contains("тайм-аут системного DNS", ignoreCase = true) ->
            "системный DNS Android не ответил для API Cloudflare"
        text.contains("пустой ответ", ignoreCase = true) -> "Cloudflare вернул пустой ответ"
        text.contains("не в формате JSON", ignoreCase = true) -> "Cloudflare вернул ответ не в формате JSON"
        text.contains("структура JSON-ответа", ignoreCase = true) -> "формат ответа Cloudflare изменился"
        text.contains("чтение ответа", ignoreCase = true) -> "ответ Cloudflare оборвался при чтении"
        httpStatus != null -> "Cloudflare вернул HTTP $httpStatus"
        text.contains("lookup", ignoreCase = true) ||
            text.contains("DNS", ignoreCase = true) -> "не разрешился адрес API Cloudflare"
        text.contains("timeout", ignoreCase = true) ||
            text.contains("deadline exceeded", ignoreCase = true) ||
            text.contains("тайм-аут", ignoreCase = true) -> "таймаут обращения к API Cloudflare"
        text.contains("certificate", ignoreCase = true) ||
            text.contains("x509", ignoreCase = true) -> "ошибка проверки TLS-сертификата API Cloudflare"
        text.contains("connection refused", ignoreCase = true) -> "соединение с API Cloudflare отклонено"
        text.contains("не вернула", ignoreCase = true) ||
            text.contains("не вернул", ignoreCase = true) -> "Cloudflare вернул неполную конфигурацию"
        else -> "запрос к API Cloudflare завершился ошибкой"
    }
    val rawEnrollmentFailure = text
        .substringAfter("фоновая подготовка WARP пока не выполнена:", "")
        .trim()
        .replaceFirst(Regex("^этап\\s+\\d/4,[^:]{0,160}:\\s*", RegexOption.IGNORE_CASE), "")
        .replace(Regex("(?i)Bearer\\s+\\S+"), "Bearer [скрыт]")
        .replace(Regex("https?://\\S+", RegexOption.IGNORE_CASE), "[URL скрыт]")
        .replace(Regex("[\\r\\n\\t]+"), " ")
        .trim()
        .take(260)
    val enrollmentTechnicalDetail = buildList {
        if (apiCode != null) add("код API $apiCode")
        when {
            text.contains("ошибка DNS для", ignoreCase = true) ->
                add(text.substringAfter("ошибка DNS для", "").trim().take(180).let { "DNS: $it" })
            text.contains("сетевая ошибка:", ignoreCase = true) ->
                add(text.substringAfter("сетевая ошибка:", "").trim().take(180))
            text.contains("не вернул ID или токен", ignoreCase = true) ->
                add("в ответе отсутствует ID или токен")
            text.contains("не вернул адрес MASQUE", ignoreCase = true) ->
                add("в ответе отсутствует адрес MASQUE")
            text.contains("неполная конфигурация", ignoreCase = true) ->
                add("в ответе отсутствует обязательное поле")
        }
        if (rawEnrollmentFailure.isNotBlank()) add(rawEnrollmentFailure)
    }.filter { it.isNotBlank() }.distinct().joinToString(", ")
        .let { if (it.isBlank()) "" else "; подробность: $it" }

    return when {
        registrationProblem -> MasqueLogPresentation(
            key = "masque_registration_invalid",
            message = "[MASQUE] Регистрация WARP повреждена или отклонена. Остановите VPN и используйте «Сбросить регистрацию WARP» в справке MASQUE.",
            warning = true,
        )
        text.contains("фоновая подготовка WARP пока не выполнена", ignoreCase = true) ->
            MasqueLogPresentation(
                key = "masque_enrollment_pending",
                message = "[MASQUE] Ошибка на этапе $enrollmentStage: $enrollmentFailureReason$enrollmentTechnicalDetail. " +
                    "Регистрация не сохранена; прямые пути продолжают работу. Для новой попытки остановите и снова запустите VPN.",
                warning = true,
            )
        text.contains("повторяем через TLS 1.2/HTTP 1.1", ignoreCase = true) &&
            text.contains("разделённым ClientHello", ignoreCase = true) ->
            MasqueLogPresentation(
                "masque_api_tls_fallback",
                "[MASQUE] API Cloudflare: обычный TLS не ответил; пробуем TLS 1.2/HTTP 1.1 с разделённым ClientHello...",
                warning = true,
            )
        text.contains("данные устройства ещё не отправлялись", ignoreCase = true) ->
            MasqueLogPresentation(
                "masque_api_retry",
                "[MASQUE] API Cloudflare не завершил соединение до отправки данных. Выполняем одну безопасную повторную попытку через системную сеть Android...",
                warning = true,
            )
        text.contains("прямые HTTPS-пути недоступны", ignoreCase = true) &&
            text.contains("выход через сервер профиля", ignoreCase = true) ->
            MasqueLogPresentation(
                "masque_api_server_retry",
                "[MASQUE] Прямой API Cloudflare не ответил; пробуем регистрацию через сервер профиля...",
                warning = true,
            )
        text.contains("выход через сервер профиля доступен", ignoreCase = true) ->
            MasqueLogPresentation(
                "masque_api_server_connected",
                "[MASQUE] Защищённый выход через сервер профиля установлен ✓",
            )
        text.contains("выход через сервер профиля сработал", ignoreCase = true) ->
            MasqueLogPresentation(
                "masque_api_server_ok",
                "[MASQUE] API Cloudflare доступен через сервер профиля ✓",
            )
        text.contains("локальный выход для регистрации WARP отклонён", ignoreCase = true) ->
            MasqueLogPresentation(
                "masque_api_server_invalid",
                "[MASQUE] Локальный выход регистрации отклонён как небезопасный; продолжаем прямые попытки",
                warning = true,
            )
        text.contains("системный DNS Android разрешил адрес", ignoreCase = true) ->
            MasqueLogPresentation(
                "masque_api_dns",
                "[MASQUE] API Cloudflare: системный DNS Android разрешил адрес ✓",
            )
        text.contains("TCP/443 через системную сеть Android установлен", ignoreCase = true) ->
            MasqueLogPresentation(
                "masque_api_tcp",
                "[MASQUE] API Cloudflare: TCP/443 через системную сеть Android установлен ✓",
            )
        text.contains("TLS-рукопожатие завершено", ignoreCase = true) &&
            text.contains("HTTP/1.1", ignoreCase = true) ->
            MasqueLogPresentation(
                "masque_api_tls_fallback_ok",
                "[MASQUE] API Cloudflare: резерв TLS 1.2/HTTP 1.1 установлен ✓",
            )
        text.contains("TLS-рукопожатие завершено", ignoreCase = true) ->
            MasqueLogPresentation(
                "masque_api_tls",
                "[MASQUE] API Cloudflare: защищённое TLS-соединение установлено ✓",
            )
        text.contains("HTTP-запрос отправлен", ignoreCase = true) &&
            text.contains("ожидаем ответ", ignoreCase = true) ->
            MasqueLogPresentation(
                "masque_api_request",
                "[MASQUE] API Cloudflare: HTTPS-запрос отправлен, ожидаем ответ...",
            )
        text.contains("получен первый байт HTTP-ответа", ignoreCase = true) ->
            MasqueLogPresentation(
                "masque_api_response",
                "[MASQUE] API Cloudflare: получен HTTP-ответ ✓",
            )
        text.contains("регистрация начата:", ignoreCase = true) ||
            text.contains("первый запуск: регистрируем", ignoreCase = true) ->
            MasqueLogPresentation(
                "masque_enrollment_start",
                "[MASQUE] Этап 1/4: создаём отдельное устройство WARP в Cloudflare...",
            )
        text.contains("этап 1/4 завершён", ignoreCase = true) ||
            text.contains("базовая регистрация WARP создана", ignoreCase = true) ->
            MasqueLogPresentation(
                "masque_account_created",
                "[MASQUE] Этап 1/4 завершён: устройство WARP создано. Этап 2/4: включаем для него MASQUE...",
            )
        text.contains("этап 2/4 завершён", ignoreCase = true) ||
            text.contains("Cloudflare принял ключ MASQUE", ignoreCase = true) ->
            MasqueLogPresentation(
                "masque_key_accepted",
                "[MASQUE] Этап 2/4 завершён: Cloudflare принял ключ MASQUE. Этап 3/4: проверяем адреса и ключ сервера...",
            )
        text.contains("этап 3/4 завершён", ignoreCase = true) ->
            MasqueLogPresentation(
                "masque_config_valid",
                "[MASQUE] Этап 3/4 завершён: конфигурация MASQUE корректна ✓",
            )
        text.contains("этап 4/4 — сохраняем", ignoreCase = true) ->
            MasqueLogPresentation(
                "masque_enrollment_saving",
                "[MASQUE] Этап 4/4: сохраняем регистрацию только в приватном хранилище приложения...",
            )
        text.contains("этап 4/4 завершён", ignoreCase = true) ||
            text.contains("enrollment WARP сохранён", ignoreCase = true) ->
            MasqueLogPresentation(
                "masque_enrollment_saved",
                "[MASQUE] Этап 4/4 завершён: регистрация WARP сохранена в приватном хранилище ✓",
            )
        text.contains("конфигурация WARP подготовлена", ignoreCase = true) ->
            MasqueLogPresentation("masque_config_ready", "[MASQUE] Сохранённая регистрация WARP готова ✓")
        text.contains("Включён резерв", ignoreCase = true) ->
            MasqueLogPresentation("masque_enabled", "[MASQUE] Резерв включён: HTTP/2 (TCP/443), затем HTTP/3 (QUIC/443)")
        text.contains("Прямые TCP/TLS-пути", ignoreCase = true) ->
            MasqueLogPresentation("masque_fallback_start", "[MASQUE] Прямые TCP/TLS-пути РТ не ответили — запускаем CONNECT-IP до попытки UDP")
        text.contains("Последний резерв после MASQUE", ignoreCase = true) ->
            MasqueLogPresentation(
                "masque_udp_fallback",
                "[MASQUE] HTTP/2 и HTTP/3 не дали рабочий TURN — пробуем прямой UDP последним резервом",
                warning = true,
            )
        text.contains("Relay:", ignoreCase = true) && h2 ->
            MasqueLogPresentation("masque_selected", "[MASQUE] Выбран HTTP/2 через TCP/443 ✓", startsDtls = true)
        text.contains("Relay:", ignoreCase = true) && h3 ->
            MasqueLogPresentation("masque_selected", "[MASQUE] Выбран HTTP/3 через QUIC/443 ✓", startsDtls = true)
        text.contains("CONNECT-IP HTTP/2 установлен", ignoreCase = true) ->
            MasqueLogPresentation("masque_h2_connected", "[MASQUE] CONNECT-IP HTTP/2 через TCP/443 установлен ✓")
        text.contains("CONNECT-IP HTTP/3 установлен", ignoreCase = true) ->
            MasqueLogPresentation("masque_h3_connected", "[MASQUE] CONNECT-IP HTTP/3 через QUIC/443 установлен ✓")
        text.contains("устанавливаем CONNECT-IP", ignoreCase = true) && h2 ->
            MasqueLogPresentation("masque_h2_connecting", "[MASQUE] Подключаем CONNECT-IP HTTP/2 через TCP/443...")
        text.contains("устанавливаем CONNECT-IP", ignoreCase = true) && h3 ->
            MasqueLogPresentation("masque_h3_connecting", "[MASQUE] Подключаем CONNECT-IP HTTP/3 через QUIC/443...")
        text.contains("Пробуем TURN", ignoreCase = true) && h2 ->
            MasqueLogPresentation("masque_h2_turn", "[MASQUE] Проверяем TURN внутри HTTP/2...")
        text.contains("Пробуем TURN", ignoreCase = true) && h3 ->
            MasqueLogPresentation("masque_h3_turn", "[MASQUE] Проверяем TURN внутри HTTP/3...")
        (text.contains("не сработал", ignoreCase = true) || text.contains("потерян", ignoreCase = true)) && h2 ->
            MasqueLogPresentation(
                "masque_h2_failed",
                "[MASQUE] Путь HTTP/2/TCP/443 не сработал ($pathFailureReason); проверяем другие TURN-адреса и HTTP/3",
                warning = true,
            )
        (text.contains("не сработал", ignoreCase = true) || text.contains("потерян", ignoreCase = true)) && h3 ->
            MasqueLogPresentation(
                "masque_h3_failed",
                "[MASQUE] Путь HTTP/3/QUIC/443 не сработал ($pathFailureReason); проверяем другие TURN-адреса и прямой UDP",
                warning = true,
            )
        else -> MasqueLogPresentation("masque_status", "[MASQUE] $text")
    }
}

const val AMNEZIA_STYLE_RECOVERY = true
private const val RECOVERABLE_NETWORK_GRACE_MS = 90_000L
private const val HARD_NETWORK_GRACE_MS = 30_000L
private const val HARD_NETWORK_STOP_DELAY_MS = 60_000L
private const val STABLE_RECOVERY_GRACE_MS = 10 * 60_000L
private const val STABLE_RECOVERY_RETRY_MS = 10 * 60_000L
private const val STABLE_ZERO_WORKERS_GRACE_MS = 15 * 60_000L
private const val STAGNANT_ACTIVE_TRAFFIC_MS = 20 * 60_000L
private const val WAKE_RECOVERY_GRACE_MS = 90_000L

object TunnelManager {
    private const val VK_CALLS_RUNTIME_PREFERENCES = "tunnel_runtime"
    private const val VK_CALLS_PREFLIGHT_COOLDOWN_UNTIL = "vkcalls_preflight_cooldown_until"
    private const val VK_CALLS_PREFLIGHT_MAX_COOLDOWN_MS = 2 * 60_000L
    // 100% защита от утечек: единый управляемый глобальный Scope
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private var process: Process? = null
    private val processInputLock = Any()
    private var readerJob: Job? = null
    private var watchdogJob: Job? = null
    private var wireGuardReloadJob: Job? = null
    private var wgHelper: WireGuardHelper? = null
    private var warpApiSshRelay: WarpApiSshRelay? = null
    
    private val startStopMutex = kotlinx.coroutines.sync.Mutex()

    // Error counters for circuit breaker
    private var floodCount = 0
    private var mismatchCount = 0
    private var refusedCount = 0
    private var currentHashErrorCount = 0
    private var wrapAuthTimeoutCount = 0
    var processStartedAtMs = 0L
    private var lastActiveAtMs = 0L
    private var lastStatsAtMs = 0L
    private var lastStatsDownTrafficSignature = ""
    private var lastStatsUpTrafficSignature = ""
    private var lastDownstreamTrafficChangedAtMs = 0L
    private var lastUpstreamTrafficChangedAtMs = 0L
    private var lastKeepaliveResponseAtMs = 0L
    private var lastStagnantTrafficIssueAtMs = 0L
    private var activeHashIndex = 0 // 0: primary, 1: secondary
    // Нативный процесс создаётся заново при выключении/включении туннеля. Эта
    // пауза остаётся в Android-процессе, чтобы быстрые нажатия не обходили
    // защиту VKCalls от flood control.
    @Volatile
    private var vkCallsPreflightCooldownUntilMs = 0L
    private var currentParams: TunnelParams? = null
    private var lastContext: Context? = null
    private var forceRegenerateUA = false // принудительная перегенерация UA при ошибках
    private var currentCaptchaMode = "wv" // режим обхода капчи: "wv" или "rjs"
    private var currentCaptchaSolveMethod = "auto" // "manual" или "auto"
    private var recoverableNetworkErrorAtMs = 0L
    private var hardNetworkErrorAtMs = 0L
    private var hardNetworkErrorCount = 0
    private var confirmedUserTrafficFailureAtMs = 0L
    private var lastRecoveryAtMs = 0L
    private var recoveryAttempts = 0
    private var softRestartCount = 0
    private var lastSoftRestartAtMs = 0L
    private var lastUnderlyingNetworkChangeAtMs = 0L
    private var networkTransitionGraceUntilMs = 0L
    private var wakeRecoveryGraceUntilMs = 0L
    private var lastNetworkSettleRestartAtMs = 0L
    private var lastStableNetworkIssueLogAtMs = 0L
    private val sessionTraffic = TunnelSessionTrafficAccumulator()
    private var sessionTrafficStore: TunnelSessionTrafficStore? = null
    private val captchaSolveRequestId = AtomicLong(0)
    private val activeCaptchaSolveRequests = ConcurrentHashMap.newKeySet<Long>()

    @Volatile
    var isLoggingEnabled = true

    val running = MutableStateFlow(false)
    val transition = MutableStateFlow(TunnelTransition.IDLE)
    val activeTunnelProfile = MutableStateFlow<Int?>(null)
    val logs = MutableStateFlow<List<LogEntry>>(emptyList())
    val unreadErrorCount = MutableStateFlow(0)
    val config = MutableStateFlow<String?>(null)
    val stats = MutableStateFlow("Ожидание данных...")
    val activeWorkers = MutableStateFlow(0)
    val connectionIssue = MutableStateFlow<ConnectionIssue?>(null)
    val vpnSlotYieldRequested = MutableStateFlow(false)
    
    val cooldownActive = MutableStateFlow(false)
    private var cooldownJob: Job? = null
    private val statsDownTrafficRegex = Regex("↓\\s*([0-9]+(?:[.,][0-9]+)?)\\s*МБ")
    private val statsUpTrafficRegex = Regex("↑\\s*([0-9]+(?:[.,][0-9]+)?)\\s*МБ")

    fun clearUnreadErrors() {
        unreadErrorCount.value = 0
    }

    private fun restoreVkCallsPreflightCooldown(context: Context, now: Long = System.currentTimeMillis()): Long {
        val storedUntil = context
            .getSharedPreferences(VK_CALLS_RUNTIME_PREFERENCES, Context.MODE_PRIVATE)
            .getLong(VK_CALLS_PREFLIGHT_COOLDOWN_UNTIL, 0L)
        val validUntil = boundedVkCallsPreflightCooldownUntil(
            untilMs = storedUntil,
            nowMs = now,
            maxDurationMs = VK_CALLS_PREFLIGHT_MAX_COOLDOWN_MS,
        )
        if (validUntil == 0L && storedUntil != 0L) {
            context.getSharedPreferences(VK_CALLS_RUNTIME_PREFERENCES, Context.MODE_PRIVATE)
                .edit()
                .remove(VK_CALLS_PREFLIGHT_COOLDOWN_UNTIL)
                .apply()
        }
        return validUntil
    }

    private fun extendVkCallsPreflightCooldown(context: Context, durationMs: Long, now: Long) {
        if (durationMs <= 0L) return
        val currentUntil = maxOf(
            vkCallsPreflightCooldownUntilMs,
            restoreVkCallsPreflightCooldown(context, now),
        )
        val proposedUntil = now + durationMs.coerceAtMost(VK_CALLS_PREFLIGHT_MAX_COOLDOWN_MS)
        val nextUntil = maxOf(currentUntil, proposedUntil)
        vkCallsPreflightCooldownUntilMs = nextUntil
        context.getSharedPreferences(VK_CALLS_RUNTIME_PREFERENCES, Context.MODE_PRIVATE)
            .edit()
            .putLong(VK_CALLS_PREFLIGHT_COOLDOWN_UNTIL, nextUntil)
            .apply()
    }

    private fun persistSessionTraffic() {
        sessionTrafficStore?.save(sessionTraffic.snapshot())
    }

    private fun noteSessionTransportRestart() {
        sessionTraffic.noteTransportRestart()
        persistSessionTraffic()
    }

    fun noteStartRequested() {
        transition.value = TunnelTransition.STARTING
    }

    fun allowVpnSlotAcquisition() {
        vpnSlotYieldRequested.value = false
    }

    fun noteStopRequested() {
        transition.value = TunnelTransition.STOPPING
    }

    fun clearTransition() {
        transition.value = TunnelTransition.IDLE
    }

    fun clearConnectionIssue(kind: ConnectionIssueKind? = null) {
        if (kind == null || connectionIssue.value?.kind == kind) {
            connectionIssue.value = null
        }
    }

    private fun setConnectionIssue(
        title: String,
        action: String,
        isError: Boolean = true,
        kind: ConnectionIssueKind = ConnectionIssueKind.GENERAL,
    ) {
        connectionIssue.value = ConnectionIssue(
            title = title,
            action = action,
            isError = isError,
            kind = kind,
        )
    }

    fun reportConnectionIssue(
        title: String,
        action: String,
        isError: Boolean = true,
        kind: ConnectionIssueKind = ConnectionIssueKind.GENERAL,
    ) {
        setConnectionIssue(title, action, isError, kind)
    }

    fun isCaptchaInProgress(): Boolean =
        activeCaptchaSolveRequests.isNotEmpty() || ManlCaptchaWebViewManager.isCaptchaPending

    private fun beginCaptchaSolve(): Long {
        val requestId = captchaSolveRequestId.incrementAndGet()
        activeCaptchaSolveRequests.add(requestId)
        return requestId
    }

    private fun endCaptchaSolve(requestId: Long) {
        activeCaptchaSolveRequests.remove(requestId)
    }

    private fun isHardNetworkFailure(line: String): Boolean {
        val lower = line.lowercase(Locale.ROOT)
        return "network is unreachable" in lower ||
            "network unreachable" in lower ||
            "no route to host" in lower ||
            "enetunreach" in lower
    }

    private fun isLocalDnsRefused(line: String): Boolean {
        val lower = line.lowercase(Locale.ROOT)
        val localDns = "[::1]:53" in lower ||
            "127.0.0.1:53" in lower ||
            "localhost:53" in lower
        return "lookup " in lower &&
            localDns &&
            ("connection refused" in lower || "read: connection refused" in lower)
    }

    private fun trailingSeconds(line: String): Int? =
        Regex("(\\d+)\\s*сек").find(line)?.groupValues?.getOrNull(1)?.toIntOrNull()

    private fun resetNetworkRecoveryState() {
        recoverableNetworkErrorAtMs = 0L
        hardNetworkErrorAtMs = 0L
        hardNetworkErrorCount = 0
        confirmedUserTrafficFailureAtMs = 0L
        lastRecoveryAtMs = 0L
        recoveryAttempts = 0
        softRestartCount = 0
        lastSoftRestartAtMs = 0L
        lastStableNetworkIssueLogAtMs = 0L
    }

    private fun resetStatsLivenessState() {
        lastActiveAtMs = 0L
        lastStatsAtMs = 0L
        lastStatsDownTrafficSignature = ""
        lastStatsUpTrafficSignature = ""
        lastDownstreamTrafficChangedAtMs = 0L
        lastUpstreamTrafficChangedAtMs = 0L
        lastKeepaliveResponseAtMs = 0L
        lastStagnantTrafficIssueAtMs = 0L
    }

    private fun trafficSignature(regex: Regex, message: String): String =
        regex.find(message)?.groupValues?.getOrNull(1)?.replace(',', '.').orEmpty()

    private fun isStatsTrafficStagnant(now: Long = System.currentTimeMillis()): Boolean {
        val startupGrace = processStartedAtMs == 0L || now - processStartedAtMs < 90_000L
        return activeWorkers.value > 0 &&
            lastUpstreamTrafficChangedAtMs > lastDownstreamTrafficChangedAtMs &&
            lastDownstreamTrafficChangedAtMs > 0L &&
            now - lastDownstreamTrafficChangedAtMs > STAGNANT_ACTIVE_TRAFFIC_MS &&
            !startupGrace &&
            !isCaptchaInProgress()
    }

    private fun noteRecoverableNetworkIssue(
        title: String,
        action: String,
        hardFailure: Boolean = false,
        confirmedUserTrafficFailure: Boolean = false,
    ) {
        val now = System.currentTimeMillis()
        if (!hardFailure && now < networkTransitionGraceUntilMs && recoverableNetworkErrorAtMs == 0L) {
            updateLog(
                "network_transition_wait",
                "[СЕТЬ] Во время смены сети был краткий сбой. Ждём стабилизации, без нового запроса к VK.",
                50,
                false
            )
            return
        }
        if (AMNEZIA_STYLE_RECOVERY) {
            if (recoverableNetworkErrorAtMs == 0L) {
                recoverableNetworkErrorAtMs = now
            }
            if (hardFailure) {
                if (hardNetworkErrorAtMs == 0L) {
                    hardNetworkErrorAtMs = now
                }
                hardNetworkErrorCount++
            }
            if (confirmedUserTrafficFailure) {
                if (confirmedUserTrafficFailureAtMs == 0L) {
                    confirmedUserTrafficFailureAtMs = now
                }
                networkTransitionGraceUntilMs = 0L
                setConnectionIssue(title, action)
            }
            if (now - lastStableNetworkIssueLogAtMs > 60_000L) {
                lastStableNetworkIssueLogAtMs = now
                val observation = if (confirmedUserTrafficFailure) {
                    "Подтверждаем сбой перед мягким восстановлением транспорта."
                } else {
                    "Наблюдаем без немедленного перезапуска; восстановление будет только после долгой тишины или смены сети."
                }
                updateLog(
                    "network_stable_observe",
                    "[СЕТЬ] $title. $observation",
                    50,
                    false
                )
            }
            return
        }
        if (recoverableNetworkErrorAtMs == 0L) {
            recoverableNetworkErrorAtMs = now
        }
        if (hardFailure) {
            if (hardNetworkErrorAtMs == 0L) {
                hardNetworkErrorAtMs = now
            }
            hardNetworkErrorCount++
            networkTransitionGraceUntilMs = 0L
        }
        setConnectionIssue(title, action)
    }

    fun pollNetworkRecoveryAction(now: Long = System.currentTimeMillis()): NetworkRecoveryAction? {
        if (!running.value) return null
        if (isWakeRecoveryGraceActive(now)) return null
        if (AMNEZIA_STYLE_RECOVERY) {
            return pollStableNetworkRecoveryAction(now)
        }
        val hardNetworkOutage = hardNetworkErrorAtMs > 0L && hardNetworkErrorCount >= 3
        if (!hardNetworkOutage && now < networkTransitionGraceUntilMs) return null
        if (isCaptchaInProgress()) {
            setConnectionIssue(
                "Ожидается решение капчи",
                "WDTT Plus не будет перезапускать транспорт, пока открыта VK Captcha, чтобы не плодить новые проверки VK."
            )
            return null
        }
        val startupGrace = processStartedAtMs == 0L || now - processStartedAtMs < 90_000L
        val noFreshStats = lastStatsAtMs > 0L && now - lastStatsAtMs > 4 * 60_000L
        val stalePositiveWorkers = activeWorkers.value > 0 &&
            noFreshStats &&
            !startupGrace &&
            !isCaptchaInProgress()
        val stagnantActiveTraffic = isStatsTrafficStagnant(now)
        if (recoverableNetworkErrorAtMs == 0L && stalePositiveWorkers) {
            noteRecoverableNetworkIssue(
                "Туннель не подаёт признаков жизни",
                "VPN включён, но давно нет свежей статистики от рабочих потоков. WDTT Plus попробует восстановить соединение автоматически."
            )
        }
        if (recoverableNetworkErrorAtMs == 0L) return null

        val hasFreshActiveWorkers = activeWorkers.value > 0 &&
            lastActiveAtMs > recoverableNetworkErrorAtMs &&
            now - lastActiveAtMs < 45_000L
        if (hasFreshActiveWorkers && !hardNetworkOutage && !stagnantActiveTraffic) return null

        val firstGraceMs = if (hardNetworkOutage) HARD_NETWORK_GRACE_MS else RECOVERABLE_NETWORK_GRACE_MS
        if (recoveryAttempts == 0 && now - recoverableNetworkErrorAtMs < firstGraceMs) {
            return null
        }

        val maxSoftRestarts = if (hardNetworkOutage) 1 else 3
        if (recoveryAttempts >= maxSoftRestarts) {
            val stopDelayMs = if (hardNetworkOutage) HARD_NETWORK_STOP_DELAY_MS else 5 * 60_000L
            if (now - lastRecoveryAtMs < stopDelayMs) return null
            setConnectionIssue(
                "VPN остановлен, чтобы вернуть интернет",
                "WDTT Plus несколько раз не смог восстановить связь. VPN выключен, чтобы телефон не остался без интернета."
            )
            return NetworkRecoveryAction.StopVpn
        }
        val recoveryDelayMs = if (hardNetworkOutage) {
            0L
        } else {
            when (recoveryAttempts) {
                0 -> 0L
                1 -> 2 * 60_000L
                2 -> 3 * 60_000L
                else -> 5 * 60_000L
            }
        }
        if (now - lastRecoveryAtMs < recoveryDelayMs) return null
        lastRecoveryAtMs = now
        recoveryAttempts++
        return if (recoveryAttempts <= maxSoftRestarts) {
            val attemptsText = if (hardNetworkOutage) {
                "жёсткая попытка восстановления перед отключением VPN"
            } else {
                "мягкая попытка $recoveryAttempts из $maxSoftRestarts без пересоздания VPN"
            }
            setConnectionIssue(
                "Восстанавливаю транспорт",
                "Сеть или DNS до VK долго не отвечают. Выполняется $attemptsText."
            )
            NetworkRecoveryAction.SoftRestart
        } else {
            setConnectionIssue(
                "VPN остановлен, чтобы вернуть интернет",
                "Мягкие попытки не восстановили связь. WDTT Plus выключит VPN, чтобы телефон не остался без интернета."
            )
            NetworkRecoveryAction.StopVpn
        }
    }

    private fun pollStableNetworkRecoveryAction(now: Long): NetworkRecoveryAction? {
        if (!running.value || isCaptchaInProgress()) return null
        if (now < networkTransitionGraceUntilMs) return null

        val startupGrace = processStartedAtMs == 0L || now - processStartedAtMs < 90_000L
        val noFreshStats = lastStatsAtMs > 0L && now - lastStatsAtMs > STABLE_RECOVERY_GRACE_MS
        val stalePositiveWorkers = activeWorkers.value > 0 && noFreshStats && !startupGrace
        if (recoverableNetworkErrorAtMs == 0L && stalePositiveWorkers) {
            recoverableNetworkErrorAtMs = now
            updateLog(
                "network_stable_stats_quiet",
                "[СЕТЬ] Долго нет свежей статистики, но VPN не пересоздаём. Подождём перед одной мягкой попыткой.",
                50,
                false
            )
        }
        if (recoverableNetworkErrorAtMs == 0L) return null

        val hardFailure = confirmedUserTrafficFailureAtMs > 0L
        val hasFreshActiveWorkers = activeWorkers.value > 0 &&
            lastActiveAtMs > recoverableNetworkErrorAtMs &&
            now - lastActiveAtMs < 2 * 60_000L
        if (!hardFailure && hasFreshActiveWorkers && !isStatsTrafficStagnant(now)) return null

        if (now - recoverableNetworkErrorAtMs < stableRecoveryGraceMs(hardFailure)) return null
        if (now - lastRecoveryAtMs < stableRecoveryRetryMs(hardFailure)) return null

        lastRecoveryAtMs = now
        val action = confirmedFailureRecoveryAction(hardFailure, recoveryAttempts)
        recoveryAttempts++
        when (action) {
            NetworkRecoveryAction.SoftRestart -> setConnectionIssue(
                "Восстанавливаю транспорт",
                "Сеть долго не подаёт признаков жизни. Выполняется тихая попытка без пересоздания VPN."
            )
            NetworkRecoveryAction.StopVpn -> setConnectionIssue(
                "VPN остановлен, чтобы вернуть интернет",
                "Повторные попытки не восстановили связь. WDTT Plus выключит VPN, чтобы телефон не остался без интернета."
            )
        }
        return action
    }

    private fun buildDeviceInfoJson(context: Context): String {
        val locale = Locale.getDefault()
        val deviceName = runCatching {
            android.provider.Settings.Global.getString(context.contentResolver, "device_name")
        }.getOrNull().orEmpty().ifBlank {
            listOf(Build.MANUFACTURER, Build.MODEL)
                .joinToString(" ")
                .trim()
                .ifBlank { "Android device" }
        }
        return JSONObject()
            .put("name", deviceName)
            .put("manufacturer", Build.MANUFACTURER.orEmpty())
            .put("brand", Build.BRAND.orEmpty())
            .put("model", Build.MODEL.orEmpty())
            .put("android_version", Build.VERSION.RELEASE.orEmpty())
            .put("sdk", Build.VERSION.SDK_INT)
            .put("abi", Build.SUPPORTED_ABIS.firstOrNull().orEmpty())
            .put("app_version", BuildConfig.VERSION_NAME)
            .put("locale", locale.toLanguageTag())
            .put("country", locale.country.orEmpty())
            .put("time_zone", TimeZone.getDefault().id)
            .toString()
    }

    private var observersInitialized = false
    private var accessRefreshRequestedForProcess = false

    fun initObservers(context: Context) {
        if (observersInitialized) return
        observersInitialized = true
        val appContext = context.applicationContext
        scope.launch {
            running.collect { running ->
                try {
                    VpnWidgetProvider.updateAllWidgets(appContext)
                    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
                        android.service.quicksettings.TileService.requestListeningState(
                            appContext,
                            android.content.ComponentName(appContext, QuickToggleTileService::class.java)
                        )
                    }
                } catch (e: Exception) {
                    // Ignore
                }
            }
        }
    }

    // Добавляем лог с Деплоя
    fun addDeployErrorLog(message: String) {
        val hash = message.hashCode().toString()
        updateLog("deploy_err_$hash", "[ДЕПЛОЙ] $message", 99, true)
    }

    fun addDeploySuccessLog(message: String) {
        val hash = message.hashCode().toString() + System.currentTimeMillis()
        updateLog("deploy_ok_$hash", message, 2, false)
    }

    fun noteTrustedWifiEvent(key: String, message: String, warning: Boolean = false) {
        val logKey = "trusted_wifi_$key"
        val text = "[ДОВЕРЕННЫЙ WI-FI] $message"
        if (warning) {
            updateWarningLog(logKey, text, 2)
        } else {
            updateLog(logKey, text, 2, false)
        }
    }

    fun noteAccessLifecycleEvent(key: String, message: String, warning: Boolean = false) {
        val logKey = "access_$key"
        val text = "[ДОСТУП] $message"
        if (warning) {
            updateWarningLog(logKey, text, 20)
        } else {
            updateLog(logKey, text, 20, false)
        }
    }

    fun noteSleepBatteryEvent(key: String, message: String, warning: Boolean = false) {
        val logKey = "sleep_battery_$key"
        val text = "[СОН] $message"
        if (warning) {
            updateWarningLog(logKey, text, 20)
        } else {
            updateLog(logKey, text, 20, false)
        }
    }

    fun noteAddressRoutingWarning(key: String, message: String) {
        updateWarningLog(
            key = "address_routing_$key",
            message = "[МАРШРУТИЗАЦИЯ] $message",
            priority = 10,
        )
    }

    fun noteVpnDnsEvent(key: String, message: String, warning: Boolean = false) {
        val logKey = "vpn_dns_$key"
        val text = "[DNS VPN] $message"
        if (warning) {
            updateWarningLog(logKey, text, 10)
        } else {
            updateLog(logKey, text, 10, false)
        }
    }

    fun noteVpnInterfaceReloadWarning(message: String) {
        updateWarningLog(
            key = "vpn_interface_reload_failed",
            message = "[VPN] $message",
            priority = 10,
        )
    }

    private fun updateLog(key: String, message: String, priority: Int, isError: Boolean = false) {
        if (!isLoggingEnabled) return
        val displayedMessage = addPhoneTimeToSleepLog(message)
        val severity = if (isError) LogSeverity.Error else LogSeverity.Info
        if (severity == LogSeverity.Error) {
            val list = logs.value
            if (list.none { it.key == key }) {
                unreadErrorCount.value++
            }
        }
        logs.update { currentList ->
            val current = currentList.toMutableList()
            val index = current.indexOfFirst { it.key == key }

            if (index != -1) {
                // Обновляем текст и счётчик НА МЕСТЕ
                val entry = current[index]
                current[index] = entry.copy(count = entry.count + 1, message = displayedMessage, priority = priority, severity = severity)
            } else {
                // Новая запись
                current.add(LogEntry(key, displayedMessage, 1, priority, severity))
            }

            // Сортировка: по приоритету (наименьший сверху), затем ошибки
            // Приоритеты: Основной=1, Капча=5, Готов=10, Статы=100, Ошибки=200
            val sorted = current.sortedWith(compareBy({ it.priority }, { if (it.isError) 1 else 0 }, { it.key }))

            // Лимит 100 записей
            if (sorted.size > 100) sorted.takeLast(100) else sorted
        }
    }

    private fun updateWarningLog(key: String, message: String, priority: Int) {
        if (!isLoggingEnabled) return
        val displayedMessage = addPhoneTimeToSleepLog(message)
        logs.update { currentList ->
            val current = currentList.toMutableList()
            val index = current.indexOfFirst { it.key == key }
            if (index != -1) {
                val entry = current[index]
                current[index] = entry.copy(
                    count = entry.count + 1,
                    message = displayedMessage,
                    priority = priority,
                    severity = LogSeverity.Warning
                )
            } else {
                current.add(LogEntry(key, displayedMessage, 1, priority, LogSeverity.Warning))
            }
            val sorted = current.sortedWith(compareBy({ it.priority }, { it.severity.ordinal }, { it.key }))
            if (sorted.size > 100) sorted.takeLast(100) else sorted
        }
    }

    fun start(
        context: Context,
        params: TunnelParams,
        isSwitching: Boolean = false,
        preserveLogs: Boolean = false,
        restoreSessionTraffic: Boolean = false,
    ) {
        if (shouldBlockVpnStart(vpnSlotYieldRequested.value)) return
        if (!isSwitching) noteStartRequested()
        scope.launch {
            startStopMutex.lock()
            try {
                if (running.value && !isSwitching) {
                    clearTransition()
                    return@launch
                }
        
                val appContext = context.applicationContext // Защита от Memory Leak
                val trafficStore = sessionTrafficStore ?: TunnelSessionTrafficStore(appContext).also {
                    sessionTrafficStore = it
                }
                
                if (!isSwitching) {
                    if (!preserveLogs) clearLogs()
                    config.value = null
                    stats.value = "Ожидание данных..."
                    if (restoreSessionTraffic) {
                        val restoredTraffic = trafficStore.load()
                        sessionTraffic.restore(restoredTraffic)
                        if (restoredTraffic != null) {
                            updateLog(
                                "service_session_restored",
                                "[СЛУЖБА] Android восстановил VPN-службу; счётчик текущей сессии продолжен.",
                                20,
                                false,
                            )
                        }
                    } else {
                        sessionTraffic.reset()
                        trafficStore.clear()
                    }
                    floodCount = 0
                    mismatchCount = 0
                    refusedCount = 0
                    currentHashErrorCount = 0
                    wrapAuthTimeoutCount = 0
                    resetNetworkRecoveryState()
                    clearConnectionIssue()
                    processStartedAtMs = 0L
                    resetStatsLivenessState()
                    lastUnderlyingNetworkChangeAtMs = 0L
                    networkTransitionGraceUntilMs = 0L
                    wakeRecoveryGraceUntilMs = 0L
                    lastNetworkSettleRestartAtMs = 0L
                    activeHashIndex = 0
                    currentParams = params
                    lastContext = appContext
                    accessRefreshRequestedForProcess = false
                    forceRegenerateUA = false
                    currentCaptchaMode = params.captchaMode
                    currentCaptchaSolveMethod = params.captchaSolveMethod
                }
                
                wgHelper = WireGuardHelper(appContext)

                val targetHash = if (activeHashIndex == 0) params.vkHashes else params.secondaryVkHash

                val customCredentials = CustomVkClientCredentials(
                    enabled = params.customVkCredentialsEnabled,
                    clientId = params.customVkClientId,
                    clientSecret = params.customVkClientSecret
                )
                customVkCredentialsError(customCredentials)?.let { error ->
                    updateLog("custom_vk_credentials_error", "Ошибка: пользовательские реквизиты VK не заполнены", 99, true)
                    setConnectionIssue(
                        "Не заполнены реквизиты VK",
                        "$error Откройте «Настройки → Клиент ID» или выключите пользовательский режим."
                    )
                    running.value = false
                    currentParams = null
                    return@launch
                }
                
                // Robust hash parsing: split by comma, newline, or whitespace
                val hashList = targetHash
                    .split(Regex("[,\\s\\n]+"))
                    .map { it.trim() }
                    .filter { it.isNotEmpty() }
                    .take(4)

                if (hashList.isEmpty()) {
                    val title = "VK-хеш не указан"
                    updateLog("hash_error", "Ошибка: Хеш не указан", 99, true)
                    setConnectionIssue(title, "Откройте настройку VK-хешей и добавьте ссылку VK-звонка или хеш после /join/.")
                    running.value = false
                    currentParams = null
                    return@launch
                }
                if (params.connectionPassword.isBlank()) {
                    val title = "Пароль подключения не указан"
                    updateLog("password_error", "Ошибка: пароль подключения не указан", 99, true)
                    setConnectionIssue(title, "Откройте «Секреты» и введите пароль туннеля или используйте готовую wdtt:// ссылку.")
                    running.value = false
                    currentParams = null
                    return@launch
                }

                val hashCount = hashList.size.coerceIn(1, 4)
                val totalWorkers = normalizeTunnelWorkerCount(
                    requested = params.workersPerHash,
                    profileMaxWorkers = params.profileMaxWorkers
                )
                
                val hashMode = if (activeHashIndex == 0) "Основной" else "Запасной"
                updateLog("config_info", "[$hashMode] Хешей=$hashCount, Потоков=$totalWorkers", 1)

                val binaryPath = context.applicationInfo.nativeLibraryDir + "/libclient.so"
                val binaryFile = File(binaryPath)
                
                if (!binaryFile.exists()) {
                    updateLog("binary_error", "Ошибка: Бинарный файл не найден", 99, true)
                    setConnectionIssue("Не найден нативный клиент", "Переустановите APK или соберите приложение заново: внутри APK отсутствует libclient.so.")
                    currentParams = null
                    return@launch
                }

                val cmd = mutableListOf(
                    binaryPath,
                    "-peer", params.peer,
                    "-vk", hashList.joinToString(","),
                    "-n", totalWorkers.toString(),
                    "-listen", "127.0.0.1:${params.port}"
                )

                if (params.fingerprint.isNotEmpty()) {
                    cmd.add("-fingerprint")
                    cmd.add(params.fingerprint)
                }

                if (params.clientIds.isNotEmpty()) {
                    cmd.add("-client-ids")
                    cmd.add(params.clientIds)
                }

                // Go boolean flags must use -flag=value. A separate "false" value
                // stops flag.Parse and silently drops every argument after it.
                vkCallsPreflightCooldownUntilMs = maxOf(
                    vkCallsPreflightCooldownUntilMs,
                    restoreVkCallsPreflightCooldown(appContext),
                )
                val useVkCallsPreflight = shouldUseVkCallsPreflight(
                    enabledByUser = params.vkCallsPreflight,
                    cooldownUntilMs = vkCallsPreflightCooldownUntilMs,
                )
                cmd.add("-vkcalls-preflight=$useVkCallsPreflight")
                if (params.vkCallsPreflight && !useVkCallsPreflight) {
                    val remainingSeconds = ((vkCallsPreflightCooldownUntilMs -
                        System.currentTimeMillis()).coerceAtLeast(0L) + 999L) / 1_000L
                    updateLog(
                        "vkcalls_restart_cooldown",
                        "[VKCalls] До следующей проверки ждём ещё ${remainingSeconds} с; используем legacy-резерв",
                        20,
                        false,
                    )
                }
                cmd.add("-turn-stream-first=${params.rtNetwork}")
                if (params.rtNetwork) {
                    val turnSni = normalizeRtTurnSni(params.rtTurnSni)
                    if (turnSni != null) {
                        cmd.add("-turn-sni")
                        cmd.add(turnSni)
                    } else if (params.rtTurnSni.isNotBlank()) {
                        updateWarningLog(
                            "rt_sni_invalid",
                            "[TURN] SNI режима «Сеть РТ» имеет неверный формат; запускаем TCP/TLS без подмены SNI",
                            20,
                        )
                    }
                }
                val useRtMasque = shouldUseRtMasque(params.rtNetwork, params.rtMasque)
                cmd.add("-rt-masque=$useRtMasque")
                if (useRtMasque) {
                    val masqueConfig = File(appContext.filesDir, RT_MASQUE_CONFIG_FILE_NAME)
                    cmd.add("-rt-masque-config")
                    cmd.add(masqueConfig.absolutePath)
                    cmd.add("-rt-masque-accept-tos=true")
                    if (
                        !masqueConfig.exists() &&
                        shouldUseRtMasqueServerBootstrap(
                            rtNetwork = params.rtNetwork,
                            rtMasque = params.rtMasque,
                            serverBootstrap = params.rtMasqueServerBootstrap,
                        )
                    ) {
                        closeWarpApiSshRelay()
                        when (val relayResult = WarpApiSshRelay.start(appContext, params.profileIndex)) {
                            is WarpApiSshRelayStartResult.Ready -> {
                                warpApiSshRelay = relayResult.relay
                                cmd.add("-warp-api-relay")
                                cmd.add(relayResult.relay.loopbackAddress)
                                updateLog(
                                    "masque_server_bootstrap_ready",
                                    "[MASQUE] Для первой регистрации подготовлен защищённый выход через сервер профиля ✓",
                                    4,
                                )
                            }
                            WarpApiSshRelayStartResult.MissingProfileAccess -> {
                                updateWarningLog(
                                    "masque_server_bootstrap_missing",
                                    "[MASQUE] «Через сервер» недоступен: в «Деплой» нет адреса сервера или выбранного SSH-доступа (пароль/приватный ключ); пробуем прямую регистрацию",
                                    20,
                                )
                            }
                            is WarpApiSshRelayStartResult.Failed -> {
                                updateWarningLog(
                                    "masque_server_bootstrap_failed",
                                    "[MASQUE] Выход через сервер не подготовлен: ${relayResult.message}; пробуем прямую регистрацию",
                                    20,
                                )
                            }
                        }
                    }
                }

                val androidId = SettingsStore(appContext).getOrCreateTunnelDeviceId()
                cmd.add("-device-id")
                cmd.add(androidId)
                cmd.add("-device-info")
                cmd.add(buildDeviceInfoJson(appContext))

                cmd.add("-password")
                cmd.add(params.connectionPassword)

                if (
                    params.managedConfigFirstStart &&
                    params.profileMaxWorkers >= TUNNEL_WORKERS_PER_GROUP
                ) {
                    cmd.add("-config-first-start=true")
                    if (totalWorkers == TUNNEL_WORKERS_PER_GROUP) {
                        cmd.add("-hash-fallback=true")
                    }
                }

                cmd.add("-captcha-mode")
                cmd.add(params.captchaMode)

                val pb = ProcessBuilder(cmd)
                pb.directory(context.filesDir)
                pb.redirectErrorStream(true)
                
                val env = pb.environment()
                env["LD_LIBRARY_PATH"] = context.applicationInfo.nativeLibraryDir
                if (params.customVkCredentialsEnabled) {
                    env["WDTT_CUSTOM_VK_CLIENT_ID"] = params.customVkClientId
                    env["WDTT_CUSTOM_VK_CLIENT_SECRET"] = params.customVkClientSecret
                } else {
                    env.remove("WDTT_CUSTOM_VK_CLIENT_ID")
                    env.remove("WDTT_CUSTOM_VK_CLIENT_SECRET")
                }

                process = pb.start()
                processStartedAtMs = System.currentTimeMillis()
                wrapAuthTimeoutCount = 0
                resetStatsLivenessState()
                running.value = true
                clearTransition()
                startLogReader()
                startWatchdog(appContext, params)

            } catch (e: Exception) {
                closeWarpApiSshRelay()
                val message = e.readableMessage()
                updateLog("critical_start_error", "Критическая ошибка запуска: $message", 99, true)
                setConnectionIssue("Не удалось запустить подключение", "Проверьте настройки туннеля и попробуйте подключиться снова. Причина: $message")
                e.printStackTrace()
                if (isSwitching && currentParams != null) {
                    // При автоматическом восстановлении не превращаем неудачную
                    // попытку в окончательную остановку: служба оставляет параметры
                    // сессии и сможет повторить восстановление позже.
                    running.value = true
                    processStartedAtMs = System.currentTimeMillis()
                    updateWarningLog(
                        "vpn_recovery_retry_pending",
                        "[VPN] Автоматическое восстановление пока не завершилось; сохраняем сессию и повторим попытку позже.",
                        50,
                    )
                } else {
                    running.value = false
                    currentParams = null
                }
                clearTransition()
            } finally {
                if (!isSwitching) clearTransition()
                startStopMutex.unlock()
            }
        }
    }

    private fun startLogReader() {
        readerJob = scope.launch {
            val observedProcess = process ?: return@launch
            val reader = observedProcess.inputStream.bufferedReader()
            var collectingConfig = false
            val configBuilder = StringBuilder()

            try {
                var lastResetTime = System.currentTimeMillis()

                reader.forEachLine { line ->
                    val now = System.currentTimeMillis()
                    if (now - lastResetTime > 60000) {
                        refusedCount = 0
                        floodCount = 0
                        mismatchCount = 0
                        currentHashErrorCount = 0
                        lastResetTime = now
                    }

                    val msgPrefixReplaced = line.replace(Regex("^\\d{4}/\\d{2}/\\d{2}\\s\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?\\s"), "")
                    val lineTrim = msgPrefixReplaced.trim()

                    val vkCallsCooldownMs = vkCallsPreflightCooldownForLog(lineTrim)
                    if (vkCallsCooldownMs > 0L) {
                        lastContext?.let { context ->
                            extendVkCallsPreflightCooldown(context, vkCallsCooldownMs, now)
                        }
                    }

                    if (lineTrim.contains("[МОЩНОСТЬ] Лимит временно занят", true)) {
                        updateLog(
                            "worker_policy_wait",
                            "[МОЩНОСТЬ] Свободные потоки этого профиля временно заняты; повторяем подключение автоматически",
                            20,
                            false
                        )
                        return@forEachLine
                    }

                    if (lineTrim.contains("[МОЩНОСТЬ] Сервер остановил лишний поток", true)) {
                        updateLog(
                            "worker_policy_limit",
                            "[МОЩНОСТЬ] Лишние потоки остановлены согласно ограничению этого доступа; подключение продолжает работать",
                            20,
                            false
                        )
                        return@forEachLine
                    }

                    val isCaptchaV2FallbackStatus = lineTrim.contains("[КАПЧА] v2", true) &&
                        (
                            lineTrim.contains("fallback продолжит", true) ||
                            lineTrim.contains("getContent не принял", true) ||
                            lineTrim.contains("status not_ok", true) ||
                            lineTrim.contains("attempts exhausted", true)
                        )
                    val isCaptchaProtocolResult = lineTrim.startsWith("[STDIN] CAPTCHA_RESULT|", true)
                    val isVkCallsFallback = lineTrim.contains("[VKCalls]", true) &&
                        (
                            lineTrim.contains("preflight не сработал", true) ||
                                lineTrim.contains("временно ограничил", true) ||
                                lineTrim.contains("временно пропущен", true) ||
                                lineTrim.contains("пробуем совместимый резерв", true)
                        )
                    val isError = !isCaptchaV2FallbackStatus && !isCaptchaProtocolResult && !isVkCallsFallback && (
                        lineTrim.contains("Ошибка", true) ||
                            lineTrim.contains("error", true) ||
                            lineTrim.contains("FAIL", true) ||
                            lineTrim.contains("timeout", true) ||
                            lineTrim.contains("refused", true) ||
                            lineTrim.contains("unreachable", true) ||
                            lineTrim.contains("FATAL_AUTH", true)
                        )

                    if (lineTrim.contains("FATAL_AUTH")) {
                        val isWrapHandshakeTimeout = lineTrim.contains("DTLS timeout", true) ||
                            lineTrim.contains("WRAP_AUTH_TIMEOUT", true)
                        if (isWrapHandshakeTimeout) {
                            if (activeWorkers.value > 0) {
                                wrapAuthTimeoutCount = 0
                                updateLog(
                                    "wrap_timeout_recovered",
                                    WRAP_HANDSHAKE_RETRY_MESSAGE,
                                    20,
                                    false
                                )
                            } else {
                                wrapAuthTimeoutCount++
                                updateWarningLog(
                                    "wrap_timeout_wait",
                                    WRAP_HANDSHAKE_RETRY_MESSAGE,
                                    50
                                )
                            }
                            return@forEachLine
                        }

                        val accessExpired = isExpiredAccessAuthFailure(lineTrim)
                        val reason = when {
                            lineTrim.contains("неверный пароль") -> "Неверный пароль подключения"
                            accessExpired -> "Срок действия пароля истёк"
                            lineTrim.contains("другому устройству") -> "Пароль привязан к другому устройству"
                            else -> "Ошибка авторизации"
                        }
                        val action = when {
                            lineTrim.contains("неверный пароль") ->
                                "Проверьте пароль в «Секретах» или вставьте актуальную wdtt:// ссылку."
                            accessExpired ->
                                "Откройте профиль, чтобы проверить срок и доступные действия."
                            lineTrim.contains("другому устройству") ->
                                (
                                    "Этот пароль уже закреплён за другим устройством. " +
                                        "Запросите отвязку или новый профиль у поставщика."
                                    )
                            else ->
                                "Проверьте пароль, VK-хеш и состояние сервера, затем попробуйте подключиться снова."
                        }
                        setConnectionIssue(
                            reason,
                            action,
                            kind = if (accessExpired) {
                                ConnectionIssueKind.ACCESS
                            } else {
                                ConnectionIssueKind.GENERAL
                            },
                        )
                        if (accessExpired) {
                            updateLog(
                                "access_expired",
                                "[ДОСТУП] Срок действия профиля закончился. Откройте вкладку «Туннель», чтобы проверить доступные действия.",
                                20,
                                true,
                            )
                            val accessContext = lastContext
                            val accessProfile = currentParams?.profileIndex
                            if (accessContext != null && accessProfile != null) {
                                scope.launch {
                                    AccessLifecycleCoordinator.noteServerDenied(
                                        accessContext,
                                        accessProfile,
                                    )
                                }
                            }
                        }
                        handleCriticalError(
                            "\uD83D\uDD12 $reason. Воркеры остановлены.",
                            if (accessExpired) {
                                TunnelStopReason.AccessExpired
                            } else {
                                TunnelStopReason.CriticalError
                            },
                        )
                        return@forEachLine
                    }

                    if (lineTrim.contains("Ошибка Reader:", true)) {
                        if (lineTrim.contains("EOF", true) || lineTrim.contains("use of closed network connection", true)) {
                            updateLog(
                                "transport_reader_closed",
                                "[ТРАНСПОРТ] Часть каналов закрылась; воркеры переподключаются",
                                50,
                                false
                            )
                        } else {
                            noteRecoverableNetworkIssue(
                                "Канал транспорта закрылся с ошибкой",
                                "WDTT Plus переподключит транспорт, если связь не восстановится сама."
                            )
                            updateWarningLog(
                                "transport_reader_error",
                                "[ТРАНСПОРТ] Ошибка чтения канала: ${lineTrim.substringAfter("Ошибка Reader:").trim()}",
                                50
                            )
                        }
                        return@forEachLine
                    }

                    if (lineTrim.contains("WRAP_AUTH_TIMEOUT", true)) {
                        if (activeWorkers.value > 0) {
                            wrapAuthTimeoutCount = 0
                            updateLog(
                                "wrap_timeout_recovered",
                                WRAP_HANDSHAKE_RETRY_MESSAGE,
                                    20,
                                    false
                            )
                        } else {
                            wrapAuthTimeoutCount++
                            updateWarningLog(
                                "wrap_timeout_wait",
                                WRAP_HANDSHAKE_RETRY_MESSAGE,
                                    50
                            )
                        }
                        return@forEachLine
                    }

                    if (lineTrim.startsWith("CAPTCHA_SOLVE|")) {
                        val payload = lineTrim.substringAfter("CAPTCHA_SOLVE|")
                        val parts = payload.split("|", limit = 4)
                        when (parts.size) {
                            4 -> {
                                val requestId = parts[0]
                                val requestMode = parts[1]
                                val redirectUri = parts[2]
                                val sessionToken = parts[3]
                                scope.launch {
                                    handleCaptchaSolve(observedProcess, requestId, requestMode, redirectUri, sessionToken)
                                }
                            }
                            3 -> {
                                val requestMode = parts[0]
                                val redirectUri = parts[1]
                                val sessionToken = parts[2]
                                scope.launch {
                                    handleCaptchaSolve(observedProcess, "", requestMode, redirectUri, sessionToken)
                                }
                            }
                            2 -> {
                                val redirectUri = parts[0]
                                val sessionToken = parts[1]
                                scope.launch {
                                    handleCaptchaSolve(observedProcess, "", "selected", redirectUri, sessionToken)
                                }
                            }
                            else -> {
                                writeCaptchaResult(observedProcess, "", "error:invalid CAPTCHA_SOLVE format")
                            }
                        }
                        return@forEachLine
                    }

                    if (isError) {
                        when {
                            lineTrim.contains("Flood control", true) -> {
                                floodCount++
                                if (floodCount >= 5) {
                                    setConnectionIssue("VK временно ограничил запросы", "Подождите 10-20 минут, затем попробуйте снова. Если повторяется часто, смените VK-хеш или уменьшите мощность.")
                                    handleCriticalError("Flood Control (ВК ограничил ваш IP). Попробуйте позже.")
                                    return@forEachLine
                                }
                            }
                            lineTrim.contains("ip mismatch", true) -> {
                                mismatchCount++
                                if (mismatchCount >= 5) {
                                    setConnectionIssue("VK потерял текущий IP", "Переподключите VPN. Если сеть часто меняется между Wi-Fi/LTE, попробуйте закрепиться на одной сети.")
                                    handleCriticalError("IP Mismatch (IP утерян). Попробуйте переподключиться.")
                                    return@forEachLine
                                }
                            }
                            lineTrim.contains("connection refused", true) ||
                                lineTrim.contains("timeout", true) ||
                                isHardNetworkFailure(lineTrim) -> {
                                refusedCount++
                                if (refusedCount >= 400) {
                                    handleCriticalError("Критическое отсутствие сети (400+ таймаутов). Отключение.")
                                    return@forEachLine
                                }
                            }
                            lineTrim.contains("9000") || lineTrim.contains("Call not found", true) -> {
                                currentHashErrorCount++
                                if (currentHashErrorCount >= 10) {
                                    handleHashError()
                                    return@forEachLine
                                }
                            }
                        }
                    }

                    if (lineTrim.contains("[СТАТИСТИКА]")) {
                        val rawStats = lineTrim.substringAfter("[СТАТИСТИКА]").trim()
                        val msg = sessionTraffic.accumulate(rawStats)
                        persistSessionTraffic()
                        stats.value = msg
                        lastStatsAtMs = now

                        val match = Regex("Активных:\\s*(\\d+)").find(msg)
                        if (match != null) {
                            val active = match.groupValues[1].toIntOrNull() ?: 0
                            activeWorkers.value = active

                            val downSignature = trafficSignature(statsDownTrafficRegex, msg)
                            val upSignature = trafficSignature(statsUpTrafficRegex, msg)
                            val trafficKnown = downSignature.isNotBlank() && upSignature.isNotBlank()
                            val downstreamChanged = trafficKnown && downSignature != lastStatsDownTrafficSignature
                            val upstreamChanged = trafficKnown && upSignature != lastStatsUpTrafficSignature
                            val trafficChanged = downstreamChanged || upstreamChanged
                            if (trafficKnown && lastDownstreamTrafficChangedAtMs == 0L) {
                                lastStatsDownTrafficSignature = downSignature
                                lastStatsUpTrafficSignature = upSignature
                                lastDownstreamTrafficChangedAtMs = now
                                lastUpstreamTrafficChangedAtMs = now
                            } else if (trafficChanged) {
                                if (downstreamChanged) {
                                    lastStatsDownTrafficSignature = downSignature
                                    lastDownstreamTrafficChangedAtMs = now
                                }
                                if (upstreamChanged) {
                                    lastStatsUpTrafficSignature = upSignature
                                    lastUpstreamTrafficChangedAtMs = now
                                }
                                lastStagnantTrafficIssueAtMs = 0L
                            }

                            if (active > 0) {
                                if (!accessRefreshRequestedForProcess) {
                                    accessRefreshRequestedForProcess = true
                                    val accessContext = lastContext
                                    val accessProfile = currentParams?.profileIndex
                                    if (accessContext != null && accessProfile != null) {
                                        scope.launch {
                                            AccessLifecycleCoordinator.refreshAfterSuccessfulConnect(
                                                accessContext,
                                                accessProfile,
                                            )
                                        }
                                    }
                                }
                                lastActiveAtMs = now
                                wrapAuthTimeoutCount = 0

                                if (recoverableNetworkErrorAtMs > 0L &&
                                    isStatsTrafficStagnant(now) &&
                                    now - lastStagnantTrafficIssueAtMs > 60_000L
                                ) {
                                    lastStagnantTrafficIssueAtMs = now
                                    setConnectionIssue(
                                        "Трафик туннеля остановился",
                                        "Активные воркеры есть, но счётчики трафика долго не меняются. WDTT Plus попробует восстановить транспорт автоматически."
                                    )
                                } else if (
                                    shouldResetNetworkRecoveryFromStats(
                                        downstreamChanged = downstreamChanged,
                                        hardNetworkFailure = confirmedUserTrafficFailureAtMs > 0L,
                                        trafficChanged = trafficChanged,
                                        statsTrafficStagnant = isStatsTrafficStagnant(now),
                                    )
                                ) {
                                    resetNetworkRecoveryState()
                                    networkTransitionGraceUntilMs = 0L
                                    clearConnectionIssue()
                                }
                            }
                        }

                        updateLog("stats", "[СТАТИСТИКА] $msg", 3, false)
                        return@forEachLine
                    }

                    val workerRetry = classifyRecoverableWorkerRetry(lineTrim, activeWorkers.value)
                    val masquePresentation = classifyMasqueLog(lineTrim)
                    when {
                        masquePresentation != null -> {
                            val presentation = masquePresentation
                            if (presentation.warning) {
                                updateWarningLog(presentation.key, presentation.message, 20)
                            } else {
                                updateLog(presentation.key, presentation.message, 2, false)
                            }
                            if (presentation.startsDtls) {
                                updateLog("dtls_start", "[DTLS] Рукопожатие DTLS...", 1, false)
                            }
                            if (presentation.key == "masque_enrollment_saved") {
                                closeWarpApiSshRelay()
                            }
                        }
                        workerRetry != null -> {
                            if (activeWorkers.value <= 0) {
                                when (workerRetry.first) {
                                    "worker_turn_allocate_retry" -> noteRecoverableNetworkIssue(
                                        "TURN/UDP не отвечает",
                                        "VK API выдал TURN-данные, но TURN Allocate не получил ответ. WDTT Plus попробует другие TURN-пути и повторы; если ошибка повторяется, оператор может ограничивать UDP/TURN."
                                    )
                                    "worker_dtls_retry" -> noteRecoverableNetworkIssue(
                                        "VPS не отвечает на DTLS",
                                        "TURN Allocate прошёл, но рукопожатие DTLS до сервера не завершилось. Проверьте порт сервера, доступность VPS и пароль подключения."
                                    )
                                }
                            }
                            updateWarningLog(workerRetry.first, workerRetry.second, 20)
                        }
                        lineTrim.contains("[ВОРКЕР #", true) &&
                            lineTrim.contains("Невосстановимая TURN/STUN ошибка", true) ->
                            updateWarningLog(
                                "worker_turn_stopped",
                                "[TURN] Отдельные каналы завершили попытки подключения; остальные продолжают работу",
                                50
                            )
                        lineTrim.contains("[DNS]", true) -> {
                            val text = lineTrim.substringAfter("[DNS]").trim()
                            when {
                                text.contains("Прямой DNS клиента недоступен", true) &&
                                    text.contains("системный DNS", true) -> {
                                    noteRecoverableNetworkIssue(
                                        "Прямой DNS клиента недоступен",
                                        "Оператор не ответил на прямые DNS-запросы клиента. WDTT Plus использует системный DNS устройства для этого запуска."
                                    )
                                    updateWarningLog(
                                        "dns_system_fallback",
                                        "[DNS] Прямой DNS клиента недоступен, используем системный DNS устройства",
                                        20
                                    )
                                }
                                text.contains("DNS до VK недоступен", true) -> {
                                    noteRecoverableNetworkIssue(
                                        "DNS до VK недоступен",
                                        "Прямой DNS клиента и системный DNS устройства не ответили. Проверьте Private DNS, сеть оператора или попробуйте другую сеть."
                                    )
                                    updateWarningLog("dns_vk_unavailable", "[DNS] DNS до VK недоступен", 99)
                                }
                                else -> updateLog("dns_status", "[DNS] $text", 2, false)
                            }
                        }
                        lineTrim.contains("[VKCalls]", true) -> {
                            when {
                                lineTrim.contains("TURN credentials получены", true) ->
                                    updateLog("vkcalls_ok", "[VKCalls] Основной бескапчевый провайдер сработал ✓", 2, false)
                                lineTrim.contains("preflight не сработал", true) ||
                                    lineTrim.contains("временно ограничил", true) ||
                                    lineTrim.contains("временно пропущен", true) ->
                                    updateLog("vkcalls_fallback", "[VKCalls] Основной провайдер временно недоступен — пробуем совместимый резерв", 20, false)
                                lineTrim.contains("пробуем совместимый резерв", true) ->
                                    updateLog("vkcalls_api_fallback", "[VKCalls] Основной API-домен не ответил — пробуем совместимый резерв", 20, false)
                                lineTrim.endsWith("[VKCalls] preflight", true) ->
                                    updateLog("vkcalls_start", "[VKCalls] Пробуем основной бескапчевый провайдер...", 2, false)
                                else -> {
                                    if (isError) updateWarningLog("vkcalls_status", lineTrim, 20)
                                    else updateLog("vkcalls_status", lineTrim, 20, false)
                                }
                            }
                        }
                        lineTrim.contains("[VK Provider]", true) -> {
                            when {
                                lineTrim.contains("TURN-данные сохранены", true) -> {
                                    val lifetime = lineTrim.substringAfter("сохранены на", "").trim()
                                    updateLog(
                                        "vk_provider_cache",
                                        "[ВК] TURN-данные сохранены${lifetime.takeIf(String::isNotBlank)?.let { " на $it" }.orEmpty()}",
                                        2,
                                        false
                                    )
                                }
                                lineTrim.contains("legacy-custom", true) && lineTrim.contains("успешно", true) ->
                                    updateLog("vk_provider_custom", "[ВК] Собственный совместимый ID клиента сработал ✓", 5, false)
                                lineTrim.contains("legacy-custom", true) && lineTrim.contains("пробуем", true) ->
                                    updateLog("vk_provider_custom", "[ВК] Пробуем собственный совместимый ID клиента...", 5, false)
                                lineTrim.contains("legacy-custom", true) && lineTrim.contains("CAPTCHA_WAIT_REQUIRED", true) ->
                                    updateLog("vk_provider_custom_wait", "[КАПЧА] Собственный совместимый провайдер ждёт следующую безопасную попытку", 20, false)
                                lineTrim.contains("legacy-custom", true) && lineTrim.contains("не сработал", true) ->
                                    updateLog("vk_provider_custom_fallback", "[ВК] Собственный совместимый ID клиента не сработал — пробуем встроенный резерв", 20, false)
                                lineTrim.contains("legacy-built-in", true) && lineTrim.contains("успешно", true) ->
                                    updateLog("vk_provider_builtin", "[ВК] Встроенный совместимый ID клиента сработал ✓", 5, false)
                                lineTrim.contains("legacy-built-in", true) && lineTrim.contains("пробуем", true) ->
                                    updateLog("vk_provider_builtin", "[ВК] Пробуем встроенный совместимый ID клиента...", 5, false)
                                lineTrim.contains("legacy-built-in", true) && lineTrim.contains("CAPTCHA_WAIT_REQUIRED", true) ->
                                    updateLog("vk_provider_builtin_wait", "[КАПЧА] Встроенный совместимый провайдер ждёт следующую безопасную попытку", 20, false)
                                lineTrim.contains("legacy-built-in", true) && lineTrim.contains("не сработал", true) ->
                                    updateLog("vk_provider_builtin_fallback", "[ВК] Этот встроенный ID клиента не сработал — пробуем следующий", 20, false)
                                lineTrim.contains("modern-vkcalls", true) && lineTrim.contains("успешно", true) ->
                                    updateLog("vk_provider_modern", "[ВК] Используется современный VKCalls ✓", 2, false)
                                else -> updateLog("vk_provider_status", lineTrim, 20, false)
                            }
                        }
                        lineTrim.contains("[VK Auth]", true) -> {
                            when {
                                lineTrim.contains("Using cached credentials", true) ->
                                    updateLog("vk_credentials_cache", "[ВК] Используются ранее полученные TURN-данные", 2, false)
                                lineTrim.contains("Throttling", true) ->
                                    updateLog("vk_credentials_throttle", "[ВК] Безопасная пауза между запросами к VK", 20, false)
                                lineTrim.contains("Credentials cache invalidated", true) ->
                                    updateLog("vk_credentials_refresh", "[ВК] TURN-данные устарели — получаем свежие", 5, false)
                                lineTrim.contains("Multiple auth errors", true) ->
                                    updateWarningLog(
                                        "vk_credentials_refresh_after_auth",
                                        "[ВК] TURN-данные несколько раз отклонены — получаем свежие",
                                        20
                                    )
                                lineTrim.contains("getCallPreview failed", true) ->
                                    updateLog("vk_preview_optional", "[ВК] Предпросмотр звонка недоступен, продолжаем получение TURN-данных", 20, false)
                                lineTrim.contains("Rate limit detected", true) ->
                                    updateLog("vk_legacy_rate_limit", "[ВК] Этот совместимый ID клиента временно ограничен — пробуем следующий", 20, false)
                                lineTrim.contains("Все legacy-провайдеры", true) ->
                                    updateLog("vk_legacy_retry", "[ВК] Совместимые провайдеры временно не ответили — выполняется безопасный повтор", 20, false)
                                else -> {
                                    if (isError) updateWarningLog("vk_auth_status", lineTrim, 20)
                                }
                            }
                        }
                        lineTrim.contains("Auth error", true) && lineTrim.contains("[STREAM", true) -> {
                            updateWarningLog(
                                "turn_stream_auth_retry",
                                "[TURN] Сервер отклонил старые TURN-данные — обновляем данные и повторяем подключение",
                                20
                            )
                        }
                        lineTrim.contains("[КАПЧА] AUTO:") -> {
                            var text = lineTrim.substringAfter("[КАПЧА] AUTO:").trim()
                            text = text.replace(Regex("\\s*\\([^)]+\\)\\s*"), " ").trim()

                            val isIntermediateFallback = text.contains("не завершил проверку", true)
                            val isErr = !isIntermediateFallback && (
                                text.contains("ошибка", true) ||
                                    text.contains("timeout", true) ||
                                    text.contains("не решил", true)
                                )
                            // У WebView есть собственное финальное сообщение
                            // «Капча решена». Не дублируем его строкой из Go.
                            // У встроенной Go-проверки такого Android-события нет.
                            if (text.contains("Auto WebView решил капчу", true) ||
                                text.contains("Manual WebView решил капчу", true)
                            ) {
                                return@forEachLine
                            }
                            val displayText = text
                                .replace("стадия", "этап", ignoreCase = true)
                                .replace("Auto WebView", "Авто-WebView", ignoreCase = true)
                                .replace("Manual WebView", "ручной WebView", ignoreCase = true)
                                .replace("Go v2", "встроенная проверка", ignoreCase = true)
                            val stableKey = when {
                                text.contains("старт") -> "captcha_auto_1"
                                isIntermediateFallback -> "captcha_auto_next_challenge"
                                text.contains("Go v2") && text.contains("2 попыт") -> "captcha_auto_2"
                                text.contains("WBV Auto попытка") -> "captcha_auto_3"
                                text.contains("финальная") -> "captcha_auto_4"
                                text.contains("ручной WebView") -> "captcha_auto_5"
                                text.contains("решил") || text.contains("решила") -> "captcha_auto_done"
                                else -> "captcha_auto_${text.take(18).hashCode()}"
                            }
                            if (isErr) updateWarningLog(stableKey, "[КАПЧА AUTO] $displayText", 5)
                            else updateLog(stableKey, "[КАПЧА AUTO] $displayText", 5, false)
                        }

                        lineTrim.contains("[КАПЧА] RJS:") -> {
                            var text = lineTrim.substringAfter("[КАПЧА] RJS:").trim()
                            text = text.replace(Regex("\\s*\\([^)]+\\)\\s*"), " ").trim()
                            
                            val stableKey = when {
                                text.contains("Загрузка") || text.contains("fetch") -> "captcha_rjs_1"
                                text.contains("PoW") -> "captcha_rjs_2"
                                text.contains("осматривает") || text.contains("человек") -> "captcha_rjs_3"
                                text.contains("captchaNotRobot") || text.contains("Отправка") -> "captcha_rjs_4"
                                text.contains("endSession") -> "captcha_rjs_5"
                                text.contains("решена") -> "captcha_rjs_6"
                                else -> "captcha_rjs_${text.take(15).hashCode()}"
                            }
                            updateLog(stableKey, "[КАПЧА RJS] $text", 5, false)
                        }

                        lineTrim.contains("[КАПЧА] WBV:") -> {
                            var text = lineTrim.substringAfter("[КАПЧА] WBV:").trim()
                            text = text.replace(Regex("\\s*\\([^)]+\\)\\s*"), " ").trim()
                            // Такой текст посылали старые native-клиенты после
                            // уже показанного результата WebView.
                            if (text.contains("solve succeeded", true)) return@forEachLine
                            
                            val isErr = text.contains("Ошибка")
                            val stableKey = when {
                                text.contains("Запрос") -> "captcha_wv_step_2"
                                text.contains("Токен") -> "captcha_wv_step_5"
                                isErr -> "captcha_wv_err"
                                else -> "captcha_wv_go_other"
                            }
                            if (isErr) updateWarningLog(stableKey, "[КАПЧА WBV] $text", 5)
                            else updateLog(stableKey, "[КАПЧА WBV] $text", 5, false)
                        }

                        lineTrim.contains("Старт") || lineTrim.contains("Ожидайте") ->
                            updateLog("creds_start", "[ВК] Получение учетных данных...", 2, false)
                        lineTrim.contains("Креды получены") ->
                            updateLog("creds_lifetime", lineTrim, 2, false)
                        lineTrim.contains("Креды OK") || lineTrim.contains("Первые креды") ->
                            updateLog("creds_ok", "[ВК] Учетные данные проверены ✓", 2, false)
                        lineTrim.contains("Решаю VK Smart Captcha") ->
                            updateLog("captcha_start", "[КАПЧА] Решение капчи...", 5, false)
                        lineTrim.contains("Smart Captcha решена") ->
                            updateLog("captcha_done", "[КАПЧА] Капча решена ✓", 5, false)
                        lineTrim.contains("капча не решена") ||
                            lineTrim.contains("не решил капчу") ||
                            lineTrim.contains("ошибка решения капчи") ->
                            updateWarningLog("captcha_failed", "[КАПЧА] Текущий способ не решил капчу, пробуем следующий", 5)
                        lineTrim.contains("Timed out waiting for", true) && lineTrim.contains("ms", true) ->
                            updateLog("captcha_auto_timeout", "[КАПЧА] Авто-WebView не успел, используется следующий способ", 5, false)
                        lineTrim.contains("CAPTCHA_WAIT_REQUIRED", true) && activeWorkers.value > 0 ->
                            updateLog("captcha_group_retry", "[КАПЧА] Дополнительная группа повторит получение credentials позже", 20, false)
                        lineTrim.contains("Креды пока не получены", true) ->
                            updateLog("creds_group_retry", "[ВК] Дополнительная группа ждёт повторного получения credentials", 20, false)
                        lineTrim.contains("[WRAP]") -> {
                            val text = lineTrim.substringAfter("[WRAP]").trim()
                            updateLog("wrap_status", "[WRAP] $text", 1, false)
                        }
                        lineTrim.contains("[TURN]") -> {
                            val text = lineTrim.substringAfter("[TURN]").trim()
                            when {
                                text.contains("Креды уже заменены", true) ->
                                    updateLog(
                                        "turn_creds_current",
                                        "[TURN] Используем уже обновлённые данные без повторного запроса к VK",
                                        5,
                                        false
                                    )
                                text.contains("Креды обновлены", true) ->
                                    updateLog("turn_creds_refreshed", "[TURN] Креды обновлены, продолжаем подключение", 2, false)
                                text.contains("Креды уже обновлялись", true) ->
                                    updateLog("turn_creds_wait", "[TURN] Ждём перед повторным обновлением кредов", 2, false)
                                text.contains("временно ограничил новые allocation", true) ->
                                    updateWarningLog(
                                        "turn_capacity_retry",
                                        "[TURN] Узел временно ограничил новые каналы; повторяем без обновления данных VK",
                                        20
                                    )
                                text.contains("неполный ответ", true) ->
                                    updateWarningLog("turn_allocate_retry", "[TURN] Неполный Allocate-ответ, обновляем данные и повторяем", 20)
                                text.contains("Ошибка allocation/кредов", true) ->
                                    updateWarningLog("turn_allocate_retry", "[TURN] Allocate не выполнен, обновляем данные и повторяем", 20)
                                text.contains("Не удалось", true) || text.contains("failed", true) ->
                                    updateWarningLog("turn_refresh_failed", "[TURN] Не удалось обновить данные с этой попытки; повторяем", 80)
                                else ->
                                    updateLog("turn_status", "[TURN] $text", 2, false)
                            }
                        }
                        lineTrim.contains("[HEALTH]") -> {
                            val text = lineTrim.substringAfter("[HEALTH]").trim()
                            if (text.contains("сервер ответил на keepalive", true)) {
                                lastKeepaliveResponseAtMs = now
                            } else if (isTransportHealthRecovery(text)) {
                                resetNetworkRecoveryState()
                                clearConnectionIssue(ConnectionIssueKind.GENERAL)
                                updateLog(
                                    "transport_health_recovered",
                                    "[СВЯЗЬ] Ответы на пользовательский трафик снова поступают ✓",
                                    20,
                                    false,
                                )
                            } else {
                                val seconds = trailingSeconds(text)
                                val userTrafficStalled = text.contains("пользовательский трафик", true)
                                noteRecoverableNetworkIssue(
                                    if (userTrafficStalled) "Нет ответа на пользовательский трафик" else "Транспорт потерял ответ сервера",
                                    if (userTrafficStalled) {
                                        "Трафик уже ушёл в VPN, но сервер не ответил. WDTT Plus восстановит транспорт или выключит VPN, чтобы вернуть обычный интернет."
                                    } else {
                                        "Keepalive от сервера не пришёл. WDTT Plus перезапустит транспорт, если связь не восстановится сама."
                                    },
                                    // Нативный клиент уже выдержал собственный таймаут
                                    // неотвеченного пользовательского трафика. Keepalive
                                    // сюда не попадает, поэтому второй минутный порог
                                    // только откладывал восстановление реального зависания.
                                    hardFailure = isConfirmedUserTrafficFailure(userTrafficStalled),
                                    confirmedUserTrafficFailure = userTrafficStalled,
                                )
                                updateWarningLog(
                                    if (userTrafficStalled) "transport_health_user_traffic" else "transport_health_keepalive",
                                    if (userTrafficStalled) {
                                        "[СВЯЗЬ] Трафик ушёл в VPN, ответа сервера нет${seconds?.let { " $it сек" } ?: ""}. Восстанавливаем транспорт"
                                    } else {
                                        "[СВЯЗЬ] Сервер не отвечает на keepalive${seconds?.let { " $it сек" } ?: ""}. Переподключаем канал"
                                    },
                                    50
                                )
                            }
                        }
                        lineTrim.contains("Relay:") ->
                            updateLog("dtls_start", "[DTLS] Рукопожатие DTLS...", 1, false)
                        lineTrim.contains("DTLS ОК") ->
                            updateLog("dtls_ok", "[DTLS] Соединение установлено ✓", 1, false)
                        lineTrim.contains("Активна ✓") ->
                            updateLog("ready", "[READY] Туннель готов к работе ✓", 2, false)
                        lineTrim.contains("Ошибка конфига", true) &&
                            lineTrim.contains("чтение ответа конфига", true) &&
                            (lineTrim.contains("timeout", true) || lineTrim.contains("context deadline exceeded", true)) ->
                            updateWarningLog(
                                "worker_config_timeout_active",
                                if (activeWorkers.value > 0) {
                                    "[ПОТОК] Один канал не получил конфигурацию вовремя; активных=${activeWorkers.value}, работа продолжается"
                                } else {
                                    "[ПОТОК] Один канал не получил конфигурацию вовремя; пробуем через другие каналы"
                                },
                                3
                            )
                        
                        isError -> {
                            val errorKey = when {
                                isHardNetworkFailure(lineTrim) -> "err_hard_network"
                                isLocalDnsRefused(lineTrim) -> "err_local_dns_refused"
                                lineTrim.contains("lookup ", true) &&
                                    (
                                        lineTrim.contains("login.vk.ru", true) ||
                                            lineTrim.contains("api.vk.ru", true) ||
                                            lineTrim.contains("api.vk.me", true) ||
                                            lineTrim.contains("calls.okcdn.ru", true)
                                        ) -> "err_vk_dns"
                                lineTrim.contains("VK HTTPS", true) -> "err_vk_https"
                                lineTrim.contains("connection refused") -> "err_conn_refused"
                                lineTrim.contains("timeout") -> "err_timeout"
                                lineTrim.contains("кредов") -> "err_creds"
                                lineTrim.contains("DTLS") -> "err_dtls"
                                else -> "general_error_" + lineTrim.take(15).hashCode()
                            }
                            val failedVkHost = listOf("login.vk.ru", "api.vk.ru", "api.vk.me", "calls.okcdn.ru")
                                .firstOrNull { lineTrim.contains(it, true) }
                            val errorMessage = if (errorKey == "err_vk_dns") {
                                "[СЕТЬ] DNS до VK недоступен: ${failedVkHost ?: "VK/OK"}"
                            } else if (errorKey == "err_vk_https") {
                                "[VK] HTTPS до VK/OK не отвечает"
                            } else {
                                lineTrim
                            }
                            if (errorKey == "err_hard_network") {
                                noteRecoverableNetworkIssue(
                                    "Сеть телефона недоступна для транспорта",
                                    "WDTT Plus попробует быстро восстановить транспорт. Если связь не вернётся, VPN будет выключен, чтобы вернуть обычный интернет.",
                                    hardFailure = true
                                )
                            } else if (errorKey == "err_local_dns_refused") {
                                noteRecoverableNetworkIssue(
                                    "DNS телефона не отвечает",
                                    "Локальный DNS вернул отказ. WDTT Plus попробует быстро восстановить транспорт, затем выключит VPN, если интернет не вернётся.",
                                    hardFailure = true
                                )
                            } else if (errorKey == "err_vk_dns") {
                                noteRecoverableNetworkIssue(
                                    "DNS до VK недоступен",
                                    "WDTT Plus попробует восстановить транспорт автоматически. Если не восстановится, проверьте интернет без VPN и DNS на устройстве."
                                )
                            } else if (errorKey == "err_vk_https") {
                                noteRecoverableNetworkIssue(
                                    "HTTPS до VK/OK не отвечает",
                                    "DNS сработал, но HTTPS-запрос к VK/OK не завершился. WDTT Plus попробует восстановить транспорт; если повторяется, проверьте ограничения сети оператора."
                                )
                            } else if (errorKey == "err_timeout" || errorKey == "err_conn_refused") {
                                noteRecoverableNetworkIssue(
                                    "Транспорт не отвечает",
                                    "WDTT Plus попробует переподключиться. Если ошибка повторяется, проверьте сеть, VK-хеш и доступность UDP-порта сервера."
                                )
                            }
                            val recoverableError = errorKey in setOf(
                                "err_hard_network",
                                "err_local_dns_refused",
                                "err_vk_dns",
                                "err_vk_https",
                                "err_conn_refused",
                                "err_timeout",
                                "err_creds"
                            ) || (errorKey == "err_dtls" && activeWorkers.value > 0)
                            if (recoverableError) {
                                updateWarningLog(errorKey, errorMessage, 99)
                            } else {
                                updateLog(errorKey, errorMessage, 99, true)
                            }
                        }
                    }

                    if (line.contains("╔") && line.contains("WireGuard")) {
                        collectingConfig = true
                        configBuilder.clear()
                        return@forEachLine
                    } else if (collectingConfig) {
                        if (line.contains("╚")) {
                            collectingConfig = false
                            val configStr = configBuilder.toString().trim()
                            config.value = configStr
                            
                            scope.launch(Dispatchers.Main) {
                                try {
                                    wgHelper?.startTunnel(configStr)
                                } catch (e: Exception) {
                                    val message = e.readableMessage()
                                    updateLog("vpn_start_error", "Ошибка запуска VPN: $message", 99, true)
                                    setConnectionIssue("WireGuard не запустился", "Проверьте VPN-разрешение Android и попробуйте снова. Причина: $message")
                                }
                            }
                        } else if (line.contains("║")) {
                            val content = line.replace("║", "").trim()
                            if (content.isNotEmpty()) {
                                configBuilder.appendLine(content)
                            }
                        }
                        return@forEachLine
                    }
                }
            } catch (e: Exception) {
                if (!e.message.toString().contains("read interrupted by close", ignoreCase = true)) {
                    val message = e.readableMessage()
                    updateLog("sys_error", "Системная ошибка: $message", -1, true)
                    setConnectionIssue("Системная ошибка туннеля", "Попробуйте подключиться снова. Причина: $message")
                }
            } finally {
                if (process === observedProcess) {
                    process = null
                    if (currentParams == null) {
                        running.value = false
                    }
                }
            }
        }
    }

    private fun handleCriticalError(
        message: String,
        stopReason: TunnelStopReason = TunnelStopReason.CriticalError,
    ) {
        if (connectionIssue.value == null) {
            setConnectionIssue("Подключение остановлено", "$message Проверьте настройки и попробуйте снова.")
        }
        updateLog("circuit_breaker", "[СТОП] $message", -1, true)
        stop(stopReason)
    }

    private fun handleHashError() {
        val params = currentParams ?: return
        val context = lastContext ?: return

        currentHashErrorCount = 0
        forceRegenerateUA = true

        if (params.secondaryVkHash.isNotEmpty() && activeHashIndex == 0) {
            updateWarningLog("hash_switch", "Основной VK-хеш недоступен, переключаемся на запасной", 50)
            activeHashIndex = 1
            stopOnlyProcess()
            start(context, params, isSwitching = true)
        } else {
            val msg = if (activeHashIndex == 1) "Запасной хеш тоже мертв. Отключение." else "Хеш умер, запасного нет. Отключение."
            setConnectionIssue("VK-звонок недоступен", "Проверьте, что групповой звонок VK ещё жив, и замените VK-хеш при необходимости.")
            handleCriticalError(msg)
        }
    }

    private fun startWatchdog(context: Context, params: TunnelParams) {
        watchdogJob?.cancel()
        watchdogJob = scope.launch {
            var zeroWorkersSince = 0L
            var processDeadSince = 0L
            val powerManager = context.getSystemService(Context.POWER_SERVICE) as? android.os.PowerManager
            delay(10_000)
            while (isActive && running.value) {
                if (
                    !shouldObserveTunnelHealth(
                        deviceInteractive = powerManager?.isInteractive != false,
                        wakeRecoveryGraceActive = isWakeRecoveryGraceActive(),
                    )
                ) {
                    // Сон и первые секунды после пробуждения не входят в длительность
                    // неисправности. Иначе старый таймер срабатывает сразу при включении
                    // экрана и без необходимости перезапускает транспорт.
                    zeroWorkersSince = 0L
                    processDeadSince = 0L
                    delay(10_000)
                    continue
                }
                val proc = process
                if (proc == null || !proc.isAlive) {
                    val now = System.currentTimeMillis()
                    if (processDeadSince == 0L) {
                        processDeadSince = now
                    }
                    if (isNetworkTransitionGraceActive() || isCaptchaInProgress()) {
                        delay(10_000)
                        continue
                    }
                    if (now - processDeadSince < 60_000L) {
                        delay(10_000)
                        continue
                    }
                    forceRegenerateUA = true
                    if (restartTransport(
                            reason = "[WATCHDOG] Процесс транспорта остановился. Мягкий перезапуск...",
                            minIntervalMs = 2 * 60_000L
                        )
                    ) {
                        return@launch
                    }
                } else {
                    processDeadSince = 0L
                }

                val workers = activeWorkers.value
                if (workers <= 0) {
                    if (zeroWorkersSince == 0L) {
                        zeroWorkersSince = System.currentTimeMillis()
                    } else if (
                        wrapAuthTimeoutCount >= 3 &&
                        processStartedAtMs > 0L &&
                        System.currentTimeMillis() - processStartedAtMs > 30_000 &&
                        lastActiveAtMs == 0L &&
                        !isCaptchaInProgress()
                    ) {
                        val wrapStopMessage = if (currentParams?.rtNetwork == true) {
                            "\uD83C\uDF10 Через сеть РТ не получен ответ WRAP. Обычно сеть не пропустила выбранный TURN/SNI; реже причина в пароле или совместимости WRAP. Воркеры остановлены."
                        } else {
                            "\uD83D\uDD12 Неверный пароль подключения или несовместимый WRAP. Воркеры остановлены."
                        }
                        handleCriticalError(wrapStopMessage)
                        return@launch
                    } else if (
                        System.currentTimeMillis() - zeroWorkersSince > (if (AMNEZIA_STYLE_RECOVERY) STABLE_ZERO_WORKERS_GRACE_MS else 3 * 60_000L) &&
                        !isCaptchaInProgress()
                    ) {
                        if (isNetworkTransitionGraceActive()) {
                            delay(10_000)
                            continue
                        }
                        forceRegenerateUA = true
                        if (restartTransport(
                                reason = if (AMNEZIA_STYLE_RECOVERY) {
                                    "[WATCHDOG] Долго нет рабочих потоков. Одна мягкая попытка восстановления транспорта..."
                                } else {
                                    "[WATCHDOG] Нет рабочих потоков после ожидания сети. Мягкий перезапуск транспорта..."
                                },
                                minIntervalMs = if (AMNEZIA_STYLE_RECOVERY) STABLE_RECOVERY_RETRY_MS else 2 * 60_000L
                            )
                        ) {
                            return@launch
                        }
                        zeroWorkersSince = System.currentTimeMillis()
                    }
                } else {
                    zeroWorkersSince = 0L
                }

                delay(5_000)
            }
        }
    }

    fun restartTransport(
        reason: String = "[СЕТЬ] Мягкий перезапуск транспорта...",
        minIntervalMs: Long = 20_000L,
        force: Boolean = false
    ): Boolean {
        val params = currentParams ?: return false
        val context = lastContext ?: return false
        val now = System.currentTimeMillis()
        val cooldownMs = (minIntervalMs + softRestartCount.coerceAtMost(4) * 30_000L).coerceAtMost(5 * 60_000L)
        if (!force && now - lastSoftRestartAtMs < cooldownMs) {
            updateLog(
                "network_restart_wait",
                "[СЕТЬ] Перезапуск отложен: ждём стабилизации сети, чтобы не плодить попытки подключения к VK.",
                50,
                false
            )
            return false
        }
        lastSoftRestartAtMs = now
        softRestartCount++
        updateLog("network_restart", reason, 50, false)
        activeWorkers.value = 0
        resetStatsLivenessState()
        noteSessionTransportRestart()
        val restartDelayMs = transportRecoveryPolicy(
            params.managedConfigFirstStart
        ).processRestartDelayMs
        scope.launch {
            killProcess()
            delay(restartDelayMs)
            if (currentParams === params && running.value) {
                start(context, params, isSwitching = true)
            }
        }
        return true
    }

    internal fun applyUpdatedProfileConfiguration(
        context: Context,
        params: TunnelParams,
        restartTransport: Boolean,
    ): TunnelProfileRuntimeApplyResult {
        val previous = currentParams ?: return TunnelProfileRuntimeApplyResult.INACTIVE
        if (!running.value || previous.profileIndex != params.profileIndex) {
            return TunnelProfileRuntimeApplyResult.INACTIVE
        }
        if (!tunnelProfileRuntimeConfigurationChanged(previous, params)) {
            return TunnelProfileRuntimeApplyResult.UNCHANGED
        }

        val appContext = context.applicationContext
        currentParams = params
        lastContext = appContext
        activeHashIndex = 0
        currentHashErrorCount = 0
        wrapAuthTimeoutCount = 0
        currentCaptchaMode = params.captchaMode
        currentCaptchaSolveMethod = params.captchaSolveMethod
        accessRefreshRequestedForProcess = false
        resetNetworkRecoveryState()
        resetStatsLivenessState()
        clearConnectionIssue(ConnectionIssueKind.GENERAL)
        activeWorkers.value = 0

        if (!restartTransport) {
            updateLog(
                "profile_runtime_update_pending",
                "[ПРОФИЛЬ] Новые параметры сохранены и будут применены при возобновлении VPN.",
                20,
                false,
            )
            return TunnelProfileRuntimeApplyResult.STORED_FOR_RESUME
        }

        updateLog(
            "profile_runtime_update",
            "[ПРОФИЛЬ] Параметры активного подключения обновлены. Мягко переподключаю транспорт.",
            20,
            false,
        )
        scope.launch {
            startStopMutex.lock()
            try {
                if (currentParams !== params || !running.value) return@launch
                noteSessionTransportRestart()
                killProcess()
                delay(250L)
            } finally {
                startStopMutex.unlock()
            }
            if (currentParams === params && running.value) {
                start(appContext, params, isSwitching = true, preserveLogs = true)
            }
        }
        return TunnelProfileRuntimeApplyResult.RESTARTED
    }

    fun noteUnderlyingNetworkChanged(
        reason: String,
        graceMs: Long = RECOVERABLE_NETWORK_GRACE_MS,
        replaceGrace: Boolean = true
    ) {
        if (!running.value) return
        val now = System.currentTimeMillis()
        lastUnderlyingNetworkChangeAtMs = now
        networkTransitionGraceUntilMs = if (replaceGrace) {
            now + graceMs
        } else {
            maxOf(networkTransitionGraceUntilMs, now + graceMs)
        }
        if (recoveryAttempts == 0 && hardNetworkErrorAtMs == 0L) {
            recoverableNetworkErrorAtMs = 0L
            val issueTitle = connectionIssue.value?.title
            if (issueTitle == "DNS до VK недоступен" ||
                issueTitle == "Транспорт не отвечает" ||
                issueTitle == "Туннель не подаёт признаков жизни"
            ) {
                clearConnectionIssue()
            }
        }
        updateLog(
            "network_transition",
            "[СЕТЬ] $reason. Ждём стабилизации сети без перезапуска VPN.",
            50,
            false
        )
    }

    fun isNetworkTransitionGraceActive(now: Long = System.currentTimeMillis()): Boolean =
        now < networkTransitionGraceUntilMs

    fun isWakeRecoveryGraceActive(now: Long = System.currentTimeMillis()): Boolean =
        now < wakeRecoveryGraceUntilMs

    fun noteDeviceSleepStarted() {
        if (!running.value) return
        // Ошибки, возникшие до или во время сна, нельзя переносить в решение о
        // восстановлении после пробуждения: сеть и вывод статистики в этот период
        // могут штатно приостанавливаться Android.
        wakeRecoveryGraceUntilMs = 0L
        sendTransportLifecycleCommand("DEVICE_SLEEP")
    }

    fun noteDeviceWakeStarted(now: Long = System.currentTimeMillis()) {
        if (!running.value) return
        resetNetworkRecoveryState()
        sendTransportLifecycleCommand("DEVICE_WAKE")
        wakeRecoveryGraceUntilMs = now + WAKE_RECOVERY_GRACE_MS
        networkTransitionGraceUntilMs = maxOf(networkTransitionGraceUntilMs, wakeRecoveryGraceUntilMs)
        updateLog(
            "wake_stabilization",
            "[СОН] Экран включён; даём текущему VPN восстановить активность без перезапуска.",
            20,
            false,
        )
    }

    fun connectionIssueTitleForNotification(now: Long = System.currentTimeMillis()): String? {
        val issue = connectionIssue.value ?: return null
        if (!running.value) return null
        val firstGraceMs = if (hardNetworkErrorAtMs > 0L) HARD_NETWORK_GRACE_MS else RECOVERABLE_NETWORK_GRACE_MS
        val waitingBeforeFirstRecovery = shouldDeferConnectionIssueNotification(
            confirmedUserTrafficFailure = confirmedUserTrafficFailureAtMs > 0L,
            recoverableNetworkErrorAtMs = recoverableNetworkErrorAtMs,
            recoveryAttempts = recoveryAttempts,
            nowMs = now,
            firstGraceMs = firstGraceMs,
        )
        return if (waitingBeforeFirstRecovery) null else issue.title
    }

    fun shouldSoftRestartAfterNetworkSettled(
        now: Long = System.currentTimeMillis(),
        settleMs: Long = 30_000L,
        freshActiveMs: Long = 45_000L
    ): Boolean {
        if (!running.value || isCaptchaInProgress()) return false
        if (now < networkTransitionGraceUntilMs) return false
        val changedAt = lastUnderlyingNetworkChangeAtMs
        if (changedAt == 0L || now - changedAt < settleMs) return false
        if (lastActiveAtMs >= changedAt && now - lastActiveAtMs < freshActiveMs) return false
        if (lastStatsAtMs >= changedAt && activeWorkers.value > 0 && now - lastStatsAtMs < freshActiveMs) return false
        if (now - lastNetworkSettleRestartAtMs < 5 * 60_000L) return false
        lastNetworkSettleRestartAtMs = now
        return true
    }

    fun hasFreshTunnelActivitySince(sinceMs: Long, now: Long = System.currentTimeMillis()): Boolean {
        return hasFreshTransportHeartbeat(
            running = running.value,
            activeWorkers = activeWorkers.value,
            lastInboundTrafficAtMs = lastDownstreamTrafficChangedAtMs,
            sinceMs = sinceMs,
            nowMs = now,
        )
    }

    fun hasFreshTransportPathSince(sinceMs: Long, now: Long = System.currentTimeMillis()): Boolean {
        return hasFreshTransportPath(
            running = running.value,
            activeWorkers = activeWorkers.value,
            lastInboundTrafficAtMs = lastDownstreamTrafficChangedAtMs,
            lastKeepaliveResponseAtMs = lastKeepaliveResponseAtMs,
            sinceMs = sinceMs,
            nowMs = now,
        )
    }

    fun hasConfirmedNetworkFailureSince(sinceMs: Long): Boolean =
        hasConfirmedNetworkFailureAtOrAfter(
            running = running.value,
            hardNetworkErrorAtMs = confirmedUserTrafficFailureAtMs,
            sinceMs = sinceMs,
        )

    private fun sendTransportLifecycleCommand(command: String) {
        val observedProcess = process ?: return
        synchronized(processInputLock) {
            if (process !== observedProcess || !observedProcess.isAlive) return
            runCatching {
                observedProcess.outputStream.write("$command\n".toByteArray(Charsets.UTF_8))
                observedProcess.outputStream.flush()
            }
        }
    }

    fun noteWakeRescueHealthy() {
        updateLog(
            "wake_rescue_ok",
            "[СОН] VPN подал свежие признаки жизни после пробуждения.",
            50,
            false
        )
    }

    fun noteWakeRescueDeferred() {
        updateWarningLog(
            "wake_rescue_deferred",
            "[СОН] После пробуждения транспорт ещё не подал свежих признаков жизни. VPN-интерфейс оставлен активным; продолжаем наблюдение без аварийного отключения.",
            50,
        )
    }

    fun noteSleepVpnPaused() {
        updateLog(
            "sleep_vpn_paused",
            "[СОН] VPN временно отключён для экономии батареи; интернет телефона идёт напрямую.",
            20,
            false,
        )
    }

    fun noteSleepVpnPauseFailed() {
        updateWarningLog(
            "sleep_vpn_pause_failed",
            "[СОН] Режим экономии не применён: системный VPN-интерфейс не удалось безопасно остановить.",
            50,
        )
    }

    fun noteSleepVpnResumed() {
        updateLog(
            "sleep_vpn_resumed",
            "[СОН] Экран включён; возобновляем VPN с сохранёнными настройками.",
            20,
            false,
        )
    }

    fun noteSleepVpnTimerResumed() {
        updateLog(
            "sleep_vpn_timer_resumed",
            "[СОН] Таймер завершён; возобновляем VPN с сохранёнными настройками.",
            20,
            false,
        )
    }

    fun noteSleepVpnUserResumed() {
        updateLog(
            "sleep_vpn_user_resumed",
            "[СОН] VPN включается досрочно по действию пользователя.",
            20,
            false,
        )
    }

    fun noteSleepVpnFailsafeResumed() {
        updateWarningLog(
            "sleep_vpn_failsafe_resumed",
            "[СОН] Таймер включения недоступен; VPN восстанавливается сразу, чтобы не оставлять соединение выключенным.",
            50,
        )
    }

    fun noteWakeRescueReconnect() {
        updateWarningLog(
            "wake_rescue_reconnect",
            "[СОН] Транспорт не ожил после пробуждения. Мягко переподключаем его без пересоздания системного VPN.",
            50
        )
    }

    fun noteSleepTimerTransportHealthy() {
        updateLog(
            "sleep_timer_transport_healthy",
            "[СОН] После таймера сервер отвечает; транспорт готов принимать трафик.",
            20,
            false,
        )
    }

    fun noteSleepTimerTransportReconnect() {
        updateWarningLog(
            "sleep_timer_transport_reconnect",
            "[СОН] После таймера сервер не ответил. Мягко переподключаем транспорт до включения экрана.",
            50,
        )
    }

    fun markStoppedAfterWakeRescue() {
        resetNetworkRecoveryState()
        setConnectionIssue(
            "VPN остановлен, чтобы вернуть интернет",
            "После пробуждения телефона WDTT Plus не увидел свежей активности туннеля и выключил VPN, чтобы интернет вернулся напрямую."
        )
        updateLog(
            "wake_rescue_fail_open",
            "[СОН] VPN не восстановился после пробуждения. Останавливаем VPN, чтобы вернуть прямой интернет.",
            -1,
            true
        )
    }

    fun recreateVpnTunnel(
        reason: String = "[VPN] Android потерял системный VPN-интерфейс, создаём его заново",
    ) {
        if (vpnSlotYieldRequested.value) return
        val params = currentParams ?: return
        val context = lastContext ?: return
        resetNetworkRecoveryState()
        resetStatsLivenessState()
        networkTransitionGraceUntilMs = System.currentTimeMillis() + WAKE_RECOVERY_GRACE_MS
        updateWarningLog("network_full_restart", reason, 50)
        scope.launch {
            withContext(Dispatchers.Main) {
                wgHelper?.stopTunnel()
            }
            noteSessionTransportRestart()
            killProcess()
            activeWorkers.value = 0
            delay(2500)
            if (currentParams === params && running.value) {
                start(context, params, isSwitching = true)
            }
        }
    }

    fun markStoppedAfterFailedRecovery() {
        resetNetworkRecoveryState()
        setConnectionIssue(
            "VPN остановлен, чтобы вернуть интернет",
            "WDTT Plus несколько раз не смог восстановить транспорт после сетевой ошибки. Интернет телефона возвращён напрямую; включите VPN снова, когда сеть стабилизируется."
        )
        updateLog(
            "network_fail_open",
            "[СЕТЬ] Автовосстановление не помогло. VPN остановлен, чтобы телефон не остался без интернета.",
            -1,
            true
        )
    }

    fun pause() {
        if (!running.value) return
        noteSessionTransportRestart()
        killProcess()
        activeWorkers.value = 0
        resetStatsLivenessState()
    }

    fun resume() {
        if (currentParams != null && lastContext != null) {
            resetNetworkRecoveryState()
            clearConnectionIssue()
            scope.launch {
                start(lastContext!!, currentParams!!, isSwitching = true)
            }
        }
    }

    private fun killProcess(cancelWatchdog: Boolean = true) {
        if (cancelWatchdog) {
            watchdogJob?.cancel()
        }
        readerJob?.cancel()
        val proc = process
        process = null
        if (proc != null) {
            try {
                proc.outputStream.write("STOP\n".toByteArray(Charsets.UTF_8))
                proc.outputStream.flush()
            } catch (_: Exception) {}
            try { proc.waitFor(1500, java.util.concurrent.TimeUnit.MILLISECONDS) } catch (_: Exception) {}
            if (proc.isAlive) {
                try { proc.destroy() } catch (_: Exception) {}
                try { proc.waitFor(750, java.util.concurrent.TimeUnit.MILLISECONDS) } catch (_: Exception) {}
            }
            if (proc.isAlive) {
                try { proc.destroyForcibly() } catch (_: Exception) {}
                try { proc.waitFor(1000, java.util.concurrent.TimeUnit.MILLISECONDS) } catch (_: Exception) {}
            }
        }
        closeWarpApiSshRelay()
    }

    @Synchronized
    private fun closeWarpApiSshRelay() {
        val relay = warpApiSshRelay
        warpApiSshRelay = null
        relay?.close()
    }

    private fun stopOnlyProcess() {
        noteSessionTransportRestart()
        killProcess()
        running.value = false
    }

    private fun markLogSessionStopped(reason: TunnelStopReason) {
        activeWorkers.value = 0
        val stoppedStats = buildStoppedSessionStats(stats.value, reason)
        stats.value = stoppedStats
        updateLog("stats", "[СТАТИСТИКА] $stoppedStats", 3, false)
    }

    fun onWireGuardInterfaceDropped(vpnSlotTransferred: Boolean) {
        if (!running.value) return
        if (vpnSlotTransferred) {
            if (vpnSlotYieldRequested.value) return
            vpnSlotYieldRequested.value = true
            updateWarningLog(
                "vpn_interface_dropped",
                "[VPN] Android передал VPN-слот другому приложению. " +
                    "WDTT Plus уступает слот и не будет включать VPN повторно.",
                50,
            )
        } else if (!vpnSlotYieldRequested.value) {
            updateWarningLog(
                "vpn_interface_dropped",
                "[VPN] Android сообщил о потере системного VPN-интерфейса. " +
                    "Проверяем состояние перед восстановлением.",
                50,
            )
        }
    }

    fun stop(reason: TunnelStopReason = TunnelStopReason.User) {
        noteStopRequested()
        scope.launch {
            startStopMutex.lock()
            try {
                if (!running.value && currentParams == null) return@launch
                withContext(Dispatchers.Main) {
                    wgHelper?.stopTunnel()
                }
                killProcess()
                running.value = false
                markLogSessionStopped(reason)
                resetStatsLivenessState()
                currentParams = null
                resetNetworkRecoveryState()
                wakeRecoveryGraceUntilMs = 0L
                ManlCaptchaWebViewManager.cancelCaptcha()
            } finally {
                if (reason == TunnelStopReason.User) {
                    startCooldown(1500L)
                }
                clearTransition()
                startStopMutex.unlock()
            }
        }
    }

    suspend fun stopAndWait(
        reason: TunnelStopReason = TunnelStopReason.User,
        context: Context? = null,
        forceVpnRelease: Boolean = false,
    ) {
        noteStopRequested()
        startStopMutex.lock()
        try {
            val hadManagedSession = running.value || currentParams != null || process != null
            if (!hadManagedSession && !forceVpnRelease) return
            val stopHelper = wgHelper ?: context?.applicationContext?.let(::WireGuardHelper)
            withContext(Dispatchers.Main) {
                stopHelper?.stopTunnel()
            }
            withContext(Dispatchers.IO) {
                killProcess()
                running.value = false
                if (hadManagedSession) {
                    markLogSessionStopped(reason)
                }
                resetStatsLivenessState()
                currentParams = null
                resetNetworkRecoveryState()
                wakeRecoveryGraceUntilMs = 0L
                ManlCaptchaWebViewManager.cancelCaptcha()
            }
        } finally {
            if (reason == TunnelStopReason.User) {
                startCooldown(1500L)
            }
            clearTransition()
            startStopMutex.unlock()
        }
    }

    fun reloadWireGuard() {
        wireGuardReloadJob?.cancel()
        wireGuardReloadJob = scope.launch {
            if (running.value && !vpnSlotYieldRequested.value) wgHelper?.reloadTunnel()
        }
    }

    fun scheduleWireGuardReload(profileIndex: Int, delayMs: Long = 250L) {
        if (!shouldReloadWireGuardRouting(running.value, activeTunnelProfile.value, profileIndex)) return
        wireGuardReloadJob?.cancel()
        wireGuardReloadJob = scope.launch {
            delay(delayMs.coerceAtLeast(0L))
            if (
                !vpnSlotYieldRequested.value &&
                shouldReloadWireGuardRouting(running.value, activeTunnelProfile.value, profileIndex)
            ) {
                wgHelper?.reloadTunnel()
            }
        }
    }

    private suspend fun handleCaptchaSolve(
        expectedProcess: Process,
        requestId: String,
        requestMode: String,
        redirectUri: String,
        sessionToken: String
    ) {
        val ctx = lastContext ?: run {
            writeCaptchaResult(expectedProcess, requestId, "error:context is null")
            return
        }
        val mode = requestMode.lowercase()
        val captchaRequestId = beginCaptchaSolve()

        try {
            val token = when (mode) {
                "auto" -> solveSingleAutoWebViewCaptcha(redirectUri, sessionToken)
                "manual" -> {
                updateLog("captcha_wv_step_1", "[КАПЧА WBV] Открываем ручной WebView...", 5, false)
                    ManlCaptchaWebViewManager.solveCaptchaAsync(ctx, redirectUri, sessionToken)
                }
                else -> {
                    if (currentCaptchaSolveMethod == "auto") {
                        solveAutoWebViewCaptcha(ctx, redirectUri, sessionToken)
                    } else {
                        updateLog("captcha_wv_step_1", "[КАПЧА WBV] Открываем ручной WebView...", 5, false)
                        ManlCaptchaWebViewManager.solveCaptchaAsync(ctx, redirectUri, sessionToken)
                    }
                }
            }
            updateLog("captcha_wv_step_4", "[КАПЧА WBV] Капча решена ✓", 5, false)
            writeCaptchaResult(expectedProcess, requestId, token)
        } catch (e: IllegalStateException) {
            val errorMsg = e.message ?: "WV state error"
            val autoFallback = mode == "auto" && (
                errorMsg == CaptchaWebViewManager.ERROR_SLIDER_DETECTED ||
                    errorMsg == CaptchaWebViewManager.ERROR_CHECKBOX_NOT_FOUND ||
                    errorMsg == CaptchaWebViewManager.ERROR_AUTO_CHECK_NOT_SENT ||
                    errorMsg == CaptchaWebViewManager.ERROR_AUTO_NO_RESULT
                )
            if (autoFallback) {
                updateLog("captcha_wv_fallback", "[КАПЧА WBV] Авто-WebView не подходит для этой капчи, идём дальше", 5, false)
            } else {
                updateWarningLog("captcha_wv_err", "[КАПЧА WBV] $errorMsg", 5)
            }
            writeCaptchaResult(expectedProcess, requestId, "error:$errorMsg")
        } catch (e: kotlinx.coroutines.TimeoutCancellationException) {
            if (mode == "auto") {
                updateLog("captcha_wv_timeout", "[КАПЧА WBV] Авто-WebView не успел, идём дальше", 5, false)
            } else {
                updateWarningLog("captcha_wv_err", "[КАПЧА WBV] WebView не ответил вовремя", 5)
            }
            writeCaptchaResult(expectedProcess, requestId, "error:timeout")
        } catch (e: kotlin.coroutines.cancellation.CancellationException) {
            updateWarningLog("captcha_wv_err", "[КАПЧА WBV] Проверка отменена", 5)
            writeCaptchaResult(expectedProcess, requestId, "error:cancelled")
        } catch (e: Exception) {
            val errorMsg = e.message ?: "${e::class.simpleName}"
            if (errorMsg != "tunnel stopped") {
                updateWarningLog("captcha_wv_err", "[КАПЧА WBV] Текущая попытка не выполнена — $errorMsg", 5)
            }
            writeCaptchaResult(expectedProcess, requestId, "error:$errorMsg")
        } finally {
            updateLog("captcha_wv_step_6", "[КАПЧА WBV] WebView уничтожен", 5, false)
            endCaptchaSolve(captchaRequestId)
        }
    }

    private suspend fun solveSingleAutoWebViewCaptcha(
        redirectUri: String,
        sessionToken: String
    ): String {
        updateLog("captcha_wv_step_1", "[КАПЧА WBV] Попытка через авто-WebView, до 18 с...", 5, false)
        return CaptchaWebViewManager.solveCaptchaAsync(redirectUri, sessionToken) { step ->
            updateLog("captcha_wv_auto_step", "[КАПЧА WBV] $step", 5, false)
        }
    }

    private suspend fun solveAutoWebViewCaptcha(
        ctx: Context,
        redirectUri: String,
        sessionToken: String
    ): String {
        for (attempt in 1..2) {
            updateLog("captcha_wv_step_1", "[КАПЧА WBV] Попытка через авто-WebView $attempt/2, до 18 с...", 5, false)
            try {
                return CaptchaWebViewManager.solveCaptchaAsync(redirectUri, sessionToken) { step ->
                    updateLog("captcha_wv_auto_step", "[КАПЧА WBV] $step", 5, false)
                }
            } catch (e: kotlinx.coroutines.TimeoutCancellationException) {
                updateWarningLog(
                    "captcha_wv_timeout",
                    "[КАПЧА WBV] Авто-WebView не ответил вовремя ($attempt/2), продолжаем",
                    5
                )
                if (attempt == 2) {
                    updateLog("captcha_wv_fallback", "[КАПЧА WBV] Две авто-попытки не ответили, открыт ручной WebView", 5, false)
                    return ManlCaptchaWebViewManager.solveCaptchaAsync(ctx, redirectUri, sessionToken)
                }
            } catch (e: IllegalStateException) {
                if (e.message == CaptchaWebViewManager.ERROR_SLIDER_DETECTED) {
                    updateLog("captcha_wv_fallback", "[КАПЧА WBV] Обнаружен слайдер, открыт ручной WebView", 5, false)
                    return ManlCaptchaWebViewManager.solveCaptchaAsync(ctx, redirectUri, sessionToken)
                }
                throw e
            }
        }
        return ManlCaptchaWebViewManager.solveCaptchaAsync(ctx, redirectUri, sessionToken)
    }

    private fun writeCaptchaResult(expectedProcess: Process, requestId: String, result: String) {
        if (process !== expectedProcess || !expectedProcess.isAlive) return
        try {
            val payload = if (requestId.isBlank()) result else "$requestId|$result"
            val line = "CAPTCHA_RESULT|$payload\n"
            expectedProcess.outputStream.write(line.toByteArray(Charsets.UTF_8))
            expectedProcess.outputStream.flush()
        } catch (e: Exception) {
            // Остановка туннеля может закрыть stdin между проверкой isAlive и записью.
            // Это штатная гонка завершения, а не ошибка подключения пользователя.
            if (process === expectedProcess && expectedProcess.isAlive) {
                updateWarningLog(
                    "captcha_write_err",
                    "[КАПЧА] Нативный клиент не принял результат: ${e.message ?: e::class.simpleName}",
                    5
                )
            }
        }
    }

    fun clearLogs() {
        logs.value = emptyList()
        if (!running.value) {
            activeWorkers.value = 0
        }
    }

    fun startCooldown(millis: Long) {
        cooldownJob?.cancel()
        cooldownActive.value = true
        cooldownJob = scope.launch(Dispatchers.Main) {
            delay(millis)
            cooldownActive.value = false
        }
    }

    private fun Throwable.readableMessage(): String {
        val text = message ?: localizedMessage
        return if (text.isNullOrBlank()) this::class.java.simpleName else "${this::class.java.simpleName}: $text"
    }
}

data class TunnelParams(
    val peer: String,
    val vkHashes: String,
    val secondaryVkHash: String = "",
    val workersPerHash: Int,
    val port: Int,
    val sni: String = "",
    val connectionPassword: String = "",
    val protocol: String = "udp",
    val vkCallsPreflight: Boolean = true,
    val rtNetwork: Boolean = false,
    val rtMasque: Boolean = false,
    val rtMasqueServerBootstrap: Boolean = false,
    val rtTurnSni: String = DEFAULT_RT_TURN_SNI,
    val captchaMode: String = "auto",
    val captchaSolveMethod: String = "auto",
    val fingerprint: String = "firefox",
    val clientIds: String = DEFAULT_VK_CLIENT_IDS,
    val customVkCredentialsEnabled: Boolean = false,
    val customVkClientId: String = "",
    val customVkClientSecret: String = "",
    val profileMaxWorkers: Int = 0,
    val managedConfigFirstStart: Boolean = false,
    val profileIndex: Int = 0,
)

internal enum class TunnelProfileRuntimeApplyResult {
    INACTIVE,
    UNCHANGED,
    STORED_FOR_RESUME,
    RESTARTED,
}
