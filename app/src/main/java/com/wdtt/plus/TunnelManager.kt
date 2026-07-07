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

@Stable
data class ConnectionIssue(
    val title: String,
    val action: String,
    val isError: Boolean = true
)

enum class NetworkRecoveryAction {
    SoftRestart,
    RecreateVpn,
    StopVpn
}

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
    ServiceDestroyed("служба VPN остановлена системой")
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

const val AMNEZIA_STYLE_RECOVERY = true
private const val RECOVERABLE_NETWORK_GRACE_MS = 90_000L
private const val HARD_NETWORK_GRACE_MS = 30_000L
private const val HARD_NETWORK_STOP_DELAY_MS = 60_000L
private const val STABLE_RECOVERY_GRACE_MS = 10 * 60_000L
private const val STABLE_RECOVERY_RETRY_MS = 10 * 60_000L
private const val STABLE_ZERO_WORKERS_GRACE_MS = 15 * 60_000L
private const val STAGNANT_ACTIVE_TRAFFIC_MS = 20 * 60_000L

object TunnelManager {
    // 100% защита от утечек: единый управляемый глобальный Scope
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private var process: Process? = null
    private var readerJob: Job? = null
    private var watchdogJob: Job? = null
    private var wgHelper: WireGuardHelper? = null
    
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
    private var lastStatsTrafficSignature = ""
    private var lastStatsTrafficChangedAtMs = 0L
    private var lastStagnantTrafficIssueAtMs = 0L
    private var activeHashIndex = 0 // 0: primary, 1: secondary
    private var currentParams: TunnelParams? = null
    private var lastContext: Context? = null
    private var forceRegenerateUA = false // принудительная перегенерация UA при ошибках
    private var currentCaptchaMode = "wv" // режим обхода капчи: "wv" или "rjs"
    private var currentCaptchaSolveMethod = "auto" // "manual" или "auto"
    private var recoverableNetworkErrorAtMs = 0L
    private var hardNetworkErrorAtMs = 0L
    private var hardNetworkErrorCount = 0
    private var lastRecoveryAtMs = 0L
    private var recoveryAttempts = 0
    private var softRestartCount = 0
    private var lastSoftRestartAtMs = 0L
    private var lastUnderlyingNetworkChangeAtMs = 0L
    private var networkTransitionGraceUntilMs = 0L
    private var lastNetworkSettleRestartAtMs = 0L
    private var lastStableNetworkIssueLogAtMs = 0L
    private val captchaSolveRequestId = AtomicLong(0)
    private val activeCaptchaSolveRequests = ConcurrentHashMap.newKeySet<Long>()

    @Volatile
    var isLoggingEnabled = true

    val running = MutableStateFlow(false)
    val logs = MutableStateFlow<List<LogEntry>>(emptyList())
    val unreadErrorCount = MutableStateFlow(0)
    val config = MutableStateFlow<String?>(null)
    val stats = MutableStateFlow("Ожидание данных...")
    val activeWorkers = MutableStateFlow(0)
    val connectionIssue = MutableStateFlow<ConnectionIssue?>(null)
    
    val cooldownActive = MutableStateFlow(false)
    private var cooldownJob: Job? = null
    private val statsTrafficRegex = Regex("[↓↑]\\s*([0-9]+(?:[.,][0-9]+)?)\\s*МБ")

    fun clearUnreadErrors() {
        unreadErrorCount.value = 0
    }

    fun clearConnectionIssue() {
        connectionIssue.value = null
    }

    private fun setConnectionIssue(title: String, action: String, isError: Boolean = true) {
        connectionIssue.value = ConnectionIssue(title = title, action = action, isError = isError)
    }

    fun reportConnectionIssue(title: String, action: String, isError: Boolean = true) {
        setConnectionIssue(title, action, isError)
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
        lastRecoveryAtMs = 0L
        recoveryAttempts = 0
        softRestartCount = 0
        lastSoftRestartAtMs = 0L
        lastStableNetworkIssueLogAtMs = 0L
    }

    private fun resetStatsLivenessState() {
        lastActiveAtMs = 0L
        lastStatsAtMs = 0L
        lastStatsTrafficSignature = ""
        lastStatsTrafficChangedAtMs = 0L
        lastStagnantTrafficIssueAtMs = 0L
    }

    private fun statsTrafficSignature(message: String): String =
        statsTrafficRegex.findAll(message)
            .joinToString("|") { match ->
                match.value.replace(Regex("\\s+"), "").replace(',', '.')
            }

    private fun isStatsTrafficStagnant(now: Long = System.currentTimeMillis()): Boolean {
        val startupGrace = processStartedAtMs == 0L || now - processStartedAtMs < 90_000L
        return activeWorkers.value > 0 &&
            lastStatsTrafficSignature.isNotBlank() &&
            lastStatsTrafficChangedAtMs > 0L &&
            now - lastStatsTrafficChangedAtMs > STAGNANT_ACTIVE_TRAFFIC_MS &&
            !startupGrace &&
            !isCaptchaInProgress()
    }

    private fun noteRecoverableNetworkIssue(title: String, action: String, hardFailure: Boolean = false) {
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
            if (now - lastStableNetworkIssueLogAtMs > 60_000L) {
                lastStableNetworkIssueLogAtMs = now
                updateLog(
                    "network_stable_observe",
                    "[СЕТЬ] $title. Наблюдаем без немедленного перезапуска; восстановление будет только после долгой тишины или смены сети.",
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

        val hasFreshActiveWorkers = activeWorkers.value > 0 &&
            lastActiveAtMs > recoverableNetworkErrorAtMs &&
            now - lastActiveAtMs < 2 * 60_000L
        if (hasFreshActiveWorkers && !isStatsTrafficStagnant(now)) return null

        if (now - recoverableNetworkErrorAtMs < STABLE_RECOVERY_GRACE_MS) return null
        if (now - lastRecoveryAtMs < STABLE_RECOVERY_RETRY_MS) return null

        lastRecoveryAtMs = now
        recoveryAttempts++
        setConnectionIssue(
            "Восстанавливаю транспорт",
            "Сеть долго не подаёт признаков жизни. Выполняется одна мягкая попытка без пересоздания VPN."
        )
        return NetworkRecoveryAction.SoftRestart
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

    private fun updateLog(key: String, message: String, priority: Int, isError: Boolean = false) {
        if (!isLoggingEnabled) return
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
                current[index] = entry.copy(count = entry.count + 1, message = message, priority = priority, severity = severity)
            } else {
                // Новая запись
                current.add(LogEntry(key, message, 1, priority, severity))
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
        logs.update { currentList ->
            val current = currentList.toMutableList()
            val index = current.indexOfFirst { it.key == key }
            if (index != -1) {
                val entry = current[index]
                current[index] = entry.copy(
                    count = entry.count + 1,
                    message = message,
                    priority = priority,
                    severity = LogSeverity.Warning
                )
            } else {
                current.add(LogEntry(key, message, 1, priority, LogSeverity.Warning))
            }
            val sorted = current.sortedWith(compareBy({ it.priority }, { it.severity.ordinal }, { it.key }))
            if (sorted.size > 100) sorted.takeLast(100) else sorted
        }
    }

    fun start(context: Context, params: TunnelParams, isSwitching: Boolean = false) {
        scope.launch {
            startStopMutex.lock()
            try {
                if (running.value && !isSwitching) return@launch
        
                val appContext = context.applicationContext // Защита от Memory Leak
                
                if (!isSwitching) {
                    clearLogs()
                    config.value = null
                    stats.value = "Ожидание данных..."
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
                    lastNetworkSettleRestartAtMs = 0L
                    activeHashIndex = 0
                    currentParams = params
                    lastContext = appContext
                    forceRegenerateUA = false
                    currentCaptchaMode = params.captchaMode
                    currentCaptchaSolveMethod = params.captchaSolveMethod
                }
                
                wgHelper = WireGuardHelper(appContext)

                val targetHash = if (activeHashIndex == 0) params.vkHashes else params.secondaryVkHash
                
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
                val totalWorkers = params.workersPerHash.coerceIn(1, 128)
                
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
                cmd.add("-vkcalls-preflight=${params.vkCallsPreflight}")

                val androidId = android.provider.Settings.Secure.getString(context.contentResolver, android.provider.Settings.Secure.ANDROID_ID) ?: "unknown"
                cmd.add("-device-id")
                cmd.add(androidId)
                cmd.add("-device-info")
                cmd.add(buildDeviceInfoJson(appContext))

                cmd.add("-password")
                cmd.add(params.connectionPassword)

                cmd.add("-captcha-mode")
                cmd.add(params.captchaMode)

                val pb = ProcessBuilder(cmd)
                pb.directory(context.filesDir)
                pb.redirectErrorStream(true)
                
                val env = pb.environment()
                env["LD_LIBRARY_PATH"] = context.applicationInfo.nativeLibraryDir

                process = pb.start()
                processStartedAtMs = System.currentTimeMillis()
                wrapAuthTimeoutCount = 0
                resetStatsLivenessState()
                running.value = true
                startLogReader()
                startWatchdog(appContext, params)

            } catch (e: Exception) {
                val message = e.readableMessage()
                updateLog("critical_start_error", "Критическая ошибка запуска: $message", 99, true)
                setConnectionIssue("Не удалось запустить подключение", "Проверьте настройки туннеля и попробуйте подключиться снова. Причина: $message")
                e.printStackTrace()
                running.value = false
                currentParams = null
            } finally {
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
                                lineTrim.contains("временно пропущен", true)
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
                                    "[WRAP] Один поток не прошёл handshake, активных=${activeWorkers.value}; повторяем",
                                    20,
                                    false
                                )
                            } else {
                                wrapAuthTimeoutCount++
                                updateWarningLog(
                                    "wrap_timeout_wait",
                                    "[WRAP] Handshake не подтвердился, проверяем пароль/сеть ($wrapAuthTimeoutCount)",
                                    50
                                )
                            }
                            return@forEachLine
                        }

                        val reason = when {
                            lineTrim.contains("неверный пароль") -> "Неверный пароль подключения"
                            lineTrim.contains("истёк") -> "Срок действия пароля истёк"
                            lineTrim.contains("другому устройству") -> "Пароль привязан к другому устройству"
                            else -> "Ошибка авторизации"
                        }
                        val action = when {
                            lineTrim.contains("неверный пароль") ->
                                "Проверьте пароль в «Секретах» или вставьте актуальную wdtt:// ссылку."
                            lineTrim.contains("истёк") ->
                                "Создайте новый пароль у администратора или продлите текущий в Telegram-боте."
                            lineTrim.contains("другому устройству") ->
                                "Этот пароль уже закреплён за другим устройством. Отвяжите устройство в Telegram-боте или создайте новый пароль."
                            else ->
                                "Проверьте пароль, VK-хеш и состояние сервера, затем попробуйте подключиться снова."
                        }
                        setConnectionIssue(reason, action)
                        handleCriticalError("\uD83D\uDD12 $reason. Воркеры остановлены.")
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
                                "[WRAP] Один поток не прошёл handshake, активных=${activeWorkers.value}; повторяем",
                                    20,
                                    false
                            )
                        } else {
                            wrapAuthTimeoutCount++
                            updateWarningLog(
                                "wrap_timeout_wait",
                                "[WRAP] Handshake не подтвердился, проверяем пароль/сеть ($wrapAuthTimeoutCount)",
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
                                    handleCaptchaSolve(requestId, requestMode, redirectUri, sessionToken)
                                }
                            }
                            3 -> {
                                val requestMode = parts[0]
                                val redirectUri = parts[1]
                                val sessionToken = parts[2]
                                scope.launch {
                                    handleCaptchaSolve("", requestMode, redirectUri, sessionToken)
                                }
                            }
                            2 -> {
                                val redirectUri = parts[0]
                                val sessionToken = parts[1]
                                scope.launch {
                                    handleCaptchaSolve("", "selected", redirectUri, sessionToken)
                                }
                            }
                            else -> {
                                writeCaptchaResult("", "error:invalid CAPTCHA_SOLVE format")
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
                        val msg = lineTrim.substringAfter("[СТАТИСТИКА]").trim()
                        stats.value = msg
                        lastStatsAtMs = now

                        val match = Regex("Активных:\\s*(\\d+)").find(msg)
                        if (match != null) {
                            val active = match.groupValues[1].toIntOrNull() ?: 0
                            activeWorkers.value = active

                            val trafficSignature = statsTrafficSignature(msg)
                            val trafficKnown = trafficSignature.isNotBlank()
                            val trafficChanged = trafficKnown && trafficSignature != lastStatsTrafficSignature
                            if (trafficChanged) {
                                lastStatsTrafficSignature = trafficSignature
                                lastStatsTrafficChangedAtMs = now
                                lastStagnantTrafficIssueAtMs = 0L
                            } else if (trafficKnown && lastStatsTrafficChangedAtMs == 0L) {
                                lastStatsTrafficSignature = trafficSignature
                                lastStatsTrafficChangedAtMs = now
                            }

                            if (active > 0) {
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
                                } else if (trafficChanged || (hardNetworkErrorAtMs == 0L && !isStatsTrafficStagnant(now))) {
                                    recoverableNetworkErrorAtMs = 0L
                                    hardNetworkErrorAtMs = 0L
                                    hardNetworkErrorCount = 0
                                    lastRecoveryAtMs = 0L
                                    recoveryAttempts = 0
                                    softRestartCount = 0
                                    lastSoftRestartAtMs = 0L
                                    networkTransitionGraceUntilMs = 0L
                                    clearConnectionIssue()
                                }
                            }
                        }

                        updateLog("stats", "[СТАТИСТИКА] $msg", 3, false)
                        return@forEachLine
                    }

                    val workerRetry = classifyRecoverableWorkerRetry(lineTrim, activeWorkers.value)
                    when {
                        workerRetry != null ->
                            updateWarningLog(workerRetry.first, workerRetry.second, 20)
                        lineTrim.contains("[ВОРКЕР #", true) &&
                            lineTrim.contains("Невосстановимая TURN/STUN ошибка", true) ->
                            updateWarningLog(
                                "worker_turn_stopped",
                                "[TURN] Отдельные каналы завершили попытки подключения; остальные продолжают работу",
                                50
                            )
                        lineTrim.contains("[VKCalls]", true) -> {
                            when {
                                lineTrim.contains("TURN credentials получены", true) ->
                                    updateLog("vkcalls_ok", "[VKCalls] Анонимные TURN-данные получены ✓", 2, false)
                                lineTrim.contains("preflight не сработал", true) ||
                                    lineTrim.contains("временно ограничил", true) ||
                                    lineTrim.contains("временно пропущен", true) ->
                                    updateLog("vkcalls_fallback", "[VKCalls] Анонимный вход временно недоступен — используется капча", 20, false)
                                lineTrim.endsWith("[VKCalls] preflight", true) ->
                                    updateLog("vkcalls_start", "[VKCalls] Пробуем анонимный вход...", 2, false)
                                else -> {
                                    if (isError) updateWarningLog("vkcalls_status", lineTrim, 20)
                                    else updateLog("vkcalls_status", lineTrim, 20, false)
                                }
                            }
                        }
                        lineTrim.contains("[КАПЧА] AUTO:") -> {
                            var text = lineTrim.substringAfter("[КАПЧА] AUTO:").trim()
                            text = text.replace(Regex("\\s*\\([^)]+\\)\\s*"), " ").trim()

                            val isIntermediateFallback = text.contains("текущая captcha-сессия завершена", true)
                            val isErr = !isIntermediateFallback && (
                                text.contains("ошибка", true) ||
                                    text.contains("timeout", true) ||
                                    text.contains("не решил", true)
                                )
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
                            if (isErr) updateWarningLog(stableKey, "[КАПЧА AUTO] $text", 5)
                            else updateLog(stableKey, "[КАПЧА AUTO] $text", 5, false)
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
                        lineTrim.contains("капча не решена") || lineTrim.contains("ошибка решения капчи") ->
                            updateWarningLog("captcha_failed", "[КАПЧА] Текущий способ не решил капчу, пробуем следующий", 5)
                        lineTrim.contains("Timed out waiting for", true) && lineTrim.contains("ms", true) ->
                            updateLog("captcha_auto_timeout", "[КАПЧА] Auto WebView не успел, используется следующий способ", 5, false)
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
                                text.contains("Креды обновлены", true) ->
                                    updateLog("turn_creds_refreshed", "[TURN] Креды обновлены, продолжаем подключение", 2, false)
                                text.contains("Креды уже обновлялись", true) ->
                                    updateLog("turn_creds_wait", "[TURN] Ждём перед повторным обновлением кредов", 2, false)
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
                            val seconds = trailingSeconds(text)
                            val userTrafficStalled = text.contains("пользовательский трафик", true)
                            noteRecoverableNetworkIssue(
                                if (userTrafficStalled) "Нет ответа на пользовательский трафик" else "Транспорт потерял ответ сервера",
                                if (userTrafficStalled) {
                                    "Трафик уже ушёл в VPN, но сервер не ответил. WDTT Plus восстановит транспорт или выключит VPN, чтобы вернуть обычный интернет."
                                } else {
                                    "Keepalive от сервера не пришёл. WDTT Plus перезапустит транспорт, если связь не восстановится сама."
                                },
                                hardFailure = userTrafficStalled && (seconds == null || seconds >= 60)
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
                        lineTrim.contains("Relay:") ->
                            updateLog("dtls_start", "[DTLS] Рукопожатие (Handshake)...", 1, false)
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
                                lineTrim.contains("lookup login.vk.ru", true) -> "err_vk_dns"
                                lineTrim.contains("connection refused") -> "err_conn_refused"
                                lineTrim.contains("timeout") -> "err_timeout"
                                lineTrim.contains("кредов") -> "err_creds"
                                lineTrim.contains("DTLS") -> "err_dtls"
                                else -> "general_error_" + lineTrim.take(15).hashCode()
                            }
                            val errorMessage = if (errorKey == "err_vk_dns") {
                                "[СЕТЬ] DNS до VK недоступен: login.vk.ru"
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

    private fun handleCriticalError(message: String) {
        if (connectionIssue.value == null) {
            setConnectionIssue("Подключение остановлено", "$message Проверьте настройки и попробуйте снова.")
        }
        updateLog("circuit_breaker", "[СТОП] $message", -1, true)
        stop(TunnelStopReason.CriticalError)
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
            delay(10_000)
            while (isActive && running.value) {
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
                        handleCriticalError("\uD83D\uDD12 Неверный пароль подключения или несовместимый WRAP. Воркеры остановлены.")
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
        killProcess()
        scope.launch {
            delay(2500)
            start(context, params, isSwitching = true)
        }
        return true
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

    fun connectionIssueTitleForNotification(now: Long = System.currentTimeMillis()): String? {
        val issue = connectionIssue.value ?: return null
        if (!running.value) return null
        val firstGraceMs = if (hardNetworkErrorAtMs > 0L) HARD_NETWORK_GRACE_MS else RECOVERABLE_NETWORK_GRACE_MS
        val waitingBeforeFirstRecovery = recoverableNetworkErrorAtMs > 0L &&
            recoveryAttempts == 0 &&
            now - recoverableNetworkErrorAtMs < firstGraceMs
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
        if (!running.value || activeWorkers.value <= 0) return false
        val freshActive = lastActiveAtMs >= sinceMs && now - lastActiveAtMs < 90_000L
        val freshStats = lastStatsAtMs >= sinceMs && now - lastStatsAtMs < 90_000L
        return (freshActive || freshStats) && !isStatsTrafficStagnant(now)
    }

    fun noteWakeRescueStarted() {
        updateLog(
            "wake_rescue_start",
            "[СОН] Экран включён. Проверяем, ожил ли VPN после сна.",
            50,
            false
        )
    }

    fun noteWakeRescueHealthy() {
        updateLog(
            "wake_rescue_ok",
            "[СОН] VPN подал свежие признаки жизни после пробуждения.",
            50,
            false
        )
    }

    fun noteWakeRescueReconnect() {
        updateWarningLog(
            "wake_rescue_reconnect",
            "[СОН] VPN не ожил после пробуждения. Делаем мягкое переподключение транспорта.",
            50
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

    fun recreateVpnTunnel() {
        val params = currentParams ?: return
        val context = lastContext ?: return
        updateWarningLog("network_full_restart", "[СЕТЬ] Мягкие попытки не помогли, пересоздаём VPN", 50)
        scope.launch {
            withContext(Dispatchers.Main) {
                wgHelper?.stopTunnel()
            }
            killProcess()
            activeWorkers.value = 0
            delay(2500)
            if (currentParams != null) {
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
            try { proc.destroy() } catch (_: Exception) {}
            try { proc.waitFor(500, java.util.concurrent.TimeUnit.MILLISECONDS) } catch (_: Exception) {}
            if (proc.isAlive) {
                try { proc.destroyForcibly() } catch (_: Exception) {}
                try { proc.waitFor(1000, java.util.concurrent.TimeUnit.MILLISECONDS) } catch (_: Exception) {}
            }
        }
    }

    private fun stopOnlyProcess() {
        killProcess()
        running.value = false
    }

    private fun markLogSessionStopped(reason: TunnelStopReason) {
        activeWorkers.value = 0
        val stoppedStats = buildStoppedSessionStats(stats.value, reason)
        stats.value = stoppedStats
        updateLog("stats", "[СТАТИСТИКА] $stoppedStats", 3, false)
    }

    fun onWireGuardStoppedExternally() {
        scope.launch {
            startStopMutex.lock()
            try {
                if (!running.value) return@launch
                updateLog(
                    "vpn_released",
                    "[VPN] Android отключил WDTT Plus VPN или передал VPN другому приложению. Транспорт остановлен.",
                    50,
                    false
                )
                killProcess()
                running.value = false
                markLogSessionStopped(TunnelStopReason.VpnStoppedExternally)
                resetStatsLivenessState()
                currentParams = null
                ManlCaptchaWebViewManager.cancelCaptcha()
            } finally {
                startStopMutex.unlock()
            }
        }
    }

    fun stop(reason: TunnelStopReason = TunnelStopReason.User) {
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
                ManlCaptchaWebViewManager.cancelCaptcha()
            } finally {
                startStopMutex.unlock()
            }
        }
    }

    suspend fun stopAndWait(reason: TunnelStopReason = TunnelStopReason.User) {
        startStopMutex.lock()
        try {
            if (!running.value && currentParams == null) return
            withContext(Dispatchers.Main) {
                wgHelper?.stopTunnel()
            }
            withContext(Dispatchers.IO) {
                killProcess()
                running.value = false
                markLogSessionStopped(reason)
                resetStatsLivenessState()
                currentParams = null
                resetNetworkRecoveryState()
                ManlCaptchaWebViewManager.cancelCaptcha()
            }
        } finally {
            startStopMutex.unlock()
        }
    }

    fun reloadWireGuard() {
        if (running.value) {
            scope.launch {
                wgHelper?.reloadTunnel()
            }
        }
    }

    private suspend fun handleCaptchaSolve(requestId: String, requestMode: String, redirectUri: String, sessionToken: String) {
        val ctx = lastContext ?: run {
            writeCaptchaResult(requestId, "error:context is null")
            return
        }
        val mode = requestMode.lowercase()
        val captchaRequestId = beginCaptchaSolve()

        try {
            val token = when (mode) {
                "auto" -> solveSingleAutoWebViewCaptcha(redirectUri, sessionToken)
                "manual" -> {
                    updateLog("captcha_wv_step_1", "[КАПЧА WBV] Создание ручного WebView...", 5, false)
                    ManlCaptchaWebViewManager.solveCaptchaAsync(ctx, redirectUri, sessionToken)
                }
                else -> {
                    if (currentCaptchaSolveMethod == "auto") {
                        solveAutoWebViewCaptcha(ctx, redirectUri, sessionToken)
                    } else {
                        updateLog("captcha_wv_step_1", "[КАПЧА WBV] Создание ручного WebView...", 5, false)
                        ManlCaptchaWebViewManager.solveCaptchaAsync(ctx, redirectUri, sessionToken)
                    }
                }
            }
            updateLog("captcha_wv_step_4", "[КАПЧА WBV] Капча решена ✓", 5, false)
            writeCaptchaResult(requestId, token)
        } catch (e: IllegalStateException) {
            val errorMsg = e.message ?: "WV state error"
            val autoFallback = mode == "auto" && (
                errorMsg == CaptchaWebViewManager.ERROR_SLIDER_DETECTED ||
                    errorMsg == CaptchaWebViewManager.ERROR_CHECKBOX_NOT_FOUND ||
                    errorMsg == CaptchaWebViewManager.ERROR_AUTO_CHECK_NOT_SENT ||
                    errorMsg == CaptchaWebViewManager.ERROR_AUTO_NO_RESULT
                )
            if (autoFallback) {
                updateLog("captcha_wv_fallback", "[КАПЧА WBV] Авто WebView не подходит для этой капчи, идём дальше", 5, false)
            } else {
                updateWarningLog("captcha_wv_err", "[КАПЧА WBV] $errorMsg", 5)
            }
            writeCaptchaResult(requestId, "error:$errorMsg")
        } catch (e: kotlinx.coroutines.TimeoutCancellationException) {
            if (mode == "auto") {
                updateLog("captcha_wv_timeout", "[КАПЧА WBV] Авто WebView не успел, идём дальше", 5, false)
            } else {
                updateWarningLog("captcha_wv_err", "[КАПЧА WBV] WebView не ответил вовремя", 5)
            }
            writeCaptchaResult(requestId, "error:timeout")
        } catch (e: kotlin.coroutines.cancellation.CancellationException) {
            updateWarningLog("captcha_wv_err", "[КАПЧА WBV] Проверка отменена", 5)
            writeCaptchaResult(requestId, "error:cancelled")
        } catch (e: Exception) {
            val errorMsg = e.message ?: "${e::class.simpleName}"
            if (errorMsg != "tunnel stopped") {
                updateWarningLog("captcha_wv_err", "[КАПЧА WBV] Текущая попытка не выполнена — $errorMsg", 5)
            }
            writeCaptchaResult(requestId, "error:$errorMsg")
        } finally {
            updateLog("captcha_wv_step_6", "[КАПЧА WBV] WebView уничтожен", 5, false)
            endCaptchaSolve(captchaRequestId)
        }
    }

    private suspend fun solveSingleAutoWebViewCaptcha(
        redirectUri: String,
        sessionToken: String
    ): String {
        updateLog("captcha_wv_step_1", "[КАПЧА WBV] Авто WebView попытка 18с...", 5, false)
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
            updateLog("captcha_wv_step_1", "[КАПЧА WBV] Авто WebView попытка $attempt/2, 18с...", 5, false)
            try {
                return CaptchaWebViewManager.solveCaptchaAsync(redirectUri, sessionToken) { step ->
                    updateLog("captcha_wv_auto_step", "[КАПЧА WBV] $step", 5, false)
                }
            } catch (e: kotlinx.coroutines.TimeoutCancellationException) {
                updateWarningLog(
                    "captcha_wv_timeout",
                    "[КАПЧА WBV] Авто WebView не ответил вовремя ($attempt/2), продолжаем",
                    5
                )
                if (attempt == 2) {
                    updateLog("captcha_wv_fallback", "[КАПЧА WBV] 2 таймаута авто, открыт ручной WebView", 5, false)
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

    private fun writeCaptchaResult(requestId: String, result: String) {
        val proc = process
        if (proc == null || !proc.isAlive) return
        try {
            val payload = if (requestId.isBlank()) result else "$requestId|$result"
            val line = "CAPTCHA_RESULT|$payload\n"
            proc.outputStream.write(line.toByteArray(Charsets.UTF_8))
            proc.outputStream.flush()
        } catch (e: Exception) {
            updateLog("captcha_write_err", "[КАПЧА] Ошибка записи: ${e.message}", 200, true)
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
    val captchaMode: String = "auto",
    val captchaSolveMethod: String = "auto",
    val fingerprint: String = "firefox",
    val clientIds: String = "6287487,8202606"
)
