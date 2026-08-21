package com.wdtt.plus

import android.app.Notification
import android.app.AlarmManager
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.os.SystemClock
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.ConcurrentHashMap

private const val TUNNEL_NOTIFICATION_CHANNEL_ID = "wdtt_tunnel_v4"
private const val TUNNEL_ALERT_CHANNEL_ID = "wdtt_tunnel_alert_v1"
private const val TUNNEL_NOTIFICATION_ID = 1
private const val TUNNEL_ALERT_NOTIFICATION_ID = 2
private const val NETWORK_CHANGE_SETTLE_MS = 90_000L
private const val NETWORK_RETURN_SETTLE_MS = 45_000L
private const val NETWORK_LOSS_GRACE_MS = 2 * 60_000L
private const val WAKE_RESCUE_GRACE_MS = 60_000L
private const val TIMER_RESUME_TRANSPORT_CONFIRM_MS = 75_000L
private const val TIMER_RESUME_TRANSPORT_WAKE_LOCK_TIMEOUT_MS =
    TIMER_RESUME_TRANSPORT_CONFIRM_MS + 15_000L
private const val ACTIVE_PROFILE_REFRESH_INTERVAL_MS = 2 * 60_000L
private const val INITIAL_VPN_START_GRACE_MS = 90_000L
private const val VPN_INTERFACE_MISSING_CONFIRM_MS = 90_000L
private const val VPN_INTERFACE_RECOVERY_RETRY_MS = 5 * 60_000L
private const val TRUSTED_WIFI_ENTER_DELAY_MS = 2_000L
private const val TRUSTED_WIFI_EXIT_DELAY_MS = 5_000L
private const val TRUSTED_WIFI_RESUME_START_TIMEOUT_MS = 30_000L
private const val TRUSTED_WIFI_TRANSITION_WAKE_LOCK_TIMEOUT_MS = 75_000L
private const val TUNNEL_TRANSITION_WAKE_LOCK_TIMEOUT_MS = 2 * 60_000L
private const val DEPLOY_WAKE_LOCK_TIMEOUT_MS = 15 * 60_000L
private const val WIFI_TRANSITION_LOCK_TIMEOUT_MS = 90_000L
private const val INTERACTIVE_STATUS_REFRESH_MS = 2_000L
private const val PASSIVE_STATUS_REFRESH_MS = 30_000L
private const val SLEEP_WAKE_RESULT_VISIBLE_MS = 5_000L
// Короткий таймер (например, одна минута) не должен теряться в Doze. Дольше
// этого CPU не удерживаем: для длинных пауз работает AlarmManager.
private const val SHORT_SLEEP_RESUME_GUARD_MAX_MS = 2 * 60_000L
private const val SHORT_SLEEP_RESUME_GUARD_TAIL_MS = 10_000L
private const val ACTION_SLEEP_PAUSE_NOW = "com.wdtt.plus.action.SLEEP_PAUSE_NOW"
private const val ACTION_SLEEP_KEEP_RUNNING = "com.wdtt.plus.action.SLEEP_KEEP_RUNNING"
private const val ACTION_SLEEP_RESUME_NOW = "com.wdtt.plus.action.SLEEP_RESUME_NOW"
private const val ACTION_SLEEP_KEEP_PAUSED = "com.wdtt.plus.action.SLEEP_KEEP_PAUSED"
private const val ACTION_SLEEP_AUTO_RESUME = "com.wdtt.plus.action.SLEEP_AUTO_RESUME"
// GoBackend сообщает об отзыве системного VPN-интерфейса отдельно от этой
// foreground-службы. Явное действие даёт ей завершить нативный транспорт
// сразу, а не ждать следующего опроса статистики.
internal const val ACTION_VPN_SLOT_REVOKED = "com.wdtt.plus.action.VPN_SLOT_REVOKED"
private const val EXTRA_SLEEP_RESUME_DEADLINE_MS = "sleep_resume_deadline_ms"
private const val SLEEP_RESUME_ALARM_REQUEST_CODE = 41

private data class TunnelNotificationAction(
    val action: String,
    val title: String,
    val requestCode: Int,
)

internal fun shouldAttemptVpnInterfaceRecovery(
    deviceInteractive: Boolean,
    startupWindow: Boolean,
    captchaActive: Boolean,
    vpnSlotYieldRequested: Boolean,
    missingForMs: Long,
    validatedNetworkAvailable: Boolean,
    sinceLastAttemptMs: Long,
): Boolean =
    deviceInteractive &&
        !startupWindow &&
        !captchaActive &&
        !vpnSlotYieldRequested &&
        missingForMs >= VPN_INTERFACE_MISSING_CONFIRM_MS &&
        validatedNetworkAvailable &&
        sinceLastAttemptMs >= VPN_INTERFACE_RECOVERY_RETRY_MS

internal fun shouldYieldVpnSlot(
    vpnSlotYieldRequested: Boolean,
    tunnelRunning: Boolean,
    stopRequested: Boolean,
): Boolean =
    vpnSlotYieldRequested &&
    tunnelRunning &&
        !stopRequested

internal fun tunnelStatusRefreshIntervalMs(
    deviceInteractive: Boolean,
    transitionWakeLockHeld: Boolean,
    trustedWifiTransitionInProgress: Boolean,
): Long = if (deviceInteractive || transitionWakeLockHeld || trustedWifiTransitionInProgress) {
    INTERACTIVE_STATUS_REFRESH_MS
} else {
    PASSIVE_STATUS_REFRESH_MS
}

internal fun shouldPauseVpnForSleep(
    pauseEnabled: Boolean,
    deviceInteractive: Boolean,
    tunnelRunning: Boolean,
    tunnelPaused: Boolean,
    trustedWifiWaiting: Boolean,
): Boolean =
    pauseEnabled &&
        !deviceInteractive &&
        tunnelRunning &&
        !tunnelPaused &&
        !trustedWifiWaiting

internal fun shouldResumeVpnAfterSleep(
    sleepPausedByPolicy: Boolean,
    tunnelRunning: Boolean,
    tunnelPaused: Boolean,
    trustedWifiWaiting: Boolean,
): Boolean =
    sleepPausedByPolicy &&
        tunnelRunning &&
        tunnelPaused &&
        !trustedWifiWaiting

internal fun shouldResumeVpnAfterNetworkReturn(
    networkPausedByLoss: Boolean,
    sleepPausedByPolicy: Boolean,
    tunnelRunning: Boolean,
    usableNetworkAvailable: Boolean,
): Boolean =
    networkPausedByLoss &&
        !sleepPausedByPolicy &&
        tunnelRunning &&
        usableNetworkAvailable

internal enum class ValidatedNetworkTransition {
    INITIAL,
    UNCHANGED,
    HANDOVER,
}

internal fun <T> classifyValidatedNetworkTransition(
    previousNetwork: T?,
    currentNetwork: T,
    previousNetworkWasLost: Boolean,
): ValidatedNetworkTransition = when {
    previousNetworkWasLost -> ValidatedNetworkTransition.HANDOVER
    previousNetwork == null -> ValidatedNetworkTransition.INITIAL
    previousNetwork == currentNetwork -> ValidatedNetworkTransition.UNCHANGED
    else -> ValidatedNetworkTransition.HANDOVER
}

internal fun shouldScheduleAvailableNetworkHandover(
    previousNetworkWasLost: Boolean,
    availableRealNetworkCount: Int,
): Boolean = previousNetworkWasLost && availableRealNetworkCount > 0

internal fun shouldTrackUnderlyingNetworkLoss(
    tunnelRunning: Boolean,
    tunnelPaused: Boolean,
    trustedWifiWaiting: Boolean,
): Boolean = tunnelRunning && !tunnelPaused && !trustedWifiWaiting

internal fun shouldStartUnderlyingNetworkCheck(
    checkPending: Boolean,
    currentJobActive: Boolean,
): Boolean = !checkPending || !currentJobActive

internal fun updatedUnderlyingNetworkEvidenceSince(
    currentEvidenceSinceMs: Long,
    networkEventAtMs: Long,
): Long = maxOf(currentEvidenceSinceMs, networkEventAtMs)

internal fun shouldRunUnderlyingNetworkReconnect(
    tunnelRunning: Boolean,
    tunnelPaused: Boolean,
    trustedWifiWaiting: Boolean,
    sleepPausedByPolicy: Boolean,
    stopRequested: Boolean,
    interactiveAtSchedule: Boolean,
    deviceInteractive: Boolean,
    wakeRecoveryGraceActive: Boolean,
    realNetworkAvailable: Boolean,
    captchaActive: Boolean,
): Boolean =
    tunnelRunning &&
        !tunnelPaused &&
        !trustedWifiWaiting &&
        !sleepPausedByPolicy &&
        !stopRequested &&
        interactiveAtSchedule &&
        deviceInteractive &&
        !wakeRecoveryGraceActive &&
        realNetworkAvailable &&
        !captchaActive

internal data class SleepBatteryPlan(
    val pauseAfterMinutes: Int,
    val resumeAfterMinutes: Int?,
)

internal fun buildSleepBatteryPlan(
    mode: SleepBatteryMode,
    pauseDelayMinutes: Int,
    resumeDelayMinutes: Int,
): SleepBatteryPlan = when (mode) {
    SleepBatteryMode.DELAYED_PAUSE -> SleepBatteryPlan(
        pauseAfterMinutes = normalizeSleepPauseDelayMinutes(pauseDelayMinutes),
        resumeAfterMinutes = null,
    )
    SleepBatteryMode.TIMED_PAUSE -> SleepBatteryPlan(
        pauseAfterMinutes = 0,
        resumeAfterMinutes = normalizeSleepPauseDelayMinutes(resumeDelayMinutes),
    )
}

internal fun shortSleepResumeGuardDurationMs(
    deadlineWallMs: Long,
    nowMs: Long,
): Long? {
    val remainingMs = deadlineWallMs - nowMs
    return if (remainingMs in 1..SHORT_SLEEP_RESUME_GUARD_MAX_MS) {
        remainingMs + SHORT_SLEEP_RESUME_GUARD_TAIL_MS
    } else {
        null
    }
}

internal fun sleepRuntimePhaseAfterPauseAttempt(
    deviceInteractive: Boolean,
    paused: Boolean,
): SleepBatteryRuntimePhase = when {
    deviceInteractive -> SleepBatteryRuntimePhase.IDLE
    paused -> SleepBatteryRuntimePhase.PAUSED_UNTIL_SCREEN_ON
    else -> SleepBatteryRuntimePhase.RESUMED_UNTIL_SCREEN_ON
}

internal fun sleepRuntimePhaseAfterResume(
    deviceInteractive: Boolean,
): SleepBatteryRuntimePhase = if (deviceInteractive) {
    SleepBatteryRuntimePhase.IDLE
} else {
    SleepBatteryRuntimePhase.RESUMED_UNTIL_SCREEN_ON
}

internal fun sleepWakeNotificationText(
    runtimePhase: SleepBatteryRuntimePhase,
): String? = when (runtimePhase) {
    SleepBatteryRuntimePhase.WAITING_TO_PAUSE ->
        "Таймер отменён: экран включён до отключения VPN"
    SleepBatteryRuntimePhase.PAUSED_UNTIL_SCREEN_ON ->
        "VPN включается после сна · во сне был выключен"
    SleepBatteryRuntimePhase.WAITING_TO_RESUME ->
        "VPN включается раньше таймера · экран включён"
    SleepBatteryRuntimePhase.RESUMED_UNTIL_SCREEN_ON ->
        "VPN был включён по таймеру во время сна"
    SleepBatteryRuntimePhase.IDLE -> null
}

internal enum class SleepResumeTrigger {
    SCREEN_ON,
    TIMER,
    USER,
    FAILSAFE,
}

internal enum class SleepResumeAction {
    KEEP_CURRENT_TUNNEL,
    RESUME_PAUSED_TUNNEL,
    RESTORE_PAUSED_TUNNEL,
}

internal fun decideSleepResumeAction(
    trigger: SleepResumeTrigger,
    runtimePhase: SleepBatteryRuntimePhase,
    tunnelRunning: Boolean,
    blockedByAnotherPolicy: Boolean,
): SleepResumeAction {
    if (blockedByAnotherPolicy) return SleepResumeAction.KEEP_CURRENT_TUNNEL

    val phaseAllowsResume = when (trigger) {
        SleepResumeTrigger.SCREEN_ON ->
            runtimePhase == SleepBatteryRuntimePhase.PAUSED_UNTIL_SCREEN_ON ||
                runtimePhase == SleepBatteryRuntimePhase.WAITING_TO_RESUME
        SleepResumeTrigger.TIMER ->
            runtimePhase == SleepBatteryRuntimePhase.WAITING_TO_RESUME
        SleepResumeTrigger.USER ->
            runtimePhase == SleepBatteryRuntimePhase.PAUSED_UNTIL_SCREEN_ON ||
                runtimePhase == SleepBatteryRuntimePhase.WAITING_TO_RESUME
        SleepResumeTrigger.FAILSAFE ->
            runtimePhase == SleepBatteryRuntimePhase.WAITING_TO_RESUME
    }
    if (!phaseAllowsResume) return SleepResumeAction.KEEP_CURRENT_TUNNEL

    if (!tunnelRunning) {
        // AlarmManager/Android могут создать службу заново после того, как
        // процесс с уже остановленным VPN был выгружен.
        return SleepResumeAction.RESTORE_PAUSED_TUNNEL
    }
    // PAUSED_UNTIL_SCREEN_ON и WAITING_TO_RESUME записываются только после
    // подтверждённой остановки интерфейса. Поэтому сохранённая фаза остаётся
    // авторитетной и после пересоздания одной лишь Service в живом процессе.
    return SleepResumeAction.RESUME_PAUSED_TUNNEL
}

internal fun sleepDelayDescription(totalMinutes: Int): String {
    val normalized = normalizeSleepPauseDelayMinutes(totalMinutes)
    val hours = normalized / 60
    val minutes = normalized % 60
    return buildList {
        if (hours > 0) add("$hours ч")
        if (minutes > 0) add("$minutes мин")
    }.joinToString(" ").ifBlank { "0 мин" }
}

class TunnelService : Service() {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val startRequestGate = TunnelStartRequestGate()
    private var pendingStartJob: Job? = null
    private var profileRuntimeUpdateJob: Job? = null
    private var activeProfileRefreshJob: Job? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null
    private var wifiLockReleaseJob: Job? = null
    private var trustedWifiTransitionWakeLock: PowerManager.WakeLock? = null
    private var updateJob: Job? = null
    private var profileNameJob: Job? = null
    private var networkChangeJob: Job? = null
    private var lastNotificationTitle: String? = null
    private var lastNotificationText: String? = null
    private var lastNotificationSmallIcon: Int? = null
    private var sleepWakeResultText: String? = null
    private var sleepWakeResultVisibleUntilMs = 0L
    private var notificationProfileTitle: String = "WDTT Plus"
    private var connectionProfileIndex: Int? = null
    private var profileStateJob: Job? = null
    private var requestedStopReason: TunnelStopReason? = null
    private var stopSequenceJob: Job? = null
    private var intentionalStopCompleted = false
    
    // Network Monitoring
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var lastNetworkChangeTime = 0L
    private val activeNetworks = ConcurrentHashMap.newKeySet<Network>()
    private val trustedWifiResumeNetworks = TrustedWifiResumeNetworkTracker<Network>()
    private var isTunnelPaused = false
    private var lastValidatedNetwork: Network? = null
    private var lastStableNetworkReconnectAt = 0L
    private var stableNetworkWasLost = false
    private var stableNetworkReconnectPending = false
    private var stableNetworkEvidenceSinceMs = 0L
    private var handoverPreviousNetwork: Network? = null
    private var networkPausedByLoss = false
    private var vpnInterfaceMissingSinceMs = 0L
    private var lastVpnInterfaceRecoveryAttemptAtMs = 0L
    private var screenStateReceiver: BroadcastReceiver? = null
    private var trustedWifiStateReceiver: BroadcastReceiver? = null
    private var packageChangeReceiver: BroadcastReceiver? = null
    private var wakeRescueJob: Job? = null
    private var timerResumeTransportJob: Job? = null
    private var sleepPauseJob: Job? = null
    private var sleepAutoResumeJob: Job? = null
    private var shortSleepPauseWakeLock: PowerManager.WakeLock? = null
    private var shortSleepResumeWakeLock: PowerManager.WakeLock? = null
    private var timerResumeTransportWakeLock: PowerManager.WakeLock? = null
    private var sleepTimerNotificationActive = false
    @Volatile
    private var sleepExecutionGeneration = 0L
    private val sleepTransitionMutex = Mutex()
    private var lastKnownDeviceInteractive = true
    @Volatile
    private var sleepPausedByPolicy = false
    private var trustedWifiNetworkCallback: ConnectivityManager.NetworkCallback? = null
    private var trustedWifiSettingsJob: Job? = null
    private var trustedWifiEvaluationJob: Job? = null
    private val trustedWifiEvaluationScheduleLock = Any()
    private var trustedWifiPendingEvaluationDelayMs: Long? = null
    private var trustedWifiResumeRetryJob: Job? = null
    private val trustedWifiResumeRetryLock = Any()
    private var trustedWifiResumeRetryCount = 0
    @Volatile
    private var trustedWifiResumeInProgress = false
    private var trustedWifiResumeStartedAt = 0L
    private val trustedWifiTransitionMutex = Mutex()
    @Volatile
    private var trustedWifiWaiting = false
    @Volatile
    private var trustedWifiWaitingSsid = ""
    private var lastStartParams: TunnelParams? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        lastKnownDeviceInteractive = isDeviceInteractive()
        if (!lastKnownDeviceInteractive) {
            TunnelManager.noteDeviceSleepStarted()
        }
        // Нужен только на время старта службы; постоянный lock не даёт
        // устройству уходить в глубокий сон при работающем VPN.
        acquireWakeLock()
        setupNetworkCallback()
        setupTrustedWifiMonitoring()
        registerScreenStateReceiver()
        registerTrustedWifiStateReceiver()
        registerPackageChangeReceiver()
        serviceScope.launch {
            TunnelProfileRuntimeUpdateBus.requests.collect(::applyUpdatedTunnelProfile)
        }
        serviceScope.launch {
            TunnelManager.vpnSlotYieldRequested.collect { yieldRequested ->
                if (
                    shouldYieldVpnSlot(
                        vpnSlotYieldRequested = yieldRequested,
                        tunnelRunning = TunnelManager.running.value,
                        stopRequested = requestedStopReason != null,
                    )
                ) {
                    Log.w(
                        "TunnelService",
                        "Android остановил интерфейс WDTT Plus; уступаем VPN-слот без автоматического восстановления."
                    )
                    stopTunnel(TunnelStopReason.VpnStoppedExternally)
                }
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) {
            restoreTunnelRespectingSleepScenario()
            return START_STICKY
        }

        when (intent.action) {
            ACTION_VPN_SLOT_REVOKED -> {
                Log.w(
                    "TunnelService",
                    "Android передал VPN-слот другому приложению; немедленно завершаем WDTT Plus."
                )
                stopTunnel(TunnelStopReason.VpnSlotTransferred)
                return START_NOT_STICKY
            }
            "START" -> {
                TunnelManager.allowVpnSlotAcquisition()
                clearSleepWakeResult()
                val notification = createNotification("Запуск...")
                startPersistentForeground(notification)

                val params = TunnelParams(
                    peer = intent.getStringExtra("peer") ?: "",
                    vkHashes = intent.getStringExtra("vk_hashes") ?: "",
                    secondaryVkHash = intent.getStringExtra("secondary_vk_hash") ?: "",
                    workersPerHash = intent.getIntExtra("workers_per_hash", 18),
                    port = intent.getIntExtra("port", 9000),
                    sni = intent.getStringExtra("sni") ?: "",
                    connectionPassword = intent.getStringExtra("connection_password") ?: "",
                    protocol = intent.getStringExtra("protocol") ?: "udp",
                    vkCallsPreflight = intent.getBooleanExtra("vkcalls_preflight", true),
                    rtNetwork = intent.getBooleanExtra("rt_network", false),
                    rtMasque = intent.getBooleanExtra("rt_masque", false),
                    rtMasqueServerBootstrap =
                        intent.getBooleanExtra("rt_masque_server_bootstrap", false),
                    rtTurnSni = intent.getStringExtra("rt_turn_sni") ?: DEFAULT_RT_TURN_SNI,
                    captchaMode = sanitizeCaptchaMode(intent.getStringExtra("captcha_mode")),
                    captchaSolveMethod = intent.getStringExtra("captcha_solve_method") ?: "auto",
                    fingerprint = intent.getStringExtra("fingerprint") ?: "firefox",
                    clientIds = intent.getStringExtra("client_ids") ?: DEFAULT_VK_CLIENT_IDS,
                    customVkCredentialsEnabled = intent.getBooleanExtra("custom_vk_credentials_enabled", false),
                    customVkClientId = intent.getStringExtra("custom_vk_client_id") ?: "",
                    customVkClientSecret = intent.getStringExtra("custom_vk_client_secret") ?: "",
                    profileMaxWorkers = intent.getIntExtra("profile_max_workers", 0),
                    managedConfigFirstStart =
                        intent.getBooleanExtra(MANAGED_CONFIG_FIRST_START_EXTRA, false),
                    profileIndex = intent.getIntExtra(TUNNEL_PROFILE_INDEX_EXTRA, 0).coerceIn(0, 2),
                )
                requestTunnelStart(params)
            }
            "STOP" -> stopTunnel(TunnelStopReason.User)
            "DEPLOY_START" -> {
                val notification = createNotification("Установка на сервер...", "DEPLOY_CANCEL", "Отменить")
                startPersistentForeground(notification)
                acquireWakeLock(DEPLOY_WAKE_LOCK_TIMEOUT_MS)
            }
            "DEPLOY_CANCEL" -> {
                com.wdtt.plus.DeployManager.writeError("[!] ❌ Установка отменена пользователем")
                com.wdtt.plus.DeployManager.stopDeploy("error: Отменена пользователем")
                if (trustedWifiWaiting) updateTrustedWifiNotification()
                else if (TunnelManager.running.value) updateNotification("Туннель активен")
                else stopForeground(STOP_FOREGROUND_REMOVE)
                scheduleTrustedWifiEvaluation(delayMs = 0L)
            }
            "DEPLOY_STOP" -> {
                if (trustedWifiWaiting) {
                    updateTrustedWifiNotification()
                } else if (!TunnelManager.running.value) {
                    stopTunnel()
                } else {
                    updateNotification("Туннель активен")
                }
                scheduleTrustedWifiEvaluation(delayMs = 0L)
            }
            "TRUSTED_WIFI_RECHECK" -> {
                val restoredState = TrustedWifiManager.state.value
                if (!trustedWifiWaiting && restoredState.waiting) {
                    trustedWifiWaiting = true
                    trustedWifiWaitingSsid = restoredState.ssid
                    startPersistentForeground(createNotification("Проверка доверенной Wi-Fi сети..."))
                    startNotificationProfileWatcher()
                    startStatsUpdater()
                    acquireTrustedWifiTransitionWakeLock()
                    releaseWakeLock()
                    releaseWifiLock()
                }
                scheduleTrustedWifiEvaluation(delayMs = 0L)
            }
            ACTION_SLEEP_PAUSE_NOW -> {
                cancelSleepExecution()
                TunnelManager.noteSleepBatteryEvent(
                    "pause_now",
                    "Пользователь завершил ожидание и запросил отключение VPN сейчас.",
                )
                serviceScope.launch {
                    val settingsStore = SettingsStore(applicationContext)
                    val runtime = settingsStore.sleepBatteryRuntimeState.first()
                    if (
                        runtime.phase != SleepBatteryRuntimePhase.WAITING_TO_PAUSE ||
                        lastKnownDeviceInteractive
                    ) {
                        saveSleepRuntimeForCurrentScreen(
                            SleepBatteryRuntimePhase.RESUMED_UNTIL_SCREEN_ON,
                        )
                        updateNotification(buildTunnelNotificationText())
                        return@launch
                    }
                    val paused = pauseTunnelForSleepIfEligible(
                        committedPhase = SleepBatteryRuntimePhase.PAUSED_UNTIL_SCREEN_ON,
                    )
                    if (!paused) {
                        saveSleepRuntimeForCurrentScreen(
                            SleepBatteryRuntimePhase.RESUMED_UNTIL_SCREEN_ON,
                        )
                    }
                    if (paused) {
                        showSleepPausedNotification()
                    } else {
                        updateNotification(buildTunnelNotificationText())
                    }
                }
            }
            ACTION_SLEEP_KEEP_RUNNING -> {
                // Если кнопка нажата ровно в момент остановки интерфейса,
                // эта же ветка дождётся перехода и безопасно откатит паузу.
                TunnelManager.noteSleepBatteryEvent(
                    "cycle_skipped",
                    "Текущий цикл экономии пропущен; VPN останется активным до следующего выключения экрана.",
                )
                resumeSleepPausedTunnelIfNeeded(SleepResumeTrigger.USER)
            }
            ACTION_SLEEP_RESUME_NOW -> {
                TunnelManager.noteSleepBatteryEvent(
                    "resume_now",
                    "Пользователь запросил включение VPN до завершения таймера.",
                )
                resumeSleepPausedTunnelIfNeeded(SleepResumeTrigger.USER)
            }
            ACTION_SLEEP_AUTO_RESUME -> {
                startPersistentForeground(createNotification("Завершение таймера сна..."))
                handleSleepAutoResume(
                    intent.getLongExtra(EXTRA_SLEEP_RESUME_DEADLINE_MS, 0L),
                )
            }
            ACTION_SLEEP_KEEP_PAUSED -> {
                cancelSleepExecution()
                TunnelManager.noteSleepBatteryEvent(
                    "keep_paused",
                    "Автоматическое включение отменено; VPN останется выключенным до включения экрана или ручного запуска.",
                )
                if (isDeviceInteractive()) {
                    resumeSleepPausedTunnelIfNeeded(SleepResumeTrigger.SCREEN_ON)
                } else {
                    serviceScope.launch {
                        SettingsStore(applicationContext).saveSleepBatteryRuntimeState(
                            SleepBatteryRuntimePhase.PAUSED_UNTIL_SCREEN_ON,
                        )
                        showSleepPausedNotification()
                    }
                }
            }
        }
        return START_STICKY
    }

    private fun restoreTunnel() {
        val notification = createNotification("Восстановление соединения...")
        startPersistentForeground(notification)

        val appContext = applicationContext
        val generation = startRequestGate.next()
        pendingStartJob?.cancel()
        pendingStartJob = serviceScope.launch {
            try {
                val store = SettingsStore(appContext)
                val savedTunnelProfile = store.activeTunnelProfile.first()
                val params = buildTunnelParamsFromSettings(appContext, savedTunnelProfile)
                if (!startRequestGate.isCurrent(generation)) return@launch
                if (params != null) {
                    val access = AccessLifecycleCoordinator.prepareStart(
                        appContext,
                        params.profileIndex,
                    )
                    if (!startRequestGate.isCurrent(generation)) return@launch
                    if (access is AccessStartDecision.Denied) {
                        reportAccessDenied(access.status)
                        stopTunnel(TunnelStopReason.AccessExpired)
                        return@launch
                    }
                    val refreshedParams = buildTunnelParamsFromSettings(
                        appContext,
                        params.profileIndex,
                    )
                    if (refreshedParams == null) {
                        stopTunnel(TunnelStopReason.RestoreFailed)
                        return@launch
                    }
                    rememberConnectionProfile(
                        refreshedParams.profileIndex,
                        persist = savedTunnelProfile == null
                    )
                    lastStartParams = refreshedParams
                    val restoreWaiting = store.trustedWifiEnabled.first() &&
                        store.trustedWifiWaiting.first()
                    if (!startRequestGate.isCurrent(generation)) return@launch
                    if (restoreWaiting) {
                        trustedWifiWaiting = true
                        trustedWifiWaitingSsid = store.trustedWifiWaitingSsid.first()
                        if (!startRequestGate.isCurrent(generation)) return@launch
                        TrustedWifiManager.setWaiting(trustedWifiWaitingSsid)
                        TunnelManager.noteTrustedWifiEvent(
                            "waiting_restored",
                            "Android восстановил службу ожидания; проверяем текущую сеть."
                        )
                        startNotificationProfileWatcher()
                        startStatsUpdater()
                        acquireTrustedWifiTransitionWakeLock()
                        releaseWakeLock()
                        releaseWifiLock()
                        scheduleTrustedWifiEvaluation(delayMs = 0L)
                    } else {
                        startOrWaitForTrustedWifi(
                            params = refreshedParams,
                            restoreSessionTraffic = true,
                        )
                    }
                } else {
                    stopTunnel(TunnelStopReason.RestoreFailed)
                }
            } catch (e: Exception) {
                if (startRequestGate.isCurrent(generation)) {
                    stopTunnel(TunnelStopReason.RestoreFailed)
                }
            }
        }
    }

    private fun restoreTunnelRespectingSleepScenario() {
        startPersistentForeground(createNotification("Восстановление состояния сна..."))
        serviceScope.launch {
            val settingsStore = SettingsStore(applicationContext)
            val runtime = settingsStore.sleepBatteryRuntimeState.first()
            val enabled = settingsStore.pauseVpnDuringSleep.first()
            val mode = settingsStore.sleepBatteryMode.first()
            if (lastKnownDeviceInteractive || !enabled) {
                settingsStore.saveSleepBatteryRuntimeState(SleepBatteryRuntimePhase.IDLE)
                restoreTunnel()
                return@launch
            }

            when (runtime.phase) {
                SleepBatteryRuntimePhase.WAITING_TO_RESUME -> {
                    if (
                        mode == SleepBatteryMode.TIMED_PAUSE &&
                        runtime.deadlineMs > System.currentTimeMillis()
                    ) {
                        TunnelManager.noteSleepBatteryEvent(
                            "state_restored",
                            "После перезапуска восстановлена пауза VPN с ожидающим таймером включения.",
                        )
                        keepTunnelPausedAfterProcessRestore()
                        if (!scheduleSleepResumeAlarmAt(runtime.deadlineMs)) {
                            resumeAfterSleepAlarmFailure()
                            return@launch
                        }
                        showSleepResumeCountdown(runtime.deadlineMs)
                    } else {
                        // Дедлайн уже прошёл: этот цикл сна завершён, поэтому
                        // после восстановления не запускаем его заново.
                        settingsStore.saveSleepBatteryRuntimeState(
                            SleepBatteryRuntimePhase.RESUMED_UNTIL_SCREEN_ON,
                        )
                        TunnelManager.noteSleepBatteryEvent(
                            "restore_deadline_complete",
                            "Сохранённый таймер уже завершён; восстанавливаем VPN без повторного запуска сценария.",
                        )
                        restoreTunnel()
                    }
                }
                SleepBatteryRuntimePhase.PAUSED_UNTIL_SCREEN_ON -> {
                    TunnelManager.noteSleepBatteryEvent(
                        "state_restored",
                        "После перезапуска восстановлено состояние: VPN выключен до включения экрана.",
                    )
                    keepTunnelPausedAfterProcessRestore()
                    showSleepPausedNotification()
                }
                SleepBatteryRuntimePhase.RESUMED_UNTIL_SCREEN_ON -> {
                    TunnelManager.noteSleepBatteryEvent(
                        "state_restored",
                        "После перезапуска восстановлено состояние: VPN уже был включён таймером.",
                    )
                    restoreTunnel()
                }
                SleepBatteryRuntimePhase.WAITING_TO_PAUSE -> {
                    if (mode != SleepBatteryMode.DELAYED_PAUSE) {
                        settingsStore.saveSleepBatteryRuntimeState(SleepBatteryRuntimePhase.IDLE)
                        TunnelManager.noteSleepBatteryEvent(
                            "restore_state_changed",
                            "Сохранённое ожидание отключения отменено: после перезапуска выбран другой сценарий сна.",
                        )
                    } else {
                        TunnelManager.noteSleepBatteryEvent(
                            "state_restored",
                            "После перезапуска восстановлен ожидающий цикл отключения VPN.",
                        )
                    }
                    restoreTunnel()
                }
                SleepBatteryRuntimePhase.IDLE -> restoreTunnel()
            }
        }
    }

    private fun keepTunnelPausedAfterProcessRestore() {
        sleepPausedByPolicy = true
        networkPausedByLoss = false
        isTunnelPaused = true
        startNotificationProfileWatcher()
        startStatsUpdater()
        releaseWakeLock()
        releaseWifiLock()
    }

    private fun requestTunnelStart(params: TunnelParams) {
        val generation = startRequestGate.next()
        pendingStartJob?.cancel()
        pendingStartJob = serviceScope.launch {
            val access = withContext(Dispatchers.IO) {
                AccessLifecycleCoordinator.prepareStart(
                    applicationContext,
                    params.profileIndex,
                )
            }
            if (!startRequestGate.isCurrent(generation)) return@launch
            when (access) {
                AccessStartDecision.Allowed -> {
                    val refreshedParams = withContext(Dispatchers.IO) {
                        buildTunnelParamsFromSettings(
                            applicationContext,
                            params.profileIndex,
                        )
                    }
                    if (refreshedParams == null) {
                        stopTunnel(TunnelStopReason.RestoreFailed)
                        return@launch
                    }
                    rememberConnectionProfile(refreshedParams.profileIndex)
                    lastStartParams = refreshedParams
                    startOrWaitForTrustedWifi(refreshedParams)
                }
                is AccessStartDecision.Denied -> {
                    reportAccessDenied(access.status)
                    stopTunnel(TunnelStopReason.AccessExpired)
                }
            }
        }
    }

    private fun applyUpdatedTunnelProfile(profileIndex: Int) {
        if (profileIndex !in 0..2) return
        val activeProfile = connectionProfileIndex
            ?: TunnelManager.activeTunnelProfile.value
            ?: return
        if (activeProfile != profileIndex) return

        profileRuntimeUpdateJob?.cancel()
        profileRuntimeUpdateJob = serviceScope.launch {
            val refreshedParams = withContext(Dispatchers.IO) {
                buildTunnelParamsFromSettings(
                    applicationContext,
                    profileIndex,
                )
            }
            if (refreshedParams == null) {
                TunnelManager.noteAccessLifecycleEvent(
                    key = "profile_${profileIndex}_runtime_update_invalid",
                    message = "Новые параметры профиля пока не удалось применить",
                    warning = true,
                )
                return@launch
            }
            lastStartParams = refreshedParams
            if (trustedWifiWaiting) {
                TunnelManager.noteAccessLifecycleEvent(
                    key = "profile_${profileIndex}_runtime_update_waiting",
                    message = "Новые параметры будут применены после выхода из доверенной сети",
                    warning = false,
                )
                return@launch
            }

            when (
                TunnelManager.applyUpdatedProfileConfiguration(
                    context = applicationContext,
                    params = refreshedParams,
                    restartTransport = !isTunnelPaused,
                )
            ) {
                TunnelProfileRuntimeApplyResult.RESTARTED ->
                    updateNotification("Обновление подключения...")
                TunnelProfileRuntimeApplyResult.STORED_FOR_RESUME ->
                    updateNotification("Ожидание сети")
                TunnelProfileRuntimeApplyResult.INACTIVE,
                TunnelProfileRuntimeApplyResult.UNCHANGED -> Unit
            }
        }
    }

    private fun invalidatePendingStart() {
        startRequestGate.invalidate()
        pendingStartJob?.cancel()
        pendingStartJob = null
    }

    private fun startTunnel(
        params: TunnelParams,
        fromTrustedWifiResume: Boolean = false,
        restoreSessionTraffic: Boolean = false,
    ) {
        cancelTrustedWifiResumeRetry(resetCount = !fromTrustedWifiResume)
        trustedWifiResumeInProgress = fromTrustedWifiResume
        trustedWifiResumeStartedAt = if (fromTrustedWifiResume) System.currentTimeMillis() else 0L
        sleepPausedByPolicy = false
        isTunnelPaused = false
        networkPausedByLoss = false
        cancelSleepExecution()
        trustedWifiWaiting = false
        trustedWifiWaitingSsid = ""
        lastStartParams = params
        TrustedWifiManager.clear()
        TunnelManager.scope.launch {
            SettingsStore(applicationContext).saveTrustedWifiWaiting(false)
        }
        requestedStopReason = null
        updateNotification("Подключение...")
        acquireWakeLock()
        acquireWifiLockForTransition()
        releaseTrustedWifiTransitionWakeLock()

        // Подготавливаем CaptchaWebViewManager (не создаёт WebView — просто сохраняет контекст)
        // Вызываем всегда — дёшево, а WebView создаётся на лету при каждом запросе капчи
        CaptchaWebViewManager.onTunnelStart(applicationContext)

        if (fromTrustedWifiResume) {
            TunnelManager.noteTrustedWifiEvent(
                "resume_start",
                "Рабочая сеть подтверждена — запускаем VPN после доверенной Wi-Fi."
            )
        }
        TunnelManager.start(
            context = this,
            params = params,
            preserveLogs = fromTrustedWifiResume || restoreSessionTraffic,
            restoreSessionTraffic = restoreSessionTraffic,
        )
        startNotificationProfileWatcher()
        startStatsUpdater()
        startActiveProfileRefresh(params.profileIndex)
        scheduleSleepPauseIfNeeded(startNewScreenOffCycle = false)
    }

    private fun stopTunnel(reason: TunnelStopReason = TunnelStopReason.User) {
        TunnelManager.noteStopRequested()
        if (stopSequenceJob?.isActive == true) return
        clearSleepWakeResult()
        sleepPausedByPolicy = false
        cancelSleepExecution()
        TunnelManager.scope.launch {
            SettingsStore(applicationContext).saveSleepBatteryRuntimeState(
                SleepBatteryRuntimePhase.IDLE,
            )
        }
        isTunnelPaused = false
        networkPausedByLoss = false
        invalidatePendingStart()
        val effectiveReason = requestedStopReason ?: reason
        requestedStopReason = effectiveReason
        updateJob?.cancel()
        profileNameJob?.cancel()
        activeProfileRefreshJob?.cancel()
        networkChangeJob?.cancel()
        wakeRescueJob?.cancel()
        cancelTimerResumeTransportConfirmation()
        cancelTrustedWifiResumeRetry(resetCount = true)
        profileNameJob = null
        activeProfileRefreshJob = null
        networkChangeJob = null
        wakeRescueJob = null
        trustedWifiResumeInProgress = false
        trustedWifiResumeStartedAt = 0L
        releaseTrustedWifiTransitionWakeLock()
        cancelTrustedWifiEvaluations()
        trustedWifiWaiting = false
        trustedWifiWaitingSsid = ""
        lastStartParams = null
        forgetConnectionProfile()
        TrustedWifiManager.clear()
        TunnelManager.scope.launch {
            SettingsStore(applicationContext).saveTrustedWifiWaiting(false)
        }

        // Уничтожаем текущий WebView (если капча решается) и чистим контекст
        CaptchaWebViewManager.onTunnelStop()

        releaseWakeLock()
        releaseWifiLock()
        lastValidatedNetwork = null
        lastStableNetworkReconnectAt = 0L
        stableNetworkWasLost = false
        stableNetworkReconnectPending = false
        stableNetworkEvidenceSinceMs = 0L
        handoverPreviousNetwork = null
        activeNetworks.clear()
        trustedWifiResumeNetworks.clear()
        updateNotification("Отключение…")

        // Служба должна жить до фактической остановки WireGuard и нативного клиента.
        // Иначе быстрый повторный тап создаёт новую службу, пока прежний транспорт
        // ещё завершается, а onDestroy ошибочно записывает системную остановку.
        stopSequenceJob = serviceScope.launch {
            try {
                TunnelManager.stopAndWait(effectiveReason)
            } finally {
                intentionalStopCompleted = true
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private fun startNotificationProfileWatcher() {
        profileNameJob?.cancel()
        val settingsStore = SettingsStore(applicationContext)
        profileNameJob = TunnelManager.scope.launch(Dispatchers.Main) {
            val profile = connectionProfileIndex
                ?: settingsStore.activeTunnelProfile.first()
                ?: settingsStore.activeProfile.first().coerceIn(0, 2)
            settingsStore.profileNames.collect { profileNames ->
                val profileLabel = vpnProfileDisplayName(profile, profileNames)
                notificationProfileTitle = "WDTT Plus · $profileLabel"
                if (trustedWifiWaiting) {
                    updateTrustedWifiNotification()
                } else if (TunnelManager.running.value && !isTunnelPaused) {
                    updateNotification(buildTunnelNotificationText())
                }
            }
        }
    }

    private fun startActiveProfileRefresh(profileIndex: Int) {
        activeProfileRefreshJob?.cancel()
        activeProfileRefreshJob = serviceScope.launch(Dispatchers.IO) {
            while (isActive) {
                delay(ACTIVE_PROFILE_REFRESH_INTERVAL_MS)
                if (
                    connectionProfileIndex != profileIndex ||
                    !TunnelManager.running.value ||
                    isTunnelPaused ||
                    trustedWifiWaiting ||
                    TunnelManager.isCaptchaInProgress() ||
                    !hasAnyRealNetwork()
                ) {
                    continue
                }
                AccessLifecycleCoordinator.refreshProfile(
                    context = applicationContext,
                    profileIndex = profileIndex,
                    force = true,
                )
            }
        }
    }

    private fun rememberConnectionProfile(profile: Int, persist: Boolean = true) {
        val normalized = profile.coerceIn(0, 2)
        connectionProfileIndex = normalized
        TunnelManager.activeTunnelProfile.value = normalized
        if (!persist) return
        profileStateJob?.cancel()
        profileStateJob = TunnelManager.scope.launch {
            SettingsStore(applicationContext).saveActiveTunnelProfile(normalized)
        }
    }

    private fun forgetConnectionProfile() {
        connectionProfileIndex = null
        TunnelManager.activeTunnelProfile.value = null
        profileStateJob?.cancel()
        profileStateJob = TunnelManager.scope.launch {
            SettingsStore(applicationContext).saveActiveTunnelProfile(null)
        }
    }

    private fun registerScreenStateReceiver() {
        if (screenStateReceiver != null) return
        screenStateReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                when (intent?.action) {
                    Intent.ACTION_SCREEN_ON -> {
                        observeDeviceInteractiveState(interactive = true)
                        resumeSleepPausedTunnelIfNeeded(SleepResumeTrigger.SCREEN_ON)
                        scheduleTrustedWifiEvaluation(delayMs = 0L)
                    }
                    Intent.ACTION_SCREEN_OFF -> {
                        observeDeviceInteractiveState(interactive = false)
                        wakeRescueJob?.cancel()
                        wakeRescueJob = null
                        scheduleSleepPauseIfNeeded(startNewScreenOffCycle = true)
                    }
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(screenStateReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(screenStateReceiver, filter)
        }
    }

    private fun registerPackageChangeReceiver() {
        if (packageChangeReceiver != null) return
        packageChangeReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                if (
                    intent?.action != Intent.ACTION_PACKAGE_ADDED &&
                    intent?.action != Intent.ACTION_PACKAGE_REMOVED &&
                    intent?.action != Intent.ACTION_PACKAGE_REPLACED
                ) return
                val profile = connectionProfileIndex
                    ?: TunnelManager.activeTunnelProfile.value
                    ?: return
                // Android проверяет allow/disallow-пакеты в момент создания VpnService.
                // После установки или удаления приложения пересобираем этот список.
                TunnelManager.scheduleWireGuardReload(profile, delayMs = 500L)
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addDataScheme("package")
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(packageChangeReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(packageChangeReceiver, filter)
        }
    }

    private fun scheduleSleepPauseIfNeeded(startNewScreenOffCycle: Boolean) {
        cancelSleepExecution()
        if (startNewScreenOffCycle) clearSleepWakeResult()
        val executionGeneration = sleepExecutionGeneration
        sleepPauseJob = serviceScope.launch {
            val settingsStore = SettingsStore(applicationContext)
            val pauseEnabled = settingsStore.pauseVpnDuringSleep.first()
            if (
                executionGeneration != sleepExecutionGeneration ||
                lastKnownDeviceInteractive ||
                !pauseEnabled
            ) {
                if (executionGeneration != sleepExecutionGeneration) return@launch
                // Обычный фоновый VPN не нуждается в удержании CPU: Android
                // разбудит foreground VPN по сетевому I/O. Таймер сна при этом
                // не запланирован, поэтому точность его работы не затрагивается.
                if (!pauseEnabled && TunnelManager.running.value && !isTunnelPaused) {
                    releaseWakeLock()
                    releaseWifiLock()
                }
                settingsStore.saveSleepBatteryRuntimeState(SleepBatteryRuntimePhase.IDLE)
                return@launch
            }

            val savedRuntime = settingsStore.sleepBatteryRuntimeState.first()
            val runtime = if (startNewScreenOffCycle) {
                SleepBatteryRuntimeState()
            } else {
                savedRuntime
            }
            if (executionGeneration != sleepExecutionGeneration || lastKnownDeviceInteractive) {
                return@launch
            }
            if (startNewScreenOffCycle && savedRuntime.phase != SleepBatteryRuntimePhase.IDLE) {
                settingsStore.saveSleepBatteryRuntimeState(SleepBatteryRuntimePhase.IDLE)
            }
            if (runtime.phase == SleepBatteryRuntimePhase.RESUMED_UNTIL_SCREEN_ON) {
                updateNotification(buildTunnelNotificationText())
                return@launch
            }

            val tunnelStarted = withTimeoutOrNull(15_000L) {
                while (isActive && !TunnelManager.running.value) {
                    delay(250L)
                }
                TunnelManager.running.value
            } ?: false
            if (!tunnelStarted) return@launch
            if (executionGeneration != sleepExecutionGeneration || lastKnownDeviceInteractive) {
                return@launch
            }

            val mode = settingsStore.sleepBatteryMode.first()
            val plan = buildSleepBatteryPlan(
                mode = mode,
                pauseDelayMinutes = settingsStore.pauseVpnDuringSleepDelayMinutes.first(),
                resumeDelayMinutes = settingsStore.resumeVpnDuringSleepDelayMinutes.first(),
            )
            when (mode) {
                SleepBatteryMode.DELAYED_PAUSE -> {
                    val delayMinutes = plan.pauseAfterMinutes
                    val nowMs = System.currentTimeMillis()
                    val deadlineMs = when {
                        delayMinutes == 0 -> 0L
                        runtime.phase == SleepBatteryRuntimePhase.WAITING_TO_PAUSE &&
                            runtime.deadlineMs > 0L -> runtime.deadlineMs
                        else -> nowMs + delayMinutes * 60_000L
                    }
                    if (executionGeneration != sleepExecutionGeneration || lastKnownDeviceInteractive) {
                        return@launch
                    }
                    settingsStore.saveSleepBatteryRuntimeState(
                        SleepBatteryRuntimePhase.WAITING_TO_PAUSE,
                        deadlineMs,
                    )
                    if (deadlineMs > nowMs) {
                        TunnelManager.noteSleepBatteryEvent(
                            "pause_scheduled",
                            "Экран выключен; VPN отключится через ${sleepDelayDescription(delayMinutes)}. Включение экрана отменит текущий цикл.",
                        )
                        showSleepTimerNotification(
                            title = "VPN включён · таймер сна",
                            text = "Отключение через",
                            deadlineWallMs = deadlineMs,
                            actions = listOf(
                                TunnelNotificationAction(ACTION_SLEEP_PAUSE_NOW, "Отключить сейчас", 42),
                                TunnelNotificationAction(ACTION_SLEEP_KEEP_RUNNING, "Пропустить", 43),
                            ),
                        )
                        acquireShortSleepPauseGuard(deadlineMs)
                        delay(deadlineMs - nowMs)
                    }
                    if (executionGeneration != sleepExecutionGeneration) return@launch
                    sleepTimerNotificationActive = false
                    val paused = pauseTunnelForSleepIfEligible(
                        committedPhase = SleepBatteryRuntimePhase.PAUSED_UNTIL_SCREEN_ON,
                        expectedExecutionGeneration = executionGeneration,
                    )
                    releaseShortSleepPauseWakeLock()
                    if (!paused && executionGeneration == sleepExecutionGeneration) {
                        TunnelManager.noteSleepBatteryEvent(
                            "pause_skipped",
                            "Отключение VPN пропущено: состояние подключения или экрана изменилось.",
                        )
                        saveSleepRuntimeForCurrentScreen(
                            SleepBatteryRuntimePhase.RESUMED_UNTIL_SCREEN_ON,
                        )
                    }
                    if (paused) {
                        showSleepPausedNotification()
                    } else {
                        updateNotification(buildTunnelNotificationText())
                    }
                }
                SleepBatteryMode.TIMED_PAUSE -> {
                    val resumeDelayMinutes = checkNotNull(plan.resumeAfterMinutes)
                    if (resumeDelayMinutes == 0) {
                        settingsStore.saveSleepBatteryRuntimeState(
                            SleepBatteryRuntimePhase.RESUMED_UNTIL_SCREEN_ON,
                        )
                        TunnelManager.noteSleepBatteryEvent(
                            "zero_timer",
                            "Таймер включения установлен на 0 мин; VPN остаётся активным в этом цикле сна.",
                        )
                        updateNotification(buildTunnelNotificationText())
                        return@launch
                    }

                    val nowMs = System.currentTimeMillis()
                    val deadlineWallMs = if (
                        runtime.phase == SleepBatteryRuntimePhase.WAITING_TO_RESUME &&
                        runtime.deadlineMs > 0L
                    ) {
                        runtime.deadlineMs
                    } else {
                        nowMs + resumeDelayMinutes * 60_000L
                    }
                    if (deadlineWallMs <= nowMs) {
                        settingsStore.saveSleepBatteryRuntimeState(
                            SleepBatteryRuntimePhase.RESUMED_UNTIL_SCREEN_ON,
                        )
                        updateNotification(buildTunnelNotificationText())
                        return@launch
                    }
                    if (executionGeneration != sleepExecutionGeneration) return@launch
                    TunnelManager.noteSleepBatteryEvent(
                        "resume_scheduled",
                        "Экран выключен; отключаем VPN и планируем включение примерно через ${sleepDelayDescription(resumeDelayMinutes)}.",
                    )
                    if (
                        !pauseTunnelForSleepIfEligible(
                            committedPhase = SleepBatteryRuntimePhase.WAITING_TO_RESUME,
                            committedDeadlineMs = deadlineWallMs,
                            expectedExecutionGeneration = executionGeneration,
                        )
                    ) {
                        cancelSleepResumeAlarm()
                        TunnelManager.noteSleepBatteryEvent(
                            "pause_skipped",
                            "Отключение VPN и таймер включения отменены: состояние подключения или экрана изменилось.",
                        )
                        if (executionGeneration == sleepExecutionGeneration) {
                            saveSleepRuntimeForCurrentScreen(
                                SleepBatteryRuntimePhase.RESUMED_UNTIL_SCREEN_ON,
                            )
                        }
                        updateNotification(buildTunnelNotificationText())
                        return@launch
                    }
                    if (!scheduleSleepResumeAlarmAt(deadlineWallMs)) {
                        resumeAfterSleepAlarmFailure()
                        return@launch
                    }
                    showSleepResumeCountdown(deadlineWallMs)
                }
            }
        }
    }

    private suspend fun pauseTunnelForSleepIfEligible(
        committedPhase: SleepBatteryRuntimePhase,
        committedDeadlineMs: Long = 0L,
        expectedExecutionGeneration: Long? = null,
    ): Boolean {
        val pauseEnabled = SettingsStore(applicationContext).pauseVpnDuringSleep.first()
        return withContext(NonCancellable) {
            sleepTransitionMutex.withLock {
                if (
                    expectedExecutionGeneration?.let { it != sleepExecutionGeneration } == true ||
                    !shouldPauseVpnForSleep(
                        pauseEnabled = pauseEnabled,
                        deviceInteractive = lastKnownDeviceInteractive,
                        tunnelRunning = TunnelManager.running.value,
                        tunnelPaused = isTunnelPaused,
                        trustedWifiWaiting = trustedWifiWaiting,
                    )
                ) return@withLock false

                sleepPausedByPolicy = true
                networkPausedByLoss = false
                isTunnelPaused = true
                networkChangeJob?.cancel()
                stableNetworkWasLost = false
                val interfaceStopped = withContext(Dispatchers.IO) {
                    // Пауза транспорта и системного VPN-интерфейса считается
                    // одной транзакцией: пробуждение дождётся её завершения.
                    TunnelManager.pause()
                    val helper = WireGuardHelper(applicationContext)
                    helper.stopTunnel()
                    !helper.isTunnelUp()
                }
                if (!interfaceStopped || lastKnownDeviceInteractive) {
                    // Если экран успел включиться во время остановки, тут же
                    // откатываем паузу: просроченное действие сна не должно
                    // оставлять VPN выключенным на активном экране.
                    sleepPausedByPolicy = false
                    networkPausedByLoss = false
                    isTunnelPaused = false
                    acquireWakeLock()
                    acquireWifiLockForTransition()
                    TunnelManager.resume()
                    if (!interfaceStopped) {
                        TunnelManager.noteSleepVpnPauseFailed()
                    }
                    updateNotification("VPN остаётся активным")
                    return@withLock false
                }
                SettingsStore(applicationContext).saveSleepBatteryRuntimeState(
                    phase = committedPhase,
                    deadlineMs = committedDeadlineMs,
                )
                TunnelManager.noteSleepVpnPaused()
                releaseWakeLock()
                releaseWifiLock()
                true
            }
        }
    }

    private fun resumeSleepPausedTunnelIfNeeded(trigger: SleepResumeTrigger) {
        cancelSleepExecution()
        serviceScope.launch {
            sleepTransitionMutex.withLock {
                val settingsStore = SettingsStore(applicationContext)
                val runtime = settingsStore.sleepBatteryRuntimeState.first()
                val deviceInteractive =
                    trigger == SleepResumeTrigger.SCREEN_ON || isDeviceInteractive()
                if (deviceInteractive) observeDeviceInteractiveState(interactive = true)
                val targetPhase = sleepRuntimePhaseAfterResume(deviceInteractive)
                if (trustedWifiWaiting || requestedStopReason != null) {
                    sleepPausedByPolicy = false
                    settingsStore.saveSleepBatteryRuntimeState(SleepBatteryRuntimePhase.IDLE)
                    if (trustedWifiWaiting) updateTrustedWifiNotification()
                    return@withLock
                }

                val action = decideSleepResumeAction(
                    trigger = trigger,
                    runtimePhase = runtime.phase,
                    tunnelRunning = TunnelManager.running.value,
                    blockedByAnotherPolicy = false,
                )
                if (trigger == SleepResumeTrigger.SCREEN_ON) {
                    rememberSleepWakeResult(runtime.phase)
                }
                if (action == SleepResumeAction.RESTORE_PAUSED_TUNNEL) {
                    sleepPausedByPolicy = false
                    networkPausedByLoss = false
                    isTunnelPaused = false
                    settingsStore.saveSleepBatteryRuntimeState(targetPhase)
                    noteSleepVpnResume(trigger)
                    // AlarmManager мог поднять процесс заново. Профиль
                    // восстанавливается, но завершённый цикл не взводится.
                    restoreTunnel()
                    if (trigger == SleepResumeTrigger.TIMER) {
                        scheduleTimerResumeTransportConfirmation()
                    }
                    return@withLock
                }
                if (action == SleepResumeAction.KEEP_CURRENT_TUNNEL) {
                    // Ожидающий таймер только снимается с взвода. Работающий
                    // VPN здесь принципиально не перезапускается.
                    if (
                        trigger == SleepResumeTrigger.SCREEN_ON &&
                        runtime.phase == SleepBatteryRuntimePhase.WAITING_TO_PAUSE
                    ) {
                        TunnelManager.noteSleepBatteryEvent(
                            "pause_cancelled_screen_on",
                            "Экран включён до отключения VPN; текущий цикл экономии отменён.",
                        )
                    }
                    sleepPausedByPolicy = false
                    settingsStore.saveSleepBatteryRuntimeState(targetPhase)
                    if (TunnelManager.running.value && !isTunnelPaused) {
                        updateNotification(buildTunnelNotificationText())
                    }
                    if (trigger == SleepResumeTrigger.SCREEN_ON) {
                        scheduleWakeRescueCheck()
                    }
                    return@withLock
                }

                sleepPausedByPolicy = false
                networkPausedByLoss = false
                isTunnelPaused = false
                settingsStore.saveSleepBatteryRuntimeState(targetPhase)
                acquireWakeLock()
                acquireWifiLockForTransition()
                updateNotification(
                    if (trigger == SleepResumeTrigger.SCREEN_ON) {
                        buildTunnelNotificationText()
                    } else {
                        "Восстановление VPN..."
                    }
                )
                noteSleepVpnResume(trigger)
                TunnelManager.resume()
                if (deviceInteractive) {
                    scheduleWakeRescueCheck()
                }
            }
        }
    }

    private fun handleSleepAutoResume(expectedDeadlineMs: Long) {
        serviceScope.launch {
            val settingsStore = SettingsStore(applicationContext)
            val runtime = settingsStore.sleepBatteryRuntimeState.first()
            if (isDeviceInteractive()) {
                resumeSleepPausedTunnelIfNeeded(SleepResumeTrigger.SCREEN_ON)
                return@launch
            }
            if (
                runtime.phase != SleepBatteryRuntimePhase.WAITING_TO_RESUME ||
                runtime.deadlineMs != expectedDeadlineMs
            ) {
                TunnelManager.noteSleepBatteryEvent(
                    "stale_timer_ignored",
                    "Устаревший таймер сна проигнорирован; состояние VPN не изменено.",
                )
                restoreNotificationAfterIgnoredSleepAlarm(runtime)
                return@launch
            }
            if (System.currentTimeMillis() < expectedDeadlineMs) {
                if (!scheduleSleepResumeAlarmAt(expectedDeadlineMs)) {
                    resumeAfterSleepAlarmFailure()
                    return@launch
                }
                showSleepResumeCountdown(expectedDeadlineMs)
                return@launch
            }
            resumeSleepPausedTunnelIfNeeded(SleepResumeTrigger.TIMER)
        }
    }

    private fun restoreNotificationAfterIgnoredSleepAlarm(
        runtime: SleepBatteryRuntimeState,
    ) {
        if (!TunnelManager.running.value && !isTunnelPaused) {
            // Просроченный PendingIntent не должен воскресить VPN, который
            // пользователь уже остановил.
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }
        val nowMs = System.currentTimeMillis()
        when {
            runtime.phase == SleepBatteryRuntimePhase.WAITING_TO_RESUME &&
                runtime.deadlineMs > nowMs -> showSleepResumeCountdown(runtime.deadlineMs)
            runtime.phase == SleepBatteryRuntimePhase.WAITING_TO_PAUSE &&
                runtime.deadlineMs > nowMs -> showSleepTimerNotification(
                title = "VPN включён · таймер сна",
                text = "Отключение через",
                deadlineWallMs = runtime.deadlineMs,
                actions = listOf(
                    TunnelNotificationAction(ACTION_SLEEP_PAUSE_NOW, "Отключить сейчас", 42),
                    TunnelNotificationAction(ACTION_SLEEP_KEEP_RUNNING, "Пропустить", 43),
                ),
            )
            runtime.phase == SleepBatteryRuntimePhase.PAUSED_UNTIL_SCREEN_ON -> {
                sleepTimerNotificationActive = false
                showSleepPausedNotification()
            }
            else -> {
                sleepTimerNotificationActive = false
                updateNotification(buildTunnelNotificationText())
            }
        }
    }

    private fun sleepResumeAlarmIntent(deadlineWallMs: Long = 0L): PendingIntent = PendingIntent.getForegroundService(
        this,
        SLEEP_RESUME_ALARM_REQUEST_CODE,
        Intent(this, TunnelService::class.java).apply {
            action = ACTION_SLEEP_AUTO_RESUME
            putExtra(EXTRA_SLEEP_RESUME_DEADLINE_MS, deadlineWallMs)
        },
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    private fun scheduleSleepResumeAlarmAt(deadlineWallMs: Long): Boolean {
        val remainingMs = (deadlineWallMs - System.currentTimeMillis()).coerceAtLeast(0L)
        return runCatching {
            val alarmManager = getSystemService(AlarmManager::class.java)
                ?: error("AlarmManager недоступен")
            val triggerAtElapsedMs = SystemClock.elapsedRealtime() + remainingMs
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S || alarmManager.canScheduleExactAlarms()) {
                alarmManager.setExactAndAllowWhileIdle(
                    AlarmManager.ELAPSED_REALTIME_WAKEUP,
                    triggerAtElapsedMs,
                    sleepResumeAlarmIntent(deadlineWallMs),
                )
            } else {
                // Без отдельного разрешения Android вправе сдвинуть такой
                // alarm. Для короткого таймера ниже есть локальный резерв.
                alarmManager.setAndAllowWhileIdle(
                    AlarmManager.ELAPSED_REALTIME_WAKEUP,
                    triggerAtElapsedMs,
                    sleepResumeAlarmIntent(deadlineWallMs),
                )
            }
            scheduleShortSleepResumeGuard(deadlineWallMs)
        }.onFailure { error ->
            TunnelManager.noteSleepBatteryEvent(
                "resume_alarm_failed",
                "Android не принял таймер включения VPN (${error.javaClass.simpleName}); восстанавливаем VPN сразу.",
                warning = true,
            )
        }.isSuccess
    }

    private fun resumeAfterSleepAlarmFailure() {
        resumeSleepPausedTunnelIfNeeded(SleepResumeTrigger.FAILSAFE)
    }

    private fun noteSleepVpnResume(trigger: SleepResumeTrigger) {
        when (trigger) {
            SleepResumeTrigger.SCREEN_ON -> TunnelManager.noteSleepVpnResumed()
            SleepResumeTrigger.TIMER -> TunnelManager.noteSleepVpnTimerResumed()
            SleepResumeTrigger.USER -> TunnelManager.noteSleepVpnUserResumed()
            SleepResumeTrigger.FAILSAFE -> TunnelManager.noteSleepVpnFailsafeResumed()
        }
    }

    private fun cancelSleepResumeAlarm() {
        getSystemService(AlarmManager::class.java).cancel(sleepResumeAlarmIntent())
    }

    private fun scheduleShortSleepResumeGuard(deadlineWallMs: Long) {
        sleepAutoResumeJob?.cancel()
        sleepAutoResumeJob = null
        releaseShortSleepResumeWakeLock()

        val nowMs = System.currentTimeMillis()
        val guardDurationMs = shortSleepResumeGuardDurationMs(deadlineWallMs, nowMs) ?: return
        val remainingMs = (deadlineWallMs - nowMs).coerceAtLeast(0L)
        val lock = (getSystemService(POWER_SERVICE) as PowerManager).newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "wdtt:short_sleep_resume",
        ).apply {
            setReferenceCounted(false)
            acquire(guardDurationMs)
        }
        shortSleepResumeWakeLock = lock
        sleepAutoResumeJob = serviceScope.launch {
            delay(remainingMs)
            handleSleepAutoResume(deadlineWallMs)
        }
    }

    private fun acquireShortSleepPauseGuard(deadlineWallMs: Long) {
        releaseShortSleepPauseWakeLock()
        val guardDurationMs = shortSleepResumeGuardDurationMs(
            deadlineWallMs = deadlineWallMs,
            nowMs = System.currentTimeMillis(),
        ) ?: return
        shortSleepPauseWakeLock = (getSystemService(POWER_SERVICE) as PowerManager).newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "wdtt:short_sleep_pause",
        ).apply {
            setReferenceCounted(false)
            acquire(guardDurationMs)
        }
    }

    private fun releaseShortSleepPauseWakeLock() {
        shortSleepPauseWakeLock?.let { lock ->
            runCatching {
                if (lock.isHeld) lock.release()
            }
        }
        shortSleepPauseWakeLock = null
    }

    private fun releaseShortSleepResumeWakeLock() {
        shortSleepResumeWakeLock?.let { lock ->
            runCatching {
                if (lock.isHeld) lock.release()
            }
        }
        shortSleepResumeWakeLock = null
    }

    private fun cancelSleepExecution() {
        sleepExecutionGeneration++
        sleepPauseJob?.cancel()
        sleepPauseJob = null
        releaseShortSleepPauseWakeLock()
        sleepAutoResumeJob?.cancel()
        sleepAutoResumeJob = null
        releaseShortSleepResumeWakeLock()
        cancelSleepResumeAlarm()
        sleepTimerNotificationActive = false
    }

    private suspend fun saveSleepRuntimeForCurrentScreen(
        phaseWhileScreenOff: SleepBatteryRuntimePhase,
        deadlineMs: Long = 0L,
    ) {
        val phase = if (lastKnownDeviceInteractive) {
            SleepBatteryRuntimePhase.IDLE
        } else {
            phaseWhileScreenOff
        }
        SettingsStore(applicationContext).saveSleepBatteryRuntimeState(
            phase = phase,
            deadlineMs = if (phase == SleepBatteryRuntimePhase.IDLE) 0L else deadlineMs,
        )
    }

    private fun showSleepResumeCountdown(deadlineWallMs: Long) {
        showSleepTimerNotification(
            title = "VPN выключен · таймер сна",
            text = "Включение через · интернет напрямую",
            deadlineWallMs = deadlineWallMs,
            actions = listOf(
                TunnelNotificationAction(ACTION_SLEEP_RESUME_NOW, "Включить сейчас", 44),
                TunnelNotificationAction(ACTION_SLEEP_KEEP_PAUSED, "Оставить выключенным", 45),
            ),
        )
    }

    private fun registerTrustedWifiStateReceiver() {
        if (trustedWifiStateReceiver != null) return
        trustedWifiStateReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                val runtimeState = TrustedWifiManager.state.value
                if (!trustedWifiWaiting && runtimeState.waiting) {
                    trustedWifiWaiting = true
                    trustedWifiWaitingSsid = runtimeState.ssid
                }
                if (!trustedWifiWaiting) return
                when (intent?.action) {
                    WifiManager.WIFI_STATE_CHANGED_ACTION -> {
                        val state = intent.getIntExtra(
                            WifiManager.EXTRA_WIFI_STATE,
                            WifiManager.WIFI_STATE_UNKNOWN
                        )
                        when (state) {
                            WifiManager.WIFI_STATE_DISABLING,
                            WifiManager.WIFI_STATE_DISABLED,
                            WifiManager.WIFI_STATE_UNKNOWN -> {
                                trustedWifiResumeNetworks.forgetWifi()
                                acquireTrustedWifiTransitionWakeLock()
                                keepTrustedWifiForeground("Ожидание рабочей сети")
                                scheduleTrustedWifiEvaluation(delayMs = 0L)
                                scheduleTrustedWifiResumeRetry()
                            }
                            else -> scheduleTrustedWifiEvaluation(TRUSTED_WIFI_ENTER_DELAY_MS)
                        }
                    }
                    WifiManager.NETWORK_STATE_CHANGED_ACTION -> {
                        keepTrustedWifiForeground()
                        // Сам broadcast не содержит стабильного Network-идентификатора:
                        // при быстрой смене двух Wi-Fi он может относиться уже к старой сети.
                        // Авторитетные lost/validated события придут через NetworkCallback.
                    }
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(WifiManager.WIFI_STATE_CHANGED_ACTION)
            addAction(WifiManager.NETWORK_STATE_CHANGED_ACTION)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(trustedWifiStateReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(trustedWifiStateReceiver, filter)
        }
    }

    private fun scheduleWakeRescueCheck() {
        if (!AMNEZIA_STYLE_RECOVERY || !TunnelManager.running.value || isTunnelPaused || TunnelManager.isCaptchaInProgress()) return
        val wakeStartedAt = System.currentTimeMillis()
        wakeRescueJob?.cancel()
        wakeRescueJob = TunnelManager.scope.launch(Dispatchers.Main) {
            delay(WAKE_RESCUE_GRACE_MS)
            if (!TunnelManager.running.value || isTunnelPaused || TunnelManager.isCaptchaInProgress()) return@launch
            val confirmedNetworkFailure = TunnelManager.hasConfirmedNetworkFailureSince(wakeStartedAt)
            val shouldReconnect = shouldReconnectTunnelAfterWake(
                activeWorkers = TunnelManager.activeWorkers.value,
                confirmedNetworkFailure = confirmedNetworkFailure,
            )
            if (TunnelManager.hasFreshTunnelActivitySince(wakeStartedAt)) {
                TunnelManager.noteWakeRescueHealthy()
            } else if (shouldReconnect) {
                TunnelManager.noteWakeRescueReconnect()
                updateNotification("Восстановление транспорта после сна...")
                TunnelManager.restartTransport(
                    reason = "[СОН] После пробуждения нет рабочих каналов или ответа на пользовательский трафик. Мягко переподключаем транспорт без пересоздания VPN.",
                    minIntervalMs = WAKE_RESCUE_GRACE_MS,
                    force = true,
                )
            } else {
                // Выход из сна сам по себе не является доказательством поломки:
                // Android и оператор могут на короткое время задержать вывод статистики.
                // Не перезапускаем ни native-транспорт, ни системный VPN-интерфейс.
                TunnelManager.noteWakeRescueDeferred()
            }
            updateNotification(buildTunnelNotificationText())
        }
    }

    // Таймерный режим обещает вернуть VPN ещё при выключенном экране. Одних
    // «Активных: N» для этого недостаточно: после сна они могут быть старыми.
    // Проверяем реальный ответ сервера и выполняем только одну мягкую попытку,
    // не пересоздавая системный VPN-интерфейс и не трогая здоровое idle-соединение.
    private fun scheduleTimerResumeTransportConfirmation() {
        cancelTimerResumeTransportConfirmation()
        val startedAtMs = System.currentTimeMillis()
        val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
        val lock = powerManager.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "wdtt:timer_resume_transport_confirmation",
        ).apply {
            setReferenceCounted(false)
            acquire(TIMER_RESUME_TRANSPORT_WAKE_LOCK_TIMEOUT_MS)
        }
        timerResumeTransportWakeLock = lock
        timerResumeTransportJob = serviceScope.launch {
            try {
                delay(TIMER_RESUME_TRANSPORT_CONFIRM_MS)
                if (!TunnelManager.running.value || isTunnelPaused || TunnelManager.isCaptchaInProgress()) return@launch
                if (TunnelManager.hasFreshTransportPathSince(startedAtMs)) {
                    TunnelManager.noteSleepTimerTransportHealthy()
                } else {
                    TunnelManager.noteSleepTimerTransportReconnect()
                    updateNotification("Восстановление транспорта после таймера...")
                    TunnelManager.restartTransport(
                        reason = "[СОН] После включения по таймеру сервер не ответил. Мягко переподключаем транспорт до включения экрана.",
                        minIntervalMs = TIMER_RESUME_TRANSPORT_CONFIRM_MS,
                        force = true,
                    )
                }
            } finally {
                releaseTimerResumeTransportWakeLock()
                timerResumeTransportJob = null
                updateNotification(buildTunnelNotificationText())
            }
        }
    }

    private fun cancelTimerResumeTransportConfirmation() {
        timerResumeTransportJob?.cancel()
        timerResumeTransportJob = null
        releaseTimerResumeTransportWakeLock()
    }

    private fun releaseTimerResumeTransportWakeLock() {
        timerResumeTransportWakeLock?.let { lock ->
            runCatching { if (lock.isHeld) lock.release() }
        }
        timerResumeTransportWakeLock = null
    }

    private suspend fun startOrWaitForTrustedWifi(
        params: TunnelParams,
        restoreSessionTraffic: Boolean = false,
    ) {
        val store = SettingsStore(applicationContext)
        val enabled = store.trustedWifiEnabled.first()
        val trustedSsids = store.trustedWifiSsids.first().toSet()
        val wifi = readConnectedWifiState(applicationContext)
        if (isWdttAlwaysOnVpn(applicationContext) && wifi.ssidAvailable && wifi.ssid in trustedSsids) {
            startTunnel(params, restoreSessionTraffic = restoreSessionTraffic)
            TunnelManager.scope.launch {
                delay(300L)
                TunnelManager.reportConnectionIssue(
                    "Доверенная сеть не применена",
                    "Для WDTT Plus включён системный режим «Всегда включённый VPN». Отключите его в настройках Android, если хотите использовать сети без VPN.",
                    isError = false
                )
            }
            return
        }
        if (
            decideTrustedWifiTransition(
                enabled = enabled,
                tunnelRunning = true,
                waiting = false,
                wifi = wifi,
                trustedSsids = trustedSsids
            ) == TrustedWifiTransition.EnterWaiting
        ) {
            lastStartParams = params
            enterTrustedWifiWaiting(wifi.ssid)
        } else {
            startTunnel(params, restoreSessionTraffic = restoreSessionTraffic)
        }
    }

    private fun setupTrustedWifiMonitoring() {
        val manager = connectivityManager
            ?: (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager).also {
                connectivityManager = it
            }
        trustedWifiNetworkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (trustedWifiWaiting) {
                    scheduleTrustedWifiEvaluation(delayMs = 0L)
                } else {
                    scheduleTrustedWifiEvaluation(TRUSTED_WIFI_ENTER_DELAY_MS)
                }
            }

            override fun onLost(network: Network) {
                if (trustedWifiWaiting) {
                    trustedWifiResumeNetworks.lost(network)
                    acquireTrustedWifiTransitionWakeLock()
                    scheduleTrustedWifiEvaluation(delayMs = 0L)
                    scheduleTrustedWifiResumeRetry()
                } else {
                    scheduleTrustedWifiEvaluation(TRUSTED_WIFI_EXIT_DELAY_MS)
                }
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                if (trustedWifiWaiting) {
                    scheduleTrustedWifiEvaluation(delayMs = 0L)
                } else {
                    scheduleTrustedWifiEvaluation(TRUSTED_WIFI_ENTER_DELAY_MS)
                }
            }
        }
        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        runCatching { manager.registerNetworkCallback(request, trustedWifiNetworkCallback!!) }
            .onFailure { Log.w("TunnelService", "Не удалось включить наблюдение доверенных Wi-Fi: ${it.message}") }

        val store = SettingsStore(applicationContext)
        trustedWifiSettingsJob = TunnelManager.scope.launch {
            combine(store.trustedWifiEnabled, store.trustedWifiSsids) { enabled, ssids ->
                enabled to ssids
            }.collect { (enabled, _) ->
                if (!enabled && trustedWifiWaiting) {
                    withContext(Dispatchers.Main) {
                        stopTunnel(TunnelStopReason.User)
                    }
                } else {
                    scheduleTrustedWifiEvaluation(delayMs = 0L)
                }
            }
        }
    }

    private fun scheduleTrustedWifiEvaluation(delayMs: Long) {
        val safeDelayMs = delayMs.coerceAtLeast(0L)
        synchronized(trustedWifiEvaluationScheduleLock) {
            trustedWifiPendingEvaluationDelayMs = trustedWifiPendingEvaluationDelayMs
                ?.let { current -> minOf(current, safeDelayMs) }
                ?: safeDelayMs
            if (trustedWifiEvaluationJob?.isActive == true) return
            trustedWifiEvaluationJob = TunnelManager.scope.launch {
                runTrustedWifiEvaluationLoop()
            }
        }
    }

    private suspend fun runTrustedWifiEvaluationLoop() {
        while (true) {
            val delayMs = synchronized(trustedWifiEvaluationScheduleLock) {
                val pending = trustedWifiPendingEvaluationDelayMs
                if (pending == null) {
                    trustedWifiEvaluationJob = null
                    return
                }
                trustedWifiPendingEvaluationDelayMs = null
                pending
            }
            if (delayMs > 0L) delay(delayMs)
            evaluateTrustedWifiState()
        }
    }

    private fun cancelTrustedWifiEvaluations() {
        synchronized(trustedWifiEvaluationScheduleLock) {
            trustedWifiPendingEvaluationDelayMs = null
            trustedWifiEvaluationJob?.cancel()
            trustedWifiEvaluationJob = null
        }
    }

    private fun scheduleTrustedWifiResumeRetry() {
        synchronized(trustedWifiResumeRetryLock) {
            if (trustedWifiResumeRetryJob?.isActive == true) return
            val plan = trustedWifiResumeRetryPlan(trustedWifiResumeRetryCount)
            if (plan.keepCpuAwake) {
                acquireTrustedWifiTransitionWakeLock()
            } else {
                releaseTrustedWifiTransitionWakeLock()
            }
            trustedWifiResumeRetryJob = TunnelManager.scope.launch {
                delay(plan.delayMs)
                val shouldEvaluate = synchronized(trustedWifiResumeRetryLock) {
                    trustedWifiResumeRetryJob = null
                    if (trustedWifiWaiting) {
                        trustedWifiResumeRetryCount += 1
                        true
                    } else {
                        false
                    }
                }
                if (shouldEvaluate) evaluateTrustedWifiState()
            }
        }
    }

    private fun cancelTrustedWifiResumeRetry(resetCount: Boolean) {
        synchronized(trustedWifiResumeRetryLock) {
            trustedWifiResumeRetryJob?.cancel()
            trustedWifiResumeRetryJob = null
            if (resetCount) trustedWifiResumeRetryCount = 0
        }
    }

    private fun isTrustedWifiResumeRetryScheduled(): Boolean =
        synchronized(trustedWifiResumeRetryLock) {
            trustedWifiResumeRetryJob?.isActive == true
        }

    private suspend fun evaluateTrustedWifiState() {
        if (DeployManager.isDeploying.value) return
        val store = SettingsStore(applicationContext)
        val enabled = store.trustedWifiEnabled.first()
        val trustedSsids = store.trustedWifiSsids.first().toSet()
        if (!enabled) return

        val wifi = readConnectedWifiState(applicationContext)
        if (isWdttAlwaysOnVpn(applicationContext) && !trustedWifiWaiting) {
            if (wifi.ssidAvailable && wifi.ssid in trustedSsids && TunnelManager.running.value) {
                TunnelManager.reportConnectionIssue(
                    "Доверенная сеть не применена",
                    "Системный режим «Всегда включённый VPN» несовместим с автоматическим отключением VPN.",
                    isError = false
                )
            }
            return
        }
        when (
            decideTrustedWifiTransition(
                enabled = enabled,
                tunnelRunning = TunnelManager.running.value,
                waiting = trustedWifiWaiting,
                wifi = wifi,
                trustedSsids = trustedSsids
            )
        ) {
            TrustedWifiTransition.EnterWaiting -> enterTrustedWifiWaiting(wifi.ssid)
            TrustedWifiTransition.ResumeVpn -> resumeFromTrustedWifiWaiting()
            TrustedWifiTransition.None -> {
                if (trustedWifiWaiting && wifi.accessProblem != null) {
                    val status = when (wifi.accessProblem) {
                        TrustedWifiAccessProblem.ForegroundPermission,
                        TrustedWifiAccessProblem.BackgroundPermission ->
                            "Нужен доступ к имени Wi-Fi. Откройте настройки доверенных сетей."
                        TrustedWifiAccessProblem.LocationDisabled ->
                            "Включите определение местоположения, чтобы распознать Wi-Fi."
                    }
                    TrustedWifiManager.setStatus(status)
                    withContext(Dispatchers.Main) { updateNotification(status) }
                } else if (trustedWifiWaiting && wifi.ssidAvailable && wifi.ssid in trustedSsids) {
                    trustedWifiWaitingSsid = wifi.ssid
                    TrustedWifiManager.setWaiting(wifi.ssid)
                    store.saveTrustedWifiWaiting(true, wifi.ssid)
                    withContext(Dispatchers.Main) { updateTrustedWifiNotification() }
                    cancelTrustedWifiResumeRetry(resetCount = true)
                    releaseTrustedWifiTransitionWakeLock()
                }
                if (trustedWifiWaiting && !isTrustedWifiResumeRetryScheduled()) {
                    releaseTrustedWifiTransitionWakeLock()
                }
            }
        }
    }

    private suspend fun enterTrustedWifiWaiting(ssid: String) {
        trustedWifiTransitionMutex.withLock {
            if (trustedWifiWaiting) return
            val cleanSsid = sanitizeTrustedWifiSsid(ssid)
            if (cleanSsid.isBlank()) return

            val params = lastStartParams ?: buildTunnelParamsFromSettings(applicationContext) ?: return
            lastStartParams = params
            cancelSleepExecution()
            sleepPausedByPolicy = false
            SettingsStore(applicationContext).saveSleepBatteryRuntimeState(
                SleepBatteryRuntimePhase.IDLE,
            )
            trustedWifiWaiting = true
            trustedWifiWaitingSsid = cleanSsid
            isTunnelPaused = false
            networkPausedByLoss = false
            trustedWifiResumeNetworks.forgetWifi()
            networkChangeJob?.cancel()
            stableNetworkWasLost = false
            wakeRescueJob?.cancel()
            activeProfileRefreshJob?.cancel()
            activeProfileRefreshJob = null
            cancelTrustedWifiResumeRetry(resetCount = true)

            // Авто-WebView может ещё решать капчу, когда нативный процесс уже
            // останавливается. Завершаем его до закрытия stdin клиента.
            CaptchaWebViewManager.onTunnelStop()
            TunnelManager.stopAndWait(TunnelStopReason.TrustedWifi)
            WireGuardHelper(applicationContext).stopTunnel()
            TunnelManager.noteTrustedWifiEvent(
                "waiting_enter",
                "Подключена доверенная сеть — VPN остановлен и ждёт выхода из неё."
            )
            TrustedWifiManager.setWaiting(cleanSsid)
            SettingsStore(applicationContext).saveTrustedWifiWaiting(true, cleanSsid)
            withContext(Dispatchers.Main) {
                releaseTrustedWifiTransitionWakeLock()
                releaseWakeLock()
                releaseWifiLock()
                startNotificationProfileWatcher()
                startStatsUpdater()
                updateTrustedWifiNotification()
                VpnWidgetProvider.updateAllWidgets(applicationContext)
            }
        }
    }

    private suspend fun resumeFromTrustedWifiWaiting() {
        trustedWifiTransitionMutex.withLock {
            if (!trustedWifiWaiting) return
            if (!hasUsableRealNetworkForTrustedWifiResume()) {
                val status = "Ожидание рабочей сети"
                TunnelManager.noteTrustedWifiEvent(
                    "resume_wait_network",
                    "Wi-Fi покинута, но Android ещё не подтвердил рабочую сеть; повторяем проверку."
                )
                TrustedWifiManager.setStatus(status)
                withContext(Dispatchers.Main) {
                    keepTrustedWifiForeground(status)
                    VpnWidgetProvider.updateAllWidgets(applicationContext)
                }
                scheduleTrustedWifiResumeRetry()
                return
            }
            if (android.net.VpnService.prepare(applicationContext) != null) {
                val status = "VPN-разрешение недоступно. Откройте WDTT Plus для восстановления."
                releaseTrustedWifiTransitionWakeLock()
                TunnelManager.noteTrustedWifiEvent(
                    "resume_permission",
                    "Android не дал повторно занять VPN-слот; требуется открыть приложение.",
                    warning = true
                )
                TrustedWifiManager.setStatus(status)
                withContext(Dispatchers.Main) { updateNotification(status) }
                return
            }

            val params = lastStartParams ?: buildTunnelParamsFromSettings(applicationContext)
            if (params == null) {
                val status = "Не удалось прочитать профиль VPN. Откройте WDTT Plus."
                releaseTrustedWifiTransitionWakeLock()
                TunnelManager.noteTrustedWifiEvent(
                    "resume_profile",
                    "Не удалось прочитать профиль для автоматического запуска.",
                    warning = true
                )
                TrustedWifiManager.setStatus(status)
                withContext(Dispatchers.Main) { updateNotification(status) }
                return
            }

            val access = AccessLifecycleCoordinator.prepareStart(
                applicationContext,
                params.profileIndex,
            )
            if (access is AccessStartDecision.Denied) {
                withContext(Dispatchers.Main) {
                    reportAccessDenied(access.status)
                    stopTunnel(TunnelStopReason.AccessExpired)
                }
                return
            }

            val refreshedParams = buildTunnelParamsFromSettings(
                applicationContext,
                params.profileIndex,
            )
            if (refreshedParams == null) {
                val status = "Не удалось прочитать обновлённый профиль VPN. Откройте WDTT Plus."
                releaseTrustedWifiTransitionWakeLock()
                TunnelManager.noteTrustedWifiEvent(
                    "resume_profile_refresh",
                    "Не удалось повторно прочитать профиль после проверки перед запуском.",
                    warning = true,
                )
                TrustedWifiManager.setStatus(status)
                withContext(Dispatchers.Main) { updateNotification(status) }
                return
            }
            lastStartParams = refreshedParams

            withContext(Dispatchers.Main) {
                acquireTrustedWifiTransitionWakeLock()
                Log.i("TunnelService", "Доверенная Wi-Fi покинута, запускаем VPN на рабочей сети")
                // startTunnel синхронно включает защитный resumeInProgress до снятия waiting.
                // Поэтому очередной сетевой callback уже не может оставить сервис между
                // состояниями: без VPN, без ожидания и с удалённым уведомлением.
                startTunnel(refreshedParams, fromTrustedWifiResume = true)
                VpnWidgetProvider.updateAllWidgets(applicationContext)
            }
        }
    }

    private fun updateTrustedWifiNotification() {
        keepTrustedWifiForeground()
    }

    private fun reportAccessDenied(status: AccessLifecycleStatus) {
        val title = status.title.ifBlank { "Профиль временно недоступен" }
        val message = status.message.ifBlank {
            "Откройте вкладку «Туннель», чтобы проверить доступные действия."
        }
        TunnelManager.reportConnectionIssue(
            title,
            message,
            kind = ConnectionIssueKind.ACCESS,
        )
        TunnelManager.noteAccessLifecycleEvent(
            key = "start_denied",
            message = title,
            warning = true,
        )
    }

    private fun keepTrustedWifiForeground(statusOverride: String? = null) {
        val networkName = trustedWifiWaitingSsid.ifBlank { "доверенная Wi-Fi" }
        val text = statusOverride ?: "VPN выключен в сети «$networkName» · ожидание выхода"
        val title = notificationProfileTitle
        lastNotificationTitle = title
        lastNotificationText = text
        startPersistentForeground(createNotification(text))
    }

    private fun setupNetworkCallback() {
        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        activeNetworks.clear()
        trustedWifiResumeNetworks.clear()
        
        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                super.onAvailable(network)
                if (trustedWifiWaiting) {
                    scheduleTrustedWifiEvaluation(TRUSTED_WIFI_EXIT_DELAY_MS)
                }
                val wasEmpty = activeNetworks.isEmpty()
                activeNetworks.add(network)
                if (AMNEZIA_STYLE_RECOVERY) {
                    if (shouldScheduleAvailableNetworkHandover(
                            previousNetworkWasLost = stableNetworkWasLost,
                            availableRealNetworkCount = activeNetworks.size,
                        )
                    ) {
                        scheduleUnderlyingNetworkReconnect(
                            "Android обнаружил доступную сеть после потери прежней"
                        )
                    }
                    return
                }
                if (wasEmpty) {
                    if (networkPausedByLoss) {
                        scheduleResumeAfterNetworkReturn()
                    } else {
                        scheduleNetworkSettleCheck("сеть появилась", NETWORK_RETURN_SETTLE_MS, minSpacingMs = 0L)
                    }
                } else {
                    scheduleNetworkSettleCheck("добавлена ещё одна сеть", NETWORK_CHANGE_SETTLE_MS)
                }
            }

            override fun onLost(network: Network) {
                super.onLost(network)
                val networkLostAt = System.currentTimeMillis()
                activeNetworks.remove(network)
                trustedWifiResumeNetworks.lost(network)
                if (trustedWifiWaiting) {
                    acquireTrustedWifiTransitionWakeLock()
                    scheduleTrustedWifiEvaluation(delayMs = 0L)
                    scheduleTrustedWifiResumeRetry()
                }
                if (AMNEZIA_STYLE_RECOVERY) {
                    val lostCurrentValidatedNetwork = lastValidatedNetwork == network
                    val lostPreviousHandoverNetwork = handoverPreviousNetwork == network
                    if (lostPreviousHandoverNetwork) {
                        handoverPreviousNetwork = null
                    }
                    if (lostCurrentValidatedNetwork) {
                        lastValidatedNetwork = null
                        // Другая сеть могла уже прийти через onAvailable, но ещё
                        // не пройти общую проверку интернета Android. Это штатно
                        // для операторских сетей с ограниченным списком ресурсов.
                    }
                    val shouldTrackLoss = shouldTrackUnderlyingNetworkLoss(
                        tunnelRunning = TunnelManager.running.value,
                        tunnelPaused = isTunnelPaused,
                        trustedWifiWaiting = trustedWifiWaiting,
                    ) && !sleepPausedByPolicy && requestedStopReason == null
                    if (lostCurrentValidatedNetwork || lostPreviousHandoverNetwork) {
                        stableNetworkWasLost = shouldTrackLoss
                    }
                    if (activeNetworks.isEmpty() && shouldTrackLoss) {
                        stableNetworkWasLost = true
                        TunnelManager.noteUnderlyingNetworkChanged(
                            "сеть временно пропала",
                            graceMs = NETWORK_LOSS_GRACE_MS,
                            replaceGrace = true
                        )
                        updateNotification("Ожидание сети")
                    } else if (
                        (lostCurrentValidatedNetwork || lostPreviousHandoverNetwork) &&
                        shouldScheduleAvailableNetworkHandover(
                            previousNetworkWasLost = stableNetworkWasLost,
                            availableRealNetworkCount = activeNetworks.size,
                        )
                    ) {
                        scheduleUnderlyingNetworkReconnect(
                            reason = "Android переключает VPN на другую доступную сеть",
                            evidenceSinceMs = networkLostAt,
                        )
                    }
                    return
                }
                if (activeNetworks.isEmpty() && TunnelManager.running.value && !isTunnelPaused) {
                    scheduleNetworkLossPause()
                } else if (activeNetworks.isNotEmpty()) {
                    scheduleNetworkSettleCheck("одна из сетей отключилась", NETWORK_CHANGE_SETTLE_MS)
                }
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                super.onCapabilitiesChanged(network, networkCapabilities)
                val usableRealNetwork =
                    networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                        networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                        networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                trustedWifiResumeNetworks.update(
                    network = network,
                    internetCapable = networkCapabilities.hasCapability(
                        NetworkCapabilities.NET_CAPABILITY_INTERNET,
                    ) && networkCapabilities.hasCapability(
                        NetworkCapabilities.NET_CAPABILITY_NOT_VPN,
                    ),
                    validated = usableRealNetwork,
                    wifi = networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                )
                if (trustedWifiWaiting) {
                    if (usableRealNetwork) {
                        acquireTrustedWifiTransitionWakeLock()
                        scheduleTrustedWifiEvaluation(delayMs = 0L)
                    } else {
                        scheduleTrustedWifiEvaluation(TRUSTED_WIFI_EXIT_DELAY_MS)
                    }
                }
                if (AMNEZIA_STYLE_RECOVERY) {
                    handleStableNetworkCapabilities(network, networkCapabilities)
                    return
                }
                if (
                    activeNetworks.contains(network) &&
                    networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                    networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                ) {
                    scheduleNetworkSettleCheck("параметры сети изменились", NETWORK_CHANGE_SETTLE_MS, minSpacingMs = NETWORK_CHANGE_SETTLE_MS)
                }
            }
        }

        // ВАЖНО: Слушаем только реальные (не VPN) сети с доступом в интернет.
        // Иначе интерфейс VPN (tun0) считается активной сетью, и при "Режиме полёта" activeNetworks не падает до 0.
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
            
        connectivityManager?.registerNetworkCallback(request, networkCallback!!)
    }

    private fun handleStableNetworkCapabilities(network: Network, networkCapabilities: NetworkCapabilities) {
        val isUsableRealNetwork = networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
            networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        if (!isUsableRealNetwork) return

        activeNetworks.add(network)
        val previous = lastValidatedNetwork
        val transition = classifyValidatedNetworkTransition(
            previousNetwork = previous,
            currentNetwork = network,
            previousNetworkWasLost = stableNetworkWasLost,
        )
        lastValidatedNetwork = network
        when (transition) {
            ValidatedNetworkTransition.HANDOVER ->
                scheduleUnderlyingNetworkReconnect(
                    reason = "Android подтвердил новую рабочую сеть",
                    previousNetwork = previous,
                )
            ValidatedNetworkTransition.INITIAL -> if (TunnelManager.running.value) {
                TunnelManager.noteUnderlyingNetworkChanged(
                    "Android подтвердил рабочую сеть",
                    graceMs = transportRecoveryPolicy(
                        lastStartParams?.managedConfigFirstStart == true
                    ).networkSettleDelayMs,
                    replaceGrace = false
                )
            }
            ValidatedNetworkTransition.UNCHANGED -> Unit
        }
    }

    private fun scheduleUnderlyingNetworkReconnect(
        reason: String,
        previousNetwork: Network? = null,
        evidenceSinceMs: Long = System.currentTimeMillis(),
    ) {
        val scheduledAt = System.currentTimeMillis()
        val interactiveAtSchedule = isDeviceInteractive()

        if (
            !shouldTrackUnderlyingNetworkLoss(
                tunnelRunning = TunnelManager.running.value,
                tunnelPaused = isTunnelPaused,
                trustedWifiWaiting = trustedWifiWaiting,
            ) || sleepPausedByPolicy || requestedStopReason != null
        ) {
            stableNetworkWasLost = false
            return
        }
        val recoveryPolicy = transportRecoveryPolicy(
            lastStartParams?.managedConfigFirstStart == true
        )
        if (!shouldStartUnderlyingNetworkCheck(
                checkPending = stableNetworkReconnectPending,
                currentJobActive = networkChangeJob?.isActive == true,
            )
        ) {
            stableNetworkEvidenceSinceMs = updatedUnderlyingNetworkEvidenceSince(
                currentEvidenceSinceMs = stableNetworkEvidenceSinceMs,
                networkEventAtMs = evidenceSinceMs,
            )
            if (handoverPreviousNetwork == null && previousNetwork != null) {
                handoverPreviousNetwork = previousNetwork
            }
            Log.d("TunnelService", "$reason; проверка handover уже запланирована без продления ожидания")
            return
        }
        // Событие потери обработано этой проверкой. Последующие capability-
        // callback не должны создавать циклы или сдвигать её дедлайн.
        stableNetworkWasLost = false
        stableNetworkReconnectPending = true
        stableNetworkEvidenceSinceMs = evidenceSinceMs
        handoverPreviousNetwork = previousNetwork
        lastNetworkChangeTime = scheduledAt
        TunnelManager.noteUnderlyingNetworkChanged(
            reason,
            graceMs = recoveryPolicy.networkSettleDelayMs + 30_000L,
            replaceGrace = true
        )
        networkChangeJob?.cancel()
        networkChangeJob = TunnelManager.scope.launch(Dispatchers.Main) {
            try {
                Log.d("TunnelService", "$reason, ждём короткую стабилизацию перед reconnect")
                delay(recoveryPolicy.networkSettleDelayMs)
                if (!shouldRunUnderlyingNetworkReconnect(
                        tunnelRunning = TunnelManager.running.value,
                        tunnelPaused = isTunnelPaused,
                        trustedWifiWaiting = trustedWifiWaiting,
                        sleepPausedByPolicy = sleepPausedByPolicy,
                        stopRequested = requestedStopReason != null,
                        interactiveAtSchedule = interactiveAtSchedule,
                        deviceInteractive = isDeviceInteractive(),
                        wakeRecoveryGraceActive = TunnelManager.isWakeRecoveryGraceActive(),
                        realNetworkAvailable = hasAnyRealNetwork(),
                        captchaActive = TunnelManager.isCaptchaInProgress(),
                    )
                ) {
                    Log.d("TunnelService", "Пропускаем reconnect: состояние VPN уже изменилось")
                    return@launch
                }

                val sinceLastReconnect = System.currentTimeMillis() - lastStableNetworkReconnectAt
                if (sinceLastReconnect < recoveryPolicy.reconnectMinIntervalMs) {
                    Log.d("TunnelService", "Пропускаем reconnect: недавний reconnect уже был")
                    return@launch
                }
                if (TunnelManager.hasFreshTunnelActivitySince(stableNetworkEvidenceSinceMs)) {
                    stableNetworkWasLost = false
                    Log.d("TunnelService", "Пропускаем reconnect: транспорт уже получает данные на новой сети")
                    return@launch
                }
                val restarted = TunnelManager.restartTransport(
                    reason = "[СЕТЬ] Android переключил underlying-сеть. Мягко переподключаю транспорт.",
                    minIntervalMs = recoveryPolicy.reconnectMinIntervalMs,
                    force = recoveryPolicy.forceRestart,
                )
                if (restarted) {
                    stableNetworkWasLost = false
                    stableNetworkEvidenceSinceMs = 0L
                    handoverPreviousNetwork = null
                    lastStableNetworkReconnectAt = System.currentTimeMillis()
                    updateNotification("Переподключение после смены сети...")
                }
            } finally {
                stableNetworkReconnectPending = false
            }
        }
    }
    
    @Suppress("DEPRECATION")
    private fun hasAnyRealNetwork(): Boolean {
        val cm = connectivityManager ?: return activeNetworks.isNotEmpty()
        if (activeNetworks.isNotEmpty()) return true
        return cm.allNetworks.any { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@any false
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        }
    }

    @Suppress("DEPRECATION")
    private fun hasValidatedRealNetwork(): Boolean {
        val cm = connectivityManager ?: return false
        return cm.allNetworks.any { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@any false
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        }
    }

    private fun isDeviceInteractive(): Boolean =
        (getSystemService(POWER_SERVICE) as PowerManager).isInteractive

    private fun observeDeviceInteractiveState(interactive: Boolean) {
        if (lastKnownDeviceInteractive == interactive) return
        lastKnownDeviceInteractive = interactive
        if (interactive) {
            TunnelManager.noteDeviceWakeStarted()
        } else {
            TunnelManager.noteDeviceSleepStarted()
            // Low-latency Wi-Fi lock нужен только для короткого запуска.
            // При гашении экрана его нельзя оставлять до конца VPN-сессии.
            releaseWifiLock()
        }
    }

    @Suppress("DEPRECATION")
    private fun hasUsableRealNetworkForTrustedWifiResume(): Boolean {
        if (trustedWifiResumeNetworks.hasUsableNetwork()) return true
        val cm = connectivityManager ?: return false
        return cm.allNetworks.any { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@any false
            isUsableTrustedWifiResumeNetwork(
                internetCapable = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN),
                validated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
                wifi = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI),
            )
        }
    }

    private fun scheduleNetworkSettleCheck(
        reason: String,
        settleMs: Long,
        minSpacingMs: Long = 30_000L
    ) {
        val now = System.currentTimeMillis()
        if (now - lastNetworkChangeTime < minSpacingMs) return
        lastNetworkChangeTime = now

        if (!TunnelManager.running.value || isTunnelPaused) return
        TunnelManager.noteUnderlyingNetworkChanged(reason, graceMs = settleMs, replaceGrace = true)
        networkChangeJob?.cancel()
        networkChangeJob = TunnelManager.scope.launch(Dispatchers.Main) {
            Log.d("TunnelService", "Сеть изменилась ($reason), ждём стабилизации без перезапуска")
            delay(settleMs)
            if (lastNetworkChangeTime != now) return@launch
            if (!TunnelManager.running.value || isTunnelPaused || !hasAnyRealNetwork()) return@launch
            if (TunnelManager.shouldSoftRestartAfterNetworkSettled(settleMs = settleMs, freshActiveMs = 60_000L)) {
                TunnelManager.restartTransport(
                    reason = "[СЕТЬ] После ожидания сети нет свежей активности. Мягко перезапускаю только транспорт.",
                    minIntervalMs = 3 * 60_000L
                )
            }
        }
    }

    private fun scheduleNetworkLossPause() {
        val now = System.currentTimeMillis()
        lastNetworkChangeTime = now

        if (!TunnelManager.running.value || isTunnelPaused) return
        TunnelManager.noteUnderlyingNetworkChanged(
            "сеть временно пропала",
            graceMs = NETWORK_LOSS_GRACE_MS + NETWORK_RETURN_SETTLE_MS,
            replaceGrace = true
        )
        networkChangeJob?.cancel()
        networkChangeJob = TunnelManager.scope.launch(Dispatchers.Main) {
            Log.d("TunnelService", "Сеть потеряна, ждём: короткие провалы не трогаем")
            delay(NETWORK_LOSS_GRACE_MS)
            if (lastNetworkChangeTime != now) return@launch
            if (!TunnelManager.running.value || isTunnelPaused || hasAnyRealNetwork()) return@launch
            isTunnelPaused = true
            networkPausedByLoss = true
            Log.d("TunnelService", "Сети долго нет, приостанавливаем транспорт без переподключений к VK")
            TunnelManager.pause()
            updateNotification("Ожидание сети")
        }
    }

    private fun scheduleResumeAfterNetworkReturn() {
        if (
            !shouldResumeVpnAfterNetworkReturn(
                networkPausedByLoss = networkPausedByLoss,
                sleepPausedByPolicy = sleepPausedByPolicy,
                tunnelRunning = TunnelManager.running.value,
                usableNetworkAvailable = true,
            )
        ) return
        val now = System.currentTimeMillis()
        lastNetworkChangeTime = now
        TunnelManager.noteUnderlyingNetworkChanged("сеть вернулась", graceMs = NETWORK_RETURN_SETTLE_MS, replaceGrace = true)
        networkChangeJob?.cancel()
        networkChangeJob = TunnelManager.scope.launch(Dispatchers.Main) {
            Log.d("TunnelService", "Сеть появилась, ждём стабилизации перед возобновлением")
            delay(NETWORK_RETURN_SETTLE_MS)
            if (lastNetworkChangeTime != now) return@launch
            if (!shouldResumeVpnAfterNetworkReturn(
                    networkPausedByLoss = networkPausedByLoss,
                    sleepPausedByPolicy = sleepPausedByPolicy,
                    tunnelRunning = TunnelManager.running.value,
                    usableNetworkAvailable = hasAnyRealNetwork(),
                )
            ) return@launch
            networkPausedByLoss = false
            isTunnelPaused = false
            TunnelManager.resume()
            updateNotification(buildTunnelNotificationText())
        }
    }

    private fun sanitizeCaptchaMode(mode: String?): String {
        return when (mode?.lowercase()) {
            "auto" -> "auto"
            "rjs" -> "rjs"
            "wv" -> "wv"
            else -> "auto"
        }
    }

    /**
     * CPU не удерживается всю VPN-сессию. Lock нужен лишь чтобы безопасно
     * завершить запуск, восстановление или деплой; после таймаута Android
     * снова может перевести телефон в глубокий сон.
     */
    private fun acquireWakeLock(timeoutMs: Long = TUNNEL_TRANSITION_WAKE_LOCK_TIMEOUT_MS) {
        releaseWakeLock()
        val pm = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "wdtt:tunnel_cpu"
        ).apply {
            setReferenceCounted(false)
            acquire(timeoutMs)
        }
    }

    @Synchronized
    private fun acquireTrustedWifiTransitionWakeLock() {
        val lock = trustedWifiTransitionWakeLock ?: run {
            val pm = getSystemService(POWER_SERVICE) as PowerManager
            pm.newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK,
                "wdtt:trusted_wifi_transition"
            ).apply {
                setReferenceCounted(false)
                trustedWifiTransitionWakeLock = this
            }
        }
        runCatching {
            if (!lock.isHeld) {
                lock.acquire(TRUSTED_WIFI_TRANSITION_WAKE_LOCK_TIMEOUT_MS)
            }
        }.onFailure {
            Log.w("TunnelService", "Не удалось удержать CPU для выхода из доверенной Wi-Fi: ${it.message}")
        }
    }

    @Synchronized
    private fun releaseTrustedWifiTransitionWakeLock() {
        trustedWifiTransitionWakeLock?.let { lock ->
            runCatching {
                if (lock.isHeld) lock.release()
            }
        }
        trustedWifiTransitionWakeLock = null
    }

    @Suppress("DEPRECATION")
    private fun acquireWifiLockForTransition() {
        if (wifiLock?.isHeld != true) {
            val wm = applicationContext.getSystemService(WIFI_SERVICE) as WifiManager

            // Не держим low-latency радиомодуль всю сессию VPN. Он даёт
            // максимум пользы в коротком окне начального подключения.
            val mode = if (Build.VERSION.SDK_INT >= 29) {
                WifiManager.WIFI_MODE_FULL_LOW_LATENCY
            } else {
                WifiManager.WIFI_MODE_FULL_HIGH_PERF
            }

            wifiLock = wm.createWifiLock(mode, "wdtt:wifi_transition").apply {
                setReferenceCounted(false)
                acquire()
            }
        }
        wifiLockReleaseJob?.cancel()
        wifiLockReleaseJob = serviceScope.launch {
            delay(WIFI_TRANSITION_LOCK_TIMEOUT_MS)
            releaseWifiLock()
        }
    }

    private fun releaseWakeLock() {
        if (wakeLock?.isHeld == true) {
            wakeLock?.release()
        }
        wakeLock = null
    }

    private fun releaseWifiLock() {
        wifiLockReleaseJob?.cancel()
        wifiLockReleaseJob = null
        if (wifiLock?.isHeld == true) {
            wifiLock?.release()
        }
        wifiLock = null
    }

    private fun releaseTransitionLocksAfterTunnelStart() {
        if (wakeLock?.isHeld != true && wifiLock?.isHeld != true) return
        // running означает, что Android VPN-интерфейс и нативный транспорт уже
        // созданы. Дальнейшая доставка пакетов идёт через сокеты и foreground
        // service, без постоянного удержания CPU или Wi-Fi радиомодуля.
        releaseWakeLock()
        releaseWifiLock()
        updateNotification(buildTunnelNotificationText())
    }

    private fun startStatsUpdater() {
        updateJob?.cancel()
        updateJob = TunnelManager.scope.launch(Dispatchers.Main) {
            delay(1000)
            while (isActive) {
                if (
                    shouldYieldVpnSlot(
                        vpnSlotYieldRequested = TunnelManager.vpnSlotYieldRequested.value,
                        tunnelRunning = TunnelManager.running.value,
                        stopRequested = requestedStopReason != null,
                    )
                ) {
                    Log.w(
                        "TunnelService",
                        "Внешняя остановка VPN подтверждена; WDTT Plus не будет повторно занимать VPN-слот."
                    )
                    stopTunnel(TunnelStopReason.VpnStoppedExternally)
                    break
                }
                if (trustedWifiResumeInProgress) {
                    when {
                        TunnelManager.running.value -> {
                            trustedWifiResumeInProgress = false
                            trustedWifiResumeStartedAt = 0L
                            cancelTrustedWifiResumeRetry(resetCount = true)
                            releaseTrustedWifiTransitionWakeLock()
                        }
                        trustedWifiResumeStartedAt > 0L &&
                            System.currentTimeMillis() - trustedWifiResumeStartedAt >=
                            TRUSTED_WIFI_RESUME_START_TIMEOUT_MS -> {
                            trustedWifiResumeInProgress = false
                            trustedWifiResumeStartedAt = 0L
                            trustedWifiWaiting = true
                            val status = "VPN не запустился, повторяем восстановление"
                            Log.w("TunnelService", status)
                            CaptchaWebViewManager.onTunnelStop()
                            releaseWakeLock()
                            releaseWifiLock()
                            acquireTrustedWifiTransitionWakeLock()
                            TunnelManager.noteTrustedWifiEvent(
                                "resume_timeout",
                                "Автоматический запуск не начался за 30 секунд; повторяем.",
                                warning = true
                            )
                            TrustedWifiManager.setWaiting("", status)
                            SettingsStore(applicationContext).saveTrustedWifiWaiting(true)
                            keepTrustedWifiForeground(status)
                            scheduleTrustedWifiResumeRetry()
                        }
                    }
                }
                if (
                    !shouldKeepTunnelServiceAlive(
                        tunnelRunning = TunnelManager.running.value,
                        tunnelStarting =
                            TunnelManager.transition.value == TunnelTransition.STARTING &&
                                lastStartParams?.let { params ->
                                    shouldUseRtMasqueServerBootstrap(
                                        rtNetwork = params.rtNetwork,
                                        rtMasque = params.rtMasque,
                                        serverBootstrap = params.rtMasqueServerBootstrap,
                                    )
                                } == true,
                        tunnelPaused = isTunnelPaused,
                        trustedWifiWaiting = trustedWifiWaiting,
                        trustedWifiResumeInProgress = trustedWifiResumeInProgress
                    )
                ) {
                    // Туннель полностью остановлен (не на паузе) — убиваем сервис
                    stopSelf()
                    break
                }
                val deviceInteractive = isDeviceInteractive()
                if (TunnelManager.running.value && !isTunnelPaused) {
                    releaseTransitionLocksAfterTunnelStart()
                    val helper = WireGuardHelper(applicationContext)
                    val startupWindow = System.currentTimeMillis() - TunnelManager.processStartedAtMs < INITIAL_VPN_START_GRACE_MS
                    val captchaActive = TunnelManager.isCaptchaInProgress()
                    if (!startupWindow && !captchaActive && android.net.VpnService.prepare(applicationContext) != null) {
                        Log.w("TunnelService", "VPN-разрешение WDTT Plus отозвано или слот передан другому VPN. Выключаем WDTT Plus.")
                        stopTunnel(TunnelStopReason.VpnSlotTransferred)
                        break
                    }
                    // Не полагаемся только на broadcast: после глубокого сна первая
                    // итерация службы иногда выполняется раньше ACTION_SCREEN_ON.
                    observeDeviceInteractiveState(deviceInteractive)
                    val shouldInspectVpnInterface =
                        deviceInteractive && !startupWindow && !captchaActive
                    val vpnInterfaceUp = !shouldInspectVpnInterface || helper.isTunnelUp()
                    if (vpnInterfaceUp) {
                        vpnInterfaceMissingSinceMs = 0L
                        lastVpnInterfaceRecoveryAttemptAtMs = 0L
                    } else {
                        val now = System.currentTimeMillis()
                        if (vpnInterfaceMissingSinceMs == 0L) {
                            vpnInterfaceMissingSinceMs = now
                            Log.w(
                                "TunnelService",
                                "Системный VPN-интерфейс не найден. Подтверждаем состояние перед восстановлением."
                            )
                        }
                        val missingForMs = now - vpnInterfaceMissingSinceMs
                        val sinceLastAttemptMs = if (lastVpnInterfaceRecoveryAttemptAtMs == 0L) {
                            Long.MAX_VALUE
                        } else {
                            now - lastVpnInterfaceRecoveryAttemptAtMs
                        }
                        if (
                            shouldAttemptVpnInterfaceRecovery(
                                deviceInteractive = deviceInteractive,
                                startupWindow = startupWindow,
                                captchaActive = captchaActive,
                                vpnSlotYieldRequested = TunnelManager.vpnSlotYieldRequested.value,
                                missingForMs = missingForMs,
                                validatedNetworkAvailable = hasValidatedRealNetwork(),
                                sinceLastAttemptMs = sinceLastAttemptMs,
                            )
                        ) {
                            lastVpnInterfaceRecoveryAttemptAtMs = now
                            Log.w(
                                "TunnelService",
                                "Потеря VPN-интерфейса подтверждена на рабочей сети. Создаём его заново."
                            )
                            updateNotification("Восстановление VPN...")
                            TunnelManager.recreateVpnTunnel()
                        }
                    }
                    if (!startupWindow && !captchaActive && vpnInterfaceUp && deviceInteractive) {
                        when (TunnelManager.pollNetworkRecoveryAction()) {
                            NetworkRecoveryAction.SoftRestart -> {
                                Log.w("TunnelService", "Сетевая ошибка туннеля. Мягко перезапускаем транспорт.")
                                TunnelManager.restartTransport(
                                    reason = "[СЕТЬ] Сетевая ошибка туннеля. Мягкий перезапуск транспорта...",
                                    minIntervalMs = 20_000L,
                                    force = true,
                                )
                            }
                            NetworkRecoveryAction.StopVpn -> {
                                Log.w("TunnelService", "Автовосстановление не помогло. Останавливаем VPN, чтобы вернуть интернет.")
                                TunnelManager.markStoppedAfterFailedRecovery()
                                showTunnelAlertNotification(
                                    "WDTT Plus остановил VPN",
                                    "Связь не восстановилась автоматически, поэтому VPN выключен и интернет телефона возвращён напрямую."
                                )
                                stopTunnel(TunnelStopReason.NetworkRecoveryFailed)
                                break
                            }
                            null -> Unit
                        }
                    }
                }
                if (deviceInteractive && !isTunnelPaused && !trustedWifiWaiting) {
                    updateNotification(buildTunnelNotificationText())
                }
                delay(
                    tunnelStatusRefreshIntervalMs(
                        deviceInteractive = deviceInteractive,
                        transitionWakeLockHeld = wakeLock?.isHeld == true,
                        trustedWifiTransitionInProgress =
                            trustedWifiResumeInProgress || trustedWifiTransitionWakeLock?.isHeld == true,
                    )
                )
            }
        }
    }

    private fun buildTunnelNotificationText(): String {
        val issueTitle = TunnelManager.connectionIssueTitleForNotification()
        if (issueTitle != null) return issueTitle

        val nowElapsedMs = SystemClock.elapsedRealtime()
        sleepWakeResultText?.let { result ->
            if (nowElapsedMs < sleepWakeResultVisibleUntilMs) return result
            sleepWakeResultText = null
            sleepWakeResultVisibleUntilMs = 0L
        }
        val statsText = TunnelManager.stats.value.trim()
        return when {
            statsText.isEmpty() -> "Туннель активен"
            statsText == "Ожидание данных..." -> "Туннель активен"
            else -> formatTunnelTrafficForNotification(statsText)
        }
    }

    private fun rememberSleepWakeResult(runtimePhase: SleepBatteryRuntimePhase) {
        val text = sleepWakeNotificationText(runtimePhase) ?: return
        sleepWakeResultText = text
        sleepWakeResultVisibleUntilMs =
            SystemClock.elapsedRealtime() + SLEEP_WAKE_RESULT_VISIBLE_MS
    }

    private fun clearSleepWakeResult() {
        sleepWakeResultText = null
        sleepWakeResultVisibleUntilMs = 0L
    }

    private fun showTunnelAlertNotification(title: String, text: String) {
        val openIntent = PendingIntent.getActivity(
            this, 3,
            Intent(this, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val notification = NotificationCompat.Builder(this, TUNNEL_ALERT_CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setSmallIcon(R.drawable.ic_notification_icon)
            .setContentIntent(openIntent)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setSilent(true)
            .build()
        getSystemService(NotificationManager::class.java).notify(TUNNEL_ALERT_NOTIFICATION_ID, notification)
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            TUNNEL_NOTIFICATION_CHANNEL_ID,
            "WDTT Plus Туннель",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Уведомление о работе туннеля"
            setShowBadge(false)
            // ВАЖНО: Разрешаем показывать на экране блокировки
            lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            setSound(null, null)
            enableVibration(false)
        }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        val alertChannel = NotificationChannel(
            TUNNEL_ALERT_CHANNEL_ID,
            "WDTT Plus проблемы туннеля",
            NotificationManager.IMPORTANCE_DEFAULT
        ).apply {
            description = "Уведомления, когда VPN не смог восстановить соединение"
            lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            setSound(null, null)
            enableVibration(false)
        }
        getSystemService(NotificationManager::class.java).createNotificationChannel(alertChannel)
    }

    private fun createNotification(
        text: String,
        actionName: String = "STOP",
        actionTitle: String = "Отключить",
        includeDefaultAction: Boolean = true,
        extraActions: List<TunnelNotificationAction> = emptyList(),
        deadlineWallMs: Long? = null,
        title: String = notificationProfileTitle,
        smallIcon: Int = R.drawable.ic_notification_icon,
    ): Notification {
        val openIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        
        val builder = NotificationCompat.Builder(this, TUNNEL_NOTIFICATION_CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(smallIcon)
            .setOngoing(true)
            .setLocalOnly(true)
            .setContentIntent(openIntent)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_DEFAULT)
            // ВАЖНО: Делаем уведомление публичным (видимым на локскрине)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            // Категория SERVICE помогает системе понять важность
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setOnlyAlertOnce(true) // Не издавать звук и не будить экран при обновлении статистики!
            .setSilent(true) // Делаем тихим само уведомление
            .setPriority(NotificationCompat.PRIORITY_LOW)

        if (includeDefaultAction) {
            val defaultIntent = PendingIntent.getService(
                this, if (actionName == "STOP") 1 else 2,
                Intent(this, TunnelService::class.java).apply { action = actionName },
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            builder.addAction(
                R.drawable.ic_stop,
                if (trustedWifiWaiting && actionName == "STOP") "Отменить ожидание" else actionTitle,
                defaultIntent,
            )
        }
        extraActions.forEach { spec ->
            val actionIntent = PendingIntent.getService(
                this,
                spec.requestCode,
                Intent(this, TunnelService::class.java).apply { action = spec.action },
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            builder.addAction(R.drawable.ic_stop, spec.title, actionIntent)
        }
        if (deadlineWallMs != null) {
            builder
                .setShowWhen(true)
                .setUsesChronometer(true)
                .setChronometerCountDown(true)
                .setWhen(deadlineWallMs)
        } else {
            builder
                .setShowWhen(false)
                .setUsesChronometer(false)
                .setWhen(0L)
        }
        return builder.build()
    }

    private fun startPersistentForeground(notification: Notification) {
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(TUNNEL_NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(TUNNEL_NOTIFICATION_ID, notification)
        }
    }

    private fun updateNotification(
        text: String,
        title: String = notificationProfileTitle,
        smallIcon: Int = R.drawable.ic_notification_icon,
    ) {
        if (sleepTimerNotificationActive) return
        if (
            lastNotificationTitle == title &&
            lastNotificationText == text &&
            lastNotificationSmallIcon == smallIcon
        ) return
        lastNotificationTitle = title
        lastNotificationText = text
        lastNotificationSmallIcon = smallIcon
        val notification = createNotification(
            text = text,
            title = title,
            smallIcon = smallIcon,
        )
        getSystemService(NotificationManager::class.java).notify(TUNNEL_NOTIFICATION_ID, notification)
    }

    private fun showSleepTimerNotification(
        title: String,
        text: String,
        deadlineWallMs: Long,
        actions: List<TunnelNotificationAction>,
    ) {
        sleepTimerNotificationActive = true
        lastNotificationTitle = null
        lastNotificationText = null
        lastNotificationSmallIcon = null
        val notification = createNotification(
            text = text,
            includeDefaultAction = false,
            extraActions = actions,
            deadlineWallMs = deadlineWallMs,
            title = title,
            smallIcon = R.drawable.ic_notification_timer,
        )
        getSystemService(NotificationManager::class.java).notify(TUNNEL_NOTIFICATION_ID, notification)
    }

    private fun showSleepPausedNotification() {
        sleepTimerNotificationActive = false
        updateNotification(
            text = "Интернет напрямую до включения экрана",
            title = "VPN выключен во сне",
            smallIcon = R.drawable.ic_notification_paused,
        )
    }

    override fun onDestroy() {
        super.onDestroy()
        val stopReasonOnUnexpectedDestroy = requestedStopReason ?: TunnelStopReason.ServiceDestroyed
        val stopWasCompleted = intentionalStopCompleted
        invalidatePendingStart()
        serviceScope.cancel()
        wakeRescueJob?.cancel()
        cancelTimerResumeTransportConfirmation()
        networkChangeJob?.cancel()
        screenStateReceiver?.let {
            runCatching { unregisterReceiver(it) }
        }
        screenStateReceiver = null
        trustedWifiStateReceiver?.let {
            runCatching { unregisterReceiver(it) }
        }
        trustedWifiStateReceiver = null
        packageChangeReceiver?.let {
            runCatching { unregisterReceiver(it) }
        }
        packageChangeReceiver = null
        networkCallback?.let {
            connectivityManager?.unregisterNetworkCallback(it)
        }
        trustedWifiNetworkCallback?.let {
            runCatching { connectivityManager?.unregisterNetworkCallback(it) }
        }
        trustedWifiSettingsJob?.cancel()
        cancelTrustedWifiEvaluations()
        cancelTrustedWifiResumeRetry(resetCount = false)
        releaseTrustedWifiTransitionWakeLock()
        releaseShortSleepPauseWakeLock()
        releaseShortSleepResumeWakeLock()
        if (trustedWifiWaiting || trustedWifiResumeInProgress) {
            releaseWakeLock()
            releaseWifiLock()
            TrustedWifiManager.setStatus("Служба ожидания будет восстановлена Android")
        } else if (!stopWasCompleted) {
            CaptchaWebViewManager.onTunnelStop()
            releaseWakeLock()
            releaseWifiLock()
            TunnelManager.stop(stopReasonOnUnexpectedDestroy)
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
