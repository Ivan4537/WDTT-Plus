package com.wdtt.plus

import android.app.Notification
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
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

private const val TUNNEL_NOTIFICATION_CHANNEL_ID = "wdtt_tunnel_v4"
private const val TUNNEL_ALERT_CHANNEL_ID = "wdtt_tunnel_alert_v1"
private const val TUNNEL_NOTIFICATION_ID = 1
private const val TUNNEL_ALERT_NOTIFICATION_ID = 2
private const val NETWORK_CHANGE_SETTLE_MS = 90_000L
private const val NETWORK_RETURN_SETTLE_MS = 45_000L
private const val NETWORK_LOSS_GRACE_MS = 2 * 60_000L
private const val STABLE_NETWORK_RECONNECT_DELAY_MS = 15_000L
private const val STABLE_NETWORK_RECONNECT_MIN_INTERVAL_MS = 2 * 60_000L
private const val WAKE_RESCUE_GRACE_MS = 60_000L
private const val WAKE_RESCUE_FAIL_OPEN_MS = 2 * 60_000L
private const val INITIAL_VPN_START_GRACE_MS = 90_000L
private const val TRUSTED_WIFI_ENTER_DELAY_MS = 2_000L
private const val TRUSTED_WIFI_EXIT_DELAY_MS = 5_000L
private const val TRUSTED_WIFI_FAST_RESUME_RETRY_COUNT = 12
private const val TRUSTED_WIFI_SLOW_RESUME_RETRY_MS = 30_000L
private const val TRUSTED_WIFI_RESUME_START_TIMEOUT_MS = 30_000L

class TunnelService : Service() {
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null
    private var updateJob: Job? = null
    private var profileNameJob: Job? = null
    private var networkChangeJob: Job? = null
    private var lastNotificationTitle: String? = null
    private var lastNotificationText: String? = null
    private var notificationProfileTitle: String = "WDTT Plus"
    private var requestedStopReason: TunnelStopReason? = null
    
    // Network Monitoring
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var lastNetworkChangeTime = 0L
    private val activeNetworks = mutableSetOf<Network>()
    private var isTunnelPaused = false
    private var lastValidatedNetwork: Network? = null
    private var lastStableNetworkReconnectAt = 0L
    private var stableNetworkWasLost = false
    private var screenStateReceiver: BroadcastReceiver? = null
    private var trustedWifiStateReceiver: BroadcastReceiver? = null
    private var wakeRescueJob: Job? = null
    private var trustedWifiNetworkCallback: ConnectivityManager.NetworkCallback? = null
    private var trustedWifiSettingsJob: Job? = null
    private var trustedWifiEvaluationJob: Job? = null
    private val trustedWifiEvaluationScheduleLock = Any()
    private var trustedWifiPendingEvaluationDelayMs: Long? = null
    private var trustedWifiResumeRetryJob: Job? = null
    private var trustedWifiResumeRetryCount = 0
    private var trustedWifiResumeInProgress = false
    private var trustedWifiResumeStartedAt = 0L
    private val trustedWifiTransitionMutex = Mutex()
    private var trustedWifiWaiting = false
    private var trustedWifiWaitingSsid = ""
    private var lastStartParams: TunnelParams? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        // Сразу берем лок при создании
        acquireWakeLock()
        setupNetworkCallback()
        setupTrustedWifiMonitoring()
        registerScreenStateReceiver()
        registerTrustedWifiStateReceiver()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) {
            restoreTunnel()
            return START_STICKY
        }

        when (intent.action) {
            "START" -> {
                val notification = createNotification("Запуск...")
                startPersistentForeground(notification)

                val params = TunnelParams(
                    peer = intent.getStringExtra("peer") ?: "",
                    vkHashes = intent.getStringExtra("vk_hashes") ?: "",
                    secondaryVkHash = intent.getStringExtra("secondary_vk_hash") ?: "",
                    workersPerHash = intent.getIntExtra("workers_per_hash", 16),
                    port = intent.getIntExtra("port", 9000),
                    sni = intent.getStringExtra("sni") ?: "",
                    connectionPassword = intent.getStringExtra("connection_password") ?: "",
                    protocol = intent.getStringExtra("protocol") ?: "udp",
                    vkCallsPreflight = intent.getBooleanExtra("vkcalls_preflight", true),
                    captchaMode = sanitizeCaptchaMode(intent.getStringExtra("captcha_mode")),
                    captchaSolveMethod = intent.getStringExtra("captcha_solve_method") ?: "auto",
                    fingerprint = intent.getStringExtra("fingerprint") ?: "firefox",
                    clientIds = intent.getStringExtra("client_ids") ?: "6287487,8202606"
                )
                lastStartParams = params
                TunnelManager.scope.launch(Dispatchers.Main) {
                    startOrWaitForTrustedWifi(params)
                }
            }
            "STOP" -> stopTunnel(TunnelStopReason.User)
            "DEPLOY_START" -> {
                val notification = createNotification("Установка на сервер...", "DEPLOY_CANCEL", "Отменить")
                startPersistentForeground(notification)
                acquireWakeLock()
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
                }
                scheduleTrustedWifiEvaluation(delayMs = 0L)
            }
        }
        return START_STICKY
    }

    private fun restoreTunnel() {
        val notification = createNotification("Восстановление соединения...")
        startPersistentForeground(notification)
        
        val appContext = applicationContext
        TunnelManager.scope.launch {
            try {
                val store = SettingsStore(appContext)
                val params = buildTunnelParamsFromSettings(appContext)
                if (params != null) {
                    launch(Dispatchers.Main) {
                        lastStartParams = params
                        val restoreWaiting = store.trustedWifiEnabled.first() && store.trustedWifiWaiting.first()
                        if (restoreWaiting) {
                            trustedWifiWaiting = true
                            trustedWifiWaitingSsid = store.trustedWifiWaitingSsid.first()
                            TrustedWifiManager.setWaiting(trustedWifiWaitingSsid)
                            startNotificationProfileWatcher()
                            startStatsUpdater()
                            scheduleTrustedWifiEvaluation(delayMs = 0L)
                        } else {
                            startOrWaitForTrustedWifi(params)
                        }
                    }
                } else {
                    launch(Dispatchers.Main) {
                        stopTunnel(TunnelStopReason.RestoreFailed)
                    }
                }
            } catch (e: Exception) {
                launch(Dispatchers.Main) {
                    stopTunnel(TunnelStopReason.RestoreFailed)
                }
            }
        }
    }

    private fun startTunnel(params: TunnelParams, fromTrustedWifiResume: Boolean = false) {
        trustedWifiResumeRetryJob?.cancel()
        trustedWifiResumeRetryJob = null
        trustedWifiResumeRetryCount = 0
        trustedWifiResumeInProgress = fromTrustedWifiResume
        trustedWifiResumeStartedAt = if (fromTrustedWifiResume) System.currentTimeMillis() else 0L
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
        acquireWifiLock()

        // Подготавливаем CaptchaWebViewManager (не создаёт WebView — просто сохраняет контекст)
        // Вызываем всегда — дёшево, а WebView создаётся на лету при каждом запросе капчи
        CaptchaWebViewManager.onTunnelStart(applicationContext)

        TunnelManager.start(this, params)
        startNotificationProfileWatcher()
        startStatsUpdater()
    }

    private fun stopTunnel(reason: TunnelStopReason = TunnelStopReason.User) {
        val effectiveReason = requestedStopReason ?: reason
        requestedStopReason = effectiveReason
        updateJob?.cancel()
        profileNameJob?.cancel()
        networkChangeJob?.cancel()
        wakeRescueJob?.cancel()
        trustedWifiResumeRetryJob?.cancel()
        profileNameJob = null
        networkChangeJob = null
        wakeRescueJob = null
        trustedWifiResumeRetryJob = null
        trustedWifiResumeRetryCount = 0
        trustedWifiResumeInProgress = false
        trustedWifiResumeStartedAt = 0L
        cancelTrustedWifiEvaluations()
        trustedWifiWaiting = false
        trustedWifiWaitingSsid = ""
        lastStartParams = null
        TrustedWifiManager.clear()
        TunnelManager.scope.launch {
            SettingsStore(applicationContext).saveTrustedWifiWaiting(false)
        }

        // Уничтожаем текущий WebView (если капча решается) и чистим контекст
        CaptchaWebViewManager.onTunnelStop()

        TunnelManager.stop(effectiveReason)
        releaseWakeLock()
        releaseWifiLock()
        lastValidatedNetwork = null
        lastStableNetworkReconnectAt = 0L
        stableNetworkWasLost = false
        activeNetworks.clear()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun startNotificationProfileWatcher() {
        profileNameJob?.cancel()
        val settingsStore = SettingsStore(applicationContext)
        profileNameJob = TunnelManager.scope.launch(Dispatchers.Main) {
            combine(
                settingsStore.activeProfile,
                settingsStore.profileNames
            ) { activeProfile, profileNames ->
                val profile = activeProfile.coerceIn(0, 2)
                val profileLabel = vpnProfileDisplayName(profile, profileNames)
                "WDTT Plus · $profileLabel"
            }.collect { prefix ->
                notificationProfileTitle = prefix
                if (trustedWifiWaiting) {
                    updateTrustedWifiNotification()
                } else if (TunnelManager.running.value && !isTunnelPaused) {
                    updateNotification(buildTunnelNotificationText())
                }
            }
        }
    }

    private fun registerScreenStateReceiver() {
        if (screenStateReceiver != null) return
        screenStateReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                when (intent?.action) {
                    Intent.ACTION_SCREEN_ON -> {
                        scheduleWakeRescueCheck()
                        scheduleTrustedWifiEvaluation(delayMs = 0L)
                    }
                    Intent.ACTION_SCREEN_OFF -> {
                        wakeRescueJob?.cancel()
                        wakeRescueJob = null
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
                                keepTrustedWifiForeground("Ожидание рабочей сети")
                                scheduleTrustedWifiEvaluation(delayMs = 0L)
                                scheduleTrustedWifiResumeRetry()
                            }
                            else -> scheduleTrustedWifiEvaluation(TRUSTED_WIFI_ENTER_DELAY_MS)
                        }
                    }
                    WifiManager.NETWORK_STATE_CHANGED_ACTION -> {
                        keepTrustedWifiForeground()
                        scheduleTrustedWifiEvaluation(delayMs = 0L)
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
        val wakeAt = System.currentTimeMillis()
        TunnelManager.noteWakeRescueStarted()
        updateNotification("Проверка VPN после сна...")

        wakeRescueJob?.cancel()
        wakeRescueJob = TunnelManager.scope.launch(Dispatchers.Main) {
            delay(WAKE_RESCUE_GRACE_MS)
            if (!TunnelManager.running.value || isTunnelPaused || TunnelManager.isCaptchaInProgress()) return@launch
            if (TunnelManager.hasFreshTunnelActivitySince(wakeAt)) {
                TunnelManager.noteWakeRescueHealthy()
                updateNotification(buildTunnelNotificationText())
                return@launch
            }

            TunnelManager.noteWakeRescueReconnect()
            updateNotification("Восстановление VPN...")
            val reconnectAt = System.currentTimeMillis()
            TunnelManager.restartTransport(
                reason = "[СОН] После пробуждения VPN не подал признаков жизни. Мягко переподключаю транспорт.",
                minIntervalMs = 60_000L
            )

            delay(WAKE_RESCUE_FAIL_OPEN_MS)
            if (!TunnelManager.running.value || isTunnelPaused || TunnelManager.isCaptchaInProgress()) return@launch
            if (TunnelManager.hasFreshTunnelActivitySince(reconnectAt)) {
                TunnelManager.noteWakeRescueHealthy()
                updateNotification(buildTunnelNotificationText())
                return@launch
            }

            TunnelManager.markStoppedAfterWakeRescue()
            showTunnelAlertNotification(
                "WDTT Plus остановил VPN",
                "После пробуждения VPN не восстановился, поэтому приложение выключило VPN и вернуло прямой интернет."
            )
            stopTunnel(TunnelStopReason.WakeRecoveryFailed)
        }
    }

    private suspend fun startOrWaitForTrustedWifi(params: TunnelParams) {
        val store = SettingsStore(applicationContext)
        val enabled = store.trustedWifiEnabled.first()
        val trustedSsids = store.trustedWifiSsids.first().toSet()
        val wifi = readConnectedWifiState(applicationContext)
        if (isWdttAlwaysOnVpn(applicationContext) && wifi.ssidAvailable && wifi.ssid in trustedSsids) {
            startTunnel(params)
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
            startTunnel(params)
        }
    }

    private fun setupTrustedWifiMonitoring() {
        val manager = connectivityManager
            ?: (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager).also {
                connectivityManager = it
            }
        trustedWifiNetworkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                scheduleTrustedWifiEvaluation(TRUSTED_WIFI_ENTER_DELAY_MS)
            }

            override fun onLost(network: Network) {
                scheduleTrustedWifiEvaluation(TRUSTED_WIFI_EXIT_DELAY_MS)
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                scheduleTrustedWifiEvaluation(
                    if (trustedWifiWaiting) TRUSTED_WIFI_EXIT_DELAY_MS else TRUSTED_WIFI_ENTER_DELAY_MS
                )
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
        trustedWifiResumeRetryJob?.cancel()
        val delayMs = if (trustedWifiResumeRetryCount < TRUSTED_WIFI_FAST_RESUME_RETRY_COUNT) {
            TRUSTED_WIFI_EXIT_DELAY_MS
        } else {
            TRUSTED_WIFI_SLOW_RESUME_RETRY_MS
        }
        trustedWifiResumeRetryCount += 1
        trustedWifiResumeRetryJob = TunnelManager.scope.launch {
            delay(delayMs)
            if (trustedWifiWaiting) {
                evaluateTrustedWifiState()
            }
        }
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
            trustedWifiWaiting = true
            trustedWifiWaitingSsid = cleanSsid
            isTunnelPaused = false
            trustedWifiResumeRetryCount = 0
            networkChangeJob?.cancel()
            wakeRescueJob?.cancel()
            trustedWifiResumeRetryJob?.cancel()
            trustedWifiResumeRetryJob = null

            TunnelManager.stopAndWait(TunnelStopReason.TrustedWifi)
            WireGuardHelper(applicationContext).stopTunnel()
            TrustedWifiManager.setWaiting(cleanSsid)
            SettingsStore(applicationContext).saveTrustedWifiWaiting(true, cleanSsid)
            withContext(Dispatchers.Main) {
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
                TrustedWifiManager.setStatus(status)
                withContext(Dispatchers.Main) { updateNotification(status) }
                return
            }

            val params = lastStartParams ?: buildTunnelParamsFromSettings(applicationContext)
            if (params == null) {
                val status = "Не удалось прочитать профиль VPN. Откройте WDTT Plus."
                TrustedWifiManager.setStatus(status)
                withContext(Dispatchers.Main) { updateNotification(status) }
                return
            }

            withContext(Dispatchers.Main) {
                Log.i("TunnelService", "Доверенная Wi-Fi покинута, запускаем VPN на рабочей сети")
                // startTunnel синхронно включает защитный resumeInProgress до снятия waiting.
                // Поэтому очередной сетевой callback уже не может оставить сервис между
                // состояниями: без VPN, без ожидания и с удалённым уведомлением.
                startTunnel(params, fromTrustedWifiResume = true)
                VpnWidgetProvider.updateAllWidgets(applicationContext)
            }
        }
    }

    private fun updateTrustedWifiNotification() {
        keepTrustedWifiForeground()
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
        
        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                super.onAvailable(network)
                if (trustedWifiWaiting) {
                    scheduleTrustedWifiEvaluation(TRUSTED_WIFI_EXIT_DELAY_MS)
                }
                val wasEmpty = activeNetworks.isEmpty()
                activeNetworks.add(network)
                if (AMNEZIA_STYLE_RECOVERY) {
                    return
                }
                if (wasEmpty) {
                    if (isTunnelPaused) {
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
                if (trustedWifiWaiting) {
                    scheduleTrustedWifiEvaluation(TRUSTED_WIFI_EXIT_DELAY_MS)
                }
                activeNetworks.remove(network)
                if (AMNEZIA_STYLE_RECOVERY) {
                    if (lastValidatedNetwork == network) {
                        lastValidatedNetwork = null
                    }
                    if (activeNetworks.isEmpty() && TunnelManager.running.value) {
                        stableNetworkWasLost = true
                        TunnelManager.noteUnderlyingNetworkChanged(
                            "сеть временно пропала",
                            graceMs = NETWORK_LOSS_GRACE_MS,
                            replaceGrace = true
                        )
                        updateNotification("Ожидание сети")
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
                if (trustedWifiWaiting) {
                    scheduleTrustedWifiEvaluation(TRUSTED_WIFI_EXIT_DELAY_MS)
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
        if (previous == null) {
            lastValidatedNetwork = network
            if (stableNetworkWasLost) {
                stableNetworkWasLost = false
                scheduleStableValidatedReconnect("Android подтвердил возвращение рабочей сети")
                return
            }
            if (TunnelManager.running.value) {
                TunnelManager.noteUnderlyingNetworkChanged(
                    "Android подтвердил рабочую сеть",
                    graceMs = STABLE_NETWORK_RECONNECT_DELAY_MS,
                    replaceGrace = false
                )
            }
            return
        }
        if (previous != network) {
            lastValidatedNetwork = network
            scheduleStableValidatedReconnect("Android подтвердил смену рабочей сети")
        }
    }

    private fun scheduleStableValidatedReconnect(reason: String) {
        val now = System.currentTimeMillis()
        lastNetworkChangeTime = now

        if (!TunnelManager.running.value || isTunnelPaused) return
        TunnelManager.noteUnderlyingNetworkChanged(
            reason,
            graceMs = STABLE_NETWORK_RECONNECT_DELAY_MS + 30_000L,
            replaceGrace = true
        )
        networkChangeJob?.cancel()
        networkChangeJob = TunnelManager.scope.launch(Dispatchers.Main) {
            Log.d("TunnelService", "$reason, ждём короткую стабилизацию перед reconnect")
            delay(STABLE_NETWORK_RECONNECT_DELAY_MS)
            if (lastNetworkChangeTime != now) return@launch
            if (!TunnelManager.running.value || !hasAnyRealNetwork() || TunnelManager.isCaptchaInProgress()) return@launch

            val sinceLastReconnect = System.currentTimeMillis() - lastStableNetworkReconnectAt
            if (sinceLastReconnect < STABLE_NETWORK_RECONNECT_MIN_INTERVAL_MS) {
                Log.d("TunnelService", "Пропускаем reconnect: недавний reconnect уже был")
                return@launch
            }
            lastStableNetworkReconnectAt = System.currentTimeMillis()
            TunnelManager.restartTransport(
                reason = "[СЕТЬ] Android подтвердил новую сеть. Мягко переподключаю транспорт.",
                minIntervalMs = STABLE_NETWORK_RECONNECT_MIN_INTERVAL_MS
            )
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
    private fun hasUsableRealNetworkForTrustedWifiResume(): Boolean {
        val cm = connectivityManager
            ?: (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager).also {
                connectivityManager = it
            }
        return cm.allNetworks.any { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@any false
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
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
            Log.d("TunnelService", "Сети долго нет, приостанавливаем транспорт без переподключений к VK")
            TunnelManager.pause()
            updateNotification("Ожидание сети")
        }
    }

    private fun scheduleResumeAfterNetworkReturn() {
        val now = System.currentTimeMillis()
        lastNetworkChangeTime = now
        TunnelManager.noteUnderlyingNetworkChanged("сеть вернулась", graceMs = NETWORK_RETURN_SETTLE_MS, replaceGrace = true)
        networkChangeJob?.cancel()
        networkChangeJob = TunnelManager.scope.launch(Dispatchers.Main) {
            Log.d("TunnelService", "Сеть появилась, ждём стабилизации перед возобновлением")
            delay(NETWORK_RETURN_SETTLE_MS)
            if (lastNetworkChangeTime != now) return@launch
            if (!hasAnyRealNetwork() || !TunnelManager.running.value) return@launch
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

    private fun acquireWakeLock() {
        if (wakeLock?.isHeld == true) return
        val pm = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "wdtt:tunnel_cpu"
        ).apply { 
            setReferenceCounted(false)
            acquire() 
        }
    }

    @Suppress("DEPRECATION")
    private fun acquireWifiLock() {
        if (wifiLock?.isHeld == true) return
        val wm = applicationContext.getSystemService(WIFI_SERVICE) as WifiManager
        
        // Используем WIFI_MODE_FULL_LOW_LATENCY для Android 10+, 
        // это предотвращает отключение радиомодуля при выключенном экране
        val mode = if (Build.VERSION.SDK_INT >= 29) {
            WifiManager.WIFI_MODE_FULL_LOW_LATENCY
        } else {
            WifiManager.WIFI_MODE_FULL_HIGH_PERF
        }
        
        wifiLock = wm.createWifiLock(mode, "wdtt:wifi_perf").apply { 
            setReferenceCounted(false)
            acquire() 
        }
    }

    private fun releaseWakeLock() {
        if (wakeLock?.isHeld == true) {
            wakeLock?.release()
        }
        wakeLock = null
    }

    private fun releaseWifiLock() {
        if (wifiLock?.isHeld == true) {
            wifiLock?.release()
        }
        wifiLock = null
    }

    private fun startStatsUpdater() {
        updateJob?.cancel()
        updateJob = TunnelManager.scope.launch(Dispatchers.Main) {
            delay(1000)
            while (isActive) {
                if (trustedWifiResumeInProgress) {
                    when {
                        TunnelManager.running.value -> {
                            trustedWifiResumeInProgress = false
                            trustedWifiResumeStartedAt = 0L
                        }
                        trustedWifiResumeStartedAt > 0L &&
                            System.currentTimeMillis() - trustedWifiResumeStartedAt >=
                            TRUSTED_WIFI_RESUME_START_TIMEOUT_MS -> {
                            trustedWifiResumeInProgress = false
                            trustedWifiResumeStartedAt = 0L
                            trustedWifiWaiting = true
                            val status = "VPN не запустился, повторяем восстановление"
                            Log.w("TunnelService", status)
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
                        tunnelPaused = isTunnelPaused,
                        trustedWifiWaiting = trustedWifiWaiting,
                        trustedWifiResumeInProgress = trustedWifiResumeInProgress
                    )
                ) {
                    // Туннель полностью остановлен (не на паузе) — убиваем сервис
                    stopSelf()
                    break
                }
                if (TunnelManager.running.value && !isTunnelPaused) {
                    val helper = WireGuardHelper(applicationContext)
                    val startupWindow = System.currentTimeMillis() - TunnelManager.processStartedAtMs < INITIAL_VPN_START_GRACE_MS
                    val captchaActive = TunnelManager.isCaptchaInProgress()
                    if (!startupWindow && !captchaActive && android.net.VpnService.prepare(applicationContext) != null) {
                        Log.w("TunnelService", "VPN-разрешение WDTT Plus отозвано или слот передан другому VPN. Выключаем WDTT Plus.")
                        stopTunnel(TunnelStopReason.VpnSlotTransferred)
                        break
                    }
                    if (!startupWindow && !captchaActive && !helper.isTunnelUp()) {
                        Log.w("TunnelService", "Обнаружена пропажа или замена VPN-интерфейса! Экстренное выключение туннеля.")
                        stopTunnel(TunnelStopReason.VpnInterfaceLost)
                        break
                    }
                    if (!startupWindow && !captchaActive) {
                        when (TunnelManager.pollNetworkRecoveryAction()) {
                            NetworkRecoveryAction.SoftRestart -> {
                                Log.w("TunnelService", "Сетевая ошибка туннеля. Мягко перезапускаем транспорт.")
                                TunnelManager.restartTransport(
                                    reason = "[СЕТЬ] Сетевая ошибка туннеля. Мягкий перезапуск транспорта...",
                                    minIntervalMs = 20_000L
                                )
                            }
                            NetworkRecoveryAction.RecreateVpn -> {
                                Log.w("TunnelService", "Мягкие попытки не помогли. Пересоздаём VPN-туннель.")
                                updateNotification("Пересоздание VPN...")
                                TunnelManager.recreateVpnTunnel()
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
                if (!isTunnelPaused && !trustedWifiWaiting) {
                    updateNotification(buildTunnelNotificationText())
                }
                delay(2000)
            }
        }
    }

    private fun buildTunnelNotificationText(): String {
        val issueTitle = TunnelManager.connectionIssueTitleForNotification()
        if (issueTitle != null) {
            return issueTitle
        }
        val statsText = TunnelManager.stats.value.trim()
        return when {
            statsText.isEmpty() -> "Туннель активен"
            statsText == "Ожидание данных..." -> "Туннель активен"
            else -> statsText
        }
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

    private fun createNotification(text: String, actionName: String = "STOP", actionTitle: String = "Отключить"): Notification {
        val openIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        
        val stopIntent = PendingIntent.getService(
            this, if (actionName == "STOP") 1 else 2,
            Intent(this, TunnelService::class.java).apply { action = actionName },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, TUNNEL_NOTIFICATION_CHANNEL_ID)
            .setContentTitle(notificationProfileTitle)
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_notification_icon)
            .setOngoing(true)
            .setLocalOnly(true)
            .setContentIntent(openIntent)
            .addAction(
                R.drawable.ic_stop,
                if (trustedWifiWaiting && actionName == "STOP") "Отменить ожидание" else actionTitle,
                stopIntent
            )
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_DEFAULT)
            // ВАЖНО: Делаем уведомление публичным (видимым на локскрине)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            // Категория SERVICE помогает системе понять важность
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setOnlyAlertOnce(true) // Не издавать звук и не будить экран при обновлении статистики!
            .setSilent(true) // Делаем тихим само уведомление
            .setShowWhen(false)
            .setUsesChronometer(false)
            .setWhen(0L)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun startPersistentForeground(notification: Notification) {
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(TUNNEL_NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(TUNNEL_NOTIFICATION_ID, notification)
        }
    }

    private fun updateNotification(text: String) {
        val title = notificationProfileTitle
        if (lastNotificationTitle == title && lastNotificationText == text) return
        lastNotificationTitle = title
        lastNotificationText = text
        val notification = createNotification(text)
        getSystemService(NotificationManager::class.java).notify(TUNNEL_NOTIFICATION_ID, notification)
    }

    override fun onDestroy() {
        super.onDestroy()
        wakeRescueJob?.cancel()
        networkChangeJob?.cancel()
        screenStateReceiver?.let {
            runCatching { unregisterReceiver(it) }
        }
        screenStateReceiver = null
        trustedWifiStateReceiver?.let {
            runCatching { unregisterReceiver(it) }
        }
        trustedWifiStateReceiver = null
        networkCallback?.let {
            connectivityManager?.unregisterNetworkCallback(it)
        }
        trustedWifiNetworkCallback?.let {
            runCatching { connectivityManager?.unregisterNetworkCallback(it) }
        }
        trustedWifiSettingsJob?.cancel()
        cancelTrustedWifiEvaluations()
        trustedWifiResumeRetryJob?.cancel()
        if (trustedWifiWaiting || trustedWifiResumeInProgress) {
            releaseWakeLock()
            releaseWifiLock()
            TrustedWifiManager.setStatus("Служба ожидания будет восстановлена Android")
        } else {
            stopTunnel(TunnelStopReason.ServiceDestroyed)
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
