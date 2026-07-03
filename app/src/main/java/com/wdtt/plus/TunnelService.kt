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
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

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

class TunnelService : Service() {
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null
    private var updateJob: Job? = null
    private var networkChangeJob: Job? = null
    private var lastNotificationText: String? = null
    
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
    private var wakeRescueJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        // Сразу берем лок при создании
        acquireWakeLock()
        setupNetworkCallback()
        registerScreenStateReceiver()
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
                startTunnel(params)
            }
            "STOP" -> stopTunnel()
            "DEPLOY_START" -> {
                val notification = createNotification("Установка на сервер...", "DEPLOY_CANCEL", "Отменить")
                startPersistentForeground(notification)
                acquireWakeLock()
            }
            "DEPLOY_CANCEL" -> {
                com.wdtt.plus.DeployManager.writeError("[!] ❌ Установка отменена пользователем")
                com.wdtt.plus.DeployManager.stopDeploy("error: Отменена пользователем")
                stopForeground(STOP_FOREGROUND_REMOVE)
            }
            "DEPLOY_STOP" -> {
                if (!TunnelManager.running.value) {
                    stopTunnel()
                } else {
                    updateNotification("Туннель активен")
                }
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
                val params = buildTunnelParamsFromSettings(appContext)
                if (params != null) {
                    launch(Dispatchers.Main) {
                        startTunnel(params)
                    }
                } else {
                    launch(Dispatchers.Main) {
                        stopTunnel()
                    }
                }
            } catch (e: Exception) {
                launch(Dispatchers.Main) {
                    stopTunnel()
                }
            }
        }
    }

    private fun startTunnel(params: TunnelParams) {
        updateNotification("Подключение...")
        acquireWakeLock()
        acquireWifiLock()

        // Подготавливаем CaptchaWebViewManager (не создаёт WebView — просто сохраняет контекст)
        // Вызываем всегда — дёшево, а WebView создаётся на лету при каждом запросе капчи
        CaptchaWebViewManager.onTunnelStart(applicationContext)

        TunnelManager.start(this, params)
        startStatsUpdater()
    }

    private fun stopTunnel() {
        updateJob?.cancel()
        networkChangeJob?.cancel()
        wakeRescueJob?.cancel()
        networkChangeJob = null
        wakeRescueJob = null

        // Уничтожаем текущий WebView (если капча решается) и чистим контекст
        CaptchaWebViewManager.onTunnelStop()

        TunnelManager.stop()
        releaseWakeLock()
        releaseWifiLock()
        lastValidatedNetwork = null
        lastStableNetworkReconnectAt = 0L
        stableNetworkWasLost = false
        activeNetworks.clear()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun registerScreenStateReceiver() {
        if (screenStateReceiver != null) return
        screenStateReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                when (intent?.action) {
                    Intent.ACTION_SCREEN_ON -> scheduleWakeRescueCheck()
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
            stopTunnel()
        }
    }

    private fun setupNetworkCallback() {
        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        activeNetworks.clear()
        
        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                super.onAvailable(network)
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
                if (!TunnelManager.running.value && !isTunnelPaused) {
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
                        stopTunnel()
                        break
                    }
                    if (!startupWindow && !captchaActive && !helper.isTunnelUp()) {
                        Log.w("TunnelService", "Обнаружена пропажа или замена VPN-интерфейса! Экстренное выключение туннеля.")
                        stopTunnel()
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
                                stopTunnel()
                                break
                            }
                            null -> Unit
                        }
                    }
                }
                if (!isTunnelPaused) {
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
            .setContentTitle("WDTT Plus")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_notification_icon)
            .setOngoing(true)
            .setLocalOnly(true)
            .setContentIntent(openIntent)
            .addAction(R.drawable.ic_stop, actionTitle, stopIntent)
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
        if (lastNotificationText == text) return
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
        networkCallback?.let {
            connectivityManager?.unregisterNetworkCallback(it)
        }
        stopTunnel()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
