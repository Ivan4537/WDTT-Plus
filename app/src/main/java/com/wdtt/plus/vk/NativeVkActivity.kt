package com.wdtt.plus.vk

import android.annotation.SuppressLint
import android.content.*
import android.net.*
import android.net.http.SslError
import android.os.*
import android.view.WindowManager
import android.webkit.*
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.lifecycleScope
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import com.wdtt.plus.SecureStringStore
import com.wdtt.plus.RemoteDocumentGateway
import com.wdtt.plus.WDTTTheme
import kotlinx.coroutines.*
import okhttp3.OkHttpClient
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream

/** Official login and four explicit local Calls requests, entirely in our task. */
open class NativeVkActivity : ComponentActivity() {
    companion object {
        private var current = java.lang.ref.WeakReference<NativeVkActivity>(null)
        private val SAFE_FALLBACK_STAGES = setOf(
            "BROKER_LOST",
            "BROKER_BIND",
            "PREPARE",
            "IDENTITY",
            "NETWORK",
            "NETWORK_LOST",
            "LOGIN",
            "WEB_TLS",
            "WEB_PAGE",
            "WEB_RENDER",
            "OAUTH_CALLBACK",
            "VK_ID_CALLBACK",
            "RESTORE",
        )
    }
    private lateinit var localProfile: com.wdtt.plus.LocalContinuationProfile
    private val prefs by lazy { getSharedPreferences("native-vk-ledger-profile-${localProfile.index}", MODE_PRIVATE) }
    private val tokenPrefs by lazy { VkLocalSession.nativeTokenPreferences(this, localProfile) }
    private val vkSession by lazy { VkLocalSession.forContext(this, localProfile) }
    private val secrets by lazy { SecureStringStore(this) }
    private val cm by lazy { getSystemService(ConnectivityManager::class.java) }
    private var key = ""
    private var device = ""
    private var expires = 0L
    private var hasCompleteLocalValues = false
    private var receiver: ResultReceiver? = null
    private var broker: Messenger? = null
    private var sequence = 0
    private val replies = mutableMapOf<Int, CompletableDeferred<JSONObject>>()
    private var bound = false
    private var callback: ConnectivityManager.NetworkCallback? = null
    private var network: Network? = null
    private var http: OkHttpClient? = null
    private var useDefaultNetwork = false
    private var tokenRoute = ""
    private var operationStage = "PREPARE"
    private val pendingLogs = ArrayDeque<String>()
    private var foreground = false
    private var disposed = false
    private var page by mutableStateOf<WebView?>(null)
    private var mainFrameUrl = ""
    private var origin by mutableStateOf("")
    private var status by mutableStateOf("Подготовка…")
    private var hasError by mutableStateOf(false)
    private var busy by mutableStateOf(true)
    private var authorized by mutableStateOf(false)
    private var completed by mutableIntStateOf(0)
    private var activeHashAttempt by mutableIntStateOf(0)
    private var confirmClose by mutableStateOf(false)
    private var token: VkApiProtocol.Token? = null
    private var requireAccountChoice = false
    private var confirmedAccountToken: String? = null
    private var offeredAccountToken: String? = null
    private var accountChoice by mutableStateOf<VkAccountIdentity?>(null)
    private var loginStage by mutableStateOf(LoginStage.NONE)
    private var vkIdAuth: VkApiProtocol.AuthAttempt? = null
    private var miniAppAuth: VkOAuthProtocol.AuthAttempt? = null
    private var journal = JSONArray()
    private var prepared = false
    private var replacementConfirmed by mutableStateOf(false)
    private var operationJob: Job? = null
    private var networkLabel by mutableStateOf("")
    private var fallbackDispatched = false
    private var captcha: VkInPlaceCaptcha? = null
    private var captchaState by mutableStateOf(VkCaptchaPolicy.State.IDLE)
    private var apiCaptchaResult: CompletableDeferred<String>? = null
    private val inbox = Messenger(object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(message: Message) {
            val pending = replies.remove(message.arg1) ?: return
            val answer = runCatching { JSONObject(message.data.getString("body").orEmpty()) }
            answer.fold(pending::complete) { pending.completeExceptionally(IllegalStateException("Повреждён ответ WDTT Plus.")) }
        }
    })
    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, service: IBinder) {
            broker = Messenger(service)
            flushLogs()
            if (!prepared && foreground) work { prepare() }
        }
            override fun onServiceDisconnected(name: ComponentName) {
            broker = null
            replies.values.forEach { it.completeExceptionally(IllegalStateException("Служебный канал прерван. Новые звонки не запускаются.")) }
            replies.clear()
            fail("BROKER_LOST", IllegalStateException(), "Соединение прервано. Попробуйте ещё раз.")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val previous = current.get()
        if (previous != null && !previous.isFinishing && !previous.isDestroyed) {
            @Suppress("DEPRECATION")
            val reply = intent.getParcelableExtra<ResultReceiver>("receiver")
            reply?.send(0, Bundle()); finish(); return
        }
        current = java.lang.ref.WeakReference(this)
        // Owner explicitly requested screenshots for diagnosing this prerelease.
        window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        key = intent.getStringExtra("key").orEmpty()
        device = intent.getStringExtra("device").orEmpty()
        expires = intent.getLongExtra("expires", 0)
        hasCompleteLocalValues = intent.getBooleanExtra("has_complete_values", false)
        @Suppress("DEPRECATION")
        receiver = intent.getParcelableExtra("receiver")
        if (runCatching { NativeVkProtocol.payload(key, device, "prepare") }.isFailure || expires <= System.currentTimeMillis() / 1000) {
            receiver?.send(3, Bundle().apply { putString("reason", "INVALID_SESSION") })
            finish(); return
        }
        setContent { WDTTTheme { ProfileSessionPreparation(status, hasError) {
            receiver?.send(0, Bundle()); finish()
        } } }
        status = "Подготавливаю вход для выбранного профиля…"
        lifecycleScope.launch {
            try {
                localProfile = ProfileWebSessionScope.read(this@NativeVkActivity, intent)
                vkSession.prepareProfile(localProfile.identity) { VkLocalSession.clearWebData() }
                if (!isFinishing && !isDestroyed) openPreparedSession()
            } catch (timeout: TimeoutCancellationException) {
                hasError = true
                status = "Не удалось подготовить отдельный сеанс профиля. Закройте окно и повторите."
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                hasError = true
                status = "Не удалось подготовить отдельный сеанс профиля. Получение не запускалось."
            }
        }
    }

    private fun openPreparedSession() {
        restore()
        requireAccountChoice = VkAccountChoicePolicy.required(vkSession.remembered,
            CookieManager.getInstance().hasCookies(), token != null)
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() { closeRequested() }
        })
        setContent { WDTTTheme {
            Box(Modifier.fillMaxSize().background(Color.Black.copy(alpha = .55f)).systemBarsPadding().imePadding(),
                contentAlignment = Alignment.Center) {
                val loginPageOpen = page != null
                val panelModifier = if (loginPageOpen) {
                    Modifier.fillMaxSize().padding(horizontal = 1.dp, vertical = 6.dp)
                } else {
                    Modifier.fillMaxWidth().wrapContentHeight().padding(horizontal = 8.dp)
                }
                Surface(
                    panelModifier,
                    shape = RoundedCornerShape(if (loginPageOpen) 22.dp else 28.dp),
                    color = MaterialTheme.colorScheme.surfaceContainerHigh) {
                    Column(
                        Modifier.padding(
                            horizontal = if (loginPageOpen) 8.dp else 18.dp,
                            vertical = if (loginPageOpen) 12.dp else 18.dp,
                        ),
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        val journalPhases = (0 until journal.length()).map {
                            journal.optJSONObject(it)?.optString("phase").orEmpty()
                        }
                        val acquireFallbackAvailable = NativeVkAccountActions.acquireFallbackAvailable(
                            busy = busy,
                            hasError = hasError,
                            journalPhases = journalPhases,
                        )
                        val replacementConfirmationNeeded =
                            NativeVkAccountActions.replacementConfirmationNeeded(
                                hasCompleteLocalValues = hasCompleteLocalValues,
                                replacementConfirmed = replacementConfirmed,
                                hasRecoveredOperation = journal.length() > 0,
                            )
                        val accountActions = NativeVkAccountActions.forState(
                            loginPageOpen = loginPageOpen,
                            authorized = authorized,
                            hasToken = token != null,
                            acquireFallbackAvailable = acquireFallbackAvailable,
                            replacementConfirmationNeeded = replacementConfirmationNeeded,
                            logoutPending = vkSession.logoutPending,
                        )
                        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                            Text(when (loginStage) {
                                LoginStage.VK_ID -> "Вход в ВК"
                                LoginStage.MINI_APP -> "Подтверждение доступа"
                                LoginStage.CAPTCHA -> "Проверка ВК"
                                LoginStage.NONE -> "Получение ВК-хешей"
                            }, style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
                            IconButton(onClick = { closeRequested() }) {
                                Icon(Icons.Default.Close, contentDescription = "Закрыть")
                            }
                        }
                        if (loginPageOpen) {
                            Text(when (loginStage) {
                                LoginStage.VK_ID -> "Войдите в аккаунт ВК на официальной странице."
                                LoginStage.MINI_APP -> "Подтвердите доступ в уже открытой сессии ВК."
                                LoginStage.CAPTCHA -> "Пройдите проверку. Получение продолжится в этом же профиле."
                                LoginStage.NONE -> "Официальная страница ВК"
                            }, style = MaterialTheme.typography.bodyMedium)
                            Surface(shape = RoundedCornerShape(50), color = MaterialTheme.colorScheme.surfaceContainerHighest) {
                                Text("Официальная страница ВК · $origin",
                                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 7.dp),
                                    style = MaterialTheme.typography.labelMedium)
                            }
                            if (captchaState != VkCaptchaPolicy.State.IDLE && !hasError) {
                                Text(VkCaptchaPolicy.message(captchaState), style = MaterialTheme.typography.bodySmall)
                            }
                            if (hasError) Text(status, color = MaterialTheme.colorScheme.error,
                                style = MaterialTheme.typography.bodySmall)
                            AndroidView(factory = { page!! }, modifier = Modifier.fillMaxWidth().weight(1f).clip(RoundedCornerShape(18.dp)))
                        } else {
                            Surface(
                                shape = RoundedCornerShape(50),
                                color = MaterialTheme.colorScheme.surfaceContainerHighest,
                            ) {
                                Text(
                                    status,
                                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 7.dp),
                                    style = MaterialTheme.typography.labelMedium,
                                    color = if (hasError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
                                )
                            }
                            if (accountChoice != null) {
                                VkAccountChoicePanel(accountChoice!!, !busy,
                                    onContinue = {
                                        confirmedAccountToken = offeredAccountToken
                                        accountChoice = null
                                        work { continuePreparedFlow(openWindow = true) }
                                    },
                                    onLogout = { work { logout() } })
                            } else {
                            VkHashProgressPanel(
                                completed = if (replacementConfirmationNeeded) 4 else completed,
                                activeAttempt = activeHashAttempt,
                                loading = busy && !replacementConfirmationNeeded,
                                error = hasError,
                            )
                            if (accountActions.showReplace) Button(
                                onClick = {
                                    replacementConfirmed = true
                                    work { continuePreparedFlow(openWindow = true) }
                                },
                                enabled = !busy,
                                modifier = Modifier.fillMaxWidth(),
                            ) {
                                Text("Получить новые ВК-хеши")
                            } else if (accountActions.showAcquire) Button(onClick = { work { continuePreparedFlow(openWindow = true) } }, enabled = !busy,
                                modifier = Modifier.fillMaxWidth()) {
                                Text(if (journal.length() == 0) "Повторить получение" else "Продолжить безопасно")
                            } else if (accountActions.showLogin) Button(onClick = { work { if (!prepared) prepare(false); openLogin() } }, enabled = !busy,
                                modifier = Modifier.fillMaxWidth()) { Text("Войти в ВК") }
                            if (networkLabel.isNotBlank()) Text(networkLabel,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                        if (accountActions.showLogout && accountChoice == null) {
                            TextButton(onClick = { work { logout() } }, enabled = !busy) {
                                Text("Выйти из ВК")
                            }
                        }
                    }
                }
            }
            if (confirmClose) AlertDialog(onDismissRequest = { confirmClose = false },
                title = { Text("Закрыть получение?") },
                text = { Text("Уже отправленный запрос ВК нельзя отменить закрытием окна. Автоповтора не будет. Если ссылки ещё не переданы, останьтесь здесь и повторите передачу.") },
                confirmButton = { TextButton(onClick = { receiver?.send(0, Bundle()); finish() }) { Text("Закрыть") } },
                dismissButton = { TextButton(onClick = { confirmClose = false }) { Text("Назад") } })
        } }
        bound = bindService(Intent(this, NativeVkBrokerService::class.java), connection, BIND_AUTO_CREATE)
        if (!bound) { busy = false; fail("BROKER_BIND", IllegalStateException(), "Не удалось подключиться. Попробуйте ещё раз.") }
    }

    override fun onResume() {
        super.onResume()
        window.decorView.post {
            sendBroadcast(Intent("com.wdtt.plus.vk.MODERN_VK_HANDOFF").setPackage(packageName))
        }
        foreground = true
        if (!prepared && broker != null) work { prepare() }
    }
    override fun onPause() { foreground = false; captcha?.userInteraction(); super.onPause() }
    private fun closeRequested() {
        if (busy || journal.length() > 0) confirmClose = true
        else { receiver?.send(0, Bundle()); finish() }
    }
    private fun work(block: suspend () -> Unit) {
        // Clicks and a reconnecting bound service must not start overlapping login work.
        if (disposed || operationJob?.isActive == true) return
        busy = true; hasError = false
        operationJob = lifecycleScope.launch {
            try { block() }
            catch (error: TimeoutCancellationException) {
                fail(operationStage, error, "Не удалось дождаться ответа. Подробности — в «Логах».")
            }
            catch (cancelled: CancellationException) { throw cancelled }
            catch (error: Exception) {
                fail(operationStage, error, if (operationStage == "CAPTCHA")
                    "ВК запросил проверку, но не удалось её завершить. Повторные запросы не отправляются."
                    else if (operationStage == "CALL")
                    "ВК не вернул ссылку. Подробности — в «Логах»."
                    else if (operationStage in setOf("PREPARE", "IDENTITY", "PERMIT", "UPLOAD", "FINISH"))
                        "Не удалось связаться с WDTT Plus. Вход ВК сохранён — повторите позже."
                    else "Не удалось завершить действие. Подробности — в «Логах».")
            } finally { busy = false }
        }
    }
    private fun record(stage: String, error: Throwable) {
        pendingLogs.addLast(NativeVkFeedback.diagnostic(stage, error))
        while (pendingLogs.size > 32) pendingLogs.removeFirst()
        flushLogs()
    }
    private fun flushLogs() {
        val service = broker ?: return
        while (pendingLogs.isNotEmpty()) {
            try {
                service.send(Message.obtain().apply {
                    what = 2; data = Bundle().apply { putString("code", pendingLogs.first()) }
                })
                pendingLogs.removeFirst()
            } catch (_: RemoteException) { return }
        }
    }
    private fun fail(stage: String, error: Throwable, message: String) {
        record(stage, error); hasError = true; status = message
        if (captchaState == VkCaptchaPolicy.State.IDLE && journal.length() == 0 && completed == 0 && stage in SAFE_FALLBACK_STAGES) {
            dispatchSafeFallback(stage)
        }
    }
    private fun dispatchSafeFallback(stage: String) {
        if (fallbackDispatched || disposed || isFinishing || isDestroyed) return
        fallbackDispatched = true
        receiver?.send(3, Bundle().apply { putString("reason", stage.take(80)) })
        finish()
    }
    private suspend fun rpc(op: String, extra: JSONObject = JSONObject()): JSONObject {
        check(!disposed && expires > System.currentTimeMillis() / 1000) { "Разрешение устарело. Новые звонки не запускаются." }
        val service = broker ?: error("Служебный канал ещё не подключён.")
        val raw = NativeVkProtocol.payload(key, device, op, extra)
        val id = ++sequence
        val result = CompletableDeferred<JSONObject>()
        replies[id] = result
        try {
            service.send(Message.obtain().apply {
                what = 1; arg1 = id; replyTo = inbox
                data = Bundle().apply { putString("body", raw) }
            })
            val response = withTimeout(35_000) { result.await() }
            if (response.has("error")) {
                record("BACKEND_${op.uppercase()}", IllegalStateException("HTTP_${response.optInt("http", 500)}"))
                error(response.getString("error"))
            }
            return response
        } finally { replies.remove(id) }
    }
    private suspend fun prepare(openWindow: Boolean = true) {
        if (vkSession.logoutPending) {
            operationStage = "LOGOUT"
            token = null; tokenRoute = ""; authorized = false
            vkSession.finishPendingLogout { VkLocalSession.clearWebData() }
        }
        if (journal.length() > 0) {
            ensureBackendPrepared()
            // A recovered operation may only upload known results. No automatic mutation.
            authorized = true
            val phases = (0 until journal.length()).map {
                journal.getJSONObject(it).optString("phase")
            }
            if (phases.any { it !in setOf("received", "uploaded") }) {
                hasError = true
                status = "Результат предыдущего запроса неизвестен. Автоповтор отключён; подробности — в «Логах»."
            } else {
                status = "Есть сохранённые результаты. Продолжение не повторит уже выполненные запросы."
            }
        } else if (NativeVkAccountActions.replacementConfirmationNeeded(
                hasCompleteLocalValues = hasCompleteLocalValues,
                replacementConfirmed = replacementConfirmed,
                hasRecoveredOperation = false,
            )) {
            authorized = false
            status = "В профиле уже сохранены четыре хеша. Новое получение заменит их."
        } else if (token != null && token!!.expiresAt > System.currentTimeMillis()) {
            ensureBackendPrepared()
            continuePreparedFlow(openWindow)
        } else {
            status = "Войдите в аккаунт ВК внутри этого окна."
            if (openWindow) openLogin()
        }
    }
    private suspend fun ensureBackendPrepared() {
        if (prepared) return
        operationStage = "PREPARE"
        rpc("prepare")
        prepared = true
    }
    private suspend fun continuePreparedFlow(openWindow: Boolean) {
        if (token != null && token!!.expiresAt > System.currentTimeMillis()) {
            connect()
            if (NativeVkRoutePolicy.needsLogin(tokenRoute, routeStamp())) {
                authorized = false
                if (openWindow) openLogin()
            } else {
                authorizeAndGenerate()
            }
        } else {
            status = "Войдите в аккаунт ВК внутри этого окна."
            if (openWindow) openLogin()
        }
    }
    private suspend fun authorizeToken() {
        check(!vkSession.logoutPending) { "LOGOUT_PENDING" }
        operationStage = "IDENTITY"
        val saved = token ?: error("Войдите в ВК.")
        check(saved.expiresAt > System.currentTimeMillis()) { "Сессия истекла. Войдите в ВК снова." }
        status = "Завершаем вход…"
        val parts = saved.value.chunked(96)
        parts.forEachIndexed { index, part ->
            val reply = rpc("auth", JSONObject().put("i", index).put("n", parts.size).put("v", part))
            if (index == parts.lastIndex) check(reply.optString("state") == "authorized")
        }
        authorized = true
        status = "Можно получать хеши"
    }
    private suspend fun authorizeAndGenerate() {
        if (journal.length() == 0 && requireAccountChoice && confirmedAccountToken != token?.value) {
            operationStage = "ACCOUNT"
            status = "Проверяю аккаунт ВК этого профиля…"
            val saved = token ?: error("Войдите в ВК.")
            val client = http ?: error("Соединение с ВК потеряно.")
            val account = withContext(Dispatchers.IO) {
                VkAccountIdentity.fromApi(VkHttp.post(client, VkApiProtocol.USER_ENDPOINT,
                    mapOf("access_token" to saved.value, "v" to "5.199")))
            }
            check(token === saved && !vkSession.logoutPending)
            offeredAccountToken = saved.value
            accountChoice = account
            status = "Подтвердите аккаунт перед получением ВК-хешей."
            return
        }
        ensureBackendPrepared()
        authorizeToken()
        status = "Вход выполнен. Получаем четыре хеша…"
        generate()
    }
    private suspend fun connect() {
        if (network != null && http != null) return
        operationStage = "NETWORK"
        try { selectNetwork(useDefaultNetwork) }
        catch (cancelled: CancellationException) { throw cancelled }
        catch (error: Exception) {
            if (!NativeVkRoutePolicy.mayFallback(useDefaultNetwork, journal.length())) throw error
            record("DIRECT_FALLBACK", error)
            useDefaultNetwork = true
            selectNetwork(true)
        }
    }
    private fun routeStamp(): String {
        val boot = android.provider.Settings.Global.getInt(contentResolver,
            android.provider.Settings.Global.BOOT_COUNT, -1)
        return "$boot:${network?.networkHandle}:${if (useDefaultNetwork) "default" else "direct"}"
    }
    private suspend fun openLogin() {
        check(!vkSession.logoutPending) { "LOGOUT_PENDING" }
        connect()
        try { pinLoginNetwork() }
        catch (error: Exception) {
            if (!NativeVkRoutePolicy.mayFallback(useDefaultNetwork, journal.length())) throw error
            record("WEB_FALLBACK", error)
            releaseNetwork()
            useDefaultNetwork = true
            selectNetwork(true)
            pinLoginNetwork()
        }
        operationStage = "LOGIN"
        login()
    }
    private suspend fun selectNetwork(defaultNetwork: Boolean) {
        status = "Подключаемся…"
        val ready = CompletableDeferred<Unit>()
        val gate = NativeVkNetworkGate<Network>(Build.VERSION.SDK_INT >= 29)
        var kind = "сеть телефона"
        var failure = "Android не сообщил о готовой прямой сети (NET_WAIT)."
        var pendingNetwork: Network? = null
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(value: Network) = runOnUiThread {
                if (disposed || callback !== this) return@runOnUiThread
                if (network != null && network != value) {
                    // requestNetwork now tracks the new best network; old onLost is not guaranteed.
                    dropNetwork("Сеть телефона сменилась. Продолжите вход в этом окне; автоповтора запросов ВК нет.")
                }
                gate.available(value)
            }
            override fun onCapabilitiesChanged(value: Network, caps: NetworkCapabilities) = runOnUiThread {
                if (disposed || callback !== this) return@runOnUiThread
                gate.capabilities(value, caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN),
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET))
                kind = when {
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
                    else -> "мобильная сеть"
                }
                select(value)
            }
            override fun onLinkPropertiesChanged(value: Network, properties: LinkProperties) = runOnUiThread {
                if (disposed || callback !== this) return@runOnUiThread
                gate.linkProperties(value)
                select(value)
            }
            override fun onBlockedStatusChanged(value: Network, blocked: Boolean) = runOnUiThread {
                if (disposed || callback !== this) return@runOnUiThread
                gate.blocked(value, blocked)
                if (blocked) {
                    failure = "Android заблокировал прямую сеть для приложения (NET_BLOCKED). Проверьте системный запрет соединений без VPN."
                    if (network == value) dropNetwork(failure)
                    if (!ready.isCompleted) ready.completeExceptionally(IllegalStateException(failure))
                } else select(value)
            }
            private fun select(value: Network) {
                if (disposed || callback !== this || network != null || ready.isCompleted ||
                    !gate.ready(value) || pendingNetwork == value) return
                pendingNetwork = value
                val selectedKind = kind
                val owner = this
                lifecycleScope.launch {
                    var stage = "NET_HTTP"
                    try {
                        val client = withContext(Dispatchers.IO) {
                            VkHttp.client(value).also {
                                stage = "NET_SOCKET"
                                // No remote connection or VK operation. The socket factory
                                // explicitly binds this socket; no process-wide binding needed.
                                VkHttp.checkSocketAccess(it)
                            }
                        }
                        if (disposed || callback !== owner || ready.isCompleted || !gate.ready(value)) {
                            client.connectionPool.evictAll()
                            return@launch
                        }
                        // Publish both together only after a direct socket was permitted.
                        http = client; network = value
                        networkLabel = "Соединение: $selectedKind"
                        ready.complete(Unit)
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (error: Exception) {
                        if (!disposed && callback === owner && !ready.isCompleted && gate.ready(value)) {
                            val errno = generateSequence<Throwable>(error) { it.cause }
                                .take(8).filterIsInstance<android.system.ErrnoException>().firstOrNull()?.errno
                            val detail = error.javaClass.simpleName + (errno?.let { " / errno=$it" } ?: "")
                            ready.completeExceptionally(IllegalStateException(
                                "$stage / $detail", error))
                        }
                    } finally {
                        if (pendingNetwork == value) pendingNetwork = null
                    }
                }
            }
            override fun onUnavailable() = runOnUiThread {
                if (!disposed && callback === this) ready.completeExceptionally(IllegalStateException(failure))
            }
            override fun onLost(value: Network) = runOnUiThread {
                if (disposed || callback !== this) return@runOnUiThread
                gate.lost(value)
                if (network == value) dropNetwork("Сеть телефона потеряна. Запросы ВК автоматически не повторяются.")
            }
        }
        callback?.let { runCatching { cm.unregisterNetworkCallback(it) } }
        callback = cb
        try {
            if (defaultNetwork) cm.registerDefaultNetworkCallback(cb)
            else cm.requestNetwork(NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), cb, 4_000)
            try { withTimeout(if (defaultNetwork) 8_000 else 5_000) { ready.await() } }
            catch (_: TimeoutCancellationException) { error(failure) }
        } catch (error: SecurityException) {
            throw IllegalStateException("Android запретил запрос прямой сети (NET_REQUEST / SecurityException).")
        } finally {
            if (network == null && callback === cb) {
                callback = null
                runCatching { cm.unregisterNetworkCallback(cb) }
            }
        }
    }

    private fun dropNetwork(message: String) {
        network = null; http?.dispatcher?.cancelAll(); http?.connectionPool?.evictAll(); http = null
        closePage(); networkLabel = "";
        fail("NETWORK_LOST", IllegalStateException(message), "Соединение изменилось. Попробуйте ещё раз.")
    }
    private fun releaseNetwork() {
        callback?.let { runCatching { cm.unregisterNetworkCallback(it) } }; callback = null
        network = null; http?.dispatcher?.cancelAll(); http?.connectionPool?.evictAll(); http = null
        closePage()
    }

    private fun pinLoginNetwork() {
        val direct = network ?: error("Сначала выберите сеть для ВК.")
        // WebView has no per-request SocketFactory, unlike the Calls API client.
        // Never render login on the default/VPN network if process binding fails.
        val pinned = try {
            cm.boundNetworkForProcess == direct || cm.bindProcessToNetwork(direct)
        } catch (error: Exception) {
            throw IllegalStateException("Не удалось привязать окно входа: NET_WEB_BIND / ${error.javaClass.simpleName}.")
        }
        check(pinned) {
            "Android не разрешил привязку страницы входа (NET_WEB_BIND_FALSE). " +
                if (authorized) "Сохранённая сессия не удалена. Можно вернуться к кнопке получения хешей."
                else "Страница входа не открывалась; внешние приложения не запускаются."
        }
    }
    @SuppressLint("SetJavaScriptEnabled")
    private fun login(captchaUrl: String? = null) {
        closePage()
        if (captchaUrl == null) authorized = false
        status = if (captchaUrl == null) "Войдите в аккаунт ВК" else "Пройдите проверку ВК в этом окне."
        loginStage = if (captchaUrl == null) LoginStage.VK_ID else LoginStage.CAPTCHA
        val attempt = if (captchaUrl == null) VkApiProtocol.newAttempt().also { vkIdAuth = it } else null
        val view = WebView(this)
        captcha = VkInPlaceCaptcha(view, { foreground && !confirmClose && !disposed }) { state ->
            if (page === view && !disposed) {
                captchaState = state
                pendingLogs.addLast("CAPTCHA_${state.name} / READY")
                flushLogs()
            }
        }
        view.setOnTouchListener { _, event ->
            if (event.actionMasked == android.view.MotionEvent.ACTION_DOWN) captcha?.userInteraction()
            false
        }
        view.settings.apply {
            javaScriptEnabled = true; domStorageEnabled = true
            allowFileAccess = false; allowContentAccess = false
            mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
            useWideViewPort = true; loadWithOverviewMode = true
            setSupportMultipleWindows(true); javaScriptCanOpenWindowsAutomatically = false
            saveFormData = false
        }
        CookieManager.getInstance().apply { setAcceptCookie(true); setAcceptThirdPartyCookies(view, true) }
        view.webChromeClient = object : WebChromeClient() {
            override fun onCreateWindow(v: WebView?, d: Boolean, g: Boolean, m: Message?) = false
        }
        view.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(v: WebView, r: WebResourceRequest) =
                navigate(v, r.url.toString(), r.isForMainFrame)
            @Deprecated("Old WebView")
            override fun shouldOverrideUrlLoading(v: WebView, url: String) = navigate(v, url, true)
            override fun onPageStarted(v: WebView, url: String?, icon: android.graphics.Bitmap?) {
                if (navigate(v, url.orEmpty(), true)) { if (page === v) v.stopLoading() }
                else {
                    mainFrameUrl = url.orEmpty()
                    origin = Uri.parse(url).host.orEmpty()
                }
            }
            override fun shouldInterceptRequest(v: WebView, r: WebResourceRequest): WebResourceResponse? {
                if (r.url.scheme == "https" && !VkOAuthProtocol.blockResource(r.url.toString(), r.isForMainFrame)
                    && (!r.isForMainFrame || VkApiProtocol.allowedPage(r.url.toString()))) return null
                return WebResourceResponse("text/plain", "UTF-8", ByteArrayInputStream(ByteArray(0)))
            }
            override fun onReceivedSslError(v: WebView, handler: SslErrorHandler, error: SslError) {
                // Never accept an invalid certificate. WebView also reports TLS failures
                // for subresources here; cancelling one optional resource must not tear
                // down an otherwise valid VK login page.
                handler.cancel()
                if (disposed || page !== v) return
                if (captcha?.active == true && (NativeVkSslPolicy.isMainFrameFailure(mainFrameUrl, error.url) ||
                        VkCaptchaPolicy.captchaPage(error.url))) {
                    fail("CAPTCHA_WEB_TLS", IllegalStateException("WEB_TLS_MAIN"),
                        "Не удалось безопасно загрузить проверку ВК. Повторный запрос не отправлен.")
                } else if (NativeVkSslPolicy.isMainFrameFailure(mainFrameUrl, error.url)) {
                    closePage()
                    fail("WEB_TLS", IllegalStateException("WEB_TLS_MAIN"),
                        "Не удалось проверить безопасное соединение с ВК.")
                } else {
                    record("WEB_TLS_RESOURCE", IllegalStateException("WEB_TLS_RESOURCE"))
                }
            }
            override fun onReceivedError(v: WebView, r: WebResourceRequest, error: WebResourceError) {
                if (disposed || page !== v) return
                record("WEB_RESOURCE", IllegalStateException("NET_WEB_RESOURCE"))
                if (captcha?.active == true && (r.isForMainFrame || VkCaptchaPolicy.captchaPage(r.url.toString()))) {
                    fail("CAPTCHA_WEB_PAGE", IllegalStateException(), "Проверка ВК не загрузилась. Проверьте соединение.")
                } else if (r.isForMainFrame) {
                    closePage()
                    fail("WEB_PAGE", IllegalStateException(), "Не удалось загрузить ВК. Попробуйте ещё раз.")
                }
            }
            override fun onReceivedHttpError(v: WebView, r: WebResourceRequest, response: WebResourceResponse) {
                if (disposed || page !== v) return
                record("WEB_HTTP", VkHttpFailure(response.statusCode))
                if (captcha?.active == true && (r.isForMainFrame || VkCaptchaPolicy.captchaPage(r.url.toString()))) {
                    fail("CAPTCHA_WEB_HTTP", VkHttpFailure(response.statusCode), "ВК не загрузил страницу проверки. Попробуйте позже.")
                } else if (r.isForMainFrame) {
                    closePage()
                    fail("WEB_PAGE", VkHttpFailure(response.statusCode), "ВК временно недоступен. Попробуйте позже.")
                }
            }
            override fun onRenderProcessGone(v: WebView, detail: RenderProcessGoneDetail): Boolean {
                if (disposed || page !== v) return true
                val stage = if (captcha?.active == true) "CAPTCHA_WEB_RENDER" else "WEB_RENDER"
                closePage(); fail(stage, IllegalStateException(), "Окно входа закрылось. Попробуйте ещё раз."); return true
            }
        }
        view.setDownloadListener { _, _, _, _, _ -> }
        page = view
        if (captchaUrl != null) {
            check(WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER) &&
                WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)) {
                "Не удалось безопасно открыть проверку ВК. Обновите Android System WebView."
            }
            val pending = CompletableDeferred<String>().also { apiCaptchaResult = it }
            val proofNonce = java.util.UUID.randomUUID().toString()
            WebViewCompat.addWebMessageListener(view, "WDTTApiCaptchaResult", VkCaptchaPolicy.origins) { source, message, sourceOrigin, _, reply ->
                if (page !== source || loginStage != LoginStage.CAPTCHA || apiCaptchaResult !== pending ||
                    !VkCaptchaPolicy.trustedOrigin(sourceOrigin.toString()) || disposed) return@addWebMessageListener
                val value = message.data.orEmpty()
                if (value.length > 17000) return@addWebMessageListener
                val data = runCatching { JSONObject(value) }.getOrNull() ?: return@addWebMessageListener
                if (data.optString("page") == captchaUrl) {
                    reply.postMessage(JSONObject().put("observe", proofNonce).toString())
                } else if (data.optString("nonce") == proofNonce && VkApiCaptcha.validProof(data.optString("proof"))) {
                    pending.complete(data.optString("proof"))
                }
            }
            WebViewCompat.addDocumentStartJavaScript(view, VkApiCaptcha.completionScript, VkCaptchaPolicy.origins)
        }
        val url = captchaUrl ?: requireNotNull(attempt).url()
        origin = Uri.parse(url).host.orEmpty()
        view.loadUrl(url)
    }
    private fun navigate(view: WebView, raw: String, main: Boolean): Boolean {
        // Destroyed login pages must not restore a token after logout/cancellation.
        if (disposed || page !== view || vkSession.logoutPending) return true
        if (loginStage == LoginStage.CAPTCHA) return !VkApiProtocol.allowedPage(raw)
        if (VkApiProtocol.isCallback(raw)) {
            if (main) receiveVkIdCallback(view, raw)
            return true
        }
        if (VkOAuthProtocol.isCallback(raw)) {
            if (main) {
                val attempt = miniAppAuth ?: return true
                miniAppAuth = null
                val result = runCatching { VkOAuthProtocol.callback(raw, attempt.state, System.currentTimeMillis()) }
                closePage()
                result.fold(onSuccess = {
                    vkSession.rememberAuthenticatedWebSession()
                    token = it
                    tokenRoute = routeStamp()
                    val data = JSONObject().put("value", it.value).put("expires", it.expiresAt).put("route", tokenRoute)
                    work {
                        check(tokenPrefs.edit().putString("token", secrets.encrypt(data.toString())).commit()) {
                            "Не удалось сохранить сессию ВК. Звонки не создавались."
                        }
                        authorizeAndGenerate()
                    }
                }, onFailure = { fail("OAUTH_CALLBACK", it, "Не удалось завершить вход. Попробуйте ещё раз.") })
            }
            return true
        }
        if (VkOAuthProtocol.containsCredential(raw)) {
            record("OAUTH_TARGET", IllegalArgumentException()); return true
        }
        val allowed = VkApiProtocol.allowedPage(raw)
        if (!allowed && main) fail("WEB_EXTERNAL", IllegalArgumentException(), "Завершите вход в этом окне.")
        return !allowed
    }

    private fun receiveVkIdCallback(view: WebView, raw: String) {
        if (loginStage != LoginStage.VK_ID) return
        val attempt = vkIdAuth ?: return
        vkIdAuth = null // A duplicate redirect cannot advance the flow twice.
        val accepted = runCatching { VkTwoStageLoginProtocol.continueWithMiniApp(raw, attempt) }
        accepted.fold(onSuccess = { nextAttempt ->
            // The authorization code intentionally is not exchanged, persisted or sent
            // anywhere. Successful callback only establishes the official VK session in
            // this isolated WebView. The compatible Mini App token is requested next in
            // the same cookie jar and remains subject to its own state validation.
            loginStage = LoginStage.MINI_APP
            status = "Вход подтверждён. Получаем разрешение для Звонков ВК…"
            val mini = nextAttempt.also { miniAppAuth = it }
            view.post {
                if (!disposed && page === view && loginStage == LoginStage.MINI_APP) {
                    origin = "oauth.vk.ru"
                    view.loadUrl(mini.url())
                }
            }
        }, onFailure = {
            closePage()
            fail("VK_ID_CALLBACK", it, "ВК не подтвердил вход. Попробуйте ещё раз.")
        })
    }

    private suspend fun generate() {
        check(!vkSession.logoutPending) { "LOGOUT_PENDING" }
        // The profile action is the user's explicit request. Normal login continues
        // automatically; a visible button is used only for a safe recovery path.
        // Resume, service reconnect and background work never call this method.
        check(foreground) { "Вернитесь в окно получения." }
        check(authorized)
        for (index in 0 until journal.length()) {
            val entry = journal.getJSONObject(index)
            if (entry.optString("phase") == "received") upload(entry)
            check(entry.optString("phase") == "uploaded") {
                "Ответ предыдущего звонка неизвестен. Повтор запрещён; проверьте звонки в ВК."
            }
        }
        if (journal.length() < 4) {
            check(token != null && token!!.expiresAt > System.currentTimeMillis()) { "Сессия ВК истекла. Сохранённые результаты не удалены." }
            connect()
            if (NativeVkRoutePolicy.needsLogin(tokenRoute, routeStamp())) {
                // A token observed on another route can be IP-bound. Refresh through
                // the official page, never retry a Calls request with it on a new path.
                openLogin()
                return
            }
        }
        while (journal.length() < 4) {
            check(NativeVkProtocol.mayCreate((0 until journal.length()).map { journal.getJSONObject(it).optString("phase") }))
            check(foreground && network != null && http != null) { "Получение приостановлено. Продолжите в этом окне." }
            val attempt = "va1_" + VkOAuthProtocol.newAttempt().state
            val entry = JSONObject().put("a", attempt).put("phase", "reserved")
            journal.put(entry); persist()
            activeHashAttempt = journal.length().coerceIn(1, 4)
            operationStage = "PERMIT"
            val permit = rpc("permit", JSONObject().put("a", attempt))
            check(!permit.optBoolean("replayed", true) && permit.optString("state") == "committed") {
                "Эта попытка уже была разрешена ранее. Повторный звонок не отправлен."
            }
            check(foreground && network != null) { "Окно или сеть изменились. Повторный звонок не отправлен." }
            val callClient = http ?: error("Выбранная сеть потеряна. Запрос ВК не отправлен.")
            val callToken = token?.value ?: error("Сессия ВК недоступна. Запрос ВК не отправлен.")
            entry.put("phase", "dispatched"); persist() // Durable BEFORE account mutation.
            operationStage = "CALL"
            status = "Получаем ссылку ${journal.length()} из 4…"
            var result = withContext(Dispatchers.IO) {
                VkHttp.post(callClient, VkApiProtocol.START_ENDPOINT,
                    mapOf("access_token" to callToken, "v" to "5.199"))
            }
            if (result.optJSONObject("error")?.optInt("error_code") == 14) {
                operationStage = "CAPTCHA"
                // Only a definitive error 14 (no success payload) can continue the
                // same permit. One continuation maximum; NEVER retry a timeout.
                result = VkApiCaptcha.continueRejected(result, solve = { challenge ->
                    entry.put("phase", "captcha_wait"); persist()
                    pinLoginNetwork()
                    try {
                        login(challenge.url)
                        withTimeout(180_000) { requireNotNull(apiCaptchaResult).await() }
                    }
                    finally { closePage() }
                }, send = { proofFields ->
                    check(foreground && http === callClient && token?.value == callToken && network != null &&
                        expires > System.currentTimeMillis() / 1000 && !vkSession.logoutPending) {
                        "Сеть или сеанс изменились. Повторный запрос не отправлен."
                    }
                    entry.put("phase", "dispatched").put("captcha_continued", true); persist()
                    operationStage = "CALL"
                    withContext(Dispatchers.IO) {
                        VkHttp.post(callClient, VkApiProtocol.START_ENDPOINT,
                            mapOf("access_token" to callToken, "v" to "5.199") + proofFields)
                    }
                })
                if (result.optJSONObject("error")?.optInt("error_code") == 14) operationStage = "CAPTCHA"
            }
            val value = NativeVkProtocol.hash(result)
            check((0 until journal.length() - 1).none { journal.getJSONObject(it).optString("v") == value }) {
                "ВК вернул повторную ссылку. Новые звонки не запускаются."
            }
            entry.put("v", value).put("phase", "received"); persist()
            upload(entry)
            if (journal.length() < 4) delay(800)
        }
        status = "Сохраняем четыре ссылки в выбранном профиле…"
        activeHashAttempt = 0
        operationStage = "FINISH"
        val result = rpc("finish")
        val document = RemoteDocumentGateway.extractLink(result.optString("document"))
            ?: error("Backend не вернул документ профиля. Повторите передачу сохранённого результата.")
        status = "Готово. Возвращаемся в профиль WDTT Plus."
        receiver?.send(1, Bundle().apply { putString("document", document.url) })
        prefs.edit().remove("operation").commit()
        finish()
    }
    private suspend fun upload(entry: JSONObject) {
        operationStage = "UPLOAD"
        val parts = entry.getString("v").chunked(96)
        parts.forEachIndexed { index, value ->
            rpc("result", JSONObject().put("a", entry.getString("a")).put("v", value)
                .put("i", index).put("n", parts.size))
        }
        entry.put("phase", "uploaded"); persist()
        completed = (0 until journal.length()).count { journal.getJSONObject(it).optString("phase") == "uploaded" }
        activeHashAttempt = if (completed < 4) completed + 1 else 0
    }
    private fun persist() {
        val data = JSONObject().put("key", key).put("device", device).put("expires", expires).put("attempts", journal)
        check(prefs.edit().putString("operation", secrets.encrypt(data.toString())).commit()) {
            "Не удалось сохранить состояние. Запрос ВК не будет повторён."
        }
    }
    private fun restore() {
        runCatching {
            secrets.decrypt(tokenPrefs.getString("token", null).takeUnless { vkSession.logoutPending })?.let {
                val json = JSONObject(it)
                if (json.getLong("expires") > System.currentTimeMillis()) {
                    token = VkApiProtocol.Token(json.getString("value"), json.getLong("expires"))
                    tokenRoute = json.optString("route")
                }
            }
            // Never import the old shared token. A legacy ledger may be recovered
            // only for the exact same opaque operation+device, preserving its budget.
            val operation = prefs.getString("operation", null)
                ?: getSharedPreferences("native-vk-v1", MODE_PRIVATE).getString("operation", null)
            secrets.decrypt(operation)?.let {
                val json = JSONObject(it)
                if (json.optString("key") == key && json.optString("device") == device) journal = json.getJSONArray("attempts")
            }
            completed = (0 until journal.length()).count { journal.getJSONObject(it).optString("phase") == "uploaded" }
        }.onFailure { fail("RESTORE", it, "Не удалось прочитать сохранённую сессию.") }
    }
    private suspend fun logout() {
        operationStage = "LOGOUT"
        closePage()
        accountChoice = null
        confirmedAccountToken = null
        offeredAccountToken = null
        requireAccountChoice = false
        token = null; tokenRoute = ""; authorized = false
        // Same semantics as VK Android SDK logout: local token + this WebView's
        // isolated cookie jar. This does NOT claim provider-wide revocation.
        vkSession.logout { VkLocalSession.clearWebData() }
        status = "Вы вышли из ВК. Можно войти в другой аккаунт."
        if (journal.length() > 0) {
            // Preserve the old durable ledger and results. A new explicit profile
            // action obtains a fresh backend-authorized batch; never reset permits.
            receiver?.send(0, Bundle()); finish()
        } else {
            openLogin()
        }
    }
    private fun closePage() {
        apiCaptchaResult?.let { if (!it.isCompleted) it.completeExceptionally(IllegalStateException("Проверка ВК закрыта.")) }
        apiCaptchaResult = null
        captcha?.close(); captcha = null
        captchaState = VkCaptchaPolicy.State.IDLE
        vkIdAuth = null
        miniAppAuth = null
        loginStage = LoginStage.NONE
        mainFrameUrl = ""
        val view = page; page = null
        view?.stopLoading(); view?.destroy()
        if (view != null) CookieManager.getInstance().flush()
    }
    override fun onDestroy() {
        if (current.get() === this) current.clear()
        disposed = true; closePage(); http?.dispatcher?.cancelAll(); http?.connectionPool?.evictAll()
        callback?.let { runCatching { cm.unregisterNetworkCallback(it) } }
        // Keep the isolated process pinned. Never unbind it onto the VPN network.
        if (bound) unbindService(connection)
        replies.values.forEach { it.cancel() }; replies.clear()
        super.onDestroy()
    }

    private enum class LoginStage { NONE, VK_ID, MINI_APP, CAPTCHA }
}
