package com.wdtt.plus.vk

import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Bitmap
import android.net.Uri
import android.net.ConnectivityManager
import android.net.http.SslError
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.ResultReceiver
import android.view.WindowManager
import android.view.View
import android.webkit.ConsoleMessage
import android.webkit.CookieManager
import android.webkit.SslErrorHandler
import android.webkit.WebChromeClient
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.webkit.RenderProcessGoneDetail
import android.widget.FrameLayout
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import androidx.activity.compose.setContent
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Key
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInRoot
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.zIndex
import androidx.compose.ui.viewinterop.AndroidView
import com.wdtt.plus.WDTTTheme
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.launch
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import java.net.URI

/**
 * Top-level VK web container for the preferred in-app flow. The protected
 * runtime may request a short-lived Mini App token before the first guarded
 * call; no token is exposed to Android or persisted here.
 */
open class ModernVkContainerActivity : ComponentActivity() {
    private var receiver: ResultReceiver? = null
    private var session = ""
    private var page by mutableStateOf<WebView?>(null)
    private var status by mutableStateOf("Открываю официальный контейнер ВК…")
    private var loading by mutableStateOf(true)
    private var error by mutableStateOf(false)
    private var confirmClose by mutableStateOf(false)
    private var confirmReplace by mutableStateOf(false)
    private var receiverRegistered = false
    private var desktopLandingZoomed = false
    private var desktopContainerActivated = false
    private var webContentVisible by mutableStateOf(true)
    private var canLogout by mutableStateOf(false)
    private var logoutInProgress by mutableStateOf(false)
    private var completedHashes by mutableIntStateOf(0)
    private var activeHashAttempt by mutableIntStateOf(0)
    private var vkMutationStarted = false
    private var fallbackRequested by mutableStateOf(false)
    private var flowGuard = ModernVkFlowGuard()
    private var accountChoice by mutableStateOf<VkAccountIdentity?>(null)
    private var continueAccount: (() -> Unit)? = null
    private var confirmedAccountId: Long? = null
    private var replacementApproved = false
    private var waitingForConsent = false
    private var captcha: VkInPlaceCaptcha? = null
    private var captchaState by mutableStateOf(VkCaptchaPolicy.State.IDLE)
    private var captchaObserverSupported by mutableStateOf(true)
    private var captchaPageVisible by mutableStateOf(false)
    private var foreground = false
    private val captchaVisible get() = captchaState != VkCaptchaPolicy.State.IDLE || captchaPageVisible
    private val preflightHandler = Handler(Looper.getMainLooper())
    private val revealConsent = Runnable {
        if (waitingForConsent && !flowGuard.terminal && !fallbackRequested) {
            webContentVisible = true
            loading = false
        }
    }
    private val preflightTimeout = VkCaptchaTimeout {
        if (flowGuard.canFallback && !fallbackRequested && !isFinishing && !isDestroyed) {
            loading = false
            error = true
            activeHashAttempt = 0
            if (captchaVisible) {
                status = "Время ожидания проверки ВК истекло. Закройте окно и повторите позже."
                flowGuard.close()
                log("CAPTCHA / TIMEOUT")
                disposePage()
                return@VkCaptchaTimeout
            }
            status = "ВК не ответил. Перехожу к резервному способу…"
            requestSafeFallback("PREFLIGHT_TIMEOUT")
        }
    }
    private val mutationTimeout = VkCaptchaTimeout {
        if (flowGuard.mutationPossible && !isFinishing && !isDestroyed) {
            flowGuard.close()
            loading = false
            error = true
            status = "Получение остановлено: ВК не ответил вовремя. Повторные запросы не отправляются."
            log("BRIDGE / FLOW_FAILED / NONE / NONE / TIMEOUT")
            disposePage()
        }
    }
    private lateinit var localProfile: com.wdtt.plus.LocalContinuationProfile
    private val vkSession by lazy { VkLocalSession.forContext(this, localProfile) }

    private val finishReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == HANDOFF_ACTION) {
                if (fallbackRequested) finish()
                return
            }
            if (intent?.getStringExtra(EXTRA_SESSION) != session) return
            if (fallbackRequested) { finish(); return }
            val successful = intent.getBooleanExtra(EXTRA_SUCCESS, false)
            if (successful) {
                log("COMPLETE / получены четыре ВК-хеша")
                setResult(RESULT_OK)
            } else {
                log("CLOSE / новые ВК-хеши не получены")
                setResult(RESULT_CANCELED)
            }
            cancelPreflightTimeout()
            finish()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        @Suppress("DEPRECATION")
        receiver = intent.getParcelableExtra(EXTRA_RECEIVER)
        setContent { WDTTTheme { ProfileSessionPreparation(status, error) {
            receiver?.send(RESULT_CANCEL, Bundle()); finish()
        } } }
        status = "Подготавливаю вход для выбранного профиля…"
        lifecycleScope.launch {
            try {
                localProfile = ProfileWebSessionScope.read(this@ModernVkContainerActivity, intent)
                vkSession.prepareProfile(localProfile.identity) { VkLocalSession.clearWebData() }
                if (!isFinishing && !isDestroyed) openPreparedContainer()
            } catch (timeout: TimeoutCancellationException) {
                error = true
                status = "Не удалось подготовить отдельный сеанс профиля. Закройте окно и повторите."
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                error = true
                status = "Не удалось подготовить отдельный сеанс профиля. Получение не запускалось."
            }
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun openPreparedContainer() {
        // The fallback engine pins this profile process to a particular network.
        // Its saved token remains route-bound, but a NEW browser flow must not
        // inherit an obsolete Wi-Fi/mobile binding from a previous invocation.
        val connectivity = getSystemService(ConnectivityManager::class.java)
        check(connectivity.boundNetworkForProcess == null || connectivity.bindProcessToNetwork(null)) {
            "Не удалось подготовить соединение с ВК."
        }
        window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        @Suppress("DEPRECATION")
        receiver = intent.getParcelableExtra(EXTRA_RECEIVER)
        session = intent.getStringExtra(EXTRA_SESSION).orEmpty()
        confirmReplace = intent.getBooleanExtra(EXTRA_HAS_COMPLETE_VALUES, false) && !replacementApproved
        val hasRememberedSession = vkSession.remembered
        val confirmAccount = VkAccountChoicePolicy.required(hasRememberedSession, CookieManager.getInstance().hasCookies())
        val launchUrl = runCatching {
            ModernVkContainerProtocol.launchUrl(intent.getStringExtra(
                if (confirmAccount) "confirmation_url" else EXTRA_URL).orEmpty())
        }.getOrElse {
            log("LAUNCH_URL / INVALID")
            receiver?.send(RESULT_SAFE_FALLBACK, Bundle().apply {
                putString("reason", "LAUNCH_URL_INVALID")
            })
            finish()
            return
        }
        val mobileEntryUrl = intent.getStringExtra(
            if (confirmAccount) "confirmation_login_url" else "login_url").orEmpty()
        val presentationContext = intent.getStringExtra("context").orEmpty()
        if (!ModernVkContainerProtocol.validLoginUrl(mobileEntryUrl) ||
            !presentationContext.matches(Regex("[A-Za-z0-9_.-]{24,2048}"))) {
            log("LAUNCH_URL / INVALID")
            receiver?.send(RESULT_SAFE_FALLBACK, Bundle())
            finish()
            return
        }
        val pendingLogout = vkSession.logoutPending
        if (pendingLogout) confirmReplace = false
        canLogout = hasRememberedSession || pendingLogout
        webContentVisible = !hasRememberedSession && !pendingLogout
        desktopContainerActivated = hasRememberedSession
        if (!receiverRegistered) {
        registerFinishReceiver()
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (fallbackRequested) return
                val current = page
                    if (webContentVisible && !flowGuard.mutationPossible && current?.canGoBack() == true) current.goBack() else confirmClose = true
            }
        })
        }

        fun createPage(desktop: Boolean): WebView = WebView(this).apply {
            val sourcePage = this
            WebView.setWebContentsDebuggingEnabled(false)
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.databaseEnabled = false
            settings.allowFileAccess = false
            settings.allowContentAccess = false
            settings.javaScriptCanOpenWindowsAutomatically = false
            settings.setSupportMultipleWindows(false)
            settings.useWideViewPort = true
            settings.loadWithOverviewMode = true
            settings.setSupportZoom(true)
            settings.builtInZoomControls = true
            settings.displayZoomControls = false
            // Configure only an unloaded WebView. Changing UA on a loading auth
            // page makes Android reload it, potentially replaying its login redirect.
            settings.userAgentString = if (desktop) {
                ModernVkContainerProtocol.DESKTOP_USER_AGENT
            } else {
                WebSettings.getDefaultUserAgent(this@ModernVkContainerActivity)
            }
            CookieManager.getInstance().setAcceptCookie(true)
            CookieManager.getInstance().setAcceptThirdPartyCookies(this, true)
            if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
                WebViewCompat.addWebMessageListener(this, "WDTTProfileAccount", setOf("https://wdttplus.ru")) {
                        view, message, origin, isMainFrame, reply ->
                    if (!isCurrentRenderer(view) || isMainFrame || origin.scheme != "https" || origin.host != "wdttplus.ru" ||
                        origin.port !in setOf(-1, 443) ||
                        !confirmAccount || flowGuard.mutationPossible || !flowGuard.acceptsPageCallbacks ||
                        fallbackRequested || logoutInProgress) return@addWebMessageListener
                    val request = runCatching {
                        VkAccountMessage.parse(message.data.orEmpty(), presentationContext)
                    }.getOrNull() ?: return@addWebMessageListener
                    flowGuard.accept("ACCOUNT_WAIT")
                    vkSession.rememberAuthenticatedWebSession()
                    canLogout = true
                    if (confirmedAccountId == request.account.id) {
                        reply.postMessage(request.continueReply())
                    } else {
                        cancelPreflightTimeout()
                        accountChoice = request.account
                        webContentVisible = false
                        loading = false
                        status = "Подтвердите аккаунт перед получением ВК-хешей."
                        continueAccount = {
                            if (!flowGuard.mutationPossible && !logoutInProgress && page === view) {
                                confirmedAccountId = request.account.id
                                accountChoice = null
                                continueAccount = null
                                loading = true
                                status = "Подготавливаю получение ВК-хешей…"
                                armPreflightTimeout(PRE_MUTATION_TIMEOUT_MS)
                                reply.postMessage(request.continueReply())
                            }
                        }
                    }
                }
            }
            // Keep the renderer attached even while the native progress card covers it.
            // An invisible page must never receive taps intended for that card.
            setOnTouchListener { _, event ->
                if (event.actionMasked == android.view.MotionEvent.ACTION_DOWN) captcha?.userInteraction()
                !webContentVisible && !captchaVisible && captchaObserverSupported
            }
            webChromeClient = object : WebChromeClient() {
                override fun onConsoleMessage(consoleMessage: ConsoleMessage?): Boolean {
                    if (!isCurrentRenderer(sourcePage)) return true
                    ModernVkContainerProtocol.diagnosticFromConsole(consoleMessage?.message().orEmpty())
                        ?.let {
                            log(it)
                            handleBridgeDiagnostic(it)
                        }
                    return super.onConsoleMessage(consoleMessage)
                }
            }
            webViewClient = object : WebViewClient() {
                override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                    if (view !== page || !flowGuard.acceptsPageCallbacks || logoutInProgress || fallbackRequested) return true
                    val uri = request.url
                    if (
                        request.isForMainFrame &&
                        ModernVkContainerProtocol.isMiniAppLanding(uri.toString()) &&
                        !desktopContainerActivated
                    ) {
                        activateDesktopContainer(view, launchUrl) { createPage(desktop = true) }
                        return true
                    }
                    // id/login redirects also perform silent session refresh and
                    // consent. Their URL is NOT evidence that VK logged the user out.
                    if (request.isForMainFrame && !ModernVkContainerProtocol.allowedNavigation(uri.toString())) {
                        error = true
                        status = "Внешний переход заблокирован. Оставайтесь в окне ВК."
                        log("NAV_BLOCK / ${uri.scheme.orEmpty()} / ${uri.host.orEmpty()}")
                        return true
                    }
                    // Let WebView follow allowed redirects itself; restarting every
                    // navigation with loadUrl loses POST/history and rebuilds the container.
                    return false
                }

                override fun onPageStarted(view: WebView?, url: String?, favicon: Bitmap?) {
                    if (view == null || view !== page || !flowGuard.acceptsPageCallbacks || fallbackRequested) return
                    captchaPageVisible = VkCaptchaPolicy.captchaPage(url.orEmpty())
                    updateCaptchaTimers()
                    if (ModernVkContainerProtocol.isAuthenticationPage(url.orEmpty())) {
                        cancelPreflightTimeout()
                        webContentVisible = true
                    } else if (!waitingForConsent && (desktopContainerActivated || ModernVkContainerProtocol.shouldFocusDesktopLanding(url.orEmpty()))) {
                        webContentVisible = false
                    }
                    if (!ModernVkContainerProtocol.shouldFocusDesktopLanding(url.orEmpty()) && desktopLandingZoomed) {
                        view?.zoomBy(1f / DESKTOP_LANDING_ZOOM)
                        view?.scrollTo(0, 0)
                        desktopLandingZoomed = false
                    }
                    if (flowGuard.allowPageStatus) {
                        loading = true
                        error = false
                        status = "Загружаю страницу ВК…"
                    }
                    log("PAGE_START / ${runCatching { Uri.parse(url).host }.getOrNull().orEmpty()}")
                }

                override fun onPageFinished(view: WebView?, url: String?) {
                    if (!isCurrentRenderer(view)) return
                    CookieManager.getInstance().flush()
                    if (!flowGuard.acceptsPageCallbacks || fallbackRequested) return
                    if (!ModernVkContainerProtocol.isCurrentPage(view?.url, url)) return
                    if (
                        view != null &&
                        !desktopContainerActivated &&
                        ModernVkContainerProtocol.shouldPromoteAuthenticatedMobilePage(url.orEmpty())
                    ) {
                        log("MOBILE_AUTH_RETURN / ${runCatching { Uri.parse(url).path }.getOrNull().orEmpty()}")
                        activateDesktopContainer(view, launchUrl) { createPage(desktop = true) }
                        return
                    }
                    if (flowGuard.allowPageStatus) {
                    loading = desktopContainerActivated && !webContentVisible
                    status = if (ModernVkContainerProtocol.isAuthenticationPage(url.orEmpty())) {
                        "Войдите в ВК. После входа получение продолжится автоматически."
                    } else if (ModernVkContainerProtocol.shouldFocusDesktopLanding(url.orEmpty())) {
                        "Проверяю вход в ВК и подготавливаю получение…"
                    } else {
                        "Завершаю вход в ВК и подготавливаю получение хешей…"
                    }
                    }
                    focusDesktopLanding(view, url.orEmpty())
                    if (flowGuard.allowPageStatus && ModernVkContainerProtocol.isMiniAppLanding(url.orEmpty())) {
                        // Repeated PAGE_READY is not progress and must not prolong
                        // preparation indefinitely. Auth pages explicitly pause it.
                        preflightTimeout.armIfIdle(PREFLIGHT_TIMEOUT_MS)
                        updateCaptchaTimers()
                    }
                    log("PAGE_READY / ${runCatching { Uri.parse(url).host }.getOrNull().orEmpty()}")
                }

                override fun onReceivedError(
                    view: WebView?,
                    request: WebResourceRequest?,
                    resourceError: WebResourceError?,
                ) {
                    if (!isCurrentRenderer(view) || request == null) return
                    if (!request.isForMainFrame && !(captchaVisible && VkCaptchaPolicy.captchaPage(request.url.toString()))) return
                    loading = false
                    error = true
                    status = "Страница ВК не загрузилась. Проверьте сеть и повторите."
                    log("WEB / ${resourceError?.errorCode ?: 0}")
                    requestSafeFallback("WEB_${resourceError?.errorCode ?: 0}")
                }

                override fun onRenderProcessGone(view: WebView, detail: RenderProcessGoneDetail): Boolean {
                    if (!isCurrentRenderer(view)) return true
                    if (flowGuard.canFallback && !captchaVisible) {
                        requestSafeFallback("RENDERER_GONE")
                    } else {
                        flowGuard.close()
                        loading = false
                        error = true
                        webContentVisible = false
                        status = "Окно ВК остановлено системой. Повторные запросы не отправляются."
                        log("BRIDGE / FLOW_FAILED / NONE / NONE / RENDERER")
                        disposePage()
                    }
                    return true
                }

                override fun onReceivedHttpError(view: WebView, request: WebResourceRequest, response: WebResourceResponse) {
                    if (!isCurrentRenderer(view) || !(request.isForMainFrame ||
                        (captchaVisible && VkCaptchaPolicy.captchaPage(request.url.toString())))) return
                    loading = false
                    error = true
                    status = "ВК не загрузил страницу проверки. Попробуйте позже."
                    log("WEB / HTTP_${response.statusCode}")
                    requestSafeFallback("HTTP_${response.statusCode}")
                }

                override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler, sslError: SslError?) {
                    handler.cancel()
                    if (!isCurrentRenderer(view)) return
                    val failedUrl = sslError?.url.orEmpty()
                    val currentUrl = view?.url.orEmpty()
                    val failedHost = runCatching { Uri.parse(failedUrl).host }.getOrNull().orEmpty()
                    val isTopLevel = failedUrl.isNotBlank() && currentUrl.substringBefore('#') == failedUrl.substringBefore('#')
                    if (isTopLevel || (captchaVisible && VkCaptchaPolicy.captchaPage(failedUrl))) {
                        loading = false
                        error = true
                        status = "Защищённое соединение со страницей ВК не подтверждено."
                        requestSafeFallback("SSL_${sslError?.primaryError ?: -1}")
                    }
                    val category = if (ModernVkContainerProtocol.isVkTelemetryHost(failedHost)) {
                        "SSL_TELEMETRY"
                    } else {
                        "SSL"
                    }
                    log("$category / ${sslError?.primaryError ?: -1} / ${failedHost.take(80)} / ${if (isTopLevel) "MAIN" else "RESOURCE"}")
                }
            }
        }
        val webView = createPage(desktop = hasRememberedSession)
        attachPage(webView)
        if (!confirmReplace && !pendingLogout) {
            webView.loadUrl(ModernVkContainerProtocol.initialLaunchUrl(
                desktopUrl = launchUrl,
                mobileLoginUrl = mobileEntryUrl,
                hasRememberedSession = hasRememberedSession,
            ))
        }
        if (hasRememberedSession && !confirmReplace) armPreflightTimeout()

        setContent {
            WDTTTheme {
                val compact = !webContentVisible && !captchaVisible && captchaObserverSupported
                var rootOffset by remember { mutableStateOf(IntOffset.Zero) }
                BoxWithConstraints(
                    Modifier.fillMaxSize().background(Color.Black.copy(alpha = 0.58f))
                        .systemBarsPadding().imePadding().onGloballyPositioned {
                            val position = it.positionInRoot()
                            rootOffset = IntOffset(position.x.toInt(), position.y.toInt())
                        },
                    contentAlignment = Alignment.Center,
                ) {
                    val density = LocalDensity.current
                    var browserOffset by remember { mutableStateOf(IntOffset.Zero) }
                    var browserSize by remember { mutableStateOf(IntSize.Zero) }
                    // A single composition site for the entire session. Never remove
                    // AndroidView when login turns into compact progress: detached
                    // WebViews may suspend Bridge callbacks/timers on OEM firmware.
                    val width = if (browserSize.width > 0) with(density) { browserSize.width.toDp() } else maxWidth
                    val height = if (browserSize.height > 0) with(density) { browserSize.height.toDp() } else maxHeight
                    if (!fallbackRequested && !logoutInProgress && page != null) AndroidView(
                        factory = { FrameLayout(it) },
                        update = { host ->
                            val current = page
                            if (host.getChildAt(0) !== current) {
                                host.removeAllViews()
                                current?.let { host.addView(it, FrameLayout.LayoutParams(-1, -1)) }
                            }
                            host.importantForAccessibility = if (compact) View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS else View.IMPORTANT_FOR_ACCESSIBILITY_AUTO
                        },
                        modifier = Modifier.align(Alignment.TopStart).offset { browserOffset }.size(width, height)
                            .clip(RoundedCornerShape(18.dp)).alpha(if (compact) 0f else 1f)
                            .zIndex(if (compact) -1f else 1f),
                    )
                    Surface(
                        modifier = (if (compact) {
                            Modifier.fillMaxWidth().widthIn(max = 560.dp).wrapContentHeight()
                                .padding(horizontal = 12.dp)
                        } else {
                            Modifier.fillMaxSize().padding(horizontal = 1.dp, vertical = 6.dp)
                        }).animateContentSize(animationSpec = tween(280)),
                        shape = RoundedCornerShape(22.dp),
                        color = MaterialTheme.colorScheme.surfaceContainerHigh,
                    ) {
                        Column(
                            modifier = (if (compact) Modifier.wrapContentHeight() else Modifier.fillMaxSize())
                                .padding(
                                    horizontal = if (compact) 18.dp else 8.dp,
                                    vertical = if (compact) 16.dp else 12.dp,
                                ),
                            verticalArrangement = Arrangement.spacedBy(if (compact) 12.dp else 8.dp),
                        ) {
                            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    if (compact) "ВК-хеши" else "Получение ВК-хешей",
                                    style = MaterialTheme.typography.titleLarge,
                                    modifier = Modifier.weight(1f),
                                )
                                if (canLogout && accountChoice == null) {
                                    TextButton(
                                        onClick = { logoutVkSession() },
                                        enabled = !logoutInProgress && !fallbackRequested,
                                    ) { Text("Выйти из ВК") }
                                }
                                IconButton(onClick = { confirmClose = true }, enabled = !fallbackRequested) {
                                    Icon(Icons.Default.Close, contentDescription = "Закрыть")
                                }
                            }
                            Text(
                                if (compact) {
                                    "Получение внутри приложения"
                                } else {
                                    "Войдите в ВК на официальной странице. Остальное приложение выполнит автоматически."
                                },
                                style = MaterialTheme.typography.bodySmall,
                                color = if (error) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Surface(
                                shape = RoundedCornerShape(50),
                                color = MaterialTheme.colorScheme.surfaceContainerHighest,
                            ) {
                                Text(
                                    if (captchaVisible && !error) VkCaptchaPolicy.message(captchaState.takeUnless {
                                        it == VkCaptchaPolicy.State.IDLE
                                    } ?: VkCaptchaPolicy.State.MANUAL) else status,
                                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 7.dp),
                                    style = MaterialTheme.typography.labelMedium,
                                )
                            }
                            if (accountChoice != null) {
                                VkAccountChoicePanel(accountChoice!!, !logoutInProgress,
                                    onContinue = { continueAccount?.invoke() }, onLogout = { logoutVkSession() })
                            } else if (compact) {
                                VkHashProgressPanel(
                                    completed = completedHashes,
                                    activeAttempt = activeHashAttempt,
                                    loading = loading,
                                    error = error,
                                )
                            } else {
                                Box(Modifier.fillMaxWidth().weight(1f).onGloballyPositioned {
                                    // Root padding is outside BoxWithConstraints' content.
                                    val position = it.positionInRoot()
                                    browserOffset = IntOffset(position.x.toInt(), position.y.toInt()) - rootOffset
                                    browserSize = it.size
                                }) {
                                if (loading) {
                                    Surface(
                                        modifier = Modifier.align(Alignment.Center),
                                        shape = RoundedCornerShape(18.dp),
                                        color = MaterialTheme.colorScheme.surface.copy(alpha = 0.92f),
                                    ) {
                                        Column(
                                            Modifier.padding(horizontal = 24.dp, vertical = 18.dp),
                                            horizontalAlignment = Alignment.CenterHorizontally,
                                        ) {
                                            CircularProgressIndicator()
                                            Spacer(Modifier.height(10.dp))
                                            Text("Загрузка…")
                                        }
                                    }
                                }
                            }
                            }
                        }
                    }
                }
                if (confirmClose) {
                    AlertDialog(
                        onDismissRequest = { confirmClose = false },
                        title = { Text("Закрыть получение?") },
                        text = { Text("Уже отправленный запрос ВК нельзя отменить закрытием окна. Автоматического повтора не будет.") },
                        confirmButton = {
                            TextButton(onClick = {
                                receiver?.send(RESULT_CANCEL, Bundle())
                                finish()
                            }) { Text("Закрыть") }
                        },
                        dismissButton = {
                            TextButton(onClick = { confirmClose = false }) { Text("Назад") }
                        },
                    )
                }
                if (confirmReplace) {
                    AlertDialog(
                        onDismissRequest = {},
                        title = { Text("Заменить ВК-хеши?") },
                        text = { Text("В профиле уже заполнены четыре ВК-хеша. Приложение создаст четыре новые ссылки и заменит текущие после успешного завершения.") },
                        confirmButton = {
                            TextButton(onClick = {
                                confirmReplace = false
                                replacementApproved = true
                                val remembered = hasRememberedSession
                                canLogout = remembered
                                webContentVisible = !remembered
                                desktopContainerActivated = remembered
                                page?.loadUrl(
                                    ModernVkContainerProtocol.initialLaunchUrl(
                                        launchUrl,
                                        mobileEntryUrl,
                                        remembered,
                                    ),
                                )
                                if (remembered) armPreflightTimeout()
                                log("REPLACE_CONFIRMED")
                            }) { Text("Получить новые") }
                        },
                        dismissButton = {
                            TextButton(onClick = {
                                receiver?.send(RESULT_CANCEL, Bundle())
                                finish()
                            }) { Text("Назад") }
                        },
                    )
                }
            }
        }
        log("OPEN / STRICT_BRIDGE_V1")
        // Finish an interrupted local logout before loading any VK page.
        if (pendingLogout) logoutVkSession()
    }

    private fun registerFinishReceiver() {
        val filter = IntentFilter(FINISH_ACTION).apply { addAction(HANDOFF_ACTION) }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(finishReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(finishReceiver, filter)
        }
        receiverRegistered = true
    }

    private fun focusDesktopLanding(view: WebView?, url: String) {
        if (view == null || desktopLandingZoomed || !ModernVkContainerProtocol.shouldFocusDesktopLanding(url)) return
        desktopLandingZoomed = true
        view.postDelayed({
            if (isFinishing || isDestroyed || page !== view) return@postDelayed
            view.zoomBy(DESKTOP_LANDING_ZOOM)
            view.postDelayed({
                if (isFinishing || isDestroyed || page !== view) return@postDelayed
                val centeredX = (view.width * (DESKTOP_LANDING_ZOOM - 1f) / 2f).toInt()
                view.scrollTo(centeredX, 0)
            }, 120L)
        }, 180L)
    }

    private fun isCurrentRenderer(view: WebView?): Boolean =
        view != null && view === page && !flowGuard.containerHandoffPending

    private fun attachPage(view: WebView) {
        page = view
        captcha = VkInPlaceCaptcha(view, { foreground && !confirmClose && !logoutInProgress },
            apiBridgeEnabled = true, changed = { state ->
                if (isCurrentRenderer(view)) onCaptchaState(state)
            })
        captchaObserverSupported = captcha?.supported == true
    }

    private fun activateDesktopContainer(view: WebView, launchUrl: String, createPage: () -> WebView) {
        if (!isCurrentRenderer(view) || !flowGuard.beginContainerHandoff()) return
        CookieManager.getInstance().flush()
        canLogout = true
        webContentVisible = false
        desktopContainerActivated = true
        loading = true
        status = "Проверяю вход в ВК и подготавливаю получение…"
        log("MOBILE_AUTH_COMPLETE / DESKTOP_BRIDGE")
        // Leave the navigation callback before retiring its renderer. The new
        // renderer uses the SAME profile's cookie jar, not a new login/storage.
        // Only the WebView child changes; the Activity/progress window stays put.
        preflightHandler.post {
            if (page !== view || isFinishing || isDestroyed || fallbackRequested || logoutInProgress ||
                !flowGuard.completeContainerHandoff()) return@post
            disposePage()
            desktopLandingZoomed = false
            try {
                attachPage(createPage())
                page?.loadUrl(launchUrl)
                armPreflightTimeout()
            } catch (_: Exception) {
                requestSafeFallback("CONTAINER_START_FAILED")
            }
        }
    }

    private fun handleBridgeDiagnostic(message: String) {
        if (fallbackRequested || isFinishing || isDestroyed || logoutInProgress) return
        val stage = message.substringAfter("BRIDGE / ").substringBefore(" / ")
        if (!flowGuard.accept(stage)) return
        // Only an authenticated Bridge stage confirms the saved-session hint.
        // In particular AUTH_READY repairs hints erased by older APKs on consent.
        vkSession.observeBridgeStage(stage)
        if (vkSession.remembered) canLogout = true
        if (flowGuard.terminal || stage == "DELIVER_FAILED") {
            mutationTimeout.cancel()
        }
        when {
            stage == "INIT_WAIT" -> {
                status = "Подключаюсь к ВК для получения хешей…"
                preflightTimeout.armIfIdle(PREFLIGHT_TIMEOUT_MS)
                updateCaptchaTimers()
            }
            stage == "SESSION_WAIT" -> status = "Проверяю сохранённый вход в ВК…"
            stage == "PROFILE_WAIT" -> status = "Подтверждаю аккаунт ВК…"
            stage == "ACCOUNT_WAIT" -> if (accountChoice == null) armPreflightTimeout(15_000L)
            stage == "ACCOUNT_READY" -> armPreflightTimeout(PRE_MUTATION_TIMEOUT_MS)
            message.startsWith("BRIDGE / CALL_SUPPORT /") &&
                message.endsWith("/ UNSUPPORTED") -> {
                loading = false
                error = true
                status = "Этот способ не поддерживается. Перехожу к резервному…"
                requestSafeFallback("CALL_UNSUPPORTED")
            }
            message.startsWith("BRIDGE / AUTH_REQUEST /") -> {
                cancelPreflightTimeout()
                waitingForConsent = true
                loading = true
                error = false
                completedHashes = 0
                activeHashAttempt = 0
                preflightHandler.removeCallbacks(revealConsent)
                preflightHandler.postDelayed(revealConsent, 900L)
                status = "Подтвердите доступ на странице ВК. Он нужен только для создания ссылок."
            }
            message.startsWith("BRIDGE / AUTH_READY /") -> {
                loading = true
                error = false
                webContentVisible = false
                status = "Доступ подтверждён. Получаю четыре ВК-хеша…"
                waitingForConsent = false
                preflightHandler.removeCallbacks(revealConsent)
                armPreflightTimeout(PRE_MUTATION_TIMEOUT_MS)
            }
            message.startsWith("BRIDGE / AUTH_FAILED /") -> {
                cancelPreflightTimeout()
                loading = false
                error = true
                activeHashAttempt = 0
                status = "Доступ не подтверждён. Перехожу к резервному способу…"
                requestSafeFallback("AUTH_FAILED")
            }
            message.startsWith("BRIDGE / CLAIM_BUSY /") -> {
                cancelPreflightTimeout()
                loading = false
                error = true
                activeHashAttempt = 0
                status = "Первичный вход ВК перезапустился. Перехожу к резервному способу…"
                requestSafeFallback("CLAIM_BUSY")
            }
            message.startsWith("BRIDGE / CLAIM_BLOCKED /") -> {
                cancelPreflightTimeout()
                loading = false
                error = true
                activeHashAttempt = 0
                status = "Запрос ВК уже отправлен. Автоматический повтор отключён."
            }
            message.startsWith("BRIDGE / CLAIM_WAIT /") -> {
                loading = true
                error = false
                webContentVisible = false
                status = "Завершаю вход и подготавливаю получение…"
                armPreflightTimeout(PRE_MUTATION_TIMEOUT_MS)
            }
            message.startsWith("BRIDGE / CLAIM_READY /") -> {
                loading = true
                error = false
                webContentVisible = false
                status = "Получение подготовлено. Создаю первую ссылку…"
                armPreflightTimeout(PRE_MUTATION_TIMEOUT_MS)
            }
            message.startsWith("BRIDGE / AUTO_READY /") -> {
                loading = true
                error = false
                completedHashes = 0
                activeHashAttempt = 1
                status = "Вход выполнен. Получаю четыре ВК-хеша…"
                armPreflightTimeout(PRE_MUTATION_TIMEOUT_MS)
            }
            message.startsWith("BRIDGE / PERMIT_WAIT_") -> {
                // Once a permit request is in flight its outcome may be unknown.
                // Do not start another engine, even if CALL_SENT has not arrived.
                cancelPreflightTimeout()
                activeHashAttempt = stage.substringAfterLast('_').toIntOrNull() ?: 1
                loading = true
                status = "Подготавливаю ссылку $activeHashAttempt из 4…"
                armMutationTimeout()
            }
            message.startsWith("BRIDGE / CALL_SENT_") -> {
                cancelPreflightTimeout()
                vkMutationStarted = true
                loading = true
                error = false
                val attempt = message.substringAfter("CALL_SENT_").substringBefore('/').trim()
                    .toIntOrNull()?.coerceIn(1, 4)
                activeHashAttempt = attempt ?: 0
                armMutationTimeout()
                status = if (attempt == null) {
                    "Создаю ссылку ВК Звонков…"
                } else {
                    "Создаю ссылку $attempt из 4…"
                }
            }
            message.startsWith("BRIDGE / CALL_HASH_") -> {
                armMutationTimeout()
                val count = message.substringAfterLast('/').trim().toIntOrNull()?.coerceIn(1, 4)
                if (count != null) {
                    completedHashes = count
                    activeHashAttempt = if (count < 4) count + 1 else 0
                }
                status = if (count == null) "Ссылка ВК Звонков получена…" else "Получено $count из 4 ВК-хешей…"
            }
            message.startsWith("BRIDGE / PREP_FAILED /") ||
                message.startsWith("BRIDGE / FLOW_FAILED /") -> {
                cancelPreflightTimeout()
                preflightHandler.removeCallbacks(revealConsent)
                waitingForConsent = false
                webContentVisible = false
                loading = false
                error = true
                status = if (flowGuard.mutationPossible) {
                    "Получение остановлено. Новые запросы автоматически не отправляются."
                } else {
                    "Не удалось подготовить получение. Открываю резервный способ…"
                }
                requestSafeFallback("PREPARATION_FAILED")
            }
            message.startsWith("BRIDGE / DELIVER_WAIT /") -> {
                armMutationTimeout()
                loading = true
                status = "Сохраняю четыре ВК-хеша в профиле…"
            }
            message.startsWith("BRIDGE / DELIVER_FAILED /") -> {
                loading = false
                error = true
                status = "Хеши созданы, но не переданы. Повторите только сохранение на странице ВК."
                webContentVisible = true
            }
            message.startsWith("BRIDGE / CALL_TIMEOUT_") -> {
                loading = false
                error = true
                activeHashAttempt = 0
                status = "ВК не ответил на создание ссылки. Закройте окно и повторите позже."
            }
            message.startsWith("BRIDGE / CALL_FAILED_") -> {
                loading = false
                error = true
                activeHashAttempt = 0
                status = if (message.split('/').getOrNull(3)?.trim() == "14")
                    "Проверка ВК не завершена. Повторные запросы не отправляются."
                else "ВК отклонил создание ссылки. Подробности сохранены в журнале."
            }
            message.startsWith("BRIDGE / CALL_INVALID_") ||
                message.startsWith("BRIDGE / CALL_EMPTY_") -> {
                loading = false
                error = true
                activeHashAttempt = 0
                status = "ВК не вернул ссылку звонка. Новая попытка автоматически не запускается."
            }
        }
    }

    private fun requestSafeFallback(reason: String) {
        if (captchaVisible) {
            loading = false
            error = true
            webContentVisible = true
            status = "Не удалось продолжить проверку ВК. Ошибка на странице оставлена видимой; автоматический повтор отключён."
            cancelPreflightTimeout()
            log("CAPTCHA / ERROR")
            return
        }
        if (!flowGuard.canFallback || vkMutationStarted || fallbackRequested || isFinishing || isDestroyed) return
        cancelPreflightTimeout()
        preflightHandler.removeCallbacks(revealConsent)
        fallbackRequested = true
        flowGuard.close()
        webContentVisible = false
        loading = true
        error = false
        waitingForConsent = false
        status = "Открываю резервный способ…"
        // Destroy the old renderer before notifying the next engine. A delayed
        // token/claim response must not create links after the handoff.
        disposePage()
        log("SAFE_FALLBACK / ${reason.take(80)}")
        receiver?.send(RESULT_SAFE_FALLBACK, Bundle().apply {
            putString("reason", reason.take(80))
        })
        // The replacement Activity closes this presentation once it is visible.
        // Until then keep one compact card, instead of flashing the profile UI.
    }

    private fun logoutVkSession() {
        if (logoutInProgress) return
        val canLoginAgain = !flowGuard.mutationPossible && !fallbackRequested
        cancelPreflightTimeout()
        preflightHandler.removeCallbacks(revealConsent)
        waitingForConsent = false
        logoutInProgress = true
        flowGuard.close()
        continueAccount = null
        accountChoice = null
        confirmedAccountId = null
        disposePage()
        webContentVisible = false
        loading = true
        error = false
        completedHashes = 0
        activeHashAttempt = 0
        status = "Выхожу из ВК…"
        lifecycleScope.launch {
            try {
                vkSession.logout { VkLocalSession.clearWebData() }
                canLogout = false
                log("LOGOUT / COMPLETE")
                // A committed or ambiguous request cannot be reset by logging out.
                if (canLoginAgain && !isFinishing && !isDestroyed) {
                    flowGuard = ModernVkFlowGuard()
                    logoutInProgress = false
                    loading = true
                    openPreparedContainer()
                } else {
                    receiver?.send(RESULT_CANCEL, Bundle())
                    finish()
                }
            } catch (timeout: TimeoutCancellationException) {
                showLogoutFailure()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                showLogoutFailure()
            } finally {
                logoutInProgress = false
            }
        }
    }

    private fun showLogoutFailure() {
        loading = false
        error = true
        canLogout = true
        status = "Не удалось полностью выйти из ВК. Нажмите «Выйти из ВК» ещё раз. Получение остановлено."
        log("LOGOUT / FAILED")
    }

    private fun armPreflightTimeout(delayMillis: Long = PREFLIGHT_TIMEOUT_MS) {
        preflightTimeout.arm(delayMillis)
        updateCaptchaTimers()
    }

    private fun armMutationTimeout() {
        mutationTimeout.arm(90_000L)
        updateCaptchaTimers()
    }

    private fun cancelPreflightTimeout() {
        preflightTimeout.cancel()
    }

    private fun updateCaptchaTimers() {
        preflightTimeout.pause(captchaVisible)
        mutationTimeout.pause(captchaVisible)
    }

    private fun onCaptchaState(state: VkCaptchaPolicy.State) {
        if (page == null || fallbackRequested || logoutInProgress || isFinishing) return
        captchaState = state
        if (state == VkCaptchaPolicy.State.IDLE && captchaObserverSupported) captchaPageVisible = false
        updateCaptchaTimers()
        if (state != VkCaptchaPolicy.State.IDLE) loading = false
        log("CAPTCHA / ${state.name}")
    }

    override fun onResume() { super.onResume(); foreground = true }
    override fun onPause() { foreground = false; captcha?.userInteraction(); super.onPause() }

    private fun log(message: String) {
        receiver?.send(RESULT_LOG, Bundle().apply { putString("message", message.take(240)) })
    }

    override fun onDestroy() {
        mutationTimeout.cancel()
        cancelPreflightTimeout()
        preflightHandler.removeCallbacks(revealConsent)
        if (receiverRegistered) runCatching { unregisterReceiver(finishReceiver) }
        CookieManager.getInstance().flush()
        disposePage()
        super.onDestroy()
    }

    override fun finish() {
        super.finish()
        @Suppress("DEPRECATION")
        overridePendingTransition(0, 0)
    }

    private fun disposePage() {
        preflightTimeout.cancel()
        mutationTimeout.cancel()
        val previous = page
        page = null // Ignore callbacks synchronously emitted by stopLoading/close.
        captcha?.close(); captcha = null
        captchaState = VkCaptchaPolicy.State.IDLE
        captchaPageVisible = false
        continueAccount = null
        accountChoice = null
        previous?.apply {
            webChromeClient = null
            webViewClient = WebViewClient()
            stopLoading()
            (parent as? android.view.ViewGroup)?.removeView(this)
            destroy()
        }
    }

    companion object {
        private const val EXTRA_URL = "url"
        private const val EXTRA_SESSION = "session"
        private const val EXTRA_RECEIVER = "receiver"
        private const val EXTRA_HAS_COMPLETE_VALUES = "has_complete_values"
        private const val EXTRA_SUCCESS = "success"
        private const val FINISH_ACTION = "com.wdtt.plus.vk.MODERN_VK_FINISH"
        private const val HANDOFF_ACTION = "com.wdtt.plus.vk.MODERN_VK_HANDOFF"
        private const val DESKTOP_LANDING_ZOOM = 1.7f
        private const val PREFLIGHT_TIMEOUT_MS = 75_000L
        private const val PRE_MUTATION_TIMEOUT_MS = 25_000L
        private const val RESULT_CANCEL = 0
        private const val RESULT_LOG = 2
        private const val RESULT_SAFE_FALLBACK = 3
    }
}

@Composable
internal fun VkHashProgressPanel(
    completed: Int,
    activeAttempt: Int,
    loading: Boolean,
    error: Boolean,
) {
    val pulse by rememberInfiniteTransition(label = "vk-hash-progress").animateFloat(
        initialValue = 0.38f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 720),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "active-segment",
    )
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        color = MaterialTheme.colorScheme.surfaceContainerHighest,
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Surface(
                    modifier = Modifier.size(42.dp),
                    shape = RoundedCornerShape(14.dp),
                    color = MaterialTheme.colorScheme.primaryContainer,
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(
                            Icons.Default.Key,
                            contentDescription = null,
                            modifier = Modifier.size(22.dp),
                            tint = MaterialTheme.colorScheme.onPrimaryContainer,
                        )
                    }
                }
                Column(Modifier.weight(1f)) {
                    Text(
                        "Получение ВК-хешей",
                        style = MaterialTheme.typography.titleSmall,
                    )
                    Text(
                        "Четыре ссылки создаются по очереди",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(7.dp),
            ) {
                repeat(4) { index ->
                    val number = index + 1
                    val segmentColor = when {
                        index < completed -> MaterialTheme.colorScheme.primary
                        error && number == activeAttempt -> MaterialTheme.colorScheme.error
                        loading && number == activeAttempt ->
                            MaterialTheme.colorScheme.primary.copy(alpha = pulse)
                        else -> MaterialTheme.colorScheme.outlineVariant
                    }
                    Box(
                        Modifier.weight(1f).height(9.dp)
                            .clip(RoundedCornerShape(50))
                            .background(segmentColor),
                    )
                }
            }
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    when {
                        completed == 4 -> "Готово"
                        error -> "Получение остановлено"
                        loading && activeAttempt > 0 -> "Получаю ссылку $activeAttempt из 4"
                        else -> "Подготавливаю получение"
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (error) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                    modifier = Modifier.weight(1f),
                )
                Text(
                    "$completed / 4",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
        }
    }
}

internal object ModernVkContainerProtocol {
    private const val DIAGNOSTIC_PREFIX = "[WDTT_VK_DIAG]"
    const val DESKTOP_USER_AGENT =
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

    /** Validate the provider destination, then open it byte-for-byte. */
    fun launchUrl(raw: String): String {
        val source = URI(raw)
        require(raw.length <= 4096 && source.scheme == "https" && source.host == "vk.ru")
        require(source.rawUserInfo == null && source.port in setOf(-1, 443))
        require(source.path == "/app54670800")
        return raw
    }

    fun allowedNavigation(raw: String): Boolean {
        val uri = runCatching { URI(raw) }.getOrNull() ?: return false
        if (uri.scheme != "https" || uri.rawUserInfo != null || uri.port !in setOf(-1, 443)) return false
        val host = uri.host?.lowercase().orEmpty()
        return host == "vk.ru" || host.endsWith(".vk.ru") ||
            host == "vk.com" || host.endsWith(".vk.com") ||
            host == "wdttplus.ru" || host.endsWith(".wdttplus.ru")
    }

    fun validLoginUrl(raw: String): Boolean = runCatching {
        val uri = URI(raw)
        raw.length <= 4096 && uri.scheme == "https" && uri.host == "m.vk.ru" &&
            uri.rawPath == "/login" && uri.rawUserInfo == null && uri.port in setOf(-1, 443)
    }.getOrDefault(false)

    fun isMiniAppLanding(raw: String): Boolean {
        val uri = runCatching { URI(raw) }.getOrNull() ?: return false
        val host = uri.host?.lowercase().orEmpty()
        return uri.scheme == "https" &&
            (host == "vk.ru" || host == "www.vk.ru" || host == "m.vk.ru") &&
            uri.path == "/app54670800"
    }

    fun isAuthenticationPage(raw: String): Boolean {
        val uri = runCatching { URI(raw) }.getOrNull() ?: return false
        val host = uri.host?.lowercase().orEmpty()
        if (uri.scheme != "https") return false
        return host == "id.vk.ru" || host.endsWith(".id.vk.ru") ||
            host == "id.vk.com" || host.endsWith(".id.vk.com") ||
            host == "login.vk.ru" || host.endsWith(".login.vk.ru") ||
            host == "login.vk.com" || host.endsWith(".login.vk.com") ||
            ((host == "m.vk.ru" || host == "vk.ru" || host == "www.vk.ru") &&
                uri.path.orEmpty().startsWith("/login"))
    }

    fun shouldPromoteAuthenticatedMobilePage(raw: String): Boolean {
        val uri = runCatching { URI(raw) }.getOrNull() ?: return false
        if (uri.scheme != "https" || uri.host?.lowercase() != "m.vk.ru") return false
        val path = uri.path.orEmpty().trimEnd('/')
        return path.isEmpty() || path == "/feed"
    }

    fun shouldFocusDesktopLanding(raw: String): Boolean {
        val uri = runCatching { URI(raw) }.getOrNull() ?: return false
        val host = uri.host?.lowercase().orEmpty()
        return uri.scheme == "https" &&
            (host == "vk.ru" || host == "www.vk.ru") &&
            uri.path == "/app54670800"
    }

    fun diagnosticFromConsole(raw: String): String? {
        if (!raw.startsWith(DIAGNOSTIC_PREFIX)) return null
        val payload = raw.removePrefix(DIAGNOSTIC_PREFIX).trim()
            .replace(Regex("https?://\\S+", RegexOption.IGNORE_CASE), "URL")
            .replace(Regex("[A-Za-z0-9_-]{16,}"), "VALUE")
            .replace(Regex("[\\r\\n\\t]+"), " ")
            .take(180)
        if (payload.isBlank()) return null
        return "BRIDGE / $payload"
    }

    fun isVkTelemetryHost(host: String): Boolean =
        host.equals("akashi.vk-portal.net", ignoreCase = true)

    fun initialLaunchUrl(
        desktopUrl: String,
        mobileLoginUrl: String,
        hasRememberedSession: Boolean,
    ): String = if (hasRememberedSession) desktopUrl else mobileLoginUrl

    fun isCurrentPage(current: String?, completed: String?): Boolean =
        !current.isNullOrBlank() && !completed.isNullOrBlank() &&
            current.substringBefore('#') == completed.substringBefore('#')


}
