package com.wdtt.plus

import android.annotation.SuppressLint
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Log
import android.view.MotionEvent
import android.view.View
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.webkit.WebViewClient
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.cancellation.CancellationException
import kotlin.random.Random

/**
 * Управляет «невидимым» WebView для автоматического прохождения VK Smart Captcha.
 *
 * Один запрос = один свежий WebView:
 * 1. Создаёт WebView с системным Android fingerprint и варьируемым viewport
 * 2. Загружает redirect_uri, ждёт короткую паузу загрузки
 * 3. Находит чекбокс "Я не робот"
 * 4. Кликает в рандомную точку внутри квадратной зоны чекбокса
 * 5. JS-interceptor перехватывает captchaNotRobot.check → success_token
 * 6. Уничтожает WebView
 */
object CaptchaWebViewManager {

    private const val TAG = "CaptchaWV"
    private const val CAPTCHA_TIMEOUT_MS = 18_000L
    private const val WV_CREATE_TIMEOUT_MS = 3000L
    private const val AUTO_PROBE_ATTEMPTS = 16
    private const val AUTO_PROBE_INTERVAL_MS = 350L
    private const val AUTO_CHECK_REQUEST_TIMEOUT_MS = 3_500L
    private const val AUTO_POST_CLICK_TIMEOUT_MS = 8_000L
    const val ERROR_SLIDER_DETECTED = "slider_detected"
    const val ERROR_CHECKBOX_NOT_FOUND = "checkbox_not_found"
    const val ERROR_AUTO_CHECK_NOT_SENT = "auto_check_not_sent"
    const val ERROR_AUTO_NO_RESULT = "auto_no_result"

    // Рандомизируемые параметры viewport (чтобы VK не видел одинаковый size)
    private val VIEWPORT_WIDTHS = intArrayOf(356, 358, 360, 362, 364, 366, 368)
    private val VIEWPORT_HEIGHTS = intArrayOf(376, 378, 380, 382, 384, 386, 388)

    private val mainHandler = Handler(Looper.getMainLooper())
    private val captchaMutex = Mutex()

    @Volatile
    private var isTunnelActive = false

    @Volatile
    private var appContext: Context? = null

    private val pendingResult = AtomicReference<CompletableDeferred<Result<String>>?>(null)
    private val postClickSliderWatcher = AtomicReference<Runnable?>(null)
    private val postClickCheckRequestWatchdog = AtomicReference<Runnable?>(null)
    private val postClickResultWatchdog = AtomicReference<Runnable?>(null)
    private val postClickCheckRequestSeen = AtomicBoolean(false)

    @Volatile
    private var currentWebView: WebView? = null

    // Interceptor: перехватывает ответ captchaNotRobot.check → достаёт success_token
    private val interceptorJSCode = """
        (function() {
            if (window.__wdtt_interceptor_installed) return;
            window.__wdtt_interceptor_installed = true;

            function getParam(body, key) {
                try {
                    if (!body) return '';
                    if (typeof body === 'string') return new URLSearchParams(body).get(key) || '';
                    if (body instanceof URLSearchParams) return body.get(key) || '';
                    if (body instanceof FormData) return body.get(key) || '';
                } catch(e) {}
                return '';
            }

            function reportPayload(body) {
                try {
                    const browserFp = getParam(body, 'browser_fp');
                    const adFp = getParam(body, 'adFp');
                    const debugInfo = getParam(body, 'debug_info');
                    if (browserFp || adFp || debugInfo) {
                        window.WdttCaptcha.onCheckPayload(browserFp || '', adFp || '', debugInfo || '');
                    }
                } catch(e) {}
            }

            const origFetch = window.fetch;
            window.fetch = async function() {
                const args = arguments;
                const input = args[0];
                const url = typeof input === 'string'
                    ? input
                    : (input && input.url ? input.url : String(input || ''));
                if (url.includes('captchaNotRobot.check')) {
                    window.WdttCaptcha.onCheckRequest();
                    reportPayload(args[1] && args[1].body);
                    const response = await origFetch.apply(this, args);
                    const clone = response.clone();
                    try {
                        const data = await clone.json();
                        if (data.response && data.response.success_token) {
                            window.WdttCaptcha.onSuccess(data.response.success_token);
                        } else if (data.response && data.response.status) {
                            window.WdttCaptcha.onCheckStatus(
                                data.response.status || '',
                                data.response.show_captcha_type || ''
                            );
                            if (data.response.show_captcha_type === 'slider') {
                                window.WdttCaptcha.onSliderDetected('check_response');
                            }
                        } else if (
                            data.response &&
                            data.response.show_captcha_type === 'slider'
                        ) {
                            window.WdttCaptcha.onSliderDetected('check_response');
                        } else if (data.error) {
                            window.WdttCaptcha.onError(JSON.stringify(data.error));
                        }
                    } catch(e) {}
                    return response;
                }
                return origFetch.apply(this, args);
            };

            const origXHROpen = XMLHttpRequest.prototype.open;
            const origXHRSend = XMLHttpRequest.prototype.send;
            XMLHttpRequest.prototype.open = function(method, url) {
                this._wdtt_url = url && url.toString ? url.toString() : String(url || '');
                return origXHROpen.apply(this, arguments);
            };
            XMLHttpRequest.prototype.send = function() {
                const xhr = this;
                if (xhr._wdtt_url && xhr._wdtt_url.includes('captchaNotRobot.check')) {
                    window.WdttCaptcha.onCheckRequest();
                    reportPayload(arguments[0]);
                    xhr.addEventListener('load', function() {
                        try {
                            const data = JSON.parse(xhr.responseText);
                            if (data.response && data.response.success_token) {
                                window.WdttCaptcha.onSuccess(data.response.success_token);
                            } else if (data.response && data.response.status) {
                                window.WdttCaptcha.onCheckStatus(
                                    data.response.status || '',
                                    data.response.show_captcha_type || ''
                                );
                                if (data.response.show_captcha_type === 'slider') {
                                    window.WdttCaptcha.onSliderDetected('check_response');
                                }
                            } else if (
                                data.response &&
                                data.response.show_captcha_type === 'slider'
                            ) {
                                window.WdttCaptcha.onSliderDetected('check_response');
                            } else if (data.error) {
                                window.WdttCaptcha.onError(JSON.stringify(data.error));
                            }
                        } catch(e) {}
                    });
                }
                return origXHRSend.apply(this, arguments);
            };
        })();
    """.trimIndent()

    private val fingerprintProbeJSCode = """
        (function() {
            try {
                var canvasOk = false;
                try {
                    var canvas = document.createElement('canvas');
                    canvas.width = 32;
                    canvas.height = 16;
                    var ctx = canvas.getContext('2d');
                    canvasOk = !!ctx;
                    if (ctx) {
                        ctx.fillText('wdtt', 2, 12);
                        canvas.toDataURL();
                    }
                } catch(e) {}

                var webgl = 'none';
                try {
                    var glCanvas = document.createElement('canvas');
                    var gl = glCanvas.getContext('webgl') || glCanvas.getContext('experimental-webgl');
                    if (gl) {
                        var ext = gl.getExtension('WEBGL_debug_renderer_info');
                        if (ext) {
                            var vendor = gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || '';
                            var renderer = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || '';
                            webgl = vendor + ' / ' + renderer;
                        } else {
                            webgl = 'available';
                        }
                    }
                } catch(e) {}

                window.WdttCaptcha.onFingerprintProbe(JSON.stringify({
                    webdriver: navigator.webdriver === true,
                    ua: navigator.userAgent || '',
                    platform: navigator.platform || '',
                    languages: navigator.languages ? navigator.languages.join(',') : navigator.language || '',
                    touch: navigator.maxTouchPoints || 0,
                    hw: navigator.hardwareConcurrency || 0,
                    dpr: window.devicePixelRatio || 0,
                    screen: (screen.width || 0) + 'x' + (screen.height || 0),
                    inner: window.innerWidth + 'x' + window.innerHeight,
                    canvas: canvasOk,
                    webgl: webgl
                }));
            } catch(e) {
                window.WdttCaptcha.onFingerprintProbe('probe_error:' + e.message);
            }
        })();
    """.trimIndent()

    // ═══════════════════════════════════════════════════════════════
    // Lifecycle
    // ═══════════════════════════════════════════════════════════════

    fun onTunnelStart(context: Context) {
        appContext = context.applicationContext
        isTunnelActive = true
        Log.d(TAG, "Туннель активен")
    }

    fun onTunnelStop() {
        isTunnelActive = false
        cancelPendingResult("tunnel stopped")
        destroyCurrentWebView()
        appContext = null
        Log.d(TAG, "Туннель остановлен")
    }

    // ═══════════════════════════════════════════════════════════════
    // Публичный API
    // ═══════════════════════════════════════════════════════════════

    suspend fun solveCaptchaAsync(redirectUri: String, sessionToken: String, onStep: (String) -> Unit = {}): String {
        if (!isTunnelActive) throw IllegalStateException("WV не готов — туннель не активен")
        val ctx = appContext ?: throw IllegalStateException("WV не готов — контекст null")

        // Используем Mutex вместо AtomicBoolean: если запрашивается вторая капча до закрытия первой,
        // она просто подождет в очереди (несколько секунд), вместо того чтобы вылетать с ошибкой.
        return captchaMutex.withLock {
            try {
                withTimeout(CAPTCHA_TIMEOUT_MS) {
                    doSolveCaptcha(ctx, redirectUri, onStep)
                }
            } finally {
                pendingResult.set(null)
                destroyCurrentWebView()
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Внутренняя логика
    // ═══════════════════════════════════════════════════════════════

    private suspend fun doSolveCaptcha(context: Context, redirectUri: String, onStep: (String) -> Unit): String {
        val deferred = CompletableDeferred<Result<String>>()
        pendingResult.set(deferred)
        postClickCheckRequestSeen.set(false)

        val webView = createWebViewSync(context, onStep)
            ?: throw IllegalStateException("Не удалось создать WebView")

        Log.d(TAG, "WebView создан ✓")

        // Загружаем страницу капчи
        withContext(Dispatchers.Main) {
            webView.evaluateJavascript(interceptorJSCode, null)
            kotlinx.coroutines.delay(80)
            webView.loadUrl(redirectUri)
        }

        // Ждём success_token от JS-bridge
        try {
            val token = deferred.await().getOrThrow()
            Log.d(TAG, "Капча решена ✓")
            return token
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "Ошибка: ${e::class.simpleName} — ${e.message}")
            throw e
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Создание WebView с рандомизированным fingerprint
    // ═══════════════════════════════════════════════════════════════

    @SuppressLint("SetJavaScriptEnabled")
    private fun createWebViewSync(context: Context, onStep: (String) -> Unit): WebView? {
        // Рандомизируем параметры для КАЖДОГО запроса
        val vw = VIEWPORT_WIDTHS[Random.Default.nextInt(VIEWPORT_WIDTHS.size)]
        val vh = VIEWPORT_HEIGHTS[Random.Default.nextInt(VIEWPORT_HEIGHTS.size)]
        val ua = android.webkit.WebSettings.getDefaultUserAgent(context)

        Log.d(TAG, "Fingerprint: системный Android WebView, viewport=${vw}x${vh}")

        val latch = CountDownLatch(1)
        var webView: WebView? = null

        val createAction = Runnable {
            try {
                val wv = WebView(context.applicationContext)
                wv.apply {
                    settings.apply {
                        javaScriptEnabled = true
                        domStorageEnabled = true
                        databaseEnabled = true
                        mediaPlaybackRequiresUserGesture = false
                        loadWithOverviewMode = true
                        useWideViewPort = true
                        blockNetworkLoads = false
                        cacheMode = android.webkit.WebSettings.LOAD_NO_CACHE
                        userAgentString = ua
                    }

                    addJavascriptInterface(CaptchaJSBridge(), "WdttCaptcha")

                    webViewClient = object : WebViewClient() {
                        override fun onPageStarted(
                            view: WebView, url: String?, favicon: android.graphics.Bitmap?
                        ) {
                            super.onPageStarted(view, url, favicon)
                            view.evaluateJavascript(interceptorJSCode, null)
                        }

                        override fun onPageFinished(view: WebView, url: String?) {
                            super.onPageFinished(view, url)

                            val isCaptchaPage = url?.let {
                                it.contains("not_robot_captcha") ||
                                it.contains("id.vk.ru/captcha") ||
                                it.contains("id.vk.com/captcha") ||
                                it.contains("not_robot")
                            } ?: false

                            if (isCaptchaPage) {
                                Log.d(TAG, "Страница капчи загружена")
                                view.evaluateJavascript(interceptorJSCode, null)

                                if (currentWebView === view && isTunnelActive) {
                                    view.evaluateJavascript(fingerprintProbeJSCode, null)
                                    val pageLoadDelay = 900L + Random.Default.nextLong(0, 800)
                                    mainHandler.postDelayed({
                                        if (currentWebView === view && isTunnelActive) {
                                            solveCaptchaAutomatedSync(view)
                                        }
                                    }, pageLoadDelay)
                                }
                            }
                        }

                        override fun shouldInterceptRequest(
                            view: WebView, request: WebResourceRequest
                        ): WebResourceResponse? {
                            return super.shouldInterceptRequest(view, request)
                        }

                        override fun onReceivedSslError(
                            view: WebView,
                            handler: android.webkit.SslErrorHandler,
                            error: android.net.http.SslError
                        ) {
                            // Разрешаем только для доверенных доменов VK/OK
                            val url = error.url ?: ""
                            if (url.contains("vk.ru") || url.contains("vk.com") || url.contains("okcdn.ru")) {
                                handler.proceed()
                            } else {
                                handler.cancel()
                                Log.w(TAG, "SSL error rejected for: $url")
                            }
                        }
                    }

                    webChromeClient = WebChromeClient()

                    measure(
                        View.MeasureSpec.makeMeasureSpec(vw, View.MeasureSpec.EXACTLY),
                        View.MeasureSpec.makeMeasureSpec(vh, View.MeasureSpec.EXACTLY)
                    )
                    layout(0, 0, vw, vh)
                    onResume()
                }
                webView = wv
                currentWebView = wv
            } catch (e: Exception) {
                Log.e(TAG, "Ошибка создания WebView: ${e.message}")
                webView = null
            } finally {
                latch.countDown()
            }
        }

        if (Looper.myLooper() == Looper.getMainLooper()) {
            createAction.run()
        } else {
            mainHandler.post(createAction)
        }

        val ok = latch.await(WV_CREATE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        if (!ok) {
            Log.e(TAG, "Таймаут создания WebView")
            return null
        }
        return webView
    }

    private fun destroyCurrentWebView() {
        val wv = currentWebView ?: return
        currentWebView = null
        clearPostClickWatchers()

        val destroyAction = Runnable {
            try {
                wv.stopLoading()
                wv.loadUrl("about:blank")
                try { wv.removeJavascriptInterface("WdttCaptcha") } catch (_: Exception) {}
                wv.webViewClient = WebViewClient()
                wv.webChromeClient = null
                wv.onPause()
                wv.removeAllViews()
                wv.destroy()
                Log.d(TAG, "WebView уничтожен ✓")
            } catch (e: Exception) {
                Log.e(TAG, "Ошибка уничтожения: ${e.message}")
            }
        }

        if (Looper.myLooper() == Looper.getMainLooper()) {
            destroyAction.run()
        } else {
            val latch = CountDownLatch(1)
            mainHandler.post {
                try { destroyAction.run() } finally { latch.countDown() }
            }
            latch.await(2000, TimeUnit.MILLISECONDS)
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Авто-решение: клик по чекбоксу «Я не робот»
    //
    // Структура VK капчи (из HTML):
    //   label.vkc__Checkbox-module__Checkbox          ← КЛИКАБЕЛЬНЫЙ label (~200x32px)
    //     input#not-robot-captcha-checkbox             ← скрытый checkbox
    //     div.vkc__Checkbox-module__Checkbox__iconBlock ← иконка чекбокса
    //     div.vkc__Checkbox-module__Checkbox__title     ← текст "Я не робот"
    //
    // Стратегия: находим ВЕСЬ label, получаем его размеры,
    // кликаем в РАНДОМНУЮ точку внутри него (не в центр).
    // ═══════════════════════════════════════════════════════════════

    private fun solveCaptchaAutomatedSync(webView: WebView, attemptsLeft: Int = AUTO_PROBE_ATTEMPTS) {
        if (currentWebView !== webView || !isTunnelActive) return

        // Ищем LABEL целиком (он большой, ~200x32px — как человек кликает).
        // Если вместо checkbox открыт slider/kaleidoscope, скрытый WebView сразу отдаёт fallback ручному WV.
        val findLabelJS = """
            (function() {
                var slider = document.querySelector(
                    '[class*="SliderCaptcha"], [class*="Kaleidoscope"], ' +
                    '.vkc__SliderCaptcha-module__description, ' +
                    '.vkc__KaleidoscopeScreen-module__captchaId, ' +
                    '.vkc__SwipeButton-module__track, ' +
                    '[class*="SwipeButton"]'
                );
                if (slider) return '${ERROR_SLIDER_DETECTED}';

                function visibleRect(node) {
                    if (!node) return null;
                    var rect = node.getBoundingClientRect();
                    var style = window.getComputedStyle(node);
                    if (rect.width < 5 || rect.height < 5 ||
                        style.display === 'none' || style.visibility === 'hidden') {
                        return null;
                    }
                    return rect;
                }

                // Приоритет: квадрат чекбокса. У VK text-area label иногда уже не отправляет check.
                var el = document.querySelector('label.vkc__Checkbox-module__Checkbox');
                if (!el) el = document.querySelector('label[for="not-robot-captcha-checkbox"]');
                if (!el) el = document.getElementById('not-robot-captcha-checkbox');
                if (!el) return 'not_found';

                var icon = el.querySelector && el.querySelector(
                    '[class*="Checkbox__iconBlock"], [class*="iconBlock"], [class*="IconBlock"]'
                );
                var iconRect = visibleRect(icon);
                if (iconRect) {
                    return 'icon,' + iconRect.left + ',' + iconRect.top + ',' + iconRect.width + ',' + iconRect.height;
                }

                var rect = visibleRect(el);
                if (!rect) return 'not_found';
                return 'label,' + rect.left + ',' + rect.top + ',' + rect.width + ',' + rect.height;
            })();
        """.trimIndent()

        webView.evaluateJavascript(findLabelJS) { rawValue ->
            val result = rawValue?.replace("\"", "") ?: ""
            Log.d(TAG, "Label чекбокса: $result")

            if (currentWebView !== webView || !isTunnelActive) return@evaluateJavascript

            if (result == ERROR_SLIDER_DETECTED) {
                Log.i(TAG, "Обнаружен слайдер — fallback на ручной WebView")
                notifyResult(Result.failure(IllegalStateException(ERROR_SLIDER_DETECTED)))
                return@evaluateJavascript
            }

            if (result == "not_found" || result.split(",").size < 5) {
                if (attemptsLeft > 1) {
                    mainHandler.postDelayed({
                        solveCaptchaAutomatedSync(webView, attemptsLeft - 1)
                    }, AUTO_PROBE_INTERVAL_MS)
                } else {
                    Log.i(TAG, "Checkbox не найден — fallback на следующую стадию")
                    notifyResult(Result.failure(IllegalStateException(ERROR_CHECKBOX_NOT_FOUND)))
                }
                return@evaluateJavascript
            }

            val parts = result.split(",")
            val target = parts[0]
            val left = parts[1].toFloatOrNull() ?: return@evaluateJavascript
            val top = parts[2].toFloatOrNull() ?: return@evaluateJavascript
            val width = parts[3].toFloatOrNull() ?: return@evaluateJavascript
            val height = parts[4].toFloatOrNull() ?: return@evaluateJavascript

            val randX = if (target == "icon") {
                left + width * (0.25f + Random.Default.nextFloat() * 0.5f)
            } else {
                left + (height * (0.35f + Random.Default.nextFloat() * 0.3f)).coerceAtMost(width * 0.35f)
            }
            val randY = top + height * (0.25f + Random.Default.nextFloat() * 0.5f)

            Log.d(TAG, "Клик: (${randX.toInt()}, ${randY.toInt()}) target=$target zone=${width.toInt()}x${height.toInt()}")

            val thinkDelay = 600L + Random.Default.nextLong(0, 700)

            mainHandler.postDelayed({
                if (currentWebView === webView && isTunnelActive) {
                    simulateHumanTouch(webView, randX, randY)
                    startPostClickSliderWatcher(webView)
                    startPostClickCheckRequestWatchdog(webView)
                    startPostClickResultWatchdog(webView)
                }
            }, thinkDelay)
        }
    }

    private fun startPostClickSliderWatcher(webView: WebView) {
        postClickSliderWatcher.getAndSet(null)?.let { mainHandler.removeCallbacks(it) }

        var attemptsLeft = 14
        val watcher = object : Runnable {
            override fun run() {
                if (currentWebView !== webView || !isTunnelActive) return

                val detectSliderJS = """
                    (function() {
                        var slider = document.querySelector(
                            '[class*="SliderCaptcha"], [class*="Kaleidoscope"], ' +
                            '.vkc__SliderCaptcha-module__description, ' +
                            '.vkc__KaleidoscopeScreen-module__captchaId, ' +
                            '.vkc__SwipeButton-module__track'
                        );
                        if (slider) return 'slider';

                        var success = document.querySelector(
                            '[class*="success"], [class*="Success"], [class*="passed"], [class*="Passed"]'
                        );
                        if (success) return 'success_ui';

                        return 'none';
                    })();
                """.trimIndent()

                webView.evaluateJavascript(detectSliderJS) { rawValue ->
                    if (currentWebView !== webView || !isTunnelActive) return@evaluateJavascript

                    val result = rawValue?.replace("\"", "") ?: "none"
                    when (result) {
                        "slider" -> {
                            Log.i(TAG, "После checkbox появился слайдер — fallback на ручной WebView")
                            notifyResult(Result.failure(IllegalStateException(ERROR_SLIDER_DETECTED)))
                        }
                        "success_ui" -> {
                            postClickSliderWatcher.set(null)
                        }
                        else -> {
                            attemptsLeft--
                            if (attemptsLeft > 0) {
                                mainHandler.postDelayed(this, 350L)
                            } else {
                                postClickSliderWatcher.set(null)
                            }
                        }
                    }
                }
            }
        }

        postClickSliderWatcher.set(watcher)
        mainHandler.postDelayed(watcher, 450L)
    }

    private fun startPostClickCheckRequestWatchdog(webView: WebView) {
        postClickCheckRequestWatchdog.getAndSet(null)?.let { mainHandler.removeCallbacks(it) }
        if (pendingResult.get() == null) return

        val watchdog = Runnable {
            if (currentWebView === webView &&
                isTunnelActive &&
                pendingResult.get() != null &&
                !postClickCheckRequestSeen.get()
            ) {
                Log.i(TAG, "Auto WebView клик не отправил captchaNotRobot.check — fresh challenge")
                notifyResult(Result.failure(IllegalStateException(ERROR_AUTO_CHECK_NOT_SENT)))
            }
        }

        postClickCheckRequestWatchdog.set(watchdog)
        mainHandler.postDelayed(watchdog, AUTO_CHECK_REQUEST_TIMEOUT_MS)
    }

    private fun startPostClickResultWatchdog(webView: WebView) {
        postClickResultWatchdog.getAndSet(null)?.let { mainHandler.removeCallbacks(it) }
        if (pendingResult.get() == null) return

        val watchdog = Runnable {
            if (currentWebView === webView && isTunnelActive && pendingResult.get() != null) {
                Log.i(TAG, "Auto WebView не вернул success_token после клика — fresh challenge")
                notifyResult(Result.failure(IllegalStateException(ERROR_AUTO_NO_RESULT)))
            }
        }

        postClickResultWatchdog.set(watchdog)
        mainHandler.postDelayed(watchdog, AUTO_POST_CLICK_TIMEOUT_MS)
    }

    private fun clearPostClickWatchers() {
        postClickSliderWatcher.getAndSet(null)?.let { mainHandler.removeCallbacks(it) }
        postClickCheckRequestWatchdog.getAndSet(null)?.let { mainHandler.removeCallbacks(it) }
        postClickResultWatchdog.getAndSet(null)?.let { mainHandler.removeCallbacks(it) }
    }

    /**
     * Имитирует нативный тач как от пальца:
     * - ACTION_DOWN с рандомным pressure (0.5-0.9)
     * - Удержание 80-180мс (как палец на экране)
     * - ACTION_UP с лёгким смещением (палец дрожит)
     */
    private fun simulateHumanTouch(webView: WebView, cssX: Float, cssY: Float) {
        if (currentWebView !== webView) return

        val density = webView.resources.displayMetrics.density
        val physX = cssX * density
        val physY = cssY * density
        val downTime = SystemClock.uptimeMillis()

        // Рандомный pressure — палец нажимает с разной силой
        val pressure = 0.5f + Random.Default.nextFloat() * 0.4f

        val downEvent = MotionEvent.obtain(
            downTime, downTime, MotionEvent.ACTION_DOWN, physX, physY, pressure, 1f, 0, 1f, 1f, 0, 0
        )
        downEvent.source = android.view.InputDevice.SOURCE_TOUCHSCREEN
        webView.dispatchTouchEvent(downEvent)
        downEvent.recycle()

        val moveTime = 70L + Random.Default.nextLong(0, 90)
        mainHandler.postDelayed({
            if (currentWebView === webView) {
                val moveX = physX + (-0.8f + Random.Default.nextFloat() * 1.6f) * density
                val moveY = physY + (-0.6f + Random.Default.nextFloat() * 1.2f) * density
                val moveEvent = MotionEvent.obtain(
                    downTime, SystemClock.uptimeMillis(), MotionEvent.ACTION_MOVE,
                    moveX, moveY, pressure, 1f, 0, 1f, 1f, 0, 0
                )
                moveEvent.source = android.view.InputDevice.SOURCE_TOUCHSCREEN
                webView.dispatchTouchEvent(moveEvent)
                moveEvent.recycle()
            }
        }, moveTime)

        val holdTime = 150L + Random.Default.nextLong(0, 170)

        mainHandler.postDelayed({
            if (currentWebView === webView) {
                // Лёгкое смещение при отпускании (палец не стоит идеально на месте)
                val jitterX = physX + (-1f + Random.Default.nextFloat() * 2f) * density
                val jitterY = physY + (-0.5f + Random.Default.nextFloat() * 1f) * density

                val upEvent = MotionEvent.obtain(
                    downTime, SystemClock.uptimeMillis(), MotionEvent.ACTION_UP,
                    jitterX, jitterY, 0f, 1f, 0, 1f, 1f, 0, 0
                )
                upEvent.source = android.view.InputDevice.SOURCE_TOUCHSCREEN
                webView.dispatchTouchEvent(upEvent)
                upEvent.recycle()
            }
        }, holdTime)
    }

    // ═══════════════════════════════════════════════════════════════
    // JS Bridge — вызывается из JavaScript background thread
    // ═══════════════════════════════════════════════════════════════

    private class CaptchaJSBridge {
        @JavascriptInterface
        fun onSuccess(token: String) {
            Log.d(TAG, "JS: success_token получен (${token.length} символов)")
            notifyResult(Result.success(token))
        }

        @JavascriptInterface
        fun onSliderDetected(source: String) {
            Log.i(TAG, "JS: обнаружен slider после auto-step ($source)")
            notifyResult(Result.failure(IllegalStateException(ERROR_SLIDER_DETECTED)))
        }

        @JavascriptInterface
        fun onCheckStatus(status: String, showType: String) {
            Log.i(TAG, "JS: captcha check status=$status show_type=$showType")
            when (status.uppercase()) {
                "BOT", "ERROR_LIMIT", "ERROR" -> {
                    notifyResult(Result.failure(IllegalStateException("captcha_check_$status")))
                }
            }
        }

        @JavascriptInterface
        fun onCheckRequest() {
            postClickCheckRequestSeen.set(true)
            postClickCheckRequestWatchdog.getAndSet(null)?.let { mainHandler.removeCallbacks(it) }
            Log.i(TAG, "JS: captcha check request sent")
        }

        @JavascriptInterface
        fun onCheckPayload(browserFp: String, adFp: String, debugInfo: String) {
            val fpHash = browserFp.safeHashPrefix()
            val adHash = adFp.safeHashPrefix()
            val dbgHash = debugInfo.safeHashPrefix()
            Log.i(TAG, "JS: check payload browser_fp=${browserFp.length}:$fpHash adFp=${adFp.length}:$adHash debug=${debugInfo.length}:$dbgHash")
        }

        @JavascriptInterface
        fun onFingerprintProbe(data: String) {
            Log.i(TAG, "JS: fingerprint probe ${data.take(700)}")
        }

        @JavascriptInterface
        fun onError(error: String) {
            Log.e(TAG, "JS: ошибка — $error")
            notifyResult(Result.failure(Exception("VK: $error")))
        }
    }

    private fun String.safeHashPrefix(): String {
        if (isBlank()) return "-"
        val digest = MessageDigest.getInstance("SHA-256").digest(toByteArray(Charsets.UTF_8))
        return digest.take(4).joinToString("") { "%02x".format(it) }
    }

    private fun notifyResult(result: Result<String>) {
        clearPostClickWatchers()
        val deferred = pendingResult.getAndSet(null) ?: return
        if (!deferred.isCompleted) {
            deferred.complete(result)
        }
    }

    private fun cancelPendingResult(reason: String) {
        clearPostClickWatchers()
        val deferred = pendingResult.getAndSet(null) ?: return
        if (!deferred.isCompleted) {
            deferred.complete(Result.failure(CancellationException(reason)))
        }
    }
}
