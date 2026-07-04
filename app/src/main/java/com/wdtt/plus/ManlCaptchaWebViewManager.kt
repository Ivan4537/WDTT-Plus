package com.wdtt.plus

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.MotionEvent
import android.view.ViewGroup
import android.webkit.*
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.core.app.NotificationCompat
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.background
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.runtime.saveable.rememberSaveable
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import java.util.concurrent.atomic.AtomicReference
import kotlin.random.Random

object ManlCaptchaWebViewManager {
    private const val TAG = "ManlCaptchaWV"
    private const val CAPTCHA_TIMEOUT_MS = 180_000L

    val captchaMutex = Mutex()
    val pendingResult = AtomicReference<CompletableDeferred<Result<String>>?>(null)
    var activeActivity: ManlCaptchaActivity? = null
    var pendingIntentToStart: Intent? = null
    var isCaptchaPending = false

    fun checkAndShowPendingCaptcha(context: Context) {
        val intent = pendingIntentToStart
        if (intent != null && activeActivity == null) {
            context.startActivity(intent)
        }
    }

    fun cancelCaptcha() {
        pendingResult.get()?.completeExceptionally(kotlin.coroutines.cancellation.CancellationException("Cancelled by system"))
    }

    private const val NOTIFICATION_ID = 9001
    private const val CHANNEL_ID = "captcha_channel"

    private fun showCaptchaNotification(context: Context, redirectUri: String) {
        if (MainActivity.isForeground) return // Если юзер уже в приложении — не спамим пушом
        
        val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Уведомления защиты (Капча)",
                NotificationManager.IMPORTANCE_HIGH
            )
            notificationManager.createNotificationChannel(channel)
        }

        val openIntent = Intent(context, ManlCaptchaActivity::class.java).apply {
            putExtra("redirectUri", redirectUri)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS)
        }

        val openPendingIntent = PendingIntent.getActivity(
            context, 0, openIntent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val cancelIntent = Intent(context, CaptchaCancelReceiver::class.java)
        val cancelPendingIntent = PendingIntent.getBroadcast(
            context, 1, cancelIntent, PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("Требуется подтверждение капчи")
            .setContentText("ВК запросил проверку безопасности. Нажмите для решения.")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(openPendingIntent)
            .setAutoCancel(true)
            .addAction(0, "Отменить и выключить", cancelPendingIntent)
            .build()

        notificationManager.notify(NOTIFICATION_ID, notification)
    }

    private fun clearCaptchaNotification(context: Context) {
        val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.cancel(NOTIFICATION_ID)
    }

    suspend fun solveCaptchaAsync(context: Context, redirectUri: String, sessionToken: String): String {
        return captchaMutex.withLock {
            isCaptchaPending = true
            val deferred = CompletableDeferred<Result<String>>()
            // Если предыдущий вызов завис, отменяем его
            pendingResult.getAndSet(deferred)?.cancel()

            showCaptchaNotification(context, redirectUri)

            val intent = Intent(context, ManlCaptchaActivity::class.java).apply {
                putExtra("redirectUri", redirectUri)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS)
            }
            pendingIntentToStart = intent

            if (MainActivity.isForeground) {
                // Запускаем окно только если интерфейс приложения активен (иначе Android блокирует старт)
                context.startActivity(intent)
            }

            try {
                withTimeout(CAPTCHA_TIMEOUT_MS) {
                    deferred.await().getOrThrow()
                }
            } finally {
                isCaptchaPending = false
                pendingResult.set(null)
                pendingIntentToStart = null
                clearCaptchaNotification(context)
                try {
                    activeActivity?.finish()
                } catch (e: Exception) {
                    Log.e(TAG, "Error finishing activity: ${e.message}")
                }
                activeActivity = null
            }
        }
    }

    fun notifyResult(result: Result<String>) {
        val deferred = pendingResult.getAndSet(null) ?: return
        if (!deferred.isCompleted) {
            deferred.complete(result)
        }
    }
}

class ManlCaptchaActivity : ComponentActivity() {
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
                        window.WdttCaptcha.onCheckPayload(
                            browserFp ? browserFp.length : 0,
                            adFp ? adFp.length : 0,
                            debugInfo ? debugInfo.length : 0
                        );
                    }
                } catch(e) {}
            }

            const origFetch = window.fetch;
            window.fetch = async function() {
                const args = arguments;
                const url = args[0] || '';
                if (typeof url === 'string' && url.includes('captchaNotRobot.check')) {
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
                this._wdtt_url = url;
                return origXHROpen.apply(this, arguments);
            };
            XMLHttpRequest.prototype.send = function() {
                const xhr = this;
                if (xhr._wdtt_url && xhr._wdtt_url.includes('captchaNotRobot.check')) {
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

    private val closeBridgeJSCode = """
        (function() {
            if (window.__wdtt_close_bridge_installed) return;
            window.__wdtt_close_bridge_installed = true;
            document.addEventListener('click', function(e) {
                if (e.target.closest('.vkc__ModalCardBase-module__dismiss')) {
                    window.WdttCaptcha.onCancel();
                }
            });
        })();
    """.trimIndent()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ManlCaptchaWebViewManager.activeActivity = this
        MainActivity.isForeground = true // Если появилось само окно капчи, мы тоже считаемся в фореграунде
        val redirectUri = intent.getStringExtra("redirectUri") ?: return finish()

        setContent {
            MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
                Box(modifier = Modifier.fillMaxSize()) {
                    Column(
                        modifier = Modifier.align(Alignment.Center),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        var isLoading by rememberSaveable { mutableStateOf(true) }
                        
                        Box {
                            Surface(
                                modifier = Modifier.fillMaxSize(),
                                color = Color.Transparent,
                                tonalElevation = 0.dp,
                                shadowElevation = 0.dp
                            ) {
                                AndroidView(
                                    modifier = Modifier.fillMaxSize(),
                                    factory = { ctx ->
                                        WebView(ctx).apply {
                                            setBackgroundColor(android.graphics.Color.TRANSPARENT)
                                            layoutParams = ViewGroup.LayoutParams(
                                                ViewGroup.LayoutParams.MATCH_PARENT,
                                                ViewGroup.LayoutParams.MATCH_PARENT
                                            )
                                            isNestedScrollingEnabled = false
                                            setOnTouchListener { v, event ->
                                                when (event.actionMasked) {
                                                    MotionEvent.ACTION_DOWN,
                                                    MotionEvent.ACTION_MOVE,
                                                    MotionEvent.ACTION_POINTER_DOWN -> {
                                                        v.parent?.requestDisallowInterceptTouchEvent(true)
                                                    }
                                                    MotionEvent.ACTION_UP,
                                                    MotionEvent.ACTION_CANCEL -> {
                                                        v.parent?.requestDisallowInterceptTouchEvent(false)
                                                    }
                                                }
                                                false
                                            }
                                settings.apply {
                                    javaScriptEnabled = true
                                    domStorageEnabled = true
                                    databaseEnabled = true
                                    mediaPlaybackRequiresUserGesture = false
                                    loadWithOverviewMode = true
                                    useWideViewPort = true
                                    blockNetworkLoads = false
                                    cacheMode = WebSettings.LOAD_DEFAULT // Включаем кэш для моментальной загрузки!
                                    userAgentString = WebSettings.getDefaultUserAgent(ctx)
                                }

                                addJavascriptInterface(object {
                                    @JavascriptInterface
                                    fun onSuccess(token: String) {
                                        Log.d("ManlCaptchaWV", "Token received")
                                        ManlCaptchaWebViewManager.notifyResult(Result.success(token))
                                        finish()
                                    }
                                    @JavascriptInterface
                                    fun onError(err: String) {
                                        Log.e("ManlCaptchaWV", "Error: $err")
                                        ManlCaptchaWebViewManager.notifyResult(Result.failure(Exception("VK Captcha error: ${'$'}err")))
                                        finish()
                                    }
                                    @JavascriptInterface
                                    fun onCheckStatus(status: String, showType: String) {
                                        Log.i("ManlCaptchaWV", "captcha check status=$status show_type=$showType")
                                    }
                                    @JavascriptInterface
                                    fun onCheckPayload(browserFpLen: Int, adFpLen: Int, debugInfoLen: Int) {
                                        Log.i("ManlCaptchaWV", "check payload browser_fp_len=$browserFpLen adFp_len=$adFpLen debug_len=$debugInfoLen")
                                    }
                                    @JavascriptInterface
                                    fun onCancel() {
                                        Log.d("ManlCaptchaWV", "User closed VK captcha")
                                        ManlCaptchaWebViewManager.notifyResult(Result.failure(Exception("Cancelled by user")))
                                        finish()
                                    }
                                }, "WdttCaptcha")

                                webViewClient = object : WebViewClient() {
                                    override fun onPageStarted(view: WebView?, url: String?, favicon: android.graphics.Bitmap?) {
                                        super.onPageStarted(view, url, favicon)
                                        view?.evaluateJavascript(interceptorJSCode, null)
                                    }
                                    override fun onPageFinished(view: WebView?, url: String?) {
                                        super.onPageFinished(view, url)
                                        view?.evaluateJavascript(interceptorJSCode, null)
                                        view?.evaluateJavascript(closeBridgeJSCode, null)
                                        isLoading = false
                                    }
                                }
                                webChromeClient = WebChromeClient()
                                loadUrl(redirectUri)
                                }
                            })
                            }
                            
                            // Индикатор загрузки, пока страница белая/прозрачная
                            if (isLoading) {
                                CircularProgressIndicator(
                                    modifier = Modifier.align(Alignment.Center).size(48.dp),
                                    color = MaterialTheme.colorScheme.primary
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        MainActivity.isForeground = false
        if (ManlCaptchaWebViewManager.activeActivity === this) {
            ManlCaptchaWebViewManager.activeActivity = null
        }
        // Мы НЕ отправляем ошибку здесь! 
        // Если юзер смахнул окно (нажал назад), капча останется висеть в памяти (через пуш).
        // Ошибка или Успех отправляются только по явным действиям (крестик, решение, или таймаут 5 мин).
    }
}

class CaptchaCancelReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        TunnelManager.stop(TunnelStopReason.CaptchaCancelled)
        ManlCaptchaWebViewManager.activeActivity?.finish()
        val notifMgr = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notifMgr.cancel(9001) // NOTIFICATION_ID
    }
}
