package com.wdtt.plus.vk

import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.webkit.WebView
import androidx.webkit.JavaScriptReplyProxy
import androidx.webkit.ScriptHandler
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import org.json.JSONObject

/** One observer per existing profile WebView. No new cookie jar or network binding. */
internal class VkInPlaceCaptcha(
    private val view: WebView,
    private val foreground: () -> Boolean,
    private val apiBridgeEnabled: Boolean = false,
    private val changed: (VkCaptchaPolicy.State) -> Unit,
) {
    private val handler = Handler(Looper.getMainLooper())
    private val policy = VkCaptchaPolicy()
    private val replies = mutableMapOf<String, Pair<Int, JavaScriptReplyProxy>>()
    private var runtime: JavaScriptReplyProxy? = null
    private var script: ScriptHandler? = null
    private var proofScript: ScriptHandler? = null
    private var apiUrl = ""
    private var apiNonce = ""
    private var apiReply: JavaScriptReplyProxy? = null
    private var apiProof: String? = null
    private var closed = false
    private var wasForeground = false
    private var resumedAt = 0L
    private var previous = VkCaptchaPolicy.State.IDLE
    val active get() = policy.active || apiNonce.isNotEmpty()
    var supported = false
        private set
    private val tick = object : Runnable {
        override fun run() {
            if (closed) return
            val now = SystemClock.elapsedRealtime()
            val visible = foreground()
            if (visible && !wasForeground) resumedAt = now
            wasForeground = visible
            // A background renderer may throttle heartbeat JS. Do not hide its
            // known challenge or enter fallback before it can report on resume.
            if (visible && now - resumedAt >= 3500) policy.refresh(now)
            publish()
            handler.postDelayed(this, 500)
        }
    }
    init {
        if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER) &&
            WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)) {
            runCatching {
                val origins = VkCaptchaPolicy.origins + "https://wdttplus.ru"
                WebViewCompat.addWebMessageListener(view, VkCaptchaScript.CHANNEL, origins) { source, message, origin, _, reply ->
                    if (closed || source !== view) return@addWebMessageListener
                    val raw = message.data.orEmpty()
                    if (raw.length > 17000) return@addWebMessageListener
                    val data = runCatching { JSONObject(raw) }.getOrNull() ?: return@addWebMessageListener
                    if (origin.toString() == "https://wdttplus.ru") {
                        when (data.optString("state")) {
                            "runtime" -> { runtime = reply; publish() }
                            "api_begin" -> {
                                val nonce = data.optString("nonce")
                                val url = data.optString("url")
                                if (apiBridgeEnabled && apiNonce.isEmpty() && nonce.matches(Regex("[A-Za-z0-9_-]{16,80}")) &&
                                    url.length <= 16384 && VkCaptchaPolicy.captchaPage(url) && foreground()) {
                                    apiUrl = url; apiNonce = nonce; apiReply = reply
                                    send(reply, JSONObject().put("api", "ready").put("nonce", nonce))
                                    publish()
                                }
                            }
                            "api_end" -> if (data.optString("nonce") == apiNonce) {
                                apiUrl = ""; apiNonce = ""; apiReply = null; apiProof = null; publish()
                            }
                        }
                        return@addWebMessageListener
                    }
                    if (raw.length > 256) return@addWebMessageListener
                    if (!VkCaptchaPolicy.trustedOrigin(origin.toString())) return@addWebMessageListener
                    val frame = data.optString("frame")
                    val generation = data.optInt("generation", -1)
                    val action = policy.update(frame, generation, data.optString("state"), SystemClock.elapsedRealtime(), foreground())
                    if (frame.matches(Regex("[a-z0-9]{1,64}")) && generation in 0..128 && replies.size < 32) {
                        replies[frame] = generation to reply
                    }
                    publish() // Reveal the original page before attempting its exact checkbox.
                    if (action != null) send(reply, JSONObject().put("frame", frame).put("generation", generation).put("action", action))
                }
                script = WebViewCompat.addDocumentStartJavaScript(view, VkCaptchaScript.source, origins)
                if (apiBridgeEnabled) {
                  WebViewCompat.addWebMessageListener(view, "WDTTApiCaptchaResult", VkCaptchaPolicy.origins) { source, message, origin, _, reply ->
                    if (closed || source !== view || apiNonce.isEmpty() || !VkCaptchaPolicy.trustedOrigin(origin.toString())) return@addWebMessageListener
                    val raw = message.data.orEmpty()
                    if (raw.length > 17000) return@addWebMessageListener
                    val data = runCatching { JSONObject(raw) }.getOrNull() ?: return@addWebMessageListener
                    if (data.optString("page") == apiUrl) {
                        send(reply, JSONObject().put("observe", apiNonce))
                    } else if (data.optString("nonce") == apiNonce && VkApiCaptcha.validProof(data.optString("proof"))) {
                        if (apiProof == null && apiReply != null) apiProof = data.optString("proof")
                        publish() // Forward once, and only while the user is in this window.
                    }
                  }
                  proofScript = WebViewCompat.addDocumentStartJavaScript(view, VkApiCaptcha.completionScript, VkCaptchaPolicy.origins)
                }
                supported = true
                handler.post(tick)
            }.onFailure { close() }
        }
    }
    fun userInteraction() {
        if (closed || !active) return
        policy.userInteraction(SystemClock.elapsedRealtime())
        replies.forEach { (frame, value) -> send(value.second, JSONObject().put("frame", frame)
            .put("generation", value.first).put("action", "manual")) }
        publish()
    }
    private fun publish() {
        runtime?.let { send(it, JSONObject().put("pending", active)) }
        if (foreground() && apiNonce.isNotEmpty()) apiProof?.let { proof ->
            apiReply?.let { send(it, JSONObject().put("api", "solved").put("nonce", apiNonce).put("proof", proof)) }
            apiReply = null; apiProof = null
        }
        val state = if (policy.active) policy.state else if (apiNonce.isNotEmpty()) VkCaptchaPolicy.State.MANUAL else VkCaptchaPolicy.State.IDLE
        if (previous != state) { previous = state; changed(state) }
    }
    private fun send(reply: JavaScriptReplyProxy, data: JSONObject) {
        runCatching { reply.postMessage(data.toString()) }
    }
    fun close() {
        if (closed) return
        closed = true
        handler.removeCallbacks(tick)
        runCatching { script?.remove() }; script = null
        runCatching { proofScript?.remove() }; proofScript = null
        if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
            runCatching { WebViewCompat.removeWebMessageListener(view, VkCaptchaScript.CHANNEL) }
            if (apiBridgeEnabled) runCatching { WebViewCompat.removeWebMessageListener(view, "WDTTApiCaptchaResult") }
        }
        replies.clear(); runtime = null; apiReply = null; apiProof = null; apiUrl = ""; apiNonce = ""
    }
}
