package com.wdtt.plus.vk

import android.app.Service
import android.content.Intent
import android.os.*
import com.wdtt.plus.*
import kotlinx.coroutines.*
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/** Unexported same-UID IPC; only this main-process service contacts our backend. */
class NativeVkBrokerService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val messenger = Messenger(object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(message: Message) {
            if (message.sendingUid != Process.myUid()) return
            if (message.what == 2) {
                val code = message.data.getString("code").orEmpty()
                if (NativeVkFeedback.validDiagnostic(code)) {
                    TunnelManager.noteSystemLifecycleEvent("native_vk_${SystemClock.elapsedRealtime()}",
                        "[ВК] ${NativeVkFeedback.presentation(code)}")
                }
                return
            }
            if (message.what != 1) return
            val reply = message.replyTo ?: return
            val id = message.arg1
            val raw = message.data.getString("body").orEmpty()
            if (raw.toByteArray().size !in 1..768) return
            scope.launch {
                val answer = try { NativeVkBackend.post(raw) } catch (error: Exception) {
                    val diagnostic = NativeVkFeedback.diagnostic("BROKER", error)
                    TunnelManager.noteSystemLifecycleEvent("native_vk_broker_${SystemClock.elapsedRealtime()}",
                        "[ВК] ${NativeVkFeedback.presentation(diagnostic)}")
                    JSONObject().put("error", "Не удалось связаться с WDTT Plus. Уже созданные ссылки сохранены; повтор передачи не создаст новые звонки.")
                }
                runCatching { reply.send(Message.obtain().apply {
                    what = 1; arg1 = id; data = Bundle().apply { putString("body", answer.toString()) }
                }) }
            }
        }
    })
    override fun onBind(intent: Intent): IBinder = messenger.binder
    override fun onDestroy() { scope.cancel(); super.onDestroy() }
}

internal object NativeVkBackend {
    suspend fun post(raw: String): JSONObject = withContext(Dispatchers.IO) {
        val json = JSONObject(raw)
        require(json.optString("o") in setOf("prepare", "auth", "permit", "result", "finish"))
        val encrypted = NativeVkCrypto.exchange(raw)
        val bytes = encrypted.request.toByteArray(Charsets.UTF_8)
        val url = "https://wdttplus.ru/api/client/native"
        val response = requestRemoteDocumentWithTunnelFallback(
            preferTunnel = TunnelManager.isUpdateRelayAvailable(),
            tunnelRequest = { TunnelManager.postOpaqueHttpsStatusThroughTunnel(url, bytes) },
            directRequest = {
                val connection = URL(url).openConnection() as HttpURLConnection
                try {
                    connection.requestMethod = "POST"
                    connection.instanceFollowRedirects = false
                    connection.connectTimeout = 4_000; connection.readTimeout = 8_000
                    connection.doOutput = true
                    connection.setRequestProperty("Content-Type", "application/json")
                    connection.outputStream.use { it.write(bytes) }
                    val status = connection.responseCode
                    val stream = if (status in 200..299) connection.inputStream else connection.errorStream
                    val body = stream?.use { input ->
                        val out = java.io.ByteArrayOutputStream()
                        val buffer = ByteArray(1024)
                        while (true) {
                            val n = input.read(buffer)
                            if (n < 0) break
                            check(out.size() + n <= 32_768)
                            out.write(buffer, 0, n)
                        }
                        out.toString("UTF-8")
                    }.orEmpty()
                    RemoteDocumentHttpResponse(status, body)
                } finally { connection.disconnect() }
            },
        )
        if (response.status in 200..299) encrypted.response(response.body) else JSONObject().put("error",
            "Не удалось установить защищённую связь с backend (HTTP ${response.status}).")
    }
}
