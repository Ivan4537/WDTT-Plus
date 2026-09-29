package com.wdtt.plus.vk

import android.content.Intent
import android.net.Uri
import android.os.*
import androidx.annotation.Keep
import com.wdtt.plus.*
import kotlinx.coroutines.*
import org.json.JSONObject

/** Device-side API fallback, available only with a server-issued capability. */
@Keep
object NativeVkContinuation : LocalContinuationExtension {
    override suspend fun execute(activity: MainActivity, target: RemoteLaunchTarget,
        deviceId: String, hasCompleteLocalValues: Boolean,
        onProgress: (String) -> Unit): Uri {
        check(target.completion.available) { "Backend не выдал разрешение на получение." }
        val profile = target.localProfile ?: error("Не указан профиль для входа.")
        ProfileWebSessionScope.requireValid(profile)
        val pending = JSONObject().put("key", target.completion.key).put("device", deviceId)
            .put("expires", target.completion.expiresAtSeconds)
        check(activity.getSharedPreferences("native-vk-return", 0).edit()
            .putString("pending", SecureStringStore(activity).encrypt(pending.toString())).commit())
        val done = CompletableDeferred<Uri>()
        val receiver = object : ResultReceiver(Handler(Looper.getMainLooper())) {
            override fun onReceiveResult(code: Int, data: Bundle?) {
                val raw = data?.getString("document").orEmpty()
                val document = RemoteDocumentGateway.extractLink(raw)
                when {
                    code == 1 && document != null -> done.complete(Uri.parse(document.url))
                    code == 3 -> done.completeExceptionally(LocalContinuationSafeFallbackException())
                    else -> done.completeExceptionally(LocalContinuationCancelledException())
                }
            }
        }
        try {
            withContext(Dispatchers.Main.immediate) {
                activity.startActivity(Intent().apply {
                    setClassName(activity, ProfileWebSessionScope.nativeActivity(profile.index))
                    ProfileWebSessionScope.put(this, profile)
                    addFlags(Intent.FLAG_ACTIVITY_NO_ANIMATION)
                    putExtra("key", target.completion.key)
                    putExtra("device", deviceId)
                    putExtra("expires", target.completion.expiresAtSeconds)
                    putExtra("has_complete_values", hasCompleteLocalValues)
                    putExtra("receiver", receiver)
                })
            }
        } catch (_: Exception) {
            throw LocalContinuationSafeFallbackException()
        }
        onProgress("Получение ВК-хешей во встроенном окне…")
        return withTimeout(15 * 60_000L) { done.await() }
    }
    override fun offerCallback(uri: Uri?) = false
    override suspend fun recoverPending(activity: MainActivity): Uri? {
        // Only retry delivery of four ledger-confirmed results. Never login or call VK.
        val prefs = activity.getSharedPreferences("native-vk-return", 0)
        return runCatching {
            val pending = JSONObject(SecureStringStore(activity).decrypt(prefs.getString("pending", null)) ?: return null)
            if (pending.getLong("expires") <= System.currentTimeMillis() / 1000) {
                prefs.edit().remove("pending").commit(); return null
            }
            val result = NativeVkBackend.post(NativeVkProtocol.payload(pending.getString("key"),
                pending.getString("device"), "finish"))
            RemoteDocumentGateway.extractLink(result.optString("document"))?.let { Uri.parse(it.url) }
        }.getOrNull()
    }
    override fun acknowledgeDocument(activity: MainActivity, uri: Uri) {
        activity.getSharedPreferences("native-vk-return", 0).edit().remove("pending").commit()
    }
}
