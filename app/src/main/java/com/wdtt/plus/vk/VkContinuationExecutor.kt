package com.wdtt.plus.vk

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.ResultReceiver
import android.os.Build
import android.webkit.WebView
import androidx.annotation.Keep
import com.wdtt.plus.LocalContinuationExtension
import com.wdtt.plus.LocalContinuationCancelledException
import com.wdtt.plus.LocalContinuationSafeFallbackException
import com.wdtt.plus.MainActivity
import com.wdtt.plus.RemoteContinuationLauncher
import com.wdtt.plus.RemoteActionCompletion
import com.wdtt.plus.RemoteActionCompletionState
import com.wdtt.plus.RemoteDocumentGateway
import com.wdtt.plus.RemoteLaunchTarget
import com.wdtt.plus.SecureStringStore
import com.wdtt.plus.TemporaryDirectRouteLease
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import java.util.UUID

private class ModernVkSafeFallbackException : IllegalStateException("Нужен резервный способ получения ВК-хешей.")

/** Device-side provider adapter. Entitlements and result delivery remain server-authoritative. */
@Keep
object VkContinuationExecutor : LocalContinuationExtension {
    private data class ActiveCallback(val result: CompletableDeferred<Uri?>)
    private data class PendingCompletion(
        val completion: RemoteActionCompletion,
        val deviceId: String,
        val documentUrl: String = "",
    )

    private val callbackLock = Any()
    private var activeCallback: ActiveCallback? = null
    private var recoveryInProgress = false

    override val experimentalAvailable: Boolean
        get() = runCatching { Class.forName(MODERN_ACTIVITY_CLASS) }.isSuccess

    override suspend fun execute(
        activity: MainActivity,
        target: RemoteLaunchTarget,
        deviceId: String,
        hasCompleteLocalValues: Boolean,
        onProgress: (String) -> Unit,
    ): Uri = executePreferredChain(
        activity,
        target,
        deviceId,
        hasCompleteLocalValues,
        onProgress,
    )

    override fun offerCallback(uri: Uri?): Boolean {
        val current = synchronized(callbackLock) { activeCallback } ?: return false
        if (uri != null && !isAcceptedCallback(uri)) return false
        current.result.complete(uri)
        return true
    }

    override suspend fun executeExperimental(
        activity: MainActivity,
        target: RemoteLaunchTarget,
        deviceId: String,
        hasCompleteLocalValues: Boolean,
        onProgress: (String) -> Unit,
    ): Uri = executePreferredChain(
        activity,
        target,
        deviceId,
        hasCompleteLocalValues,
        onProgress,
    )

    private suspend fun executePreferredChain(
        activity: MainActivity,
        target: RemoteLaunchTarget,
        deviceId: String,
        hasCompleteLocalValues: Boolean,
        onProgress: (String) -> Unit,
    ): Uri {
        check(target.completion.available) { "WDTT Plus не выдал разрешение на получение." }
        var callback = ActiveCallback(CompletableDeferred())
        var closeModernWindow: (() -> Unit)? = null
        synchronized(callbackLock) {
            check(activeCallback == null) { "Другое получение уже выполняется." }
            activeCallback = callback
        }
        try {
            savePending(activity, PendingCompletion(target.completion, deviceId))
            val modernResult = try {
                runModernContainer(
                    activity = activity,
                    target = target,
                    deviceId = deviceId,
                    hasCompleteLocalValues = hasCompleteLocalValues,
                    onProgress = onProgress,
                    callback = callback,
                    retainFallbackWindow = { closeModernWindow = it },
                )
            } catch (_: ModernVkSafeFallbackException) {
                noteVkEvent("Основной способ недоступен до создания ссылок. Открываю резервный способ внутри приложения.")
                progress(onProgress, "Открываю резервный способ внутри приложения…")
                null
            }
            if (modernResult != null) return modernResult

            callback = replaceCallback(callback)
            val native = nativeContinuationOrNull()
            if (native != null) {
                try {
                    return native.execute(
                        activity,
                        target,
                        deviceId,
                        hasCompleteLocalValues,
                        onProgress,
                    ).also { markReadyDocument(activity, it) }
                } catch (_: LocalContinuationSafeFallbackException) {
                    noteVkEvent("Встроенный резервный способ не подошёл до создания ссылок. Открываю ВК в браузере.")
                    progress(onProgress, "Открываю резервный способ в браузере…")
                }
            }
            callback = replaceCallback(callback)
            return runBrowserFallback(activity, target, deviceId, onProgress, callback)
        } finally {
            closeModernWindow?.invoke()
            synchronized(callbackLock) {
                if (activeCallback === callback) activeCallback = null
            }
        }
    }

    private suspend fun runModernContainer(
        activity: MainActivity,
        target: RemoteLaunchTarget,
        deviceId: String,
        hasCompleteLocalValues: Boolean,
        onProgress: (String) -> Unit,
        callback: ActiveCallback,
        retainFallbackWindow: (() -> Unit) -> Unit,
    ): Uri {
        val embedded = target.embedded ?: throw ModernVkSafeFallbackException()
        val profile = target.localProfile ?: throw IllegalStateException("Не указан профиль для входа.")
        ProfileWebSessionScope.requireValid(profile)
        if (!modernContainerSupported(activity, profile.index)) throw ModernVkSafeFallbackException()
        val session = UUID.randomUUID().toString()
        var directRouteLease: TemporaryDirectRouteLease? = null
        var completedSuccessfully = false
        var handingOff = false
        val closeWindow = {
            activity.sendBroadcast(Intent(MODERN_FINISH_ACTION).apply {
                setPackage(activity.packageName)
                putExtra("session", session)
                putExtra("success", completedSuccessfully)
            })
        }
        try {
            progress(onProgress, "Открываю получение ВК-хешей внутри приложения…")
            directRouteLease = TemporaryDirectRouteLease.acquire(
                context = activity,
                domains = DIRECT_VK_DOMAINS,
            )
            val receiver = object : ResultReceiver(Handler(Looper.getMainLooper())) {
                override fun onReceiveResult(code: Int, data: Bundle?) {
                    when (code) {
                        MODERN_RESULT_LOG -> {
                            modernLogPresentation(data?.getString("message").orEmpty())
                                ?.let(::noteVkEvent)
                        }
                        MODERN_RESULT_CANCEL -> callback.result.complete(null)
                        MODERN_RESULT_SAFE_FALLBACK -> callback.result.completeExceptionally(
                            ModernVkSafeFallbackException(),
                        )
                    }
                }
            }
            try {
                withContext(Dispatchers.Main.immediate) {
                    activity.startActivity(Intent().apply {
                        addFlags(Intent.FLAG_ACTIVITY_NO_ANIMATION)
                        setClassName(activity, ProfileWebSessionScope.modernActivity(profile.index))
                        ProfileWebSessionScope.put(this, profile)
                        putExtra("url", embedded.url)
                        putExtra("login_url", embedded.fallback)
                        putExtra("confirmation_url", embedded.confirmationUrl)
                        putExtra("confirmation_login_url", embedded.confirmationFallback)
                        putExtra("context", embedded.context)
                        putExtra("session", session)
                        putExtra("has_complete_values", hasCompleteLocalValues)
                        putExtra("receiver", receiver)
                    })
                }
            } catch (_: Exception) {
                throw ModernVkSafeFallbackException()
            }
            progress(onProgress, "Войдите в ВК при необходимости. Хеши будут получены автоматически…")
            val documentUri = try {
                withTimeout(AUTH_TIMEOUT_MS) {
                    awaitCallbackOrCompletion(
                        activity = activity,
                        callback = callback,
                        completion = target.completion,
                        deviceId = deviceId,
                    )
                }
            } catch (_: TimeoutCancellationException) {
                throw IllegalStateException(
                    "Время ожидания ответа ВК истекло. Новые ссылки автоматически не создаются.",
                )
            } ?: throw LocalContinuationCancelledException()
            markReadyDocument(activity, documentUri)
            completedSuccessfully = true
            progress(onProgress, "Четыре хеша получены. Обновляю профиль…")
            return documentUri
        } catch (fallback: ModernVkSafeFallbackException) {
            handingOff = true
            retainFallbackWindow(closeWindow)
            throw fallback
        } finally {
            if (!handingOff) closeWindow()
            directRouteLease?.release()
        }
    }

    private suspend fun runBrowserFallback(
        activity: MainActivity,
        target: RemoteLaunchTarget,
        deviceId: String,
        onProgress: (String) -> Unit,
        callback: ActiveCallback,
    ): Uri {
        var directRouteLease: TemporaryDirectRouteLease? = null
        try {
            progress(onProgress, "Открываю ВК в браузере…")
            directRouteLease = TemporaryDirectRouteLease.acquire(
                context = activity,
                domains = DIRECT_VK_DOMAINS,
            )
            val launchUri = Uri.parse(RemoteContinuationLauncher.authTabLaunchUrl(target))
            withContext(Dispatchers.Main.immediate) {
                activity.launchLocalContinuation(launchUri)
            }
            val callbackUri = try {
                withTimeout(AUTH_TIMEOUT_MS) {
                    awaitCallbackOrCompletion(
                        activity = activity,
                        callback = callback,
                        completion = target.completion,
                        deviceId = deviceId,
                    )
                }
            } catch (_: TimeoutCancellationException) {
                throw IllegalStateException("Время ожидания ответа ВК истекло.")
            } ?: throw LocalContinuationCancelledException()
            if (RemoteContinuationLauncher.isCancellationCallback(callbackUri)) {
                throw LocalContinuationCancelledException()
            }
            val documentUri = RemoteDocumentGateway.extractLink(callbackUri)?.let { callbackUri }
                ?: RemoteContinuationLauncher.callbackDocumentUri(callbackUri)
                ?: throw IllegalStateException(
                    "WDTT Plus получил повреждённый результат автоматической настройки.",
                )
            markReadyDocument(activity, documentUri)
            progress(onProgress, "Хеши получены. Обновляю профиль…")
            return documentUri
        } finally {
            directRouteLease?.release()
        }
    }

    private fun replaceCallback(previous: ActiveCallback): ActiveCallback {
        val replacement = ActiveCallback(CompletableDeferred())
        synchronized(callbackLock) {
            check(activeCallback === previous) { "Состояние получения изменилось." }
            activeCallback = replacement
        }
        return replacement
    }

    private fun nativeContinuationOrNull(): LocalContinuationExtension? = try {
        Class.forName("com.wdtt.plus.vk.NativeVkContinuation")
            .getField("INSTANCE").get(null) as LocalContinuationExtension
    } catch (_: ReflectiveOperationException) {
        null
    }

    private fun modernContainerSupported(activity: MainActivity, profileIndex: Int): Boolean {
        if (!experimentalAvailable) return false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (runCatching { WebView.getCurrentWebViewPackage() }.getOrNull() == null) return false
        }
        return runCatching {
            activity.packageManager.getActivityInfo(
                android.content.ComponentName(activity, ProfileWebSessionScope.modernActivity(profileIndex)),
                0,
            )
        }.isSuccess
    }

    private fun modernLogPresentation(raw: String): String? {
        val message = raw.trim()
        return when {
            message == "CAPTCHA / AUTOMATIC" -> "ВК запросил проверку. Выполняется одна автоматическая попытка."
            message == "CAPTCHA / MANUAL" -> "Пройдите проверку ВК вручную в открытом окне."
            message == "CAPTCHA / ERROR" -> "Не удалось пройти проверку ВК автоматически. Ошибка показана в окне проверки."
            message == "CAPTCHA / IDLE" -> "Окно проверки ВК закрыто. Продолжаю действие."
            message == "CAPTCHA / TIMEOUT" -> "Время ожидания проверки ВК истекло. Повторные запросы не отправляются."
            message.startsWith("OPEN /") -> "Открыто получение ВК-хешей внутри приложения."
            message.startsWith("MOBILE_AUTH_COMPLETE /") -> "Проверяю сессию ВК после мобильного входа."
            message.startsWith("REPLACE_CONFIRMED") -> "Подтверждена замена четырёх ВК-хешей."
            message.startsWith("BRIDGE / AUTO_READY /") -> "ВК готов к автоматическому получению хешей."
            message.startsWith("BRIDGE / INIT_WAIT /") -> "Подключаюсь к ВК для получения хешей."
            message.startsWith("BRIDGE / SESSION_WAIT /") -> "Проверяю сохранённый вход в ВК."
            message.startsWith("BRIDGE / PROFILE_WAIT /") -> "Подтверждаю аккаунт ВК."
            message.startsWith("BRIDGE / AUTH_REQUEST /") ->
                "ВК запросил подтверждение доступа для создания ссылок."
            message.startsWith("BRIDGE / AUTH_READY /") ->
                "Доступ ВК подтверждён. Начинаю получение хешей."
            message.startsWith("BRIDGE_REOPEN /") ->
                "После входа заново открываю получение ВК-хешей."
            message.startsWith("BRIDGE / CLAIM_WAIT /") ->
                "Завершаю вход в ВК и подготавливаю получение хешей."
            message.startsWith("BRIDGE / CLAIM_READY /") ->
                "Получение ВК-хешей подготовлено."
            message.startsWith("BRIDGE / AUTH_FAILED /") ->
                "Доступ ВК не подтверждён. Перехожу к резервному способу."
            message.startsWith("BRIDGE / CALL_SENT_") -> {
                val number = message.substringAfter("CALL_SENT_").substringBefore('/').trim()
                "Создаю ссылку ВК $number из 4."
            }
            message.startsWith("BRIDGE / CALL_HASH_") -> {
                val count = message.substringAfterLast('/').trim()
                "Получено ВК-хешей: $count из 4."
            }
            message.startsWith("BRIDGE / CALL_TIMEOUT_") ->
                "ВК не ответил вовремя. Автоматический повтор отключён."
            message.startsWith("BRIDGE / CALL_FAILED_") ->
                "ВК не создал ссылку. Автоматический повтор отключён."
            message.startsWith("BRIDGE / CALL_INVALID_") ||
                message.startsWith("BRIDGE / CALL_EMPTY_") ->
                "ВК не вернул ссылку звонка. Автоматический повтор отключён."
            message.startsWith("BRIDGE / PREP_FAILED /") ->
                "Не удалось завершить подготовку получения ВК-хешей."
            message.startsWith("BRIDGE / FLOW_FAILED /") ->
                "Получение остановлено без повторного создания ссылок."
            message.startsWith("BRIDGE / DELIVER_WAIT /") ->
                "Сохраняю четыре ВК-хеша в профиле."
            message.startsWith("BRIDGE / DELIVER_FAILED /") ->
                "Ссылки созданы, но передача результата не завершена. Повторяется только сохранение."
            message.startsWith("LOGOUT / COMPLETE") -> "Выполнен выход из ВК."
            message.startsWith("LOGOUT / FAILED") -> "Не удалось полностью выйти из ВК. Получение остановлено; повторите выход."
            message.startsWith("COMPLETE /") -> "Получены четыре ВК-хеша."
            message.startsWith("CLOSE /") -> "Получение ВК-хешей закрыто."
            else -> null
        }
    }

    private fun noteVkEvent(message: String) {
        com.wdtt.plus.TunnelManager.noteSystemLifecycleEvent(
            "vk_hashes_${System.currentTimeMillis()}",
            "[ВК] $message",
        )
    }

    override suspend fun recoverPending(activity: MainActivity): Uri? {
        synchronized(callbackLock) {
            if (activeCallback != null || recoveryInProgress) return null
            recoveryInProgress = true
        }
        try {
            val pending = loadPending(activity) ?: return null
            if (pending.completion.expiresAtSeconds <= nowSeconds()) {
                clearPending(activity)
                return null
            }
            if (pending.documentUrl.isNotBlank()) {
                return Uri.parse(pending.documentUrl)
            }
            val native = try {
                Class.forName("com.wdtt.plus.vk.NativeVkContinuation")
                    .getField("INSTANCE").get(null) as LocalContinuationExtension
            } catch (_: ClassNotFoundException) { null }
            native?.recoverPending(activity)?.let { recovered ->
                markReadyDocument(activity, recovered)
                return recovered
            }
            return when (
                val status = runCatching {
                    RemoteContinuationLauncher.checkCompletion(
                        context = activity,
                        completion = pending.completion,
                        device = pending.deviceId,
                    )
                }.getOrNull()
            ) {
                is RemoteActionCompletionState.Ready -> {
                    Uri.parse(status.document.url).also { markReadyDocument(activity, it) }
                }
                RemoteActionCompletionState.Unavailable -> {
                    clearPending(activity)
                    null
                }
                else -> null
            }
        } finally {
            synchronized(callbackLock) { recoveryInProgress = false }
        }
    }

    override fun acknowledgeDocument(activity: MainActivity, uri: Uri) {
        val context = activity.applicationContext
        val delivered = RemoteDocumentGateway.extractLink(uri)?.url ?: return
        val pending = loadPending(context) ?: return
        if (pending.documentUrl == delivered) {
            clearPending(context)
            val native = try {
                Class.forName("com.wdtt.plus.vk.NativeVkContinuation")
                    .getField("INSTANCE").get(null) as LocalContinuationExtension
            } catch (_: ClassNotFoundException) { null }
            native?.acknowledgeDocument(activity, uri)
        }
    }

    private suspend fun awaitCallbackOrCompletion(
        activity: MainActivity,
        callback: ActiveCallback,
        completion: RemoteActionCompletion,
        deviceId: String,
    ): Uri? {
        if (!completion.available) return callback.result.await()
        return coroutineScope {
            val polling = async(Dispatchers.IO) {
                delay(INITIAL_POLL_DELAY_MS)
                var attempt = 0
                while (isActive && completion.expiresAtSeconds > nowSeconds()) {
                    when (
                        val status = runCatching {
                            RemoteContinuationLauncher.checkCompletion(
                                context = activity,
                                completion = completion,
                                device = deviceId,
                            )
                        }.getOrNull()
                    ) {
                        is RemoteActionCompletionState.Ready ->
                            return@async Uri.parse(status.document.url)
                        RemoteActionCompletionState.Unavailable -> return@async null
                        else -> Unit
                    }
                    attempt++
                    delay(if (attempt < FAST_POLL_ATTEMPTS) FAST_POLL_MS else SLOW_POLL_MS)
                }
                null
            }
            try {
                select {
                    callback.result.onAwait { it }
                    polling.onAwait { recovered ->
                        recovered?.also { markReadyDocument(activity, it) }
                    }
                }
            } finally {
                polling.cancel()
            }
        }
    }

    private fun isAcceptedCallback(uri: Uri): Boolean =
        RemoteContinuationLauncher.isCancellationCallback(uri) ||
            RemoteContinuationLauncher.callbackDocumentUri(uri) != null

    private fun savePending(context: Context, pending: PendingCompletion) {
        val plain = JSONObject()
            .put("url", pending.completion.url)
            .put("key", pending.completion.key)
            .put("expires", pending.completion.expiresAtSeconds)
            .put("device", pending.deviceId)
            .put("document", pending.documentUrl)
            .toString()
        val encrypted = SecureStringStore(context).encrypt(plain)
        context.applicationContext
            .getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .edit()
            .putString(PENDING_KEY, encrypted)
            .apply()
    }

    private fun loadPending(context: Context): PendingCompletion? {
        val encrypted = context.applicationContext
            .getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .getString(PENDING_KEY, null)
            ?: return null
        val plain = SecureStringStore(context).decrypt(encrypted) ?: run {
            clearPending(context)
            return null
        }
        return runCatching {
            val root = JSONObject(plain)
            val completion = RemoteActionCompletion(
                available = true,
                url = root.getString("url"),
                key = root.getString("key"),
                expiresAtSeconds = root.getLong("expires"),
            )
            val device = root.getString("device")
            check(completion.url.startsWith("https://"))
            check(completion.key.length in 24..256)
            check(device.length in 8..128)
            PendingCompletion(
                completion = completion,
                deviceId = device,
                documentUrl = root.optString("document"),
            )
        }.getOrElse {
            clearPending(context)
            null
        }
    }

    private fun markReadyDocument(context: Context, uri: Uri) {
        val document = RemoteDocumentGateway.extractLink(uri)?.url ?: return
        val pending = loadPending(context) ?: return
        savePending(context, pending.copy(documentUrl = document))
    }

    private fun clearPending(context: Context) {
        context.applicationContext
            .getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .edit()
            .remove(PENDING_KEY)
            .apply()
    }

    private suspend fun progress(onProgress: (String) -> Unit, message: String) {
        withContext(Dispatchers.Main.immediate) { onProgress(message) }
    }

    private fun nowSeconds(): Long = System.currentTimeMillis() / 1000L

    private const val AUTH_TIMEOUT_MS = 15 * 60 * 1000L
    private const val INITIAL_POLL_DELAY_MS = 4_000L
    private const val FAST_POLL_MS = 4_000L
    private const val SLOW_POLL_MS = 10_000L
    private const val FAST_POLL_ATTEMPTS = 15
    private const val PREFERENCES = "wdtt_local_continuation"
    private const val PENDING_KEY = "pending_completion"
    private const val MODERN_ACTIVITY_CLASS = "com.wdtt.plus.vk.ModernVkContainerActivity"
    private const val MODERN_FINISH_ACTION = "com.wdtt.plus.vk.MODERN_VK_FINISH"
    private const val MODERN_RESULT_CANCEL = 0
    private const val MODERN_RESULT_LOG = 2
    private const val MODERN_RESULT_SAFE_FALLBACK = 3
    private val DIRECT_VK_DOMAINS = setOf(
        "vk.ru",
        "m.vk.ru",
        "id.vk.ru",
        "login.vk.ru",
        "api.vk.ru",
        "api.vk.com",
        "vk.com",
        "m.vk.com",
        "id.vk.com",
        "login.vk.com",
    )
}
