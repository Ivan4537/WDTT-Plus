package com.wdtt.plus

import android.net.Uri
import kotlinx.coroutines.CancellationException

/** Provider-neutral continuation interface for the built-in device adapter. */
interface LocalContinuationExtension {
    /** Optional isolated preview route. The normal continuation remains the default. */
    val experimentalAvailable: Boolean
        get() = false

    suspend fun execute(
        activity: MainActivity,
        target: RemoteLaunchTarget,
        deviceId: String,
        hasCompleteLocalValues: Boolean,
        onProgress: (String) -> Unit,
    ): Uri

    fun offerCallback(uri: Uri?): Boolean

    suspend fun recoverPending(activity: MainActivity): Uri?

    fun acknowledgeDocument(activity: MainActivity, uri: Uri)

    suspend fun executeExperimental(
        activity: MainActivity,
        target: RemoteLaunchTarget,
        deviceId: String,
        hasCompleteLocalValues: Boolean,
        onProgress: (String) -> Unit,
    ): Uri = throw IllegalStateException("Экспериментальный способ недоступен в этой сборке.")
}

class LocalContinuationCancelledException : CancellationException("Получение из ВК отменено.")

/** No external mutation was started, so another continuation may be tried safely. */
class LocalContinuationSafeFallbackException : IllegalStateException(
    "Нужен резервный способ получения ВК-хешей.",
)

object LocalContinuationExtensions {
    private val extension: LocalContinuationExtension? by lazy {
        runCatching {
            Class.forName(EXTENSION_CLASS)
                .getField("INSTANCE")
                .get(null) as LocalContinuationExtension
        }.getOrNull()
    }

    val available: Boolean
        get() = extension != null

    val experimentalAvailable: Boolean
        get() = extension?.experimentalAvailable == true

    suspend fun execute(
        activity: MainActivity,
        target: RemoteLaunchTarget,
        deviceId: String,
        hasCompleteLocalValues: Boolean,
        onProgress: (String) -> Unit,
    ): Uri {
        val current = extension
            ?: throw IllegalStateException("Локальное продолжение недоступно в этой сборке.")
        return try {
            current.execute(
                activity,
                target,
                deviceId,
                hasCompleteLocalValues,
                onProgress,
            )
        } catch (cancelled: CancellationException) {
            throw cancelled
        }
    }

    suspend fun executeExperimental(
        activity: MainActivity,
        target: RemoteLaunchTarget,
        deviceId: String,
        hasCompleteLocalValues: Boolean,
        onProgress: (String) -> Unit,
    ): Uri {
        val current = extension
            ?.takeIf { it.experimentalAvailable }
            ?: throw IllegalStateException("Экспериментальный способ недоступен в этой сборке.")
        return current.executeExperimental(
            activity = activity,
            target = target,
            deviceId = deviceId,
            hasCompleteLocalValues = hasCompleteLocalValues,
            onProgress = onProgress,
        )
    }

    fun offerCallback(uri: Uri?): Boolean = extension?.offerCallback(uri) == true

    suspend fun recoverPending(activity: MainActivity): Uri? =
        extension?.recoverPending(activity)

    fun acknowledgeDocument(activity: MainActivity, uri: Uri) {
        extension?.acknowledgeDocument(activity, uri)
    }

    private const val EXTENSION_CLASS = "com.wdtt.plus.vk.VkContinuationExecutor"
}
