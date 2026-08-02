package com.wdtt.plus

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.activity.result.ActivityResultLauncher
import androidx.browser.auth.AuthTabIntent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.net.URLDecoder

data class RemoteLaunchTarget(
    val primaryUrl: String,
    val fallbackUrl: String = "",
    val preferredHandler: String = "",
    val alternateHandlers: List<String> = emptyList(),
    val returnScheme: String = "",
) {
    internal fun handlerPackages(): List<String> =
        (listOf(preferredHandler) + alternateHandlers)
            .filter(String::isNotBlank)
            .distinct()
}

object RemoteContinuationLauncher {
    suspend fun begin(
        capability: RemoteContinuation,
        device: String,
        localDocument: String? = null,
    ): RemoteLaunchTarget {
        require(capability.available && opaqueValue(capability.key)) {
            "Автоматическое заполнение недоступно для этого профиля."
        }
        require(safeServiceUrl(capability.url)) { "Автоматическое заполнение сейчас недоступно." }
        require(validDevice(device)) { "Не удалось определить текущее устройство." }
        return withContext(Dispatchers.IO) {
            val request = JSONObject()
                .put("key", capability.key.trim())
                .put("device", device.trim())
                .put("return_transport", "auth_tab")
            attachmentDocumentForRequest(localDocument)?.let { document ->
                request.put("profile", document)
            }
            val payload = request
                .toString()
                .toByteArray(Charsets.UTF_8)
            var connection: HttpURLConnection? = null
            try {
                connection = URL(capability.url).openConnection() as HttpURLConnection
                connection.requestMethod = "POST"
                connection.connectTimeout = 10_000
                connection.readTimeout = 15_000
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
                connection.setRequestProperty("Accept", "application/json")
                connection.outputStream.use { it.write(payload) }
                val status = connection.responseCode
                val body = readBody(connection, status)
                if (status !in 200..299) {
                    val detail = runCatching { JSONObject(body).optString("detail") }.getOrDefault("")
                    throw IllegalStateException(
                        detail.ifBlank { "Не удалось продолжить действие. Откройте свежую ссылку подключения." }
                    )
                }
                val response = runCatching { JSONObject(body) }
                    .getOrElse { throw IllegalStateException("WDTT Plus вернул неполные данные.") }
                val primary = response.optString("url").trim()
                val fallback = response.optString("fallback").trim()
                val handler = response.optString("handler").trim()
                val alternateHandlers = parseAlternateHandlers(response)
                val returnScheme = response.optString("return_scheme").trim()
                require(safeExternalUrl(primary)) {
                    "WDTT Plus вернул повреждённый адрес продолжения."
                }
                require(fallback.isBlank() || safeExternalUrl(fallback)) {
                    "WDTT Plus вернул повреждённый резервный адрес."
                }
                require(handler.isBlank() || safePackageName(handler)) {
                    "WDTT Plus вернул повреждённый обработчик продолжения."
                }
                require(alternateHandlers != null) {
                    "WDTT Plus вернул повреждённые резервные обработчики."
                }
                require(returnScheme.isBlank() || returnScheme == AUTH_TAB_RETURN_SCHEME) {
                    "WDTT Plus вернул повреждённый способ возврата."
                }
                RemoteLaunchTarget(
                    primaryUrl = primary,
                    fallbackUrl = fallback,
                    preferredHandler = handler,
                    alternateHandlers = alternateHandlers,
                    returnScheme = returnScheme,
                )
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                if (error is IllegalStateException) throw error
                throw IllegalStateException(
                    "Не удалось связаться с WDTT Plus. Проверьте интернет и повторите попытку."
                )
            } finally {
                connection?.disconnect()
            }
        }
    }

    fun launch(
        context: Context,
        target: RemoteLaunchTarget,
        authTabLauncher: ActivityResultLauncher<Intent>? = null,
    ) {
        require(safeExternalUrl(target.primaryUrl)) { "Адрес продолжения повреждён." }
        val handlerPackages = target.handlerPackages()
        require(handlerPackages.size <= MAX_HANDLER_PACKAGES) {
            "Получено слишком много обработчиков продолжения."
        }
        handlerPackages.forEach { handler ->
            require(safePackageName(handler)) { "Обработчик продолжения повреждён." }
            try {
                context.startActivity(
                    Intent(Intent.ACTION_VIEW, Uri.parse(target.primaryUrl)).apply {
                        addCategory(Intent.CATEGORY_BROWSABLE)
                        setPackage(handler)
                    }
                )
                return
            } catch (_: ActivityNotFoundException) {
                // The fallback preserves the remote operation when its preferred app is unavailable.
            } catch (_: SecurityException) {
                // Some Android builds reject explicit package launches; use the browser below.
            }
        }
        if (target.returnScheme == AUTH_TAB_RETURN_SCHEME && authTabLauncher != null) {
            AuthTabIntent.Builder()
                .build()
                .launch(
                    authTabLauncher,
                    Uri.parse(authTabLaunchUrl(target)),
                    AUTH_TAB_RETURN_SCHEME,
                )
            return
        }
        var lastFailure: Exception? = null
        for (browserUrl in browserLaunchUrls(target)) {
            try {
                context.startActivity(
                    Intent(Intent.ACTION_VIEW, Uri.parse(browserUrl)).apply {
                        addCategory(Intent.CATEGORY_BROWSABLE)
                    }
                )
                return
            } catch (error: ActivityNotFoundException) {
                lastFailure = error
            } catch (error: SecurityException) {
                lastFailure = error
            }
        }
        throw IllegalStateException(
            "Не удалось открыть VK или страницу продолжения. Проверьте приложение VK и браузер.",
            lastFailure,
        )
    }

    internal fun authTabLaunchUrl(target: RemoteLaunchTarget): String =
        browserLaunchUrls(target).first()

    internal fun browserLaunchUrls(target: RemoteLaunchTarget): List<String> =
        (
            // The primary URL is for the preferred native VK handler. When
            // that handler is unavailable, the backend-provided mobile login
            // URL is the proven browser entry: it preserves the opaque `to`
            // state through an unauthenticated VK login and immediately
            // continues to the Mini App for an existing browser session.
            if (target.handlerPackages().isNotEmpty() && target.fallbackUrl.isNotBlank()) {
                listOf(target.fallbackUrl, target.primaryUrl)
            } else {
                listOf(target.primaryUrl, target.fallbackUrl)
            }
        )
            .filter { it.isNotBlank() }
            .onEach {
                require(safeExternalUrl(it)) { "Резервный адрес продолжения повреждён." }
            }
            .distinct()

    internal fun callbackDocumentUri(callback: Uri?): Uri? {
        val document = callbackDocumentUrl(callback?.toString().orEmpty()) ?: return null
        return Uri.parse(document)
    }

    internal fun isCancellationCallback(callback: Uri?): Boolean =
        isCancellationCallback(callback?.toString().orEmpty())

    internal fun isCancellationCallback(rawCallback: String): Boolean {
        val uri = runCatching { URI(rawCallback.trim()) }.getOrNull() ?: return false
        return uri.scheme.equals(AUTH_TAB_RETURN_SCHEME, ignoreCase = true) &&
            uri.host.equals("return", ignoreCase = true) &&
            uri.port == -1 &&
            uri.rawUserInfo.isNullOrBlank() &&
            uri.path.orEmpty().isBlank() &&
            uri.rawQuery.isNullOrBlank() &&
            uri.rawFragment.isNullOrBlank()
    }

    internal fun callbackDocumentUrl(rawCallback: String): String? {
        val callback = runCatching { URI(rawCallback.trim()) }.getOrNull() ?: return null
        if (
            !callback.scheme.equals(AUTH_TAB_RETURN_SCHEME, ignoreCase = true) ||
            !callback.host.equals("return", ignoreCase = true) ||
            callback.port != -1 ||
            !callback.rawUserInfo.isNullOrBlank() ||
            !callback.rawFragment.isNullOrBlank() ||
            callback.path.orEmpty().isNotBlank()
        ) {
            return null
        }
        val documents = callback.rawQuery.orEmpty()
            .split('&')
            .mapNotNull { item ->
                val separator = item.indexOf('=')
                if (separator <= 0) return@mapNotNull null
                val key = URLDecoder.decode(
                    item.substring(0, separator),
                    Charsets.UTF_8.name(),
                )
                if (key != "document") return@mapNotNull null
                URLDecoder.decode(
                    item.substring(separator + 1),
                    Charsets.UTF_8.name(),
                )
            }
        val document = documents.singleOrNull()?.trim().orEmpty()
        return RemoteDocumentGateway.extractLink(document)?.url
    }

    private fun safeServiceUrl(value: String): Boolean {
        val uri = runCatching { URI(value) }.getOrNull() ?: return false
        return uri.scheme.equals("https", ignoreCase = true) &&
            uri.host.equals(BuildConfig.WDTT_PLUS_DOMAIN, ignoreCase = true) &&
            uri.rawUserInfo.isNullOrBlank() &&
            uri.rawQuery.isNullOrBlank() &&
            uri.rawFragment.isNullOrBlank() &&
            (uri.port == -1 || uri.port == 443)
    }

    private fun safeExternalUrl(value: String): Boolean {
        val uri = runCatching { URI(value) }.getOrNull() ?: return false
        return uri.scheme.equals("https", ignoreCase = true) &&
            !uri.host.isNullOrBlank() &&
            uri.rawUserInfo.isNullOrBlank() &&
            (uri.port == -1 || uri.port == 443)
    }

    private fun safePackageName(value: String): Boolean =
        value.length in 3..255 &&
            Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+$").matches(value)

    private fun parseAlternateHandlers(source: JSONObject): List<String>? {
        val handlers = source.optJSONArray("alternate_handlers") ?: return emptyList()
        if (handlers.length() > MAX_HANDLER_PACKAGES - 1) return null
        return (0 until handlers.length())
            .map { index -> handlers.optString(index).trim() }
            .takeIf { values ->
                values.all { it.isNotBlank() && safePackageName(it) } &&
                    values.distinct().size == values.size
            }
    }

    private fun opaqueValue(value: String): Boolean =
        value.length in 24..256 && Regex("^[A-Za-z0-9_-]+$").matches(value)

    private fun validDevice(value: String): Boolean =
        Regex("^[A-Za-z0-9_.:-]{8,128}$").matches(value.trim())

    private fun readBody(connection: HttpURLConnection, status: Int): String {
        val stream = if (status in 200..299) connection.inputStream else connection.errorStream
        return stream?.use { it.readUtf8TextLimited(MAX_RESPONSE_BYTES) }.orEmpty()
    }

    private const val AUTH_TAB_RETURN_SCHEME = "wdtt"
    private const val MAX_HANDLER_PACKAGES = 8
    private const val MAX_RESPONSE_BYTES = 32 * 1024
}
