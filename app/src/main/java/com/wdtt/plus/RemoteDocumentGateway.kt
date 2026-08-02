package com.wdtt.plus

import android.net.Uri
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.util.TimeZone

data class RemoteDocumentLink(val url: String)

data class RemoteDocumentFailureAction(
    val label: String,
    val target: RemoteLaunchTarget,
)

class RemoteDocumentFailure(
    message: String,
    val action: RemoteDocumentFailureAction? = null,
    val profileAttachmentRequired: Boolean = false,
) : IllegalStateException(message)

data class RemoteContinuation(
    val available: Boolean,
    val key: String = "",
    val url: String = "",
    val expiresAt: Long = 0,
    val message: String = ""
)

enum class RemoteDocumentKind {
    BASE,
    UPDATE,
    ATTACHMENT,
}

data class RemoteDocumentDelivery(
    val document: String,
    val binding: String,
    val continuation: RemoteContinuation,
    val access: RemoteAccessCapability,
    val kind: RemoteDocumentKind,
    val profileMaxWorkers: Int = 0,
    val profileRevision: Long = 0,
)

internal fun RemoteDocumentDelivery.shouldPreserveLocalVkHashes(
    existingProfileRedelivery: Boolean = false,
): Boolean {
    val deliveredHashes = WdttDeepLink.parse(
        document,
        allowMissingHashes = true,
        allowOmittedConnection = kind == RemoteDocumentKind.UPDATE,
    )
        ?.hashes
        .orEmpty()
    return deliveredHashes.isBlank() &&
        (
            kind == RemoteDocumentKind.UPDATE ||
                (kind == RemoteDocumentKind.BASE && existingProfileRedelivery)
            )
}

internal fun RemoteDocumentDelivery.requiresInitialContinuationWarning(
    existingProfileHasVkHashes: Boolean = false,
): Boolean =
    kind == RemoteDocumentKind.BASE &&
        !continuation.available &&
    !existingProfileHasVkHashes

internal fun attachmentDocumentForRequest(localDocument: String?): String? =
    localDocument
        ?.trim()
        ?.takeIf { document ->
            document.length <= 4 * 1024 &&
                document.startsWith("wdtt://connect?", ignoreCase = true) &&
                WdttDeepLink.parse(document, allowMissingHashes = true)
                    ?.let { it.hashes.isBlank() } == true
        }

internal fun eligibleRemoteAttachmentDocument(
    localDocument: String?,
    alreadyManaged: Boolean,
): String? = if (alreadyManaged) null else attachmentDocumentForRequest(localDocument)

internal fun profileAttachmentRequired(value: String?): Boolean = value?.trim() == "1"

object RemoteDocumentGateway {
    private const val MAX_RESPONSE_CHARS = 32 * 1024

    fun extractLink(uri: Uri): RemoteDocumentLink? = extractLink(uri.toString())

    fun extractLink(rawUri: String): RemoteDocumentLink? {
        val uri = runCatching { URI(rawUri.trim()) }.getOrNull() ?: return null
        val path = uri.path.orEmpty()
        val code = path.takeIf { it.startsWith("/c/") }
            ?.removePrefix("/c/")
            ?.trim()
            .orEmpty()
        val navigationMarkerValid = uri.rawQuery.isNullOrBlank() ||
            Regex("^open=[0-9]{1,20}$").matches(uri.rawQuery)
        val valid = trustedServiceUri(uri) &&
            navigationMarkerValid &&
            uri.rawFragment.isNullOrBlank() &&
            Regex("^[A-Za-z0-9_-]{6,64}$").matches(code)
        if (!valid) return null
        return RemoteDocumentLink("https://${BuildConfig.WDTT_PLUS_DOMAIN}/c/$code")
    }

    suspend fun receive(
        link: RemoteDocumentLink,
        device: String,
        label: String,
        client: String,
        system: String,
        localBindings: Collection<String>? = null,
        localDocument: String? = null,
        profileAttachment: Boolean = false,
    ): RemoteDocumentDelivery {
        require(extractLink(link.url) != null) { "Ссылка повреждена или неполна." }
        require(validDevice(device)) { "Не удалось определить текущее устройство." }
        return withContext(Dispatchers.IO) {
            val request = JSONObject()
                .put("device", device.trim())
                .put("label", label.trim().take(160))
                .put("client", client.trim().take(64))
                .put("system", system.trim().take(64))
                .put("timezone", TimeZone.getDefault().id.take(64))
            if (localBindings != null) {
                val bindings = localBindings
                    .map(String::trim)
                    .filter(::opaqueValue)
                    .distinct()
                    .take(6)
                request.put("bindings", JSONArray(bindings))
            }
            attachmentDocumentForRequest(localDocument)
                ?.let { request.put("profile", it) }
            if (profileAttachment) {
                request.put("attach", true)
            }
            val payload = request
                .toString()
                .toByteArray(Charsets.UTF_8)
            var connection: HttpURLConnection? = null
            try {
                connection = URL(link.url).openConnection() as HttpURLConnection
                connection.requestMethod = "POST"
                connection.connectTimeout = 10_000
                connection.readTimeout = 12_000
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
                connection.setRequestProperty("Accept", "application/json")
                connection.outputStream.use { it.write(payload) }
                val status = connection.responseCode
                val body = readBody(connection, status)
                if (status !in 200..299) {
                    val failure = parseFailure(body)
                    throw RemoteDocumentFailure(
                        failure.first.ifBlank {
                            "Ссылка недоступна. Получите новую ссылку подключения."
                        },
                        failure.second,
                        profileAttachmentRequired = profileAttachmentRequired(
                            connection.getHeaderField("X-WDTT-Profile-Required")
                        ),
                    )
                }
                parse(body)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                if (error is IllegalStateException) throw error
                throw IllegalStateException(
                    "Не удалось связаться с WDTT Plus. Проверьте интернет и попробуйте ещё раз."
                )
            } finally {
                connection?.disconnect()
            }
        }
    }

    internal fun parse(body: String): RemoteDocumentDelivery {
        require(body.length <= MAX_RESPONSE_CHARS) { "Ответ WDTT Plus слишком большой." }
        val root = runCatching { JSONObject(body) }
            .getOrElse { throw IllegalStateException("WDTT Plus вернул неполные данные.") }
        if (root.optInt("version", 0) != 1) {
            throw IllegalStateException("Для этой ссылки нужна более новая версия WDTT Plus.")
        }
        val kind = when (root.optString("type").trim()) {
            "base" -> RemoteDocumentKind.BASE
            "update" -> RemoteDocumentKind.UPDATE
            "attachment" -> RemoteDocumentKind.ATTACHMENT
            else -> throw IllegalStateException("WDTT Plus вернул неподдерживаемый тип данных.")
        }
        val document = root.optString("document").trim()
        val documentParts = document
            .takeIf(String::isNotBlank)
            ?.let {
                WdttDeepLink.parse(
                    it,
                    allowMissingHashes = true,
                    allowOmittedConnection = kind == RemoteDocumentKind.UPDATE,
                )
            }
        if (kind != RemoteDocumentKind.ATTACHMENT && documentParts == null) {
            throw IllegalStateException("WDTT Plus вернул неполные данные подключения.")
        }
        val binding = root.optString("binding").trim().takeIf(::opaqueValue).orEmpty()
        val action = root.optJSONObject("continuation")
        val key = action?.optString("key").orEmpty().trim()
        val url = action?.optString("url").orEmpty().trim()
        val available = action?.optBoolean("available", false) == true &&
            opaqueValue(key) && safeServiceUrl(url)
        val accessSource = root.optJSONObject("access")
        val accessKey = accessSource?.optString("key").orEmpty().trim()
        val accessUrl = accessSource?.optString("url").orEmpty().trim()
        val accessBinding = accessSource?.optString("binding").orEmpty().trim()
        val accessAvailable = accessSource?.optBoolean("available", false) == true &&
            opaqueValue(accessKey) &&
            safeServiceUrl(accessUrl) &&
            opaqueValue(accessBinding)
        val cachedAction = accessSource
            ?.optJSONObject("cached_action")
            ?.let(::parseCachedAction)
            ?: CachedRemoteAction.Unavailable
        val exchange = accessSource
            ?.optJSONObject("exchange")
            ?.let(::parseProfileExchange)
            ?: RemoteProfileExchange.Unavailable
        val initialAccessStatus = if (accessAvailable) {
            accessSource
                ?.optJSONObject("status")
                ?.let { nested ->
                    AccessLifecycleGateway.parseStatus(
                        JSONObject(nested.toString()).put("version", 1).toString()
                    )
                }
        } else {
            null
        }
        when (kind) {
            RemoteDocumentKind.BASE -> {
                if (documentParts?.hashes?.isNotBlank() == true) {
                    throw IllegalStateException(
                        "Ссылка подключения содержит лишние данные. Получите новую ссылку."
                    )
                }
            }
            RemoteDocumentKind.UPDATE -> {
                if (
                    binding.isBlank() ||
                    action != null
                ) {
                    throw IllegalStateException(
                        "Обновление профиля неполное или относится к другому действию."
                    )
                }
            }
            RemoteDocumentKind.ATTACHMENT -> {
                if (
                    document.isNotBlank() ||
                    binding.isBlank() ||
                    !available ||
                    !accessAvailable ||
                    accessBinding != binding
                ) {
                    throw IllegalStateException(
                        "WDTT Plus вернул неполное разрешение для выбранного профиля."
                    )
                }
            }
        }
        val workers = root.optJSONObject("limits")?.optInt("workers", 0)
            ?.takeIf {
                it in TUNNEL_WORKERS_PER_GROUP..APP_MAX_WORKERS &&
                    it % TUNNEL_WORKERS_PER_GROUP == 0
            }
            ?: 0
        val profileRevision = root.optLong("profile_revision", 0L).coerceAtLeast(0)
        return RemoteDocumentDelivery(
            document = document,
            binding = binding,
            continuation = RemoteContinuation(
                available = available,
                key = key.takeIf { available }.orEmpty(),
                url = url.takeIf { available }.orEmpty(),
                expiresAt = action?.optLong("expires", 0L) ?: 0L,
                message = action?.optString("message").orEmpty().trim()
            ),
            access = RemoteAccessCapability(
                available = accessAvailable,
                key = accessKey.takeIf { accessAvailable }.orEmpty(),
                url = accessUrl.takeIf { accessAvailable }.orEmpty(),
                binding = accessBinding.takeIf { accessAvailable }.orEmpty(),
                initialStatus = initialAccessStatus.takeIf { accessAvailable },
                cachedAction = cachedAction.takeIf { accessAvailable }
                    ?: CachedRemoteAction.Unavailable,
                exchange = exchange.takeIf { accessAvailable }
                    ?: RemoteProfileExchange.Unavailable,
            ),
            kind = kind,
            profileMaxWorkers = workers,
            profileRevision = profileRevision,
        )
    }

    internal fun parseFailure(body: String): Pair<String, RemoteDocumentFailureAction?> {
        if (body.length > MAX_RESPONSE_CHARS) return "" to null
        val root = runCatching { JSONObject(body) }.getOrNull() ?: return "" to null
        val detail = root.optString("detail").trim().take(600)
        val source = root.optJSONObject("action") ?: return detail to null
        if (!source.optBoolean("available", false)) return detail to null
        val label = source.optString("label").trim().take(120)
        val primary = source.optString("url").trim()
        val fallback = source.optString("fallback").trim()
        val handler = source.optString("handler").trim()
        val alternatesSource = source.optJSONArray("alternate_handlers") ?: JSONArray()
        if (alternatesSource.length() > 8) return detail to null
        val alternates = buildList {
            repeat(alternatesSource.length()) { index ->
                val value = alternatesSource.optString(index).trim()
                if (!safePackageName(value)) return detail to null
                add(value)
            }
        }.distinct()
        val valid = label.isNotBlank() &&
            safeExternalUrl(primary) &&
            (fallback.isBlank() || safeExternalUrl(fallback)) &&
            (handler.isBlank() || safePackageName(handler))
        if (!valid) return detail to null
        return detail to RemoteDocumentFailureAction(
            label = label,
            target = RemoteLaunchTarget(
                primaryUrl = primary,
                fallbackUrl = fallback,
                preferredHandler = handler,
                alternateHandlers = alternates,
            ),
        )
    }

    private fun safeServiceUrl(value: String): Boolean {
        val uri = runCatching { URI(value) }.getOrNull() ?: return false
        return trustedServiceUri(uri) &&
            uri.rawQuery.isNullOrBlank() &&
            uri.rawFragment.isNullOrBlank()
    }

    internal fun parseCachedAction(source: JSONObject): CachedRemoteAction {
        val payload = source.optString("payload").trim()
        val primary = source.optString("url").trim()
        val fallback = source.optString("fallback").trim()
        val handler = source.optString("handler").trim()
        val available = source.optBoolean("available", false) &&
            opaquePayload(payload) &&
            safeExternalUrl(primary) &&
            (fallback.isBlank() || safeExternalUrl(fallback)) &&
            (handler.isBlank() || safePackageName(handler))
        if (!available) return CachedRemoteAction.Unavailable
        return CachedRemoteAction(
            available = true,
            payload = payload,
            target = RemoteLaunchTarget(
                primaryUrl = primary,
                fallbackUrl = fallback,
                preferredHandler = handler,
            ),
            title = source.optString("title").trim().take(120),
            message = source.optString("message").trim().take(600),
            label = source.optString("label").trim().take(120),
            clipboardLabel = source.optString("clipboard_label").trim().take(120),
            copiedMessage = source.optString("copied_message").trim().take(240),
            failedMessage = source.optString("failed_message").trim().take(240),
            helpTitle = source.optString("help_title").trim().take(120),
            helpIntro = source.optString("help_intro").trim().take(600),
            helpSteps = source.optString("help_steps").trim().take(1200),
        )
    }

    internal fun parseProfileExchange(source: JSONObject): RemoteProfileExchange {
        val submit = source.optJSONObject("submit")
        val action = source.optJSONObject("action")
        val submitToken = submit?.optString("token").orEmpty().trim()
        val actionToken = action?.optString("token").orEmpty().trim()
        val submitAvailable =
            submit?.optBoolean("available", false) == true && opaqueValue(submitToken)
        val label = action?.optString("label").orEmpty().trim().take(80)
        val message = action?.optString("message").orEmpty().trim().take(300)
        val actionAvailable =
            action?.optBoolean("available", false) == true &&
                opaqueValue(actionToken) &&
                label.isNotBlank()
        return if (submitAvailable || opaqueValue(actionToken)) {
            RemoteProfileExchange(
                submitAvailable = submitAvailable,
                submitToken = submitToken.takeIf { submitAvailable }.orEmpty(),
                actionAvailable = actionAvailable,
                actionToken = actionToken.takeIf(::opaqueValue).orEmpty(),
                label = label,
                message = message,
            )
        } else {
            RemoteProfileExchange.Unavailable
        }
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

    private fun opaquePayload(value: String): Boolean =
        value.length in 24..512 && Regex("^[A-Za-z0-9._-]+$").matches(value)

    private fun trustedServiceUri(uri: URI): Boolean =
        uri.scheme.equals("https", ignoreCase = true) &&
            uri.host.equals(BuildConfig.WDTT_PLUS_DOMAIN, ignoreCase = true) &&
            uri.rawUserInfo.isNullOrBlank() &&
            (uri.port == -1 || uri.port == 443)

    private fun opaqueValue(value: String): Boolean =
        value.length in 24..256 && Regex("^[A-Za-z0-9_-]+$").matches(value)

    private fun validDevice(value: String): Boolean =
        Regex("^[A-Za-z0-9_.:-]{8,128}$").matches(value.trim())

    private fun readBody(connection: HttpURLConnection, status: Int): String {
        val stream = if (status in 200..299) connection.inputStream else connection.errorStream
        return stream?.use { it.readUtf8TextLimited(MAX_RESPONSE_CHARS) }.orEmpty()
    }
}
