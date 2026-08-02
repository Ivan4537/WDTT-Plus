package com.wdtt.plus

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL

enum class AccessLifecycleFailureKind {
    REJECTED,
    UNBOUND,
    UNAVAILABLE,
    TEMPORARY;

    val authoritative: Boolean
        get() = this != TEMPORARY
}

class AccessLifecycleRequestException(
    val kind: AccessLifecycleFailureKind,
    val code: String,
    message: String,
) : IllegalStateException(message)

object AccessLifecycleGateway {
    private const val MAX_RESPONSE_CHARS = 32 * 1024

    suspend fun fetch(
        capability: RemoteAccessCapability,
        device: String,
        client: String,
        system: String,
        timezone: String,
        profileRevision: Long,
    ): AccessLifecycleStatus = request(
        capability = capability,
        device = device,
        client = client,
        system = system,
        timezone = timezone,
        profileRevision = profileRevision,
        operation = "status",
    ).let(::parseStatus)

    suspend fun begin(
        capability: RemoteAccessCapability,
        device: String,
        client: String,
        system: String,
        timezone: String,
        profileRevision: Long,
    ): RemoteLaunchTarget = request(
        capability = capability,
        device = device,
        client = client,
        system = system,
        timezone = timezone,
        profileRevision = profileRevision,
        operation = "continue",
    ).let(::parseLaunchTarget)

    suspend fun submitProfileValues(
        capability: RemoteAccessCapability,
        token: String,
        device: String,
        client: String,
        system: String,
        timezone: String,
        values: List<String>,
    ): RemoteProfileExchange =
        parseExchangeResult(
            request(
                capability = capability,
                device = device,
                client = client,
                system = system,
                timezone = timezone,
                profileRevision = 0,
                action = token,
                values = values,
            )
        )

    suspend fun invokeProfileAction(
        capability: RemoteAccessCapability,
        token: String,
        device: String,
        client: String,
        system: String,
        timezone: String,
        profileRevision: Long,
    ): RemoteDocumentLink = request(
        capability = capability,
        device = device,
        client = client,
        system = system,
        timezone = timezone,
        profileRevision = profileRevision,
        action = token,
    ).let(::parseActionDocument)

    private suspend fun request(
        capability: RemoteAccessCapability,
        device: String,
        client: String,
        system: String,
        timezone: String,
        profileRevision: Long,
        operation: String = "",
        action: String = "",
        values: List<String> = emptyList(),
    ): String {
        require(capability.available && opaqueValue(capability.key)) {
            "Управление доступом недоступно для этого профиля."
        }
        require(safeServiceUrl(capability.url)) {
            "Не удалось проверить доступ для этого профиля."
        }
        require(validDevice(device)) { "Не удалось определить текущее устройство." }
        require(
            (
                operation in setOf("status", "continue") &&
                    action.isBlank()
                ) ||
                (
                    operation.isBlank() &&
                        opaqueValue(action)
                    )
        )
        require(values.size <= 16)
        return withContext(Dispatchers.IO) {
            val payload = JSONObject()
                .put("key", capability.key.trim())
                .put("device", device.trim())
                .put("client", client.trim().take(64))
                .put("system", system.trim().take(64))
                .put("timezone", timezone.trim().take(64))
                .put("profile_revision", profileRevision.coerceAtLeast(0))
                .put("values", org.json.JSONArray(values))
                .apply {
                    if (operation.isNotBlank()) put("operation", operation)
                    if (action.isNotBlank()) put("action", action)
                }
                .toString()
                .toByteArray(Charsets.UTF_8)
            var connection: HttpURLConnection? = null
            try {
                connection = URL(capability.url).openConnection() as HttpURLConnection
                connection.requestMethod = "POST"
                connection.instanceFollowRedirects = false
                connection.connectTimeout = 7_000
                connection.readTimeout = 9_000
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
                connection.setRequestProperty("Accept", "application/json")
                connection.outputStream.use { it.write(payload) }
                val status = connection.responseCode
                val body = readBody(connection, status)
                if (status !in 200..299) {
                    throw parseHttpFailure(
                        status = status,
                        body = body,
                        operation = operation,
                        codeHint = connection.getHeaderField("X-WDTT-Access-Code").orEmpty(),
                    )
                }
                body
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                if (error is IllegalStateException) throw error
                throw IllegalStateException(
                    if (operation == "continue") {
                        "Не удалось открыть страницу. Проверьте интернет и повторите попытку."
                    } else if (action.isNotBlank()) {
                        "Не удалось обновить сохранённые данные профиля."
                    } else {
                        "Не удалось проверить профиль. Проверьте интернет."
                    }
                )
            } finally {
                connection?.disconnect()
            }
        }
    }

    internal fun parseHttpFailure(
        status: Int,
        body: String,
        operation: String,
        codeHint: String = "",
    ): AccessLifecycleRequestException {
        val root = runCatching { JSONObject(body) }.getOrNull()
        val detail = root?.opt("detail")
        val structured = detail as? JSONObject
        val code = structured?.optString("code").orEmpty()
            .ifBlank { root?.optString("code").orEmpty() }
            .ifBlank { codeHint }
            .trim()
            .lowercase()
        val message = (
            structured?.optString("message")
                ?: (detail as? String)
                ?: ""
            ).trim().take(300)
        val kind = when {
            status == 410 || code == "expired" -> AccessLifecycleFailureKind.REJECTED
            code in setOf("unbound", "device_mismatch") -> AccessLifecycleFailureKind.UNBOUND
            status in setOf(401, 403, 404) ||
                code in setOf("removed", "revoked", "not_found", "forbidden") ->
                AccessLifecycleFailureKind.UNAVAILABLE
            else -> AccessLifecycleFailureKind.TEMPORARY
        }
        val fallback = when {
            operation == "continue" -> "Действие сейчас недоступно. Попробуйте позже."
            kind == AccessLifecycleFailureKind.REJECTED ->
                "Поставщик отклонил использование этого профиля."
            kind == AccessLifecycleFailureKind.UNBOUND ->
                "Профиль отвязан от этого устройства."
            kind == AccessLifecycleFailureKind.UNAVAILABLE ->
                "Профиль больше недоступен для этого устройства."
            else -> "Не удалось проверить профиль."
        }
        return AccessLifecycleRequestException(
            kind = kind,
            code = code.ifBlank { "http_$status" },
            message = message.ifBlank { fallback },
        )
    }

    internal fun parseStatus(body: String): AccessLifecycleStatus {
        val root = parseRoot(body)
        require(root.optInt("version", 0) == 1) {
            "Для проверки доступа нужна более новая версия WDTT Plus."
        }
        require(root.has("allow_connect")) {
            "WDTT Plus вернул неполное решение по профилю."
        }
        val allowConnect = root.optBoolean("allow_connect", false)
        val action = root.optJSONObject("action")
        val actionAvailable = action?.optBoolean("available", false) == true
        val actionLabel = action?.optString("label").orEmpty().trim().take(80)
        val actionMessage = action?.optString("message").orEmpty().trim().take(240)
        val actionIcon = action?.optString("icon").orEmpty().trim().take(32)
            .takeIf { it == "update" }
            .orEmpty()
        val continuationAvailable = root.optJSONObject("continuation")
            ?.takeIf { it.has("available") }
            ?.optBoolean("available", false)
        val continuationExpiresAtSeconds = root.optJSONObject("continuation")
            ?.takeIf { it.has("expires") }
            ?.optLong("expires", 0L)
            ?.coerceAtLeast(0L)
        val dismissible = root
            .takeIf { it.has("dismissible") }
            ?.optBoolean("dismissible", false)
        val dismissedMessage = root.optString("dismissed_message").trim().take(400)
        val title = root.optString("title").trim().take(120)
        val message = root.optString("message").trim().take(400)
        val detail = root.optJSONObject("detail")
        val detailLabel = detail?.optString("label").orEmpty().trim().take(80)
        val detailValue = detail?.optString("value").orEmpty().trim().take(120)
        val severity = AccessLifecycleSeverity.parse(
            root.optString("severity"),
            allowConnect,
        )

        val profile = root.optJSONObject("profile")
        val revision = profile?.optLong("revision", 0)?.coerceAtLeast(0) ?: 0
        val update = if (profile?.optBoolean("update_available", false) == true) {
            val link = RemoteDocumentGateway.extractLink(profile.optString("document"))
                ?: throw IllegalStateException("WDTT Plus вернул повреждённое обновление профиля.")
            require(revision > 0) { "WDTT Plus вернул неполное обновление профиля." }
            AccessProfileUpdate(revision = revision, link = link)
        } else {
            null
        }
        val cachedAction = root.optJSONObject("cached_action")
            ?.let(RemoteDocumentGateway::parseCachedAction)
            ?: CachedRemoteAction.Unavailable
        val exchange = root.optJSONObject("exchange")
            ?.let(RemoteDocumentGateway::parseProfileExchange)
        return AccessLifecycleStatus(
            allowConnect = allowConnect,
            actionAvailable = actionAvailable,
            actionLabel = actionLabel,
            actionMessage = actionMessage,
            title = title,
            message = message,
            detailLabel = detailLabel,
            detailValue = detailValue,
            actionIcon = actionIcon,
            continuationAvailable = continuationAvailable,
            continuationExpiresAtSeconds = continuationExpiresAtSeconds,
            dismissible = dismissible,
            dismissedMessage = dismissedMessage,
            severity = severity,
            profileRevision = revision,
            profileUpdate = update,
            cachedAction = cachedAction,
            exchange = exchange,
        )
    }

    internal fun parseLaunchTarget(body: String): RemoteLaunchTarget {
        val root = parseRoot(body)
        val primary = root.optString("url").trim()
        val fallback = root.optString("fallback").trim()
        val handler = root.optString("handler").trim()
        val alternateHandlers = root.optJSONArray("alternate_handlers")?.let { source ->
            if (source.length() > 7) null else {
                (0 until source.length())
                    .map { index -> source.optString(index).trim() }
                    .takeIf { values ->
                        values.all { it.isNotBlank() && safePackageName(it) } &&
                            values.distinct().size == values.size
                    }
            }
        } ?: if (root.has("alternate_handlers")) null else emptyList()
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
        return RemoteLaunchTarget(
            primaryUrl = primary,
            fallbackUrl = fallback,
            preferredHandler = handler,
            alternateHandlers = alternateHandlers,
        )
    }

    internal fun parseActionDocument(body: String): RemoteDocumentLink {
        val root = parseRoot(body)
        require(root.optInt("version", 0) == 1) {
            "Для действия нужна более новая версия WDTT Plus."
        }
        return RemoteDocumentGateway.extractLink(root.optString("document"))
            ?: throw IllegalStateException("WDTT Plus вернул повреждённое обновление профиля.")
    }

    internal fun parseExchangeResult(body: String): RemoteProfileExchange {
        val root = parseRoot(body)
        require(root.optInt("version", 0) == 1) {
            "WDTT Plus не подтвердил обновление данных профиля."
        }
        val source = root.optJSONObject("exchange")
            ?: throw IllegalStateException("WDTT Plus вернул неполный ответ.")
        return RemoteDocumentGateway.parseProfileExchange(source)
    }

    private fun parseRoot(body: String): JSONObject {
        require(body.length <= MAX_RESPONSE_CHARS) { "Ответ WDTT Plus слишком большой." }
        return runCatching { JSONObject(body) }
            .getOrElse { throw IllegalStateException("WDTT Plus вернул неполные данные.") }
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

    private fun opaqueValue(value: String): Boolean =
        value.length in 24..256 && Regex("^[A-Za-z0-9_-]+$").matches(value)

    private fun validDevice(value: String): Boolean =
        Regex("^[A-Za-z0-9_.:-]{8,128}$").matches(value.trim())

    private fun readBody(connection: HttpURLConnection, status: Int): String {
        val stream = if (status in 200..299) connection.inputStream else connection.errorStream
        return stream?.use { it.readUtf8TextLimited(MAX_RESPONSE_CHARS) }.orEmpty()
    }
}
