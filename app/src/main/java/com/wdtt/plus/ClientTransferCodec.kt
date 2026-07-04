package com.wdtt.plus

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONObject
import java.security.SecureRandom

private const val CLIENT_TRANSFER_FORMAT = "wdtt-plus-client"
private const val CLIENT_TRANSFER_VERSION = 1

data class ClientTransferPayload(
    val password: String,
    val label: String,
    val vkHash: String,
    val expiresAt: Long,
    val deactivated: Boolean,
    val createdAt: Long = System.currentTimeMillis()
)

object ClientPasswordRules {
    const val LENGTH = 16
    const val ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
    private val random = SecureRandom()

    fun generate(): String = buildString(LENGTH) {
        repeat(LENGTH) { append(ALPHABET[random.nextInt(ALPHABET.length)]) }
    }

    fun validate(value: String): String? = when {
        value.length != LENGTH -> "Пароль должен содержать ровно $LENGTH символов."
        value.any { it !in ALPHABET } -> "Допустимы только безопасные латинские буквы и цифры без 0, 1, I, i, O, o и l."
        else -> null
    }
}

object ClientTransferCodec {
    fun encode(payload: ClientTransferPayload): String {
        ClientPasswordRules.validate(payload.password)?.let { throw IllegalArgumentException(it) }
        require(payload.expiresAt >= 0) { "Некорректный срок клиента." }
        require(payload.label.length <= 40 && payload.label.none(Char::isISOControl)) { "Название клиента повреждено или слишком длинное." }
        val vkHash = normalizeVkHashes(payload.vkHash)
        return JSONObject()
            .put("format", CLIENT_TRANSFER_FORMAT)
            .put("version", CLIENT_TRANSFER_VERSION)
            .put("created_at", payload.createdAt)
            .put("password", payload.password)
            .put("label", payload.label.trim())
            .put("vk_hash", vkHash)
            .put("expires_at", payload.expiresAt)
            .put("deactivated", payload.deactivated)
            .toString()
    }

    fun decode(value: String): ClientTransferPayload {
        val json = runCatching { JSONObject(value.trim()) }
            .getOrElse { throw IllegalArgumentException("Данные клиента повреждены или имеют неверный формат.") }
        require(json.optString("format") == CLIENT_TRANSFER_FORMAT) { "Это не файл переноса клиента WDTT Plus." }
        require(json.optInt("version", -1) == CLIENT_TRANSFER_VERSION) { "Версия файла клиента не поддерживается." }
        val password = json.optString("password")
        ClientPasswordRules.validate(password)?.let { throw IllegalArgumentException(it) }
        val label = json.optString("label").trim()
        require(label.length <= 40 && label.none(Char::isISOControl)) { "Название клиента повреждено или длиннее 40 символов." }
        val vkHash = normalizeVkHashes(json.optString("vk_hash"))
        val expiresAt = json.optLong("expires_at", -1)
        require(expiresAt >= 0) { "В файле указан некорректный срок клиента." }
        return ClientTransferPayload(
            password = password,
            label = label,
            vkHash = vkHash,
            expiresAt = expiresAt,
            deactivated = json.optBoolean("deactivated", false),
            createdAt = json.optLong("created_at", 0)
        )
    }

    fun isClientTransfer(value: String): Boolean = runCatching {
        val json = JSONObject(value.trim())
        json.optString("format") == CLIENT_TRANSFER_FORMAT
    }.getOrDefault(false)

    fun fromClient(client: ServerClientInfo): ClientTransferPayload = ClientTransferPayload(
        password = client.password,
        label = client.label,
        vkHash = client.vkHash,
        expiresAt = client.expiresAt,
        deactivated = client.status == "deactivated"
    )

    private fun normalizeVkHashes(value: String): String {
        val clean = value.trim()
        if (clean.isBlank()) return ""
        require(clean.length <= 4096 && clean.none(Char::isISOControl)) { "Поле VK-хешей повреждено." }
        val hashes = clean.split(Regex("[,\\s]+"))
            .map { VkJoinLink.extractHash(it) }
            .filter { it.isNotBlank() }
        require(hashes.isNotEmpty() && hashes.all { it.length >= 16 } && hashes.none { it.contains('/') || it.contains('\\') }) {
            "VK-хеши в переносе имеют неверный формат."
        }
        return hashes.distinct().joinToString(",")
    }
}

object ClientTransferInbox {
    private val mutablePending = MutableStateFlow<String?>(null)
    val pending = mutablePending.asStateFlow()

    fun offer(value: String) {
        mutablePending.value = value.trim()
    }

    fun clear(value: String) {
        if (mutablePending.value == value) mutablePending.value = null
    }
}
