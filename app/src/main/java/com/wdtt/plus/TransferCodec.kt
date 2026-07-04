package com.wdtt.plus

import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.Base64
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

private const val TRANSFER_FORMAT = "wdtt-plus-transfer"
private const val TRANSFER_VERSION = 1
private const val ADMIN_KIND = "admin-settings"
private const val PBKDF2_ITERATIONS = 210_000
private const val KEY_BITS = 256
private const val GCM_TAG_BITS = 128

data class AdminTransferPreview(
    val createdAt: Long,
    val profileCount: Int,
    val sourceVersion: String
)

object WdttTransferCodec {
    private val random = SecureRandom()

    fun buildConnectionLink(parts: WdttLinkParts): String {
        val values = linkedMapOf(
            "v" to "1",
            "host" to parts.host,
            "dtls" to parts.dtlsPort.toString(),
            "wg" to parts.wgPort.toString(),
            "local" to parts.localPort.toString(),
            "password" to parts.password,
            "hashes" to parts.hashes
        )
        normalizeVpnProfileName(parts.profileName)
            .takeIf { it.isNotBlank() }
            ?.let { values["name"] = it }
        return "wdtt://connect?" + values.entries.joinToString("&") { (key, value) ->
            "${encode(key)}=${encode(value)}"
        }
    }

    fun parseConnectionLink(value: String): WdttLinkParts? = runCatching {
        parseConnectionLinkUnsafe(value)
    }.getOrNull()

    private fun parseConnectionLinkUnsafe(value: String): WdttLinkParts? {
        val clean = extractWdttLink(value) ?: return null
        if (!clean.startsWith("wdtt://connect?", ignoreCase = true)) return null
        val query = clean.substringAfter('?', "")
        val values = query.split('&')
            .mapNotNull { token ->
                val separator = token.indexOf('=')
                if (separator <= 0) null
                else decode(token.substring(0, separator)) to decode(token.substring(separator + 1))
            }
            .toMap()
        if (values["v"] != "1") return null
        return WdttLinkParts(
            host = values["host"].orEmpty(),
            dtlsPort = values["dtls"]?.toIntOrNull() ?: return null,
            wgPort = values["wg"]?.toIntOrNull() ?: return null,
            localPort = values["local"]?.toIntOrNull() ?: return null,
            password = values["password"].orEmpty(),
            hashes = values["hashes"].orEmpty(),
            profileName = values["name"].orEmpty()
        )
    }

    fun extractWdttLink(value: String): String? {
        val start = value.indexOf("wdtt://", ignoreCase = true)
        if (start < 0) return null
        return value.substring(start)
            .substringBeforeAny(charArrayOf('\n', '\r', '\t', ' '))
            .trimEnd('.', ',', ';', ')', ']', '}', '»', '"', '\'')
            .takeIf { it.isNotBlank() }
    }

    fun encryptAdminSettings(settingsJson: String, password: CharArray): String {
        require(password.size >= 8) { "Пароль должен содержать не меньше 8 символов." }
        val salt = ByteArray(16).also(random::nextBytes)
        val iv = ByteArray(12).also(random::nextBytes)
        val key = deriveKey(password, salt, PBKDF2_ITERATIONS)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        val compressed = gzip(settingsJson.toByteArray(StandardCharsets.UTF_8))
        val encrypted = cipher.doFinal(compressed)
        key.encoded?.fill(0)

        return JSONObject()
            .put("format", TRANSFER_FORMAT)
            .put("version", TRANSFER_VERSION)
            .put("kind", ADMIN_KIND)
            .put("createdAt", System.currentTimeMillis())
            .put("sourceVersion", BuildConfig.VERSION_NAME)
            .put("kdf", "PBKDF2-HMAC-SHA256")
            .put("iterations", PBKDF2_ITERATIONS)
            .put("salt", Base64.getEncoder().encodeToString(salt))
            .put("iv", Base64.getEncoder().encodeToString(iv))
            .put("data", Base64.getEncoder().encodeToString(encrypted))
            .toString()
    }

    fun isAdminTransfer(value: String): Boolean = runCatching {
        val json = JSONObject(value.trim())
        json.optString("format") == TRANSFER_FORMAT &&
            json.optInt("version") == TRANSFER_VERSION &&
            json.optString("kind") == ADMIN_KIND
    }.getOrDefault(false)

    fun documentFormat(value: String): String? = runCatching {
        JSONObject(value.trim()).optString("format").takeIf { it.isNotBlank() }
    }.getOrNull()

    fun previewAdminTransfer(value: String): AdminTransferPreview {
        val json = requireAdminEnvelope(value)
        return AdminTransferPreview(
            createdAt = json.optLong("createdAt"),
            profileCount = 3,
            sourceVersion = json.optString("sourceVersion", "неизвестно")
        )
    }

    fun decryptAdminSettings(value: String, password: CharArray): String {
        require(password.isNotEmpty()) { "Введите пароль файла." }
        val json = requireAdminEnvelope(value)
        val iterations = json.optInt("iterations", 0)
        require(iterations in 100_000..1_000_000) { "Некорректные параметры защиты файла." }
        val salt = Base64.getDecoder().decode(json.getString("salt"))
        val iv = Base64.getDecoder().decode(json.getString("iv"))
        val encrypted = Base64.getDecoder().decode(json.getString("data"))
        require(salt.size == 16 && iv.size == 12) { "Файл передачи повреждён." }
        val key = deriveKey(password, salt, iterations)
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            ungzip(cipher.doFinal(encrypted)).toString(StandardCharsets.UTF_8)
        } catch (_: Exception) {
            throw IllegalArgumentException("Неверный пароль или файл повреждён.")
        } finally {
            key.encoded?.fill(0)
        }
    }

    private fun requireAdminEnvelope(value: String): JSONObject {
        val json = runCatching { JSONObject(value.trim()) }
            .getOrElse { throw IllegalArgumentException("Файл передачи повреждён или имеет неизвестный формат.") }
        require(json.optString("format") == TRANSFER_FORMAT) { "Это не файл передачи WDTT Plus." }
        require(json.optInt("version") == TRANSFER_VERSION) { "Версия файла пока не поддерживается." }
        require(json.optString("kind") == ADMIN_KIND) { "В файле нет настроек администратора." }
        return json
    }

    private fun deriveKey(password: CharArray, salt: ByteArray, iterations: Int): SecretKeySpec {
        val spec = PBEKeySpec(password, salt, iterations, KEY_BITS)
        return try {
            val bytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
            SecretKeySpec(bytes, "AES")
        } finally {
            spec.clearPassword()
        }
    }

    private fun gzip(value: ByteArray): ByteArray = ByteArrayOutputStream().use { output ->
        GZIPOutputStream(output).use { it.write(value) }
        output.toByteArray()
    }

    private fun ungzip(value: ByteArray): ByteArray =
        GZIPInputStream(ByteArrayInputStream(value)).use { it.readBytes() }

    private fun encode(value: String): String = URLEncoder.encode(value, StandardCharsets.UTF_8.name())
        .replace("+", "%20")

    private fun decode(value: String): String = URLDecoder.decode(value, StandardCharsets.UTF_8.name())

    private fun String.substringBeforeAny(delimiters: CharArray): String {
        val index = indexOfFirst { it in delimiters }
        return if (index < 0) this else substring(0, index)
    }
}
