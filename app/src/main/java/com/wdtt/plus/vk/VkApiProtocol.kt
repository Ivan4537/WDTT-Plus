package com.wdtt.plus.vk

import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import org.json.JSONObject

internal object VkApiProtocol {
    const val CLIENT_ID = "54670575"
    const val REDIRECT = "vk54670575://vk.ru/blank.html"
    const val START_ENDPOINT = "https://api.vk.ru/method/calls.start"
    const val USER_ENDPOINT = "https://api.vk.ru/method/users.get"

    // Intentionally not data classes: their toString() must not expose credentials.
    class AuthAttempt(val verifier: String, val state: String) {
        val challenge: String get() = base64(MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray()))
        fun url(): String = "https://id.vk.ru/authorize?" + encode(linkedMapOf(
            "client_id" to CLIENT_ID, "redirect_uri" to REDIRECT, "response_type" to "code",
            "scope" to "vkid.personal_info", "state" to state,
            "code_challenge" to challenge, "code_challenge_method" to "S256",
        ))
    }
    class Callback(val code: String, val deviceId: String)
    class Token(val value: String, val expiresAt: Long)
    class Started(val callId: String, val linkReceived: Boolean)

    fun newAttempt(): AuthAttempt = AuthAttempt(random(), random())
    private fun random(): String = base64(ByteArray(32).also(SecureRandom()::nextBytes))
    private fun base64(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    fun encode(fields: Map<String, String>): String = fields.entries.joinToString("&") {
        URLEncoder.encode(it.key, "UTF-8") + "=" + URLEncoder.encode(it.value, "UTF-8")
    }

    fun allowedPage(raw: String): Boolean = runCatching {
        require(raw.length <= 16_384)
        val uri = URI(raw)
        val host = uri.host?.lowercase() ?: return false
        uri.scheme == "https" && uri.userInfo == null && uri.port in setOf(-1, 443) &&
            (host == "vk.ru" || host.endsWith(".vk.ru") || host == "vk.com" || host.endsWith(".vk.com"))
    }.getOrDefault(false)

    fun isCallback(raw: String): Boolean = runCatching {
        val uri = URI(raw)
        uri.scheme == "vk$CLIENT_ID" && uri.host == "vk.ru" && uri.rawPath == "/blank.html" &&
            uri.rawUserInfo == null && uri.port == -1
    }.getOrDefault(false)

    fun callback(raw: String, expectedState: String): Callback {
        require(raw.length <= 16_384 && isCallback(raw))
        val uri = URI(raw)
        require(uri.rawFragment == null)
        val fields = mutableMapOf<String, String>()
        uri.rawQuery.orEmpty().split('&').forEach {
            val pair = it.split('=', limit = 2)
            require(pair.size == 2)
            val key = URLDecoder.decode(pair[0], "UTF-8")
            require(!fields.containsKey(key))
            fields[key] = URLDecoder.decode(pair[1], "UTF-8")
        }
        require(MessageDigest.isEqual(fields["state"].orEmpty().toByteArray(), expectedState.toByteArray()))
        require(!fields.containsKey("error"))
        val code = fields["code"].orEmpty()
        val device = fields["device_id"].orEmpty()
        require(code.length in 1..4096 && device.length in 1..4096)
        return Callback(code, device)
    }

    fun started(json: JSONObject): Started {
        val result = json.getJSONObject("response")
        val id = result.getString("call_id")
        require(Regex("[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}").matches(id))
        val hasLink = listOf("join_link", "ok_join_link").any {
            runCatching {
                val uri = URI(result.optString(it))
                uri.scheme == "https" && uri.host != null && uri.rawUserInfo == null &&
                    !uri.rawPath.isNullOrBlank()
            }.getOrDefault(false)
        }
        return Started(id, hasLink)
    }

    fun apiError(json: JSONObject, method: String = "calls.start"): String? {
        require(method == "calls.start")
        if (!json.has("error")) return null
        val code = json.optJSONObject("error")?.optInt("error_code", -1) ?: -1
        return if (code == 1051) "VK API: ошибка 1051. Метод недоступен этому типу приложения/токена. Вход выполнен, но $method недоступен."
        else if (code in 0..1_000_000) "VK API: ошибка $code. Повторный $method не выполнялся."
        else "VK API вернул неизвестную ошибку. Повторный $method не выполнялся."
    }
}
