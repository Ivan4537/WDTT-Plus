package com.wdtt.plus.vk

import java.net.URI
import java.net.URLDecoder
import java.security.MessageDigest

/** Official Mini App OAuth adapter. No cookie extraction, injected script or third-party identity. */
internal object VkOAuthProtocol {
    const val CLIENT_ID = "54670800"
    const val REDIRECT = "https://oauth.vk.ru/blank.html"
    // Local upper bound, not a claim about the provider's token lifetime.
    private const val MAX_LOCAL_TOKEN_SECONDS = 86_400L

    class AuthAttempt(val state: String) {
        fun url(): String = "https://oauth.vk.ru/authorize?" + VkApiProtocol.encode(linkedMapOf(
            "client_id" to CLIENT_ID, "redirect_uri" to REDIRECT,
            "display" to "mobile", "response_type" to "token", "v" to "5.199", "state" to state,
        ))
    }

    enum class Rejection { REDIRECT, MALFORMED, MISSING_STATE, STATE_MISMATCH, DENIED }
    class Rejected(val reason: Rejection) : IllegalArgumentException("OAuth response rejected")

    fun newAttempt(): AuthAttempt = AuthAttempt(VkApiProtocol.newAttempt().state)

    fun isCallback(raw: String): Boolean = runCatching {
        if (raw.length > 16_384) return false
        val uri = URI(raw)
        uri.scheme == "https" && uri.host == "oauth.vk.ru" && uri.rawPath == "/blank.html" &&
            uri.rawUserInfo == null && uri.port == -1
    }.getOrDefault(false)

    /** Never allow an access-token redirect to be loaded as a web page, even at a wrong target. */
    fun containsCredential(raw: String): Boolean = runCatching {
        val uri = URI(raw)
        listOf(uri.rawQuery, uri.rawFragment).filterNotNull().any { part ->
            part.split('&').any {
                URLDecoder.decode(it.substringBefore('='), "UTF-8") in
                    setOf("access_token", "id_token", "refresh_token")
            }
        }
    }.getOrDefault(true)

    fun blockResource(raw: String, mainFrame: Boolean): Boolean =
        isCallback(raw) || (mainFrame && containsCredential(raw))

    fun callback(raw: String, expectedState: String, now: Long): VkApiProtocol.Token {
        if (!isCallback(raw)) throw Rejected(Rejection.REDIRECT)
        try {
            require(expectedState.matches(Regex("[A-Za-z0-9_-]{32,128}")))
            val uri = URI(raw)
            // Successful implicit OAuth responses belong in the fragment, never the query.
            require(uri.rawQuery == null)
            val fields = uniqueFields(uri.rawFragment ?: throw Rejected(Rejection.MALFORMED))
            val state = fields["state"]?.takeIf { it.isNotEmpty() }
                ?: throw Rejected(Rejection.MISSING_STATE)
            if (!MessageDigest.isEqual(state.toByteArray(), expectedState.toByteArray())) {
                throw Rejected(Rejection.STATE_MISMATCH)
            }
            if (fields.containsKey("error")) throw Rejected(Rejection.DENIED)
            require(!fields.containsKey("code") && !fields.containsKey("id_token") && !fields.containsKey("refresh_token"))
            val value = fields["access_token"].orEmpty()
            require(value.length in 1..8192 && value.matches(Regex("[A-Za-z0-9._~+/-]+=*")))
            val userId = fields["user_id"].orEmpty()
            require(userId.matches(Regex("[1-9][0-9]{0,18}")) && userId.toLong() > 0)
            val secondsText = fields["expires_in"].orEmpty()
            require(secondsText.matches(Regex("[0-9]{1,8}")))
            val seconds = secondsText.toLong()
            require(seconds in 0..31_536_000)
            val localSeconds = if (seconds == 0L) MAX_LOCAL_TOKEN_SECONDS
                else minOf(seconds, MAX_LOCAL_TOKEN_SECONDS)
            return VkApiProtocol.Token(value, Math.addExact(now, localSeconds * 1000))
        } catch (error: Rejected) {
            throw error
        } catch (_: Exception) {
            // Do not retain malformed URLs, provider messages or token fragments in exceptions.
            throw Rejected(Rejection.MALFORMED)
        }
    }

    private fun uniqueFields(raw: String): Map<String, String> {
        val result = mutableMapOf<String, String>()
        raw.split('&').forEach {
            val pair = it.split('=', limit = 2)
            require(pair.size == 2)
            val key = URLDecoder.decode(pair[0], "UTF-8")
            require(key.isNotEmpty() && !result.containsKey(key))
            result[key] = URLDecoder.decode(pair[1], "UTF-8")
        }
        return result
    }

    fun rejectionMessage(error: Rejected): String = when (error.reason) {
        Rejection.MISSING_STATE -> "VK не вернул state. Ответ входа отклонён; calls.start не отправлялся."
        Rejection.STATE_MISMATCH -> "Ответ VK относится к другой попытке входа. calls.start не отправлялся."
        Rejection.DENIED -> "VK не выдал разрешение или вход отменён. calls.start не отправлялся."
        Rejection.REDIRECT -> "VK вернул разрешение на неожиданный адрес. Ответ отклонён; calls.start не отправлялся."
        Rejection.MALFORMED -> "Ответ OAuth Mini App не прошёл проверку. calls.start не отправлялся."
    }
}
