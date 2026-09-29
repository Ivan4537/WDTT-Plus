package com.wdtt.plus.vk

import java.net.URI

/** Fail closed for the login document without aborting it for a blocked subresource. */
internal object NativeVkSslPolicy {
    fun isMainFrameFailure(mainFrameUrl: String, failedUrl: String?): Boolean {
        val failed = canonical(failedUrl) ?: return true
        val main = canonical(mainFrameUrl) ?: return true
        return failed == main
    }

    private fun canonical(raw: String?): String? = runCatching {
        val uri = URI(raw?.takeIf { it.length in 1..16_384 } ?: return null)
        val host = uri.host?.lowercase() ?: return null
        if (uri.scheme != "https" || uri.rawUserInfo != null || uri.port !in setOf(-1, 443)) return null
        URI("https", null, host, -1, uri.rawPath.orEmpty().ifEmpty { "/" }, uri.rawQuery, null).toASCIIString()
    }.getOrNull()
}
