package com.wdtt.plus.vk

import java.net.URI
import org.json.JSONObject

internal object NativeVkProtocol {
    fun mayCreate(phases: List<String>): Boolean = phases.size < 4 && phases.all { it == "uploaded" }

    fun hash(response: JSONObject): String {
        VkApiProtocol.apiError(response)?.let { throw IllegalStateException(it) }
        VkApiProtocol.started(response) // Validate call identity before accepting its link.
        val result = response.getJSONObject("response")
        val uri = URI(result.getString("join_link"))
        require(uri.scheme == "https" && uri.rawUserInfo == null && uri.port in setOf(-1, 443))
        require(uri.host in setOf("vk.ru", "vk.com", "m.vk.ru", "m.vk.com"))
        require(uri.rawPath.startsWith("/call/join/"))
        val hash = uri.rawPath.removePrefix("/call/join/")
        require(Regex("[A-Za-z0-9_-]{16,512}").matches(hash))
        return hash
    }

    fun payload(key: String, device: String, op: String, extras: JSONObject = JSONObject()): String {
        require(Regex("[A-Za-z0-9_.-]{24,100}").matches(key))
        require(Regex("[A-Za-z0-9_.:-]{8,128}").matches(device))
        require(op in setOf("prepare", "auth", "permit", "result", "finish"))
        val result = JSONObject().put("k", key).put("d", device).put("o", op)
        extras.keys().forEach { field ->
            require(field in setOf("a", "v", "i", "n"))
            result.put(field, extras.get(field))
        }
        return result.toString().also { require(it.toByteArray(Charsets.UTF_8).size <= 768) }
    }
}
