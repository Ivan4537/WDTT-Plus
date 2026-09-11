package com.wdtt.plus

import org.json.JSONObject
import java.util.Base64

private const val NATIVE_STARTUP_CONFIG_PREFIX = "START_CONFIG|"

internal data class NativeClientStartupSecrets(
    val vkHashes: String,
    val connectionPassword: String = "",
    val customVkClientId: String = "",
    val customVkClientSecret: String = "",
    val socksUsername: String = "",
    val socksPassword: String = "",
)

internal fun nativeClientStartupConfigLine(secrets: NativeClientStartupSecrets): String {
    val json = JSONObject()
        .put("vk_hashes", secrets.vkHashes)
        .put("connection_password", secrets.connectionPassword)
        .put("custom_vk_client_id", secrets.customVkClientId)
        .put("custom_vk_client_secret", secrets.customVkClientSecret)
        .put("socks_username", secrets.socksUsername)
        .put("socks_password", secrets.socksPassword)
        .toString()
    val encoded = Base64.getUrlEncoder()
        .withoutPadding()
        .encodeToString(json.toByteArray(Charsets.UTF_8))
    return NATIVE_STARTUP_CONFIG_PREFIX + encoded
}
