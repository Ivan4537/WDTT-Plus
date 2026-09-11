package com.wdtt.plus

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class NativeClientStartupConfigTest {
    @Test
    fun startupSecretsAreEncodedOutsideProcessArguments() {
        val secrets = NativeClientStartupSecrets(
            vkHashes = "https://example.invalid/join/test",
            connectionPassword = "connection-secret",
            customVkClientId = "1234567",
            customVkClientSecret = "client-secret",
            socksUsername = "local-user",
            socksPassword = "local-password",
        )

        val line = nativeClientStartupConfigLine(secrets)

        assertTrue(line.startsWith("START_CONFIG|"))
        assertFalse(line.contains(secrets.vkHashes))
        assertFalse(line.contains(secrets.connectionPassword))
        assertFalse(line.contains(secrets.customVkClientSecret))
        assertFalse(line.contains(secrets.socksPassword))

        val decoded = String(
            Base64.getUrlDecoder().decode(line.substringAfter("START_CONFIG|")),
            Charsets.UTF_8,
        )
        val json = JSONObject(decoded)
        assertEquals(secrets.vkHashes, json.getString("vk_hashes"))
        assertEquals(secrets.connectionPassword, json.getString("connection_password"))
        assertEquals(secrets.customVkClientId, json.getString("custom_vk_client_id"))
        assertEquals(secrets.customVkClientSecret, json.getString("custom_vk_client_secret"))
        assertEquals(secrets.socksUsername, json.getString("socks_username"))
        assertEquals(secrets.socksPassword, json.getString("socks_password"))
    }
}
