package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.json.JSONObject

class TransferCodecTest {
    @Test
    fun modernConnectionLink_roundTripsSpecialCharacters() {
        val original = WdttLinkParts(
            host = "vpn.example.org",
            dtlsPort = 56000,
            wgPort = 56001,
            localPort = 9000,
            password = "пароль: со знаками +?&=%",
            hashes = "1234567890abcdef,fedcba0987654321"
        )

        val link = WdttTransferCodec.buildConnectionLink(original)
        val parsed = WdttTransferCodec.parseConnectionLink(link)

        assertEquals(original, parsed)
        assertTrue(WdttDeepLink.validate(link).canStartVpn)
    }

    @Test
    fun legacyConnectionLink_remainsSupported() {
        val validation = WdttDeepLink.validate(
            "wdtt://vpn.example.org:56000:56001:9000:secret:1234567890abcdef"
        )

        assertTrue(validation.canStartVpn)
        assertEquals("vpn.example.org", validation.parts?.host)
    }

    @Test
    fun linkCanBeExtractedFromSharedText() {
        val value = "Подключение: wdtt://vpn.example.org:56000:56001:9000:secret:1234567890abcdef\nНе передавайте посторонним"

        assertEquals(
            "wdtt://vpn.example.org:56000:56001:9000:secret:1234567890abcdef",
            WdttTransferCodec.extractWdttLink(value)
        )
    }

    @Test
    fun modernConnectionLink_rejectsInvalidPort() {
        val link = WdttTransferCodec.buildConnectionLink(
            WdttLinkParts("vpn.example.org", 70000, 56001, 9000, "secret", "1234567890abcdef")
        )

        assertFalse(WdttDeepLink.validate(link).canStartVpn)
    }

    @Test
    fun malformedModernLink_isNotParsed() {
        val validation = WdttDeepLink.validate("wdtt://connect?v=1&host=vpn.example.org")

        assertFalse(validation.canStartVpn)
        assertNotNull(validation.errors.firstOrNull())
    }

    @Test
    fun malformedPercentEncoding_doesNotCrashParser() {
        val validation = WdttDeepLink.validate("wdtt://connect?v=1&host=%ZZ")

        assertFalse(validation.canStartVpn)
    }

    @Test
    fun adminSettings_areEncryptedAndAuthenticated() {
        val plain = JSONObject()
            .put("format", "wdtt-plus-admin-settings")
            .put("version", 1)
            .put("secret", "bot-token-and-password")
            .toString()
        val password = "сложный пароль 123".toCharArray()

        val encrypted = WdttTransferCodec.encryptAdminSettings(plain, password)

        assertTrue(WdttTransferCodec.isAdminTransfer(encrypted))
        assertFalse(encrypted.contains("bot-token-and-password"))
        assertEquals(plain, WdttTransferCodec.decryptAdminSettings(encrypted, password))
    }

    @Test(expected = IllegalArgumentException::class)
    fun adminSettings_rejectWrongPassword() {
        val encrypted = WdttTransferCodec.encryptAdminSettings("{}", "correct-password".toCharArray())

        WdttTransferCodec.decryptAdminSettings(encrypted, "wrong-password".toCharArray())
    }
}
