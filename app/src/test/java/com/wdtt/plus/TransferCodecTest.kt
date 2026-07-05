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
    fun modernConnectionLink_preservesFourVkHashesAndTheirOrder() {
        val hashes = listOf(
            "3XariaxnHDP9eTiWVFukTMO6ZjCw7c0QQS_J3gYiiaM",
            "8b6EGN4gYNV5IoCO8tsnKuj49od-GxNhotdbBqjPlaU",
            "OnEpu4S_nWEKy9wN_ehrMn-8tCfKaL7iiJEe4N50ggg",
            "pjCFYpjm_ibjy3YTyVZoEWZv3Oai4-QxAWcD2hWexLE"
        )
        val original = WdttLinkParts(
            host = "vpn.example.org",
            dtlsPort = 56000,
            wgPort = 56001,
            localPort = 9000,
            password = "ABCDEFGHJKLMNPQR",
            hashes = hashes.joinToString(",")
        )

        val link = WdttTransferCodec.buildConnectionLink(original)
        val parsed = WdttDeepLink.validate(link).parts

        assertEquals(hashes, parsed?.hashes?.split(","))
    }

    @Test
    fun modernConnectionLink_acceptsVkJoinLinksAsHashInputs() {
        val first = "3XariaxnHDP9eTiWVFukTMO6ZjCw7c0QQS_J3gYiiaM"
        val second = "8b6EGN4gYNV5IoCO8tsnKuj49od-GxNhotdbBqjPlaU"
        val link = WdttTransferCodec.buildConnectionLink(
            WdttLinkParts(
                host = "vpn.example.org",
                dtlsPort = 56000,
                wgPort = 56001,
                localPort = 9000,
                password = "ABCDEFGHJKLMNPQR",
                hashes = "https://vk.com/call/join/$first?from=share,https://vk.ru/call/join/$second"
            )
        )

        assertEquals("$first,$second", WdttDeepLink.validate(link).parts?.hashes)
    }

    @Test
    fun modernConnectionLink_carriesCustomProfileName() {
        val original = WdttLinkParts(
            host = "vpn.example.org",
            dtlsPort = 56000,
            wgPort = 56001,
            localPort = 9000,
            password = "ABCDEFGHJKLMNPQR",
            hashes = "1234567890abcdef",
            profileName = "Домашний VPN"
        )

        val link = WdttTransferCodec.buildConnectionLink(original)

        assertTrue(link.contains("name=%D0%94"))
        assertEquals(original, WdttDeepLink.parse(link))
    }

    @Test
    fun modernConnectionLink_omitsEmptyProfileName() {
        val link = WdttTransferCodec.buildConnectionLink(
            WdttLinkParts(
                host = "vpn.example.org",
                dtlsPort = 56000,
                wgPort = 56001,
                localPort = 9000,
                password = "ABCDEFGHJKLMNPQR",
                hashes = "1234567890abcdef"
            )
        )

        assertFalse(link.contains("&name="))
    }

    @Test
    fun legacyConnectionLink_remainsSupported() {
        val validation = WdttDeepLink.validate(
            "wdtt://vpn.example.org:56000:56001:9000:secret:1234567890abcdef"
        )

        assertTrue(validation.canStartVpn)
        assertEquals("vpn.example.org", validation.parts?.host)
        assertEquals("", validation.parts?.profileName)
    }

    @Test
    fun onlyRenamedProfileIsPreparedForTransfer() {
        assertEquals("", vpnProfileTransferName(0, listOf("", "", "")))
        assertEquals("", vpnProfileTransferName(1, listOf("", "VPN 2", "")))
        assertEquals("Работа", vpnProfileTransferName(2, listOf("", "", "Работа")))
    }

    @Test
    fun vpnProfileNameInput_allowsSpacesBetweenWords() {
        assertEquals("Домашний ", sanitizeVpnProfileNameInput("Домашний "))
        assertEquals("Домашний сервер", sanitizeVpnProfileNameInput("  Домашний   сервер"))
        assertEquals("Домашний сервер", normalizeVpnProfileName("  Домашний   сервер  "))
    }

    @Test
    fun adminProfilePatch_omitsEmptyAndDefaultTunnelFields() {
        val defaults = ServerAdminProfileInfo()
        assertEquals(listOf("update-admin-profile"), buildAdminProfilePatchArgs(defaults))
        assertFalse(hasMeaningfulAdminProfileFields(defaults))

        val custom = defaults.copy(
            vkHashes = "hash-value",
            profileName = "Домашний сервер",
            workersPerHash = 24,
            noDns = true
        )
        assertEquals(
            listOf(
                "update-admin-profile",
                "--vk-hashes", "hash-value",
                "--profile-name", "Домашний сервер",
                "--workers", "24",
                "--no-dns"
            ),
            buildAdminProfilePatchArgs(custom)
        )
        assertTrue(hasMeaningfulAdminProfileFields(custom))
    }

    @Test
    fun serverClientLink_carriesSourceVpnProfileName() {
        val link = buildServerConnectionLink(
            password = "ABCDEFGHJKLMNPQR",
            hashes = "1234567890abcdef",
            ports = "56000,56001,9000",
            fallbackHost = "vpn.example.org",
            publicHost = "",
            profileName = "Мой сервер"
        )

        assertNotNull(link)
        assertEquals("Мой сервер", WdttDeepLink.parse(link.orEmpty())?.profileName)
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
