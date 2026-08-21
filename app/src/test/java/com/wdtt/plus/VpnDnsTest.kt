package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnDnsTest {
    @Test
    fun presetsHaveStableUniqueIdsAndExpectedAddresses() {
        assertEquals(
            mapOf(
                "cloudflare" to listOf("1.1.1.1", "1.0.0.1"),
                "google" to listOf("8.8.8.8", "8.8.4.4"),
                "quad9" to listOf("9.9.9.9", "149.112.112.112"),
                "adguard" to listOf("94.140.14.14", "94.140.15.15"),
                "xbox" to listOf("111.88.96.50", "111.88.96.51"),
                "comss" to listOf("83.220.169.155", "212.109.195.93"),
            ),
            vpnDnsPresets.associate { it.id to it.servers },
        )
        assertEquals(vpnDnsPresets.size, vpnDnsPresets.map { it.id }.distinct().size)
        assertTrue(vpnDnsPresets.flatMap { it.servers }.all(::isIpv4Literal))
    }

    @Test
    fun invalidSelectionSafelyNormalizesToProfileDns() {
        assertEquals(VPN_DNS_PROFILE_ID, normalizeVpnDnsSelectionId(null))
        assertEquals(VPN_DNS_PROFILE_ID, normalizeVpnDnsSelectionId("unknown"))
        assertEquals("quad9", normalizeVpnDnsSelectionId(" QUAD9 "))
    }

    @Test
    fun customDnsAcceptsOneOrTwoNumericIpv4Addresses() {
        assertEquals(listOf("10.0.0.53"), normalizeCustomVpnDnsServers("10.0.0.53"))
        assertEquals(
            listOf("1.1.1.1", "8.8.8.8"),
            normalizeCustomVpnDnsServers("1.1.1.1; 8.8.8.8"),
        )
        assertEquals(
            listOf("1.1.1.1"),
            normalizeCustomVpnDnsServers("1.1.1.1, 1.1.1.1"),
        )
    }

    @Test
    fun customDnsRejectsUnsafeOrUnsupportedValues() {
        listOf(
            "",
            "dns.example",
            "1.1.1.1, 8.8.8.8, 9.9.9.9",
            "2001:4860:4860::8888",
            "01.1.1.1",
            "0.0.0.0",
            "127.0.0.1",
            "224.0.0.1",
            "255.255.255.255",
        ).forEach { value ->
            assertThrows(IllegalArgumentException::class.java) {
                normalizeCustomVpnDnsServers(value)
            }
        }
    }

    @Test
    fun effectiveDnsUsesProfilePresetAndCustomSelections() {
        val profileServers = listOf("10.66.66.1")

        assertEquals(
            profileServers,
            resolveEffectiveVpnDns(
                VpnDnsSettingsSnapshot(profileIndex = 0),
                profileServers,
            ).servers,
        )
        assertEquals(
            listOf("8.8.8.8", "8.8.4.4"),
            resolveEffectiveVpnDns(
                VpnDnsSettingsSnapshot(profileIndex = 0, selectionId = "google"),
                profileServers,
            ).servers,
        )
        assertEquals(
            listOf("10.0.0.53"),
            resolveEffectiveVpnDns(
                VpnDnsSettingsSnapshot(
                    profileIndex = 0,
                    selectionId = VPN_DNS_CUSTOM_ID,
                    customServers = listOf("10.0.0.53"),
                ),
                profileServers,
            ).servers,
        )
    }

    @Test
    fun missingCustomDnsFallsBackToWireGuardProfile() {
        val effective = resolveEffectiveVpnDns(
            VpnDnsSettingsSnapshot(
                profileIndex = 1,
                selectionId = VPN_DNS_CUSTOM_ID,
                customServers = emptyList(),
            ),
            profileServers = listOf("10.66.66.1"),
        )

        assertTrue(effective.fellBackToProfile)
        assertEquals(VPN_DNS_PROFILE_ID, effective.selectionId)
        assertEquals(listOf("10.66.66.1"), effective.servers)
    }

    @Test
    fun appliedLogUsesProfileNameAndHumanDnsText() {
        val profileDns = resolveEffectiveVpnDns(
            VpnDnsSettingsSnapshot(profileIndex = 0),
            profileServers = listOf("1.1.1.1", "1.0.0.1"),
        )
        val fallbackDns = resolveEffectiveVpnDns(
            VpnDnsSettingsSnapshot(
                profileIndex = 0,
                selectionId = VPN_DNS_CUSTOM_ID,
                customServers = emptyList(),
            ),
            profileServers = listOf("9.9.9.9"),
        )

        assertEquals(
            "«Дом»: DNS из WireGuard-профиля используется внутри VPN: 1.1.1.1, 1.0.0.1.",
            vpnDnsAppliedLogMessage("Дом", profileDns),
        )
        assertTrue(
            vpnDnsAppliedLogMessage("Дом", fallbackDns)
                .contains("Свой DNS был некорректен"),
        )
    }

    @Test
    fun dnsValuesAreRegisteredAsPerProfilePreferences() {
        assertTrue(
            SettingsStore.resettableProfilePreferenceNames().containsAll(
                setOf("vpn_dns_selection", "vpn_dns_custom")
            )
        )
    }

    @Test
    fun smartDnsAndInvalidCustomAreVisibleInDeviceDiagnostics() {
        val smart = vpnDnsModeItem(
            settings = VpnDnsSettingsSnapshot(profileIndex = 0, selectionId = "xbox"),
            tunnelRunning = true,
            runningProfile = 0,
        )
        val invalidCustom = vpnDnsModeItem(
            settings = VpnDnsSettingsSnapshot(
                profileIndex = 1,
                selectionId = VPN_DNS_CUSTOM_ID,
            ),
            tunnelRunning = false,
            runningProfile = null,
        )

        assertEquals(DeviceCheckSeverity.Info, smart.severity)
        assertTrue(smart.details.contains("сторонний Smart DNS"))
        assertEquals(DeviceCheckSeverity.Warning, invalidCustom.severity)
        assertFalse(invalidCustom.recommendation.isBlank())
    }
}
