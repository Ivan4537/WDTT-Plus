package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.json.JSONObject

class VpnAddressRoutingTest {
    @Test
    fun addressListsAreRegisteredAsPerProfilePreferences() {
        assertTrue(
            SettingsStore.resettableProfilePreferenceNames().containsAll(
                setOf("blacklist_addresses", "whitelist_addresses")
            )
        )
    }

    @Test
    fun normalizesDomainUrlIpAndSubnet() {
        assertEquals(
            VpnAddressRule(VpnAddressType.DOMAIN, "xn--e1afmkfd.xn--p1ai"),
            normalizeVpnAddressRule("https://Пример.рф/path?q=1"),
        )
        assertEquals(
            VpnAddressRule(VpnAddressType.IP, "1.2.3.4"),
            normalizeVpnAddressRule("1.2.3.4"),
        )
        assertEquals(
            VpnAddressRule(VpnAddressType.IP, "1.2.3.4"),
            normalizeVpnAddressRule("https://1.2.3.4/status"),
        )
        assertEquals(
            VpnAddressRule(VpnAddressType.SUBNET, "192.168.1.0/24"),
            normalizeVpnAddressRule("192.168.1.77/24"),
        )
        assertEquals(
            VpnAddressRule(VpnAddressType.DOMAIN, "example.org"),
            normalizeVpnAddressRule("example.org:443"),
        )
        assertEquals(
            VpnAddressRule(VpnAddressType.IP, "1.2.3.4"),
            normalizeVpnAddressRule("1.2.3.4:53"),
        )
    }

    @Test
    fun normalizesMultilineInputAndIpv4Ranges() {
        assertEquals(
            listOf(
                VpnAddressRule(VpnAddressType.DOMAIN, "example.org"),
                VpnAddressRule(VpnAddressType.SUBNET, "192.0.2.1/32"),
                VpnAddressRule(VpnAddressType.SUBNET, "192.0.2.2/31"),
                VpnAddressRule(VpnAddressType.SUBNET, "192.0.2.4/31"),
                VpnAddressRule(VpnAddressType.SUBNET, "192.0.2.6/32"),
                VpnAddressRule(VpnAddressType.IP, "8.8.8.8"),
            ),
            normalizeVpnAddressRules(
                """
                    example.org
                    192.0.2.1 - 192.0.2.6
                    8.8.8.8 - 8.8.8.8
                """.trimIndent()
            ),
        )
        assertThrows(IllegalArgumentException::class.java) {
            normalizeVpnAddressRules("192.0.2.10 - 192.0.2.1")
        }
    }

    @Test
    fun rejectsWildcardIpv6AndMalformedIpv4() {
        assertThrows(IllegalArgumentException::class.java) {
            normalizeVpnAddressRule("*.example.org")
        }
        assertThrows(IllegalArgumentException::class.java) {
            normalizeVpnAddressRule("2001:db8::1")
        }
        assertThrows(IllegalArgumentException::class.java) {
            normalizeVpnAddressRule("01.2.3.4", VpnAddressType.IP)
        }
    }

    @Test
    fun codecPreservesValidatedRules() {
        val rules = listOf(
            normalizeVpnAddressRule("example.org"),
            normalizeVpnAddressRule("1.1.1.1"),
            normalizeVpnAddressRule("10.10.15.8/16"),
        )

        assertEquals(rules, decodeVpnAddressRulesStrict(encodeVpnAddressRules(rules)))
    }

    @Test
    fun routingDocumentRoundTripPreservesBothModesAndCategories() {
        val document = VpnRoutingDocument(
            isWhitelist = true,
            blacklistApps = listOf("android", "app.black"),
            whitelistApps = listOf("app.white"),
            blacklistAddresses = listOf(normalizeVpnAddressRule("black.example")),
            whitelistAddresses = listOf(normalizeVpnAddressRule("10.20.30.0/24")),
        )

        assertEquals(document, decodeVpnRoutingDocument(encodeVpnRoutingDocument(document)))
    }

    @Test
    fun routingDocumentRejectsInvalidPackagesAndMissingLists() {
        val valid = JSONObject(encodeVpnRoutingDocument(
            VpnRoutingDocument(false, emptyList(), emptyList(), emptyList(), emptyList())
        ))
        valid.getJSONArray("blacklistApps").put("not a package")
        assertThrows(IllegalArgumentException::class.java) {
            decodeVpnRoutingDocument(valid.toString())
        }

        val missingAddresses = JSONObject()
            .put("format", "wdtt-plus-routing")
            .put("version", 1)
            .put("blacklistApps", org.json.JSONArray())
            .put("whitelistApps", org.json.JSONArray())
        assertThrows(IllegalArgumentException::class.java) {
            decodeVpnRoutingDocument(missingAddresses.toString())
        }
    }

    @Test
    fun emptyAddressListKeepsTheDefaultRouteInBothModes() {
        assertEquals(
            listOf("0.0.0.0/0"),
            resolveVpnAddressRouting(false, emptyList()) { emptyList() }.allowedIps,
        )
        assertEquals(
            listOf("0.0.0.0/0"),
            resolveVpnAddressRouting(true, emptyList()) { emptyList() }.allowedIps,
        )
    }

    @Test
    fun blacklistSubtractsIpAndSubnetFromDefaultRoute() {
        val blockedIp = ipv4("1.1.1.1")
        val blockedSubnetIp = ipv4("10.20.30.40")
        val regularIp = ipv4("8.8.8.8")
        val rules = listOf(
            normalizeVpnAddressRule("1.1.1.1"),
            normalizeVpnAddressRule("10.0.0.0/8"),
        )

        val routes = resolveVpnAddressRouting(false, rules) { emptyList() }.allowedIps

        assertFalse(routes.any { cidrContains(it, blockedIp) })
        assertFalse(routes.any { cidrContains(it, blockedSubnetIp) })
        assertTrue(routes.any { cidrContains(it, regularIp) })
    }

    @Test
    fun completeBlacklistAndWhitelistHaveOppositeBoundaryRoutes() {
        val allIpv4 = listOf(normalizeVpnAddressRule("0.0.0.0/0"))

        assertTrue(resolveVpnAddressRouting(false, allIpv4) { emptyList() }.allowedIps.isEmpty())
        assertEquals(
            listOf("0.0.0.0/0"),
            resolveVpnAddressRouting(true, allIpv4) { emptyList() }.allowedIps,
        )
    }

    @Test
    fun adjacentPrefixesCollapseWithoutChangingTheirCoverage() {
        val allIpv4AsTwoHalves = listOf(
            normalizeVpnAddressRule("0.0.0.0/1"),
            normalizeVpnAddressRule("128.0.0.0/1"),
        )

        assertEquals(
            listOf("0.0.0.0/0"),
            resolveVpnAddressRouting(true, allIpv4AsTwoHalves) { emptyList() }.allowedIps,
        )
        assertTrue(
            resolveVpnAddressRouting(false, allIpv4AsTwoHalves) { emptyList() }
                .allowedIps
                .isEmpty()
        )
    }

    @Test
    fun overlappingBlacklistRulesDoNotCreateHolesOutsideTheSelection() {
        val routes = resolveVpnAddressRouting(
            isWhitelist = false,
            rules = listOf(
                normalizeVpnAddressRule("10.0.0.0/8"),
                normalizeVpnAddressRule("10.20.0.0/16"),
                normalizeVpnAddressRule("10.20.30.40"),
                normalizeVpnAddressRule("255.255.255.255"),
            ),
            domainResolver = { emptyList() },
        ).allowedIps

        listOf("10.0.0.0", "10.20.30.40", "10.255.255.255", "255.255.255.255")
            .forEach { excluded -> assertFalse(routes.any { cidrContains(it, ipv4(excluded)) }) }
        listOf("0.0.0.0", "9.255.255.255", "11.0.0.0", "255.255.255.254")
            .forEach { included -> assertTrue(routes.any { cidrContains(it, ipv4(included)) }) }
    }

    @Test
    fun whitelistUsesOnlySelectedAndResolvedAddresses() {
        val rules = listOf(
            normalizeVpnAddressRule("example.org"),
            normalizeVpnAddressRule("192.168.7.0/24"),
        )

        val result = resolveVpnAddressRouting(true, rules) { domain ->
            if (domain == "example.org") listOf("93.184.216.34", "2001:db8::1") else emptyList()
        }

        assertEquals(setOf("93.184.216.34/32", "192.168.7.0/24"), result.allowedIps.toSet())
        assertTrue(result.unresolvedDomains.isEmpty())
    }

    @Test
    fun unresolvedDomainIsReportedAndDoesNotBroadenWhitelist() {
        val result = resolveVpnAddressRouting(
            isWhitelist = true,
            rules = listOf(normalizeVpnAddressRule("offline.example")),
            domainResolver = { emptyList() },
        )

        assertTrue(result.allowedIps.isEmpty())
        assertEquals(listOf("offline.example"), result.unresolvedDomains)
    }

    @Test
    fun blacklistSplitRouteKeepsIpv6FromFallingThroughOutsideVpn() {
        val splitBlacklist = resolveVpnAddressRouting(
            isWhitelist = false,
            rules = listOf(normalizeVpnAddressRule("1.1.1.1")),
            domainResolver = { emptyList() },
        )

        val effective = effectiveWireGuardAllowedIps(
            isWhitelist = false,
            addressRulesConfigured = true,
            addressRouting = splitBlacklist,
            vpnDnsIpv4 = listOf("8.8.8.8"),
        )

        assertTrue("::/1" in effective)
        assertTrue("8000::/1" in effective)
        assertFalse("::/0" in effective)
        assertTrue("8.8.8.8/32" in effective)
    }

    @Test
    fun whitelistAddsVpnDnsButAllowsUnselectedFamiliesToFallThrough() {
        val addressWhitelist = resolveVpnAddressRouting(
            isWhitelist = true,
            rules = listOf(normalizeVpnAddressRule("1.1.1.1")),
            domainResolver = { emptyList() },
        )

        val effective = effectiveWireGuardAllowedIps(
            isWhitelist = true,
            addressRulesConfigured = true,
            addressRouting = addressWhitelist,
            vpnDnsIpv4 = listOf("8.8.8.8", "invalid"),
        )

        assertEquals(setOf("1.1.1.1/32", "8.8.8.8/32"), effective.toSet())
        assertFalse("::/0" in effective)
    }

    @Test
    fun unresolvedBlacklistDomainDoesNotUnnecessarilyChangeIpv6Policy() {
        val unresolvedBlacklist = resolveVpnAddressRouting(
            isWhitelist = false,
            rules = listOf(normalizeVpnAddressRule("offline.example")),
            domainResolver = { emptyList() },
        )

        val effective = effectiveWireGuardAllowedIps(
            isWhitelist = false,
            addressRulesConfigured = true,
            addressRouting = unresolvedBlacklist,
            vpnDnsIpv4 = emptyList(),
        )

        assertEquals(listOf("0.0.0.0/0"), effective)
    }

    private fun ipv4(value: String): Long = value.split('.').fold(0L) { result, part ->
        (result shl 8) or part.toLong()
    }

    private fun cidrContains(cidr: String, address: Long): Boolean {
        val (networkValue, lengthValue) = cidr.split('/')
        val network = ipv4(networkValue)
        val length = lengthValue.toInt()
        val mask = if (length == 0) 0L else (0xffff_ffffL shl (32 - length)) and 0xffff_ffffL
        return address and mask == network
    }
}
