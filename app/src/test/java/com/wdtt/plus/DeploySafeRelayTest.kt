package com.wdtt.plus

import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DeploySafeRelayTest {
    @Test
    fun activePeerMustMatchDeployTargetExactly() {
        assertTrue(deployTargetMatchesActivePeer("server.example", "server.example:56000"))
        assertTrue(deployTargetMatchesActivePeer("SERVER.EXAMPLE.", "server.example:56000"))
        assertTrue(deployTargetMatchesActivePeer("2001:db8::1", "[2001:db8::1]:56000"))
        assertFalse(deployTargetMatchesActivePeer("other.example", "server.example:56000"))
        assertFalse(deployTargetMatchesActivePeer("server.example.evil", "server.example:56000"))
    }

    @Test
    fun domainAndIpMayMatchOnlyWhenResolutionConfirmsSameAddress() {
        val addresses = mapOf(
            "server.example" to setOf("203.0.113.10"),
            "alias.example" to setOf("203.0.113.10"),
            "203.0.113.10" to setOf("203.0.113.10"),
            "other.example" to setOf("203.0.113.11"),
        )
        val resolver: (String) -> Set<String> = { addresses[it].orEmpty() }

        assertTrue(deployResolvedHostsMatch("203.0.113.10", "server.example:56000", resolver))
        assertTrue(deployResolvedHostsMatch("server.example", "203.0.113.10:56000", resolver))
        assertFalse(deployResolvedHostsMatch("other.example", "203.0.113.10:56000", resolver))
        assertFalse(deployResolvedHostsMatch("unknown.example", "203.0.113.10:56000", resolver))
        assertEquals(
            DeploySafeRelayTargetMatch.Resolved,
            classifyDeployTargetMatch("203.0.113.10", "server.example:56000", resolver),
        )
        assertEquals(
            DeploySafeRelayTargetMatch.Different,
            classifyDeployTargetMatch("other.example", "203.0.113.10:56000", resolver),
        )
        assertEquals(
            DeploySafeRelayTargetMatch.Unresolved,
            classifyDeployTargetMatch("unknown.example", "203.0.113.10:56000", resolver),
        )
        assertEquals(
            DeploySafeRelayTargetMatch.Unresolved,
            classifyDeployTargetMatch("alias.example", "server.example:56000", resolver),
        )
    }

    @Test
    fun relayAvailabilityExplainsDifferentAndUnresolvedAddresses() {
        val different = DeploySafeRelayAvailability(
            transportAvailable = true,
            targetMatch = DeploySafeRelayTargetMatch.Different,
        )
        assertFalse(different.available)
        assertTrue(different.unavailableMessage().contains("другому серверу"))
        assertTrue(different.unavailableMessage().contains("один и тот же IP-адрес или домен"))
        assertTrue(different.unavailableMessage().contains("пока не поддерживается"))

        val unresolved = DeploySafeRelayAvailability(
            transportAvailable = true,
            targetMatch = DeploySafeRelayTargetMatch.Unresolved,
        )
        assertFalse(unresolved.available)
        assertTrue(unresolved.unavailableMessage().contains("Не удалось подтвердить"))
        assertTrue(unresolved.unavailableMessage().contains("один и тот же IP-адрес или домен"))
    }

    @Test
    fun controlRelayUsesLiveTransportWithoutDependingOnSystemVpnInterface() {
        assertTrue(transportControlRelayAvailable(true, 1, TUNNEL_MODE_VPN, false))
        assertTrue(transportControlRelayAvailable(true, 27, TUNNEL_MODE_SOCKS5, false))
        assertFalse(transportControlRelayAvailable(true, 27, TUNNEL_MODE_VPN, true))
        assertFalse(transportControlRelayAvailable(true, 0, TUNNEL_MODE_VPN, false))
        assertFalse(transportControlRelayAvailable(false, 27, TUNNEL_MODE_VPN, false))
    }
}
