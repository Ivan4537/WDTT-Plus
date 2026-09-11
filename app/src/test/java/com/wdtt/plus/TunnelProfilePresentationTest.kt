package com.wdtt.plus

import com.wdtt.plus.ui.hasTunnelConnectionSource
import com.wdtt.plus.ui.resolveConnectionInputMethod
import com.wdtt.plus.ui.resolveTunnelStartReadiness
import com.wdtt.plus.ui.selectedTunnelConnectionRequirements
import com.wdtt.plus.ui.storedLinkConnectionRequirements
import com.wdtt.plus.ui.TunnelConnectionRequirements
import com.wdtt.plus.ui.TunnelStartIssueTarget
import com.wdtt.plus.ui.usesCompactTunnelInterface
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelProfilePresentationTest {
    @Test
    fun `start issues are ordered by the next actionable setting`() {
        val readiness = resolveTunnelStartReadiness(
            connectionConfigured = false,
            hashesPresent = false,
            hashesInvalid = false,
            rtSniValid = false,
            proxySettingsValid = false,
        )
        val issues = readiness.issues

        assertFalse(readiness.canStart)
        assertEquals(
            listOf(
                TunnelStartIssueTarget.CONNECTION,
                TunnelStartIssueTarget.HASHES,
                TunnelStartIssueTarget.PARAMETERS,
                TunnelStartIssueTarget.PROXY_SETTINGS,
            ),
            issues.map { it.target },
        )
        assertTrue(issues[1].message.contains("хотя бы один ВК-хеш"))
    }

    @Test
    fun `invalid hashes replace the missing hash message`() {
        val issues = resolveTunnelStartReadiness(
            connectionConfigured = true,
            hashesPresent = true,
            hashesInvalid = true,
            rtSniValid = true,
            proxySettingsValid = true,
        ).issues

        assertEquals(1, issues.size)
        assertEquals(TunnelStartIssueTarget.HASHES, issues.single().target)
        assertTrue(issues.single().message.contains("исправьте"))
    }

    @Test
    fun `complete profile has no start issues`() {
        assertTrue(
            resolveTunnelStartReadiness(
                connectionConfigured = true,
                hashesPresent = true,
                hashesInvalid = false,
                rtSniValid = true,
                proxySettingsValid = true,
            ).canStart
        )
    }

    @Test
    fun `user role uses compact tunnel interface`() {
        assertTrue(usesCompactTunnelInterface("user"))
        assertFalse(usesCompactTunnelInterface("admin"))
    }

    @Test
    fun `empty profiles use role specific default method`() {
        assertEquals("link", resolveConnectionInputMethod("", false, false, true))
        assertEquals("manual", resolveConnectionInputMethod("", false, false, false))
        assertEquals("manual", resolveConnectionInputMethod("", false, true, true))
        assertEquals("link", resolveConnectionInputMethod("link", false, true, false))
    }

    @Test
    fun `legacy profiles without saved method keep their configured source`() {
        assertEquals("link", resolveConnectionInputMethod("", true, false, false))
        assertEquals("link", resolveConnectionInputMethod("", true, true, true))
        assertEquals("manual", resolveConnectionInputMethod("", false, true, false))
        val ready = TunnelConnectionRequirements(true, true, false)
        val incomplete = TunnelConnectionRequirements(false, false, false)
        assertTrue(
            selectedTunnelConnectionRequirements(
                selectedMethod = "link",
                savedMethod = "",
                storedLinkMode = true,
                storedLink = ready,
                manual = incomplete,
            ).canStart
        )
        assertTrue(
            selectedTunnelConnectionRequirements(
                selectedMethod = "manual",
                savedMethod = "",
                storedLinkMode = false,
                storedLink = incomplete,
                manual = ready,
            ).canStart
        )
    }

    @Test
    fun `manual and link profiles detect their own connection source`() {
        assertTrue(hasTunnelConnectionSource(false, false, "vpn.example", "secret"))
        assertFalse(hasTunnelConnectionSource(false, false, "vpn.example", ""))
        assertTrue(hasTunnelConnectionSource(true, true, "", ""))
        assertTrue(hasTunnelConnectionSource(true, false, "vpn.example", "secret"))
    }

    @Test
    fun `selected connection method must match configured method`() {
        val ready = TunnelConnectionRequirements(true, true, false)
        val incomplete = TunnelConnectionRequirements(false, false, false)
        assertTrue(
            selectedTunnelConnectionRequirements(
                selectedMethod = "manual",
                savedMethod = "manual",
                storedLinkMode = false,
                storedLink = incomplete,
                manual = ready,
            ).canStart
        )
        assertFalse(
            selectedTunnelConnectionRequirements(
                selectedMethod = "link",
                savedMethod = "manual",
                storedLinkMode = false,
                storedLink = incomplete,
                manual = ready,
            ).canStart
        )
        assertTrue(
            selectedTunnelConnectionRequirements(
                selectedMethod = "link",
                savedMethod = "link",
                storedLinkMode = false,
                storedLink = incomplete,
                manual = ready,
            ).canStart
        )
        assertFalse(
            selectedTunnelConnectionRequirements(
                selectedMethod = "manual",
                savedMethod = "link",
                storedLinkMode = false,
                storedLink = incomplete,
                manual = ready,
            ).canStart
        )
    }

    @Test
    fun `incomplete selected method is not ready`() {
        val ready = TunnelConnectionRequirements(true, true, false)
        val incomplete = TunnelConnectionRequirements(false, false, false)
        assertFalse(
            selectedTunnelConnectionRequirements(
                selectedMethod = "manual",
                savedMethod = "manual",
                storedLinkMode = false,
                storedLink = ready,
                manual = incomplete,
            ).canStart
        )
        assertFalse(
            selectedTunnelConnectionRequirements(
                selectedMethod = "link",
                savedMethod = "",
                storedLinkMode = true,
                storedLink = incomplete,
                manual = ready,
            ).canStart
        )
    }

    @Test
    fun `stored link separates connection and hash problems`() {
        val missingHashesLink = WdttTransferCodec.buildConnectionLink(
            WdttLinkParts("vpn.example.org", 56000, 56001, 9000, "secret", "")
        )
        val missingHashes = storedLinkConnectionRequirements(
            missingHashesLink,
            WdttDeepLink.validate(missingHashesLink),
        )
        assertTrue(missingHashes.connectionConfigured)
        assertFalse(missingHashes.hashesPresent)
        assertFalse(missingHashes.hashesInvalid)

        val invalidHashesLink = WdttTransferCodec.buildConnectionLink(
            WdttLinkParts("vpn.example.org", 56000, 56001, 9000, "secret", "неверный")
        )
        val invalidHashes = storedLinkConnectionRequirements(
            invalidHashesLink,
            WdttDeepLink.validate(invalidHashesLink),
        )
        assertTrue(invalidHashes.connectionConfigured)
        assertFalse(invalidHashes.hashesPresent)
        assertTrue(invalidHashes.hashesInvalid)

        val malformedConnection = "wdtt://connect?v=1&host=vpn.example.org"
        val malformed = storedLinkConnectionRequirements(
            malformedConnection,
            WdttDeepLink.validate(malformedConnection),
        )
        assertFalse(malformed.connectionConfigured)
        assertTrue(malformed.hashesPresent)
    }

    @Test
    fun `running tunnel keeps launch profile after selection changes`() {
        assertEquals(
            0,
            displayedTunnelProfile(
                selectedProfile = 2,
                activeTunnelProfile = 0,
                running = true,
                trustedWifiWaiting = false,
            )
        )
    }

    @Test
    fun `trusted wifi waiting keeps tunnel profile`() {
        assertEquals(
            1,
            displayedTunnelProfile(
                selectedProfile = 2,
                activeTunnelProfile = 1,
                running = false,
                trustedWifiWaiting = true,
            )
        )
    }

    @Test
    fun `disconnected interface follows selected profile`() {
        assertEquals(
            2,
            displayedTunnelProfile(
                selectedProfile = 2,
                activeTunnelProfile = 0,
                running = false,
                trustedWifiWaiting = false,
            )
        )
    }
}
