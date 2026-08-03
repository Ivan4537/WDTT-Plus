package com.wdtt.plus

import com.wdtt.plus.ui.hasTunnelConnectionSource
import com.wdtt.plus.ui.isSelectedCompactConnectionReady
import com.wdtt.plus.ui.resolveConnectionInputMethod
import com.wdtt.plus.ui.usesCompactTunnelInterface
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelProfilePresentationTest {
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
        assertTrue(
            isSelectedCompactConnectionReady(
                selectedMethod = "link",
                savedMethod = "",
                storedLinkMode = true,
                linkPresent = true,
                linkValid = true,
                manualValid = false,
            )
        )
        assertTrue(
            isSelectedCompactConnectionReady(
                selectedMethod = "manual",
                savedMethod = "",
                storedLinkMode = false,
                linkPresent = false,
                linkValid = false,
                manualValid = true,
            )
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
        assertTrue(
            isSelectedCompactConnectionReady(
                selectedMethod = "manual",
                savedMethod = "manual",
                storedLinkMode = false,
                linkPresent = false,
                linkValid = false,
                manualValid = true,
            )
        )
        assertFalse(
            isSelectedCompactConnectionReady(
                selectedMethod = "link",
                savedMethod = "manual",
                storedLinkMode = false,
                linkPresent = false,
                linkValid = false,
                manualValid = true,
            )
        )
        assertTrue(
            isSelectedCompactConnectionReady(
                selectedMethod = "link",
                savedMethod = "link",
                storedLinkMode = false,
                linkPresent = false,
                linkValid = false,
                manualValid = true,
            )
        )
        assertFalse(
            isSelectedCompactConnectionReady(
                selectedMethod = "manual",
                savedMethod = "link",
                storedLinkMode = false,
                linkPresent = false,
                linkValid = false,
                manualValid = true,
            )
        )
    }

    @Test
    fun `incomplete selected method is not ready`() {
        assertFalse(
            isSelectedCompactConnectionReady(
                selectedMethod = "manual",
                savedMethod = "manual",
                storedLinkMode = false,
                linkPresent = false,
                linkValid = false,
                manualValid = false,
            )
        )
        assertFalse(
            isSelectedCompactConnectionReady(
                selectedMethod = "link",
                savedMethod = "",
                storedLinkMode = true,
                linkPresent = true,
                linkValid = false,
                manualValid = true,
            )
        )
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
