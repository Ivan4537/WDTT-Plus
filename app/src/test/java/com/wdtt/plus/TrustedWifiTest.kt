package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TrustedWifiTest {
    @Test
    fun `running tunnel enters waiting only on exact trusted ssid`() {
        assertEquals(
            TrustedWifiTransition.EnterWaiting,
            decideTrustedWifiTransition(
                enabled = true,
                tunnelRunning = true,
                waiting = false,
                wifi = ConnectedWifiState(connected = true, ssid = "Home Wi-Fi"),
                trustedSsids = setOf("Home Wi-Fi")
            )
        )
        assertEquals(
            TrustedWifiTransition.None,
            decideTrustedWifiTransition(
                enabled = true,
                tunnelRunning = true,
                waiting = false,
                wifi = ConnectedWifiState(connected = true, ssid = "home wi-fi"),
                trustedSsids = setOf("Home Wi-Fi")
            )
        )
    }

    @Test
    fun `waiting resumes after wifi disconnect or untrusted wifi`() {
        assertEquals(
            TrustedWifiTransition.ResumeVpn,
            decideTrustedWifiTransition(
                enabled = true,
                tunnelRunning = false,
                waiting = true,
                wifi = ConnectedWifiState(connected = false),
                trustedSsids = setOf("Home")
            )
        )
        assertEquals(
            TrustedWifiTransition.ResumeVpn,
            decideTrustedWifiTransition(
                enabled = true,
                tunnelRunning = false,
                waiting = true,
                wifi = ConnectedWifiState(connected = true, ssid = "Office"),
                trustedSsids = setOf("Home")
            )
        )
    }

    @Test
    fun `unknown ssid never disables running vpn and restores waiting vpn`() {
        val unknown = ConnectedWifiState(
            connected = true,
            accessProblem = TrustedWifiAccessProblem.ForegroundPermission
        )
        assertEquals(
            TrustedWifiTransition.None,
            decideTrustedWifiTransition(true, true, false, unknown, setOf("Home"))
        )
        assertEquals(
            TrustedWifiTransition.ResumeVpn,
            decideTrustedWifiTransition(true, false, true, unknown, setOf("Home"))
        )
    }

    @Test
    fun `ssid is unquoted and limited to wifi byte limit`() {
        assertEquals("Home Wi-Fi", sanitizeTrustedWifiSsid("\"Home Wi-Fi\""))
        assertEquals(32, sanitizeTrustedWifiSsid("a".repeat(40)).toByteArray().size)
    }

    @Test
    fun `leaving trusted wifi never starts vpn unless waiting was armed`() {
        assertEquals(
            TrustedWifiTransition.None,
            decideTrustedWifiTransition(
                enabled = true,
                tunnelRunning = false,
                waiting = false,
                wifi = ConnectedWifiState(connected = false),
                trustedSsids = setOf("Home")
            )
        )
    }

    @Test
    fun `removing last trusted network resumes armed vpn`() {
        assertEquals(
            TrustedWifiTransition.ResumeVpn,
            decideTrustedWifiTransition(
                enabled = true,
                tunnelRunning = false,
                waiting = true,
                wifi = ConnectedWifiState(connected = true, ssid = "Home"),
                trustedSsids = emptySet()
            )
        )
    }

    @Test
    fun `service stays alive while trusted wifi vpn is resuming`() {
        assertTrue(
            shouldKeepTunnelServiceAlive(
                tunnelRunning = false,
                tunnelPaused = false,
                trustedWifiWaiting = false,
                trustedWifiResumeInProgress = true
            )
        )
        assertFalse(
            shouldKeepTunnelServiceAlive(
                tunnelRunning = false,
                tunnelPaused = false,
                trustedWifiWaiting = false,
                trustedWifiResumeInProgress = false
            )
        )
    }
}
