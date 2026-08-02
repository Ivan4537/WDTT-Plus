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
                tunnelStarting = false,
                tunnelPaused = false,
                trustedWifiWaiting = false,
                trustedWifiResumeInProgress = true
            )
        )
        assertFalse(
            shouldKeepTunnelServiceAlive(
                tunnelRunning = false,
                tunnelStarting = false,
                tunnelPaused = false,
                trustedWifiWaiting = false,
                trustedWifiResumeInProgress = false
            )
        )
    }

    @Test
    fun `service stays alive while tunnel process is starting`() {
        assertTrue(
            shouldKeepTunnelServiceAlive(
                tunnelRunning = false,
                tunnelStarting = true,
                tunnelPaused = false,
                trustedWifiWaiting = false,
                trustedWifiResumeInProgress = false
            )
        )
    }

    @Test
    fun `trusted wifi resume retries keep cpu awake only during fast recovery window`() {
        assertEquals(
            TrustedWifiResumeRetryPlan(delayMs = 5_000L, keepCpuAwake = true),
            trustedWifiResumeRetryPlan(0)
        )
        assertEquals(
            TrustedWifiResumeRetryPlan(delayMs = 5_000L, keepCpuAwake = true),
            trustedWifiResumeRetryPlan(11)
        )
        assertEquals(
            TrustedWifiResumeRetryPlan(delayMs = 30_000L, keepCpuAwake = false),
            trustedWifiResumeRetryPlan(12)
        )
    }

    @Test
    fun `lost trusted wifi is not reused as validated resume network`() {
        val networks = TrustedWifiValidatedNetworkTracker<String>()
        networks.update(network = "home", validated = true, wifi = true)
        assertTrue(networks.hasUsableNetwork())

        networks.forgetWifi()
        assertFalse(networks.hasUsableNetwork())

        networks.update(network = "cellular", validated = true, wifi = false)
        assertTrue(networks.hasUsableNetwork())

        networks.lost("cellular")
        assertFalse(networks.hasUsableNetwork())
    }

    @Test
    fun `trusted wifi loss preserves an already validated cellular network`() {
        val networks = TrustedWifiValidatedNetworkTracker<String>()
        networks.update(network = "home", validated = true, wifi = true)
        networks.update(network = "cellular", validated = true, wifi = false)

        networks.forgetWifi()

        assertTrue(networks.hasUsableNetwork())
    }

    @Test
    fun `internet capability without validation is not enough to resume`() {
        val networks = TrustedWifiValidatedNetworkTracker<String>()
        networks.update(network = "cellular", validated = false, wifi = false)
        assertFalse(networks.hasUsableNetwork())

        networks.update(network = "cellular", validated = true, wifi = false)
        assertTrue(networks.hasUsableNetwork())
    }

    @Test
    fun `losing trusted wifi does not discard a newly validated untrusted wifi`() {
        val networks = TrustedWifiValidatedNetworkTracker<String>()
        networks.update(network = "home", validated = true, wifi = true)
        networks.update(network = "office", validated = true, wifi = true)

        networks.lost("home")

        assertTrue(networks.hasUsableNetwork())
    }
}
