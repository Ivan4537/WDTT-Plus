package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelStartConfigTest {

    @Test
    fun managedProfileUsesSpareHashesAtMoreThanOneWorkerGroup() {
        assertTrue(shouldUseManagedHashFallback(profileMaxWorkers = 18, hashCount = 4))
        assertTrue(shouldUseManagedHashFallback(profileMaxWorkers = 9, hashCount = 2))
        assertFalse(shouldUseManagedHashFallback(profileMaxWorkers = 0, hashCount = 4))
        assertFalse(shouldUseManagedHashFallback(profileMaxWorkers = 18, hashCount = 1))
    }

    @Test
    fun `wireguard config is required before workers for every profile`() {
        assertEquals(true, shouldUseConfigFirstStart())
    }

    @Test
    fun `tile and widgets stop both active and trusted wifi waiting tunnel`() {
        assertEquals(
            TunnelToggleAction.STOP,
            tunnelToggleAction(
                running = true,
                trustedWifiWaiting = false,
                vpnPermissionRequired = false,
            )
        )
        assertEquals(
            TunnelToggleAction.STOP,
            tunnelToggleAction(
                running = false,
                trustedWifiWaiting = true,
                vpnPermissionRequired = false,
            )
        )
    }

    @Test
    fun `tile and widgets request permission before start`() {
        assertEquals(
            TunnelToggleAction.REQUEST_VPN_PERMISSION,
            tunnelToggleAction(
                running = false,
                trustedWifiWaiting = false,
                vpnPermissionRequired = true,
            )
        )
        assertEquals(
            TunnelToggleAction.START,
            tunnelToggleAction(
                running = false,
                trustedWifiWaiting = false,
                vpnPermissionRequired = false,
            )
        )
    }

    @Test
    fun `stop action is selected before any permission probe`() {
        assertEquals(
            TunnelToggleAction.STOP,
            tunnelToggleAction(
                running = true,
                trustedWifiWaiting = false,
                vpnPermissionRequired = true,
            ),
        )
        assertEquals(
            TunnelToggleAction.STOP,
            tunnelToggleAction(
                running = false,
                trustedWifiWaiting = true,
                vpnPermissionRequired = true,
            ),
        )
    }

}
