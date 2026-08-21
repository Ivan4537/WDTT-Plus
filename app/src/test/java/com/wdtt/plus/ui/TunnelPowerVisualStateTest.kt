package com.wdtt.plus.ui

import org.junit.Assert.assertEquals
import org.junit.Test

class TunnelPowerVisualStateTest {
    @Test
    fun tunWithoutNetworkIsNotPresentedAsConnected() {
        assertEquals(
            TunnelPowerVisualState.NoNetwork,
            state(
                running = true,
                activeWorkers = 0,
                underlyingNetworkAvailable = false,
            ),
        )
    }

    @Test
    fun zeroWorkersRemainConnectingUntilFirstWorkerAppears() {
        assertEquals(
            TunnelPowerVisualState.Connecting,
            state(
                running = true,
                activeWorkers = 0,
                underlyingNetworkAvailable = true,
            ),
        )
        assertEquals(
            TunnelPowerVisualState.Connected,
            state(
                running = true,
                activeWorkers = 1,
                underlyingNetworkAvailable = true,
            ),
        )
    }

    @Test
    fun deliberateStopAndTrustedWifiWaitingKeepTheirOwnStates() {
        assertEquals(
            TunnelPowerVisualState.Stopping,
            state(stopping = true),
        )
        assertEquals(
            TunnelPowerVisualState.WaitingForTrustedWifi,
            state(waitingForTrustedWifi = true),
        )
    }

    private fun state(
        running: Boolean = false,
        waitingForTrustedWifi: Boolean = false,
        starting: Boolean = false,
        stopping: Boolean = false,
        activeWorkers: Int = 0,
        underlyingNetworkAvailable: Boolean = true,
        hasConnectionError: Boolean = false,
        cooldownActive: Boolean = false,
    ): TunnelPowerVisualState = tunnelPowerVisualState(
        running = running,
        waitingForTrustedWifi = waitingForTrustedWifi,
        starting = starting,
        stopping = stopping,
        activeWorkers = activeWorkers,
        underlyingNetworkAvailable = underlyingNetworkAvailable,
        hasConnectionError = hasConnectionError,
        cooldownActive = cooldownActive,
    )
}
