package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Test

class TunnelRecoveryPolicyTest {
    @Test
    fun firstRecoveryIsTransportOnly() {
        assertEquals(
            NetworkRecoveryAction.SoftRestart,
            stableNetworkRecoveryAction(completedAttempts = 0),
        )
    }

    @Test
    fun repeatedStableRecoveryRemainsTransportOnly() {
        assertEquals(
            NetworkRecoveryAction.SoftRestart,
            stableNetworkRecoveryAction(completedAttempts = 1),
        )
        assertEquals(
            NetworkRecoveryAction.SoftRestart,
            stableNetworkRecoveryAction(completedAttempts = 2),
        )
        assertEquals(
            NetworkRecoveryAction.SoftRestart,
            stableNetworkRecoveryAction(completedAttempts = 3),
        )
    }

    @Test
    fun vpnInterfaceRecoveryRequiresAwakeDeviceAndValidatedNetwork() {
        assertEquals(
            false,
            shouldAttemptVpnInterfaceRecovery(
                deviceInteractive = false,
                startupWindow = false,
                captchaActive = false,
                missingForMs = 120_000L,
                validatedNetworkAvailable = true,
                sinceLastAttemptMs = Long.MAX_VALUE,
            ),
        )
        assertEquals(
            false,
            shouldAttemptVpnInterfaceRecovery(
                deviceInteractive = true,
                startupWindow = false,
                captchaActive = false,
                missingForMs = 120_000L,
                validatedNetworkAvailable = false,
                sinceLastAttemptMs = Long.MAX_VALUE,
            ),
        )
        assertEquals(
            true,
            shouldAttemptVpnInterfaceRecovery(
                deviceInteractive = true,
                startupWindow = false,
                captchaActive = false,
                missingForMs = 120_000L,
                validatedNetworkAvailable = true,
                sinceLastAttemptMs = Long.MAX_VALUE,
            ),
        )
        assertEquals(
            false,
            shouldAttemptVpnInterfaceRecovery(
                deviceInteractive = true,
                startupWindow = false,
                captchaActive = false,
                missingForMs = 30_000L,
                validatedNetworkAvailable = true,
                sinceLastAttemptMs = Long.MAX_VALUE,
            ),
        )
        assertEquals(
            false,
            shouldAttemptVpnInterfaceRecovery(
                deviceInteractive = true,
                startupWindow = false,
                captchaActive = false,
                missingForMs = 120_000L,
                validatedNetworkAvailable = true,
                sinceLastAttemptMs = 60_000L,
            ),
        )
    }

    @Test
    fun sleepBatteryModePausesOnlyAnActiveTunnel() {
        assertEquals(
            true,
            shouldPauseVpnForSleep(
                pauseEnabled = true,
                deviceInteractive = false,
                tunnelRunning = true,
                tunnelPaused = false,
                trustedWifiWaiting = false,
            ),
        )
        assertEquals(
            false,
            shouldPauseVpnForSleep(
                pauseEnabled = false,
                deviceInteractive = false,
                tunnelRunning = true,
                tunnelPaused = false,
                trustedWifiWaiting = false,
            ),
        )
        assertEquals(
            false,
            shouldPauseVpnForSleep(
                pauseEnabled = true,
                deviceInteractive = true,
                tunnelRunning = true,
                tunnelPaused = false,
                trustedWifiWaiting = false,
            ),
        )
        assertEquals(
            false,
            shouldPauseVpnForSleep(
                pauseEnabled = true,
                deviceInteractive = false,
                tunnelRunning = true,
                tunnelPaused = true,
                trustedWifiWaiting = false,
            ),
        )
    }

    @Test
    fun sleepBatteryModeResumesOnlyItsOwnPause() {
        assertEquals(
            true,
            shouldResumeVpnAfterSleep(
                sleepPausedByPolicy = true,
                tunnelRunning = true,
                tunnelPaused = true,
                trustedWifiWaiting = false,
            ),
        )
        assertEquals(
            false,
            shouldResumeVpnAfterSleep(
                sleepPausedByPolicy = false,
                tunnelRunning = true,
                tunnelPaused = true,
                trustedWifiWaiting = false,
            ),
        )
        assertEquals(
            false,
            shouldResumeVpnAfterSleep(
                sleepPausedByPolicy = true,
                tunnelRunning = true,
                tunnelPaused = true,
                trustedWifiWaiting = true,
            ),
        )
    }

    @Test
    fun freshActiveHeartbeatDoesNotRequireTrafficGrowth() {
        assertEquals(
            true,
            hasFreshTransportHeartbeat(
                running = true,
                activeWorkers = 9,
                lastActiveAtMs = 120_000L,
                lastStatsAtMs = 120_000L,
                sinceMs = 100_000L,
                nowMs = 130_000L,
            ),
        )
    }

    @Test
    fun oldOrEmptyHeartbeatStillRequiresRecovery() {
        assertEquals(
            false,
            hasFreshTransportHeartbeat(
                running = true,
                activeWorkers = 9,
                lastActiveAtMs = 90_000L,
                lastStatsAtMs = 90_000L,
                sinceMs = 100_000L,
                nowMs = 130_000L,
            ),
        )
        assertEquals(
            false,
            hasFreshTransportHeartbeat(
                running = true,
                activeWorkers = 0,
                lastActiveAtMs = 120_000L,
                lastStatsAtMs = 120_000L,
                sinceMs = 100_000L,
                nowMs = 130_000L,
            ),
        )
    }

    @Test
    fun tunnelHealthIsNotJudgedDuringSleepOrWakeStabilization() {
        assertEquals(
            false,
            shouldObserveTunnelHealth(
                deviceInteractive = false,
                wakeRecoveryGraceActive = false,
            ),
        )
        assertEquals(
            false,
            shouldObserveTunnelHealth(
                deviceInteractive = true,
                wakeRecoveryGraceActive = true,
            ),
        )
        assertEquals(
            true,
            shouldObserveTunnelHealth(
                deviceInteractive = true,
                wakeRecoveryGraceActive = false,
            ),
        )
    }

    @Test
    fun phantomVpnCleanupDoesNotRaceExpectedRestore() {
        assertEquals(false, shouldClearPhantomVpn(activeTunnelProfile = 0))
        assertEquals(false, shouldClearPhantomVpn(activeTunnelProfile = 2))
        assertEquals(true, shouldClearPhantomVpn(activeTunnelProfile = null))
    }
}
