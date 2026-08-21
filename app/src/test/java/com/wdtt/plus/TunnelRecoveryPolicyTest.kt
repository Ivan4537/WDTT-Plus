package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.TimeZone

class TunnelRecoveryPolicyTest {
    @Test
    fun vkCallsFloodCooldownSurvivesFastNativeRestarts() {
        assertEquals(
            false,
            shouldUseVkCallsPreflight(
                enabledByUser = true,
                cooldownUntilMs = 160_000L,
                nowMs = 100_000L,
            ),
        )
        assertEquals(
            true,
            shouldUseVkCallsPreflight(
                enabledByUser = true,
                cooldownUntilMs = 160_000L,
                nowMs = 160_000L,
            ),
        )
        assertEquals(
            false,
            shouldUseVkCallsPreflight(
                enabledByUser = false,
                cooldownUntilMs = 0L,
                nowMs = 100_000L,
            ),
        )
    }

    @Test
    fun vkCallsPreflightFailuresKeepTheirCooldownAcrossNativeRestarts() {
        assertEquals(60_000L, vkCallsPreflightCooldownForLog("[VKCalls] VK временно ограничил анонимный вход"))
        assertEquals(120_000L, vkCallsPreflightCooldownForLog("[VKCalls] VKCalls запросил CAPTCHA; временно не повторяем preflight"))
        assertEquals(45_000L, vkCallsPreflightCooldownForLog("[VKCalls] preflight не сработал: timeout; временно не повторяем его"))
        assertEquals(0L, vkCallsPreflightCooldownForLog("[VKCalls] TURN credentials получены"))
    }

    @Test
    fun staleVkCallsCooldownIsNeverRestoredAfterTheAppRestarts() {
        assertEquals(
            160_000L,
            boundedVkCallsPreflightCooldownUntil(
                untilMs = 160_000L,
                nowMs = 100_000L,
            ),
        )
        assertEquals(
            0L,
            boundedVkCallsPreflightCooldownUntil(
                untilMs = 220_001L,
                nowMs = 100_000L,
            ),
        )
        assertEquals(
            0L,
            boundedVkCallsPreflightCooldownUntil(
                untilMs = 100_000L,
                nowMs = 100_000L,
            ),
        )
    }

    @Test
    fun sleepLogsIncludePhoneTimeAfterTheFirstEventPhrase() {
        val utc = TimeZone.getTimeZone("UTC")
        val nowMs = 56_342_000L

        assertEquals(
            "[СОН] Экран включён в 15:39:02. Проверяем VPN.",
            addPhoneTimeToSleepLog(
                message = "[СОН] Экран включён. Проверяем VPN.",
                nowMs = nowMs,
                timeZone = utc,
            ),
        )
        assertEquals(
            "[СОН] Устройство проснулось в 15:39:02; ждём стабилизации.",
            addPhoneTimeToSleepLog(
                message = "[СОН] Устройство проснулось; ждём стабилизации.",
                nowMs = nowMs,
                timeZone = utc,
            ),
        )
        assertEquals(
            "[СЕТЬ] Сеть изменилась.",
            addPhoneTimeToSleepLog(
                message = "[СЕТЬ] Сеть изменилась.",
                nowMs = nowMs,
                timeZone = utc,
            ),
        )
    }

    @Test
    fun timerResumeRequiresAnActualServerOrUserTrafficResponse() {
        assertEquals(
            true,
            hasFreshTransportPath(
                running = true,
                activeWorkers = 36,
                lastInboundTrafficAtMs = 0L,
                lastKeepaliveResponseAtMs = 120_000L,
                sinceMs = 100_000L,
                nowMs = 150_000L,
            ),
        )
        assertEquals(
            false,
            hasFreshTransportPath(
                running = true,
                activeWorkers = 36,
                lastInboundTrafficAtMs = 0L,
                lastKeepaliveResponseAtMs = 0L,
                sinceMs = 100_000L,
                nowMs = 175_000L,
            ),
        )
    }

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
                vpnSlotYieldRequested = false,
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
                vpnSlotYieldRequested = false,
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
                vpnSlotYieldRequested = false,
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
                vpnSlotYieldRequested = false,
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
                vpnSlotYieldRequested = false,
                missingForMs = 120_000L,
                validatedNetworkAvailable = true,
                sinceLastAttemptMs = 60_000L,
            ),
        )
    }

    @Test
    fun externalVpnDropYieldsSlotInsteadOfRecoveringInterface() {
        assertEquals(
            false,
            shouldAttemptVpnInterfaceRecovery(
                deviceInteractive = true,
                startupWindow = false,
                captchaActive = false,
                vpnSlotYieldRequested = true,
                missingForMs = 120_000L,
                validatedNetworkAvailable = true,
                sinceLastAttemptMs = Long.MAX_VALUE,
            ),
        )
        assertEquals(
            true,
            shouldYieldVpnSlot(
                vpnSlotYieldRequested = true,
                tunnelRunning = true,
                stopRequested = false,
            ),
        )
        assertEquals(
            false,
            shouldYieldVpnSlot(
                vpnSlotYieldRequested = false,
                tunnelRunning = true,
                stopRequested = false,
            ),
        )
        assertEquals(
            false,
            shouldYieldVpnSlot(
                vpnSlotYieldRequested = true,
                tunnelRunning = true,
                stopRequested = true,
            ),
        )
        assertEquals(
            false,
            shouldYieldVpnSlot(
                vpnSlotYieldRequested = true,
                tunnelRunning = false,
                stopRequested = false,
            ),
        )
        assertEquals(
            true,
            shouldBlockVpnStart(
                vpnSlotYieldRequested = true,
            ),
        )
        assertEquals(
            false,
            shouldBlockVpnStart(
                vpnSlotYieldRequested = false,
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
    fun networkReturnNeverResumesATunnelPausedBySleepPolicy() {
        assertEquals(
            true,
            shouldResumeVpnAfterNetworkReturn(
                networkPausedByLoss = true,
                sleepPausedByPolicy = false,
                tunnelRunning = true,
                usableNetworkAvailable = true,
            ),
        )
        assertEquals(
            false,
            shouldResumeVpnAfterNetworkReturn(
                networkPausedByLoss = true,
                sleepPausedByPolicy = true,
                tunnelRunning = true,
                usableNetworkAvailable = true,
            ),
        )
        assertEquals(
            false,
            shouldResumeVpnAfterNetworkReturn(
                networkPausedByLoss = false,
                sleepPausedByPolicy = false,
                tunnelRunning = true,
                usableNetworkAvailable = true,
            ),
        )
    }

    @Test
    fun validatedNetworkTransitionHandlesBothCallbackOrders() {
        assertEquals(
            ValidatedNetworkTransition.HANDOVER,
            classifyValidatedNetworkTransition(
                previousNetwork = "wifi",
                currentNetwork = "cellular",
                previousNetworkWasLost = false,
            ),
        )
        assertEquals(
            ValidatedNetworkTransition.HANDOVER,
            classifyValidatedNetworkTransition(
                previousNetwork = null,
                currentNetwork = "cellular",
                previousNetworkWasLost = true,
            ),
        )
        assertEquals(
            ValidatedNetworkTransition.INITIAL,
            classifyValidatedNetworkTransition(
                previousNetwork = null,
                currentNetwork = "cellular",
                previousNetworkWasLost = false,
            ),
        )
        assertEquals(
            ValidatedNetworkTransition.UNCHANGED,
            classifyValidatedNetworkTransition(
                previousNetwork = "cellular",
                currentNetwork = "cellular",
                previousNetworkWasLost = false,
            ),
        )
    }

    @Test
    fun availableNetworkCanRecoverHandoverWithoutAndroidValidation() {
        assertEquals(
            true,
            shouldScheduleAvailableNetworkHandover(
                previousNetworkWasLost = true,
                availableRealNetworkCount = 1,
            ),
        )
        assertEquals(
            false,
            shouldScheduleAvailableNetworkHandover(
                previousNetworkWasLost = true,
                availableRealNetworkCount = 0,
            ),
        )
        assertEquals(
            false,
            shouldScheduleAvailableNetworkHandover(
                previousNetworkWasLost = false,
                availableRealNetworkCount = 1,
            ),
        )
    }

    @Test
    fun handoverTrackingIsLimitedToTheActiveTunnelAndDoesNotExtendPendingCheck() {
        assertEquals(
            true,
            shouldTrackUnderlyingNetworkLoss(
                tunnelRunning = true,
                tunnelPaused = false,
                trustedWifiWaiting = false,
            ),
        )
        assertEquals(
            false,
            shouldTrackUnderlyingNetworkLoss(
                tunnelRunning = false,
                tunnelPaused = false,
                trustedWifiWaiting = false,
            ),
        )
        assertEquals(
            false,
            shouldTrackUnderlyingNetworkLoss(
                tunnelRunning = true,
                tunnelPaused = true,
                trustedWifiWaiting = false,
            ),
        )
        assertEquals(
            false,
            shouldTrackUnderlyingNetworkLoss(
                tunnelRunning = true,
                tunnelPaused = false,
                trustedWifiWaiting = true,
            ),
        )
        assertEquals(
            false,
            shouldStartUnderlyingNetworkCheck(
                checkPending = true,
                currentJobActive = true,
            ),
        )
        assertEquals(
            true,
            shouldStartUnderlyingNetworkCheck(
                checkPending = true,
                currentJobActive = false,
            ),
        )
        assertEquals(
            130_000L,
            updatedUnderlyingNetworkEvidenceSince(
                currentEvidenceSinceMs = 100_000L,
                networkEventAtMs = 130_000L,
            ),
        )
        assertEquals(
            130_000L,
            updatedUnderlyingNetworkEvidenceSince(
                currentEvidenceSinceMs = 130_000L,
                networkEventAtMs = 120_000L,
            ),
        )
    }

    @Test
    fun handoverReconnectDoesNotOverlapOtherTunnelPolicies() {
        fun reconnectAllowed(
            tunnelRunning: Boolean = true,
            tunnelPaused: Boolean = false,
            trustedWifiWaiting: Boolean = false,
            sleepPausedByPolicy: Boolean = false,
            stopRequested: Boolean = false,
            interactiveAtSchedule: Boolean = true,
            deviceInteractive: Boolean = true,
            wakeRecoveryGraceActive: Boolean = false,
            realNetworkAvailable: Boolean = true,
            captchaActive: Boolean = false,
        ): Boolean = shouldRunUnderlyingNetworkReconnect(
            tunnelRunning = tunnelRunning,
            tunnelPaused = tunnelPaused,
            trustedWifiWaiting = trustedWifiWaiting,
            sleepPausedByPolicy = sleepPausedByPolicy,
            stopRequested = stopRequested,
            interactiveAtSchedule = interactiveAtSchedule,
            deviceInteractive = deviceInteractive,
            wakeRecoveryGraceActive = wakeRecoveryGraceActive,
            realNetworkAvailable = realNetworkAvailable,
            captchaActive = captchaActive,
        )

        assertEquals(true, reconnectAllowed())
        assertEquals(false, reconnectAllowed(tunnelRunning = false))
        assertEquals(false, reconnectAllowed(tunnelPaused = true))
        assertEquals(false, reconnectAllowed(trustedWifiWaiting = true))
        assertEquals(false, reconnectAllowed(sleepPausedByPolicy = true))
        assertEquals(false, reconnectAllowed(stopRequested = true))
        assertEquals(false, reconnectAllowed(interactiveAtSchedule = false))
        assertEquals(false, reconnectAllowed(deviceInteractive = false))
        assertEquals(false, reconnectAllowed(wakeRecoveryGraceActive = true))
        assertEquals(false, reconnectAllowed(realNetworkAvailable = false))
        assertEquals(false, reconnectAllowed(captchaActive = true))
    }

    @Test
    fun freshInboundTrafficConfirmsWakeRecovery() {
        assertEquals(
            true,
            hasFreshTransportHeartbeat(
                running = true,
                activeWorkers = 9,
                lastInboundTrafficAtMs = 120_000L,
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
                lastInboundTrafficAtMs = 90_000L,
                sinceMs = 100_000L,
                nowMs = 130_000L,
            ),
        )
        assertEquals(
            false,
            hasFreshTransportHeartbeat(
                running = true,
                activeWorkers = 0,
                lastInboundTrafficAtMs = 120_000L,
                sinceMs = 100_000L,
                nowMs = 130_000L,
            ),
        )
    }

    @Test
    fun confirmedUserTrafficFailureUsesShortRecoveryWindow() {
        assertEquals(true, isConfirmedUserTrafficFailure(userTrafficStalled = true))
        assertEquals(false, isConfirmedUserTrafficFailure(userTrafficStalled = false))
        assertEquals(
            true,
            isTransportHealthRecovery("пользовательский трафик снова получает ответы"),
        )
        assertEquals(
            false,
            isTransportHealthRecovery("пользовательский трафик не получает ответы"),
        )
        assertEquals(30_000L, stableRecoveryGraceMs(hardFailure = true))
        assertEquals(2 * 60_000L, stableRecoveryRetryMs(hardFailure = true))
        assertEquals(10 * 60_000L, stableRecoveryGraceMs(hardFailure = false))
        assertEquals(10 * 60_000L, stableRecoveryRetryMs(hardFailure = false))
        assertEquals(
            false,
            shouldDeferConnectionIssueNotification(
                confirmedUserTrafficFailure = true,
                recoverableNetworkErrorAtMs = 100_000L,
                recoveryAttempts = 0,
                nowMs = 100_001L,
                firstGraceMs = 30_000L,
            ),
        )
        assertEquals(
            true,
            shouldDeferConnectionIssueNotification(
                confirmedUserTrafficFailure = false,
                recoverableNetworkErrorAtMs = 100_000L,
                recoveryAttempts = 0,
                nowMs = 100_001L,
                firstGraceMs = 30_000L,
            ),
        )
        assertEquals(
            NetworkRecoveryAction.SoftRestart,
            confirmedFailureRecoveryAction(hardFailure = true, completedAttempts = 0),
        )
        assertEquals(
            NetworkRecoveryAction.StopVpn,
            confirmedFailureRecoveryAction(hardFailure = true, completedAttempts = 1),
        )
        assertEquals(
            NetworkRecoveryAction.SoftRestart,
            confirmedFailureRecoveryAction(hardFailure = false, completedAttempts = 0),
        )
        assertEquals(
            NetworkRecoveryAction.SoftRestart,
            confirmedFailureRecoveryAction(hardFailure = false, completedAttempts = 3),
        )
    }

    @Test
    fun confirmedFailureTimestampMustExistAndMatchRequestedWindow() {
        assertEquals(false, hasConfirmedNetworkFailureAtOrAfter(true, 0L, 0L))
        assertEquals(false, hasConfirmedNetworkFailureAtOrAfter(false, 120_000L, 100_000L))
        assertEquals(false, hasConfirmedNetworkFailureAtOrAfter(true, 99_999L, 100_000L))
        assertEquals(true, hasConfirmedNetworkFailureAtOrAfter(true, 100_000L, 100_000L))
    }

    @Test
    fun confirmedFailureIsClearedOnlyByRealDownstreamTraffic() {
        assertEquals(
            false,
            shouldResetNetworkRecoveryFromStats(
                downstreamChanged = false,
                hardNetworkFailure = true,
                trafficChanged = true,
                statsTrafficStagnant = false,
            ),
        )
        assertEquals(
            true,
            shouldResetNetworkRecoveryFromStats(
                downstreamChanged = true,
                hardNetworkFailure = true,
                trafficChanged = true,
                statsTrafficStagnant = false,
            ),
        )
        assertEquals(
            true,
            shouldResetNetworkRecoveryFromStats(
                downstreamChanged = false,
                hardNetworkFailure = false,
                trafficChanged = true,
                statsTrafficStagnant = false,
            ),
        )
    }

    @Test
    fun wakeRecoveryReconnectsForZeroWorkersOrConfirmedFailure() {
        assertEquals(
            true,
            shouldReconnectTunnelAfterWake(activeWorkers = 0, confirmedNetworkFailure = false),
        )
        assertEquals(
            true,
            shouldReconnectTunnelAfterWake(activeWorkers = 9, confirmedNetworkFailure = true),
        )
        assertEquals(
            false,
            shouldReconnectTunnelAfterWake(activeWorkers = 9, confirmedNetworkFailure = false),
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
    fun passiveVpnRefreshesStatusRarelyButTransitionsStayResponsive() {
        assertEquals(
            30_000L,
            tunnelStatusRefreshIntervalMs(
                deviceInteractive = false,
                transitionWakeLockHeld = false,
                trustedWifiTransitionInProgress = false,
            ),
        )
        assertEquals(
            2_000L,
            tunnelStatusRefreshIntervalMs(
                deviceInteractive = true,
                transitionWakeLockHeld = false,
                trustedWifiTransitionInProgress = false,
            ),
        )
        assertEquals(
            2_000L,
            tunnelStatusRefreshIntervalMs(
                deviceInteractive = false,
                transitionWakeLockHeld = true,
                trustedWifiTransitionInProgress = false,
            ),
        )
        assertEquals(
            2_000L,
            tunnelStatusRefreshIntervalMs(
                deviceInteractive = false,
                transitionWakeLockHeld = false,
                trustedWifiTransitionInProgress = true,
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
