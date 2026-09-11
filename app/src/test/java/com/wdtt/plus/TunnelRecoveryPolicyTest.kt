package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.TimeZone

class TunnelRecoveryPolicyTest {
    @Test
    fun unansweredUserTrafficIsEscalatedOnlyForSystemVpn() {
        assertEquals(true, shouldEscalateUserTrafficStall(TUNNEL_MODE_VPN))
        assertEquals(false, shouldEscalateUserTrafficStall(TUNNEL_MODE_SOCKS5))
        assertEquals(false, shouldEscalateUserTrafficStall(TUNNEL_MODE_HTTP))
    }

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
    fun onlyConfirmedVkCallsFloodKeepsCooldownAcrossNativeRestarts() {
        assertEquals(60_000L, vkCallsPreflightCooldownForLog("[VKCalls] VK временно ограничил анонимный вход"))
        assertEquals(0L, vkCallsPreflightCooldownForLog("[VKCalls] две современные анонимные сессии запросили CAPTCHA"))
        assertEquals(0L, vkCallsPreflightCooldownForLog("[VKCalls] preflight не сработал после безопасного повтора: timeout"))
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
    fun firstStatsSampleOnlyInitializesBaselineAndDoesNotFakeInboundTraffic() {
        assertEquals(
            TrafficSignatureDelta(
                initializeBaseline = true,
                downstreamChanged = false,
                upstreamChanged = false,
            ),
            classifyTrafficSignatureDelta(
                previousDownstream = "",
                previousUpstream = "",
                currentDownstream = "0.08",
                currentUpstream = "0.04",
            ),
        )
    }

    @Test
    fun onlyARealCounterChangeBecomesFreshTrafficEvidence() {
        assertEquals(
            TrafficSignatureDelta(
                initializeBaseline = false,
                downstreamChanged = true,
                upstreamChanged = false,
            ),
            classifyTrafficSignatureDelta(
                previousDownstream = "0.08",
                previousUpstream = "0.04",
                currentDownstream = "0.09",
                currentUpstream = "0.04",
            ),
        )
        assertEquals(
            TrafficSignatureDelta(
                initializeBaseline = false,
                downstreamChanged = false,
                upstreamChanged = false,
            ),
            classifyTrafficSignatureDelta(
                previousDownstream = "0.08",
                previousUpstream = "0.04",
                currentDownstream = "0.08",
                currentUpstream = "0.04",
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
    fun repeatedTransportTimeoutsEnterRecoveryInsteadOfImmediateCriticalStop() {
        assertEquals(
            true,
            shouldDeferRepeatedTransportErrorStop(
                line = "TURN UDP подключение 91.231.135.175:19302: dial udp: connect: network is unreachable",
                refusedCount = 400,
            ),
        )
        assertEquals(
            true,
            shouldDeferRepeatedTransportErrorStop(
                line = "read udp timeout",
                refusedCount = 400,
            ),
        )
        assertEquals(
            false,
            shouldDeferRepeatedTransportErrorStop(
                line = "read udp timeout",
                refusedCount = 399,
            ),
        )
        assertEquals(
            false,
            shouldDeferRepeatedTransportErrorStop(
                line = "FATAL_AUTH неверный пароль",
                refusedCount = 400,
            ),
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
    fun wakeRecoveryRequiresEveryChannelButKeepsPartialCapacityAvailable() {
        assertEquals(
            WakeRescueAction.HEALTHY,
            decideWakeRescueAction(
                freshTransportPath = true,
                readyWorkers = 18,
                targetWorkers = 18,
                confirmedNetworkFailure = false,
            ),
        )
        assertEquals(
            WakeRescueAction.RECONNECT,
            decideWakeRescueAction(
                freshTransportPath = false,
                readyWorkers = 0,
                targetWorkers = 18,
                confirmedNetworkFailure = false,
            ),
        )
        assertEquals(
            WakeRescueAction.PARTIALLY_AVAILABLE,
            decideWakeRescueAction(
                freshTransportPath = true,
                readyWorkers = 9,
                targetWorkers = 18,
                confirmedNetworkFailure = false,
            ),
        )
        assertEquals(
            WakeRescueAction.RECONNECT,
            decideWakeRescueAction(
                freshTransportPath = false,
                readyWorkers = 9,
                targetWorkers = 18,
                confirmedNetworkFailure = true,
            ),
        )
    }

    @Test
    fun wakeWorkerStatusIsParsedAndRejectsImpossibleCounts() {
        assertEquals(
            WakeWorkerStatus(generation = 3L, ready = 9, total = 18),
            parseWakeWorkerStatus("2026/09/08 10:00:00 [WAKE_STATUS] generation=3 ready=9 total=18"),
        )
        assertEquals(null, parseWakeWorkerStatus("[WAKE_STATUS] generation=3 ready=19 total=18"))
        assertEquals(null, parseWakeWorkerStatus("[WAKE_STATUS] generation=0 ready=0 total=18"))
    }

    @Test
    fun processReaderErrorsAreHiddenOnlyAfterExpectedCancellationOrReplacement() {
        assertEquals(true, shouldReportProcessReaderFailure(true, true))
        assertEquals(false, shouldReportProcessReaderFailure(false, true))
        assertEquals(false, shouldReportProcessReaderFailure(true, false))
        assertEquals(
            "поток чтения неожиданно закрыт",
            localizedProcessReaderFailure("IOException: Stream closed"),
        )
    }

    @Test
    fun screenOffHoldPolicyReleasesForEveryStopLikeStateAndSupportsProxy() {
        assertEquals(
            true,
            shouldHoldConnectionWhileScreenOff(
                ScreenOffMode.HOLD_CONNECTION, false, true, false, false, false, false,
                TUNNEL_MODE_VPN,
            ),
        )
        assertEquals(
            true,
            shouldHoldConnectionWhileScreenOff(
                ScreenOffMode.HOLD_CONNECTION, false, true, false, false, false, true,
                TUNNEL_MODE_SOCKS5,
            ),
        )
        assertEquals(
            true,
            shouldHoldConnectionWhileScreenOff(
                ScreenOffMode.HOLD_CONNECTION, false, true, false, false, false, true,
                TUNNEL_MODE_HTTP,
            ),
        )
        val blocked = listOf(
            shouldHoldConnectionWhileScreenOff(ScreenOffMode.BALANCED, false, true, false, false, false, false, TUNNEL_MODE_VPN),
            shouldHoldConnectionWhileScreenOff(ScreenOffMode.SAVE_BATTERY, false, true, false, false, false, false, TUNNEL_MODE_VPN),
            shouldHoldConnectionWhileScreenOff(ScreenOffMode.HOLD_CONNECTION, true, true, false, false, false, false, TUNNEL_MODE_VPN),
            shouldHoldConnectionWhileScreenOff(ScreenOffMode.HOLD_CONNECTION, false, false, false, false, false, false, TUNNEL_MODE_VPN),
            shouldHoldConnectionWhileScreenOff(ScreenOffMode.HOLD_CONNECTION, false, true, true, false, false, false, TUNNEL_MODE_VPN),
            shouldHoldConnectionWhileScreenOff(ScreenOffMode.HOLD_CONNECTION, false, true, false, true, false, false, TUNNEL_MODE_VPN),
            shouldHoldConnectionWhileScreenOff(ScreenOffMode.HOLD_CONNECTION, false, true, false, false, true, false, TUNNEL_MODE_VPN),
            shouldHoldConnectionWhileScreenOff(ScreenOffMode.HOLD_CONNECTION, false, true, false, false, false, true, TUNNEL_MODE_VPN),
        )
        assertEquals(List(blocked.size) { false }, blocked)
    }

    @Test
    fun hardHoldKeepsWifiForItsTransportWithoutDependingOnInternetValidation() {
        assertEquals(true, shouldHoldBackgroundWifiRadio(true, true))
        assertEquals(false, shouldHoldBackgroundWifiRadio(true, false))
        assertEquals(false, shouldHoldBackgroundWifiRadio(false, true))
    }

    @Test
    fun hardHoldPreparesCpuLockBeforeScreenOffAndReleasesForStopStates() {
        assertTrue(
            shouldKeepHoldModeCpuLock(
                ScreenOffMode.HOLD_CONNECTION,
                tunnelRunning = true,
                tunnelPaused = false,
                trustedWifiWaiting = false,
                stopRequested = false,
                vpnSlotYieldRequested = false,
                tunnelMode = TUNNEL_MODE_VPN,
            )
        )
        assertTrue(
            shouldKeepHoldModeCpuLock(
                ScreenOffMode.HOLD_CONNECTION,
                tunnelRunning = true,
                tunnelPaused = false,
                trustedWifiWaiting = false,
                stopRequested = false,
                vpnSlotYieldRequested = true,
                tunnelMode = TUNNEL_MODE_SOCKS5,
            )
        )
        val blocked = listOf(
            shouldKeepHoldModeCpuLock(ScreenOffMode.BALANCED, true, false, false, false, false, TUNNEL_MODE_VPN),
            shouldKeepHoldModeCpuLock(ScreenOffMode.HOLD_CONNECTION, false, false, false, false, false, TUNNEL_MODE_VPN),
            shouldKeepHoldModeCpuLock(ScreenOffMode.HOLD_CONNECTION, true, true, false, false, false, TUNNEL_MODE_VPN),
            shouldKeepHoldModeCpuLock(ScreenOffMode.HOLD_CONNECTION, true, false, true, false, false, TUNNEL_MODE_VPN),
            shouldKeepHoldModeCpuLock(ScreenOffMode.HOLD_CONNECTION, true, false, false, true, false, TUNNEL_MODE_VPN),
            shouldKeepHoldModeCpuLock(ScreenOffMode.HOLD_CONNECTION, true, false, false, false, true, TUNNEL_MODE_VPN),
        )
        assertEquals(List(blocked.size) { false }, blocked)
    }

    @Test
    fun wakeStatusDoesNotDescribeUnverifiedWorkersAsUnavailable() {
        assertEquals("Проверяем 27 потоков после сна…", wakeRecoveryStatusText(0, 27))
        assertEquals("Проверяем потоки после сна…", wakeRecoveryStatusText(0, 0))
        assertEquals(
            "Восстановление после сна · доступно 9/27",
            wakeRecoveryStatusText(9, 27),
        )
        assertEquals(
            "Проверяем удержанное соединение · 27 потоков",
            wakeRecoveryStatusText(0, 27, heldConnection = true),
        )
        assertEquals(
            "Соединение удерживается · подтверждено 9/27",
            wakeRecoveryStatusText(9, 27, heldConnection = true),
        )
    }

    @Test
    fun failedBackgroundAccessRefreshUsesBoundedBackoff() {
        assertEquals(2 * 60_000L, activeProfileRefreshDelayMs(0))
        assertEquals(4 * 60_000L, activeProfileRefreshDelayMs(1))
        assertEquals(8 * 60_000L, activeProfileRefreshDelayMs(2))
        assertEquals(16 * 60_000L, activeProfileRefreshDelayMs(3))
        assertEquals(16 * 60_000L, activeProfileRefreshDelayMs(99))
    }

    @Test
    fun repeatedFullWakeStatusDoesNotInflateCompletionLogCounter() {
        assertEquals(true, shouldLogWakeWorkerCompletion(true, 27, 27, 4L, 3L))
        assertEquals(false, shouldLogWakeWorkerCompletion(false, 27, 27, 4L, 3L))
        assertEquals(false, shouldLogWakeWorkerCompletion(true, 26, 27, 4L, 3L))
        assertEquals(false, shouldLogWakeWorkerCompletion(true, 27, 27, 4L, 4L))
        assertEquals(true, shouldLogWakeWorkerCompletion(true, 27, 27, 5L, 4L))
    }

    @Test
    fun peerDnsWaitDefersRecoveryOnlyForBoundedWindow() {
        assertEquals(false, shouldDeferRecoveryForPeerDns(0L, 100_000L))
        assertEquals(true, shouldDeferRecoveryForPeerDns(100_000L, 399_999L))
        assertEquals(false, shouldDeferRecoveryForPeerDns(100_000L, 400_000L))
    }

    @Test
    fun legacySleepSettingMigratesToTheMatchingThreeWayMode() {
        assertEquals(ScreenOffMode.SAVE_BATTERY, resolveScreenOffMode(null, true))
        assertEquals(ScreenOffMode.BALANCED, resolveScreenOffMode(null, false))
        assertEquals(
            ScreenOffMode.HOLD_CONNECTION,
            resolveScreenOffMode(ScreenOffMode.HOLD_CONNECTION.storedValue, true),
        )
    }

    @Test
    fun wakeRecoveryIncludesPongThatArrivedBeforeRescueJobStarted() {
        assertEquals(
            10_000L,
            wakeRecoveryReferenceAt(
                lastDeviceWakeAtMs = 10_000L,
                nowMs = 10_250L,
            ),
        )
        assertEquals(
            80_001L,
            wakeRecoveryReferenceAt(
                lastDeviceWakeAtMs = 10_000L,
                nowMs = 80_001L,
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
    fun wakeRecoveryNeverOverridesAnotherVpnPolicy() {
        assertEquals(
            true,
            shouldRunWakeTransportRecovery(
                tunnelRunning = true,
                tunnelPaused = false,
                trustedWifiWaiting = false,
                sleepPausedByPolicy = false,
                stopRequested = false,
                captchaActive = false,
                vpnSlotYieldRequested = false,
                realNetworkAvailable = true,
            ),
        )

        val blockedStates = listOf(
            shouldRunWakeTransportRecovery(false, false, false, false, false, false, false, true),
            shouldRunWakeTransportRecovery(true, true, false, false, false, false, false, true),
            shouldRunWakeTransportRecovery(true, false, true, false, false, false, false, true),
            shouldRunWakeTransportRecovery(true, false, false, true, false, false, false, true),
            shouldRunWakeTransportRecovery(true, false, false, false, true, false, false, true),
            shouldRunWakeTransportRecovery(true, false, false, false, false, true, false, true),
            shouldRunWakeTransportRecovery(true, false, false, false, false, false, true, true),
            shouldRunWakeTransportRecovery(true, false, false, false, false, false, false, false),
        )
        assertEquals(List(blockedStates.size) { false }, blockedStates)
    }

    @Test
    fun activeRecoveryWaitsForARealUnderlyingNetwork() {
        assertEquals(true, shouldRunActiveTransportRecovery(false, false, true, true, true))
        assertEquals(false, shouldRunActiveTransportRecovery(false, false, true, true, false))
        assertEquals(false, shouldRunActiveTransportRecovery(true, false, true, true, true))
    }

    @Test
    fun phantomVpnCleanupDoesNotRaceExpectedRestore() {
        assertEquals(false, shouldClearPhantomVpn(activeTunnelProfile = 0))
        assertEquals(false, shouldClearPhantomVpn(activeTunnelProfile = 2))
        assertEquals(true, shouldClearPhantomVpn(activeTunnelProfile = null))
    }
}
