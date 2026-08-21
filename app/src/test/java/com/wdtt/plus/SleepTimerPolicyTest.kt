package com.wdtt.plus

import com.wdtt.plus.ui.adjustSleepTimerHours
import com.wdtt.plus.ui.formatSleepTimerDuration
import com.wdtt.plus.ui.replaceSleepTimerMinuteComponent
import com.wdtt.plus.ui.sleepBatteryModeDiagnosticText
import com.wdtt.plus.ui.sleepBatteryRuntimeDiagnosticText
import com.wdtt.plus.ui.updateSleepTimerFromDialDrag
import org.junit.Assert.assertEquals
import org.junit.Test

class SleepTimerPolicyTest {
    @Test
    fun shortPauseAndResumeTimersKeepOnlyABoundedWakeGuard() {
        assertEquals(
            70_000L,
            shortSleepResumeGuardDurationMs(deadlineWallMs = 160_000L, nowMs = 100_000L),
        )
        assertEquals(
            null,
            shortSleepResumeGuardDurationMs(
                deadlineWallMs = 100_000L + 2 * 60_000L + 1L,
                nowMs = 100_000L,
            ),
        )
        assertEquals(
            null,
            shortSleepResumeGuardDurationMs(deadlineWallMs = 100_000L, nowMs = 100_000L),
        )
    }

    @Test
    fun timerBoundsAreAlwaysEnforced() {
        assertEquals(5, DEFAULT_SLEEP_PAUSE_DELAY_MINUTES)
        assertEquals(0, normalizeSleepPauseDelayMinutes(-1))
        assertEquals(0, normalizeSleepPauseDelayMinutes(0))
        assertEquals(24 * 60, normalizeSleepPauseDelayMinutes(Int.MAX_VALUE))
        assertEquals(90, adjustSleepTimerHours(totalMinutes = 30, hoursDelta = 1))
        assertEquals(0, adjustSleepTimerHours(totalMinutes = 30, hoursDelta = -1))
        assertEquals(0, adjustSleepTimerHours(totalMinutes = 60, hoursDelta = -1))
        assertEquals(24 * 60, adjustSleepTimerHours(totalMinutes = 23 * 60 + 30, hoursDelta = 1))
    }

    @Test
    fun dialReplacesMinutesAndCountsFullTurnsAsHours() {
        assertEquals(165, replaceSleepTimerMinuteComponent(totalMinutes = 125, minute = 45))
        assertEquals(
            60,
            updateSleepTimerFromDialDrag(
                totalMinutes = 59,
                previousMinute = 59,
                nextMinute = 0,
            ),
        )
        assertEquals(
            59,
            updateSleepTimerFromDialDrag(
                totalMinutes = 60,
                previousMinute = 0,
                nextMinute = 59,
            ),
        )
        assertEquals(
            24 * 60,
            updateSleepTimerFromDialDrag(
                totalMinutes = 24 * 60,
                previousMinute = 0,
                nextMinute = 1,
            ),
        )
        assertEquals(
            24 * 60 - 1,
            updateSleepTimerFromDialDrag(
                totalMinutes = 24 * 60,
                previousMinute = 0,
                nextMinute = 59,
            ),
        )
        assertEquals(
            0,
            updateSleepTimerFromDialDrag(
                totalMinutes = 0,
                previousMinute = 0,
                nextMinute = 59,
            ),
        )
        assertEquals(
            0,
            updateSleepTimerFromDialDrag(
                totalMinutes = 0,
                previousMinute = 59,
                nextMinute = 58,
            ),
        )
        assertEquals(
            1,
            updateSleepTimerFromDialDrag(
                totalMinutes = 0,
                previousMinute = 58,
                nextMinute = 59,
            ),
        )
        assertEquals(
            24 * 60,
            updateSleepTimerFromDialDrag(
                totalMinutes = 24 * 60,
                previousMinute = 1,
                nextMinute = 2,
            ),
        )
        assertEquals(
            24 * 60 - 1,
            updateSleepTimerFromDialDrag(
                totalMinutes = 24 * 60,
                previousMinute = 2,
                nextMinute = 1,
            ),
        )
    }

    @Test
    fun durationUsesCompactRussianLabels() {
        assertEquals("0 мин", formatSleepTimerDuration(0))
        assertEquals("2 мин", formatSleepTimerDuration(2))
        assertEquals("1 ч", formatSleepTimerDuration(60))
        assertEquals("2 ч 5 мин", formatSleepTimerDuration(125))
        assertEquals("24 ч", formatSleepTimerDuration(24 * 60))
    }

    @Test
    fun sleepBatteryDiagnosticsDescribeConfiguredModeAndRuntime() {
        assertEquals(
            "отключить VPN после задержки до включения экрана",
            sleepBatteryModeDiagnosticText(SleepBatteryMode.DELAYED_PAUSE),
        )
        assertEquals(
            "VPN отключён, ожидается включение по таймеру, осталось 2 мин",
            sleepBatteryRuntimeDiagnosticText(
                runtime = SleepBatteryRuntimeState(
                    phase = SleepBatteryRuntimePhase.WAITING_TO_RESUME,
                    deadlineMs = 220_000L,
                ),
                nowMs = 100_000L,
            ),
        )
    }

    @Test
    fun sleepModesHaveStablePersistedValuesAndSafeFallback() {
        assertEquals(
            SleepBatteryMode.DELAYED_PAUSE,
            SleepBatteryMode.fromStoredValue("delayed_pause"),
        )
        assertEquals(
            SleepBatteryMode.TIMED_PAUSE,
            SleepBatteryMode.fromStoredValue("timed_pause"),
        )
        assertEquals(
            SleepBatteryMode.DELAYED_PAUSE,
            SleepBatteryMode.fromStoredValue("unknown"),
        )
        assertEquals(
            SleepBatteryPlan(pauseAfterMinutes = 5, resumeAfterMinutes = null),
            buildSleepBatteryPlan(
                mode = SleepBatteryMode.DELAYED_PAUSE,
                pauseDelayMinutes = 5,
                resumeDelayMinutes = 90,
            ),
        )
        assertEquals(
            SleepBatteryPlan(pauseAfterMinutes = 0, resumeAfterMinutes = 90),
            buildSleepBatteryPlan(
                mode = SleepBatteryMode.TIMED_PAUSE,
                pauseDelayMinutes = 5,
                resumeDelayMinutes = 90,
            ),
        )
    }

    @Test
    fun screenOnAlwaysDisarmsTheCurrentSleepCycle() {
        assertEquals(
            SleepBatteryRuntimePhase.IDLE,
            sleepRuntimePhaseAfterPauseAttempt(deviceInteractive = true, paused = true),
        )
        assertEquals(
            SleepBatteryRuntimePhase.IDLE,
            sleepRuntimePhaseAfterResume(deviceInteractive = true),
        )
    }

    @Test
    fun wakeNotificationExplainsWhatTheSleepTimerDid() {
        assertEquals(
            "Таймер отменён: экран включён до отключения VPN",
            sleepWakeNotificationText(SleepBatteryRuntimePhase.WAITING_TO_PAUSE),
        )
        assertEquals(
            "VPN включается после сна · во сне был выключен",
            sleepWakeNotificationText(SleepBatteryRuntimePhase.PAUSED_UNTIL_SCREEN_ON),
        )
        assertEquals(
            "VPN включается раньше таймера · экран включён",
            sleepWakeNotificationText(SleepBatteryRuntimePhase.WAITING_TO_RESUME),
        )
        assertEquals(
            "VPN был включён по таймеру во время сна",
            sleepWakeNotificationText(SleepBatteryRuntimePhase.RESUMED_UNTIL_SCREEN_ON),
        )
        assertEquals(null, sleepWakeNotificationText(SleepBatteryRuntimePhase.IDLE))
    }

    @Test
    fun completedActionsAreNotRearmedBeforeTheNextScreenOff() {
        assertEquals(
            SleepBatteryRuntimePhase.PAUSED_UNTIL_SCREEN_ON,
            sleepRuntimePhaseAfterPauseAttempt(deviceInteractive = false, paused = true),
        )
        assertEquals(
            SleepBatteryRuntimePhase.RESUMED_UNTIL_SCREEN_ON,
            sleepRuntimePhaseAfterPauseAttempt(deviceInteractive = false, paused = false),
        )
        assertEquals(
            SleepBatteryRuntimePhase.RESUMED_UNTIL_SCREEN_ON,
            sleepRuntimePhaseAfterResume(deviceInteractive = false),
        )
    }

    @Test
    fun screenOnDoesNotRestartVpnWhileDelayedPauseIsOnlyWaiting() {
        assertEquals(
            SleepResumeAction.KEEP_CURRENT_TUNNEL,
            decideSleepResumeAction(
                trigger = SleepResumeTrigger.SCREEN_ON,
                runtimePhase = SleepBatteryRuntimePhase.WAITING_TO_PAUSE,
                tunnelRunning = true,
                blockedByAnotherPolicy = false,
            ),
        )
    }

    @Test
    fun screenOnResumesOnlyACommittedSleepPause() {
        assertEquals(
            SleepResumeAction.KEEP_CURRENT_TUNNEL,
            decideSleepResumeAction(
                trigger = SleepResumeTrigger.SCREEN_ON,
                runtimePhase = SleepBatteryRuntimePhase.IDLE,
                tunnelRunning = true,
                blockedByAnotherPolicy = false,
            ),
        )
        assertEquals(
            SleepResumeAction.RESUME_PAUSED_TUNNEL,
            decideSleepResumeAction(
                trigger = SleepResumeTrigger.SCREEN_ON,
                runtimePhase = SleepBatteryRuntimePhase.PAUSED_UNTIL_SCREEN_ON,
                tunnelRunning = true,
                blockedByAnotherPolicy = false,
            ),
        )
    }

    @Test
    fun timedResumeCannotBeReusedForAnotherSleepPhase() {
        assertEquals(
            SleepResumeAction.RESUME_PAUSED_TUNNEL,
            decideSleepResumeAction(
                trigger = SleepResumeTrigger.TIMER,
                runtimePhase = SleepBatteryRuntimePhase.WAITING_TO_RESUME,
                tunnelRunning = true,
                blockedByAnotherPolicy = false,
            ),
        )
        assertEquals(
            SleepResumeAction.KEEP_CURRENT_TUNNEL,
            decideSleepResumeAction(
                trigger = SleepResumeTrigger.TIMER,
                runtimePhase = SleepBatteryRuntimePhase.PAUSED_UNTIL_SCREEN_ON,
                tunnelRunning = true,
                blockedByAnotherPolicy = false,
            ),
        )
    }

    @Test
    fun timerRestoresACommittedPauseAfterAndroidRecreatesTheProcess() {
        assertEquals(
            SleepResumeAction.RESTORE_PAUSED_TUNNEL,
            decideSleepResumeAction(
                trigger = SleepResumeTrigger.TIMER,
                runtimePhase = SleepBatteryRuntimePhase.WAITING_TO_RESUME,
                tunnelRunning = false,
                blockedByAnotherPolicy = false,
            ),
        )
        assertEquals(
            SleepResumeAction.KEEP_CURRENT_TUNNEL,
            decideSleepResumeAction(
                trigger = SleepResumeTrigger.TIMER,
                runtimePhase = SleepBatteryRuntimePhase.WAITING_TO_RESUME,
                tunnelRunning = false,
                blockedByAnotherPolicy = true,
            ),
        )
    }

    @Test
    fun alarmFailureRestoresACommittedPauseInsteadOfLeavingVpnOff() {
        assertEquals(
            SleepResumeAction.RESTORE_PAUSED_TUNNEL,
            decideSleepResumeAction(
                trigger = SleepResumeTrigger.FAILSAFE,
                runtimePhase = SleepBatteryRuntimePhase.WAITING_TO_RESUME,
                tunnelRunning = false,
                blockedByAnotherPolicy = false,
            ),
        )
    }

    @Test
    fun runtimePhasesHaveStablePersistedValuesAndSafeFallback() {
        SleepBatteryRuntimePhase.entries.forEach { phase ->
            assertEquals(phase, SleepBatteryRuntimePhase.fromStoredValue(phase.storedValue))
        }
        assertEquals(
            SleepBatteryRuntimePhase.IDLE,
            SleepBatteryRuntimePhase.fromStoredValue("unknown"),
        )
    }
}
