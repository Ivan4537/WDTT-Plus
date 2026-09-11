package com.wdtt.plus

import android.app.ApplicationExitInfo
import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceCompatibilityTest {
    @Test
    fun activeHoldModeReportsExactRuntimeState() {
        val item = connectionHoldRuntimeItem(
            running = true,
            diagnostics = ConnectionHoldDiagnostics(
                modeSelected = true,
                active = true,
                cpuWakeLockHeld = true,
                wifiLockHeld = true,
                wifiTransportAvailable = true,
                deviceInteractive = false,
            ),
        )

        assertEquals(DeviceCheckSeverity.Ok, item.severity)
        assertEquals("действует", item.status)
        assertTrue(item.details.contains("CPU wake lock — активен"))
        assertTrue(item.details.contains("Wi-Fi lock — активен"))
    }

    @Test
    fun runningHoldModeWarnsWhenCpuHoldIsMissing() {
        val item = connectionHoldRuntimeItem(
            running = true,
            diagnostics = ConnectionHoldDiagnostics(modeSelected = true),
        )

        assertEquals(DeviceCheckSeverity.Warning, item.severity)
        assertEquals("не действует", item.status)
    }

    @Test
    fun processExitHistoryKeepsSystemKillVisibleAfterPackageUpdate() {
        val now = 1_800_000_000_000L
        val systemKill = ProcessExitRecord(
            timestampMs = now - 2_000L,
            reason = ApplicationExitInfo.REASON_OTHER,
            description = "o-kill(6) private-value-must-not-leak",
        )
        val packageUpdate = ProcessExitRecord(
            timestampMs = now - 1_000L,
            reason = ApplicationExitInfo.REASON_PACKAGE_UPDATED,
        )

        val history = processExitHistory(listOf(systemKill, packageUpdate), now)
        val item = processExitHistoryItem(
            history = history,
            manufacturer = "OnePlus",
            backgroundRestricted = false,
            batteryOptimizationsIgnored = true,
        )

        assertEquals(packageUpdate, history.latest)
        assertEquals(systemKill, history.latestUnexpected)
        assertEquals(DeviceCheckSeverity.Warning, item.severity)
        assertTrue(item.details.contains("o-kill(6)"))
        assertTrue(item.details.contains("более новое штатное событие"))
        assertTrue(!item.details.contains("private-value-must-not-leak"))
        assertTrue(item.recommendation.contains("OxygenOS"))
    }

    @Test
    fun userRequestedExitIsNotReportedAsSystemKill() {
        val now = 1_800_000_000_000L
        val history = processExitHistory(
            records = listOf(
                ProcessExitRecord(
                    timestampMs = now - 1_000L,
                    reason = ApplicationExitInfo.REASON_USER_REQUESTED,
                )
            ),
            nowMs = now,
        )

        val item = processExitHistoryItem(
            history = history,
            manufacturer = "Samsung",
            backgroundRestricted = false,
            batteryOptimizationsIgnored = true,
        )

        assertEquals(null, history.latestUnexpected)
        assertEquals(DeviceCheckSeverity.Info, item.severity)
        assertTrue(item.status.contains("пользователем"))
    }

    @Test
    fun backgroundRestrictionRecommendationExplainsBothAndroidAndVendorSetting() {
        val recommendation = backgroundRestrictionRecommendation(
            manufacturer = "Xiaomi",
            backgroundRestricted = true,
            batteryOptimizationsIgnored = true,
        )

        assertTrue(recommendation.contains("ограниченное в фоне"))
        assertTrue(recommendation.contains("Без ограничений"))
        assertTrue(recommendation.contains("автозапуск"))
    }

    @Test
    fun sixteenKibPagesAreSupportedByThe64BitRelease() {
        val item = pageSizeCompatibilityItem(16L * 1024L, processIs64Bit = true)

        assertEquals(DeviceCheckSeverity.Ok, item.severity)
        assertTrue(item.status.contains("поддерживается"))
    }

    @Test
    fun nonStandardPageSizeStillWarnsWhenItIsNotThe64BitPath() {
        val item = pageSizeCompatibilityItem(16L * 1024L, processIs64Bit = false)

        assertEquals(DeviceCheckSeverity.Warning, item.severity)
    }

    @Test
    fun masqueEnrollmentInspectorRejectsIncompleteFiles() {
        val directory = Files.createTempDirectory("wdtt-masque-check-").toFile()
        val config = directory.resolve(RT_MASQUE_CONFIG_FILE_NAME)
        try {
            config.writeText("{\"version\":1,\"private_key\":\"secret\"}")

            assertEquals(RtMasqueEnrollmentState.Invalid, inspectRtMasqueEnrollment(config))
        } finally {
            config.delete()
            directory.delete()
        }
    }

    @Test
    fun masqueEnrollmentInspectorAcceptsTheVersionOneShape() {
        val directory = Files.createTempDirectory("wdtt-masque-check-").toFile()
        val config = directory.resolve(RT_MASQUE_CONFIG_FILE_NAME)
        try {
            config.writeText(
                """{"version":1,"private_key":"private","endpoint_v4":"192.0.2.1","endpoint_pub_key":"public","ipv4":"172.16.0.2"}"""
            )

            assertEquals(RtMasqueEnrollmentState.Ready, inspectRtMasqueEnrollment(config))
        } finally {
            config.delete()
            directory.delete()
        }
    }

    @Test
    fun activeWorkersDoNotHideConfirmedTrafficFailure() {
        val item = tunnelHealthItem(
            running = true,
            activeWorkers = 36,
            issue = null,
            confirmedNetworkFailure = true,
        )

        assertEquals(DeviceCheckSeverity.Warning, item.severity)
        assertTrue(item.status.contains("нет ответа"))
    }

    @Test
    fun recoveryIssueDoesNotLookHealthyWhileWorkersRemainActive() {
        val item = tunnelHealthItem(
            running = true,
            activeWorkers = 36,
            issue = ConnectionIssue("Перезапускаю VPN", "Ожидается восстановление"),
            confirmedNetworkFailure = false,
        )

        assertEquals(DeviceCheckSeverity.Warning, item.severity)
        assertEquals("обнаружена проблема", item.status)
    }

    @Test
    fun activeWorkersWithoutFailureRemainHealthy() {
        val item = tunnelHealthItem(
            running = true,
            activeWorkers = 9,
            issue = null,
            confirmedNetworkFailure = false,
        )

        assertEquals(DeviceCheckSeverity.Ok, item.severity)
        assertEquals("активно", item.status)
    }

    @Test
    fun vpnSlotTransferIsSeparatedFromWholeProcessTermination() {
        val item = lastTunnelStopItem(
            running = false,
            reason = TunnelStopReason.VpnSlotTransferred,
        )

        requireNotNull(item)
        assertEquals(DeviceCheckSeverity.Info, item.severity)
        assertTrue(item.details.contains("VPN-слот"))
        assertTrue(item.details.contains("не означает"))
        assertEquals(DeviceCheckAction.VpnSettings, item.action)
    }

    @Test
    fun socksHealthReportDescribesLocalProxyInsteadOfVpnInterface() {
        val item = tunnelHealthItem(
            running = true,
            activeWorkers = 9,
            issue = null,
            confirmedNetworkFailure = false,
            tunnelMode = TUNNEL_MODE_SOCKS5,
        )

        assertEquals(DeviceCheckSeverity.Ok, item.severity)
        assertTrue(item.details.contains("Прокси SOCKS5"))
        assertTrue(!item.details.contains("VPN"))
    }

    @Test
    fun timedSleepResumeWarnsWhenAndroidBatteryRestrictionsRemain() {
        val item = sleepBatteryModeItem(
            enabled = true,
            mode = SleepBatteryMode.TIMED_PAUSE,
            pauseDelayMinutes = 5,
            resumeDelayMinutes = 60,
            runtime = SleepBatteryRuntimeState(SleepBatteryRuntimePhase.WAITING_TO_RESUME, 123L),
            notificationsGranted = true,
            batteryOptimizationsIgnored = false,
        )

        assertEquals(DeviceCheckSeverity.Warning, item.severity)
        assertEquals(DeviceCheckAction.BatterySettings, item.action)
        assertTrue(item.status.contains("1 ч"))
        assertTrue(item.details.contains("ожидается таймер"))
    }

    @Test
    fun zeroTimedSleepModeExplainsThatVpnStaysActive() {
        val item = sleepBatteryModeItem(
            enabled = true,
            mode = SleepBatteryMode.TIMED_PAUSE,
            pauseDelayMinutes = 5,
            resumeDelayMinutes = 0,
            runtime = SleepBatteryRuntimeState(),
            notificationsGranted = true,
            batteryOptimizationsIgnored = false,
        )

        assertEquals(DeviceCheckSeverity.Ok, item.severity)
        assertTrue(item.status.contains("VPN остаётся активным"))
    }

    @Test
    fun holdConnectionModeWarnsWhenAndroidStillRestrictsBattery() {
        val item = sleepBatteryModeItem(
            enabled = false,
            screenOffMode = ScreenOffMode.HOLD_CONNECTION,
            mode = SleepBatteryMode.DELAYED_PAUSE,
            pauseDelayMinutes = 5,
            resumeDelayMinutes = 5,
            runtime = SleepBatteryRuntimeState(),
            notificationsGranted = true,
            batteryOptimizationsIgnored = false,
        )

        assertEquals(DeviceCheckSeverity.Warning, item.severity)
        assertEquals(DeviceCheckAction.BatterySettings, item.action)
        assertTrue(item.details.contains("сохранять активное соединение"))
        assertTrue(item.details.contains("Wi-Fi"))
    }

    @Test
    fun holdConnectionModeWarnsWhenBackgroundIsRestrictedDespiteBatteryExemption() {
        val item = sleepBatteryModeItem(
            enabled = false,
            screenOffMode = ScreenOffMode.HOLD_CONNECTION,
            mode = SleepBatteryMode.DELAYED_PAUSE,
            pauseDelayMinutes = 5,
            resumeDelayMinutes = 5,
            runtime = SleepBatteryRuntimeState(),
            notificationsGranted = true,
            batteryOptimizationsIgnored = true,
            backgroundRestricted = true,
        )

        assertEquals(DeviceCheckSeverity.Warning, item.severity)
        assertEquals(DeviceCheckAction.BatterySettings, item.action)
        assertTrue(item.recommendation.contains("ограничен в фоне"))
    }

    @Test
    fun trustedWifiWarnsWhenEnabledWithoutSavedNetworks() {
        val item = trustedWifiModeItem(
            enabled = true,
            savedNetworkCount = 0,
            waiting = false,
            waitingSsid = "",
            accessProblem = null,
        )

        assertEquals(DeviceCheckSeverity.Warning, item.severity)
        assertTrue(item.status.contains("сети не сохранены"))
    }

    @Test
    fun trustedWifiWaitingIsReportedAsIntentionalVpnPause() {
        val item = trustedWifiModeItem(
            enabled = true,
            savedNetworkCount = 2,
            waiting = true,
            waitingSsid = "Home",
            accessProblem = null,
        )

        assertEquals(DeviceCheckSeverity.Ok, item.severity)
        assertTrue(item.details.contains("намеренно выключен"))
        assertTrue(item.details.contains("Home"))
    }

    @Test
    fun emptyWhitelistWarnsThatItBlocksApplicationTraffic() {
        val item = vpnRoutingModeItem(
            snapshot = VpnRoutingSettingsSnapshot(
                profileIndex = 1,
                isWhitelist = true,
                appPackages = "",
                addressRules = emptyList(),
            ),
            installedPackages = setOf("com.wdtt.plus"),
            ownPackageName = "com.wdtt.plus",
        )

        assertEquals(DeviceCheckSeverity.Warning, item.severity)
        assertTrue(item.details.contains("не пропускает"))
    }

    @Test
    fun addressOnlyWhitelistIsRecognizedAsValid() {
        val item = vpnRoutingModeItem(
            snapshot = VpnRoutingSettingsSnapshot(
                profileIndex = 0,
                isWhitelist = true,
                appPackages = "",
                addressRules = listOf(VpnAddressRule(VpnAddressType.DOMAIN, "example.org")),
            ),
            installedPackages = setOf("com.wdtt.plus"),
            ownPackageName = "com.wdtt.plus",
        )

        assertEquals(DeviceCheckSeverity.Ok, item.severity)
        assertTrue(item.details.contains("ко всем приложениям"))
        assertTrue(item.status.contains("доменов: 1"))
    }
}
