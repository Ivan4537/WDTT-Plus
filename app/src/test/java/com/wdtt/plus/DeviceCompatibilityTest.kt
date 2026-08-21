package com.wdtt.plus

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceCompatibilityTest {
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
