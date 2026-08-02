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
}
