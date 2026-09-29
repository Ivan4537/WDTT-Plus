package com.wdtt.plus.ui

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ServerUpdateDiagnosticsTest {
    private fun snapshot(state: ServerUpdateRollbackState) = ServerUpdateDiagnosticSnapshot(
        rollbackState = state,
        serviceExists = true,
        binaryExists = true,
        configDirExists = true,
        accessDbExists = true,
        wgKeysExist = true,
        serviceActive = true,
        inspectionSucceeded = true,
    )

    @Test
    fun `report includes only bounded inspection results`() {
        val report = buildServerUpdateDiagnosticReport(
            snapshot(ServerUpdateRollbackState.PreparedCorrupted("checksum mismatch")),
            generatedAt = "2026-09-30T12:00:00Z",
            appVersion = "20",
        )
        assertTrue(report.contains("Состояние страховочной копии: prepared_corrupted"))
        assertTrue(report.contains("Код проверки копии: checksum_mismatch"))
        assertTrue(report.contains("Служба активна: yes"))
        assertTrue(report.contains("База доступа обнаружена: yes"))
    }

    @Test
    fun `unknown remote diagnostic is never copied into report`() {
        val secret = "secret-host.example token=not-for-export"
        val report = buildServerUpdateDiagnosticReport(
            snapshot(ServerUpdateRollbackState.UnknownState(secret)),
            generatedAt = "2026-09-30T12:00:00Z",
            appVersion = "20",
        )
        assertTrue(report.contains("Код проверки копии: other"))
        assertFalse(report.contains(secret))
        assertFalse(report.contains("secret-host.example"))
    }

    @Test
    fun `unsafe rollback dialog exposes only read only extra actions`() {
        val source = sequenceOf(
            File("app/src/main/java/com/wdtt/plus/ui/DeployTab.kt"),
            File("src/main/java/com/wdtt/plus/ui/DeployTab.kt"),
        ).first(File::isFile).readText()
        assertTrue(source.contains("Повторить проверку"))
        assertTrue(source.contains("Сохранить диагностику"))
        assertTrue(source.contains("startDeployCheck(deployRequest, requireExistingServer = true)"))
    }
}
