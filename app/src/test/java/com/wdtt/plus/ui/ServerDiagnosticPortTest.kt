package com.wdtt.plus.ui

import com.wdtt.plus.DeviceCheckSeverity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ServerDiagnosticPortTest {
    private fun probe(socket: String, port: Int, ssStatus: Int = 0): Int {
        val function = serverDiagnosticsScript().substringAfter("wdtt_diag_udp_listen_port() {")
            .substringBefore("wdtt_diag_tcp_listen_port() {")
        val process = ProcessBuilder("sh", "-c", """
            wdtt_diag_cmd() { return 0; }
            ss() { printf '%s\n' "${'$'}FAKE_SOCKETS"; return $ssStatus; }
            wdtt_diag_udp_listen_port() {$function
            wdtt_diag_udp_listen_port $port
        """.trimIndent()).apply { environment()["FAKE_SOCKETS"] = socket }.start()
        return process.waitFor()
    }

    @Test
    fun matchesOnlyExactLocalPortForIpv4AndIpv6() {
        assertEquals(0, probe("UNCONN 0 0 0.0.0.0:56000 0.0.0.0:*", 56000))
        assertEquals(0, probe("UNCONN 0 0 [::]:56000 [::]:*", 56000))
        assertEquals(1, probe("UNCONN 0 0 0.0.0.0:56000 0.0.0.0:*", 5600))
        assertEquals(1, probe("UNCONN 0 0 0.0.0.0:12345 1.2.3.4:56000", 56000))
    }

    @Test
    fun failedInspectionIsNotReportedAsMissingPort() {
        assertEquals(2, probe("", 56000, ssStatus = 1))
    }

    @Test
    fun incompleteSshResponseIsNotReportedAsServerCommandFailure() {
        val incomplete = "WDTT_SERVER_DIAG|OK|ОС|найдена|Linux|\nerror: SSH channel closed before exit status"
        val issue = serverDiagnosticsOutputIssue(incomplete)

        assertTrue(issue?.contains("SSH-канал закрылся") == true)
        assertTrue(serverDiagnosticsSshInterrupted(incomplete))
        assertFalse(issue.orEmpty().contains("root", ignoreCase = true))
        assertTrue(serverDiagnosticsSshInterrupted("error: remote command exited with code -1"))
        assertTrue(serverDiagnosticsSshInterrupted("error: timeout"))
    }

    @Test
    fun completeResponseHasExplicitEndMarkerAndNoTransportError() {
        val script = serverDiagnosticsScript()
        assertTrue(script.contains("WDTT_SERVER_DIAG_COMPLETE=1"))
        val complete = "WDTT_SERVER_DIAG|OK|ОС|найдена|Linux|\nWDTT_SERVER_DIAG_COMPLETE=1"
        assertNull(serverDiagnosticsOutputIssue(complete))
        assertFalse(serverDiagnosticsSshInterrupted(complete))
        assertFalse(serverDiagnosticsSshInterrupted("error: remote command exited with code 1"))
    }

    @Test
    fun shortDirectResponseIsIncompleteButRelayResponseIsExplicitlyReduced() {
        val partial = "WDTT_SERVER_DIAG|OK|ОС|найдена|Linux|"
        assertEquals(DeviceCheckSeverity.Warning, serverDiagnosticsCompletionItem(partial, true)?.severity)
        assertEquals("сокращённая проверка", serverDiagnosticsCompletionItem(partial, false)?.status)
        assertNull(serverDiagnosticsCompletionItem("$partial\nWDTT_SERVER_DIAG_COMPLETE=1", true))
        assertEquals(DeviceCheckSeverity.Warning, serverDiagnosticsCompletionItem("$partial\nerror: timeout", false)?.severity)
    }

    @Test
    fun coreServerChecksAreCollectedBeforeOptionalExternalSites() {
        val script = serverDiagnosticsScript()
        assertTrue(script.indexOf("\"WDTT сервер\"") < script.indexOf("PUBLIC_IP="))
        assertTrue(script.contains("timeout 3 getent ahostsv4"))
    }
}
