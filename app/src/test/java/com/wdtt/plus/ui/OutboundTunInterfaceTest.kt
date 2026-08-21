package com.wdtt.plus.ui

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class OutboundTunInterfaceTest {
    @Test
    fun interfaceNameValidation_acceptsLinuxNameAndRejectsUnsafeOrReservedValues() {
        assertNull(tunInterfaceNameIssue("xray0"))
        assertNull(tunInterfaceNameIssue("sing-box_1"))
        assertTrue(tunInterfaceNameIssue("wdtt0") != null)
        assertTrue(tunInterfaceNameIssue("wg-wdtt-exit") != null)
        assertTrue(tunInterfaceNameIssue("xray0; reboot") != null)
        assertTrue(tunInterfaceNameIssue("-xray0") != null)
        assertTrue(tunInterfaceNameIssue("..") != null)
        assertTrue(tunInterfaceNameIssue("interface-name-is-too-long") != null)
    }

    @Test
    fun interfaceSelection_blocksAKnownStoppedCandidateButAllowsManualNames() {
        val candidates = listOf(
            TunInterfaceCandidate("xray0", false),
            TunInterfaceCandidate("singtun0", true),
        )

        assertTrue(tunInterfaceSelectionIssue("xray0", candidates)?.contains("остановлен") == true)
        assertNull(tunInterfaceSelectionIssue("singtun0", candidates))
        assertNull(tunInterfaceSelectionIssue("manualtun0", candidates))
    }

    @Test
    fun tunStatePolling_runsOnlyWhileItsServerUiIsVisible() {
        assertTrue(
            shouldPollTunOutboundState(
                visible = false,
                expanded = false,
                dialog = OutboundDialog.TunInterface,
                mode = null,
                hasSshAuthentication = true,
            )
        )
        assertTrue(
            shouldPollTunOutboundState(
                visible = true,
                expanded = true,
                dialog = null,
                mode = "tun_interface",
                hasSshAuthentication = true,
            )
        )
        assertFalse(
            shouldPollTunOutboundState(
                visible = true,
                expanded = true,
                dialog = null,
                mode = "direct",
                hasSshAuthentication = true,
            )
        )
        assertFalse(
            shouldPollTunOutboundState(
                visible = true,
                expanded = true,
                dialog = OutboundDialog.TunInterface,
                mode = "tun_interface",
                hasSshAuthentication = false,
            )
        )
    }

    @Test
    fun candidateParser_keepsSafeCandidatesAndShowsUpStateFirst() {
        val parsed = parseTunInterfaceCandidates(
            """
            noise
            WDTT_TUN_CANDIDATE=tun9|0
            WDTT_TUN_CANDIDATE=xray0|1
            WDTT_TUN_CANDIDATE=wdtt0|1
            WDTT_TUN_CANDIDATE=xray0|1
            """.trimIndent()
        )

        assertEquals(
            listOf(
                TunInterfaceCandidate("xray0", true),
                TunInterfaceCandidate("tun9", false)
            ),
            parsed
        )
    }

    @Test
    fun candidateDiscovery_readsKernelTunDevicesWithoutSelectingOne() {
        val script = tunInterfaceCandidatesScript()

        assertTrue("/sys/class/net/*" in script)
        assertTrue("tun_flags" in script)
        assertTrue("WDTT_TUN_CANDIDATE=" in script)
        assertFalse("TUN_INTERFACE_B64" in script)
        assertShellSyntax(script)
    }

    @Test
    fun enableScript_isScopedFailClosedAndChecksRealWdttTraffic() {
        val script = buildTunInterfaceExitScript("xray0")

        assertTrue("wdtt_clear_external_out" in script)
        assertTrue("trap tun_rollback EXIT" in script)
        assertTrue("rollback after TUN setup error" in script)
        assertTrue("TUN_COMMITTED=1" in script)
        assertTrue("trap - EXIT" in script)
        assertTrue("WDTT_TUN_TABLE=110" in script)
        assertTrue("WDTT_TUN_PRIORITY=90" in script)
        assertTrue("WDTT_TUN_EXIT" in script)
        assertTrue("wdtt-tun-exit.service" in script)
        assertTrue("tun-exit-watch" in script)
        assertTrue("STATE_FILE=/run/wdtt-tun-exit.state" in script)
        assertTrue("report_state blocked" in script)
        assertTrue("logger -t wdtt-tun-exit" in script)
        assertTrue("ip route replace unreachable default" in script)
        assertTrue("blocked_status && return 0" in script)
        assertTrue(
            script.indexOf("ip route replace unreachable default table") <
                script.indexOf("ip route replace default dev \"${'$'}TUN_IFACE\"")
        )
        assertFalse("block() {\n          cleanup" in script)
        assertTrue("${'$'}ROUTE_HELPER\" block" in script)
        assertTrue("curl -4fsS --interface \"${'$'}TEST_SOURCE\"" in script)
        assertTrue("wdtt_write_mode \"tun_interface\"" in script)
        assertTrue("tun_interface_is_primary" in script)
        assertTrue("WDTT_TUN_EXIT_V1" in script)
        assertTrue("tun_exit_ownership_conflict" in script)
        assertTrue("/proc/sys/net/ipv4/ip_forward" in script)
        assertTrue("tun_ip_forward_failed" in script)
        assertTrue("rollback after TUN traffic test error" in script)
        assertFalse("ip link delete \"${'$'}TUN_IFACE\"" in script)
        assertFalse("--comment WDTT_MANAGED -j" in script)
        assertShellSyntax(script)
    }

    @Test(expected = IllegalArgumentException::class)
    fun enableScript_rejectsShellMetacharacters() {
        buildTunInterfaceExitScript("xray0;reboot")
    }

    @Test
    fun directAndDeleteScripts_removeOnlyWdttOwnedTunState() {
        val direct = disableOutboundExitScript()
        val delete = deleteTunInterfaceExitScript()

        assertTrue("wdtt_clear_tun_out" in direct)
        assertTrue("WDTT_TUN_TABLE" in direct)
        assertTrue("WDTT_TUN_EXIT" in direct)
        assertTrue("TUN_OWNED" in direct)
        assertTrue("wdtt_require_tun_cleanup_ownership" in direct)
        assertTrue("WDTT_ERROR=tun_exit_not_owned" in direct)
        assertTrue("wdtt-tun-exit.service" in delete)
        assertTrue(
            delete.indexOf("wdtt_require_tun_cleanup_ownership ||") <
                delete.indexOf("Останавливаю управляемый TUN-выход")
        )
        assertTrue("TUN_INTERFACE_B64" in delete)
        assertTrue("/run/wdtt-tun-exit.state" in delete)
        assertTrue("Сам TUN-интерфейс" in delete)
        assertFalse("ip link delete \"${'$'}TUN_IFACE\"" in delete)
        assertFalse("systemctl disable --now xray" in delete)
        assertFalse("systemctl disable --now 3x-ui" in delete)
        assertShellSyntax(direct)
        assertShellSyntax(delete)
    }

    @Test
    fun checkScript_requiresOwnedHelperAndProbesRealWdttTraffic() {
        val script = checkTunInterfaceExitScript("xray0")

        assertTrue("WDTT_TUN_EXIT_V1" in script)
        assertTrue("WDTT_ERROR=tun_exit_not_owned" in script)
        assertTrue("WDTT_ERROR=tun_interface_mismatch" in script)
        assertTrue("tun-exit-route status" in script)
        assertTrue("curl -4fsS --interface \"${'$'}TEST_SOURCE\"" in script)
        assertShellSyntax(script)
    }

    @Test
    fun snapshotStatusAndDiagnostics_reportTunComponents() {
        val snapshot = outboundSnapshotScript()
        val status = outboundStatusScript()
        val diagnostics = serverDiagnosticsScript()

        assertTrue("WDTT_TUN_INTERFACE_B64" in snapshot)
        assertTrue("WDTT_TUN_POLICY_RULE_ACTIVE" in snapshot)
        assertTrue("WDTT_TUN_FORWARD_RULES_ACTIVE" in snapshot)
        assertTrue("WDTT_TUN_IP_FORWARD_ACTIVE" in snapshot)
        assertTrue("WDTT_TUN_FAIL_CLOSED_ACTIVE" in snapshot)
        assertTrue("[ -e \"${'$'}WDTT_TUN_OWNER_FILE\" ]" in snapshot)
        assertTrue("[ -e \"${'$'}WDTT_TUN_CONFIG_FILE\" ]" in snapshot)
        assertTrue("Автозапуск TUN-выхода" in status)
        assertTrue("Пересылка IPv4-пакетов" in status)
        assertTrue("Аварийная блокировка прямого выхода" in status)
        assertTrue("Маршрут по умолчанию через TUN" in status)
        assertTrue("TUN-выход запущен не полностью" in diagnostics)
        assertTrue("table 110" in diagnostics)
        assertShellSyntax(snapshot)
        assertShellSyntax(status)
        assertShellSyntax(diagnostics)
    }

    @Test
    fun tunMode_conflictsWithAnotherRouteAndCanAlwaysBeCleaned() {
        val tunOnly = snapshot(
            mode = "tun_interface",
            tunPresent = true,
            tunInterfaceActive = true,
            tunServiceActive = true,
            tunServiceEnabled = true,
            tunPolicyRuleActive = true,
            tunDefaultRouteActive = true,
            tunForwardRulesActive = true,
            tunIpForwardActive = true,
            tunFailClosedActive = false
        )
        assertEquals(
            OutboundModeIndicator(OutboundModeVisualState.Active, "активен"),
            outboundModeIndicator(tunOnly, OutboundDialog.TunInterface)
        )
        assertTrue(canDisableOutboundDialog(tunOnly, OutboundDialog.TunInterface))
        assertTrue(canReturnDirect(tunOnly))

        assertEquals(
            OutboundModeVisualState.Error,
            outboundModeIndicator(
                tunOnly.copy(tunIpForwardActive = false),
                OutboundDialog.TunInterface
            ).state
        )

        val blocked = tunOnly.copy(
            tunInterfaceActive = false,
            tunDefaultRouteActive = false,
            tunForwardRulesActive = false,
            tunFailClosedActive = true
        )
        assertEquals(
            OutboundModeVisualState.Error,
            outboundModeIndicator(blocked, OutboundDialog.TunInterface).state
        )

        val conflict = tunOnly.copy(
            externalProxyRouteActive = true,
            externalProxyServiceActive = true
        )
        assertTrue(conflict.hasRouteConflict)
        assertEquals(
            OutboundModeVisualState.Error,
            outboundModeIndicator(conflict, OutboundDialog.TunInterface).state
        )
        assertEquals(
            OutboundModeVisualState.Error,
            outboundModeIndicator(conflict, OutboundDialog.ExternalProxy).state
        )
    }

    private fun snapshot(
        mode: String,
        tunPresent: Boolean,
        tunInterfaceActive: Boolean,
        tunServiceActive: Boolean,
        tunServiceEnabled: Boolean,
        tunPolicyRuleActive: Boolean,
        tunDefaultRouteActive: Boolean,
        tunForwardRulesActive: Boolean,
        tunIpForwardActive: Boolean,
        tunFailClosedActive: Boolean
    ) = OutboundServerSnapshot(
        mode = mode,
        detail = "xray0",
        updatedAt = "",
        hasProfile = true,
        localProxyPresent = false,
        localProxyActive = false,
        localProxyPort = "",
        localProxyLogin = "",
        localProxyPassword = "",
        externalProxyPresent = false,
        externalProxyActive = false,
        externalProxyKindName = "",
        externalProxyHost = "",
        externalProxyPort = "",
        externalProxyLogin = "",
        externalProxyPassword = "",
        wireGuardPresent = false,
        wireGuardActive = false,
        wireGuardExitHost = "",
        wireGuardExitSshPort = "",
        wireGuardExitUser = "",
        wireGuardExitPassword = "",
        wireGuardExitPort = "",
        wireGuardExitDns = "",
        warpPresent = false,
        warpMtu = "",
        importedWireGuardConfig = "",
        tunInterface = "xray0",
        tunPresent = tunPresent,
        tunInterfaceActive = tunInterfaceActive,
        tunServiceActive = tunServiceActive,
        tunServiceEnabled = tunServiceEnabled,
        tunPolicyRuleActive = tunPolicyRuleActive,
        tunDefaultRouteActive = tunDefaultRouteActive,
        tunForwardRulesActive = tunForwardRulesActive,
        tunIpForwardActive = tunIpForwardActive,
        tunFailClosedActive = tunFailClosedActive
    )

    private fun assertShellSyntax(script: String) {
        val file = File.createTempFile("wdtt-tun-exit-", ".sh")
        try {
            file.writeText(script)
            listOf("sh", "bash").forEach { shell ->
                val process = ProcessBuilder(shell, "-n", file.absolutePath)
                    .redirectErrorStream(true)
                    .start()
                val output = process.inputStream.bufferedReader().readText()
                val code = process.waitFor()
                assertTrue("$shell -n завершился с кодом $code: $output", code == 0)
            }
        } finally {
            file.delete()
        }
    }
}
