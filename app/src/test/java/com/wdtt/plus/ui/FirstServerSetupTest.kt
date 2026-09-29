package com.wdtt.plus.ui

import org.junit.Assert.*
import org.junit.Test
import com.wdtt.plus.shouldPrepareInitialServerTunnel

class FirstServerSetupTest {
    private val valid = ServerSetupDraft(host = "203.0.113.42", sshPassword = "vps-secret", mainPassword = "wdtt-secret")

    @Test fun `fresh classification requires absence of every installation trace`() {
        assertEquals(ServerSetupKind.FRESH, classifyFirstServerSetup(false, DeploymentOwnership.UnknownExisting, false))
        assertEquals(ServerSetupKind.FRESH, classifyFirstServerSetup(false, DeploymentOwnership.NoInstall, false))
        assertNull(classifyFirstServerSetup(true, DeploymentOwnership.UnknownExisting, false))
        assertNull(classifyFirstServerSetup(false, DeploymentOwnership.AndroidDeploy, false))
    }
    @Test fun `known installations and backups select separate safe routes`() {
        val cases = mapOf(
            DeploymentOwnership.AndroidDeploy to ServerSetupKind.EXISTING,
            DeploymentOwnership.LegacyAndroidDeploy to ServerSetupKind.EXISTING,
            DeploymentOwnership.PreservedAndroidData to ServerSetupKind.PRESERVED,
            DeploymentOwnership.IncompleteAndroidDeploy to ServerSetupKind.INCOMPLETE,
            DeploymentOwnership.StandaloneInstaller to ServerSetupKind.STANDALONE,
        )
        cases.forEach { (owner, expected) -> assertEquals(expected, classifyFirstServerSetup(true, owner, false)) }
        assertEquals(ServerSetupKind.RECOVERY, classifyFirstServerSetup(false, DeploymentOwnership.UnknownExisting, true))
        assertEquals(ServerSetupKind.STANDALONE, classifyFirstServerSetup(true, DeploymentOwnership.StandaloneInstaller, true))
    }
    @Test fun `password generation is compatible and does not repeat a fixed default`() {
        val values = (1..100).map { generateServerAdminPassword() }
        assertTrue(values.all { it.matches(Regex("[a-zA-Z0-9]{24}")) })
        assertEquals(values.size, values.toSet().size)
        assertTrue(valid.copy(mainPassword = values.first()).settingsIssue() == null)
    }
    @Test fun `missing and malformed SSH settings block probing`() {
        assertNull(valid.accessIssue())
        assertNotNull(valid.copy(host = "").accessIssue())
        assertNotNull(valid.copy(sshPassword = "").accessIssue())
        assertNotNull(valid.copy(sshPort = "65536").accessIssue())
        assertNotNull(valid.copy(authMode = "key", privateKey = "").accessIssue())
    }
    @Test fun `custom ports DNS and optional bot are checked before confirmation`() {
        assertNull(valid.settingsIssue())
        assertNotNull(valid.copy(mainPassword = "").settingsIssue())
        assertNotNull(valid.copy(mainPassword = "contains space").settingsIssue())
        assertNotNull(valid.copy(dtlsPort = "0").settingsIssue())
        assertNotNull(valid.copy(dtlsPort = "56001").settingsIssue())
        assertNotNull(valid.copy(localPort = "65536").settingsIssue())
        assertNotNull(valid.copy(dns1 = "1.1.1.1;echo").settingsIssue())
        assertNotNull(valid.copy(adminId = "123").settingsIssue())
        assertNotNull(valid.copy(adminId = "bad", botToken = "token").settingsIssue())
        assertNull(valid.copy(dns1 = "9.9.9.9", dns2 = "", dtlsPort = "60000", wgPort = "60001", localPort = "9100").settingsIssue())
    }
    @Test fun `request uses the confirmed settings and keeps VPS and WDTT passwords separate`() {
        val request = valid.copy(user = "operator", sshPort = "2222", dtlsPort = "60000", wgPort = "60001", localPort = "9100", dns1 = "9.9.9.9", dns2 = "", adminId = "123", botToken = "token").request()
        assertEquals("vps-secret", request.pass)
        assertEquals("wdtt-secret", request.mainPass)
        assertEquals("operator", request.user)
        assertEquals(2222, request.sshPort)
        assertEquals(60000, request.dtlsPort)
        assertEquals(60001, request.wgPort)
        assertEquals(9100, request.localPort)
        assertEquals("9.9.9.9", request.dns1)
        assertEquals("", request.dns2)
        assertEquals("123", request.adminId)
        assertEquals("token", request.botToken)
        val localOnly = valid.copy(localPort = "9100").request()
        assertEquals(56000, localOnly.dtlsPort)
        assertEquals(56001, localOnly.wgPort)
        assertEquals(9100, localOnly.localPort)
    }
    @Test fun `moving between wizard steps requires the exact VPS access that was checked`() {
        val checked = valid.copy(authMode = "password", sshPort = "22")
        assertTrue(checked.copy(mainPassword = "changed", dns1 = "9.9.9.9").sameServerAccess(checked))
        assertFalse(checked.copy(host = "203.0.113.43").sameServerAccess(checked))
        assertFalse(checked.copy(sshPassword = "other-password").sameServerAccess(checked))
        assertFalse(checked.copy(sshPort = "2222").sameServerAccess(checked))
        assertFalse(checked.copy(authMode = "key", privateKey = "key").sameServerAccess(checked))
    }
    @Test fun `filled existing profile can update without an old wizard completion marker`() {
        assertTrue(offersServerUpdate(false, true, "wdtt-secret"))
        assertTrue(offersServerUpdate(true, false, ""))
        assertFalse(offersServerUpdate(false, false, "wdtt-secret"))
        assertFalse(offersServerUpdate(false, true, " "))
    }
    @Test fun `first install prepares only a tunnel without any existing server credentials or remote binding`() {
        assertTrue(shouldPrepareInitialServerTunnel("", "", "", false, ""))
        assertTrue(shouldPrepareInitialServerTunnel(" ", " ", " ", false, ""))
        assertFalse(shouldPrepareInitialServerTunnel("old.example.org", "", "", false, ""))
        assertFalse(shouldPrepareInitialServerTunnel("", "old-password", "", false, ""))
        assertFalse(shouldPrepareInitialServerTunnel("", "", "wdtt://old-profile", false, ""))
        assertFalse(shouldPrepareInitialServerTunnel("", "", "", true, ""))
        assertFalse(shouldPrepareInitialServerTunnel("", "", "", false, "opaque-binding"))
    }
    @Test fun `first install can open tunnel only while its original navigation is unchanged`() {
        assertTrue(canOpenInitialServerTunnel(2, 10, 2, 10, true, false))
        assertFalse(canOpenInitialServerTunnel(2, 10, 2, 11, false, false))
        // Returning to Deploy cannot revive a transition cancelled by earlier navigation.
        assertFalse(canOpenInitialServerTunnel(2, 10, 2, 12, true, false))
        assertFalse(canOpenInitialServerTunnel(2, 10, 1, 10, true, false))
    }
    @Test fun `opening another window permanently cancels only the automatic navigation`() {
        assertFalse(canOpenInitialServerTunnel(2, 10, 2, 10, true, true))
        assertFalse(canOpenInitialServerTunnel(2, 10, 2, 10, false, false))
        assertFalse(canOpenInitialServerTunnel(null, null, 2, 10, true, false))
    }
    private fun completeProbe(): String = listOf("SERVICE", "BINARY", "CONFIG_DIR", "ACCESS_DB", "WG_KEYS", "WDTT_STANDALONE_MANAGED", "WDTT_ANDROID_DEPLOY_MANAGED", "WDTT_LEGACY_ANDROID_DEPLOY_CANDIDATE", "WDTT_ANDROID_DATA_PRESERVED", "WDTT_INCOMPLETE_ANDROID_DEPLOY_CANDIDATE").joinToString("\n") { "$it=0" } + "\nACTIVE=unknown\nWDTT_UPDATE_BACKUP_STATUS=none\n"
    @Test fun `truncated failed duplicated or malformed probe cannot imply a clean VPS`() {
        validateExistingInstallProbe(completeProbe())
        for (bad in listOf("", "Permission denied", completeProbe().replace("SERVICE=0\n", ""), completeProbe().replace("BINARY=0", "BINARY=2"), completeProbe() + "SERVICE=1\n", completeProbe().replace("WDTT_UPDATE_BACKUP_STATUS=none\n", ""))) {
            assertTrue(runCatching { validateExistingInstallProbe(bad) }.isFailure)
        }
    }
}
