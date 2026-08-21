package com.wdtt.plus.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OutboundProfileComparisonTest {
    @Test
    fun unusedGeneratedDefaults_doNotLookLikeServerChanges() {
        val server = snapshot(
            localProxyPort = "1080",
            localProxyLogin = "old-generated-login",
            localProxyPassword = "old-generated-password",
            externalProxyKindName = "",
            externalProxyPort = "",
            wireGuardExitSshPort = "",
            wireGuardExitUser = "",
            wireGuardExitPort = "",
            wireGuardExitDns = ""
        )
        val local = forms(
            localProxyLogin = "new-generated-login",
            localProxyPassword = "new-generated-password"
        )

        assertFalse(outboundProfilesDiffer(server, local))
    }

    @Test
    fun configuredValues_areComparedAfterStorageNormalization() {
        val server = snapshot(
            mode = "wireguard_vps",
            wireGuardPresent = true,
            wireGuardExitHost = "exit.example.org",
            wireGuardExitSshPort = "22",
            wireGuardExitUser = "root",
            wireGuardExitPassword = "secret",
            wireGuardExitPort = "51820",
            wireGuardExitDns = "1.1.1.1,8.8.8.8"
        )
        val local = forms(
            wireGuardExitHost = " exit.example.org ",
            wireGuardExitSshPort = "port 22",
            wireGuardExitUser = "root",
            wireGuardExitPassword = "secret",
            wireGuardExitPort = "51820 ",
            wireGuardExitDns = "9.9.9.9"
        )

        // DNS WireGuard-выхода намеренно не сравнивается: DNS клиентов задаётся
        // в основных настройках WDTT и не применяется этим режимом.
        assertFalse(outboundProfilesDiffer(server, local))
    }

    @Test
    fun configuredProxyChange_isReported() {
        val server = snapshot(
            externalProxyPresent = true,
            externalProxyKindName = "Socks5",
            externalProxyHost = "old.example.org",
            externalProxyPort = "1080"
        )
        val local = forms(externalProxyHost = "new.example.org")

        assertTrue(outboundProfilesDiffer(server, local))
    }

    @Test
    fun configuredTunInterfaceChange_isReported() {
        val server = snapshot(mode = "tun_interface", tunInterface = "xray0")
        val local = forms(tunInterface = "singtun0")

        assertTrue(outboundProfilesDiffer(server, local))
    }

    @Test
    fun orphanedWarpInterface_isAttributedOnlyToWarpAndCanBeDisabledThere() {
        val server = snapshot(
            mode = "direct",
            wireGuardPresent = true,
            wireGuardActive = true,
            warpPresent = true
        )

        assertEquals(
            OutboundModeIndicator(OutboundModeVisualState.Error, "не отключён"),
            outboundModeIndicator(server, OutboundDialog.FreeWarp)
        )
        assertEquals(
            OutboundModeVisualState.Off,
            outboundModeIndicator(server, OutboundDialog.WireGuardVps).state
        )
        assertEquals(
            OutboundModeVisualState.Off,
            outboundModeIndicator(server, OutboundDialog.ImportedWireGuard).state
        )
        assertTrue(canDisableOutboundDialog(server, OutboundDialog.FreeWarp))
        assertFalse(canDisableOutboundDialog(server, OutboundDialog.WireGuardVps))
        assertFalse(canDisableOutboundDialog(server, OutboundDialog.ImportedWireGuard))
        assertTrue(canReturnDirect(server))
    }

    @Test
    fun ownerMarker_winsOverUnrelatedWarpRegistration() {
        val server = snapshot(
            mode = "direct",
            wireGuardPresent = true,
            wireGuardActive = true,
            warpPresent = true,
            wireGuardOwnerMode = "imported_wg"
        )

        assertEquals(
            OutboundModeVisualState.Error,
            outboundModeIndicator(server, OutboundDialog.ImportedWireGuard).state
        )
        assertEquals(
            OutboundModeVisualState.Warning,
            outboundModeIndicator(server, OutboundDialog.FreeWarp).state
        )
        assertTrue(canDisableOutboundDialog(server, OutboundDialog.ImportedWireGuard))
        assertFalse(canDisableOutboundDialog(server, OutboundDialog.FreeWarp))
    }

    @Test
    fun partialExternalProxy_isNotReportedAsActiveAndCanBeCleaned() {
        val server = snapshot(
            mode = "external_proxy",
            externalProxyPresent = true,
            externalProxyServiceActive = true,
            externalProxyRouteActive = false
        )

        assertEquals(
            OutboundModeIndicator(OutboundModeVisualState.Error, "запущен частично"),
            outboundModeIndicator(server, OutboundDialog.ExternalProxy)
        )
        assertTrue(canDisableOutboundDialog(server, OutboundDialog.ExternalProxy))
        assertTrue(canReturnDirect(server))
    }

    @Test
    fun recordedInactiveWireGuardMode_canStillBeDisabledFromItsDialog() {
        val server = snapshot(
            mode = "imported_wg",
            wireGuardPresent = true,
            wireGuardActive = false
        )

        assertTrue(canDisableOutboundDialog(server, OutboundDialog.ImportedWireGuard))
        assertTrue(canReturnDirect(server))
    }

    @Test
    fun proxyCredentials_rejectAmbiguousValuesAndEscapeConfig() {
        assertEquals(
            "Логин внешнего прокси не должен содержать двоеточие.",
            externalProxyCredentialsIssue("user:name", "password")
        )
        assertTrue(localProxyCredentialsIssue("user", "short") != null)
        assertEquals("""a\\b\"c""", escapeRedsocksQuotedValue("""a\b"c"""))
    }

    private fun forms(
        localProxyPort: String = "1080",
        localProxyLogin: String = "generated-login",
        localProxyPassword: String = "generated-password",
        externalProxyKindName: String = "Socks5",
        externalProxyHost: String = "",
        externalProxyPort: String = "1080",
        externalProxyLogin: String = "",
        externalProxyPassword: String = "",
        wireGuardExitHost: String = "",
        wireGuardExitSshPort: String = "22",
        wireGuardExitUser: String = "root",
        wireGuardExitPassword: String = "",
        wireGuardExitPort: String = "51820",
        wireGuardExitDns: String = "1.1.1.1,8.8.8.8",
        importedWireGuardConfig: String = "",
        tunInterface: String = ""
    ) = OutboundProfileForms(
        localProxyPort = localProxyPort,
        localProxyLogin = localProxyLogin,
        localProxyPassword = localProxyPassword,
        externalProxyKindName = externalProxyKindName,
        externalProxyHost = externalProxyHost,
        externalProxyPort = externalProxyPort,
        externalProxyLogin = externalProxyLogin,
        externalProxyPassword = externalProxyPassword,
        wireGuardExitHost = wireGuardExitHost,
        wireGuardExitSshPort = wireGuardExitSshPort,
        wireGuardExitUser = wireGuardExitUser,
        wireGuardExitPassword = wireGuardExitPassword,
        wireGuardExitPort = wireGuardExitPort,
        wireGuardExitDns = wireGuardExitDns,
        importedWireGuardConfig = importedWireGuardConfig,
        tunInterface = tunInterface
    )

    private fun snapshot(
        mode: String = "direct",
        localProxyPresent: Boolean = false,
        localProxyPort: String = "",
        localProxyLogin: String = "",
        localProxyPassword: String = "",
        externalProxyPresent: Boolean = false,
        externalProxyKindName: String = "",
        externalProxyHost: String = "",
        externalProxyPort: String = "",
        externalProxyLogin: String = "",
        externalProxyPassword: String = "",
        wireGuardPresent: Boolean = false,
        wireGuardActive: Boolean = false,
        wireGuardExitHost: String = "",
        wireGuardExitSshPort: String = "",
        wireGuardExitUser: String = "",
        wireGuardExitPassword: String = "",
        wireGuardExitPort: String = "",
        wireGuardExitDns: String = "",
        importedWireGuardConfig: String = "",
        warpPresent: Boolean = false,
        externalProxyServiceActive: Boolean = false,
        externalProxyRouteActive: Boolean = false,
        wireGuardOwnerMode: String = "",
        tunInterface: String = ""
    ) = OutboundServerSnapshot(
        mode = mode,
        detail = "",
        updatedAt = "",
        hasProfile = true,
        localProxyPresent = localProxyPresent,
        localProxyActive = false,
        localProxyPort = localProxyPort,
        localProxyLogin = localProxyLogin,
        localProxyPassword = localProxyPassword,
        externalProxyPresent = externalProxyPresent,
        externalProxyActive = false,
        externalProxyKindName = externalProxyKindName,
        externalProxyHost = externalProxyHost,
        externalProxyPort = externalProxyPort,
        externalProxyLogin = externalProxyLogin,
        externalProxyPassword = externalProxyPassword,
        wireGuardPresent = wireGuardPresent,
        wireGuardActive = wireGuardActive,
        wireGuardExitHost = wireGuardExitHost,
        wireGuardExitSshPort = wireGuardExitSshPort,
        wireGuardExitUser = wireGuardExitUser,
        wireGuardExitPassword = wireGuardExitPassword,
        wireGuardExitPort = wireGuardExitPort,
        wireGuardExitDns = wireGuardExitDns,
        warpPresent = warpPresent,
        warpMtu = "",
        importedWireGuardConfig = importedWireGuardConfig,
        checkedAtMillis = 0L,
        externalProxyServiceActive = externalProxyServiceActive,
        externalProxyRouteActive = externalProxyRouteActive,
        wireGuardOwnerMode = wireGuardOwnerMode,
        tunInterface = tunInterface,
        tunPresent = tunInterface.isNotBlank()
    )
}
