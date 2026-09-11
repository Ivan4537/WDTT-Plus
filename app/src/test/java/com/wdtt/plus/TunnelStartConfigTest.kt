package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelStartConfigTest {

    @Test
    fun `proxy stops only after another VPN captures this app twice`() {
        var observations = nextProxyVpnCaptureObservationCount(
            TUNNEL_MODE_SOCKS5,
            appDefaultNetworkIsVpn = true,
            previousCount = 0,
        )
        assertEquals(1, observations)
        assertFalse(proxyVpnCaptureConfirmed(observations))

        observations = nextProxyVpnCaptureObservationCount(
            TUNNEL_MODE_SOCKS5,
            appDefaultNetworkIsVpn = true,
            previousCount = observations,
        )
        assertTrue(proxyVpnCaptureConfirmed(observations))
    }

    @Test
    fun `physical network or VPN mode resets proxy capture observations`() {
        assertEquals(
            0,
            nextProxyVpnCaptureObservationCount(
                TUNNEL_MODE_SOCKS5,
                appDefaultNetworkIsVpn = false,
                previousCount = 1,
            ),
        )
        assertEquals(
            0,
            nextProxyVpnCaptureObservationCount(
                TUNNEL_MODE_VPN,
                appDefaultNetworkIsVpn = true,
                previousCount = 1,
            ),
        )
    }

    @Test
    fun everyProfileUsesConfiguredSpareHashes() {
        assertTrue(shouldUseHashFallback(hashCount = 4))
        assertTrue(shouldUseHashFallback(hashCount = 2))
        assertFalse(shouldUseHashFallback(hashCount = 1))
    }

    @Test
    fun `wireguard config is required before workers for every profile`() {
        assertEquals(true, shouldUseConfigFirstStart())
    }

    @Test
    fun `tile and widgets stop both active and trusted wifi waiting tunnel`() {
        assertEquals(
            TunnelToggleAction.STOP,
            tunnelToggleAction(
                running = true,
                trustedWifiWaiting = false,
                vpnPermissionRequired = false,
            )
        )
        assertEquals(
            TunnelToggleAction.STOP,
            tunnelToggleAction(
                running = false,
                trustedWifiWaiting = true,
                vpnPermissionRequired = false,
            )
        )
    }

    @Test
    fun `tile and widgets request permission before start`() {
        assertEquals(
            TunnelToggleAction.REQUEST_VPN_PERMISSION,
            tunnelToggleAction(
                running = false,
                trustedWifiWaiting = false,
                vpnPermissionRequired = true,
            )
        )
        assertEquals(
            TunnelToggleAction.START,
            tunnelToggleAction(
                running = false,
                trustedWifiWaiting = false,
                vpnPermissionRequired = false,
            )
        )
    }

    @Test
    fun `stop action is selected before any permission probe`() {
        assertEquals(
            TunnelToggleAction.STOP,
            tunnelToggleAction(
                running = true,
                trustedWifiWaiting = false,
                vpnPermissionRequired = true,
            ),
        )
        assertEquals(
            TunnelToggleAction.STOP,
            tunnelToggleAction(
                running = false,
                trustedWifiWaiting = true,
                vpnPermissionRequired = true,
            ),
        )
    }

    @Test
    fun `SOCKS5 mode never needs Android VPN permission`() {
        assertFalse(tunnelModeNeedsVpnPermission("auto"))
        assertFalse(tunnelModeNeedsVpnPermission("socks5"))
        assertFalse(tunnelModeNeedsVpnPermission("http"))
        assertTrue(tunnelModeNeedsVpnPermission("vpn"))
        assertTrue(tunnelModeNeedsVpnPermission("tun"))
        assertTrue(tunnelModeNeedsVpnPermission("unknown"))
    }

    @Test
    fun `tile notification and widgets identify active SOCKS5 mode`() {
        assertEquals("SOCKS5", tunnelModeStatusLabel(TUNNEL_MODE_SOCKS5))
        assertEquals("АВТО ПРОКСИ", tunnelModeStatusLabel(TUNNEL_MODE_AUTO))
        assertEquals("VPN", tunnelModeStatusLabel(TUNNEL_MODE_VPN))
        assertEquals("HTTP CONNECT", tunnelModeStatusLabel(TUNNEL_MODE_HTTP))
        assertEquals(
            "SOCKS5 · Чехия",
            fullWidgetRunningStatus(TUNNEL_MODE_SOCKS5, "Чехия"),
        )
        assertEquals(
            "SOCKS · Чехия",
            compactWidgetRunningStatus(TUNNEL_MODE_SOCKS5, "Чехия"),
        )
        assertEquals(
            "Остановить SOCKS5",
            tunnelToggleContentDescription(running = true, tunnelMode = TUNNEL_MODE_SOCKS5),
        )
        assertEquals(
            "Запустить SOCKS5",
            tunnelToggleContentDescription(running = false, tunnelMode = TUNNEL_MODE_SOCKS5),
        )
        assertEquals("HTTP · Чехия", fullWidgetRunningStatus(TUNNEL_MODE_HTTP, "Чехия"))
        assertEquals(
            "Остановить HTTP CONNECT",
            tunnelToggleContentDescription(running = true, tunnelMode = TUNNEL_MODE_HTTP),
        )
    }

    @Test
    fun `SOCKS5 settings fail closed to safe defaults`() {
        assertEquals(TUNNEL_MODE_SOCKS5, normalizeTunnelMode(" SOCKS5 "))
        assertEquals(TUNNEL_MODE_AUTO, normalizeTunnelMode("mixed"))
        assertEquals(TUNNEL_MODE_HTTP, normalizeTunnelMode("HTTP-CONNECT"))
        assertEquals(TUNNEL_MODE_VPN, normalizeTunnelMode("invalid"))
        assertEquals(TUNNEL_MODE_VPN, resolveStoredTunnelMode("socks5", explicitlyActivated = false))
        assertEquals(TUNNEL_MODE_SOCKS5, resolveStoredTunnelMode("socks5", explicitlyActivated = true))
        assertEquals(DEFAULT_SOCKS5_PORT, normalizeSocks5Port(0))
        assertEquals(DEFAULT_SOCKS5_PORT, normalizeSocks5Port(65_536))
        assertEquals(10_801, normalizeSocks5Port(10_801))
        assertTrue(isValidSocks5Credential("user"))
        assertFalse(isValidSocks5Credential(""))
        assertFalse(isValidSocks5Credential("я".repeat(128)))
    }

    @Test
    fun `LAN proxy always requires authentication`() {
        assertTrue(
            proxySettingsAreValid(
                mode = TUNNEL_MODE_SOCKS5,
                port = 1080,
                access = PROXY_ACCESS_LAN,
                authEnabled = true,
                username = "wdtt",
                password = "secret",
            ),
        )
        assertFalse(
            proxySettingsAreValid(
                mode = TUNNEL_MODE_HTTP,
                port = 8080,
                access = PROXY_ACCESS_LAN,
                authEnabled = false,
                username = "",
                password = "",
            ),
        )
        assertTrue(
            proxySettingsAreValid(
                mode = TUNNEL_MODE_HTTP,
                port = 8080,
                access = PROXY_ACCESS_DEVICE,
                authEnabled = false,
                username = "",
                password = "",
            ),
        )
    }

    @Test
    fun `SOCKS5 credentials are truncated on a UTF-8 boundary`() {
        assertEquals("plain", truncateSocks5Credential("plain"))
        assertEquals("я".repeat(127), truncateSocks5Credential("я".repeat(128)))
        val emoji = truncateSocks5Credential("🙂".repeat(64))
        assertEquals(63, emoji.codePointCount(0, emoji.length))
        assertTrue(emoji.toByteArray(Charsets.UTF_8).size <= 255)
        assertTrue(isValidSocks5Credential(emoji))
    }

    @Test
    fun `profile SOCKS5 settings reach native tunnel parameters`() {
        val params = buildTunnelParams(
            TunnelProfileSnapshot(
                profileIndex = 0,
                remoteManaged = false,
                linkMode = false,
                link = "",
                peer = "vpn.example",
                vkHashes = "hash",
                secondaryVkHash = "",
                connectionPassword = "password",
                workersPerHash = 18,
                profileMaxWorkers = 0,
                manualPortsEnabled = false,
                serverDtlsPort = 56000,
                listenPort = 9000,
                sni = "",
                protocol = "udp",
                vkCallsPreflight = true,
                captchaMode = "auto",
                captchaSolveMethod = "auto",
                fingerprint = "firefox",
                clientIds = DEFAULT_VK_CLIENT_IDS,
                customVkCredentialsEnabled = false,
                customVkClientId = "",
                customVkClientSecret = "",
                proxyMode = TUNNEL_MODE_SOCKS5,
                proxyPort = 10_801,
                proxyUdpEnabled = true,
                proxyLanEnabled = true,
                proxyAuthEnabled = true,
                proxyUsername = "local-user",
                proxyPassword = "local-password",
            )
        )

        assertEquals(TUNNEL_MODE_SOCKS5, params?.mode)
        assertEquals(10_801, params?.socksPort)
        assertEquals(true, params?.socksUdpEnabled)
        assertEquals(true, params?.proxyLanEnabled)
        assertEquals(true, params?.socksAuthEnabled)
        assertEquals("local-user", params?.socksUsername)
        assertEquals("local-password", params?.socksPassword)
    }

    @Test
    fun `HTTP profile settings reach native tunnel parameters`() {
        val params = buildTunnelParams(
            TunnelProfileSnapshot(
                profileIndex = 0,
                remoteManaged = false,
                linkMode = false,
                link = "",
                peer = "vpn.example",
                vkHashes = "hash",
                secondaryVkHash = "",
                connectionPassword = "password",
                workersPerHash = 18,
                profileMaxWorkers = 0,
                manualPortsEnabled = false,
                serverDtlsPort = 56000,
                listenPort = 9000,
                sni = "",
                protocol = "udp",
                vkCallsPreflight = true,
                captchaMode = "auto",
                captchaSolveMethod = "auto",
                fingerprint = "firefox",
                clientIds = DEFAULT_VK_CLIENT_IDS,
                customVkCredentialsEnabled = false,
                customVkClientId = "",
                customVkClientSecret = "",
                proxyMode = TUNNEL_MODE_HTTP,
                proxyPort = 8080,
            ),
        )
        assertEquals(TUNNEL_MODE_HTTP, params?.mode)
        assertEquals(8080, params?.socksPort)
        assertFalse(tunnelModeNeedsVpnPermission(params?.mode))
    }

    @Test
    fun `auto profile forces SOCKS UDP and preserves both access`() {
        val params = buildTunnelParams(
            TunnelProfileSnapshot(
                profileIndex = 0,
                remoteManaged = false,
                linkMode = false,
                link = "",
                peer = "vpn.example",
                vkHashes = "hash",
                secondaryVkHash = "",
                connectionPassword = "password",
                workersPerHash = 18,
                profileMaxWorkers = 0,
                manualPortsEnabled = false,
                serverDtlsPort = 56000,
                listenPort = 9000,
                sni = "",
                protocol = "udp",
                vkCallsPreflight = true,
                captchaMode = "auto",
                captchaSolveMethod = "auto",
                fingerprint = "firefox",
                clientIds = DEFAULT_VK_CLIENT_IDS,
                customVkCredentialsEnabled = false,
                customVkClientId = "",
                customVkClientSecret = "",
                proxyMode = TUNNEL_MODE_AUTO,
                proxyPort = 1080,
                proxyUdpEnabled = false,
                proxyAccess = PROXY_ACCESS_BOTH,
                proxyAuthEnabled = true,
                proxyUsername = "wdtt",
                proxyPassword = "secret",
            ),
        )
        assertEquals(TUNNEL_MODE_AUTO, params?.mode)
        assertTrue(params?.socksUdpEnabled == true)
        assertEquals(PROXY_ACCESS_BOTH, params?.proxyAccess)
        assertFalse(tunnelModeNeedsVpnPermission(params?.mode))
    }

}
