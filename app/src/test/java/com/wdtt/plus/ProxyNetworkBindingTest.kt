package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ProxyNetworkBindingTest {
    @Test
    fun `LAN binding selects a real private local interface`() {
        val binding = selectProxyLanBinding(
            listOf(
                ProxyInterfaceAddress("tun0", "10.66.66.2", 24),
                ProxyInterfaceAddress("wlan0", "192.168.42.15", 24),
                ProxyInterfaceAddress("eth0", "10.0.0.12", 24),
                ProxyInterfaceAddress("wlan1", "203.0.113.2", 24),
            ),
        )
        assertNotNull(binding)
        assertEquals("192.168.42.15", binding?.host)
        assertEquals("192.168.42.0/24", binding?.allowedCidr)
    }

    @Test
    fun `LAN binding fails closed without a private non-tunnel address`() {
        assertNull(
            selectProxyLanBinding(
                listOf(
                    ProxyInterfaceAddress("tun0", "10.66.66.2", 24),
                    ProxyInterfaceAddress("wlan0", "203.0.113.2", 24),
                    ProxyInterfaceAddress("wlan1", "192.168.1.2", 31),
                ),
            ),
        )
    }

    @Test
    fun `proxy presentation distinguishes local and LAN endpoints`() {
        assertEquals("127.0.0.1:1080", proxyDisplayAddress(false, 1080))
        assertEquals(
            "192.168.50.1:1080",
            proxyDisplayAddress(
                lanEnabled = true,
                port = 1080,
                lanBinding = ProxyListenBinding("192.168.50.1", "192.168.50.0/24"),
            ),
        )
        assertEquals("Сеть:1080", proxyDisplayAddress(true, 1080))
    }

    @Test
    fun `generated LAN password is strong enough for display and SOCKS auth`() {
        val password = generateProxyPassword()
        assertTrue(password.length >= 18)
        assertTrue(isValidSocks5Credential(password))
        assertFalse(password.any(Char::isWhitespace))
    }

    @Test
    fun `SOCKS import URI contains endpoint credentials and recognizable title`() {
        assertEquals(
            "socks5://wdtt:p%40ss%20word@127.0.0.1:1080#WDTT-Plus%20SOCKS5",
            proxyImportUri(
                mode = TUNNEL_MODE_SOCKS5,
                readyAddress = "127.0.0.1:1080",
                authEnabled = true,
                username = "wdtt",
                password = "p@ss word",
            ),
        )
    }

    @Test
    fun `HTTP import URI supports LAN endpoint without credentials`() {
        assertEquals(
            "http://192.168.1.113:8080#WDTT-Plus%20HTTP",
            proxyImportUri(
                mode = TUNNEL_MODE_HTTP,
                readyAddress = "192.168.1.113:8080",
                authEnabled = false,
                username = "",
                password = "",
            ),
        )
    }

    @Test
    fun `proxy import URI fails closed for invalid input`() {
        assertNull(proxyImportUri(TUNNEL_MODE_VPN, "127.0.0.1:1080", false, "", ""))
        assertNull(proxyImportUri(TUNNEL_MODE_SOCKS5, "Сеть:1080", false, "", ""))
        assertNull(proxyImportUri(TUNNEL_MODE_SOCKS5, "127.0.0.1:1080", true, "", "secret"))
    }

    @Test
    fun `new proxy settings default to auto-compatible both access`() {
        assertTrue(SettingsStore.resettableProfilePreferenceNames().contains("proxy_access"))
        assertEquals(PROXY_ACCESS_BOTH, normalizeProxyAccess(null))
        assertEquals(
            PROXY_ACCESS_BOTH,
            resolveStoredProxyAccess(null, legacyLanEnabled = false, explicitlyActivated = false),
        )
        assertEquals(
            PROXY_ACCESS_DEVICE,
            resolveStoredProxyAccess(null, legacyLanEnabled = false, explicitlyActivated = true),
        )
        assertEquals(
            PROXY_ACCESS_LAN,
            resolveStoredProxyAccess(null, legacyLanEnabled = true, explicitlyActivated = true),
        )
        assertTrue(proxyAccessIncludesDevice(PROXY_ACCESS_BOTH))
        assertTrue(proxyAccessIncludesLan(PROXY_ACCESS_BOTH))
        assertTrue(proxyAccessNeedsAuthentication(PROXY_ACCESS_BOTH))
    }

    @Test
    fun `auto proxy exposes each ready protocol and access copy option`() {
        val options = proxyCopyOptions(
            mode = TUNNEL_MODE_AUTO,
            readyAddresses = listOf("127.0.0.1:1080", "192.168.1.10:1080"),
            authEnabled = true,
            username = "wdtt",
            password = "secret",
        )
        assertEquals(4, options.size)
        assertEquals(
            listOf(
                "SOCKS5 · Устройство",
                "HTTP · Устройство",
                "SOCKS5 · Сеть",
                "HTTP · Сеть",
            ),
            options.map { "${it.protocolLabel} · ${it.accessLabel}" },
        )
        assertTrue(options.all { it.uri.contains("wdtt:secret@") })
    }

    @Test
    fun `expected ready addresses follow all access modes`() {
        assertEquals(
            listOf("127.0.0.1:1080", "192.168.1.20:1080"),
            expectedProxyReadyAddresses(PROXY_ACCESS_BOTH, 1080, "192.168.1.20"),
        )
        assertEquals(
            listOf("127.0.0.1:1080"),
            expectedProxyReadyAddresses(PROXY_ACCESS_DEVICE, 1080, "192.168.1.20"),
        )
        assertEquals(
            listOf("192.168.1.20:1080"),
            expectedProxyReadyAddresses(PROXY_ACCESS_LAN, 1080, "192.168.1.20"),
        )
        assertEquals(
            listOf("127.0.0.1:1080"),
            expectedProxyReadyAddresses(PROXY_ACCESS_BOTH, 1080, null),
        )
    }
}
