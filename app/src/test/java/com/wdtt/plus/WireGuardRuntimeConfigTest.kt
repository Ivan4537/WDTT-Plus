package com.wdtt.plus

import com.wireguard.config.Config
import com.wireguard.config.Peer
import com.wireguard.crypto.Key
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class WireGuardRuntimeConfigTest {
    private val privateKey = Key.fromBytes(ByteArray(32) { index -> (index + 1).toByte() })
        .toBase64()
    private val publicKey = Key.fromBytes(ByteArray(32) { index -> (index + 33).toByte() })
        .toBase64()

    @Test
    fun unchangedConfigurationKeepsRunningVpnInterface() {
        val current = config(endpointPort = 9000)
        val updated = config(endpointPort = 9000)

        assertTrue(
            shouldReuseRunningWireGuard(
                tunnelUp = true,
                currentConfigFingerprint = wireGuardConfigFingerprint(current),
                updatedConfig = updated,
            )
        )
    }

    @Test
    fun changedConfigurationReplacesVpnInterface() {
        assertFalse(
            shouldReuseRunningWireGuard(
                tunnelUp = true,
                currentConfigFingerprint = wireGuardConfigFingerprint(
                    config(endpointPort = 9000)
                ),
                updatedConfig = config(endpointPort = 9001),
            )
        )
    }

    @Test
    fun changedApplicationRoutingReplacesVpnInterface() {
        val current = config(endpointPort = 9000, excludedApplication = "app.one")
        val updated = config(endpointPort = 9000, excludedApplication = "app.two")

        assertFalse(
            shouldReuseRunningWireGuard(
                tunnelUp = true,
                currentConfigFingerprint = wireGuardConfigFingerprint(current),
                updatedConfig = updated,
            )
        )
    }

    @Test
    fun changedDnsReplacesVpnInterface() {
        val current = config(endpointPort = 9000, dns = "1.1.1.1")
        val updated = config(endpointPort = 9000, dns = "8.8.8.8")

        assertFalse(
            shouldReuseRunningWireGuard(
                tunnelUp = true,
                currentConfigFingerprint = wireGuardConfigFingerprint(current),
                updatedConfig = updated,
            )
        )
    }

    @Test
    fun stoppedVpnInterfaceIsNeverReused() {
        val config = config(endpointPort = 9000)

        assertFalse(
            shouldReuseRunningWireGuard(
                tunnelUp = false,
                currentConfigFingerprint = wireGuardConfigFingerprint(config),
                updatedConfig = config,
            )
        )
    }

    @Test
    fun peerWithoutAllowedIpsIsValidForAnEmptyAddressWhitelist() {
        val peer = Peer.Builder()
            .parsePublicKey(publicKey)
            .build()

        assertTrue(peer.allowedIps.isEmpty())
    }

    private fun config(
        endpointPort: Int,
        excludedApplication: String? = null,
        dns: String = "1.1.1.1",
    ): Config {
        val appRouting = excludedApplication
            ?.let { "ExcludedApplications = $it" }
            .orEmpty()
        val text = """
            [Interface]
            PrivateKey = $privateKey
            Address = 10.0.0.2/32
            DNS = $dns
            MTU = 1280
            $appRouting

            [Peer]
            PublicKey = $publicKey
            AllowedIPs = 0.0.0.0/0
            Endpoint = 127.0.0.1:$endpointPort
            PersistentKeepalive = 25
        """.trimIndent()
        return Config.parse(ByteArrayInputStream(text.toByteArray()))
    }
}
