package com.wdtt.plus.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class OutboundWireGuardTest {
    private val safeConfig = """
        [Interface]
        PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
        Address = 172.16.0.2/32
        DNS = 1.1.1.1
        MTU = 1280
        Table = auto

        [Peer]
        PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
        AllowedIPs = 0.0.0.0/0, ::/0
        Endpoint = engage.cloudflareclient.com:2408
        PersistentKeepalive = 25
    """.trimIndent()

    @Test
    fun importedWireGuardConfig_isSanitizedForPolicyRouting() {
        val sanitized = sanitizeWireGuardConfigForWdttExit(safeConfig)

        assertTrue("Table = off" in sanitized)
        assertTrue("MTU = 1280" in sanitized)
        assertFalse(Regex("(?im)^\\s*DNS\\s*=").containsMatchIn(sanitized))
        assertFalse("Table = auto" in sanitized)
    }

    @Test
    fun importedWireGuardConfig_rejectsCommandsAndUnknownParameters() {
        val commandConfig = safeConfig.replace("MTU = 1280", "PostUp = touch /tmp/unsafe")
        val unknownConfig = safeConfig.replace("MTU = 1280", "UnsafeOption = true")

        assertTrue(validateWireGuardConfigText(commandConfig).isFailure)
        assertTrue(validateWireGuardConfigText(unknownConfig).isFailure)
    }

    @Test
    fun importedWireGuardConfig_requiresDefaultIpv4Route() {
        val config = safeConfig.replace("0.0.0.0/0, ::/0", "10.0.0.0/8")

        assertTrue(validateWireGuardConfigText(config).isFailure)
    }

    @Test
    fun freeWarpScript_hasSafeUpdateChecksAndValidShellSyntax() {
        val script = buildFreeWarpInstallScript(1392)

        assertTrue("WARP_MTU=1392" in script)
        assertTrue("checksums.txt" in script)
        assertTrue("sha256sum" in script)
        assertTrue("--accept-tos" in script)
        assertTrue("wdtt-warp-watchdog.timer" in script)
        assertTrue("wdtt_warp_autotune" in script)
        assertTrue("WARP_ENDPOINT_CANDIDATES" in script)
        assertTrue("engage.cloudflareclient.com:2408" in script)
        assertTrue("rollback after WARP check error" in script)
        assertShellSyntax(script)
    }

    @Test
    fun serverDiagnosticsScript_hasPortableChecksAndValidShellSyntax() {
        val script = serverDiagnosticsScript()

        assertTrue("WDTT_SERVER_DIAG" in script)
        assertTrue("apt-get dnf yum zypper apk pacman" in script)
        assertTrue("wdtt_diag_install_dependencies" in script)
        assertTrue("DEBIAN_FRONTEND=noninteractive apt-get install" in script)
        assertTrue("dnf install -y" in script)
        assertTrue("yum install -y" in script)
        assertTrue("zypper --non-interactive install" in script)
        assertTrue("apk add --no-cache" in script)
        assertTrue("pacman -Sy --noconfirm --needed" in script)
        assertTrue("systemctl" in script)
        assertTrue("iptables" in script)
        assertTrue("nft" in script)
        assertTrue("VK / TURN-зависимости" in script)
        assertTrue("api.vk.me" in script)
        assertTrue("calls.okcdn.ru" in script)
        assertTrue("api.telegram.org" in script)
        assertTrue("Бесплатный WARP" in script)
        assertTrue("engage.cloudflareclient.com" in script)
        assertTrue("WDTT_EXPECTED_DTLS_PORT" in script)
        assertTrue("wdtt_diag_udp_probe" in script)
        assertTrue("/dev/net/tun" in script)
        assertTrue("admin.sock" in script)
        assertFalse("PrivateKey =" in script)
        assertShellSyntax(script, shell = "sh")
    }

    @Test(expected = IllegalArgumentException::class)
    fun freeWarpScript_rejectsUnsafeMtu() {
        buildFreeWarpInstallScript(1600)
    }

    private fun assertShellSyntax(script: String, shell: String = "bash") {
        val file = File.createTempFile("wdtt-warp-", ".sh")
        try {
            file.writeText(script)
            val process = ProcessBuilder(shell, "-n", file.absolutePath)
                .redirectErrorStream(true)
                .start()
            val output = process.inputStream.bufferedReader().readText()
            val code = process.waitFor()
            assertTrue("$shell -n завершился с кодом $code: $output", code == 0)
        } finally {
            file.delete()
        }
    }
}
