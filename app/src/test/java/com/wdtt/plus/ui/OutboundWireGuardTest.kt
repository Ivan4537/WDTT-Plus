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
        assertTrue("for attempt in 1 2 3" in script)
        assertShellSyntax(script)
    }

    @Test(expected = IllegalArgumentException::class)
    fun freeWarpScript_rejectsUnsafeMtu() {
        buildFreeWarpInstallScript(1600)
    }

    private fun assertShellSyntax(script: String) {
        val file = File.createTempFile("wdtt-warp-", ".sh")
        try {
            file.writeText(script)
            val process = ProcessBuilder("bash", "-n", file.absolutePath)
                .redirectErrorStream(true)
                .start()
            val output = process.inputStream.bufferedReader().readText()
            val code = process.waitFor()
            assertTrue("bash -n завершился с кодом $code: $output", code == 0)
        } finally {
            file.delete()
        }
    }
}
