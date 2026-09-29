package com.wdtt.plus.ui

import java.io.File
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test

class ServerUpdateSafetyTest {
    private class Host : AutoCloseable {
        val root = Files.createTempDirectory("wdtt-update-safety-").toFile()
        private val tools = File(root, "tools").apply { mkdir() }
        val paths = ServerUpdatePaths(
            backup = File(root, "backup").path,
            config = File(root, "config").path,
            binary = File(root, "server").path,
            unit = File(root, "service").path,
            lock = File(root, "update.lock").path,
        )
        val active = File(root, "active")
        val events = File(root, "events")
        val attempt = "test-attempt"
        init {
            File(paths.config).mkdir()
            File(paths.config, "passwords.json").writeText("{\"main_password\":\"fixture\",\"devices\":{},\"passwords\":{}}")
            File(paths.config, "server.log").writeText("old-stats")
            File(paths.config, "nested").mkdir()
            File(paths.config, "nested/settings with spaces").writeText("kept")
            File(paths.binary).apply { writeText("old-server"); setExecutable(true) }
            File(paths.unit).writeText("old-unit")
            active.writeText("active")
            events.writeText("")
            executable("systemctl", """
                #!/bin/bash
                printf '%s\n' "${'$'}1" >> '${events.path}'
                case "${'$'}1" in
                  is-active) [ -f '${active.path}' ] ;;
                  is-enabled) exit 0 ;;
                  stop) rm -f '${active.path}'; if [ -d '${paths.config}' ]; then printf 'flushed-stats' > '${paths.config}/server.log'; fi ;;
                  start|restart) [ "${'$'}{FAIL_START:-0}" = 0 ] || exit 1; touch '${active.path}' ;;
                  *) exit 0 ;;
                esac
            """.trimIndent())
            executable("cp", """
                #!/bin/bash
                if [ "${'$'}{FAIL_CP:-0}" = 1 ]; then echo 'copy fixture failed' >&2; exit 65; fi
                if [ "${'$'}{HUP_CP:-0}" = 1 ]; then kill -HUP "${'$'}PPID"; exit 66; fi
                /bin/cp "${'$'}@" || exit "${'$'}?"
                # Models the original race: an active daemon changes its source after copying.
                if [ -f '${active.path}' ]; then printf 'changed-by-daemon' > '${paths.config}/server.log'; fi
            """.trimIndent())
            executable("rm", """
                #!/bin/bash
                if [ "${'$'}{FAIL_CLEANUP:-0}" = 1 ] && [[ "${'$'}*" = *'.completed.'* ]]; then exit 67; fi
                exec /bin/rm "${'$'}@"
            """.trimIndent())
            executable("df", """
                #!/bin/bash
                if [ "${'$'}{NO_SPACE:-0}" = 1 ]; then
                  printf 'Filesystem 1024-blocks Used Available Capacity Mounted\nfixture 100 99 1 99%% /\n'
                else exec /bin/df "${'$'}@"; fi
            """.trimIndent())
        }
        private fun executable(name: String, text: String) {
            File(tools, name).apply { writeText(text + "\n"); setExecutable(true) }
        }
        fun run(script: String, vararg env: Pair<String, String>): Pair<Int, String> {
            val builder = ProcessBuilder("bash", "-c", script).redirectErrorStream(true)
            builder.environment()["PATH"] = tools.path + ":" + System.getenv("PATH")
            env.forEach { builder.environment()[it.first] = it.second }
            val process = builder.start()
            if (!process.waitFor(15, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                fail("shell test timed out")
            }
            val output = process.inputStream.bufferedReader().readText()
            return process.exitValue() to output
        }
        fun prepare(vararg env: Pair<String, String>) = run(prepareServerUpdateRollbackScript(paths, attempt), *env)
        fun probe() = parseServerUpdateRollbackState(run(serverUpdateRollbackProbeScript(paths.backup)).second)
        fun privateBackup() = File(paths.backup).apply {
            mkdirs()
            Files.setPosixFilePermissions(toPath(), java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"))
        }
        override fun close() { root.deleteRecursively() }
    }

    @Test fun `stable preparation stops daemon and includes its last flushed data`() = Host().use { host ->
        val result = host.prepare()
        assertEquals(result.second, 0, result.first)
        assertTrue(host.probe() is ServerUpdateRollbackState.PreparedValid)
        assertFalse("daemon must remain quiescent until installation", host.active.exists())
        assertEquals("flushed-stats", File(host.paths.backup, "config/server.log").readText())
        assertEquals("kept", File(host.paths.backup, "config/nested/settings with spaces").readText())
        assertTrue(File(host.paths.backup, "checksums").isFile)
    }

    @Test fun `copy failure resumes old service and preserves partial copy away from active path`() = Host().use { host ->
        val result = host.prepare("FAIL_CP" to "1")
        assertNotEquals(0, result.first)
        assertTrue(result.second.contains("copy_config"))
        assertTrue(host.active.exists())
        assertFalse(File(host.paths.backup).exists())
        val archive = host.root.listFiles()!!.single { it.name.startsWith("backup.incomplete.") }
        assertEquals("preparation_failed\n", File(archive, "copy/state").readText())
        assertEquals("old-server", File(host.paths.binary).readText())
        assertEquals(0, host.prepare().first)
    }

    @Test fun `lost ssh signal resumes service and does not publish partial backup`() = Host().use { host ->
        val result = host.prepare("HUP_CP" to "1")
        assertNotEquals(0, result.first)
        assertTrue(host.active.exists())
        assertFalse(File(host.paths.backup).exists())
        assertTrue(host.root.listFiles()!!.any { it.name.startsWith("backup.incomplete.") })
    }

    @Test fun `restart failure leaves a recoverable preparation rather than deleting evidence`() = Host().use { host ->
        val result = host.prepare("FAIL_CP" to "1", "FAIL_START" to "1")
        assertNotEquals(0, result.first)
        assertEquals(ServerUpdateRollbackState.PreparationIncomplete, host.probe())
        assertFalse(host.active.exists())
        val recovered = host.run(cancelServerUpdatePreparationScript(host.paths))
        assertEquals(recovered.second, 0, recovered.first)
        assertTrue(host.active.exists())
        assertEquals(ServerUpdateRollbackState.None, host.probe())
    }

    @Test fun `complete backup corruption and extra files fail checksum validation`() = Host().use { host ->
        assertEquals(0, host.prepare().first)
        val config = File(host.paths.backup, "config/server.log")
        val original = config.readText()
        config.writeText("tampered")
        assertTrue(host.probe() is ServerUpdateRollbackState.PreparedCorrupted)
        config.writeText(original)
        File(host.paths.backup, "config/extra").writeText("unexpected")
        assertTrue(host.probe() is ServerUpdateRollbackState.PreparedCorrupted)
    }

    @Test fun `applying and committed phases retain integrity but committed cannot be applied again`() = Host().use { host ->
        assertEquals(0, host.prepare().first)
        val apply = host.run(serverUpdateApplyGuardScript("echo applied", host.attempt, host.paths))
        assertEquals(apply.second, 0, apply.first)
        assertEquals("applying\n", File(host.paths.backup, "state").readText())
        assertTrue(host.probe() is ServerUpdateRollbackState.PreparedValid)
        File(host.paths.backup, "state").writeText("committed\n")
        assertEquals(ServerUpdateRollbackState.Committed, host.probe())
        assertNotEquals(0, host.run(serverUpdateApplyGuardScript("echo applied", host.attempt, host.paths)).first)
    }

    @Test fun `another attempt cannot apply or overwrite a prepared backup`() = Host().use { host ->
        assertEquals(0, host.prepare().first)
        assertNotEquals(0, host.run(serverUpdateApplyGuardScript("echo unsafe", "other", host.paths)).first)
        assertNotEquals(0, host.prepare().first)
        assertEquals("prepared\n", File(host.paths.backup, "state").readText())
    }

    @Test fun `unsafe source symlink is rejected without stopping service`() = Host().use { host ->
        Files.createSymbolicLink(File(host.paths.config, "foreign").toPath(), File(host.paths.binary).toPath())
        assertNotEquals(0, host.prepare().first)
        assertTrue(host.active.exists())
        assertFalse(File(host.paths.backup).exists())
        assertFalse(host.events.readText().lineSequence().contains("stop"))
    }

    @Test fun `legacy config only preparation is archived explicitly without changing current files`() = Host().use { host ->
        File(host.paths.backup, "config").mkdirs()
        host.privateBackup()
        File(host.paths.backup, "config/partial").writeText("evidence")
        assertTrue(host.probe() is ServerUpdateRollbackState.PreparedCorrupted)
        val result = host.run(archiveLegacyUpdatePreparationScript(host.paths))
        assertEquals(result.second, 0, result.first)
        assertTrue(host.active.exists())
        assertEquals("old-server", File(host.paths.binary).readText())
        assertEquals(ServerUpdateRollbackState.None, host.probe())
        val archive = host.root.listFiles()!!.single { it.name.startsWith("backup.incomplete.") }
        assertEquals("evidence", File(archive, "copy/config/partial").readText())
    }

    @Test fun `unknown legacy state or inactive service cannot be archived`() = Host().use { host ->
        File(host.paths.backup, "config").mkdirs()
        host.privateBackup()
        File(host.paths.backup, "foreign").writeText("unknown")
        assertNotEquals(0, host.run(archiveLegacyUpdatePreparationScript(host.paths)).first)
        File(host.paths.backup, "foreign").delete()
        host.active.delete()
        assertNotEquals(0, host.run(archiveLegacyUpdatePreparationScript(host.paths)).first)
        assertTrue(File(host.paths.backup).exists())
    }

    @Test fun `rollback restores the entire verified tree before restarting service`() = Host().use { host ->
        assertEquals(0, host.prepare().first)
        File(host.paths.binary).writeText("new-server")
        File(host.paths.unit).writeText("new-unit")
        File(host.paths.config, "nested/settings with spaces").writeText("new-settings")
        File(host.paths.config, "added-by-install").writeText("new-file")
        host.active.writeText("active")
        val result = host.run(rollbackServerUpdateScript(host.paths, host.attempt))
        assertEquals(result.second, 0, result.first)
        assertTrue(host.active.exists())
        assertEquals("old-server", File(host.paths.binary).readText())
        assertEquals("old-unit", File(host.paths.unit).readText())
        assertEquals("kept", File(host.paths.config, "nested/settings with spaces").readText())
        assertFalse(File(host.paths.config, "added-by-install").exists())
        assertEquals(ServerUpdateRollbackState.None, host.probe())
    }

    @Test fun `interrupted rollback remains retryable without losing original backup`() = Host().use { host ->
        assertEquals(0, host.prepare().first)
        assertNotEquals(0, host.run(rollbackServerUpdateScript(host.paths, host.attempt), "FAIL_CP" to "1").first)
        assertFalse(host.active.exists())
        assertTrue(host.probe() is ServerUpdateRollbackState.PreparedValid)
        val result = host.run(rollbackServerUpdateScript(host.paths, host.attempt))
        assertEquals(result.second, 0, result.first)
        assertTrue(host.active.exists())
        assertEquals("kept", File(host.paths.config, "nested/settings with spaces").readText())
    }

    @Test fun `corrupt backup cannot stop or overwrite a healthy current installation`() = Host().use { host ->
        assertEquals(0, host.prepare().first)
        File(host.paths.binary).writeText("new-server")
        File(host.paths.backup, "wdtt-server").writeText("corrupt")
        host.active.writeText("active")
        host.events.writeText("")
        assertNotEquals(0, host.run(rollbackServerUpdateScript(host.paths, host.attempt)).first)
        assertTrue(host.active.exists())
        assertEquals("new-server", File(host.paths.binary).readText())
        assertFalse(host.events.readText().lineSequence().contains("stop"))
    }

    @Test fun `cleanup failure cannot leave a blocking partial backup or revert new installation`() = Host().use { host ->
        assertEquals(0, host.prepare().first)
        host.active.writeText("active")
        File(host.paths.binary).writeText("new-server")
        val result = host.run(cleanupServerUpdateBackupScript(host.paths, host.attempt), "FAIL_CLEANUP" to "1")
        assertNotEquals(0, result.first)
        assertTrue(host.active.exists())
        assertEquals("new-server", File(host.paths.binary).readText())
        assertEquals(ServerUpdateRollbackState.None, host.probe())
        assertTrue(host.root.listFiles()!!.any { it.name.startsWith("backup.completed.") })
    }

    @Test fun `stopped service remains stopped after preparation failure and rollback`() = Host().use { host ->
        host.active.delete()
        assertNotEquals(0, host.prepare("FAIL_CP" to "1").first)
        assertFalse(host.active.exists())
        assertEquals(0, host.prepare().first)
        val result = host.run(rollbackServerUpdateScript(host.paths, host.attempt))
        assertEquals(result.second, 0, result.first)
        assertFalse(host.active.exists())
        assertFalse(host.events.readText().lineSequence().contains("restart"))
    }

    @Test fun `concurrent operation holds lock without stopping daemon or creating backup`() = Host().use { host ->
        val blocker = ProcessBuilder("bash", "-c", "exec 9>'${host.paths.lock}'; flock 9; echo ready; read -r ignored")
            .redirectErrorStream(true).start()
        try {
            assertEquals("ready", blocker.inputStream.bufferedReader().readLine())
            val result = host.prepare()
            assertNotEquals(0, result.first)
            assertTrue(result.second.contains("другая операция"))
            assertTrue(host.active.exists())
            assertFalse(File(host.paths.backup).exists())
        } finally { blocker.outputStream.close(); blocker.waitFor(5, TimeUnit.SECONDS); blocker.destroyForcibly() }
    }

    @Test fun `missing format or checksums cannot downgrade new backup to legacy validation`() = Host().use { host ->
        assertEquals(0, host.prepare().first)
        val format = File(host.paths.backup, "format")
        format.delete()
        assertTrue(host.probe() is ServerUpdateRollbackState.PreparedCorrupted)
        format.writeText("2\n")
        File(host.paths.backup, "checksums").delete()
        assertTrue(host.probe() is ServerUpdateRollbackState.PreparedCorrupted)
    }

    @Test fun `insufficient snapshot space is rejected before stopping healthy service`() = Host().use { host ->
        val result = host.prepare("NO_SPACE" to "1")
        assertNotEquals(0, result.first)
        assertTrue(result.second.contains("недостаточно свободного места"))
        assertTrue(host.active.exists())
        assertFalse(File(host.paths.backup).exists())
        assertFalse(host.events.readText().lineSequence().contains("stop"))
    }

    @Test fun `lock acquisition does not truncate an existing regular lock file`() = Host().use { host ->
        File(host.paths.lock).writeText("existing-lock-data")
        assertEquals(0, host.prepare().first)
        assertEquals("existing-lock-data", File(host.paths.lock).readText())
    }

    @Test fun `symlink and hardlink lock targets are refused before mutation`() = Host().use { host ->
        val target = File(host.root, "foreign-lock-target").apply { writeText("preserve") }
        val lock = File(host.paths.lock).toPath()
        Files.createSymbolicLink(lock, target.toPath())
        assertNotEquals(0, host.prepare().first)
        Files.delete(lock)
        Files.createLink(lock, target.toPath())
        assertNotEquals(0, host.prepare().first)
        assertEquals("preserve", target.readText())
        assertTrue(host.active.exists())
        assertFalse(File(host.paths.backup).exists())
    }

    @Test fun `failure details remain bounded and redact credentials`() {
        val detail = serverUpdateFailureDetail((1..50).joinToString("\n") { "line$it" } + "\nTOKEN=secret-value")
        assertFalse(detail.contains("secret-value"))
        assertFalse(detail.contains("line1\n"))
        assertTrue(detail.contains("line50"))
        assertTrue(detail.length <= 3000)
    }
}
