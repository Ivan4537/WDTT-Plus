package com.wdtt.plus

import java.nio.file.Files
import java.util.concurrent.TimeUnit
import com.wdtt.plus.ui.rootCommand
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ServerAdminSudoTest {
    private val request = "{\"main_password\":\"owner-secret\",\"args\":[\"list\"]}\n"

    @Test
    fun framedAdminInputSurvivesPasswordPrompt() {
        val plan = buildAdminRootStdinExecPlan(
            command = "cat",
            sudoPassword = "sudo-secret",
            stdinPayload = request,
        )

        val inputAfterSudoPassword = plan.stdinPayload.substringAfter('\n')
        val result = runShell(buildAdminStdinForwardingCommand("cat"), inputAfterSudoPassword)

        assertEquals(0, result.exitCode)
        assertEquals(request, result.stdout)
        assertEquals("", result.stderr)
    }

    @Test
    fun framedAdminInputSurvivesCachedOrPasswordlessSudo() {
        val plan = buildAdminRootStdinExecPlan(
            command = "cat",
            sudoPassword = "sudo-secret",
            stdinPayload = request,
        )

        val result = runShell(buildAdminStdinForwardingCommand("cat"), plan.stdinPayload)

        assertEquals(0, result.exitCode)
        assertEquals(request, result.stdout)
        assertEquals("", result.stderr)
    }

    @Test
    fun framingAlsoHandlesPasswordEqualToPublicStartMarker() {
        val marker = buildAdminRootStdinExecPlan("cat", "password", request)
            .stdinPayload
            .lineSequence()
            .drop(1)
            .first()
        val plan = buildAdminRootStdinExecPlan("cat", marker, request)

        val result = runShell(buildAdminStdinForwardingCommand("cat"), plan.stdinPayload)

        assertEquals(0, result.exitCode)
        assertEquals(request, result.stdout)
    }

    @Test
    fun adminPlanUsesOneChannelAndKeepsSecretsOutOfCommand() {
        val plan = buildAdminRootStdinExecPlan(
            command = "/usr/local/bin/wdtt-server admin --config-dir /etc/wdtt --request-stdin",
            sudoPassword = "sudo-secret",
            stdinPayload = request,
        )

        assertTrue("sudo -S -p ''" in plan.command)
        assertTrue("command -v sudo" in plan.command)
        assertTrue("id -u" in plan.command)
        assertFalse("sudo -n" in plan.command)
        assertFalse("sudo -v" in plan.command)
        assertFalse("sudo-secret" in plan.command)
        assertFalse("owner-secret" in plan.command)
        assertTrue("sudo-secret" in plan.stdinPayload)
        assertTrue("owner-secret" in plan.stdinPayload)
    }

    @Test
    fun completeAdminPlanWorksWhenSudoReadsPassword() {
        val result = runPlanWithFakePrivileges(
            sudoScript = """
                #!/bin/sh
                [ "${'$'}1" = "-S" ] && shift
                if [ "${'$'}1" = "-p" ]; then shift 2; fi
                IFS= read -r supplied_password || exit 40
                [ "${'$'}supplied_password" = "sudo-secret" ] || exit 41
                exec "${'$'}@"
            """.trimIndent(),
        )

        assertEquals(0, result.exitCode)
        assertEquals(request, result.stdout)
        assertEquals("", result.stderr)
    }

    @Test
    fun completeAdminPlanWorksWhenSudoDoesNotReadPassword() {
        val result = runPlanWithFakePrivileges(
            sudoScript = """
                #!/bin/sh
                [ "${'$'}1" = "-S" ] && shift
                if [ "${'$'}1" = "-p" ]; then shift 2; fi
                exec "${'$'}@"
            """.trimIndent(),
        )

        assertEquals(0, result.exitCode)
        assertEquals(request, result.stdout)
        assertEquals("", result.stderr)
    }

    @Test
    fun completeAdminPlanUsesDirectRootPathWithoutSudo() {
        val result = runPlanWithFakePrivileges(
            sudoScript = """
                #!/bin/sh
                exit 99
            """.trimIndent(),
            uid = 0,
        )

        assertEquals(0, result.exitCode)
        assertEquals(request, result.stdout)
        assertEquals("", result.stderr)
    }

    @Test
    fun multilineSudoPasswordFailsBeforeOpeningRemoteCommand() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            buildAdminRootStdinExecPlan("cat", "first\nsecond", request)
        }

        assertTrue(error.message.orEmpty().contains("перенос строки"))
    }

    @Test
    fun sudoFailuresHaveActionableRussianMessages() {
        assertEquals(
            "Не удалось подтвердить права sudo. Проверьте SSH-пароль или пароль sudo в «Деплой → SSH».",
            friendlyAdminSudoError("sudo: 1 incorrect password attempt"),
        )
        assertEquals(
            "У SSH-пользователя нет разрешения выполнять команды управления через sudo.",
            friendlyAdminSudoError("user is not in the sudoers file"),
        )
        assertEquals(
            "Для управления сервером нужны root-права или установленный sudo.",
            friendlyAdminSudoError("error: root privileges required and sudo not found"),
        )
    }

    @Test
    fun fastCommandWaitsForInputBeforeFinishing() {
        val plan = buildSshExecStdinPlan(
            "if [ 0 = 0 ]; then printf 'ready\\n'; else sudo -S -p '' printf 'ready\\n'; fi",
            "sudo-secret",
        )!!
        // Test the actual frame received by root or passwordless sudo. Delay the
        // writer, as happens when the SSH reply outruns the local sending thread.
        val process = ProcessBuilder("bash", "-c", buildAdminStdinForwardingCommand("exec sh -s")).start()
        try {
            assertFalse(process.waitFor(150, TimeUnit.MILLISECONDS))
            process.outputStream.use { it.write(plan.stdinPayload.toByteArray()) }
            assertTrue(process.waitFor(5, TimeUnit.SECONDS))
            assertEquals(0, process.exitValue())
            assertEquals("ready\n", process.inputStream.bufferedReader().readText())
            assertEquals("", process.errorStream.bufferedReader().readText())
        } finally {
            process.destroyForcibly()
        }
    }

    @Test
    fun ordinaryCommandsDoNotReceivePasswordOrWrapper() {
        assertEquals(null, buildSshExecStdinPlan("command -v sudo; printf 'ready\\n'", "sudo-secret"))
    }

    @Test
    fun alreadyFramedAdminRequestIsNotFramedTwice() {
        val original = buildAdminRootStdinExecPlan("cat", "sudo-secret", request)
        assertEquals(original, buildSshExecStdinPlan(original.command, "sudo-secret", original.stdinPayload))
    }

    @Test
    fun plainRootCommandReceivesNoUnusedPassword() {
        val plan = buildSshExecStdinPlan(
            "if [ 0 = 0 ]; then cat </dev/null; else sudo -S -p '' cat; fi",
            "sudo-secret",
        )!!
        val result = runShell(buildAdminStdinForwardingCommand("exec sh -s"), plan.stdinPayload)
        assertEquals(0, result.exitCode)
        assertEquals("", result.stdout)
        assertEquals("", result.stderr)
        assertFalse("sudo-secret" in plan.command)
    }

    @Test
    fun plainShDiagnosticsDoNotGainBashDependency() {
        val plan = buildSshExecStdinPlan(
            "if [ 0 = 0 ]; then sh -c 'printf ready'; else sudo -S -p '' sh -c 'printf ready'; fi",
            "sudo-secret",
        )!!
        assertFalse("bash" in plan.command)
        val result = runShell(buildAdminStdinForwardingCommand("exec sh -s", shell = "sh"), plan.stdinPayload)
        assertEquals(0, result.exitCode)
        assertEquals("ready", result.stdout)
    }

    @Test
    fun longRootScriptTravelsOverStdinWithoutExceedingArgumentLimit() {
        val script = "printf 'probe-ok\\n'\n" + "v='x'\n".repeat(4_000)
        val original = rootCommand(script)
        assertTrue(original.length in 50_000..130_000)
        assertTrue(buildAdminRootStdinExecPlan(original, "sudo-secret", "", shell = "sh").command.length > 131_072)
        val plan = buildSshExecStdinPlan(original, "sudo-secret")!!
        assertTrue(plan.command.length < 2_000)
        assertFalse(original in plan.command)
        assertTrue(original in plan.stdinPayload)

        val directory = Files.createTempDirectory("wdtt-long-ssh-script-").toFile()
        try {
            val fakeId = directory.resolve("id")
            fakeId.writeText("#!/bin/sh\nprintf '0\\n'\n")
            assertTrue(fakeId.setExecutable(true))
            val result = runShell(
                plan.command,
                plan.stdinPayload,
                mapOf("PATH" to "${directory.absolutePath}:${System.getenv("PATH")}"),
            )
            assertEquals(0, result.exitCode)
            assertEquals("probe-ok\n", result.stdout)
            assertEquals("", result.stderr)
        } finally {
            directory.deleteRecursively()
        }
    }

    private fun runShell(command: String, input: String): ShellResult {
        return runShell(command, input, emptyMap())
    }

    private fun runPlanWithFakePrivileges(sudoScript: String, uid: Int = 1000): ShellResult {
        val directory = Files.createTempDirectory("wdtt-admin-sudo-test-").toFile()
        return try {
            val fakeId = directory.resolve("id")
            fakeId.writeText("#!/bin/sh\nprintf '$uid\\n'\n")
            assertTrue(fakeId.setExecutable(true))
            val fakeSudo = directory.resolve("sudo")
            fakeSudo.writeText("$sudoScript\n")
            assertTrue(fakeSudo.setExecutable(true))
            val plan = buildAdminRootStdinExecPlan("cat", "sudo-secret", request)
            runShell(
                command = plan.command,
                input = plan.stdinPayload,
                environment = mapOf("PATH" to "${directory.absolutePath}:${System.getenv("PATH")}"),
            )
        } finally {
            directory.deleteRecursively()
        }
    }

    private fun runShell(command: String, input: String, environment: Map<String, String>): ShellResult {
        val builder = ProcessBuilder("bash", "-c", command)
        builder.environment().putAll(environment)
        val process = builder.start()
        process.outputStream.bufferedWriter().use { it.write(input) }
        val stdout = process.inputStream.bufferedReader().use { it.readText() }
        val stderr = process.errorStream.bufferedReader().use { it.readText() }
        return ShellResult(process.waitFor(), stdout, stderr)
    }

    private data class ShellResult(
        val exitCode: Int,
        val stdout: String,
        val stderr: String,
    )
}
