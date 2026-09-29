package com.wdtt.plus.ui

import java.nio.file.Files
import org.junit.Assert.*
import org.junit.Test

class ExternalProxyDiagnosticsTest {
    private fun probe(scenario: String): Pair<Int, String> {
        val dir = Files.createTempDirectory("proxy-probe-test").toFile()
        try {
            fun executable(name: String, body: String) = dir.resolve(name).apply {
                writeText("#!/bin/sh\n$body\n")
                setExecutable(true)
            }
            executable("systemctl", "exit 0")
            executable("iptables", """
                case "${'$'}*" in
                  *"-A WDTT_PROXY_TEST"*) [ "${'$'}SCENARIO" != rule_failure ] || exit 1 ;;
                  *"-L WDTT_PROXY_TEST"*)
                    if [ "${'$'}SCENARIO" = bypass ]; then echo '0 0 REDIRECT'; else echo '1 60 REDIRECT'; fi ;;
                esac
                exit 0
            """.trimIndent())
            executable("curl", """
                echo curl >>"${'$'}CALLS"
                [ "${'$'}1" = -q ] || exit 99
                case " ${'$'}* " in *" --proxy  --noproxy * --interface 10.66.66.1 "*) ;; *) exit 99 ;; esac
                case "${'$'}SCENARIO" in
                  fallback) case "${'$'}*" in *api.ipify.org*) exit 28 ;; esac ;;
                  partial) echo 198.51.100.2; exit 28 ;;
                  invalid) echo '<html>error</html>'; exit 0 ;;
                esac
                echo 198.51.100.2
            """.trimIndent())
            val script = dir.resolve("probe.sh").apply {
                writeText("""
                    set -e
                    wdtt_test_source() { echo 10.66.66.1; }
                    wdtt_cleanup_proxy_test() { echo cleanup >>"${'$'}CALLS"; }
                    wdtt_proxy_reserved_returns() { return 0; }
                    ${externalProxyProbeFunctions()}
                    if ! wdtt_test_redsocks_path 203.0.113.2; then exit 3; fi
                """.trimIndent())
            }
            val calls = dir.resolve("calls")
            val process = ProcessBuilder("sh", script.absolutePath).apply {
                environment()["PATH"] = dir.absolutePath + ":" + System.getenv("PATH")
                environment()["SCENARIO"] = scenario
                environment()["CALLS"] = calls.absolutePath
                redirectErrorStream(true)
            }.start()
            val output = process.inputStream.bufferedReader().readText()
            val result = process.waitFor()
            val events = calls.readLines()
            assertEquals("Cleanup before and after every probe", 2, events.count { it == "cleanup" })
            if (scenario == "rule_failure") assertFalse(events.contains("curl"))
            if (scenario == "fallback") assertEquals(2, events.count { it == "curl" })
            return result to output
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun alternativeSiteCanVerifyRedirectedConnection() {
        val (code, output) = probe("fallback")
        assertEquals(output, 0, code)
        assertTrue(output.contains("198.51.100.2"))
    }

    @Test fun failedRulesAndUnredirectedRequestsCannotPass() {
        for ((scenario, marker) in listOf(
            "rule_failure" to "external_proxy_test_rule_failed",
            "bypass" to "external_proxy_test_not_redirected",
        )) {
            val (code, output) = probe(scenario)
            assertEquals(output, 3, code)
            assertTrue(output.contains("WDTT_ERROR=$marker"))
        }
    }

    @Test fun partialCurlOutputAndHtmlAreNotSuccessfulChecks() {
        for (scenario in listOf("partial", "invalid")) {
            val (code, output) = probe(scenario)
            assertEquals(output, 3, code)
            assertTrue(output.contains("WDTT_ERROR=external_proxy_apply_failed"))
        }
    }

    @Test fun currentErrorSurvivesLongProgressAndDoesNotClaimDirectSuccess() {
        val excerpt = rootScriptErrorExcerpt("WDTT_PROGRESS|0.1|install\n".repeat(100) +
            "WDTT_ERROR=external_proxy_apply_failed\nWDTT_PROXY_CURL_EXIT=28\n")
        assertTrue(excerpt.startsWith("WDTT_ERROR="))
        val message = externalProxyFailureMessage(excerpt)
        assertTrue(message.contains("врем"))
        assertFalse(message.contains("отвечает напрямую"))
        assertFalse(message.contains("redsocks_drop_client"))
    }
}
