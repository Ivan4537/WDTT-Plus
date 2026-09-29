package com.wdtt.plus.ui

import org.junit.Assert.*
import org.junit.Test

class DeployRootAccessTest {
    @Test
    fun confirmedRootAccessIsAccepted() {
        validateRootAccessOutput("WDTT_ROOT_ACCESS=ok\n")
    }

    @Test
    fun timeoutIsReportedAsTimeoutRatherThanMissingRoot() {
        val error = assertThrows(IllegalStateException::class.java) {
            validateRootAccessOutput("error: timeout")
        }
        assertTrue(friendlyDeployError(error, "проверка сервера").contains("не ответил вовремя"))
        assertFalse(error.message.orEmpty().contains("sudo"))
    }

    @Test
    fun brokenChannelIsReportedAsConnectionFailure() {
        for (failure in listOf("session is down", "Pipe closed", "Broken pipe", "Socket closed", "Connection reset", "channel is not opened")) {
            val error = assertThrows(IllegalStateException::class.java) {
                validateRootAccessOutput("error: $failure")
            }
            assertTrue(friendlyDeployError(error, "проверка сервера").contains("SSH-сессия оборвалась"))
        }
    }

    @Test
    fun missingAnswerDoesNotClaimPermissionDenial() {
        for (output in listOf("", "partial response", "WDTT_ROOT_ACCESS=")) {
            val error = assertThrows(IllegalStateException::class.java) { validateRootAccessOutput(output) }
            assertTrue(error.message.orEmpty().contains("не подтвердил проверку"))
            assertFalse(error.message.orEmpty().contains("root-права не получены"))
        }
    }

    @Test
    fun rootMarkerDoesNotHideCommandFailure() {
        assertThrows(IllegalStateException::class.java) {
            validateRootAccessOutput("WDTT_ROOT_ACCESS=ok\nerror: remote command exited with code 1\n")
        }
    }

    @Test
    fun actualSudoDenialKeepsPermissionGuidance() {
        for (output in listOf("sudo: 1 incorrect password attempt", "user is not in the sudoers file", "error: root privileges required and sudo not found")) {
            val error = assertThrows(IllegalStateException::class.java) { validateRootAccessOutput(output) }
            assertTrue(error.message.orEmpty().contains("sudo"))
        }
    }
}
