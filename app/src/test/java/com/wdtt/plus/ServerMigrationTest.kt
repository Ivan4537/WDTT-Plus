package com.wdtt.plus

import java.security.MessageDigest
import java.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ServerMigrationTest {
    @Test
    fun currentServerSnapshotWithBackupPolicyIsAccepted() {
        fun file(path: String, value: String): JSONObject {
            val data = value.toByteArray()
            val sha256 = MessageDigest.getInstance("SHA-256")
                .digest(data)
                .joinToString("") { "%02x".format(it) }
            return JSONObject()
                .put("path", path)
                .put("mode", 384)
                .put("size", data.size)
                .put("sha256", sha256)
                .put("data_b64", Base64.getEncoder().encodeToString(data))
        }
        val keys = List(4) { "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" }.joinToString("\n")
        val response = JSONObject()
            .put("format", "wdtt-server-snapshot")
            .put("version", 3)
            .put("id", "20260902T151523Z-d43d8a6dd6ab")
            .put("created_at", 1_778_000_000L)
            .put("reason", "manual")
            .put("server_version", "16")
            .put("password_count", 0)
            .put("device_count", 0)
            .put(
                "files",
                JSONArray()
                    .put(file("passwords.json", "{}"))
                    .put(file("wg-keys.dat", keys))
                    .put(file("backup-policy.json", "{\"enabled\":false,\"interval_hours\":24,\"retention_count\":14}"))
            )

        val parsed = ServerAdminClient.parseBackupDocument(response)

        assertEquals(3, parsed.files.size)
        assertTrue(parsed.files.any { it.path == "backup-policy.json" })
    }

    @Test
    fun skippedVersionsAccumulateLatestServerMigration() {
        val result = resolveServerMigrationInitialization(
            currentVersionCode = 8,
            isUpdatedInstall = true,
            storedLastSeenAppVersionCode = 3,
            storedPendingLevel = 0,
            storedAcknowledgedLevel = 3,
            legacyAcknowledgedLevel = 3
        )

        assertEquals(7, result.pendingLevel)
        assertEquals(3, result.acknowledgedLevel)
    }

    @Test
    fun legacyFlagsPreventAlreadySeenNoticesButNotLaterMigrations() {
        val result = resolveServerMigrationInitialization(
            currentVersionCode = 8,
            isUpdatedInstall = true,
            storedLastSeenAppVersionCode = null,
            storedPendingLevel = 0,
            storedAcknowledgedLevel = null,
            legacyAcknowledgedLevel = 5
        )

        assertEquals(7, result.pendingLevel)
        assertEquals(5, result.acknowledgedLevel)
    }

    @Test
    fun freshInstallDoesNotRequireServerMigration() {
        val result = resolveServerMigrationInitialization(
            currentVersionCode = 8,
            isUpdatedInstall = false,
            storedLastSeenAppVersionCode = null,
            storedPendingLevel = 0,
            storedAcknowledgedLevel = null,
            legacyAcknowledgedLevel = 0
        )

        assertEquals(0, result.pendingLevel)
        assertEquals(8, result.lastSeenAppVersionCode)
    }

    @Test
    fun appVersionWithoutServerChangesDoesNotCreateNewNotice() {
        val result = resolveServerMigrationInitialization(
            currentVersionCode = 8,
            isUpdatedInstall = true,
            storedLastSeenAppVersionCode = 7,
            storedPendingLevel = 7,
            storedAcknowledgedLevel = 7,
            legacyAcknowledgedLevel = 5
        )

        assertEquals(7, result.pendingLevel)
        assertEquals(7, result.acknowledgedLevel)
    }

    @Test
    fun updateFrom13To14RequiresServerMigration() {
        val result = resolveServerMigrationInitialization(
            currentVersionCode = 14,
            isUpdatedInstall = true,
            storedLastSeenAppVersionCode = 13,
            storedPendingLevel = 12,
            storedAcknowledgedLevel = 12,
            legacyAcknowledgedLevel = 5
        )

        assertEquals(14, result.pendingLevel)
        assertEquals(12, result.acknowledgedLevel)
        assertEquals(14, latestServerMigrationLevel(14))
    }

    @Test
    fun updateFrom14To15RequiresServerMigration() {
        val result = resolveServerMigrationInitialization(
            currentVersionCode = 15,
            isUpdatedInstall = true,
            storedLastSeenAppVersionCode = 14,
            storedPendingLevel = 14,
            storedAcknowledgedLevel = 14,
            legacyAcknowledgedLevel = 5
        )

        assertEquals(15, result.pendingLevel)
        assertEquals(14, result.acknowledgedLevel)
        assertEquals(15, latestServerMigrationLevel(15))
    }

    @Test
    fun updateFrom15To16RequiresServerMigration() {
        val result = resolveServerMigrationInitialization(
            currentVersionCode = 16,
            isUpdatedInstall = true,
            storedLastSeenAppVersionCode = 15,
            storedPendingLevel = 15,
            storedAcknowledgedLevel = 15,
            legacyAcknowledgedLevel = 5
        )

        assertEquals(16, result.pendingLevel)
        assertEquals(15, result.acknowledgedLevel)
        assertEquals(16, latestServerMigrationLevel(16))
    }

    @Test
    fun updateFrom16To17RequiresServerMigration() {
        val result = resolveServerMigrationInitialization(
            currentVersionCode = 17,
            isUpdatedInstall = true,
            storedLastSeenAppVersionCode = 16,
            storedPendingLevel = 16,
            storedAcknowledgedLevel = 16,
            legacyAcknowledgedLevel = 5
        )

        assertEquals(17, result.pendingLevel)
        assertEquals(16, result.acknowledgedLevel)
        assertEquals(17, latestServerMigrationLevel(17))
    }

    @Test
    fun reinstallSameVersionDoesNotCreateServerMigrationNotice() {
        val result = resolveServerMigrationInitialization(
            currentVersionCode = 16,
            isUpdatedInstall = true,
            storedLastSeenAppVersionCode = 16,
            storedPendingLevel = 15,
            storedAcknowledgedLevel = 15,
            legacyAcknowledgedLevel = 5
        )

        assertEquals(15, result.pendingLevel)
        assertEquals(15, result.acknowledgedLevel)
        assertEquals(16, latestServerMigrationLevel(16))
    }

    @Test
    fun stateSeparatesReadNoticeFromCompletedDeployment() {
        val state = ServerMigrationState(
            pendingLevel = 7,
            acknowledgedLevel = 7,
            completedLevel = 5
        )

        assertFalse(state.noticeRequired)
        assertTrue(state.profileUpdateRequired)
    }

    @Test
    fun serverNoticeRequiresBothSshAndOwnerCredentials() {
        assertTrue(hasManagedServerCredentials("example.org", "password", "ssh-password", "owner-password"))
        assertFalse(hasManagedServerCredentials("example.org", "password", "", "owner-password"))
        assertFalse(hasManagedServerCredentials("example.org", "password", "ssh-password", ""))
        assertFalse(hasManagedServerCredentials("", "password", "ssh-password", "owner-password"))
        val key = "-----BEGIN OPENSSH PRIVATE KEY-----\ndGVzdA==\n-----END OPENSSH PRIVATE KEY-----"
        assertTrue(hasManagedServerCredentials("example.org", "key", "", "owner-password", key))
        assertFalse(hasManagedServerCredentials("example.org", "key", "sudo-password", "owner-password", ""))
        assertFalse(hasManagedServerCredentials("example.org", "password", "", "owner-password", key))
    }
}
