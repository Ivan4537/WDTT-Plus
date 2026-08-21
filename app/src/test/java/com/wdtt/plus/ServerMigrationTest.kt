package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ServerMigrationTest {
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
