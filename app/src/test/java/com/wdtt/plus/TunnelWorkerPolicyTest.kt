package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Test

class TunnelWorkerPolicyTest {
    @Test
    fun profilePolicyCapsOnlyTheProfileThatCarriesIt() {
        assertEquals(9, normalizeTunnelWorkerCount(1, profileMaxWorkers = 9))
        assertEquals(9, normalizeTunnelWorkerCount(27, profileMaxWorkers = 9))
        assertEquals(18, normalizeTunnelWorkerCount(27, profileMaxWorkers = 18))
    }

    @Test
    fun profileWithoutPolicyRetainsFullPowerRange() {
        assertEquals(18, normalizeTunnelWorkerCount(16))
        assertEquals(108, normalizeTunnelWorkerCount(108))
        assertEquals(108, normalizeTunnelWorkerCount(500))
    }

    @Test
    fun managedProfileRisesOnceWhenItsCeilingRises() {
        assertEquals(
            18,
            reconcileTunnelWorkerCountForProfileLimit(
                selectedWorkers = 9,
                previousProfileMaxWorkers = 9,
                currentProfileMaxWorkers = 18,
                remoteManaged = true,
            ),
        )
    }

    @Test
    fun manualChoiceIsKeptAfterNewCeilingWasSeen() {
        assertEquals(
            9,
            reconcileTunnelWorkerCountForProfileLimit(
                selectedWorkers = 9,
                previousProfileMaxWorkers = 18,
                currentProfileMaxWorkers = 18,
                remoteManaged = true,
            ),
        )
    }

    @Test
    fun firstRunAfterAnOlderAppReceivedTheLimitUsesTheNewCeiling() {
        assertEquals(
            18,
            reconcileTunnelWorkerCountForProfileLimit(
                selectedWorkers = 9,
                previousProfileMaxWorkers = null,
                currentProfileMaxWorkers = 18,
                remoteManaged = true,
            ),
        )
    }

    @Test
    fun ordinaryProfileDoesNotAutoPromote() {
        assertEquals(
            9,
            reconcileTunnelWorkerCountForProfileLimit(
                selectedWorkers = 9,
                previousProfileMaxWorkers = 9,
                currentProfileMaxWorkers = 18,
                remoteManaged = false,
            ),
        )
    }
}
