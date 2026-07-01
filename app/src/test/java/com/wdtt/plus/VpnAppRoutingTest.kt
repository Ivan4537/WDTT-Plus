package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnAppRoutingTest {
    private val ownPackage = "com.wdtt.plus"
    private val installed = setOf(
        ownPackage,
        "com.vkontakte.android",
        "com.vk.calls",
        "app.one",
        "app.two"
    )

    @Test
    fun blacklistExcludesSelectedAndRequiredPackages() {
        val routing = resolveVpnAppRouting(
            isWhitelist = false,
            selectedPackages = setOf("app.one", "missing.app"),
            installedPackages = installed,
            ownPackageName = ownPackage
        )

        assertTrue(routing.included.isEmpty())
        assertEquals(
            setOf(ownPackage, "com.vkontakte.android", "com.vk.calls", "app.one"),
            routing.excluded
        )
    }

    @Test
    fun whitelistIncludesOnlySelectedInstalledApps() {
        val routing = resolveVpnAppRouting(
            isWhitelist = true,
            selectedPackages = setOf("app.two", "com.vkontakte.android", "missing.app"),
            installedPackages = installed,
            ownPackageName = ownPackage
        )

        assertEquals(setOf("app.two"), routing.included)
        assertTrue(routing.excluded.isEmpty())
    }

    @Test
    fun emptyWhitelistExplicitlyExcludesAllApps() {
        val routing = resolveVpnAppRouting(
            isWhitelist = true,
            selectedPackages = emptySet(),
            installedPackages = installed,
            ownPackageName = ownPackage
        )

        assertTrue(routing.included.isEmpty())
        assertEquals(installed, routing.excluded)
    }
}
