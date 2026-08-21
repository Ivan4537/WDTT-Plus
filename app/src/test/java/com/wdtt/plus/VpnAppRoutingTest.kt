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
    fun emptyWhitelistRemovesAllPeerRoutes() {
        val routing = resolveVpnAppRouting(
            isWhitelist = true,
            selectedPackages = emptySet(),
            installedPackages = installed,
            ownPackageName = ownPackage
        )

        assertTrue(routing.included.isEmpty())
        assertTrue(routing.excluded.isEmpty())
        assertTrue(routing.blocksAllApps)
        assertTrue(
            applyVpnAppRoutingToAllowedIps(routing, listOf("0.0.0.0/0")).isEmpty()
        )
    }

    @Test
    fun addressOnlyWhitelistLeavesAppsEligibleButKeepsRequiredBypasses() {
        val routing = resolveVpnAppRouting(
            isWhitelist = true,
            selectedPackages = emptySet(),
            installedPackages = installed,
            ownPackageName = ownPackage,
            addressWhitelistConfigured = true,
        )

        assertTrue(routing.included.isEmpty())
        assertEquals(
            setOf(ownPackage, "com.vkontakte.android", "com.vk.calls"),
            routing.excluded,
        )
        assertTrue(!routing.blocksAllApps)
    }

    @Test
    fun missingConfiguredWhitelistAppDoesNotBroadenAddressRulesToEveryApp() {
        val routing = resolveVpnAppRouting(
            isWhitelist = true,
            selectedPackages = setOf("app.from.other.phone"),
            installedPackages = installed,
            ownPackageName = ownPackage,
            addressWhitelistConfigured = true,
        )

        assertTrue(routing.included.isEmpty())
        assertTrue(routing.excluded.isEmpty())
        assertTrue(routing.blocksAllApps)
        assertTrue(
            applyVpnAppRoutingToAllowedIps(routing, listOf("10.0.0.0/8")).isEmpty()
        )
    }

    @Test
    fun importedRoutingCannotKeepHiddenRequiredBypassPackages() {
        assertEquals(
            listOf("app.one", "app.two"),
            sanitizeVpnRoutingPackages(
                packageNames = listOf(
                    ownPackage,
                    "com.vkontakte.android",
                    "com.vk.calls",
                    "app.two",
                    " app.one ",
                    "app.two",
                ),
                ownPackageName = ownPackage,
            ),
        )
    }

    @Test
    fun routingReloadOnlyTargetsTheActuallyRunningProfile() {
        assertTrue(shouldReloadWireGuardRouting(true, activeTunnelProfile = 1, changedProfile = 1))
        assertTrue(!shouldReloadWireGuardRouting(true, activeTunnelProfile = 1, changedProfile = 0))
        assertTrue(!shouldReloadWireGuardRouting(false, activeTunnelProfile = 1, changedProfile = 1))
        assertTrue(!shouldReloadWireGuardRouting(true, activeTunnelProfile = null, changedProfile = 1))
        assertTrue(!shouldReloadWireGuardRouting(true, activeTunnelProfile = 2, changedProfile = 99))
    }
}
