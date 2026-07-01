package com.wdtt.plus

internal val ALWAYS_BYPASSED_VPN_PACKAGES = setOf(
    "com.vkontakte.android",
    "com.vk.calls"
)

internal fun isAlwaysBypassedVpnPackage(packageName: String, ownPackageName: String): Boolean {
    return packageName == ownPackageName || packageName in ALWAYS_BYPASSED_VPN_PACKAGES
}

internal data class VpnAppRouting(
    val included: Set<String> = emptySet(),
    val excluded: Set<String> = emptySet()
)

internal fun resolveVpnAppRouting(
    isWhitelist: Boolean,
    selectedPackages: Set<String>,
    installedPackages: Set<String>,
    ownPackageName: String
): VpnAppRouting {
    val alwaysBypassed = (ALWAYS_BYPASSED_VPN_PACKAGES + ownPackageName)
        .intersect(installedPackages)
    val selectedInstalled = selectedPackages
        .intersect(installedPackages)
        .minus(alwaysBypassed)

    if (!isWhitelist) {
        return VpnAppRouting(excluded = alwaysBypassed + selectedInstalled)
    }

    // Пустой allowed-list в Android означает «ограничение не задано», то есть весь трафик.
    // Поэтому для пустого БС явно исключаем все установленные пакеты.
    return if (selectedInstalled.isEmpty()) {
        VpnAppRouting(excluded = installedPackages)
    } else {
        VpnAppRouting(included = selectedInstalled)
    }
}
