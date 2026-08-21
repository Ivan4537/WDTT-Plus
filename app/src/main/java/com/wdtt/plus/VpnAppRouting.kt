package com.wdtt.plus

internal val ALWAYS_BYPASSED_VPN_PACKAGES = setOf(
    "com.vkontakte.android",
    "com.vk.calls"
)

internal fun isAlwaysBypassedVpnPackage(packageName: String, ownPackageName: String): Boolean {
    return packageName == ownPackageName || packageName in ALWAYS_BYPASSED_VPN_PACKAGES
}

internal fun sanitizeVpnRoutingPackages(
    packageNames: Collection<String>,
    ownPackageName: String,
): List<String> = packageNames
    .asSequence()
    .map(String::trim)
    .filter(String::isNotEmpty)
    .filterNot { isAlwaysBypassedVpnPackage(it, ownPackageName) }
    .distinct()
    .sorted()
    .toList()

internal data class VpnAppRouting(
    val included: Set<String> = emptySet(),
    val excluded: Set<String> = emptySet(),
    val blocksAllApps: Boolean = false,
)

internal fun applyVpnAppRoutingToAllowedIps(
    routing: VpnAppRouting,
    allowedIps: List<String>,
): List<String> = if (routing.blocksAllApps) emptyList() else allowedIps

internal fun resolveVpnAppRouting(
    isWhitelist: Boolean,
    selectedPackages: Set<String>,
    installedPackages: Set<String>,
    ownPackageName: String,
    addressWhitelistConfigured: Boolean = false,
): VpnAppRouting {
    val alwaysBypassed = (ALWAYS_BYPASSED_VPN_PACKAGES + ownPackageName)
        .intersect(installedPackages)
    val selectedInstalled = selectedPackages
        .intersect(installedPackages)
        .minus(alwaysBypassed)
    val hasConfiguredSelectablePackages = selectedPackages.any {
        !isAlwaysBypassedVpnPackage(it, ownPackageName)
    }

    if (!isWhitelist) {
        return VpnAppRouting(excluded = alwaysBypassed + selectedInstalled)
    }

    // Если БС адресов заполнен, а приложений нет, адресные правила применяются ко всем
    // приложениям, кроме обязательных исключений. Если обе категории пусты, не разрешаем
    // Android трактовать пустой список приложений как «все приложения». В закрытом
    // состоянии не перечисляем установленные пакеты: список устареет после установки
    // нового приложения. Вместо этого вызывающий код оставляет peer без маршрутов.
    return if (selectedInstalled.isEmpty()) {
        if (addressWhitelistConfigured && !hasConfiguredSelectablePackages) {
            VpnAppRouting(excluded = alwaysBypassed)
        } else {
            VpnAppRouting(blocksAllApps = true)
        }
    } else {
        VpnAppRouting(included = selectedInstalled)
    }
}
