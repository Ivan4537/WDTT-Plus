package com.wdtt.plus

internal const val VPN_DNS_PROFILE_ID = "profile"
internal const val VPN_DNS_CUSTOM_ID = "custom"
internal const val MAX_CUSTOM_VPN_DNS_SERVERS = 2

internal enum class VpnDnsCategory {
    STANDARD,
    SMART,
}

internal data class VpnDnsPreset(
    val id: String,
    val title: String,
    val servers: List<String>,
    val category: VpnDnsCategory,
    val description: String,
)

internal val vpnDnsPresets = listOf(
    VpnDnsPreset(
        id = "cloudflare",
        title = "Cloudflare",
        servers = listOf("1.1.1.1", "1.0.0.1"),
        category = VpnDnsCategory.STANDARD,
        description = "Обычный DNS без фильтрации содержимого.",
    ),
    VpnDnsPreset(
        id = "google",
        title = "Google DNS",
        servers = listOf("8.8.8.8", "8.8.4.4"),
        category = VpnDnsCategory.STANDARD,
        description = "Обычный публичный DNS без фильтрации содержимого.",
    ),
    VpnDnsPreset(
        id = "quad9",
        title = "Quad9",
        servers = listOf("9.9.9.9", "149.112.112.112"),
        category = VpnDnsCategory.STANDARD,
        description = "Блокирует известные вредоносные домены.",
    ),
    VpnDnsPreset(
        id = "adguard",
        title = "AdGuard DNS",
        servers = listOf("94.140.14.14", "94.140.15.15"),
        category = VpnDnsCategory.STANDARD,
        description = "Блокирует рекламу, трекеры и фишинговые домены.",
    ),
    VpnDnsPreset(
        id = "xbox",
        title = "Xbox DNS",
        servers = listOf("111.88.96.50", "111.88.96.51"),
        category = VpnDnsCategory.SMART,
        description = "Сторонний Smart DNS для отдельных сервисов и игр.",
    ),
    VpnDnsPreset(
        id = "comss",
        title = "Comss.one DNS",
        servers = listOf("83.220.169.155", "212.109.195.93"),
        category = VpnDnsCategory.SMART,
        description = "Сторонний Smart DNS для ИИ-сервисов с фильтрацией.",
    ),
)

internal data class VpnDnsSettingsSnapshot(
    val profileIndex: Int,
    val selectionId: String = VPN_DNS_PROFILE_ID,
    val customServers: List<String> = emptyList(),
) {
    val preset: VpnDnsPreset?
        get() = vpnDnsPresets.firstOrNull { it.id == selectionId }

    val isSmartDns: Boolean
        get() = preset?.category == VpnDnsCategory.SMART

    val title: String
        get() = when (selectionId) {
            VPN_DNS_PROFILE_ID -> "Как в профиле"
            VPN_DNS_CUSTOM_ID -> "Свой DNS"
            else -> preset?.title ?: "Как в профиле"
        }

    val configuredServers: List<String>
        get() = when (selectionId) {
            VPN_DNS_PROFILE_ID -> emptyList()
            VPN_DNS_CUSTOM_ID -> customServers
            else -> preset?.servers.orEmpty()
        }
}

internal data class EffectiveVpnDns(
    val servers: List<String>,
    val selectionId: String,
    val title: String,
    val isSmartDns: Boolean,
    val fellBackToProfile: Boolean = false,
)

internal fun vpnDnsAppliedLogMessage(
    profileName: String,
    effectiveDns: EffectiveVpnDns,
): String = buildString {
    append('«')
    append(profileName.ifBlank { "Профиль" })
    append("»: ")
    val modeTitle = if (effectiveDns.selectionId == VPN_DNS_PROFILE_ID) {
        "DNS из WireGuard-профиля"
    } else {
        effectiveDns.title
    }
    append(modeTitle)
    if (effectiveDns.servers.isEmpty()) {
        append(" не задан; Android использует DNS основной сети.")
    } else {
        append(" используется внутри VPN: ")
        append(effectiveDns.servers.joinToString(", "))
        append('.')
    }
    if (effectiveDns.isSmartDns) {
        append(" Это сторонний Smart DNS: часть сервисов может идти через его шлюзы.")
    }
    if (effectiveDns.fellBackToProfile) {
        append(" Свой DNS был некорректен, поэтому безопасно включён DNS из WireGuard-профиля.")
    }
}

internal fun normalizeVpnDnsSelectionId(value: String?): String {
    val normalized = value?.trim()?.lowercase().orEmpty()
    return when {
        normalized == VPN_DNS_PROFILE_ID -> VPN_DNS_PROFILE_ID
        normalized == VPN_DNS_CUSTOM_ID -> VPN_DNS_CUSTOM_ID
        vpnDnsPresets.any { it.id == normalized } -> normalized
        else -> VPN_DNS_PROFILE_ID
    }
}

internal fun normalizeCustomVpnDnsServers(raw: String): List<String> {
    val values = raw
        .split(Regex("[,;\\s]+"))
        .map(String::trim)
        .filter(String::isNotEmpty)
    require(values.isNotEmpty()) { "Укажите хотя бы один IPv4-адрес DNS." }
    require(values.size <= MAX_CUSTOM_VPN_DNS_SERVERS) {
        "Можно указать не больше двух DNS-серверов."
    }
    return values.map(::normalizeVpnDnsIpv4).distinct().also { normalized ->
        require(normalized.isNotEmpty()) { "Укажите хотя бы один IPv4-адрес DNS." }
    }
}

internal fun decodeStoredCustomVpnDnsServers(raw: String): List<String> =
    runCatching { normalizeCustomVpnDnsServers(raw) }.getOrDefault(emptyList())

internal fun isIpv4Literal(value: String): Boolean {
    val parts = value.split('.')
    return parts.size == 4 && parts.all { part ->
        part.isNotEmpty() &&
            part.length <= 3 &&
            part.all(Char::isDigit) &&
            (part.length == 1 || part.first() != '0') &&
            (part.toIntOrNull()?.let { it in 0..255 } == true)
    }
}

internal fun resolveEffectiveVpnDns(
    settings: VpnDnsSettingsSnapshot,
    profileServers: List<String>,
): EffectiveVpnDns {
    val normalizedSelection = normalizeVpnDnsSelectionId(settings.selectionId)
    val preset = vpnDnsPresets.firstOrNull { it.id == normalizedSelection }
    val selectedServers = when (normalizedSelection) {
        VPN_DNS_PROFILE_ID -> profileServers
        VPN_DNS_CUSTOM_ID -> settings.customServers
        else -> preset?.servers.orEmpty()
    }
    val customInvalid = normalizedSelection == VPN_DNS_CUSTOM_ID && selectedServers.isEmpty()
    return if (customInvalid) {
        EffectiveVpnDns(
            servers = profileServers,
            selectionId = VPN_DNS_PROFILE_ID,
            title = "Как в профиле",
            isSmartDns = false,
            fellBackToProfile = true,
        )
    } else {
        EffectiveVpnDns(
            servers = selectedServers.distinct(),
            selectionId = normalizedSelection,
            title = when (normalizedSelection) {
                VPN_DNS_PROFILE_ID -> "Как в профиле"
                VPN_DNS_CUSTOM_ID -> "Свой DNS"
                else -> preset?.title ?: "Как в профиле"
            },
            isSmartDns = preset?.category == VpnDnsCategory.SMART,
        )
    }
}

private fun normalizeVpnDnsIpv4(value: String): String {
    val parts = value.split('.')
    require(parts.size == 4) { "Некорректный IPv4-адрес DNS: $value" }
    val octets = parts.map { part ->
        require(part.isNotEmpty() && part.length <= 3 && part.all(Char::isDigit)) {
            "Некорректный IPv4-адрес DNS: $value"
        }
        require(part.length == 1 || part.first() != '0') {
            "Некорректный IPv4-адрес DNS: $value"
        }
        part.toInt().also { octet ->
            require(octet in 0..255) { "Некорректный IPv4-адрес DNS: $value" }
        }
    }
    require(octets != listOf(0, 0, 0, 0)) { "Адрес 0.0.0.0 нельзя использовать как DNS." }
    require(octets.first() != 127) { "Локальный адрес 127.0.0.0/8 нельзя использовать как DNS VPN." }
    require(octets.first() !in 224..239) { "Multicast-адрес нельзя использовать как DNS." }
    require(octets != listOf(255, 255, 255, 255)) { "Широковещательный адрес нельзя использовать как DNS." }
    return octets.joinToString(".")
}
