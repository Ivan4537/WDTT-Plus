package com.wdtt.plus

import org.json.JSONArray
import org.json.JSONObject
import java.net.IDN

internal const val MAX_VPN_ADDRESS_RULES = 128
internal const val MAX_VPN_ADDRESS_IMPORT_BYTES = 1024 * 1024
private const val MAX_WIREGUARD_ALLOWED_IPS = 4096
private const val MAX_EFFECTIVE_IPV4_PREFIXES = 128
private const val IPV4_BITS = 32
private const val IPV4_MAX = 0xffff_ffffL

internal enum class VpnAddressType(val storedValue: String) {
    DOMAIN("domain"),
    IP("ip"),
    SUBNET("subnet");

    companion object {
        fun fromStoredValue(value: String): VpnAddressType? =
            entries.firstOrNull { it.storedValue == value }
    }
}

internal data class VpnAddressRule(
    val type: VpnAddressType,
    val value: String,
)

internal data class VpnAddressRoutingResult(
    val allowedIps: List<String>,
    val unresolvedDomains: List<String> = emptyList(),
)

internal fun effectiveWireGuardAllowedIps(
    isWhitelist: Boolean,
    addressRulesConfigured: Boolean,
    addressRouting: VpnAddressRoutingResult,
    vpnDnsIpv4: List<String>,
): List<String> = buildList {
    addAll(addressRouting.allowedIps)
    if (addressRulesConfigured) {
        // Android sends DNS to the addresses configured on the VPN interface.
        // Keep those exact destinations in the tunnel even if an address rule
        // would otherwise route them directly.
        vpnDnsIpv4.forEach { dns ->
            parseIpv4(dns)?.let { add("${formatIpv4(it)}/32") }
        }
    }
    if (
        !isWhitelist &&
        addressRulesConfigured &&
        "0.0.0.0/0" !in addressRouting.allowedIps
    ) {
        // GoBackend включает общий kill-switch при любом /0. Поэтом ::/0
        // заблокировал бы и те IPv4-адреса, которые пользователь вынес в ЧС.
        // Два /1 закрывают всё IPv6 через VPN, но оставляют IPv4 split-route
        // рабочим: исключённые IPv4 продолжают идти напрямую.
        add("::/1")
        add("8000::/1")
    }
}.distinct()

internal data class VpnRoutingDocument(
    val isWhitelist: Boolean,
    val blacklistApps: List<String>,
    val whitelistApps: List<String>,
    val blacklistAddresses: List<VpnAddressRule>,
    val whitelistAddresses: List<VpnAddressRule>,
)

internal fun encodeVpnRoutingDocument(document: VpnRoutingDocument): String =
    JSONObject().apply {
        put("format", "wdtt-plus-routing")
        put("version", 1)
        put("isWhitelist", document.isWhitelist)
        put("blacklistApps", JSONArray(document.blacklistApps.distinct().sorted()))
        put("whitelistApps", JSONArray(document.whitelistApps.distinct().sorted()))
        put("blacklistAddresses", JSONArray(encodeVpnAddressRules(document.blacklistAddresses)))
        put("whitelistAddresses", JSONArray(encodeVpnAddressRules(document.whitelistAddresses)))
    }.toString(2)

internal fun decodeVpnRoutingDocument(raw: String): VpnRoutingDocument {
    require(raw.toByteArray(Charsets.UTF_8).size <= MAX_VPN_ADDRESS_IMPORT_BYTES) {
        "Файл маршрутизации слишком большой."
    }
    val root = runCatching { JSONObject(raw) }
        .getOrElse { throw IllegalArgumentException("Файл маршрутизации повреждён.") }
    require(root.optString("format") == "wdtt-plus-routing" && root.optInt("version") == 1) {
        "Это не поддерживаемый файл маршрутизации WDTT Plus."
    }
    require(root.opt("isWhitelist") is Boolean) { "В файле повреждён режим ЧС/БС." }
    return VpnRoutingDocument(
        isWhitelist = root.getBoolean("isWhitelist"),
        blacklistApps = parseVpnPackagesJson(root, "blacklistApps"),
        whitelistApps = parseVpnPackagesJson(root, "whitelistApps"),
        blacklistAddresses = parseVpnAddressRulesJson(root, "blacklistAddresses"),
        whitelistAddresses = parseVpnAddressRulesJson(root, "whitelistAddresses"),
    )
}

internal fun decodeStoredVpnPackages(raw: String): List<String> =
    raw.split(',').map(String::trim).filter(String::isNotEmpty).distinct().sorted()

internal fun normalizeVpnAddressRule(
    rawValue: String,
    requestedType: VpnAddressType? = null,
): VpnAddressRule {
    val clean = rawValue.trim()
    require(clean.isNotEmpty()) { "Введите домен, IPv4-адрес или подсеть." }
    require(clean.length <= 512) { "Адрес слишком длинный." }
    require('*' !in clean) {
        "Маска домена требует DNS-перехвата и пока не поддерживается. Добавьте нужные поддомены отдельными строками."
    }
    val extractedHost = extractHttpHost(clean) ?: extractBareHostWithPort(clean)

    val type = requestedType ?: when {
        extractedHost != null && parseIpv4(extractedHost) != null -> VpnAddressType.IP
        extractedHost != null -> VpnAddressType.DOMAIN
        '/' in clean -> VpnAddressType.SUBNET
        parseIpv4(clean) != null -> VpnAddressType.IP
        else -> VpnAddressType.DOMAIN
    }

    return when (type) {
        VpnAddressType.IP -> {
            require(extractedHost != null || ':' !in clean) {
                "IPv6 пока не поддерживается; укажите IPv4-адрес."
            }
            val address = parseIpv4(extractedHost ?: clean)
                ?: throw IllegalArgumentException("Некорректный IPv4-адрес.")
            VpnAddressRule(type, formatIpv4(address))
        }

        VpnAddressType.SUBNET -> {
            require(':' !in clean) { "IPv6-подсети пока не поддерживаются; укажите IPv4/CIDR." }
            val prefix = parseIpv4Prefix(clean)
                ?: throw IllegalArgumentException("Некорректная IPv4-подсеть. Пример: 192.168.1.0/24.")
            VpnAddressRule(type, prefix.toCidr())
        }

        VpnAddressType.DOMAIN -> {
            val domain = normalizeDomain(extractedHost ?: clean)
            VpnAddressRule(type, domain)
        }
    }
}

internal fun normalizeVpnAddressRules(rawValue: String): List<VpnAddressRule> {
    val entries = rawValue.lineSequence()
        .map(String::trim)
        .filter(String::isNotEmpty)
        .toList()
    require(entries.isNotEmpty()) { "Введите хотя бы один адрес." }

    val rules = buildList {
        entries.forEachIndexed { index, entry ->
            val range = parseIpv4Range(entry)
            val normalized = if (range == null) {
                listOf(normalizeVpnAddressRule(entry))
            } else if (range.first == range.last) {
                listOf(VpnAddressRule(VpnAddressType.IP, formatIpv4(range.first)))
            } else {
                ipv4RangeToPrefixes(range.first, range.last).map { prefix ->
                    VpnAddressRule(VpnAddressType.SUBNET, prefix.toCidr())
                }
            }
            addAll(normalized)
            require(size <= MAX_VPN_ADDRESS_RULES) {
                "Адрес или диапазон в строке ${index + 1} создаёт слишком много правил; " +
                    "в одном списке допускается не больше $MAX_VPN_ADDRESS_RULES."
            }
        }
    }
    return rules.distinct()
}

internal fun encodeVpnAddressRules(rules: List<VpnAddressRule>): String =
    JSONArray().apply {
        rules.distinct().take(MAX_VPN_ADDRESS_RULES).forEach { rule ->
            put(
                JSONObject()
                    .put("type", rule.type.storedValue)
                    .put("value", rule.value)
            )
        }
    }.toString()

internal fun decodeVpnAddressRules(raw: String): List<VpnAddressRule> {
    if (raw.isBlank()) return emptyList()
    return runCatching {
        val array = JSONArray(raw)
        buildList {
            for (index in 0 until minOf(array.length(), MAX_VPN_ADDRESS_RULES)) {
                val item = array.optJSONObject(index) ?: continue
                val type = VpnAddressType.fromStoredValue(item.optString("type")) ?: continue
                runCatching {
                    normalizeVpnAddressRule(item.optString("value"), type)
                }.getOrNull()?.let(::add)
            }
        }.distinct()
    }.getOrDefault(emptyList())
}

internal fun decodeVpnAddressRulesStrict(raw: String): List<VpnAddressRule> {
    if (raw.isBlank()) return emptyList()
    val array = runCatching { JSONArray(raw) }
        .getOrElse { throw IllegalArgumentException("Список адресов повреждён.") }
    require(array.length() <= MAX_VPN_ADDRESS_RULES) {
        "В одном списке может быть не больше $MAX_VPN_ADDRESS_RULES адресов."
    }
    return buildList {
        for (index in 0 until array.length()) {
            val item = array.optJSONObject(index)
                ?: throw IllegalArgumentException("Запись адреса №${index + 1} повреждена.")
            val type = VpnAddressType.fromStoredValue(item.optString("type"))
                ?: throw IllegalArgumentException("Неизвестный тип адреса в записи №${index + 1}.")
            add(normalizeVpnAddressRule(item.optString("value"), type))
        }
    }.distinct()
}

internal fun resolveVpnAddressRouting(
    isWhitelist: Boolean,
    rules: List<VpnAddressRule>,
    domainResolver: (String) -> List<String>,
): VpnAddressRoutingResult {
    if (rules.isEmpty()) {
        return VpnAddressRoutingResult(allowedIps = listOf("0.0.0.0/0"))
    }

    val prefixes = linkedSetOf<Ipv4Prefix>()
    val unresolvedDomains = mutableListOf<String>()
    rules.forEach { rule ->
        when (rule.type) {
            VpnAddressType.IP -> parseIpv4(rule.value)?.let {
                prefixes += Ipv4Prefix(it, IPV4_BITS)
            }

            VpnAddressType.SUBNET -> parseIpv4Prefix(rule.value)?.let(prefixes::add)
            VpnAddressType.DOMAIN -> {
                val resolved = runCatching { domainResolver(rule.value) }
                    .getOrDefault(emptyList())
                    .mapNotNull(::parseIpv4)
                    .distinct()
                if (resolved.isEmpty()) {
                    unresolvedDomains += rule.value
                } else {
                    resolved.forEach { prefixes += Ipv4Prefix(it, IPV4_BITS) }
                }
            }
        }
    }

    val compactPrefixes = collapseIpv4Prefixes(prefixes)
    require(compactPrefixes.size <= MAX_EFFECTIVE_IPV4_PREFIXES) {
        "Домены и адреса дали слишком много IPv4-маршрутов (${compactPrefixes.size}). " +
            "Сократите список или объедините адреса в подсети."
    }
    val allowed = if (isWhitelist) {
        compactPrefixes
    } else {
        subtractIpv4Prefixes(
            source = listOf(Ipv4Prefix(0L, 0)),
            excluded = compactPrefixes,
        )
    }
    require(allowed.size <= MAX_WIREGUARD_ALLOWED_IPS) {
        "Список адресов создаёт слишком много маршрутов (${allowed.size}). Объедините адреса в подсети."
    }
    return VpnAddressRoutingResult(
        allowedIps = allowed.sortedWith(compareBy<Ipv4Prefix> { it.network }.thenBy { it.length })
            .map(Ipv4Prefix::toCidr),
        unresolvedDomains = unresolvedDomains,
    )
}

private fun normalizeDomain(rawValue: String): String {
    require(
        ':' !in rawValue ||
            rawValue.startsWith("http://", true) ||
            rawValue.startsWith("https://", true)
    ) {
        "Некорректный домен. Для IP используйте IPv4-адрес."
    }
    val candidate = if (rawValue.startsWith("http://", true) || rawValue.startsWith("https://", true)) {
        extractHttpHost(rawValue) ?: throw IllegalArgumentException("В ссылке не найден домен.")
    } else {
        require('/' !in rawValue && '?' !in rawValue && '#' !in rawValue && '@' !in rawValue) {
            "Укажите только домен либо вставьте полную ссылку http/https."
        }
        rawValue
    }
    val withoutTrailingDot = candidate.trim().trimEnd('.')
    val ascii = runCatching { IDN.toASCII(withoutTrailingDot, IDN.USE_STD3_ASCII_RULES) }
        .getOrElse { throw IllegalArgumentException("Некорректный домен.") }
        .lowercase()
    require(ascii.isNotEmpty() && ascii.length <= 253) { "Некорректная длина домена." }
    val labels = ascii.split('.')
    require(labels.all { label ->
        label.length in 1..63 &&
            label.first().isLetterOrDigit() &&
            label.last().isLetterOrDigit() &&
            label.all { it.isLetterOrDigit() || it == '-' }
    }) { "Некорректный домен." }
    require(labels.any { label -> label.any(Char::isLetter) }) { "Некорректный домен или IPv4-адрес." }
    return ascii
}

private fun extractHttpHost(rawValue: String): String? {
    if (!rawValue.startsWith("http://", true) && !rawValue.startsWith("https://", true)) return null
    val authority = rawValue.substringAfter("://")
        .substringBefore('/')
        .substringBefore('?')
        .substringBefore('#')
    if (authority.isBlank() || '@' in authority) return null
    return authority.substringBefore(':').takeIf(String::isNotBlank)
}

private fun extractBareHostWithPort(rawValue: String): String? {
    if (rawValue.count { it == ':' } != 1) return null
    val host = rawValue.substringBeforeLast(':').trim()
    val port = rawValue.substringAfterLast(':').toIntOrNull()
    if (host.isBlank() || port == null || port !in 1..65535) return null
    return host
}

private fun parseVpnPackagesJson(root: JSONObject, key: String): List<String> {
    val array = root.optJSONArray(key)
        ?: throw IllegalArgumentException("В файле нет списка $key.")
    require(array.length() <= 5_000) { "Список приложений в файле слишком большой." }
    // В Android встречается системный пакет `android` без точки, поэтому формат
    // должен принимать и его: файл, созданный самим приложением, обязан импортироваться.
    val packagePattern = Regex("[A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z0-9_]+)*")
    return buildList {
        for (index in 0 until array.length()) {
            val packageName = array.optString(index).trim()
            require(packageName.length in 1..255 && packagePattern.matches(packageName)) {
                "Некорректный пакет приложения в записи №${index + 1}."
            }
            add(packageName)
        }
    }.distinct().sorted()
}

private fun parseVpnAddressRulesJson(root: JSONObject, key: String): List<VpnAddressRule> {
    val array = root.optJSONArray(key)
        ?: throw IllegalArgumentException("В файле нет списка $key.")
    return decodeVpnAddressRulesStrict(array.toString())
}

private data class Ipv4Prefix(
    val network: Long,
    val length: Int,
) {
    init {
        require(length in 0..IPV4_BITS)
        require(network == (network and prefixMask(length)))
    }

    fun contains(other: Ipv4Prefix): Boolean =
        length <= other.length && (other.network and prefixMask(length)) == network

    fun toCidr(): String = "${formatIpv4(network)}/$length"
}

private fun parseIpv4(value: String): Long? {
    val parts = value.trim().split('.')
    if (parts.size != 4) return null
    var result = 0L
    for (part in parts) {
        if (part.isEmpty() || part.length > 3 || part.any { !it.isDigit() }) return null
        if (part.length > 1 && part.startsWith('0')) return null
        val octet = part.toIntOrNull()?.takeIf { it in 0..255 } ?: return null
        result = (result shl 8) or octet.toLong()
    }
    return result
}

private fun parseIpv4Prefix(value: String): Ipv4Prefix? {
    val separator = value.indexOf('/')
    if (separator <= 0 || separator != value.lastIndexOf('/')) return null
    val address = parseIpv4(value.substring(0, separator)) ?: return null
    val length = value.substring(separator + 1).toIntOrNull()?.takeIf { it in 0..IPV4_BITS }
        ?: return null
    return Ipv4Prefix(address and prefixMask(length), length)
}

private fun parseIpv4Range(value: String): LongRange? {
    val match = Regex("^\\s*([^\\s]+)\\s*[-–—]\\s*([^\\s]+)\\s*$").matchEntire(value)
        ?: return null
    val first = parseIpv4(match.groupValues[1]) ?: return null
    val last = parseIpv4(match.groupValues[2]) ?: return null
    require(first <= last) { "Начало диапазона IPv4 должно быть не больше конца." }
    return first..last
}

private fun ipv4RangeToPrefixes(first: Long, last: Long): List<Ipv4Prefix> {
    require(first in 0..IPV4_MAX && last in first..IPV4_MAX)
    val result = mutableListOf<Ipv4Prefix>()
    var current = first
    while (current <= last) {
        var prefixLength = IPV4_BITS
        while (prefixLength > 0) {
            val candidateLength = prefixLength - 1
            val candidateNetwork = current and prefixMask(candidateLength)
            if (candidateNetwork != current) break
            val blockSize = 1L shl (IPV4_BITS - candidateLength)
            val candidateLast = candidateNetwork + blockSize - 1L
            if (candidateLast > last) break
            prefixLength = candidateLength
        }
        val prefix = Ipv4Prefix(current, prefixLength)
        result += prefix
        current += 1L shl (IPV4_BITS - prefixLength)
    }
    return result
}

private fun prefixMask(length: Int): Long = when (length) {
    0 -> 0L
    IPV4_BITS -> IPV4_MAX
    else -> (IPV4_MAX shl (IPV4_BITS - length)) and IPV4_MAX
}

private fun formatIpv4(value: Long): String =
    (3 downTo 0).joinToString(".") { shift -> ((value shr (shift * 8)) and 0xff).toString() }

private fun collapseIpv4Prefixes(values: Collection<Ipv4Prefix>): List<Ipv4Prefix> {
    val result = linkedSetOf<Ipv4Prefix>()
    values.sortedWith(compareBy<Ipv4Prefix> { it.length }.thenBy { it.network }).forEach { prefix ->
        if (result.none { it.contains(prefix) }) result += prefix
    }

    for (length in IPV4_BITS downTo 1) {
        val atLength = result.filter { it.length == length }.mapTo(hashSetOf()) { it.network }
        val consumed = hashSetOf<Long>()
        atLength.sorted().forEach { network ->
            if (network in consumed) return@forEach
            val bit = 1L shl (IPV4_BITS - length)
            val sibling = network xor bit
            if (sibling in atLength) {
                result.remove(Ipv4Prefix(network, length))
                result.remove(Ipv4Prefix(sibling, length))
                result += Ipv4Prefix(network and prefixMask(length - 1), length - 1)
                consumed += network
                consumed += sibling
            }
        }
    }
    return result.toList()
}

private fun subtractIpv4Prefixes(
    source: List<Ipv4Prefix>,
    excluded: List<Ipv4Prefix>,
): List<Ipv4Prefix> {
    var remaining = source
    excluded.forEach { blocked ->
        remaining = remaining.flatMap { allowed -> subtractIpv4Prefix(allowed, blocked) }
    }
    return collapseIpv4Prefixes(remaining)
}

private fun subtractIpv4Prefix(allowed: Ipv4Prefix, blocked: Ipv4Prefix): List<Ipv4Prefix> {
    if (!allowed.contains(blocked) && !blocked.contains(allowed)) return listOf(allowed)
    if (blocked.contains(allowed)) return emptyList()
    if (allowed.length == IPV4_BITS) return emptyList()

    val childLength = allowed.length + 1
    val childBit = 1L shl (IPV4_BITS - childLength)
    val first = Ipv4Prefix(allowed.network, childLength)
    val second = Ipv4Prefix(allowed.network or childBit, childLength)
    return if (first.contains(blocked)) {
        subtractIpv4Prefix(first, blocked) + listOf(second)
    } else {
        listOf(first) + subtractIpv4Prefix(second, blocked)
    }
}
