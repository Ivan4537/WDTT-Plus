package com.wdtt.plus

import java.net.Inet4Address
import java.net.NetworkInterface
import java.net.URI
import java.security.SecureRandom

internal const val PROXY_ACCESS_DEVICE = "device"
internal const val PROXY_ACCESS_LAN = "lan"
internal const val PROXY_ACCESS_BOTH = "both"

internal data class ProxyInterfaceAddress(
    val interfaceName: String,
    val host: String,
    val prefixLength: Int,
)

internal data class ProxyListenBinding(
    val host: String,
    val allowedCidr: String,
)

internal data class ProxyCopyOption(
    val protocolLabel: String,
    val accessLabel: String,
    val address: String,
    val uri: String,
)

internal fun normalizeProxyAccess(value: String?): String = when (value?.trim()?.lowercase()) {
    PROXY_ACCESS_DEVICE -> PROXY_ACCESS_DEVICE
    PROXY_ACCESS_LAN -> PROXY_ACCESS_LAN
    PROXY_ACCESS_BOTH -> PROXY_ACCESS_BOTH
    else -> PROXY_ACCESS_BOTH
}

internal fun resolveStoredProxyAccess(
    value: String?,
    legacyLanEnabled: Boolean,
    explicitlyActivated: Boolean,
): String = value?.takeIf { it.isNotBlank() }?.let(::normalizeProxyAccess)
    ?: if (explicitlyActivated) {
        if (legacyLanEnabled) PROXY_ACCESS_LAN else PROXY_ACCESS_DEVICE
    } else {
        PROXY_ACCESS_BOTH
    }

internal fun proxyAccessIncludesDevice(value: String?): Boolean =
    normalizeProxyAccess(value) != PROXY_ACCESS_LAN

internal fun proxyAccessIncludesLan(value: String?): Boolean =
    normalizeProxyAccess(value) != PROXY_ACCESS_DEVICE

internal fun proxyAccessNeedsAuthentication(value: String?): Boolean =
    proxyAccessIncludesLan(value)

internal fun expectedProxyReadyAddresses(
    access: String?,
    port: Int,
    lanHost: String?,
): List<String> = buildList {
    if (proxyAccessIncludesDevice(access)) {
        add("$SOCKS5_LOOPBACK_HOST:$port")
    }
    if (proxyAccessIncludesLan(access) && !lanHost.isNullOrBlank()) {
        add("$lanHost:$port")
    }
}

internal fun selectProxyLanBinding(
    addresses: List<ProxyInterfaceAddress>,
): ProxyListenBinding? = addresses
    .asSequence()
    .filter { candidate ->
        candidate.prefixLength in 8..30 &&
            isPrivateIpv4(candidate.host) &&
            !isTunnelLikeInterface(candidate.interfaceName)
    }
    .sortedWith(
        compareBy<ProxyInterfaceAddress> { interfacePriority(it.interfaceName) }
            .thenBy { it.interfaceName }
            .thenBy { it.host },
    )
    .mapNotNull { candidate ->
        val restrictedPrefixLength = maxOf(candidate.prefixLength, 24)
        ipv4NetworkCidr(candidate.host, restrictedPrefixLength)?.let { cidr ->
            ProxyListenBinding(candidate.host, cidr)
        }
    }
    .firstOrNull()

internal fun findProxyLanBinding(): ProxyListenBinding? = runCatching {
    val candidates = buildList {
        val interfaces = NetworkInterface.getNetworkInterfaces() ?: return@buildList
        while (interfaces.hasMoreElements()) {
            val networkInterface = interfaces.nextElement()
            runCatching {
                if (!networkInterface.isUp || networkInterface.isLoopback) return@runCatching
                networkInterface.interfaceAddresses.forEach { interfaceAddress ->
                    val address = interfaceAddress.address as? Inet4Address ?: return@forEach
                    add(
                        ProxyInterfaceAddress(
                            interfaceName = networkInterface.name.orEmpty(),
                            host = address.hostAddress.orEmpty(),
                            prefixLength = interfaceAddress.networkPrefixLength.toInt(),
                        ),
                    )
                }
            }
        }
    }
    selectProxyLanBinding(candidates)
}.getOrNull()

internal fun proxyDisplayAddress(
    lanEnabled: Boolean,
    port: Int,
    readyAddress: String? = null,
    lanBinding: ProxyListenBinding? = null,
): String = readyAddress?.takeIf { it.isNotBlank() }
    ?: if (lanEnabled) {
        lanBinding?.let { "${it.host}:$port" } ?: "Сеть:$port"
    } else {
        "$SOCKS5_LOOPBACK_HOST:$port"
    }

internal fun proxyImportUri(
    mode: String,
    readyAddress: String,
    authEnabled: Boolean,
    username: String,
    password: String,
): String? {
    val normalizedMode = normalizeTunnelMode(mode)
    val (scheme, title) = when (normalizedMode) {
        TUNNEL_MODE_SOCKS5 -> "socks5" to "WDTT-Plus SOCKS5"
        TUNNEL_MODE_HTTP -> "http" to "WDTT-Plus HTTP"
        else -> return null
    }
    if (authEnabled &&
        (!isValidSocks5Credential(username) || !isValidSocks5Credential(password))
    ) {
        return null
    }
    val endpoint = runCatching { URI("proxy://$readyAddress") }.getOrNull() ?: return null
    val host = endpoint.host?.takeIf { it.isNotBlank() } ?: return null
    val port = endpoint.port.takeIf { it in 1..65535 } ?: return null
    val userInfo = if (authEnabled) "$username:$password" else null
    return runCatching {
        URI(scheme, userInfo, host, port, null, null, title).toASCIIString()
    }.getOrNull()
}

internal fun proxyCopyOptions(
    mode: String,
    readyAddresses: List<String>,
    authEnabled: Boolean,
    username: String,
    password: String,
): List<ProxyCopyOption> {
    val protocols = when (normalizeTunnelMode(mode)) {
        TUNNEL_MODE_AUTO -> listOf(
            TUNNEL_MODE_SOCKS5 to "SOCKS5",
            TUNNEL_MODE_HTTP to "HTTP",
        )
        TUNNEL_MODE_SOCKS5 -> listOf(TUNNEL_MODE_SOCKS5 to "SOCKS5")
        TUNNEL_MODE_HTTP -> listOf(TUNNEL_MODE_HTTP to "HTTP")
        else -> emptyList()
    }
    return readyAddresses
        .distinct()
        .sortedBy { if (it.startsWith("$SOCKS5_LOOPBACK_HOST:")) 0 else 1 }
        .flatMap { address ->
            val accessLabel = if (address.startsWith("$SOCKS5_LOOPBACK_HOST:")) {
                "Устройство"
            } else {
                "Сеть"
            }
            protocols.mapNotNull { (protocol, protocolLabel) ->
                proxyImportUri(
                    mode = protocol,
                    readyAddress = address,
                    authEnabled = authEnabled,
                    username = username,
                    password = password,
                )?.let { uri ->
                    ProxyCopyOption(protocolLabel, accessLabel, address, uri)
                }
            }
        }
}

internal fun generateProxyPassword(length: Int = 18): String {
    val alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    val random = SecureRandom()
    return buildString(length.coerceIn(12, 64)) {
        repeat(length.coerceIn(12, 64)) {
            append(alphabet[random.nextInt(alphabet.length)])
        }
    }
}

private fun isTunnelLikeInterface(name: String): Boolean {
    val normalized = name.lowercase()
    return listOf("tun", "tap", "wg", "ppp", "rmnet", "dummy", "v4-").any(normalized::startsWith)
}

private fun interfacePriority(name: String): Int {
    val normalized = name.lowercase()
    return when {
        normalized.startsWith("ap") || normalized.startsWith("swlan") ||
            normalized.startsWith("softap") -> 0
        normalized.startsWith("wlan") || normalized.startsWith("wifi") -> 1
        normalized.startsWith("rndis") || normalized.startsWith("usb") -> 2
        normalized.startsWith("eth") -> 3
        else -> 4
    }
}

private fun isPrivateIpv4(value: String): Boolean {
    val bytes = parseIpv4(value) ?: return false
    val first = bytes[0]
    val second = bytes[1]
    return first == 10 ||
        first == 172 && second in 16..31 ||
        first == 192 && second == 168
}

private fun ipv4NetworkCidr(host: String, prefixLength: Int): String? {
    if (prefixLength !in 8..30) return null
    val bytes = parseIpv4(host) ?: return null
    var address = 0
    bytes.forEach { part -> address = (address shl 8) or part }
    val mask = (-1 shl (32 - prefixLength))
    val network = address and mask
    val networkHost = listOf(24, 16, 8, 0).joinToString(".") { shift ->
        ((network ushr shift) and 0xff).toString()
    }
    return "$networkHost/$prefixLength"
}

private fun parseIpv4(value: String): IntArray? {
    val parts = value.split('.')
    if (parts.size != 4) return null
    return IntArray(4) { index ->
        val part = parts[index]
        if (part.isEmpty() || part.length > 3 || part.any { !it.isDigit() }) return null
        part.toIntOrNull()?.takeIf { it in 0..255 } ?: return null
    }
}
