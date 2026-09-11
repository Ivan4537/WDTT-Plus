package com.wdtt.plus

import android.content.Context
import android.content.Intent

internal const val TUNNEL_PROFILE_INDEX_EXTRA = "profile_index"
internal const val CONFIG_FIRST_START_EXTRA = "config_first_start"
internal const val DEFAULT_RT_TURN_SNI = "ya.ru"
internal const val TUNNEL_MODE_VPN = "vpn"
internal const val TUNNEL_MODE_AUTO = "auto"
internal const val TUNNEL_MODE_SOCKS5 = "socks5"
internal const val TUNNEL_MODE_HTTP = "http"
internal const val SOCKS5_LOOPBACK_HOST = "127.0.0.1"
internal const val DEFAULT_SOCKS5_PORT = 1080
internal const val DEFAULT_HTTP_CONNECT_PORT = 8080
internal const val PROXY_VPN_CAPTURE_CONFIRMATIONS = 2

internal fun normalizeTunnelMode(value: String?): String = when (value?.trim()?.lowercase()) {
    TUNNEL_MODE_AUTO, "mixed" -> TUNNEL_MODE_AUTO
    TUNNEL_MODE_SOCKS5 -> TUNNEL_MODE_SOCKS5
    TUNNEL_MODE_HTTP, "http-connect", "connect" -> TUNNEL_MODE_HTTP
    "tun", TUNNEL_MODE_VPN -> TUNNEL_MODE_VPN
    else -> TUNNEL_MODE_VPN
}

internal fun resolveStoredTunnelMode(value: String?, explicitlyActivated: Boolean): String =
    if (explicitlyActivated) normalizeTunnelMode(value) else TUNNEL_MODE_VPN

internal fun tunnelModeNeedsVpnPermission(value: String?): Boolean =
    normalizeTunnelMode(value) == TUNNEL_MODE_VPN

internal fun tunnelModeUsesLocalProxy(value: String?): Boolean =
    normalizeTunnelMode(value) != TUNNEL_MODE_VPN

/**
 * ConnectivityManager returns a UID-aware default network. If it is another
 * VPN while WDTT runs as a local proxy, that VPN did not exclude WDTT Plus and
 * will feed the transport back into the same proxy. Confirm twice so a single
 * capabilities handover cannot stop a healthy proxy session.
 */
internal fun nextProxyVpnCaptureObservationCount(
    tunnelMode: String?,
    appDefaultNetworkIsVpn: Boolean,
    previousCount: Int,
): Int = if (tunnelModeUsesLocalProxy(tunnelMode) && appDefaultNetworkIsVpn) {
    (previousCount + 1).coerceAtMost(PROXY_VPN_CAPTURE_CONFIRMATIONS)
} else {
    0
}

internal fun proxyVpnCaptureConfirmed(observationCount: Int): Boolean =
    observationCount >= PROXY_VPN_CAPTURE_CONFIRMATIONS

internal fun tunnelModeStatusLabel(value: String?): String = when (normalizeTunnelMode(value)) {
    TUNNEL_MODE_AUTO -> "АВТО ПРОКСИ"
    TUNNEL_MODE_SOCKS5 -> "SOCKS5"
    TUNNEL_MODE_HTTP -> "HTTP CONNECT"
    else -> "VPN"
}

internal fun fullWidgetRunningStatus(tunnelMode: String?, profileName: String): String = when (
    normalizeTunnelMode(tunnelMode)
) {
    TUNNEL_MODE_AUTO -> "ПРОКСИ · $profileName"
    TUNNEL_MODE_SOCKS5 -> "SOCKS5 · $profileName"
    TUNNEL_MODE_HTTP -> "HTTP · $profileName"
    else -> "Подключено к $profileName"
}

internal fun compactWidgetRunningStatus(tunnelMode: String?, profileName: String): String = when (
    normalizeTunnelMode(tunnelMode)
) {
    TUNNEL_MODE_AUTO -> "ПРОКСИ · $profileName"
    TUNNEL_MODE_SOCKS5 -> "SOCKS · $profileName"
    TUNNEL_MODE_HTTP -> "HTTP · $profileName"
    else -> profileName
}

internal fun normalizeProxyPort(value: Int, mode: String): Int = value.takeIf { it in 1..65535 }
    ?: if (normalizeTunnelMode(mode) == TUNNEL_MODE_HTTP) DEFAULT_HTTP_CONNECT_PORT else DEFAULT_SOCKS5_PORT

internal fun proxySettingsAreValid(
    mode: String,
    port: Int,
    access: String,
    authEnabled: Boolean,
    username: String,
    password: String,
): Boolean = !tunnelModeUsesLocalProxy(mode) ||
    port in 1..65535 &&
    (!authEnabled || isValidSocks5Credential(username) && isValidSocks5Credential(password)) &&
    (!proxyAccessIncludesLan(access) || authEnabled)

internal fun tunnelToggleContentDescription(running: Boolean, tunnelMode: String?): String =
    if (running) {
        "Остановить ${tunnelModeStatusLabel(tunnelMode)}"
    } else {
        "Запустить ${tunnelModeStatusLabel(tunnelMode)}"
    }

internal fun normalizeSocks5Port(value: Int): Int =
    value.takeIf { it in 1..65535 } ?: DEFAULT_SOCKS5_PORT

internal fun isValidSocks5Credential(value: String): Boolean =
    value.isNotBlank() && value.toByteArray(Charsets.UTF_8).size <= 255

internal fun truncateSocks5Credential(value: String, maxBytes: Int = 255): String {
    if (maxBytes <= 0 || value.isEmpty()) return ""
    if (value.toByteArray(Charsets.UTF_8).size <= maxBytes) return value
    var index = 0
    var usedBytes = 0
    while (index < value.length) {
        val nextIndex = value.offsetByCodePoints(index, 1)
        val codePointBytes = value.substring(index, nextIndex).toByteArray(Charsets.UTF_8).size
        if (usedBytes + codePointBytes > maxBytes) break
        usedBytes += codePointBytes
        index = nextIndex
    }
    return value.substring(0, index)
}

internal fun normalizeRtTurnSni(value: String): String? {
    val host = value.trim().lowercase()
    if (
        host.isBlank() ||
        host.length > 253 ||
        host.startsWith(".") ||
        host.endsWith(".") ||
        host.contains("..")
    ) {
        return null
    }
    val labels = host.split('.')
    if (labels.size < 2 || labels.all { it.toIntOrNull() != null }) return null
    return host.takeIf {
        labels.all { label ->
            label.isNotBlank() &&
                label.length <= 63 &&
                !label.startsWith("-") &&
                !label.endsWith("-") &&
                label.all { char ->
                    char in 'a'..'z' || char in '0'..'9' || char == '-'
                }
        }
    }
}

internal data class TransportRecoveryPolicy(
    val networkSettleDelayMs: Long,
    val reconnectMinIntervalMs: Long,
    val processRestartDelayMs: Long,
    val forceRestart: Boolean,
)

internal fun transportRecoveryPolicy(
    configFirstStart: Boolean,
): TransportRecoveryPolicy {
    val processRestartDelayMs = if (configFirstStart) 250L else 2_500L
    return TransportRecoveryPolicy(
        networkSettleDelayMs = 15_000L,
        reconnectMinIntervalMs = 2 * 60_000L,
        processRestartDelayMs = processRestartDelayMs,
        forceRestart = false,
    )
}

internal enum class TunnelToggleAction {
    START,
    STOP,
    REQUEST_VPN_PERMISSION,
}

internal fun tunnelToggleAction(
    running: Boolean,
    trustedWifiWaiting: Boolean,
    vpnPermissionRequired: Boolean,
): TunnelToggleAction = when {
    running || trustedWifiWaiting -> TunnelToggleAction.STOP
    vpnPermissionRequired -> TunnelToggleAction.REQUEST_VPN_PERMISSION
    else -> TunnelToggleAction.START
}

internal fun displayedTunnelProfile(
    selectedProfile: Int,
    activeTunnelProfile: Int?,
    running: Boolean,
    trustedWifiWaiting: Boolean,
): Int = if (running || trustedWifiWaiting) {
    activeTunnelProfile ?: selectedProfile
} else {
    selectedProfile
}.coerceIn(0, 2)

/**
 * WireGuard configuration is mandatory for every profile, not only for a
 * remotely managed profile with a worker limit. Starting data workers before
 * GETCONF succeeds can otherwise report an active transport while Android has
 * no VPN interface and user traffic is still going directly over Wi-Fi.
 */
internal fun shouldUseConfigFirstStart(): Boolean = true

internal fun shouldUseHashFallback(hashCount: Int): Boolean = hashCount > 1

suspend fun buildTunnelParamsFromSettings(
    context: Context,
    profileIndex: Int? = null,
): TunnelParams? {
    val store = SettingsStore(context.applicationContext)
    store.reconcileRemoteProfileWorkerLimit(profileIndex)
    val saved = store.tunnelProfileSnapshot(profileIndex)
    return buildTunnelParams(saved)
}

internal fun buildTunnelParams(saved: TunnelProfileSnapshot): TunnelParams? {
    val workersPerHash = normalizeTunnelWorkerCount(
        saved.workersPerHash,
        saved.profileMaxWorkers
    )
    val configFirstStart = shouldUseConfigFirstStart()
    val linkParts = saved.link
        .takeIf { saved.linkMode }
        ?.let { WdttDeepLink.validate(it).parts }

    return if (linkParts != null) {
        TunnelParams(
            peer = "${linkParts.host}:${linkParts.dtlsPort}",
            vkHashes = linkParts.hashes,
            secondaryVkHash = "",
            workersPerHash = workersPerHash,
            port = linkParts.localPort,
            sni = saved.sni,
            connectionPassword = linkParts.password,
            protocol = saved.protocol,
            vkCallsPreflight = saved.vkCallsPreflight,
            rtNetwork = saved.rtNetwork,
            rtMasque = saved.rtMasque,
            rtMasqueServerBootstrap =
                saved.rtMasqueServerBootstrap && saved.rtMasqueServerAccessReady,
            rtTurnSni = saved.rtTurnSni,
            captchaMode = sanitizeTunnelCaptchaMode(saved.captchaMode),
            captchaSolveMethod = saved.captchaSolveMethod,
            fingerprint = saved.fingerprint,
            clientIds = saved.clientIds,
            customVkCredentialsEnabled = saved.customVkCredentialsEnabled,
            customVkClientId = saved.customVkClientId,
            customVkClientSecret = saved.customVkClientSecret,
            profileMaxWorkers = saved.profileMaxWorkers,
            configFirstStart = configFirstStart,
            profileIndex = saved.profileIndex,
            mode = normalizeTunnelMode(saved.proxyMode),
            socksPort = normalizeProxyPort(saved.proxyPort, saved.proxyMode),
            socksUdpEnabled = saved.proxyUdpEnabled || normalizeTunnelMode(saved.proxyMode) == TUNNEL_MODE_AUTO,
            proxyAccess = normalizeProxyAccess(saved.proxyAccess),
            proxyLanEnabled = saved.proxyLanEnabled,
            socksAuthEnabled = saved.proxyAuthEnabled,
            socksUsername = saved.proxyUsername,
            socksPassword = saved.proxyPassword,
        )
    } else {
        val basePeer = saved.peer.trim()
        val hashes = saved.vkHashes.trim()
        val password = saved.connectionPassword
        if (basePeer.isBlank() || hashes.isBlank() || password.isBlank()) return null

        val serverDtlsPort = if (saved.manualPortsEnabled) saved.serverDtlsPort else 56000
        val localPort = if (saved.manualPortsEnabled) saved.listenPort else 9000
        val peerWithPort = if (basePeer.contains(":")) basePeer else "$basePeer:$serverDtlsPort"

        TunnelParams(
            peer = peerWithPort,
            vkHashes = hashes,
            secondaryVkHash = saved.secondaryVkHash,
            workersPerHash = workersPerHash,
            port = localPort,
            sni = saved.sni,
            connectionPassword = password,
            protocol = saved.protocol,
            vkCallsPreflight = saved.vkCallsPreflight,
            rtNetwork = saved.rtNetwork,
            rtMasque = saved.rtMasque,
            rtMasqueServerBootstrap =
                saved.rtMasqueServerBootstrap && saved.rtMasqueServerAccessReady,
            rtTurnSni = saved.rtTurnSni,
            captchaMode = sanitizeTunnelCaptchaMode(saved.captchaMode),
            captchaSolveMethod = saved.captchaSolveMethod,
            fingerprint = saved.fingerprint,
            clientIds = saved.clientIds,
            customVkCredentialsEnabled = saved.customVkCredentialsEnabled,
            customVkClientId = saved.customVkClientId,
            customVkClientSecret = saved.customVkClientSecret,
            profileMaxWorkers = saved.profileMaxWorkers,
            configFirstStart = configFirstStart,
            profileIndex = saved.profileIndex,
            mode = normalizeTunnelMode(saved.proxyMode),
            socksPort = normalizeProxyPort(saved.proxyPort, saved.proxyMode),
            socksUdpEnabled = saved.proxyUdpEnabled || normalizeTunnelMode(saved.proxyMode) == TUNNEL_MODE_AUTO,
            proxyAccess = normalizeProxyAccess(saved.proxyAccess),
            proxyLanEnabled = saved.proxyLanEnabled,
            socksAuthEnabled = saved.proxyAuthEnabled,
            socksUsername = saved.proxyUsername,
            socksPassword = saved.proxyPassword,
        )
    }
}

suspend fun buildTunnelStartIntentFromSettings(
    context: Context,
    profileIndex: Int? = null,
): Intent? {
    val params = buildTunnelParamsFromSettings(context, profileIndex) ?: return null
    return Intent(context, TunnelService::class.java).apply {
        action = "START"
        putExtra("peer", params.peer)
        putExtra("vk_hashes", params.vkHashes)
        putExtra("secondary_vk_hash", params.secondaryVkHash)
        putExtra("workers_per_hash", params.workersPerHash)
        putExtra("port", params.port)
        putExtra("sni", params.sni)
        putExtra("connection_password", params.connectionPassword)
        putExtra("protocol", params.protocol)
        putExtra("vkcalls_preflight", params.vkCallsPreflight)
        putExtra("rt_network", params.rtNetwork)
        putExtra("rt_masque", params.rtMasque)
        putExtra("rt_masque_server_bootstrap", params.rtMasqueServerBootstrap)
        putExtra("rt_turn_sni", params.rtTurnSni)
        putExtra("captcha_mode", params.captchaMode)
        putExtra("captcha_solve_method", params.captchaSolveMethod)
        putExtra("fingerprint", params.fingerprint)
        putExtra("client_ids", params.clientIds)
        putExtra("custom_vk_credentials_enabled", params.customVkCredentialsEnabled)
        putExtra("custom_vk_client_id", params.customVkClientId)
        putExtra("custom_vk_client_secret", params.customVkClientSecret)
        putExtra("profile_max_workers", params.profileMaxWorkers)
        putExtra(CONFIG_FIRST_START_EXTRA, params.configFirstStart)
        putExtra(TUNNEL_PROFILE_INDEX_EXTRA, params.profileIndex)
        putExtra("tunnel_mode", params.mode)
        putExtra("socks_port", params.socksPort)
        putExtra("socks_udp", params.socksUdpEnabled)
        putExtra("proxy_access", params.proxyAccess)
        putExtra("proxy_lan", params.proxyLanEnabled)
        putExtra("socks_auth", params.socksAuthEnabled)
        putExtra("socks_username", params.socksUsername)
        putExtra("socks_password", params.socksPassword)
    }
}

private fun sanitizeTunnelCaptchaMode(mode: String?): String {
    return when (mode?.lowercase()) {
        "auto" -> "auto"
        "rjs" -> "rjs"
        "wv" -> "wv"
        else -> "auto"
    }
}
