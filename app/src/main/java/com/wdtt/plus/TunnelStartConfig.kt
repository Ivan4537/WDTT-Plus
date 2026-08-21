package com.wdtt.plus

import android.content.Context
import android.content.Intent

internal const val TUNNEL_PROFILE_INDEX_EXTRA = "profile_index"
internal const val MANAGED_CONFIG_FIRST_START_EXTRA = "managed_config_first_start"
internal const val DEFAULT_RT_TURN_SNI = "ya.ru"

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
    managedConfigFirstStart: Boolean,
): TransportRecoveryPolicy {
    val processRestartDelayMs = if (managedConfigFirstStart) 250L else 2_500L
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

internal fun shouldUseManagedConfigFirstStart(
    remoteManaged: Boolean,
    profileMaxWorkers: Int,
): Boolean = remoteManaged &&
    profileMaxWorkers in TUNNEL_WORKERS_PER_GROUP..APP_MAX_WORKERS &&
    profileMaxWorkers % TUNNEL_WORKERS_PER_GROUP == 0

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
    val managedConfigFirstStart = shouldUseManagedConfigFirstStart(
        remoteManaged = saved.remoteManaged,
        profileMaxWorkers = saved.profileMaxWorkers,
    )
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
            managedConfigFirstStart = managedConfigFirstStart,
            profileIndex = saved.profileIndex,
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
            managedConfigFirstStart = managedConfigFirstStart,
            profileIndex = saved.profileIndex,
        )
    }
}

suspend fun buildTunnelStartIntentFromSettings(context: Context): Intent? {
    val params = buildTunnelParamsFromSettings(context) ?: return null
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
        putExtra(MANAGED_CONFIG_FIRST_START_EXTRA, params.managedConfigFirstStart)
        putExtra(TUNNEL_PROFILE_INDEX_EXTRA, params.profileIndex)
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
