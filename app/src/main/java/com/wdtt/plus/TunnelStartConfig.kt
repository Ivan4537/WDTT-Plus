package com.wdtt.plus

import android.content.Context
import android.content.Intent
import kotlinx.coroutines.flow.first

suspend fun buildTunnelParamsFromSettings(context: Context): TunnelParams? {
    val store = SettingsStore(context.applicationContext)
    val linkMode = store.wdttLinkMode.first()
    val workersPerHash = store.workersPerHash.first()
    val sni = store.sni.first()
    val protocol = store.protocol.first()
    val vkCallsPreflight = store.vkCallsPreflight.first()
    val captchaMode = sanitizeTunnelCaptchaMode(store.captchaMode.first())
    val captchaSolveMethod = store.captchaSolveMethod.first()
    val fingerprint = store.selectedFingerprint.first()
    val clientIds = store.activeClientIds.first()

    return if (linkMode) {
        val parts = WdttDeepLink.validate(store.wdttLink.first()).parts ?: return null
        TunnelParams(
            peer = "${parts.host}:${parts.dtlsPort}",
            vkHashes = parts.hashes,
            secondaryVkHash = "",
            workersPerHash = workersPerHash,
            port = parts.localPort,
            sni = sni,
            connectionPassword = parts.password,
            protocol = protocol,
            vkCallsPreflight = vkCallsPreflight,
            captchaMode = captchaMode,
            captchaSolveMethod = captchaSolveMethod,
            fingerprint = fingerprint,
            clientIds = clientIds
        )
    } else {
        val basePeer = store.peer.first().trim()
        val hashes = store.vkHashes.first().trim()
        val password = store.connectionPassword.first()
        if (basePeer.isBlank() || hashes.isBlank() || password.isBlank()) return null

        val manualPortsEnabled = store.manualPortsEnabled.first()
        val serverDtlsPort = if (manualPortsEnabled) store.serverDtlsPort.first() else 56000
        val localPort = if (manualPortsEnabled) store.listenPort.first() else 9000
        val peerWithPort = if (basePeer.contains(":")) basePeer else "$basePeer:$serverDtlsPort"

        TunnelParams(
            peer = peerWithPort,
            vkHashes = hashes,
            secondaryVkHash = store.secondaryVkHash.first(),
            workersPerHash = workersPerHash,
            port = localPort,
            sni = sni,
            connectionPassword = password,
            protocol = protocol,
            vkCallsPreflight = vkCallsPreflight,
            captchaMode = captchaMode,
            captchaSolveMethod = captchaSolveMethod,
            fingerprint = fingerprint,
            clientIds = clientIds
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
        putExtra("captcha_mode", params.captchaMode)
        putExtra("captcha_solve_method", params.captchaSolveMethod)
        putExtra("fingerprint", params.fingerprint)
        putExtra("client_ids", params.clientIds)
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
