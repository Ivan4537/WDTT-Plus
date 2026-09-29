package com.wdtt.plus

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/** Only a short retry deadline is cached, never a permanent transport preference. */
internal object ConnectionNetwork {
    private const val udpPauseMs = 5 * 60_000L

    fun underlying(context: Context): Network? {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return null
        fun usable(n: Network): Boolean = cm.getNetworkCapabilities(n)?.let {
            it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                it.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        } == true
        return cm.activeNetwork?.takeIf(::usable) ?: cm.allNetworks.firstOrNull(::usable)
    }

    fun cacheKey(context: Context, params: TunnelParams): String? {
        val network = underlying(context) ?: return null
        // Digest is private local data. It is never exported or written to logs.
        val identity = listOf(
            network.networkHandle, params.profileIndex, params.peer, params.vkHashes,
            params.secondaryVkHash, params.connectionPassword, params.rtTurnSni,
            params.rtMasque, params.rtNetwork, params.mode,
        ).joinToString("\u0000")
        return MessageDigest.getInstance("SHA-256").digest(identity.toByteArray())
            .joinToString("") { "%02x".format(it) }
    }

    fun udpBackoffSeconds(context: Context, key: String?, now: Long = System.currentTimeMillis()): Long {
        if (key == null) return 0
        val until = context.getSharedPreferences("connection_retry", Context.MODE_PRIVATE).getLong(key, 0L)
        return ((until - now).coerceIn(0L, udpPauseMs) + 999L) / 1_000L
    }

    fun noteUdpFailure(context: Context, key: String?) {
        if (key == null) return
        val prefs = context.getSharedPreferences("connection_retry", Context.MODE_PRIVATE)
        val now = System.currentTimeMillis()
        val edit = prefs.edit()
        prefs.all.forEach { (name, value) ->
            if (value !is Long || value <= now || prefs.all.size > 128) edit.remove(name)
        }
        edit.putLong(key, now + udpPauseMs).apply()
    }

    fun noteReady(context: Context, key: String?, kind: String) {
        if (key != null && kind == "udp") context.getSharedPreferences("connection_retry", Context.MODE_PRIVATE)
            .edit().remove(key).apply()
    }

    // These small HTTPS requests are bound to the underlying network, never to
    // the VPN. Failure alone is inconclusive (including Android lockdown).
    fun reachable(network: Network, host: String): Boolean = runCatching {
        val connection = network.openConnection(URL("https://$host/")) as HttpURLConnection
        try {
            connection.connectTimeout = 3_000
            connection.readTimeout = 3_000
            connection.requestMethod = "HEAD"
            connection.instanceFollowRedirects = false
            connection.responseCode in 100..599
        } finally {
            connection.disconnect()
        }
    }.getOrDefault(false)
}

/** Unknown accessibility is not an outage. Only loss of both previously
 * reachable controls on the same network can suspend new VPN attempts. */
internal class ConnectionReachability {
    private var confirmed = false
    private var failures = 0
    fun observe(first: Boolean, second: Boolean): Boolean {
        if (first && second) confirmed = true
        failures = if (first || second) 0 else failures + 1
        return confirmed && failures >= 3
    }
}
