package com.wdtt.plus

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.provider.Settings
import androidx.core.content.ContextCompat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

private const val UNKNOWN_WIFI_SSID = "<unknown ssid>"
private const val BACKGROUND_LOCATION_PERMISSION = "android.permission.ACCESS_BACKGROUND_LOCATION"

data class TrustedWifiRuntimeState(
    val waiting: Boolean = false,
    val ssid: String = "",
    val status: String = ""
)

object TrustedWifiManager {
    private val _state = MutableStateFlow(TrustedWifiRuntimeState())
    val state = _state.asStateFlow()

    fun setWaiting(ssid: String, status: String = "VPN ожидает выхода из доверенной сети") {
        _state.value = TrustedWifiRuntimeState(waiting = true, ssid = ssid, status = status)
    }

    fun setStatus(status: String) {
        _state.value = _state.value.copy(status = status)
    }

    fun clear() {
        _state.value = TrustedWifiRuntimeState()
    }
}

enum class TrustedWifiAccessProblem {
    ForegroundPermission,
    BackgroundPermission,
    LocationDisabled
}

data class ConnectedWifiState(
    val connected: Boolean,
    val ssid: String = "",
    val accessProblem: TrustedWifiAccessProblem? = null
) {
    val ssidAvailable: Boolean get() = connected && ssid.isNotBlank() && accessProblem == null
}

enum class TrustedWifiTransition {
    None,
    EnterWaiting,
    ResumeVpn
}

internal fun decideTrustedWifiTransition(
    enabled: Boolean,
    tunnelRunning: Boolean,
    waiting: Boolean,
    wifi: ConnectedWifiState,
    trustedSsids: Set<String>
): TrustedWifiTransition {
    if (!enabled) return TrustedWifiTransition.None
    if (trustedSsids.isEmpty()) {
        return if (waiting) TrustedWifiTransition.ResumeVpn else TrustedWifiTransition.None
    }
    if (waiting) {
        if (!wifi.connected) return TrustedWifiTransition.ResumeVpn
        if (!wifi.ssidAvailable) return TrustedWifiTransition.ResumeVpn
        return if (wifi.ssid in trustedSsids) TrustedWifiTransition.None else TrustedWifiTransition.ResumeVpn
    }
    if (!tunnelRunning || !wifi.ssidAvailable) return TrustedWifiTransition.None
    return if (wifi.ssid in trustedSsids) TrustedWifiTransition.EnterWaiting else TrustedWifiTransition.None
}

internal fun shouldKeepTunnelServiceAlive(
    tunnelRunning: Boolean,
    tunnelPaused: Boolean,
    trustedWifiWaiting: Boolean,
    trustedWifiResumeInProgress: Boolean
): Boolean = tunnelRunning || tunnelPaused || trustedWifiWaiting || trustedWifiResumeInProgress

fun sanitizeTrustedWifiSsid(value: String): String {
    val clean = value
        .filterNot { Character.isISOControl(it) }
        .trim()
        .removeSurrounding("\"")
        .trim()
    if (clean.isEmpty()) return ""

    val result = StringBuilder()
    var byteCount = 0
    clean.forEach { character ->
        val characterBytes = character.toString().toByteArray(Charsets.UTF_8).size
        if (byteCount + characterBytes <= 32) {
            result.append(character)
            byteCount += characterBytes
        }
    }
    return result.toString()
}

fun hasTrustedWifiForegroundPermission(context: Context): Boolean =
    ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) ==
        PackageManager.PERMISSION_GRANTED

fun hasTrustedWifiBackgroundPermission(context: Context): Boolean =
    Build.VERSION.SDK_INT < Build.VERSION_CODES.Q ||
        ContextCompat.checkSelfPermission(context, BACKGROUND_LOCATION_PERMISSION) ==
        PackageManager.PERMISSION_GRANTED

fun trustedWifiAccessProblem(context: Context): TrustedWifiAccessProblem? {
    if (!hasTrustedWifiForegroundPermission(context)) return TrustedWifiAccessProblem.ForegroundPermission
    if (!hasTrustedWifiBackgroundPermission(context)) return TrustedWifiAccessProblem.BackgroundPermission
    val locationManager = context.getSystemService(LocationManager::class.java)
    if (locationManager?.isLocationEnabled != true) return TrustedWifiAccessProblem.LocationDisabled
    return null
}

fun isWdttAlwaysOnVpn(context: Context): Boolean = runCatching {
    Settings.Secure.getString(context.contentResolver, "always_on_vpn_app") == context.packageName
}.getOrDefault(false)

@Suppress("DEPRECATION")
fun readConnectedWifiState(context: Context): ConnectedWifiState {
    val appContext = context.applicationContext
    val connectivityManager = appContext.getSystemService(ConnectivityManager::class.java)
    val wifiConnected = runCatching {
        connectivityManager?.allNetworks?.any { network ->
            connectivityManager.getNetworkCapabilities(network)?.let { capabilities ->
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
                    capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            } == true
        } == true
    }.getOrDefault(false)
    if (!wifiConnected) return ConnectedWifiState(connected = false)

    val accessProblem = trustedWifiAccessProblem(appContext)
    if (accessProblem != null) {
        return ConnectedWifiState(connected = true, accessProblem = accessProblem)
    }

    val capabilitiesSsid = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        runCatching {
            connectivityManager?.allNetworks
                ?.asSequence()
                ?.mapNotNull { network -> connectivityManager.getNetworkCapabilities(network) }
                ?.firstOrNull {
                    it.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
                        it.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                }
                ?.transportInfo
                ?.let { it as? WifiInfo }
                ?.ssid
        }.getOrNull()
    } else {
        null
    }
    val fallbackSsid = runCatching {
        appContext.getSystemService(WifiManager::class.java)?.connectionInfo?.ssid
    }.getOrNull()
    val ssid = sanitizeTrustedWifiSsid(
        listOf(capabilitiesSsid, fallbackSsid)
            .firstOrNull { !it.isNullOrBlank() && !it.equals(UNKNOWN_WIFI_SSID, ignoreCase = true) }
            .orEmpty()
    )
    return ConnectedWifiState(connected = true, ssid = ssid)
}
