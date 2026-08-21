package com.wdtt.plus.ui

import android.content.Context
import android.content.SharedPreferences
import com.wdtt.plus.SecureStringStore

internal data class StoredOutboundForms(
    val forms: OutboundProfileForms,
    val warpMtu: String,
)

/**
 * Локальные черновики выходного IP относятся к конкретному VPN-профилю.
 * Пароли и WireGuard-конфиг хранятся через Android Keystore.
 */
internal class OutboundFormsStore(context: Context) {
    private val prefs =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val secureStore = SecureStringStore(context.applicationContext)

    init {
        migrateLegacyValuesToProfileZero()
    }

    fun load(profileIndex: Int): StoredOutboundForms {
        val profile = profileIndex.coerceIn(0, 2)
        return StoredOutboundForms(
            forms = OutboundProfileForms(
                localProxyPort = string(profile, LOCAL_PROXY_PORT, "1080"),
                localProxyLogin = string(profile, LOCAL_PROXY_LOGIN, ""),
                localProxyPassword = secret(profile, LOCAL_PROXY_PASSWORD),
                externalProxyKindName = string(profile, EXTERNAL_PROXY_KIND, "Socks5"),
                externalProxyHost = string(profile, EXTERNAL_PROXY_HOST, ""),
                externalProxyPort = string(profile, EXTERNAL_PROXY_PORT, "1080"),
                externalProxyLogin = string(profile, EXTERNAL_PROXY_LOGIN, ""),
                externalProxyPassword = secret(profile, EXTERNAL_PROXY_PASSWORD),
                wireGuardExitHost = string(profile, WG_EXIT_HOST, ""),
                wireGuardExitSshPort = string(profile, WG_EXIT_SSH_PORT, "22"),
                wireGuardExitUser = string(profile, WG_EXIT_USER, "root"),
                wireGuardExitPassword = secret(profile, WG_EXIT_PASSWORD),
                wireGuardExitPort = string(profile, WG_EXIT_PORT, "51820"),
                wireGuardExitDns = string(profile, WG_EXIT_DNS, "1.1.1.1,8.8.8.8"),
                importedWireGuardConfig = secret(profile, IMPORTED_WG_CONFIG),
                tunInterface = string(profile, TUN_INTERFACE, ""),
            ),
            warpMtu = string(profile, WARP_MTU, "1280"),
        )
    }

    fun save(profileIndex: Int, forms: OutboundProfileForms, warpMtu: String) {
        val profile = profileIndex.coerceIn(0, 2)
        val editor = prefs.edit()
            .putString(key(profile, LOCAL_PROXY_PORT), forms.localProxyPort)
            .putString(key(profile, LOCAL_PROXY_LOGIN), forms.localProxyLogin)
            .putString(key(profile, EXTERNAL_PROXY_KIND), forms.externalProxyKindName)
            .putString(key(profile, EXTERNAL_PROXY_HOST), forms.externalProxyHost)
            .putString(key(profile, EXTERNAL_PROXY_PORT), forms.externalProxyPort)
            .putString(key(profile, EXTERNAL_PROXY_LOGIN), forms.externalProxyLogin)
            .putString(key(profile, WG_EXIT_HOST), forms.wireGuardExitHost)
            .putString(key(profile, WG_EXIT_SSH_PORT), forms.wireGuardExitSshPort)
            .putString(key(profile, WG_EXIT_USER), forms.wireGuardExitUser)
            .putString(key(profile, WG_EXIT_PORT), forms.wireGuardExitPort)
            .putString(key(profile, WG_EXIT_DNS), forms.wireGuardExitDns)
            .putString(key(profile, TUN_INTERFACE), forms.tunInterface)
            .putString(key(profile, WARP_MTU), warpMtu)

        editor.putSecret(profile, LOCAL_PROXY_PASSWORD, forms.localProxyPassword)
        editor.putSecret(profile, EXTERNAL_PROXY_PASSWORD, forms.externalProxyPassword)
        editor.putSecret(profile, WG_EXIT_PASSWORD, forms.wireGuardExitPassword)
        editor.putSecret(profile, IMPORTED_WG_CONFIG, forms.importedWireGuardConfig)
        editor.apply()
    }

    private fun string(profile: Int, name: String, default: String): String =
        prefs.getString(key(profile, name), default) ?: default

    private fun secret(profile: Int, name: String): String {
        val encryptedKey = encryptedKey(profile, name)
        secureStore.decrypt(prefs.getString(encryptedKey, null))?.let { return it }
        return prefs.getString(key(profile, name), "").orEmpty()
    }

    private fun SharedPreferences.Editor.putSecret(profile: Int, name: String, value: String) {
        val plainKey = key(profile, name)
        remove(plainKey)
        if (value.isBlank()) {
            remove(encryptedKey(profile, name))
        } else {
            putString(encryptedKey(profile, name), secureStore.encrypt(value))
        }
    }

    private fun migrateLegacyValuesToProfileZero() {
        val legacyNames = NON_SECRET_NAMES + SECRET_NAMES
        if (legacyNames.none(prefs::contains)) return

        val editor = prefs.edit()
        NON_SECRET_NAMES.forEach { name ->
            if (prefs.contains(name) && !prefs.contains(key(0, name))) {
                editor.putString(key(0, name), prefs.getString(name, "").orEmpty())
            }
            editor.remove(name)
        }
        SECRET_NAMES.forEach { name ->
            val legacyValue = prefs.getString(name, "").orEmpty()
            if (
                legacyValue.isNotBlank() &&
                !prefs.contains(encryptedKey(0, name)) &&
                !prefs.contains(key(0, name))
            ) {
                editor.putString(encryptedKey(0, name), secureStore.encrypt(legacyValue))
            }
            editor.remove(name)
        }
        editor.apply()
    }

    companion object {
        const val PREFS_NAME = "wdtt_outbound_forms"

        private const val LOCAL_PROXY_PORT = "local_proxy_port"
        private const val LOCAL_PROXY_LOGIN = "local_proxy_login"
        private const val LOCAL_PROXY_PASSWORD = "local_proxy_password"
        private const val EXTERNAL_PROXY_KIND = "external_proxy_kind"
        private const val EXTERNAL_PROXY_HOST = "external_proxy_host"
        private const val EXTERNAL_PROXY_PORT = "external_proxy_port"
        private const val EXTERNAL_PROXY_LOGIN = "external_proxy_login"
        private const val EXTERNAL_PROXY_PASSWORD = "external_proxy_password"
        private const val WG_EXIT_HOST = "wg_exit_host"
        private const val WG_EXIT_SSH_PORT = "wg_exit_ssh_port"
        private const val WG_EXIT_USER = "wg_exit_user"
        private const val WG_EXIT_PASSWORD = "wg_exit_password"
        private const val WG_EXIT_PORT = "wg_exit_port"
        private const val WG_EXIT_DNS = "wg_exit_dns"
        private const val WARP_MTU = "warp_mtu"
        private const val IMPORTED_WG_CONFIG = "imported_wg_config"
        private const val TUN_INTERFACE = "tun_interface"

        private val NON_SECRET_NAMES = listOf(
            LOCAL_PROXY_PORT,
            LOCAL_PROXY_LOGIN,
            EXTERNAL_PROXY_KIND,
            EXTERNAL_PROXY_HOST,
            EXTERNAL_PROXY_PORT,
            EXTERNAL_PROXY_LOGIN,
            WG_EXIT_HOST,
            WG_EXIT_SSH_PORT,
            WG_EXIT_USER,
            WG_EXIT_PORT,
            WG_EXIT_DNS,
            WARP_MTU,
            TUN_INTERFACE,
        )
        private val SECRET_NAMES = listOf(
            LOCAL_PROXY_PASSWORD,
            EXTERNAL_PROXY_PASSWORD,
            WG_EXIT_PASSWORD,
            IMPORTED_WG_CONFIG,
        )

        internal fun key(profile: Int, name: String): String =
            "profile_${profile.coerceIn(0, 2)}_$name"

        internal fun encryptedKey(profile: Int, name: String): String =
            "${key(profile, name)}_encrypted"

        internal fun isSecretPlainKey(key: String): Boolean =
            SECRET_NAMES.any { key.endsWith("_$it") || key == it }
    }
}
