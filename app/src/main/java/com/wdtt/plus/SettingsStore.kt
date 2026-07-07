package com.wdtt.plus

import android.content.Context
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject

import android.os.Build

data class VkHashInsertResult(
    val slot: Int,
    val hash: String,
    val previousHash: String
)

data class WdttLinkParts(
    val host: String,
    val dtlsPort: Int,
    val wgPort: Int,
    val localPort: Int,
    val password: String,
    val hashes: String,
    val profileName: String = ""
)

data class WdttDeepLinkValidation(
    val parts: WdttLinkParts?,
    val errors: List<String>,
    val warnings: List<String> = emptyList()
) {
    val canStartVpn: Boolean = parts != null && errors.isEmpty()

    fun userMessage(): String {
        return if (canStartVpn) {
            buildString {
                append("Ссылка wdtt:// корректна. VPN сможет использовать эти данные для подключения.")
                parts?.profileName?.takeIf { it.isNotBlank() }?.let {
                    append("\nНазвание профиля: «")
                    append(it)
                    append("».")
                }
                if (warnings.isNotEmpty()) {
                    append("\n\nПредупреждения:\n")
                    append(warnings.joinToString("\n") { "• $it" })
                }
            }
        } else {
            buildString {
                append("VPN не запустится по этой ссылке, потому что в ней есть ошибки:\n")
                append(errors.joinToString("\n") { "• $it" })
                append("\n\nПравильный вид: wdtt://адрес:DTLS-порт:WG-порт:локальный-порт:пароль:VK-хеши")
            }
        }
    }
}

data class WdttDeepLinkApplyPlan(
    val link: String,
    val targetProfile: Int,
    val requiresConfirmation: Boolean,
    val storeAsLink: Boolean
)

data class WdttDeepLinkApplyResult(
    val targetProfile: Int,
    val overwritten: Boolean,
    val storedAsLink: Boolean
)

object WdttDeepLink {
    private val expectedFormat = "wdtt://адрес:DTLS-порт:WG-порт:локальный-порт:пароль:VK-хеши"

    fun parse(value: String): WdttLinkParts? {
        return validate(value).parts
    }

    fun validate(value: String): WdttDeepLinkValidation {
        val clean = WdttTransferCodec.extractWdttLink(value) ?: value.trim()
        val errors = mutableListOf<String>()
        val warnings = mutableListOf<String>()

        if (clean.isBlank()) {
            return WdttDeepLinkValidation(
                parts = null,
                errors = listOf("Ссылка пустая. Нужен вид: $expectedFormat.")
            )
        }

        if (!clean.startsWith("wdtt://", ignoreCase = true)) {
            return WdttDeepLinkValidation(
                parts = null,
                errors = listOf("Ссылка должна начинаться с wdtt://.")
            )
        }

        val modernParts = if (clean.startsWith("wdtt://connect?", ignoreCase = true)) {
            WdttTransferCodec.parseConnectionLink(clean)
        } else null
        if (clean.startsWith("wdtt://connect?", ignoreCase = true) && modernParts == null) {
            return WdttDeepLinkValidation(
                parts = null,
                errors = listOf("Новая ссылка повреждена, содержит неподдерживаемую версию или не все поля.")
            )
        }

        val parts = if (modernParts == null) clean.substringAfter("://").split(":") else emptyList()
        if (modernParts == null && parts.size != 6) {
            val found = parts.size
            val detail = when {
                found < 6 -> "не хватает ${6 - found} ${fieldWord(6 - found)}"
                else -> "лишние поля после VK-хешей"
            }
            return WdttDeepLinkValidation(
                parts = null,
                errors = listOf("В ссылке должно быть 6 полей после wdtt://, сейчас $found: $detail.")
            )
        }

        val host = modernParts?.host?.trim() ?: parts[0].trim()
        if (!isValidTunnelHost(host)) {
            errors += "Адрес сервера пустой или неверный. Нужен домен или IPv4 без https://, порта и пути."
        }

        val dtlsPort = validatePort((modernParts?.dtlsPort ?: parts[1]).toString(), "DTLS-порт", errors)
        val wgPort = validatePort((modernParts?.wgPort ?: parts[2]).toString(), "WG-порт", errors)
        val localPort = validatePort((modernParts?.localPort ?: parts[3]).toString(), "локальный порт", errors)

        val password = modernParts?.password?.trim() ?: parts[4].trim()
        if (password.isBlank()) {
            errors += "Не указан пароль туннеля."
        }

        val rawHashes = (modernParts?.hashes ?: parts[5]).split(",")
        val hashes = rawHashes
            .map { VkJoinLink.extractHash(it) }
            .filter { it.isNotBlank() && it.length >= 16 }
            .distinct()
            .joinToString(",")

        if (hashes.isBlank()) {
            errors += "Нет рабочего VK-хеша. Нужен хотя бы один хеш длиной от 16 символов или ссылка VK-звонка."
        } else {
            val invalidHashes = rawHashes
                .map { it.trim() }
                .filter { it.isNotBlank() }
                .count { VkJoinLink.extractHash(it).length < 16 }
            if (invalidHashes > 0) {
                warnings += "$invalidHashes ${hashWord(invalidHashes)} короче 16 символов и будет пропущено."
            }
        }

        val linkParts = if (errors.isEmpty() && dtlsPort != null && wgPort != null && localPort != null) {
            WdttLinkParts(
                host = host,
                dtlsPort = dtlsPort,
                wgPort = wgPort,
                localPort = localPort,
                password = password,
                hashes = hashes,
                profileName = normalizeVpnProfileName(modernParts?.profileName.orEmpty())
            )
        } else null

        return WdttDeepLinkValidation(linkParts, errors, warnings)
    }

    private fun validatePort(raw: String, label: String, errors: MutableList<String>): Int? {
        val value = raw.trim()
        if (value.isBlank()) {
            errors += "$label не указан."
            return null
        }
        val port = value.toIntOrNull()
        if (port == null) {
            errors += "$label должен быть числом от 1 до 65535."
            return null
        }
        if (port !in 1..65535) {
            errors += "$label вне диапазона 1-65535."
            return null
        }
        return port
    }

    private fun isValidTunnelHost(host: String): Boolean {
        if (host.isBlank() || host.contains("/") || host.contains(":")) return false
        val ipv4 = Regex("""^(\d{1,3}\.){3}\d{1,3}$""")
        if (ipv4.matches(host)) return host.split(".").all { it.toIntOrNull()?.let { n -> n in 0..255 } == true }
        return host.length <= 253 &&
            host.contains(".") &&
            host.split(".").all { label ->
                label.length in 1..63 &&
                    !label.startsWith("-") &&
                    !label.endsWith("-") &&
                    label.all { it.isLetterOrDigit() || it == '-' }
            }
    }

    private fun fieldWord(count: Int): String {
        return when {
            count % 10 == 1 && count % 100 != 11 -> "поля"
            count % 10 in 2..4 && count % 100 !in 12..14 -> "полей"
            else -> "полей"
        }
    }

    private fun hashWord(count: Int): String {
        return when {
            count % 10 == 1 && count % 100 != 11 -> "хеш"
            count % 10 in 2..4 && count % 100 !in 12..14 -> "хеша"
            else -> "хешей"
        }
    }
}

class SettingsStore(context: Context) {
    private val appContext = context.applicationContext
    private val storeScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val preferencesState: StateFlow<Preferences?> = appContext.dataStore.data.stateIn(
        storeScope,
        SharingStarted.Eagerly,
        null
    )
    private val preferencesFlow: Flow<Preferences> = preferencesState.filterNotNull()
    private val _settingsReady = MutableStateFlow(false)
    val settingsReady: StateFlow<Boolean> = _settingsReady.asStateFlow()

    init {
        storeScope.launch {
            preferencesFlow.first()
            _settingsReady.value = true
        }
    }

    companion object {
        private val Context.dataStore by preferencesDataStore("settings")
        private val ACTIVE_PROFILE = intPreferencesKey("active_profile")
        private val PROFILE_NAME = stringPreferencesKey("profile_name")
        private val SHOW_SYSTEM_APPS = booleanPreferencesKey("show_system_apps")
        private val LOGGING_ENABLED = booleanPreferencesKey("logging_enabled")
        private val TRUSTED_WIFI_ENABLED = booleanPreferencesKey("trusted_wifi_enabled")
        private val TRUSTED_WIFI_SSIDS = stringPreferencesKey("trusted_wifi_ssids")
        private val TRUSTED_WIFI_WAITING = booleanPreferencesKey("trusted_wifi_waiting")
        private val TRUSTED_WIFI_WAITING_SSID = stringPreferencesKey("trusted_wifi_waiting_ssid")
        private val WDTT_LINK = stringPreferencesKey("wdtt_link")
        private val WDTT_LINK_MODE = booleanPreferencesKey("wdtt_link_mode")

        private val PEER = stringPreferencesKey("peer")
        private val VK_HASHES = stringPreferencesKey("vk_hashes")
        private val SECONDARY_VK_HASH = stringPreferencesKey("secondary_vk_hash")
        private val VK_HASH_NEXT_SLOT = intPreferencesKey("vk_hash_next_slot")
        private val WORKERS_PER_HASH = intPreferencesKey("workers_per_hash")
        private val PROTOCOL = stringPreferencesKey("protocol")
        private val LISTEN_PORT = intPreferencesKey("listen_port")
        private val MANUAL_PORTS_ENABLED = booleanPreferencesKey("manual_ports_enabled")
        private val SERVER_DTLS_PORT = intPreferencesKey("server_dtls_port")
        private val SERVER_WG_PORT = intPreferencesKey("server_wg_port")
        private val SNI = stringPreferencesKey("sni")
        private val NO_DTLS = booleanPreferencesKey("no_dtls")
        private val NO_DNS = booleanPreferencesKey("no_dns")

        private val USER_AGENT = stringPreferencesKey("user_agent")

        private val DEPLOY_IP = stringPreferencesKey("deploy_ip")
        private val DEPLOY_LOGIN = stringPreferencesKey("deploy_login")
        private val DEPLOY_PASSWORD = stringPreferencesKey("deploy_password")
        private val DEPLOY_PASSWORD_ENCRYPTED = stringPreferencesKey("deploy_password_encrypted")
        private val DEPLOY_SSH_PRIVATE_KEY = stringPreferencesKey("deploy_ssh_private_key")
        private val DEPLOY_SSH_PRIVATE_KEY_ENCRYPTED = stringPreferencesKey("deploy_ssh_private_key_encrypted")
        private val DEPLOY_SSH_KEY_PASSPHRASE = stringPreferencesKey("deploy_ssh_key_passphrase")
        private val DEPLOY_SSH_KEY_PASSPHRASE_ENCRYPTED = stringPreferencesKey("deploy_ssh_key_passphrase_encrypted")
        private val DEPLOY_SSH_AUTH_MODE = stringPreferencesKey("deploy_ssh_auth_mode")
        private val WG_EXIT_SSH_PRIVATE_KEY = stringPreferencesKey("wg_exit_ssh_private_key")
        private val WG_EXIT_SSH_PRIVATE_KEY_ENCRYPTED = stringPreferencesKey("wg_exit_ssh_private_key_encrypted")
        private val WG_EXIT_SSH_KEY_PASSPHRASE = stringPreferencesKey("wg_exit_ssh_key_passphrase")
        private val WG_EXIT_SSH_KEY_PASSPHRASE_ENCRYPTED = stringPreferencesKey("wg_exit_ssh_key_passphrase_encrypted")
        private val WG_EXIT_SSH_AUTH_MODE = stringPreferencesKey("wg_exit_ssh_auth_mode")
        private val DEPLOY_SSH_PORT = stringPreferencesKey("deploy_ssh_port")
        private val DEPLOY_DNS1 = stringPreferencesKey("deploy_dns1")
        private val DEPLOY_DNS2 = stringPreferencesKey("deploy_dns2")
        private val EXCLUDED_APPS = stringPreferencesKey("excluded_apps")
        
        private val DETAILED_LOGS = booleanPreferencesKey("detailed_logs")
        
        // ═══ Пароли и Управление ═══
        private val CONNECTION_PASSWORD = stringPreferencesKey("connection_password")
        private val CONNECTION_PASSWORD_ENCRYPTED = stringPreferencesKey("connection_password_encrypted")
        private val DEPLOY_MAIN_PASSWORD = stringPreferencesKey("deploy_main_password")
        private val DEPLOY_MAIN_PASSWORD_ENCRYPTED = stringPreferencesKey("deploy_main_password_encrypted")
        private val DEPLOY_ADMIN_ID = stringPreferencesKey("deploy_admin_id")
        private val DEPLOY_ADMIN_ID_ENCRYPTED = stringPreferencesKey("deploy_admin_id_encrypted")
        private val DEPLOY_BOT_TOKEN = stringPreferencesKey("deploy_bot_token")
        private val DEPLOY_BOT_TOKEN_ENCRYPTED = stringPreferencesKey("deploy_bot_token_encrypted")

        // ═══ Proxy Mode ═══
        private val PROXY_MODE = stringPreferencesKey("proxy_mode") // "tun" or "socks5"
        private val PROXY_HOST = stringPreferencesKey("proxy_host")
        private val PROXY_PORT = intPreferencesKey("proxy_port")

        // ═══ Captcha Solve Mode ═══
        private val VKCALLS_PREFLIGHT = booleanPreferencesKey("vkcalls_preflight")
        private val CAPTCHA_MODE = stringPreferencesKey("captcha_mode") // "auto", "wv", or "rjs"
        private val CAPTCHA_SOLVE_METHOD = stringPreferencesKey("captcha_solve_method") // "manual" or "auto"
        private val CAPTCHA_WBV_SOLVE_METHOD = stringPreferencesKey("captcha_wbv_solve_method") // "manual" or "auto"
        
        // ═══ VPN App Routing ═══
        private val IS_WHITELIST = booleanPreferencesKey("is_whitelist")
        private val BLACKLIST_APPS = stringPreferencesKey("blacklist_apps")
        private val WHITELIST_APPS = stringPreferencesKey("whitelist_apps")

        // ═══ Theme Mode ═══
        private val THEME_MODE = stringPreferencesKey("theme_mode") // "system", "light", "dark"
        private val IS_DYNAMIC_COLOR = booleanPreferencesKey("is_dynamic_color")
        private val THEME_PALETTE = stringPreferencesKey("theme_palette")

        // ═══ Fingerprint & Client IDs ═══
        private val SELECTED_FINGERPRINT = stringPreferencesKey("selected_fingerprint")
        private val ACTIVE_CLIENT_IDS = stringPreferencesKey("active_client_ids")

        private val UPDATE_LAST_CHECK_AT = longPreferencesKey("update_last_check_at")
        private val UPDATE_LATEST_VERSION = stringPreferencesKey("update_latest_version")
        private val UPDATE_LAST_ERROR = stringPreferencesKey("update_last_error")
        private val UPDATE_CHECK_INTERVAL_MINUTES = intPreferencesKey("update_check_interval_hours")
        private val UPDATE_POSTPONE_UNTIL = longPreferencesKey("update_postpone_until")
        private val UPDATE_POSTPONE_VERSION = stringPreferencesKey("update_postpone_version")
        private val UPDATE_DIALOG_LAST_SHOWN_VERSION = stringPreferencesKey("update_dialog_last_shown_version")
        private val UPDATE_DIALOG_LAST_SHOWN_AT = longPreferencesKey("update_dialog_last_shown_at")
        private val UPDATE_DIALOG_LAST_ACTION_VERSION = stringPreferencesKey("update_dialog_last_action_version")
        private val UPDATE_DIALOG_LAST_ACTION = stringPreferencesKey("update_dialog_last_action")
        private val UPDATE_DIALOG_LAST_ACTION_AT = longPreferencesKey("update_dialog_last_action_at")
        private val MIGRATION_NOTICE_V2_SHOWN = booleanPreferencesKey("migration_notice_v2_shown")
        private val MIGRATION_NOTICE_V3_SHOWN = booleanPreferencesKey("migration_notice_v3_shown")
        private val MIGRATION_NOTICE_V5_SHOWN = booleanPreferencesKey("migration_notice_v5_shown")
        private val SERVER_MIGRATION_STATE_INITIALIZED = booleanPreferencesKey("server_migration_state_initialized")
        private val LAST_SEEN_APP_VERSION_CODE = intPreferencesKey("last_seen_app_version_code")
        private val SERVER_MIGRATION_PENDING_LEVEL = intPreferencesKey("server_migration_pending_level")
        private val SERVER_MIGRATION_NOTICE_ACK_LEVEL = intPreferencesKey("server_migration_notice_ack_level")
        private val SERVER_MIGRATION_COMPLETED_LEVEL = intPreferencesKey("server_migration_completed_level")
        private val DEVICE_COMPATIBILITY_CHECK_COMPLETE = booleanPreferencesKey("device_compatibility_check_complete")
        private val DEPLOY_CLIENTS_SECTION_EXPANDED = booleanPreferencesKey("deploy_clients_section_expanded")
        private val DEPLOY_OUTBOUND_SECTION_EXPANDED = booleanPreferencesKey("deploy_outbound_section_expanded")
        private val DEPLOY_MIGRATION_SECTION_EXPANDED = booleanPreferencesKey("deploy_migration_section_expanded")

        private val CLIENT_ID_CHECK_RESULTS = stringPreferencesKey("client_id_check_results")
        private val INTERFACE_ROLE = stringPreferencesKey("interface_role")
        private val PERMISSION_ONBOARDING_COMPLETE = booleanPreferencesKey("permission_onboarding_complete")
        private const val VPN_PROFILE_COUNT = 3

        private fun <T> getProfileKey(baseKey: Preferences.Key<T>, profile: Int): Preferences.Key<T> {
            if (profile == 0) return baseKey
            val newName = "${baseKey.name}_$profile"
            @Suppress("UNCHECKED_CAST")
            return when (baseKey) {
                PROFILE_NAME, PEER, VK_HASHES, SECONDARY_VK_HASH, PROTOCOL, SNI, USER_AGENT, DEPLOY_IP, DEPLOY_LOGIN, DEPLOY_PASSWORD, DEPLOY_PASSWORD_ENCRYPTED, DEPLOY_SSH_PRIVATE_KEY, DEPLOY_SSH_PRIVATE_KEY_ENCRYPTED, DEPLOY_SSH_KEY_PASSPHRASE, DEPLOY_SSH_KEY_PASSPHRASE_ENCRYPTED, DEPLOY_SSH_AUTH_MODE, WG_EXIT_SSH_PRIVATE_KEY, WG_EXIT_SSH_PRIVATE_KEY_ENCRYPTED, WG_EXIT_SSH_KEY_PASSPHRASE, WG_EXIT_SSH_KEY_PASSPHRASE_ENCRYPTED, WG_EXIT_SSH_AUTH_MODE, DEPLOY_SSH_PORT, DEPLOY_DNS1, DEPLOY_DNS2, EXCLUDED_APPS, BLACKLIST_APPS, WHITELIST_APPS, CONNECTION_PASSWORD, CONNECTION_PASSWORD_ENCRYPTED, DEPLOY_MAIN_PASSWORD, DEPLOY_MAIN_PASSWORD_ENCRYPTED, DEPLOY_ADMIN_ID, DEPLOY_ADMIN_ID_ENCRYPTED, DEPLOY_BOT_TOKEN, DEPLOY_BOT_TOKEN_ENCRYPTED, PROXY_MODE, PROXY_HOST, CAPTCHA_MODE, CAPTCHA_SOLVE_METHOD, CAPTCHA_WBV_SOLVE_METHOD, WDTT_LINK, SELECTED_FINGERPRINT, ACTIVE_CLIENT_IDS -> stringPreferencesKey(newName) as Preferences.Key<T>
                WORKERS_PER_HASH, VK_HASH_NEXT_SLOT, LISTEN_PORT, SERVER_DTLS_PORT, SERVER_WG_PORT, PROXY_PORT -> intPreferencesKey(newName) as Preferences.Key<T>
                MANUAL_PORTS_ENABLED, NO_DTLS, NO_DNS, IS_WHITELIST, WDTT_LINK_MODE, VKCALLS_PREFLIGHT, DETAILED_LOGS -> booleanPreferencesKey(newName) as Preferences.Key<T>
                else -> throw IllegalArgumentException("Unsupported key type: ${baseKey.name}")
            }
        }
    }

    private val dataStore = appContext.dataStore
    private val secureStore = SecureStringStore(appContext)

    init {
        CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
            migrateSecretsToKeystore()
            migrateWireGuardExitSshAuthMode()
            migrateVpnAppLists()
        }
    }

    val activeProfile: Flow<Int> = preferencesFlow.map { it[ACTIVE_PROFILE] ?: 0 }
    val profileNames: Flow<List<String>> = preferencesFlow.map { prefs ->
        (0 until VPN_PROFILE_COUNT).map { profile ->
            prefs[getProfileKey(PROFILE_NAME, profile)].orEmpty()
        }
    }
    val showSystemApps: Flow<Boolean> = preferencesFlow.map { it[SHOW_SYSTEM_APPS] ?: false }
    val loggingEnabled: Flow<Boolean> = preferencesFlow.map { it[LOGGING_ENABLED] ?: true }
    val trustedWifiEnabled: Flow<Boolean> = preferencesFlow.map { it[TRUSTED_WIFI_ENABLED] ?: false }
    val trustedWifiSsids: Flow<List<String>> = preferencesFlow.map { prefs ->
        parseTrustedWifiSsids(prefs[TRUSTED_WIFI_SSIDS].orEmpty())
    }
    val trustedWifiWaiting: Flow<Boolean> = preferencesFlow.map { it[TRUSTED_WIFI_WAITING] ?: false }
    val trustedWifiWaitingSsid: Flow<String> = preferencesFlow.map {
        sanitizeTrustedWifiSsid(it[TRUSTED_WIFI_WAITING_SSID].orEmpty())
    }
    val wdttLink: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(WDTT_LINK, profile)] ?: ""
    }
    val wdttLinkMode: Flow<Boolean> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(WDTT_LINK_MODE, profile)] ?: false
    }

    val peer: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(PEER, profile)] ?: ""
    }
    val vkHashes: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(VK_HASHES, profile)] ?: ""
    }
    val secondaryVkHash: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(SECONDARY_VK_HASH, profile)] ?: ""
    }
    val workersPerHash: Flow<Int> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(WORKERS_PER_HASH, profile)] ?: 16
    }
    val protocol: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(PROTOCOL, profile)] ?: "udp"
    }
    val listenPort: Flow<Int> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(LISTEN_PORT, profile)] ?: 9000
    }
    val manualPortsEnabled: Flow<Boolean> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(MANUAL_PORTS_ENABLED, profile)] ?: false
    }
    val serverDtlsPort: Flow<Int> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(SERVER_DTLS_PORT, profile)] ?: 56000
    }
    val serverWgPort: Flow<Int> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(SERVER_WG_PORT, profile)] ?: 56001
    }
    val sni: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(SNI, profile)] ?: ""
    }
    val noDns: Flow<Boolean> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(NO_DNS, profile)] ?: false
    }
    val userAgent: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(USER_AGENT, profile)] ?: ""
    }

    val deployIp: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(DEPLOY_IP, profile)] ?: ""
    }
    val deployLogin: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(DEPLOY_LOGIN, profile)] ?: ""
    }
    val deployPassword: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        readSecret(prefs, DEPLOY_PASSWORD_ENCRYPTED, DEPLOY_PASSWORD, profile)
    }
    val deploySshPrivateKey: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        readSecret(prefs, DEPLOY_SSH_PRIVATE_KEY_ENCRYPTED, DEPLOY_SSH_PRIVATE_KEY, profile)
    }
    val deploySshKeyPassphrase: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        readSecret(prefs, DEPLOY_SSH_KEY_PASSPHRASE_ENCRYPTED, DEPLOY_SSH_KEY_PASSPHRASE, profile)
    }
    val deploySshAuthMode: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(DEPLOY_SSH_AUTH_MODE, profile)]
            ?.takeIf { it == "password" || it == "key" }
            ?: if (readSecret(prefs, DEPLOY_SSH_PRIVATE_KEY_ENCRYPTED, DEPLOY_SSH_PRIVATE_KEY, profile).isNotBlank()) "key" else "password"
    }
    val wireGuardExitSshPrivateKey: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        readSecret(prefs, WG_EXIT_SSH_PRIVATE_KEY_ENCRYPTED, WG_EXIT_SSH_PRIVATE_KEY, profile)
    }
    val wireGuardExitSshKeyPassphrase: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        readSecret(prefs, WG_EXIT_SSH_KEY_PASSPHRASE_ENCRYPTED, WG_EXIT_SSH_KEY_PASSPHRASE, profile)
    }
    val wireGuardExitSshAuthMode: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(WG_EXIT_SSH_AUTH_MODE, profile)]
            ?.takeIf { it == "password" || it == "key" }
            ?: if (readSecret(prefs, WG_EXIT_SSH_PRIVATE_KEY_ENCRYPTED, WG_EXIT_SSH_PRIVATE_KEY, profile).isNotBlank()) "key" else "password"
    }
    val deploySshPort: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(DEPLOY_SSH_PORT, profile)] ?: ""
    }
    val deployDns1: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(DEPLOY_DNS1, profile)] ?: "1.1.1.1"
    }
    val deployDns2: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(DEPLOY_DNS2, profile)] ?: "1.0.0.1"
    }
    val vpnAppPackages: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        val baseKey = if (prefs[getProfileKey(IS_WHITELIST, profile)] == true) {
            WHITELIST_APPS
        } else {
            BLACKLIST_APPS
        }
        prefs[getProfileKey(baseKey, profile)] ?: ""
    }
    
    val detailedLogs: Flow<Boolean> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(DETAILED_LOGS, profile)] ?: false
    }
    
    // ═══ Пароли и Управление ═══
    val connectionPassword: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        readSecret(prefs, CONNECTION_PASSWORD_ENCRYPTED, CONNECTION_PASSWORD, profile)
    }
    val deployMainPassword: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        readSecret(prefs, DEPLOY_MAIN_PASSWORD_ENCRYPTED, DEPLOY_MAIN_PASSWORD, profile)
    }
    val deployAdminId: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        readSecret(prefs, DEPLOY_ADMIN_ID_ENCRYPTED, DEPLOY_ADMIN_ID, profile)
    }
    val deployBotToken: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        readSecret(prefs, DEPLOY_BOT_TOKEN_ENCRYPTED, DEPLOY_BOT_TOKEN, profile)
    }

    // ═══ Proxy Mode ═══
    val proxyMode: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(PROXY_MODE, profile)] ?: "tun"
    }
    val proxyHost: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(PROXY_HOST, profile)] ?: "127.0.0.1"
    }
    val proxyPort: Flow<Int> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(PROXY_PORT, profile)] ?: 1080
    }

    // ═══ Captcha Solve Mode ═══
    val vkCallsPreflight: Flow<Boolean> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(VKCALLS_PREFLIGHT, profile)] ?: true
    }
    val captchaMode: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(CAPTCHA_MODE, profile)] ?: "auto"
    }
    val captchaSolveMethod: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(CAPTCHA_SOLVE_METHOD, profile)] ?: "auto"
    }
    val captchaWbvSolveMethod: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(CAPTCHA_WBV_SOLVE_METHOD, profile)] ?: "auto"
    }

    // ═══ VPN Exclusions Mode ═══
    val isWhitelist: Flow<Boolean> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(IS_WHITELIST, profile)] ?: false
    }

    // ═══ Theme Mode ═══
    val themeMode: Flow<String> = preferencesFlow.map { it[THEME_MODE] ?: "system" }
    val isDynamicColor: Flow<Boolean> = preferencesFlow.map { it[IS_DYNAMIC_COLOR] ?: (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) }
    val themePalette: Flow<String> = preferencesFlow.map { it[THEME_PALETTE] ?: "indigo" }

    // ═══ Fingerprint & Client IDs ═══
    val selectedFingerprint: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(SELECTED_FINGERPRINT, profile)] ?: "firefox"
    }
    val activeClientIds: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(ACTIVE_CLIENT_IDS, profile)] ?: "6287487,8202606"
    }
    val clientIdCheckResults: Flow<String> = preferencesFlow.map { prefs ->
        prefs[CLIENT_ID_CHECK_RESULTS] ?: "{}"
    }

    val updateLastCheckAt: Flow<Long> = preferencesFlow.map { it[UPDATE_LAST_CHECK_AT] ?: 0L }
    val updateLatestVersion: Flow<String> = preferencesFlow.map { it[UPDATE_LATEST_VERSION] ?: "" }
    val updateLastError: Flow<String> = preferencesFlow.map { it[UPDATE_LAST_ERROR] ?: "" }
    val updateCheckIntervalMinutes: Flow<Int> = preferencesFlow.map {
        normalizeUpdateCheckIntervalMinutes(it[UPDATE_CHECK_INTERVAL_MINUTES] ?: DEFAULT_UPDATE_CHECK_INTERVAL_MINUTES)
    }
    val updatePostponeUntil: Flow<Long> = preferencesFlow.map { it[UPDATE_POSTPONE_UNTIL] ?: 0L }
    val updatePostponeVersion: Flow<String> = preferencesFlow.map { it[UPDATE_POSTPONE_VERSION] ?: "" }
    val updateDialogLastShownVersion: Flow<String> = preferencesFlow.map { it[UPDATE_DIALOG_LAST_SHOWN_VERSION] ?: "" }
    val updateDialogLastShownAt: Flow<Long> = preferencesFlow.map { it[UPDATE_DIALOG_LAST_SHOWN_AT] ?: 0L }
    val updateDialogLastActionVersion: Flow<String> = preferencesFlow.map { it[UPDATE_DIALOG_LAST_ACTION_VERSION] ?: "" }
    val updateDialogLastAction: Flow<String> = preferencesFlow.map { it[UPDATE_DIALOG_LAST_ACTION] ?: "" }
    val updateDialogLastActionAt: Flow<Long> = preferencesFlow.map { it[UPDATE_DIALOG_LAST_ACTION_AT] ?: 0L }
    val serverMigrationState: Flow<ServerMigrationState?> = preferencesFlow.map { prefs ->
        if (prefs[SERVER_MIGRATION_STATE_INITIALIZED] != true) {
            null
        } else {
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            ServerMigrationState(
                pendingLevel = prefs[SERVER_MIGRATION_PENDING_LEVEL] ?: 0,
                acknowledgedLevel = prefs[SERVER_MIGRATION_NOTICE_ACK_LEVEL] ?: 0,
                completedLevel = prefs[serverMigrationCompletedKey(profile)] ?: 0
            )
        }
    }
    val deviceCompatibilityCheckComplete: Flow<Boolean> = preferencesFlow.map {
        it[DEVICE_COMPATIBILITY_CHECK_COMPLETE] ?: false
    }
    val deployClientsSectionExpanded: Flow<Boolean> = preferencesFlow.map { it[DEPLOY_CLIENTS_SECTION_EXPANDED] ?: false }
    val deployOutboundSectionExpanded: Flow<Boolean> = preferencesFlow.map { it[DEPLOY_OUTBOUND_SECTION_EXPANDED] ?: false }
    val deployMigrationSectionExpanded: Flow<Boolean> = preferencesFlow.map { it[DEPLOY_MIGRATION_SECTION_EXPANDED] ?: false }
    val interfaceRole: Flow<String> = preferencesFlow.map { it[INTERFACE_ROLE] ?: "" }
    val permissionOnboardingComplete: Flow<Boolean> = preferencesFlow.map { prefs ->
        prefs[PERMISSION_ONBOARDING_COMPLETE] ?: !prefs[INTERFACE_ROLE].isNullOrBlank()
    }

    suspend fun saveInterfaceRole(role: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            val hadRole = !prefs[INTERFACE_ROLE].isNullOrBlank()
            prefs[INTERFACE_ROLE] = role
            prefs[getProfileKey(WDTT_LINK_MODE, profile)] = role == "user"
            if (!hadRole && !prefs.contains(PERMISSION_ONBOARDING_COMPLETE)) {
                prefs[PERMISSION_ONBOARDING_COMPLETE] = false
            }
        }
    }

    suspend fun savePermissionOnboardingComplete(complete: Boolean) {
        dataStore.edit { prefs ->
            prefs[PERMISSION_ONBOARDING_COMPLETE] = complete
        }
    }

    suspend fun saveThemeMode(mode: String) {
        dataStore.edit { prefs ->
            prefs[THEME_MODE] = mode
        }
    }

    suspend fun saveDynamicColor(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[IS_DYNAMIC_COLOR] = enabled
        }
    }

    suspend fun saveThemePalette(palette: String) {
        dataStore.edit { prefs ->
            prefs[THEME_PALETTE] = palette
        }
    }

    suspend fun saveFingerprint(fingerprint: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(SELECTED_FINGERPRINT, profile)] = fingerprint
        }
    }

    suspend fun saveActiveClientIds(clientIds: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(ACTIVE_CLIENT_IDS, profile)] = clientIds
        }
    }

    suspend fun saveClientIdCheckResults(resultsJson: String) {
        dataStore.edit { prefs ->
            prefs[CLIENT_ID_CHECK_RESULTS] = resultsJson
        }
    }

    suspend fun saveUpdateState(lastCheckAt: Long, latestVersion: String, error: String) {
        dataStore.edit { prefs ->
            prefs[UPDATE_LAST_CHECK_AT] = lastCheckAt
            prefs[UPDATE_LATEST_VERSION] = latestVersion
            prefs[UPDATE_LAST_ERROR] = error
        }
    }

    suspend fun saveUpdateCheckIntervalMinutes(minutes: Int) {
        dataStore.edit { prefs ->
            prefs[UPDATE_CHECK_INTERVAL_MINUTES] = normalizeUpdateCheckIntervalMinutes(minutes)
        }
    }

    suspend fun saveUpdatePostpone(version: String, until: Long) {
        dataStore.edit { prefs ->
            prefs[UPDATE_POSTPONE_VERSION] = version
            prefs[UPDATE_POSTPONE_UNTIL] = until
        }
    }

    suspend fun saveUpdateDialogShown(version: String, shownAt: Long) {
        dataStore.edit { prefs ->
            prefs[UPDATE_DIALOG_LAST_SHOWN_VERSION] = version
            prefs[UPDATE_DIALOG_LAST_SHOWN_AT] = shownAt
        }
    }

    suspend fun saveUpdateDialogAction(version: String, action: String, actedAt: Long) {
        dataStore.edit { prefs ->
            prefs[UPDATE_DIALOG_LAST_ACTION_VERSION] = version
            prefs[UPDATE_DIALOG_LAST_ACTION] = action
            prefs[UPDATE_DIALOG_LAST_ACTION_AT] = actedAt
        }
    }

    suspend fun initializeServerMigrationState(currentVersionCode: Int, isUpdatedInstall: Boolean) {
        dataStore.edit { prefs ->
            val legacyAcknowledgedLevel = when {
                prefs[MIGRATION_NOTICE_V5_SHOWN] == true -> 5
                prefs[MIGRATION_NOTICE_V3_SHOWN] == true -> 3
                prefs[MIGRATION_NOTICE_V2_SHOWN] == true -> 2
                else -> 0
            }
            val result = resolveServerMigrationInitialization(
                currentVersionCode = currentVersionCode,
                isUpdatedInstall = isUpdatedInstall,
                storedLastSeenAppVersionCode = prefs[LAST_SEEN_APP_VERSION_CODE],
                storedPendingLevel = prefs[SERVER_MIGRATION_PENDING_LEVEL] ?: 0,
                storedAcknowledgedLevel = prefs[SERVER_MIGRATION_NOTICE_ACK_LEVEL],
                legacyAcknowledgedLevel = legacyAcknowledgedLevel
            )
            prefs[LAST_SEEN_APP_VERSION_CODE] = result.lastSeenAppVersionCode
            prefs[SERVER_MIGRATION_PENDING_LEVEL] = result.pendingLevel
            prefs[SERVER_MIGRATION_NOTICE_ACK_LEVEL] = result.acknowledgedLevel
            prefs[SERVER_MIGRATION_STATE_INITIALIZED] = true
        }
    }

    suspend fun acknowledgeServerMigrationNotice(level: Int) {
        if (level <= 0) return
        dataStore.edit { prefs ->
            prefs[SERVER_MIGRATION_NOTICE_ACK_LEVEL] = maxOf(
                prefs[SERVER_MIGRATION_NOTICE_ACK_LEVEL] ?: 0,
                level
            )
        }
    }

    suspend fun markProfileServerMigrationComplete(profile: Int, level: Int) {
        if (level <= 0) return
        dataStore.edit { prefs ->
            val key = serverMigrationCompletedKey(profile.coerceIn(0, VPN_PROFILE_COUNT - 1))
            prefs[key] = maxOf(prefs[key] ?: 0, level)
        }
    }

    suspend fun saveDeviceCompatibilityCheckComplete(complete: Boolean) {
        dataStore.edit { prefs ->
            prefs[DEVICE_COMPATIBILITY_CHECK_COMPLETE] = complete
        }
    }

    private fun serverMigrationCompletedKey(profile: Int): Preferences.Key<Int> =
        if (profile == 0) SERVER_MIGRATION_COMPLETED_LEVEL
        else intPreferencesKey("${SERVER_MIGRATION_COMPLETED_LEVEL.name}_$profile")

    suspend fun saveDeployClientsSectionExpanded(expanded: Boolean) {
        dataStore.edit { prefs ->
            prefs[DEPLOY_CLIENTS_SECTION_EXPANDED] = expanded
        }
    }

    suspend fun saveDeployOutboundSectionExpanded(expanded: Boolean) {
        dataStore.edit { prefs ->
            prefs[DEPLOY_OUTBOUND_SECTION_EXPANDED] = expanded
        }
    }

    suspend fun saveDeployMigrationSectionExpanded(expanded: Boolean) {
        dataStore.edit { prefs ->
            prefs[DEPLOY_MIGRATION_SECTION_EXPANDED] = expanded
        }
    }

    suspend fun saveActiveProfile(profile: Int) {
        dataStore.edit { prefs ->
            prefs[ACTIVE_PROFILE] = profile
        }
    }

    suspend fun saveProfileName(profile: Int, name: String) {
        dataStore.edit { prefs ->
            val index = profile.coerceIn(0, VPN_PROFILE_COUNT - 1)
            val clean = normalizeVpnProfileName(name)
            val key = getProfileKey(PROFILE_NAME, index)
            if (clean.isBlank() || clean == vpnProfileDefaultName(index)) {
                prefs.remove(key)
            } else {
                prefs[key] = clean
            }
        }
    }

    suspend fun saveShowSystemApps(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[SHOW_SYSTEM_APPS] = enabled
        }
    }

    suspend fun saveLoggingEnabled(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[LOGGING_ENABLED] = enabled
        }
    }

    suspend fun saveTrustedWifiEnabled(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[TRUSTED_WIFI_ENABLED] = enabled
            if (!enabled) {
                prefs.remove(TRUSTED_WIFI_WAITING)
                prefs.remove(TRUSTED_WIFI_WAITING_SSID)
            }
        }
    }

    suspend fun addTrustedWifiSsid(ssid: String): Boolean {
        val clean = sanitizeTrustedWifiSsid(ssid)
        if (clean.isBlank()) return false
        var added = false
        dataStore.edit { prefs ->
            val values = parseTrustedWifiSsids(prefs[TRUSTED_WIFI_SSIDS].orEmpty()).toMutableList()
            if (clean !in values) {
                values.add(clean)
                added = true
            }
            prefs[TRUSTED_WIFI_SSIDS] = JSONArray(values).toString()
        }
        return added
    }

    suspend fun removeTrustedWifiSsid(ssid: String) {
        val clean = sanitizeTrustedWifiSsid(ssid)
        dataStore.edit { prefs ->
            val values = parseTrustedWifiSsids(prefs[TRUSTED_WIFI_SSIDS].orEmpty())
                .filterNot { it == clean }
            if (values.isEmpty()) prefs.remove(TRUSTED_WIFI_SSIDS)
            else prefs[TRUSTED_WIFI_SSIDS] = JSONArray(values).toString()
        }
    }

    suspend fun saveTrustedWifiWaiting(waiting: Boolean, ssid: String = "") {
        dataStore.edit { prefs ->
            if (waiting) {
                prefs[TRUSTED_WIFI_WAITING] = true
                prefs[TRUSTED_WIFI_WAITING_SSID] = sanitizeTrustedWifiSsid(ssid)
            } else {
                prefs.remove(TRUSTED_WIFI_WAITING)
                prefs.remove(TRUSTED_WIFI_WAITING_SSID)
            }
        }
    }

    suspend fun saveWdttLink(link: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(WDTT_LINK, profile)] = link
            val importedProfileName = vpnProfileRestorableName(WdttDeepLink.parse(link)?.profileName.orEmpty())
            if (importedProfileName.isNotBlank()) {
                val profileNameKey = getProfileKey(PROFILE_NAME, profile)
                prefs[profileNameKey] = importedProfileName
            }
        }
    }

    suspend fun createWdttDeepLinkApplyPlan(link: String): WdttDeepLinkApplyPlan? {
        WdttDeepLink.parse(link) ?: return null
        val cleanLink = link.trim()
        return appContext.dataStore.data.map { prefs ->
            val activeProfile = (prefs[ACTIVE_PROFILE] ?: 0).coerceIn(0, VPN_PROFILE_COUNT - 1)
            val freeProfile = (0 until VPN_PROFILE_COUNT).firstOrNull { profile ->
                prefs.isTunnelProfileEmpty(profile)
            }
            WdttDeepLinkApplyPlan(
                link = cleanLink,
                targetProfile = freeProfile ?: activeProfile,
                requiresConfirmation = freeProfile == null,
                storeAsLink = false
            )
        }.first()
    }

    suspend fun connectionLinkForProfile(profileIndex: Int): String {
        val profile = profileIndex.coerceIn(0, VPN_PROFILE_COUNT - 1)
        return appContext.dataStore.data.map { prefs ->
            val storedLink = prefs[getProfileKey(WDTT_LINK, profile)].orEmpty()
            val storedParts = WdttDeepLink.parse(storedLink)
            val parts = storedParts ?: WdttLinkParts(
                host = prefs[getProfileKey(PEER, profile)].orEmpty().trim(),
                dtlsPort = prefs[getProfileKey(SERVER_DTLS_PORT, profile)] ?: 56000,
                wgPort = prefs[getProfileKey(SERVER_WG_PORT, profile)] ?: 56001,
                localPort = prefs[getProfileKey(LISTEN_PORT, profile)] ?: 9000,
                password = readSecret(prefs, CONNECTION_PASSWORD_ENCRYPTED, CONNECTION_PASSWORD, profile),
                hashes = prefs[getProfileKey(VK_HASHES, profile)].orEmpty()
            )
            val names = (0 until VPN_PROFILE_COUNT).map { index ->
                prefs[getProfileKey(PROFILE_NAME, index)].orEmpty()
            }
            val profileLabel = vpnProfileDisplayName(profile, names)
            val link = WdttTransferCodec.buildConnectionLink(
                parts.copy(profileName = vpnProfileTransferName(profile, names))
            )
            val validation = WdttDeepLink.validate(link)
            require(validation.canStartVpn) {
                "Профиль «$profileLabel» заполнен не полностью. Проверьте адрес, порты, пароль и VK-хеши."
            }
            link
        }.first()
    }

    suspend fun exportAdminSettings(): String = appContext.dataStore.data.map { prefs ->
        val profiles = JSONArray()
        repeat(VPN_PROFILE_COUNT) { profile ->
            profiles.put(JSONObject().apply {
                put("wdttLink", prefs[getProfileKey(WDTT_LINK, profile)].orEmpty())
                put("wdttLinkMode", prefs[getProfileKey(WDTT_LINK_MODE, profile)] ?: false)
                put("peer", prefs[getProfileKey(PEER, profile)].orEmpty())
                put("vkHashes", prefs[getProfileKey(VK_HASHES, profile)].orEmpty())
                put("secondaryVkHash", prefs[getProfileKey(SECONDARY_VK_HASH, profile)].orEmpty())
                put("workersPerHash", prefs[getProfileKey(WORKERS_PER_HASH, profile)] ?: 16)
                put("protocol", prefs[getProfileKey(PROTOCOL, profile)] ?: "udp")
                put("listenPort", prefs[getProfileKey(LISTEN_PORT, profile)] ?: 9000)
                put("manualPortsEnabled", prefs[getProfileKey(MANUAL_PORTS_ENABLED, profile)] ?: false)
                put("serverDtlsPort", prefs[getProfileKey(SERVER_DTLS_PORT, profile)] ?: 56000)
                put("serverWgPort", prefs[getProfileKey(SERVER_WG_PORT, profile)] ?: 56001)
                put("sni", prefs[getProfileKey(SNI, profile)].orEmpty())
                put("noDtls", prefs[getProfileKey(NO_DTLS, profile)] ?: false)
                put("noDns", prefs[getProfileKey(NO_DNS, profile)] ?: false)
                put("userAgent", prefs[getProfileKey(USER_AGENT, profile)].orEmpty())
                put("connectionPassword", readSecret(prefs, CONNECTION_PASSWORD_ENCRYPTED, CONNECTION_PASSWORD, profile))
                put("deployIp", prefs[getProfileKey(DEPLOY_IP, profile)].orEmpty())
                put("deployLogin", prefs[getProfileKey(DEPLOY_LOGIN, profile)].orEmpty())
                put("deployPassword", readSecret(prefs, DEPLOY_PASSWORD_ENCRYPTED, DEPLOY_PASSWORD, profile))
                put("deploySshPort", prefs[getProfileKey(DEPLOY_SSH_PORT, profile)].orEmpty())
                put("deployDns1", prefs[getProfileKey(DEPLOY_DNS1, profile)] ?: "1.1.1.1")
                put("deployDns2", prefs[getProfileKey(DEPLOY_DNS2, profile)] ?: "1.0.0.1")
                put("deployMainPassword", readSecret(prefs, DEPLOY_MAIN_PASSWORD_ENCRYPTED, DEPLOY_MAIN_PASSWORD, profile))
                put("deployAdminId", readSecret(prefs, DEPLOY_ADMIN_ID_ENCRYPTED, DEPLOY_ADMIN_ID, profile))
                put("deployBotToken", readSecret(prefs, DEPLOY_BOT_TOKEN_ENCRYPTED, DEPLOY_BOT_TOKEN, profile))
                put("proxyMode", prefs[getProfileKey(PROXY_MODE, profile)] ?: "tun")
                put("proxyHost", prefs[getProfileKey(PROXY_HOST, profile)] ?: "127.0.0.1")
                put("proxyPort", prefs[getProfileKey(PROXY_PORT, profile)] ?: 1080)
                put("vkCallsPreflight", prefs[getProfileKey(VKCALLS_PREFLIGHT, profile)] ?: true)
                put("captchaMode", prefs[getProfileKey(CAPTCHA_MODE, profile)] ?: "auto")
                put("captchaSolveMethod", prefs[getProfileKey(CAPTCHA_SOLVE_METHOD, profile)] ?: "auto")
                put("captchaWbvSolveMethod", prefs[getProfileKey(CAPTCHA_WBV_SOLVE_METHOD, profile)] ?: "auto")
                put("isWhitelist", prefs[getProfileKey(IS_WHITELIST, profile)] ?: false)
                put("blacklistApps", prefs[getProfileKey(BLACKLIST_APPS, profile)].orEmpty())
                put("whitelistApps", prefs[getProfileKey(WHITELIST_APPS, profile)].orEmpty())
                put("detailedLogs", prefs[getProfileKey(DETAILED_LOGS, profile)] ?: false)
                put("selectedFingerprint", prefs[getProfileKey(SELECTED_FINGERPRINT, profile)] ?: "firefox")
                put("activeClientIds", prefs[getProfileKey(ACTIVE_CLIENT_IDS, profile)] ?: "6287487,8202606")
                put("profileName", prefs[getProfileKey(PROFILE_NAME, profile)].orEmpty())
            })
        }
        JSONObject().apply {
            put("format", "wdtt-plus-admin-settings")
            put("version", 1)
            put("activeProfile", (prefs[ACTIVE_PROFILE] ?: 0).coerceIn(0, VPN_PROFILE_COUNT - 1))
            put("themeMode", prefs[THEME_MODE] ?: "system")
            put("dynamicColor", prefs[IS_DYNAMIC_COLOR] ?: false)
            put("themePalette", prefs[THEME_PALETTE] ?: "indigo")
            put("showSystemApps", prefs[SHOW_SYSTEM_APPS] ?: false)
            put("loggingEnabled", prefs[LOGGING_ENABLED] ?: true)
            put(
                "updateCheckIntervalMinutes",
                normalizeUpdateCheckIntervalMinutes(
                    prefs[UPDATE_CHECK_INTERVAL_MINUTES] ?: DEFAULT_UPDATE_CHECK_INTERVAL_MINUTES
                )
            )
            put("profiles", profiles)
            put("outbound", exportSharedPreferences("wdtt_outbound_forms"))
        }.toString()
    }.first()

    suspend fun importAdminSettings(settingsJson: String) {
        val root = runCatching { JSONObject(settingsJson) }
            .getOrElse { throw IllegalArgumentException("Расшифрованные настройки повреждены.") }
        require(root.optString("format") == "wdtt-plus-admin-settings" && root.optInt("version") == 1) {
            "Версия настроек не поддерживается."
        }
        val profiles = root.optJSONArray("profiles")
            ?: throw IllegalArgumentException("В файле нет профилей VPN.")
        require(profiles.length() == VPN_PROFILE_COUNT) { "Файл должен содержать три профиля VPN." }

        dataStore.edit { prefs ->
            repeat(VPN_PROFILE_COUNT) { profile ->
                val item = profiles.getJSONObject(profile)
                prefs[getProfileKey(WDTT_LINK, profile)] = item.optString("wdttLink")
                prefs[getProfileKey(WDTT_LINK_MODE, profile)] = item.optBoolean("wdttLinkMode")
                prefs[getProfileKey(PEER, profile)] = item.optString("peer")
                prefs[getProfileKey(VK_HASHES, profile)] = item.optString("vkHashes")
                prefs[getProfileKey(SECONDARY_VK_HASH, profile)] = item.optString("secondaryVkHash")
                prefs[getProfileKey(VK_HASH_NEXT_SLOT, profile)] = 0
                prefs.remove(getProfileKey(EXCLUDED_APPS, profile))
                prefs[getProfileKey(WORKERS_PER_HASH, profile)] = item.optInt("workersPerHash", 16).coerceIn(1, 128)
                prefs[getProfileKey(PROTOCOL, profile)] = item.optString("protocol", "udp").takeIf { it in setOf("udp", "tcp") } ?: "udp"
                prefs[getProfileKey(LISTEN_PORT, profile)] = item.safePort("listenPort", 9000)
                prefs[getProfileKey(MANUAL_PORTS_ENABLED, profile)] = item.optBoolean("manualPortsEnabled")
                prefs[getProfileKey(SERVER_DTLS_PORT, profile)] = item.safePort("serverDtlsPort", 56000)
                prefs[getProfileKey(SERVER_WG_PORT, profile)] = item.safePort("serverWgPort", 56001)
                prefs[getProfileKey(SNI, profile)] = item.optString("sni")
                prefs[getProfileKey(NO_DTLS, profile)] = item.optBoolean("noDtls")
                prefs[getProfileKey(NO_DNS, profile)] = item.optBoolean("noDns")
                prefs[getProfileKey(USER_AGENT, profile)] = item.optString("userAgent")
                prefs.putSecret(CONNECTION_PASSWORD_ENCRYPTED, CONNECTION_PASSWORD, item.optString("connectionPassword"), profile)
                prefs[getProfileKey(DEPLOY_IP, profile)] = item.optString("deployIp")
                prefs[getProfileKey(DEPLOY_LOGIN, profile)] = item.optString("deployLogin")
                prefs.putSecret(DEPLOY_PASSWORD_ENCRYPTED, DEPLOY_PASSWORD, item.optString("deployPassword"), profile)
                prefs.putSecret(DEPLOY_SSH_PRIVATE_KEY_ENCRYPTED, DEPLOY_SSH_PRIVATE_KEY, "", profile)
                prefs.putSecret(DEPLOY_SSH_KEY_PASSPHRASE_ENCRYPTED, DEPLOY_SSH_KEY_PASSPHRASE, "", profile)
                prefs[getProfileKey(DEPLOY_SSH_AUTH_MODE, profile)] = "password"
                prefs.putSecret(WG_EXIT_SSH_PRIVATE_KEY_ENCRYPTED, WG_EXIT_SSH_PRIVATE_KEY, "", profile)
                prefs.putSecret(WG_EXIT_SSH_KEY_PASSPHRASE_ENCRYPTED, WG_EXIT_SSH_KEY_PASSPHRASE, "", profile)
                prefs[getProfileKey(WG_EXIT_SSH_AUTH_MODE, profile)] = "password"
                prefs[getProfileKey(DEPLOY_SSH_PORT, profile)] = item.optString("deploySshPort")
                prefs[getProfileKey(DEPLOY_DNS1, profile)] = item.optString("deployDns1", "1.1.1.1")
                prefs[getProfileKey(DEPLOY_DNS2, profile)] = item.optString("deployDns2", "1.0.0.1")
                prefs.putSecret(DEPLOY_MAIN_PASSWORD_ENCRYPTED, DEPLOY_MAIN_PASSWORD, item.optString("deployMainPassword"), profile)
                prefs.putSecret(DEPLOY_ADMIN_ID_ENCRYPTED, DEPLOY_ADMIN_ID, item.optString("deployAdminId"), profile)
                prefs.putSecret(DEPLOY_BOT_TOKEN_ENCRYPTED, DEPLOY_BOT_TOKEN, item.optString("deployBotToken"), profile)
                prefs[getProfileKey(PROXY_MODE, profile)] = item.optString("proxyMode", "tun")
                prefs[getProfileKey(PROXY_HOST, profile)] = item.optString("proxyHost", "127.0.0.1")
                prefs[getProfileKey(PROXY_PORT, profile)] = item.safePort("proxyPort", 1080)
                prefs[getProfileKey(VKCALLS_PREFLIGHT, profile)] = item.optBoolean("vkCallsPreflight", true)
                prefs[getProfileKey(CAPTCHA_MODE, profile)] = item.optString("captchaMode", "auto")
                prefs[getProfileKey(CAPTCHA_SOLVE_METHOD, profile)] = item.optString("captchaSolveMethod", "auto")
                prefs[getProfileKey(CAPTCHA_WBV_SOLVE_METHOD, profile)] = item.optString("captchaWbvSolveMethod", "auto")
                prefs[getProfileKey(IS_WHITELIST, profile)] = item.optBoolean("isWhitelist")
                prefs[getProfileKey(BLACKLIST_APPS, profile)] = item.optString("blacklistApps")
                prefs[getProfileKey(WHITELIST_APPS, profile)] = item.optString("whitelistApps")
                prefs[getProfileKey(DETAILED_LOGS, profile)] = item.optBoolean("detailedLogs")
                prefs[getProfileKey(SELECTED_FINGERPRINT, profile)] = item.optString("selectedFingerprint", "firefox")
                prefs[getProfileKey(ACTIVE_CLIENT_IDS, profile)] = item.optString("activeClientIds", "6287487,8202606")
                val importedName = normalizeVpnProfileName(item.optString("profileName"))
                val profileNameKey = getProfileKey(PROFILE_NAME, profile)
                if (importedName.isBlank() || importedName == vpnProfileDefaultName(profile)) {
                    prefs.remove(profileNameKey)
                } else {
                    prefs[profileNameKey] = importedName
                }
            }
            prefs[ACTIVE_PROFILE] = root.optInt("activeProfile", 0).coerceIn(0, VPN_PROFILE_COUNT - 1)
            prefs[THEME_MODE] = root.optString("themeMode", "system")
            prefs[IS_DYNAMIC_COLOR] = root.optBoolean("dynamicColor")
            prefs[THEME_PALETTE] = root.optString("themePalette", "indigo")
            prefs[SHOW_SYSTEM_APPS] = root.optBoolean("showSystemApps")
            prefs[LOGGING_ENABLED] = root.optBoolean("loggingEnabled", true)
            val updateIntervalMinutes = when {
                root.has("updateCheckIntervalMinutes") ->
                    root.optInt("updateCheckIntervalMinutes", DEFAULT_UPDATE_CHECK_INTERVAL_MINUTES)
                root.has("updateCheckIntervalHours") ->
                    root.optInt("updateCheckIntervalHours", 1) * 60
                else -> DEFAULT_UPDATE_CHECK_INTERVAL_MINUTES
            }.let(::normalizeUpdateCheckIntervalMinutes)
            prefs[UPDATE_CHECK_INTERVAL_MINUTES] = updateIntervalMinutes
            prefs[INTERFACE_ROLE] = "admin"
        }
        importSharedPreferences("wdtt_outbound_forms", root.optJSONObject("outbound") ?: JSONObject())
    }

    suspend fun applyWdttDeepLink(plan: WdttDeepLinkApplyPlan): WdttDeepLinkApplyResult? {
        val parts = WdttDeepLink.parse(plan.link) ?: return null
        val profile = plan.targetProfile.coerceIn(0, VPN_PROFILE_COUNT - 1)
        dataStore.edit { prefs ->
            prefs[ACTIVE_PROFILE] = profile
            val importedProfileName = vpnProfileRestorableName(parts.profileName)
            if (importedProfileName.isNotBlank()) {
                val profileNameKey = getProfileKey(PROFILE_NAME, profile)
                prefs[profileNameKey] = importedProfileName
            }
            prefs[getProfileKey(WDTT_LINK_MODE, profile)] = plan.storeAsLink
            if (plan.storeAsLink) {
                prefs[getProfileKey(WDTT_LINK, profile)] = plan.link
                prefs.clearManualTunnelFields(profile)
            } else {
                prefs.remove(getProfileKey(WDTT_LINK, profile))
                prefs[getProfileKey(PEER, profile)] = parts.host
                prefs[getProfileKey(SERVER_DTLS_PORT, profile)] = parts.dtlsPort
                prefs[getProfileKey(SERVER_WG_PORT, profile)] = parts.wgPort
                prefs[getProfileKey(LISTEN_PORT, profile)] = parts.localPort
                prefs.putSecret(CONNECTION_PASSWORD_ENCRYPTED, CONNECTION_PASSWORD, parts.password, profile)
                prefs[getProfileKey(VK_HASHES, profile)] = parts.hashes
                prefs[getProfileKey(SECONDARY_VK_HASH, profile)] = ""
                prefs[getProfileKey(MANUAL_PORTS_ENABLED, profile)] = true
            }
        }
        return WdttDeepLinkApplyResult(
            targetProfile = profile,
            overwritten = plan.requiresConfirmation,
            storedAsLink = plan.storeAsLink
        )
    }

    suspend fun saveWdttLinkMode(enabled: Boolean) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(WDTT_LINK_MODE, profile)] = enabled
        }
    }

    suspend fun save(
        peer: String,
        vkHashes: String,
        secondaryVkHash: String,
        workersPerHash: Int,
        protocol: String,
        listenPort: Int,
        sni: String = "",
        noDns: Boolean = false
    ) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(PEER, profile)] = peer
            prefs[getProfileKey(VK_HASHES, profile)] = vkHashes
            prefs[getProfileKey(SECONDARY_VK_HASH, profile)] = secondaryVkHash
            prefs[getProfileKey(WORKERS_PER_HASH, profile)] = workersPerHash
            prefs[getProfileKey(PROTOCOL, profile)] = protocol
            prefs[getProfileKey(LISTEN_PORT, profile)] = listenPort
            prefs[getProfileKey(SNI, profile)] = sni
            prefs[getProfileKey(NO_DNS, profile)] = noDns
        }
    }

    suspend fun saveWorkersPerHash(workersPerHash: Int) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(WORKERS_PER_HASH, profile)] = workersPerHash.coerceIn(1, 128)
        }
    }

    suspend fun insertVkHashFromShare(hash: String): VkHashInsertResult {
        val cleanedHash = VkJoinLink.extractHash(hash)
        require(cleanedHash.length >= 16) { "VK-хеш слишком короткий" }
        var result = VkHashInsertResult(slot = 1, hash = cleanedHash, previousHash = "")
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            val hashesKey = getProfileKey(VK_HASHES, profile)
            val nextSlotKey = getProfileKey(VK_HASH_NEXT_SLOT, profile)
            val slots = parseVkHashSlots(prefs[hashesKey] ?: "")
            val duplicateSlot = slots.indexOfFirst { it == cleanedHash }
            require(duplicateSlot < 0) {
                "Такой VK-хеш уже добавлен в поле VK Хеш ${duplicateSlot + 1}. Добавьте другой хеш."
            }

            val savedNext = (prefs[nextSlotKey] ?: 0).coerceIn(0, 3)
            val slotIndex = slots.indexOfFirst { it.isBlank() }.takeIf { it >= 0 } ?: savedNext
            val previous = slots[slotIndex]
            slots[slotIndex] = cleanedHash

            prefs[hashesKey] = slots.joinToString(",")
            prefs[nextSlotKey] = (slotIndex + 1) % 4
            result = VkHashInsertResult(slot = slotIndex + 1, hash = cleanedHash, previousHash = previous)
        }
        return result
    }

    private fun parseVkHashSlots(raw: String): MutableList<String> {
        val tokens = if (raw.contains(",")) {
            raw.split(",")
        } else {
            raw.split(Regex("[\\s\\n]+"))
        }
        val slots = tokens
            .map { VkJoinLink.extractHash(it) }
            .take(4)
            .toMutableList()
        while (slots.size < 4) {
            slots.add("")
        }
        return slots
    }

    suspend fun saveManualPortsEnabled(enabled: Boolean) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(MANUAL_PORTS_ENABLED, profile)] = enabled
        }
    }

    suspend fun savePorts(serverDtlsPort: Int, serverWgPort: Int, listenPort: Int) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(SERVER_DTLS_PORT, profile)] = serverDtlsPort
            prefs[getProfileKey(SERVER_WG_PORT, profile)] = serverWgPort
            prefs[getProfileKey(LISTEN_PORT, profile)] = listenPort
        }
    }

    suspend fun saveUserAgent(ua: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(USER_AGENT, profile)] = ua
        }
    }

    suspend fun saveDeploy(ip: String, login: String, pass: String, sshPort: String, dns1: String, dns2: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(DEPLOY_IP, profile)] = ip
            prefs[getProfileKey(DEPLOY_LOGIN, profile)] = login
            prefs.putSecret(DEPLOY_PASSWORD_ENCRYPTED, DEPLOY_PASSWORD, pass, profile)
            prefs[getProfileKey(DEPLOY_SSH_PORT, profile)] = sshPort
            prefs[getProfileKey(DEPLOY_DNS1, profile)] = dns1
            prefs[getProfileKey(DEPLOY_DNS2, profile)] = dns2
        }
    }

    suspend fun saveDeploySshKey(privateKey: String, passphrase: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            val normalizedKey = normalizeSshPrivateKey(privateKey)
            prefs.putSecret(
                DEPLOY_SSH_PRIVATE_KEY_ENCRYPTED,
                DEPLOY_SSH_PRIVATE_KEY,
                normalizedKey,
                profile
            )
            prefs.putSecret(
                DEPLOY_SSH_KEY_PASSPHRASE_ENCRYPTED,
                DEPLOY_SSH_KEY_PASSPHRASE,
                passphrase.takeIf { normalizedKey.isNotBlank() }.orEmpty(),
                profile
            )
        }
    }

    suspend fun saveDeploySshAuthMode(mode: String) {
        require(mode == "password" || mode == "key")
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(DEPLOY_SSH_AUTH_MODE, profile)] = mode
        }
    }

    suspend fun saveWireGuardExitSshKey(privateKey: String, passphrase: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            val normalizedKey = normalizeSshPrivateKey(privateKey)
            prefs.putSecret(WG_EXIT_SSH_PRIVATE_KEY_ENCRYPTED, WG_EXIT_SSH_PRIVATE_KEY, normalizedKey, profile)
            prefs.putSecret(
                WG_EXIT_SSH_KEY_PASSPHRASE_ENCRYPTED,
                WG_EXIT_SSH_KEY_PASSPHRASE,
                passphrase.takeIf { normalizedKey.isNotBlank() }.orEmpty(),
                profile
            )
        }
    }

    suspend fun saveWireGuardExitSshAuthMode(mode: String) {
        require(mode == "password" || mode == "key")
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(WG_EXIT_SSH_AUTH_MODE, profile)] = mode
        }
    }

    suspend fun toggleVpnAppSelected(packageName: String, whitelist: Boolean) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            val key = getProfileKey(if (whitelist) WHITELIST_APPS else BLACKLIST_APPS, profile)
            val packages = prefs[key]
                .orEmpty()
                .split(",")
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .toMutableSet()
            if (!packages.add(packageName)) packages.remove(packageName)
            prefs[key] = packages.sorted().joinToString(",")
        }
    }

    suspend fun addBlacklistPackages(newPackages: Set<String>): Int {
        var addedCount = 0
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            val key = getProfileKey(BLACKLIST_APPS, profile)
            val packages = prefs[key]
                .orEmpty()
                .split(",")
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .toMutableSet()
            val before = packages.size
            packages.addAll(newPackages)
            addedCount = packages.size - before
            prefs[key] = packages.sorted().joinToString(",")
        }
        return addedCount
    }
    
    suspend fun saveDetailedLogs(enabled: Boolean) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(DETAILED_LOGS, profile)] = enabled
        }
    }
    
    // ═══ Сохранение пароля подключения ═══
    suspend fun saveConnectionPassword(password: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs.putSecret(CONNECTION_PASSWORD_ENCRYPTED, CONNECTION_PASSWORD, password, profile)
        }
    }
    
    // ═══ Сохранение секретов деплоя ═══
    suspend fun saveDeploySecrets(mainPass: String, adminId: String, botToken: String, sshPort: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs.putSecret(DEPLOY_MAIN_PASSWORD_ENCRYPTED, DEPLOY_MAIN_PASSWORD, mainPass, profile)
            prefs.putSecret(DEPLOY_ADMIN_ID_ENCRYPTED, DEPLOY_ADMIN_ID, adminId, profile)
            prefs.putSecret(DEPLOY_BOT_TOKEN_ENCRYPTED, DEPLOY_BOT_TOKEN, botToken, profile)
            prefs[getProfileKey(DEPLOY_SSH_PORT, profile)] = sshPort
        }
    }

    // ═══ Сохранение proxy mode ═══
    suspend fun saveProxyMode(mode: String, host: String, port: Int) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(PROXY_MODE, profile)] = mode
            prefs[getProfileKey(PROXY_HOST, profile)] = host
            prefs[getProfileKey(PROXY_PORT, profile)] = port
        }
    }

    // ═══ Сохранение режима обхода капчи ═══
    suspend fun saveVkCallsPreflight(enabled: Boolean) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(VKCALLS_PREFLIGHT, profile)] = enabled
        }
    }

    suspend fun saveCaptchaMode(mode: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(CAPTCHA_MODE, profile)] = mode
        }
    }

    suspend fun saveCaptchaSolveMethod(method: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(CAPTCHA_SOLVE_METHOD, profile)] = method
        }
    }

    suspend fun saveWbvCaptchaSolveMethod(method: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(CAPTCHA_WBV_SOLVE_METHOD, profile)] = method
            if (prefs[getProfileKey(CAPTCHA_MODE, profile)] == "wv") {
                prefs[getProfileKey(CAPTCHA_SOLVE_METHOD, profile)] = method
            }
        }
    }

    // ═══ Сохранение режима списка (ЧС/БС) ═══
    suspend fun saveIsWhitelist(enabled: Boolean) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(IS_WHITELIST, profile)] = enabled
        }
    }

    private suspend fun migrateSecretsToKeystore() {
        dataStore.edit { prefs ->
            for (profile in 0..2) {
                prefs.migrateSecret(getProfileKey(DEPLOY_PASSWORD_ENCRYPTED, profile), getProfileKey(DEPLOY_PASSWORD, profile))
                prefs.migrateSecret(getProfileKey(DEPLOY_SSH_PRIVATE_KEY_ENCRYPTED, profile), getProfileKey(DEPLOY_SSH_PRIVATE_KEY, profile))
                prefs.migrateSecret(getProfileKey(DEPLOY_SSH_KEY_PASSPHRASE_ENCRYPTED, profile), getProfileKey(DEPLOY_SSH_KEY_PASSPHRASE, profile))
                prefs.migrateSecret(getProfileKey(WG_EXIT_SSH_PRIVATE_KEY_ENCRYPTED, profile), getProfileKey(WG_EXIT_SSH_PRIVATE_KEY, profile))
                prefs.migrateSecret(getProfileKey(WG_EXIT_SSH_KEY_PASSPHRASE_ENCRYPTED, profile), getProfileKey(WG_EXIT_SSH_KEY_PASSPHRASE, profile))
                prefs.migrateSecret(getProfileKey(CONNECTION_PASSWORD_ENCRYPTED, profile), getProfileKey(CONNECTION_PASSWORD, profile))
                prefs.migrateSecret(getProfileKey(DEPLOY_MAIN_PASSWORD_ENCRYPTED, profile), getProfileKey(DEPLOY_MAIN_PASSWORD, profile))
                prefs.migrateSecret(getProfileKey(DEPLOY_ADMIN_ID_ENCRYPTED, profile), getProfileKey(DEPLOY_ADMIN_ID, profile))
                prefs.migrateSecret(getProfileKey(DEPLOY_BOT_TOKEN_ENCRYPTED, profile), getProfileKey(DEPLOY_BOT_TOKEN, profile))
            }
        }
    }

    private suspend fun migrateWireGuardExitSshAuthMode() {
        val legacyPrefs = appContext.getSharedPreferences("wdtt_outbound_forms", Context.MODE_PRIVATE)
        val legacyMode = legacyPrefs.getString("wg_exit_auth_mode", null)
            ?.takeIf { it == "password" || it == "key" }
            ?: return
        dataStore.edit { prefs ->
            for (profile in 0 until VPN_PROFILE_COUNT) {
                val key = getProfileKey(WG_EXIT_SSH_AUTH_MODE, profile)
                if (prefs[key] == null) prefs[key] = legacyMode
            }
        }
        legacyPrefs.edit().remove("wg_exit_auth_mode").apply()
    }

    private suspend fun migrateVpnAppLists() {
        dataStore.edit { prefs ->
            for (profile in 0 until VPN_PROFILE_COUNT) {
                val legacyKey = getProfileKey(EXCLUDED_APPS, profile)
                val legacyPackages = prefs[legacyKey].orEmpty()
                if (legacyPackages.isBlank()) continue

                val targetBaseKey = if (prefs[getProfileKey(IS_WHITELIST, profile)] == true) {
                    WHITELIST_APPS
                } else {
                    BLACKLIST_APPS
                }
                val targetKey = getProfileKey(targetBaseKey, profile)
                if (prefs[targetKey] == null) {
                    prefs[targetKey] = legacyPackages
                }
                prefs.remove(legacyKey)
            }
        }
    }

    private fun readSecret(
        prefs: Preferences,
        encryptedKey: Preferences.Key<String>,
        legacyKey: Preferences.Key<String>,
        profile: Int
    ): String {
        val profEncryptedKey = getProfileKey(encryptedKey, profile)
        val profLegacyKey = getProfileKey(legacyKey, profile)
        return secureStore.decrypt(prefs[profEncryptedKey]) ?: prefs[profLegacyKey] ?: ""
    }

    private fun MutablePreferences.putSecret(
        encryptedKey: Preferences.Key<String>,
        legacyKey: Preferences.Key<String>,
        value: String,
        profile: Int
    ) {
        val profEncryptedKey = getProfileKey(encryptedKey, profile)
        val profLegacyKey = getProfileKey(legacyKey, profile)
        if (value.isBlank()) {
            remove(profEncryptedKey)
            remove(profLegacyKey)
        } else {
            this[profEncryptedKey] = secureStore.encrypt(value)
            remove(profLegacyKey)
        }
    }

    private fun Preferences.isTunnelProfileEmpty(profile: Int): Boolean {
        val hasLink = (this[getProfileKey(WDTT_LINK, profile)] ?: "").isNotBlank()
        val hasManualData = (this[getProfileKey(PEER, profile)] ?: "").isNotBlank() ||
            (this[getProfileKey(VK_HASHES, profile)] ?: "").split(",").any { it.isNotBlank() } ||
            (this[getProfileKey(SECONDARY_VK_HASH, profile)] ?: "").isNotBlank() ||
            readSecret(this, CONNECTION_PASSWORD_ENCRYPTED, CONNECTION_PASSWORD, profile).isNotBlank() ||
            (this[getProfileKey(MANUAL_PORTS_ENABLED, profile)] == true &&
                ((this[getProfileKey(SERVER_DTLS_PORT, profile)] ?: 56000) != 56000 ||
                    (this[getProfileKey(SERVER_WG_PORT, profile)] ?: 56001) != 56001 ||
                    (this[getProfileKey(LISTEN_PORT, profile)] ?: 9000) != 9000))
        return !hasLink && !hasManualData
    }

    private fun MutablePreferences.clearManualTunnelFields(profile: Int) {
        remove(getProfileKey(PEER, profile))
        remove(getProfileKey(VK_HASHES, profile))
        remove(getProfileKey(SECONDARY_VK_HASH, profile))
        putSecret(CONNECTION_PASSWORD_ENCRYPTED, CONNECTION_PASSWORD, "", profile)
        remove(getProfileKey(MANUAL_PORTS_ENABLED, profile))
    }

    private fun MutablePreferences.migrateSecret(
        encryptedKey: Preferences.Key<String>,
        legacyKey: Preferences.Key<String>
    ) {
        val legacyValue = this[legacyKey]
        val encryptedValue = this[encryptedKey]
        if (!encryptedValue.isNullOrBlank()) {
            remove(legacyKey)
            return
        }
        if (!legacyValue.isNullOrBlank()) {
            runCatching {
                this[encryptedKey] = secureStore.encrypt(legacyValue)
                remove(legacyKey)
            }
        }
    }

    private fun exportSharedPreferences(name: String): JSONObject {
        val result = JSONObject()
        appContext.getSharedPreferences(name, Context.MODE_PRIVATE).all.forEach { (key, value) ->
            when (value) {
                is String, is Boolean, is Int, is Long, is Float -> result.put(key, value)
                is Set<*> -> result.put(key, JSONArray(value.filterIsInstance<String>()))
            }
        }
        return result
    }

    private fun importSharedPreferences(name: String, json: JSONObject) {
        val editor = appContext.getSharedPreferences(name, Context.MODE_PRIVATE).edit().clear()
        val keys = json.keys()
        while (keys.hasNext()) {
            val key = keys.next()
            when (val value = json.get(key)) {
                is String -> editor.putString(key, value)
                is Boolean -> editor.putBoolean(key, value)
                is Int -> editor.putInt(key, value)
                is Long -> editor.putLong(key, value)
                is Double -> editor.putFloat(key, value.toFloat())
                is JSONArray -> editor.putStringSet(
                    key,
                    (0 until value.length()).mapNotNull { value.optString(it).takeIf(String::isNotBlank) }.toSet()
                )
            }
        }
        editor.apply()
    }

    private fun JSONObject.safePort(name: String, fallback: Int): Int =
        optInt(name, fallback).takeIf { it in 1..65535 } ?: fallback
}

fun vpnProfileDefaultName(profile: Int): String = "VPN ${profile.coerceIn(0, 2) + 1}"

private fun parseTrustedWifiSsids(raw: String): List<String> {
    if (raw.isBlank()) return emptyList()
    return runCatching {
        val json = JSONArray(raw)
        buildList {
            for (index in 0 until json.length()) {
                val ssid = sanitizeTrustedWifiSsid(json.optString(index))
                if (ssid.isNotBlank() && ssid !in this) add(ssid)
            }
        }
    }.getOrDefault(emptyList())
}

fun sanitizeVpnProfileNameInput(name: String): String {
    val safe = buildString {
        name.forEach { character ->
            when {
                character.isWhitespace() -> append(' ')
                !Character.isISOControl(character) -> append(character)
            }
        }
    }
    return safe
        .replace(Regex(" +"), " ")
        .trimStart()
        .take(48)
}

fun normalizeVpnProfileName(name: String): String =
    sanitizeVpnProfileNameInput(name).trimEnd()

fun normalizeUpdateCheckIntervalMinutes(minutes: Int): Int =
    if (minutes == UPDATE_CHECK_NEVER) {
        UPDATE_CHECK_NEVER
    } else {
        minutes.coerceAtLeast(DEFAULT_UPDATE_CHECK_INTERVAL_MINUTES)
    }

fun vpnProfileDisplayName(profile: Int, names: List<String>): String {
    val clean = normalizeVpnProfileName(names.getOrNull(profile).orEmpty())
    return clean.ifBlank { vpnProfileDefaultName(profile) }
}

fun vpnProfileTransferName(profile: Int, names: List<String>): String {
    val displayName = vpnProfileDisplayName(profile, names)
    return displayName.takeUnless { it == vpnProfileDefaultName(profile) }.orEmpty()
}

fun isStandardVpnProfileName(name: String): Boolean {
    val clean = normalizeVpnProfileName(name)
    return clean.isNotBlank() && (0..2).any { clean == vpnProfileDefaultName(it) }
}

fun vpnProfileRestorableName(name: String): String {
    val clean = normalizeVpnProfileName(name)
    return clean.takeUnless { it.isBlank() || isStandardVpnProfileName(it) }.orEmpty()
}
