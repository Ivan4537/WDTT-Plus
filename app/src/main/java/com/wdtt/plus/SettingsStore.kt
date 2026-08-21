package com.wdtt.plus

import android.content.Context
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.floatPreferencesKey
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
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject

import android.os.Build
import java.util.UUID

internal const val DEFAULT_SLEEP_PAUSE_DELAY_MINUTES = 5
internal const val MIN_SLEEP_PAUSE_DELAY_MINUTES = 0
internal const val MAX_SLEEP_PAUSE_DELAY_MINUTES = 24 * 60

internal fun normalizeSleepPauseDelayMinutes(minutes: Int): Int =
    minutes.coerceIn(MIN_SLEEP_PAUSE_DELAY_MINUTES, MAX_SLEEP_PAUSE_DELAY_MINUTES)

enum class SleepBatteryMode(val storedValue: String) {
    DELAYED_PAUSE("delayed_pause"),
    TIMED_PAUSE("timed_pause");

    companion object {
        fun fromStoredValue(value: String?): SleepBatteryMode =
            entries.firstOrNull { it.storedValue == value } ?: DELAYED_PAUSE
    }
}

internal enum class SleepBatteryRuntimePhase(val storedValue: String) {
    IDLE("idle"),
    WAITING_TO_PAUSE("waiting_to_pause"),
    PAUSED_UNTIL_SCREEN_ON("paused_until_screen_on"),
    WAITING_TO_RESUME("waiting_to_resume"),
    RESUMED_UNTIL_SCREEN_ON("resumed_until_screen_on");

    companion object {
        fun fromStoredValue(value: String?): SleepBatteryRuntimePhase =
            entries.firstOrNull { it.storedValue == value } ?: IDLE
    }
}

internal data class SleepBatteryRuntimeState(
    val phase: SleepBatteryRuntimePhase = SleepBatteryRuntimePhase.IDLE,
    val deadlineMs: Long = 0L,
)

data class VkHashInsertResult(
    val slot: Int,
    val hash: String,
    val previousHash: String,
    val profile: Int = 0,
    val hashes: List<String> = emptyList(),
)

internal data class VpnRoutingImportResult(
    val blacklistAppCount: Int,
    val whitelistAppCount: Int,
    val blacklistAddressCount: Int,
    val whitelistAddressCount: Int,
    val isWhitelist: Boolean,
)

internal data class VpnRoutingSettingsSnapshot(
    val profileIndex: Int,
    val isWhitelist: Boolean,
    val appPackages: String,
    val addressRules: List<VpnAddressRule>,
)

data class WdttLinkParts(
    val host: String,
    val dtlsPort: Int,
    val wgPort: Int,
    val localPort: Int,
    val password: String,
    val hashes: String,
    val profileName: String = "",
    val maxWorkers: Int = 0
)

internal fun WdttLinkParts.hasNonStandardPorts(): Boolean =
    dtlsPort != 56000 || wgPort != 56001 || localPort != 9000

private val supportedWdttLinkFormats = """
    Поддерживаются форматы:
    • Новый: wdtt://connect?v=1&host=адрес&dtls=DTLS-порт&wg=WG-порт&local=локальный-порт&password=пароль&hashes=VK-хеши
    • Старый: wdtt://адрес:DTLS-порт:WG-порт:локальный-порт:пароль:VK-хеши
""".trimIndent()

data class WdttDeepLinkValidation(
    val parts: WdttLinkParts?,
    val errors: List<String>,
    val warnings: List<String> = emptyList()
) {
    val canStartVpn: Boolean = parts != null && errors.isEmpty() && parts.hashes.isNotBlank()

    fun userMessage(): String {
        return if (parts != null && errors.isEmpty()) {
            buildString {
                if (parts.hashes.isBlank()) {
                    append("Ссылка wdtt:// распознана. Добавьте свой VK-хеш перед запуском VPN.")
                } else {
                    append("Ссылка wdtt:// корректна. VPN сможет использовать эти данные для подключения.")
                }
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
                append("\n\n")
                append(supportedWdttLinkFormats)
            }
        }
    }
}

data class WdttDeepLinkApplyPlan(
    val link: String,
    val targetProfile: Int,
    val requiresConfirmation: Boolean,
    val storeAsLink: Boolean,
    val blockedProfiles: Set<Int> = emptySet(),
)

data class WdttDeepLinkApplyResult(
    val targetProfile: Int,
    val overwritten: Boolean,
    val storedAsLink: Boolean,
    val alreadyApplied: Boolean = false,
)

internal fun shouldPreserveConnectionSettingsForRemoteUpdate(
    isBoundUpdate: Boolean,
    remoteManaged: Boolean,
    incomingHost: String,
    incomingPassword: String,
): Boolean = isBoundUpdate && (
    !remoteManaged || incomingHost.isBlank() && incomingPassword.isBlank()
)

internal data class InterfaceRoleProfileState(
    val role: String,
    val rememberedRole: String?,
)

internal fun reconcileInterfaceRoleForProfile(
    storedRole: String,
    rememberedRole: String?,
    remoteManagedProfile: Boolean,
): InterfaceRoleProfileState {
    val validStoredRole = storedRole.takeIf { it == "user" || it == "admin" }.orEmpty()
    val validRememberedRole = rememberedRole?.takeIf { it == "user" || it == "admin" }
    return if (remoteManagedProfile) {
        InterfaceRoleProfileState(
            role = "user",
            rememberedRole = validRememberedRole ?: validStoredRole.takeIf { it.isNotBlank() },
        )
    } else {
        InterfaceRoleProfileState(
            role = validRememberedRole ?: validStoredRole,
            rememberedRole = null,
        )
    }
}

data class TunnelProfileSnapshot(
    val profileIndex: Int,
    val remoteManaged: Boolean,
    val linkMode: Boolean,
    val link: String,
    val peer: String,
    val vkHashes: String,
    val secondaryVkHash: String,
    val connectionPassword: String,
    val workersPerHash: Int,
    val profileMaxWorkers: Int,
    val manualPortsEnabled: Boolean,
    val serverDtlsPort: Int,
    val listenPort: Int,
    val sni: String,
    val protocol: String,
    val vpnDnsSelectionId: String = VPN_DNS_PROFILE_ID,
    val vpnDnsCustomServers: List<String> = emptyList(),
    val vkCallsPreflight: Boolean,
    val rtNetwork: Boolean = false,
    val rtMasque: Boolean = false,
    val rtMasqueServerBootstrap: Boolean = false,
    val rtMasqueServerAccessReady: Boolean = false,
    val rtTurnSni: String = DEFAULT_RT_TURN_SNI,
    val captchaMode: String,
    val captchaSolveMethod: String,
    val fingerprint: String,
    val clientIds: String,
    val customVkCredentialsEnabled: Boolean,
    val customVkClientId: String,
    val customVkClientSecret: String,
)

data class RemoteAttachmentCandidate(
    val profileIndex: Int,
    val displayName: String,
    val sourceLabel: String,
    val document: String,
    val modified: Boolean,
)

internal data class RemoteAttachmentSelection(
    val choices: List<RemoteAttachmentCandidate> = emptyList(),
)

internal data class RemoteAttachmentDocument(
    val document: String,
    val sourceLabel: String,
)

internal fun selectRemoteAttachmentDocument(
    tunnelParts: WdttLinkParts,
    deployParts: WdttLinkParts,
    profileName: String,
    maxWorkers: Int,
    alreadyManaged: Boolean,
): RemoteAttachmentDocument? {
    if (alreadyManaged) return null
    for ((parts, sourceLabel) in listOf(tunnelParts to "Туннель", deployParts to "Деплой")) {
        val document = WdttTransferCodec.buildConnectionLink(
            parts.copy(
                hashes = "",
                profileName = profileName,
                maxWorkers = maxWorkers,
            )
        )
        eligibleRemoteAttachmentDocument(document, alreadyManaged = false)?.let {
            return RemoteAttachmentDocument(it, sourceLabel)
        }
    }
    return null
}

internal fun resolveRemoteAttachmentCandidates(
    candidates: List<RemoteAttachmentCandidate>,
): RemoteAttachmentSelection = RemoteAttachmentSelection(choices = candidates)

internal fun canReplaceRemoteAttachment(
    hasAttachment: Boolean,
    remoteManaged: Boolean,
    continuationAvailable: Boolean?,
    dismissible: Boolean?,
): Boolean =
    hasAttachment &&
        !remoteManaged &&
        continuationAvailable == false &&
        dismissible == true

internal fun shouldRestoreUiAfterBoundUpdate(isBoundUpdate: Boolean): Boolean = isBoundUpdate

internal fun protectsRemoteProfileFromReplacement(
    remoteManagedProfile: Boolean,
    allowConnect: Boolean?,
): Boolean = remoteManagedProfile && allowConnect != false

/**
 * One atomic DataStore projection for the visible Tunnel tab.
 *
 * Keeping these values in one snapshot prevents a profile switch from briefly combining the
 * new profile index with connection fields (or interface role) emitted for the previous one.
 */
data class ActiveTunnelProfileUiSnapshot(
    val profileIndex: Int,
    val profileNames: List<String>,
    val interfaceRole: String,
    val permissionOnboardingComplete: Boolean,
    val connectionInputMethod: String,
    val linkMode: Boolean,
    val link: String,
    val peer: String,
    val vkHashes: String,
    val connectionPassword: String,
    val workersPerHash: Int,
    val manualPortsEnabled: Boolean,
    val serverDtlsPort: Int,
    val serverWgPort: Int,
    val listenPort: Int,
    val sni: String,
    val vpnDnsSelectionId: String,
    val vpnDnsCustomServers: List<String>,
    val captchaMode: String,
    val captchaSolveMethod: String,
    val fingerprint: String,
    val clientIds: String,
    val customVkCredentialsEnabled: Boolean,
    val customVkClientId: String,
    val customVkClientSecret: String,
    val vkCallsPreflight: Boolean,
    val rtNetwork: Boolean = false,
    val rtMasque: Boolean = false,
    val rtMasqueServerBootstrap: Boolean = false,
    val rtMasqueServerAccessStatus: SshProfileAccessStatus,
    val rtTurnSni: String = DEFAULT_RT_TURN_SNI,
    val remoteActionKey: String,
    val remoteActionUrl: String,
    val remoteManaged: Boolean,
    val cachedRemoteAction: CachedRemoteAction,
    val remoteCardDismissed: Boolean,
    val accessLifecycle: AccessLifecycleUiState,
    val accessLifecycleDismissedSignature: String,
    val profileMaxWorkers: Int,
)

data class ActiveTunnelAccessUiSnapshot(
    val profileIndex: Int,
    val lifecycle: AccessLifecycleUiState,
    val dismissedSignature: String,
)

internal fun ActiveTunnelProfileUiSnapshot.withoutTransientAccessState():
    ActiveTunnelProfileUiSnapshot = copy(
        accessLifecycle = AccessLifecycleUiState.Unmanaged,
        accessLifecycleDismissedSignature = "",
    )

internal fun existingProfileValuesForRemoteAttachment(
    linkMode: Boolean,
    storedLink: String,
    manualValues: String,
): String {
    val storedValues = if (linkMode) {
        WdttDeepLink.parse(storedLink, allowMissingHashes = true)?.hashes.orEmpty()
    } else {
        manualValues
    }
    return storedValues
        .split(",")
        .map(VkJoinLink::extractHash)
        .filter(VkJoinLink::isValidHash)
        .distinct()
        .take(4)
        .joinToString(",")
}

object WdttDeepLink {
    fun parse(
        value: String,
        allowMissingHashes: Boolean = false,
        allowOmittedConnection: Boolean = false,
    ): WdttLinkParts? {
        return validate(value, allowMissingHashes, allowOmittedConnection).parts
    }

    fun validate(
        value: String,
        allowMissingHashes: Boolean = false,
        allowOmittedConnection: Boolean = false,
    ): WdttDeepLinkValidation {
        val clean = WdttTransferCodec.extractWdttLink(value) ?: value.trim()
        val errors = mutableListOf<String>()
        val warnings = mutableListOf<String>()

        if (clean.isBlank()) {
            return WdttDeepLinkValidation(
                parts = null,
                errors = listOf("Ссылка пустая. Вставьте ссылку WDTT нового или старого формата.")
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
                errors = listOf("В старой ссылке должно быть 6 полей после wdtt://, сейчас $found: $detail.")
            )
        }

        val host = modernParts?.host?.trim() ?: parts[0].trim()
        val password = modernParts?.password?.trim() ?: parts[4].trim()
        val connectionOmitted = allowOmittedConnection &&
            modernParts != null &&
            host.isBlank() &&
            password.isBlank()
        if (!connectionOmitted && !isValidTunnelHost(host)) {
            errors += "Адрес сервера пустой или неверный. Нужен домен или IPv4 без https://, порта и пути."
        }

        val dtlsPort = validatePort((modernParts?.dtlsPort ?: parts[1]).toString(), "DTLS-порт", errors)
        val wgPort = validatePort((modernParts?.wgPort ?: parts[2]).toString(), "WG-порт", errors)
        val localPort = validatePort((modernParts?.localPort ?: parts[3]).toString(), "локальный порт", errors)

        if (!connectionOmitted && password.isBlank()) {
            errors += "Не указан пароль туннеля."
        }

        val rawHashes = (modernParts?.hashes ?: parts[5]).split(",")
        val hashes = rawHashes
            .mapNotNull { VkJoinLink.normalizeHashes(it)?.takeIf(String::isNotBlank) }
            .distinct()
            .joinToString(",")

        if (hashes.isBlank()) {
            val invalidHashesProvided = rawHashes.any { it.isNotBlank() }
            if (invalidHashesProvided) {
                errors += "VK-хеш содержит недопустимые символы. Используйте латинские буквы, цифры, _ и - либо ссылку VK-звонка."
            } else if (allowMissingHashes) {
                warnings += "VK-хеши ещё не заполнены. Добавьте их в WDTT Plus перед запуском VPN."
            } else {
                errors += "Нет рабочего VK-хеша. Нужен хеш из латинских букв, цифр, _ или - либо ссылка VK-звонка."
            }
        } else {
            val invalidHashes = rawHashes
                .map { it.trim() }
                .filter { it.isNotBlank() }
                .count { !VkJoinLink.isValidInput(it) }
            if (invalidHashes > 0) {
                warnings += "$invalidHashes ${hashWord(invalidHashes)} содержит недопустимые символы и будет пропущено."
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
                profileName = normalizeVpnProfileName(modernParts?.profileName.orEmpty()),
                maxWorkers = modernParts?.maxWorkers ?: 0
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
    private val sharedPreferences = obtainSharedPreferences(appContext)
    private val storeScope = sharedPreferences.scope
    private val preferencesState: StateFlow<Preferences?> = sharedPreferences.state
    private val preferencesFlow: Flow<Preferences> = preferencesState.filterNotNull()
    private val _settingsReady = MutableStateFlow(false)
    val settingsReady: StateFlow<Boolean> = _settingsReady.asStateFlow()

    companion object {
        private val Context.dataStore by preferencesDataStore("settings")
        private data class SharedPreferences(
            val scope: CoroutineScope,
            val state: StateFlow<Preferences?>,
        )

        @Volatile
        private var sharedPreferences: SharedPreferences? = null

        private fun obtainSharedPreferences(context: Context): SharedPreferences =
            sharedPreferences ?: synchronized(this) {
                sharedPreferences ?: run {
                    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
                    SharedPreferences(
                        scope = scope,
                        state = context.dataStore.data.stateIn(
                            scope,
                            SharingStarted.Eagerly,
                            null,
                        ),
                    ).also { sharedPreferences = it }
                }
            }
        private val ACTIVE_PROFILE = intPreferencesKey("active_profile")
        private val ACTIVE_TUNNEL_PROFILE = intPreferencesKey("active_tunnel_profile")
        private val PROFILE_NAME = stringPreferencesKey("profile_name")
        private val SHOW_SYSTEM_APPS = booleanPreferencesKey("show_system_apps")
        private val LOGGING_ENABLED = booleanPreferencesKey("logging_enabled")
        private val FLOATING_TOOLBAR_Y_FRACTION = floatPreferencesKey("floating_toolbar_y_fraction")
        private val TRUSTED_WIFI_ENABLED = booleanPreferencesKey("trusted_wifi_enabled")
        private val TRUSTED_WIFI_SSIDS = stringPreferencesKey("trusted_wifi_ssids")
        private val TRUSTED_WIFI_WAITING = booleanPreferencesKey("trusted_wifi_waiting")
        private val TRUSTED_WIFI_WAITING_SSID = stringPreferencesKey("trusted_wifi_waiting_ssid")
        private val PAUSE_VPN_DURING_SLEEP = booleanPreferencesKey("pause_vpn_during_sleep")
        private val PAUSE_VPN_DURING_SLEEP_DELAY_MINUTES =
            intPreferencesKey("pause_vpn_during_sleep_delay_minutes")
        private val PAUSE_VPN_DURING_SLEEP_MODE =
            stringPreferencesKey("pause_vpn_during_sleep_mode")
        private val RESUME_VPN_DURING_SLEEP_DELAY_MINUTES =
            intPreferencesKey("resume_vpn_during_sleep_delay_minutes")
        private val SLEEP_BATTERY_SETTINGS_CONFIGURED =
            booleanPreferencesKey("sleep_battery_settings_configured")
        private val SLEEP_BATTERY_RUNTIME_PHASE =
            stringPreferencesKey("sleep_battery_runtime_phase")
        private val ACTIVE_TIMED_SLEEP_RESUME_DEADLINE_MS =
            longPreferencesKey("active_timed_sleep_resume_deadline_ms")
        private val WDTT_LINK = stringPreferencesKey("wdtt_link")
        private val WDTT_LINK_MODE = booleanPreferencesKey("wdtt_link_mode")
        private val CONNECTION_INPUT_METHOD = stringPreferencesKey("connection_input_method")
        private val CONNECT_DEVICE_ID = stringPreferencesKey("connect_device_id")
        private val TUNNEL_DEVICE_ID = stringPreferencesKey("tunnel_device_id")

        private val PEER = stringPreferencesKey("peer")
        private val VK_HASHES = stringPreferencesKey("vk_hashes")
        private val SECONDARY_VK_HASH = stringPreferencesKey("secondary_vk_hash")
        private val PROFILE_VALUES_SYNC_PENDING =
            booleanPreferencesKey("profile_values_sync_pending")
        private val REMOTE_ACTION_KEY = stringPreferencesKey("remote_action_key")
        private val REMOTE_ACTION_KEY_ENCRYPTED =
            stringPreferencesKey("remote_action_key_encrypted")
        private val REMOTE_ACTION_URL = stringPreferencesKey("remote_action_url")
        private val REMOTE_DOCUMENT_BINDING = stringPreferencesKey("remote_document_binding")
        private val REMOTE_MANAGED_PROFILE = booleanPreferencesKey("remote_managed_profile")
        private val REMOTE_CARD_DISMISSED = booleanPreferencesKey("remote_card_dismissed")
        private val ACCESS_LIFECYCLE_DISMISSED_SIGNATURE =
            stringPreferencesKey("access_lifecycle_dismissed_signature")
        private val ACCESS_LIFECYCLE_KEY_ENCRYPTED =
            stringPreferencesKey("access_lifecycle_key_encrypted")
        private val ACCESS_LIFECYCLE_URL = stringPreferencesKey("access_lifecycle_url")
        private val ACCESS_LIFECYCLE_BINDING = stringPreferencesKey("access_lifecycle_binding")
        private val PROFILE_EXCHANGE_SUBMIT_TOKEN_ENCRYPTED =
            stringPreferencesKey("profile_exchange_submit_token_encrypted")
        private val PROFILE_EXCHANGE_ACTION_TOKEN_ENCRYPTED =
            stringPreferencesKey("profile_exchange_action_token_encrypted")
        private val PROFILE_EXCHANGE_ACTION_LABEL =
            stringPreferencesKey("profile_exchange_action_label")
        private val PROFILE_EXCHANGE_ACTION_MESSAGE =
            stringPreferencesKey("profile_exchange_action_message")
        private val PROFILE_EXCHANGE_ACTION_AVAILABLE =
            booleanPreferencesKey("profile_exchange_action_available")
        private val CACHED_ACTION_PAYLOAD_ENCRYPTED =
            stringPreferencesKey("cached_action_payload_encrypted")
        private val CACHED_ACTION_URL = stringPreferencesKey("cached_action_url")
        private val CACHED_ACTION_FALLBACK = stringPreferencesKey("cached_action_fallback")
        private val CACHED_ACTION_HANDLER = stringPreferencesKey("cached_action_handler")
        private val CACHED_ACTION_TITLE = stringPreferencesKey("cached_action_title")
        private val CACHED_ACTION_MESSAGE = stringPreferencesKey("cached_action_message")
        private val CACHED_ACTION_LABEL = stringPreferencesKey("cached_action_label")
        private val CACHED_ACTION_CLIPBOARD_LABEL =
            stringPreferencesKey("cached_action_clipboard_label")
        private val CACHED_ACTION_COPIED_MESSAGE =
            stringPreferencesKey("cached_action_copied_message")
        private val CACHED_ACTION_FAILED_MESSAGE =
            stringPreferencesKey("cached_action_failed_message")
        private val CACHED_ACTION_HELP_TITLE =
            stringPreferencesKey("cached_action_help_title")
        private val CACHED_ACTION_HELP_INTRO =
            stringPreferencesKey("cached_action_help_intro")
        private val CACHED_ACTION_HELP_STEPS =
            stringPreferencesKey("cached_action_help_steps")
        private val ACCESS_ACTION_LABEL = stringPreferencesKey("access_action_label")
        private val ACCESS_ACTION_MESSAGE = stringPreferencesKey("access_action_message")
        private val ACCESS_TITLE = stringPreferencesKey("access_title")
        private val ACCESS_MESSAGE = stringPreferencesKey("access_message")
        private val ACCESS_DETAIL_LABEL = stringPreferencesKey("access_detail_label")
        private val ACCESS_DETAIL_VALUE = stringPreferencesKey("access_detail_value")
        private val ACCESS_ACTION_ICON = stringPreferencesKey("access_action_icon")
        private val ACCESS_SEVERITY = stringPreferencesKey("access_severity")
        private val ACCESS_ALLOW_CONNECT = booleanPreferencesKey("access_allow_connect")
        private val ACCESS_ACTION_AVAILABLE = booleanPreferencesKey("access_action_available")
        private val ACCESS_CONTINUATION_AVAILABLE =
            booleanPreferencesKey("access_continuation_available")
        private val ACCESS_CONTINUATION_EXPIRES_AT =
            longPreferencesKey("access_continuation_expires_at")
        private val ACCESS_DISMISSIBLE = booleanPreferencesKey("access_dismissible")
        private val ACCESS_DISMISSED_MESSAGE =
            stringPreferencesKey("access_dismissed_message")
        private val ACCESS_CHECKED_AT = longPreferencesKey("access_checked_at")
        private val ACCESS_LAST_ATTEMPT_AT = longPreferencesKey("access_last_attempt_at")
        private val ACCESS_PROFILE_REVISION = longPreferencesKey("access_profile_revision")
        private val ACCESS_ACTION_LAUNCHED_AT =
            longPreferencesKey("access_action_launched_at")
        private val PROFILE_MAX_WORKERS = intPreferencesKey("profile_max_workers")
        private val PROFILE_WORKER_LIMIT_SEEN = intPreferencesKey("profile_worker_limit_seen")
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
        private val VPN_DNS_SELECTION = stringPreferencesKey("vpn_dns_selection")
        private val VPN_DNS_CUSTOM = stringPreferencesKey("vpn_dns_custom")

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
        private val RT_NETWORK = booleanPreferencesKey("rt_network")
        private val RT_MASQUE = booleanPreferencesKey("rt_masque")
        private val RT_MASQUE_SERVER_BOOTSTRAP = booleanPreferencesKey("rt_masque_server_bootstrap")
        private val RT_TURN_SNI = stringPreferencesKey("rt_turn_sni")
        private val CAPTCHA_MODE = stringPreferencesKey("captcha_mode") // "auto", "wv", or "rjs"
        private val CAPTCHA_SOLVE_METHOD = stringPreferencesKey("captcha_solve_method") // "manual" or "auto"
        private val CAPTCHA_WBV_SOLVE_METHOD = stringPreferencesKey("captcha_wbv_solve_method") // "manual" or "auto"
        
        // ═══ VPN App Routing ═══
        private val IS_WHITELIST = booleanPreferencesKey("is_whitelist")
        private val BLACKLIST_APPS = stringPreferencesKey("blacklist_apps")
        private val WHITELIST_APPS = stringPreferencesKey("whitelist_apps")
        private val BLACKLIST_ADDRESSES = stringPreferencesKey("blacklist_addresses")
        private val WHITELIST_ADDRESSES = stringPreferencesKey("whitelist_addresses")

        // ═══ Theme Mode ═══
        private val THEME_MODE = stringPreferencesKey("theme_mode") // "system", "light", "dark"
        private val IS_DYNAMIC_COLOR = booleanPreferencesKey("is_dynamic_color")
        private val THEME_PALETTE = stringPreferencesKey("theme_palette")

        // ═══ Fingerprint & Client IDs ═══
        private val SELECTED_FINGERPRINT = stringPreferencesKey("selected_fingerprint")
        private val ACTIVE_CLIENT_IDS = stringPreferencesKey("active_client_ids")
        private val CUSTOM_VK_CREDENTIALS_ENABLED = booleanPreferencesKey("custom_vk_credentials_enabled")
        private val CUSTOM_VK_CLIENT_ID = stringPreferencesKey("custom_vk_client_id")
        private val CUSTOM_VK_CLIENT_SECRET = stringPreferencesKey("custom_vk_client_secret")
        private val CUSTOM_VK_CLIENT_SECRET_ENCRYPTED =
            stringPreferencesKey("custom_vk_client_secret_encrypted")

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
        private val INTERFACE_ROLE_BEFORE_REMOTE_PROFILE =
            stringPreferencesKey("interface_role_before_remote_profile")
        private val PERMISSION_ONBOARDING_COMPLETE = booleanPreferencesKey("permission_onboarding_complete")
        private const val VPN_PROFILE_COUNT = 3

        private val PROFILE_STRING_KEYS = listOf(
            PROFILE_NAME,
            PEER,
            VK_HASHES,
            SECONDARY_VK_HASH,
            REMOTE_ACTION_KEY,
            REMOTE_ACTION_KEY_ENCRYPTED,
            REMOTE_ACTION_URL,
            REMOTE_DOCUMENT_BINDING,
            ACCESS_LIFECYCLE_KEY_ENCRYPTED,
            ACCESS_LIFECYCLE_URL,
            ACCESS_LIFECYCLE_BINDING,
            PROFILE_EXCHANGE_SUBMIT_TOKEN_ENCRYPTED,
            PROFILE_EXCHANGE_ACTION_TOKEN_ENCRYPTED,
            PROFILE_EXCHANGE_ACTION_LABEL,
            PROFILE_EXCHANGE_ACTION_MESSAGE,
            CACHED_ACTION_PAYLOAD_ENCRYPTED,
            CACHED_ACTION_URL,
            CACHED_ACTION_FALLBACK,
            CACHED_ACTION_HANDLER,
            CACHED_ACTION_TITLE,
            CACHED_ACTION_MESSAGE,
            CACHED_ACTION_LABEL,
            CACHED_ACTION_CLIPBOARD_LABEL,
            CACHED_ACTION_COPIED_MESSAGE,
            CACHED_ACTION_FAILED_MESSAGE,
            CACHED_ACTION_HELP_TITLE,
            CACHED_ACTION_HELP_INTRO,
            CACHED_ACTION_HELP_STEPS,
            ACCESS_ACTION_LABEL,
            ACCESS_ACTION_MESSAGE,
            ACCESS_TITLE,
            ACCESS_MESSAGE,
            ACCESS_DETAIL_LABEL,
            ACCESS_DETAIL_VALUE,
            ACCESS_ACTION_ICON,
            ACCESS_SEVERITY,
            ACCESS_DISMISSED_MESSAGE,
            ACCESS_LIFECYCLE_DISMISSED_SIGNATURE,
            PROTOCOL,
            SNI,
            VPN_DNS_SELECTION,
            VPN_DNS_CUSTOM,
            USER_AGENT,
            DEPLOY_IP,
            DEPLOY_LOGIN,
            DEPLOY_PASSWORD,
            DEPLOY_PASSWORD_ENCRYPTED,
            DEPLOY_SSH_PRIVATE_KEY,
            DEPLOY_SSH_PRIVATE_KEY_ENCRYPTED,
            DEPLOY_SSH_KEY_PASSPHRASE,
            DEPLOY_SSH_KEY_PASSPHRASE_ENCRYPTED,
            DEPLOY_SSH_AUTH_MODE,
            WG_EXIT_SSH_PRIVATE_KEY,
            WG_EXIT_SSH_PRIVATE_KEY_ENCRYPTED,
            WG_EXIT_SSH_KEY_PASSPHRASE,
            WG_EXIT_SSH_KEY_PASSPHRASE_ENCRYPTED,
            WG_EXIT_SSH_AUTH_MODE,
            DEPLOY_SSH_PORT,
            DEPLOY_DNS1,
            DEPLOY_DNS2,
            EXCLUDED_APPS,
            BLACKLIST_APPS,
            WHITELIST_APPS,
            BLACKLIST_ADDRESSES,
            WHITELIST_ADDRESSES,
            CONNECTION_PASSWORD,
            CONNECTION_PASSWORD_ENCRYPTED,
            DEPLOY_MAIN_PASSWORD,
            DEPLOY_MAIN_PASSWORD_ENCRYPTED,
            DEPLOY_ADMIN_ID,
            DEPLOY_ADMIN_ID_ENCRYPTED,
            DEPLOY_BOT_TOKEN,
            DEPLOY_BOT_TOKEN_ENCRYPTED,
            PROXY_MODE,
            PROXY_HOST,
            CAPTCHA_MODE,
            CAPTCHA_SOLVE_METHOD,
            CAPTCHA_WBV_SOLVE_METHOD,
            RT_TURN_SNI,
            WDTT_LINK,
            CONNECTION_INPUT_METHOD,
            SELECTED_FINGERPRINT,
            ACTIVE_CLIENT_IDS,
            CUSTOM_VK_CLIENT_ID,
            CUSTOM_VK_CLIENT_SECRET,
            CUSTOM_VK_CLIENT_SECRET_ENCRYPTED
        )
        private val PROFILE_INT_KEYS = listOf(
            WORKERS_PER_HASH,
            PROFILE_MAX_WORKERS,
            PROFILE_WORKER_LIMIT_SEEN,
            VK_HASH_NEXT_SLOT,
            LISTEN_PORT,
            SERVER_DTLS_PORT,
            SERVER_WG_PORT,
            PROXY_PORT
        )
        private val PROFILE_LONG_KEYS = listOf(
            ACCESS_CHECKED_AT,
            ACCESS_LAST_ATTEMPT_AT,
            ACCESS_PROFILE_REVISION,
            ACCESS_ACTION_LAUNCHED_AT,
            ACCESS_CONTINUATION_EXPIRES_AT,
        )
        private val PROFILE_BOOLEAN_KEYS = listOf(
            MANUAL_PORTS_ENABLED,
            NO_DTLS,
            NO_DNS,
            IS_WHITELIST,
            WDTT_LINK_MODE,
            REMOTE_MANAGED_PROFILE,
            REMOTE_CARD_DISMISSED,
            VKCALLS_PREFLIGHT,
            RT_NETWORK,
            RT_MASQUE,
            RT_MASQUE_SERVER_BOOTSTRAP,
            DETAILED_LOGS,
            CUSTOM_VK_CREDENTIALS_ENABLED,
            ACCESS_ALLOW_CONNECT,
            ACCESS_ACTION_AVAILABLE,
            ACCESS_CONTINUATION_AVAILABLE,
            ACCESS_DISMISSIBLE,
            PROFILE_VALUES_SYNC_PENDING,
            PROFILE_EXCHANGE_ACTION_AVAILABLE,
        )

        internal fun resettableProfilePreferenceNames(): Set<String> =
            (PROFILE_STRING_KEYS + PROFILE_INT_KEYS + PROFILE_LONG_KEYS + PROFILE_BOOLEAN_KEYS)
                .mapTo(linkedSetOf()) { it.name }

        private fun <T> getProfileKey(baseKey: Preferences.Key<T>, profile: Int): Preferences.Key<T> {
            if (profile == 0) return baseKey
            val newName = "${baseKey.name}_$profile"
            @Suppress("UNCHECKED_CAST")
            return when {
                PROFILE_STRING_KEYS.any { it.name == baseKey.name } -> stringPreferencesKey(newName) as Preferences.Key<T>
                PROFILE_INT_KEYS.any { it.name == baseKey.name } -> intPreferencesKey(newName) as Preferences.Key<T>
                PROFILE_LONG_KEYS.any { it.name == baseKey.name } -> longPreferencesKey(newName) as Preferences.Key<T>
                PROFILE_BOOLEAN_KEYS.any { it.name == baseKey.name } -> booleanPreferencesKey(newName) as Preferences.Key<T>
                else -> throw IllegalArgumentException("Unsupported key type: ${baseKey.name}")
            }
        }
    }

    private val dataStore = appContext.dataStore
    private val secureStore = SecureStringStore(appContext)
    // Keep the selected profile responsive while the DataStore write is being flushed. The
    // snapshot still falls back to the persisted value for every other caller.
    private val activeProfileOverride = MutableStateFlow<Int?>(null)

    val activeProfile: Flow<Int> = preferencesFlow.map { it[ACTIVE_PROFILE] ?: 0 }
    val activeTunnelProfileUiSnapshot: StateFlow<ActiveTunnelProfileUiSnapshot?> =
        combine(preferencesState, activeProfileOverride) { prefs, requestedProfile ->
            prefs?.let {
                val persistedProfile = (it[ACTIVE_PROFILE] ?: 0)
                    .coerceIn(0, VPN_PROFILE_COUNT - 1)
                if (requestedProfile != null && requestedProfile == persistedProfile) {
                    // The DataStore emission has caught up. Clearing the override here keeps
                    // the same snapshot (distinctUntilChanged prevents a visual bounce).
                    activeProfileOverride.compareAndSet(requestedProfile, null)
                }
                val profile =
                    (requestedProfile ?: persistedProfile)
                        .coerceIn(0, VPN_PROFILE_COUNT - 1)
                ActiveTunnelProfileUiSnapshot(
                    profileIndex = profile,
                    profileNames = (0 until VPN_PROFILE_COUNT).map { index ->
                        it[getProfileKey(PROFILE_NAME, index)].orEmpty()
                    },
                    interfaceRole = it[INTERFACE_ROLE].orEmpty(),
                    permissionOnboardingComplete =
                        it[PERMISSION_ONBOARDING_COMPLETE] ?: !it[INTERFACE_ROLE].isNullOrBlank(),
                    connectionInputMethod = it[getProfileKey(CONNECTION_INPUT_METHOD, profile)]
                        ?.takeIf { method -> method == "link" || method == "manual" }
                        .orEmpty(),
                    linkMode = it[getProfileKey(WDTT_LINK_MODE, profile)] ?: false,
                    link = it[getProfileKey(WDTT_LINK, profile)].orEmpty(),
                    peer = it[getProfileKey(PEER, profile)].orEmpty(),
                    vkHashes = it[getProfileKey(VK_HASHES, profile)].orEmpty(),
                    connectionPassword = readSecret(
                        it,
                        CONNECTION_PASSWORD_ENCRYPTED,
                        CONNECTION_PASSWORD,
                        profile
                    ),
                    workersPerHash = it[getProfileKey(WORKERS_PER_HASH, profile)] ?: 18,
                    manualPortsEnabled = it[getProfileKey(MANUAL_PORTS_ENABLED, profile)] ?: false,
                    serverDtlsPort = it[getProfileKey(SERVER_DTLS_PORT, profile)] ?: 56000,
                    serverWgPort = it[getProfileKey(SERVER_WG_PORT, profile)] ?: 56001,
                    listenPort = it[getProfileKey(LISTEN_PORT, profile)] ?: 9000,
                    sni = it[getProfileKey(SNI, profile)].orEmpty(),
                    vpnDnsSelectionId = normalizeVpnDnsSelectionId(
                        it[getProfileKey(VPN_DNS_SELECTION, profile)]
                    ),
                    vpnDnsCustomServers = decodeStoredCustomVpnDnsServers(
                        it[getProfileKey(VPN_DNS_CUSTOM, profile)].orEmpty()
                    ),
                    captchaMode = it[getProfileKey(CAPTCHA_MODE, profile)] ?: "auto",
                    captchaSolveMethod = it[getProfileKey(CAPTCHA_SOLVE_METHOD, profile)] ?: "auto",
                    fingerprint = it[getProfileKey(SELECTED_FINGERPRINT, profile)] ?: "firefox",
                    clientIds = it[getProfileKey(ACTIVE_CLIENT_IDS, profile)] ?: DEFAULT_VK_CLIENT_IDS,
                    customVkCredentialsEnabled =
                        it[getProfileKey(CUSTOM_VK_CREDENTIALS_ENABLED, profile)] ?: false,
                    customVkClientId = normalizeVkClientId(
                        it[getProfileKey(CUSTOM_VK_CLIENT_ID, profile)].orEmpty()
                    ),
                    customVkClientSecret = readSecret(
                        it,
                        CUSTOM_VK_CLIENT_SECRET_ENCRYPTED,
                        CUSTOM_VK_CLIENT_SECRET,
                        profile
                    ),
                    vkCallsPreflight = it[getProfileKey(VKCALLS_PREFLIGHT, profile)] ?: true,
                    rtNetwork = it[getProfileKey(RT_NETWORK, profile)] ?: false,
                    rtMasque = it[getProfileKey(RT_MASQUE, profile)] ?: false,
                    rtMasqueServerBootstrap =
                        it[getProfileKey(RT_MASQUE_SERVER_BOOTSTRAP, profile)] ?: false,
                    rtMasqueServerAccessStatus = deploySshAccessStatus(it, profile),
                    rtTurnSni = it[getProfileKey(RT_TURN_SNI, profile)] ?: DEFAULT_RT_TURN_SNI,
                    remoteActionKey = readSecret(
                        it,
                        REMOTE_ACTION_KEY_ENCRYPTED,
                        REMOTE_ACTION_KEY,
                        profile
                    ),
                    remoteActionUrl = it[getProfileKey(REMOTE_ACTION_URL, profile)].orEmpty(),
                    remoteManaged =
                        it[getProfileKey(REMOTE_MANAGED_PROFILE, profile)] == true,
                    cachedRemoteAction = readCachedRemoteAction(it, profile),
                    remoteCardDismissed =
                        it[getProfileKey(REMOTE_CARD_DISMISSED, profile)] ?: false,
                    accessLifecycle = readAccessLifecycleUiState(it, profile),
                    accessLifecycleDismissedSignature =
                        it[getProfileKey(ACCESS_LIFECYCLE_DISMISSED_SIGNATURE, profile)].orEmpty(),
                    profileMaxWorkers =
                        (it[getProfileKey(PROFILE_MAX_WORKERS, profile)] ?: 0)
                            .coerceIn(0, APP_MAX_WORKERS),
                )
            }
        }.distinctUntilChanged()
            .flowOn(Dispatchers.IO)
            .stateIn(storeScope, SharingStarted.Eagerly, null)

    val activeTunnelProfileContentUiSnapshot: StateFlow<ActiveTunnelProfileUiSnapshot?> =
        activeTunnelProfileUiSnapshot
            .map { snapshot -> snapshot?.withoutTransientAccessState() }
            .distinctUntilChanged()
            .stateIn(storeScope, SharingStarted.Eagerly, null)

    val activeTunnelAccessUiSnapshot: StateFlow<ActiveTunnelAccessUiSnapshot?> =
        activeTunnelProfileUiSnapshot
            .map { snapshot ->
                snapshot?.let {
                    ActiveTunnelAccessUiSnapshot(
                        profileIndex = it.profileIndex,
                        lifecycle = it.accessLifecycle,
                        dismissedSignature = it.accessLifecycleDismissedSignature,
                    )
                }
            }
            .distinctUntilChanged()
            .stateIn(storeScope, SharingStarted.Eagerly, null)

    init {
        storeScope.launch {
            preferencesFlow.first()
            migrateSecretsToKeystore()
            prewarmTunnelProfileSecrets(preferencesFlow.first())
            migrateWireGuardExitSshAuthMode()
            migrateVpnAppLists()
            repairInvalidLinkModes()
            _settingsReady.value = true
        }
    }

    private fun prewarmTunnelProfileSecrets(prefs: Preferences) {
        for (profile in 0 until VPN_PROFILE_COUNT) {
            readSecret(prefs, CONNECTION_PASSWORD_ENCRYPTED, CONNECTION_PASSWORD, profile)
            readSecret(
                prefs,
                CUSTOM_VK_CLIENT_SECRET_ENCRYPTED,
                CUSTOM_VK_CLIENT_SECRET,
                profile,
            )
            readSecret(prefs, REMOTE_ACTION_KEY_ENCRYPTED, REMOTE_ACTION_KEY, profile)
            readProtectedSecret(prefs, ACCESS_LIFECYCLE_KEY_ENCRYPTED, profile)
            readProtectedSecret(prefs, CACHED_ACTION_PAYLOAD_ENCRYPTED, profile)
        }
    }

    private fun deploySshAccessStatus(
        prefs: Preferences,
        profile: Int,
    ): SshProfileAccessStatus {
        val privateKey = readSecret(
            prefs,
            DEPLOY_SSH_PRIVATE_KEY_ENCRYPTED,
            DEPLOY_SSH_PRIVATE_KEY,
            profile,
        )
        val authMode = prefs[getProfileKey(DEPLOY_SSH_AUTH_MODE, profile)]
            ?.takeIf { it == "password" || it == "key" }
            ?: if (privateKey.isNotBlank()) "key" else "password"
        return sshProfileAccessStatus(
            host = prefs[getProfileKey(DEPLOY_IP, profile)].orEmpty().trim(),
            authMode = authMode,
            password = readSecret(
                prefs,
                DEPLOY_PASSWORD_ENCRYPTED,
                DEPLOY_PASSWORD,
                profile,
            ),
            privateKey = privateKey,
        )
    }

    val activeTunnelProfile: Flow<Int?> = preferencesFlow.map { prefs ->
        prefs[ACTIVE_TUNNEL_PROFILE]?.takeIf { it in 0 until VPN_PROFILE_COUNT }
    }
    val profileNames: Flow<List<String>> = preferencesFlow.map { prefs ->
        (0 until VPN_PROFILE_COUNT).map { profile ->
            prefs[getProfileKey(PROFILE_NAME, profile)].orEmpty()
        }
    }
    val showSystemApps: Flow<Boolean> = preferencesFlow.map { it[SHOW_SYSTEM_APPS] ?: false }
    val loggingEnabled: Flow<Boolean> = preferencesFlow.map { it[LOGGING_ENABLED] ?: true }
    val floatingToolbarYFraction: Flow<Float> = preferencesFlow.map { prefs ->
        prefs[FLOATING_TOOLBAR_Y_FRACTION]?.coerceIn(0f, 1f) ?: -1f
    }
    val trustedWifiEnabled: Flow<Boolean> = preferencesFlow.map { it[TRUSTED_WIFI_ENABLED] ?: false }
    val trustedWifiSsids: Flow<List<String>> = preferencesFlow.map { prefs ->
        parseTrustedWifiSsids(prefs[TRUSTED_WIFI_SSIDS].orEmpty())
    }
    val trustedWifiWaiting: Flow<Boolean> = preferencesFlow.map { it[TRUSTED_WIFI_WAITING] ?: false }
    val trustedWifiWaitingSsid: Flow<String> = preferencesFlow.map {
        sanitizeTrustedWifiSsid(it[TRUSTED_WIFI_WAITING_SSID].orEmpty())
    }
    val pauseVpnDuringSleep: Flow<Boolean> = preferencesFlow.map {
        it[PAUSE_VPN_DURING_SLEEP] ?: false
    }
    val pauseVpnDuringSleepDelayMinutes: Flow<Int> = preferencesFlow.map {
        normalizeSleepPauseDelayMinutes(
            it[PAUSE_VPN_DURING_SLEEP_DELAY_MINUTES] ?: DEFAULT_SLEEP_PAUSE_DELAY_MINUTES
        )
    }
    val sleepBatteryMode: Flow<SleepBatteryMode> = preferencesFlow.map {
        SleepBatteryMode.fromStoredValue(it[PAUSE_VPN_DURING_SLEEP_MODE])
    }
    val resumeVpnDuringSleepDelayMinutes: Flow<Int> = preferencesFlow.map {
        normalizeSleepPauseDelayMinutes(
            it[RESUME_VPN_DURING_SLEEP_DELAY_MINUTES] ?: DEFAULT_SLEEP_PAUSE_DELAY_MINUTES
        )
    }
    val sleepBatterySettingsConfigured: Flow<Boolean> = preferencesFlow.map {
        it[SLEEP_BATTERY_SETTINGS_CONFIGURED]
            ?: (
                it[PAUSE_VPN_DURING_SLEEP_DELAY_MINUTES] != null ||
                    it[PAUSE_VPN_DURING_SLEEP_MODE] != null ||
                    it[RESUME_VPN_DURING_SLEEP_DELAY_MINUTES] != null
                )
    }
    internal val sleepBatteryRuntimeState: Flow<SleepBatteryRuntimeState> = preferencesFlow.map { prefs ->
        val deadlineMs = (prefs[ACTIVE_TIMED_SLEEP_RESUME_DEADLINE_MS] ?: 0L).coerceAtLeast(0L)
        val storedPhase = prefs[SLEEP_BATTERY_RUNTIME_PHASE]
        SleepBatteryRuntimeState(
            phase = if (storedPhase == null && deadlineMs > 0L) {
                // Совместимость с локальными сборками, где сохранялся только
                // дедлайн второго режима.
                SleepBatteryRuntimePhase.WAITING_TO_RESUME
            } else {
                SleepBatteryRuntimePhase.fromStoredValue(storedPhase)
            },
            deadlineMs = deadlineMs,
        )
    }
    val wdttLink: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(WDTT_LINK, profile)] ?: ""
    }
    val wdttLinkMode: Flow<Boolean> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(WDTT_LINK_MODE, profile)] ?: false
    }
    val connectionInputMethod: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(CONNECTION_INPUT_METHOD, profile)]
            ?.takeIf { it == "link" || it == "manual" }
            .orEmpty()
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
    val remoteActionKey: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        readSecret(prefs, REMOTE_ACTION_KEY_ENCRYPTED, REMOTE_ACTION_KEY, profile)
    }
    val remoteActionUrl: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(REMOTE_ACTION_URL, profile)].orEmpty()
    }
    val remoteManagedProfile: Flow<Boolean> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(REMOTE_MANAGED_PROFILE, profile)] == true
    }
    val activeAccessLifecycle: Flow<AccessLifecycleUiState> = preferencesFlow.map { prefs ->
        val profile = (prefs[ACTIVE_PROFILE] ?: 0).coerceIn(0, VPN_PROFILE_COUNT - 1)
        readAccessLifecycleUiState(prefs, profile)
    }.distinctUntilChanged().flowOn(Dispatchers.IO)
    val profileMaxWorkers: Flow<Int> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        (prefs[getProfileKey(PROFILE_MAX_WORKERS, profile)] ?: 0).coerceIn(0, APP_MAX_WORKERS)
    }
    val workersPerHash: Flow<Int> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(WORKERS_PER_HASH, profile)] ?: 18
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
    }.distinctUntilChanged().flowOn(Dispatchers.IO)
    val deploySshPrivateKey: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        readSecret(prefs, DEPLOY_SSH_PRIVATE_KEY_ENCRYPTED, DEPLOY_SSH_PRIVATE_KEY, profile)
    }.distinctUntilChanged().flowOn(Dispatchers.IO)
    val deploySshKeyPassphrase: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        readSecret(prefs, DEPLOY_SSH_KEY_PASSPHRASE_ENCRYPTED, DEPLOY_SSH_KEY_PASSPHRASE, profile)
    }.distinctUntilChanged().flowOn(Dispatchers.IO)
    val deploySshAuthMode: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(DEPLOY_SSH_AUTH_MODE, profile)]
            ?.takeIf { it == "password" || it == "key" }
            ?: if (readSecret(prefs, DEPLOY_SSH_PRIVATE_KEY_ENCRYPTED, DEPLOY_SSH_PRIVATE_KEY, profile).isNotBlank()) "key" else "password"
    }.distinctUntilChanged().flowOn(Dispatchers.IO)
    val wireGuardExitSshPrivateKey: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        readSecret(prefs, WG_EXIT_SSH_PRIVATE_KEY_ENCRYPTED, WG_EXIT_SSH_PRIVATE_KEY, profile)
    }.distinctUntilChanged().flowOn(Dispatchers.IO)
    val wireGuardExitSshKeyPassphrase: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        readSecret(prefs, WG_EXIT_SSH_KEY_PASSPHRASE_ENCRYPTED, WG_EXIT_SSH_KEY_PASSPHRASE, profile)
    }.distinctUntilChanged().flowOn(Dispatchers.IO)
    val wireGuardExitSshAuthMode: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(WG_EXIT_SSH_AUTH_MODE, profile)]
            ?.takeIf { it == "password" || it == "key" }
            ?: if (readSecret(prefs, WG_EXIT_SSH_PRIVATE_KEY_ENCRYPTED, WG_EXIT_SSH_PRIVATE_KEY, profile).isNotBlank()) "key" else "password"
    }.distinctUntilChanged().flowOn(Dispatchers.IO)
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

    private fun vpnDnsSettingsSnapshot(
        prefs: Preferences,
        profileIndex: Int,
    ): VpnDnsSettingsSnapshot {
        val profile = profileIndex.coerceIn(0, VPN_PROFILE_COUNT - 1)
        return VpnDnsSettingsSnapshot(
            profileIndex = profile,
            selectionId = normalizeVpnDnsSelectionId(
                prefs[getProfileKey(VPN_DNS_SELECTION, profile)]
            ),
            customServers = decodeStoredCustomVpnDnsServers(
                prefs[getProfileKey(VPN_DNS_CUSTOM, profile)].orEmpty()
            ),
        )
    }

    internal val vpnDnsSettings: Flow<VpnDnsSettingsSnapshot> = preferencesFlow.map { prefs ->
        vpnDnsSettingsSnapshot(
            prefs = prefs,
            profileIndex = prefs[ACTIVE_PROFILE] ?: 0,
        )
    }.distinctUntilChanged().flowOn(Dispatchers.IO)

    internal suspend fun vpnDnsSettingsForProfile(
        profileIndex: Int,
    ): VpnDnsSettingsSnapshot = vpnDnsSettingsSnapshot(
        prefs = preferencesFlow.first(),
        profileIndex = profileIndex,
    )

    private fun vpnRoutingSettingsSnapshot(
        prefs: Preferences,
        profileIndex: Int,
    ): VpnRoutingSettingsSnapshot {
        val profile = profileIndex.coerceIn(0, VPN_PROFILE_COUNT - 1)
        val whitelist = prefs[getProfileKey(IS_WHITELIST, profile)] == true
        val appKey = if (whitelist) {
            WHITELIST_APPS
        } else {
            BLACKLIST_APPS
        }
        val addressKey = if (whitelist) {
            WHITELIST_ADDRESSES
        } else {
            BLACKLIST_ADDRESSES
        }
        return VpnRoutingSettingsSnapshot(
            profileIndex = profile,
            isWhitelist = whitelist,
            appPackages = sanitizeVpnRoutingPackages(
                decodeStoredVpnPackages(prefs[getProfileKey(appKey, profile)].orEmpty()),
                appContext.packageName,
            ).joinToString(","),
            addressRules = decodeVpnAddressRules(
                prefs[getProfileKey(addressKey, profile)].orEmpty()
            ),
        )
    }

    internal val vpnRoutingSettings: Flow<VpnRoutingSettingsSnapshot> = preferencesFlow.map { prefs ->
        vpnRoutingSettingsSnapshot(
            prefs = prefs,
            profileIndex = prefs[ACTIVE_PROFILE] ?: 0,
        )
    }.distinctUntilChanged().flowOn(Dispatchers.IO)

    internal suspend fun vpnRoutingSettingsForProfile(
        profileIndex: Int,
    ): VpnRoutingSettingsSnapshot = vpnRoutingSettingsSnapshot(
        prefs = preferencesFlow.first(),
        profileIndex = profileIndex,
    )

    val vpnAppPackages: Flow<String> = vpnRoutingSettings
        .map { snapshot -> snapshot.appPackages }
        .distinctUntilChanged()

    internal val vpnAddressRules: Flow<List<VpnAddressRule>> = vpnRoutingSettings
        .map { snapshot -> snapshot.addressRules }
        .distinctUntilChanged()
    
    val detailedLogs: Flow<Boolean> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(DETAILED_LOGS, profile)] ?: false
    }
    
    // ═══ Пароли и Управление ═══
    val connectionPassword: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        readSecret(prefs, CONNECTION_PASSWORD_ENCRYPTED, CONNECTION_PASSWORD, profile)
    }.distinctUntilChanged().flowOn(Dispatchers.IO)
    val deployMainPassword: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        readSecret(prefs, DEPLOY_MAIN_PASSWORD_ENCRYPTED, DEPLOY_MAIN_PASSWORD, profile)
    }.distinctUntilChanged().flowOn(Dispatchers.IO)
    val deployAdminId: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        readSecret(prefs, DEPLOY_ADMIN_ID_ENCRYPTED, DEPLOY_ADMIN_ID, profile)
    }.distinctUntilChanged().flowOn(Dispatchers.IO)
    val deployBotToken: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        readSecret(prefs, DEPLOY_BOT_TOKEN_ENCRYPTED, DEPLOY_BOT_TOKEN, profile)
    }.distinctUntilChanged().flowOn(Dispatchers.IO)

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
    val rtNetwork: Flow<Boolean> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(RT_NETWORK, profile)] ?: false
    }
    val rtMasque: Flow<Boolean> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(RT_MASQUE, profile)] ?: false
    }
    val rtMasqueServerBootstrap: Flow<Boolean> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(RT_MASQUE_SERVER_BOOTSTRAP, profile)] ?: false
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
    val isWhitelist: Flow<Boolean> = vpnRoutingSettings
        .map { snapshot -> snapshot.isWhitelist }
        .distinctUntilChanged()

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
        prefs[getProfileKey(ACTIVE_CLIENT_IDS, profile)] ?: DEFAULT_VK_CLIENT_IDS
    }
    val customVkCredentialsEnabled: Flow<Boolean> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(CUSTOM_VK_CREDENTIALS_ENABLED, profile)] ?: false
    }
    val customVkClientId: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        normalizeVkClientId(prefs[getProfileKey(CUSTOM_VK_CLIENT_ID, profile)].orEmpty())
    }
    val customVkClientSecret: Flow<String> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        readSecret(
            prefs,
            CUSTOM_VK_CLIENT_SECRET_ENCRYPTED,
            CUSTOM_VK_CLIENT_SECRET,
            profile
        )
    }
    val customVkCredentialsComplete: Flow<Boolean> = preferencesFlow.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        val clientId = prefs[getProfileKey(CUSTOM_VK_CLIENT_ID, profile)].orEmpty()
        val clientSecret = readSecret(
            prefs,
            CUSTOM_VK_CLIENT_SECRET_ENCRYPTED,
            CUSTOM_VK_CLIENT_SECRET,
            profile
        )
        isValidVkClientId(clientId) && clientSecret.isNotBlank()
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
        require(role == "user" || role == "admin") { "Неизвестный режим интерфейса" }
        dataStore.edit { prefs ->
            val hadRole = !prefs[INTERFACE_ROLE].isNullOrBlank()
            prefs[INTERFACE_ROLE] = role
            prefs.remove(INTERFACE_ROLE_BEFORE_REMOTE_PROFILE)
            if (!hadRole && !prefs.contains(PERMISSION_ONBOARDING_COMPLETE)) {
                prefs[PERMISSION_ONBOARDING_COMPLETE] = false
            }
        }
    }

    suspend fun synchronizeInterfaceRoleForProfile(remoteManagedProfile: Boolean) {
        dataStore.edit { prefs ->
            val hadRole = !prefs[INTERFACE_ROLE].isNullOrBlank()
            val state = reconcileInterfaceRoleForProfile(
                storedRole = prefs[INTERFACE_ROLE].orEmpty(),
                rememberedRole = prefs[INTERFACE_ROLE_BEFORE_REMOTE_PROFILE],
                remoteManagedProfile = remoteManagedProfile,
            )
            if (state.role.isBlank()) {
                prefs.remove(INTERFACE_ROLE)
            } else {
                prefs[INTERFACE_ROLE] = state.role
            }
            state.rememberedRole?.let { rememberedRole ->
                prefs[INTERFACE_ROLE_BEFORE_REMOTE_PROFILE] = rememberedRole
            } ?: prefs.remove(INTERFACE_ROLE_BEFORE_REMOTE_PROFILE)
            if (!hadRole && state.role.isNotBlank() && !prefs.contains(PERMISSION_ONBOARDING_COMPLETE)) {
                prefs[PERMISSION_ONBOARDING_COMPLETE] = false
            }
        }
    }

    suspend fun useUserInterfaceForRemoteActivationIfUnset() {
        dataStore.edit { prefs ->
            if (prefs[INTERFACE_ROLE].isNullOrBlank()) {
                prefs[INTERFACE_ROLE] = "user"
                if (!prefs.contains(PERMISSION_ONBOARDING_COMPLETE)) {
                    prefs[PERMISSION_ONBOARDING_COMPLETE] = false
                }
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

    suspend fun saveCustomVkCredentialsEnabled(enabled: Boolean) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(CUSTOM_VK_CREDENTIALS_ENABLED, profile)] = enabled
        }
    }

    suspend fun saveCustomVkCredentials(clientId: String, clientSecret: String) {
        val normalizedId = normalizeVkClientId(clientId)
        val normalizedSecret = normalizeVkClientSecret(clientSecret)
        require(isValidVkClientId(normalizedId)) { "Client ID должен состоять из цифр" }
        require(normalizedSecret.isNotBlank()) { "Client secret не может быть пустым" }
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(CUSTOM_VK_CLIENT_ID, profile)] = normalizedId
            prefs.putSecret(
                CUSTOM_VK_CLIENT_SECRET_ENCRYPTED,
                CUSTOM_VK_CLIENT_SECRET,
                normalizedSecret,
                profile
            )
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
        val normalized = profile.coerceIn(0, VPN_PROFILE_COUNT - 1)
        activeProfileOverride.value = normalized
        dataStore.edit { prefs ->
            prefs[ACTIVE_PROFILE] = normalized
        }
    }

    suspend fun saveFloatingToolbarYFraction(fraction: Float) {
        dataStore.edit { prefs ->
            prefs[FLOATING_TOOLBAR_Y_FRACTION] = fraction.coerceIn(0f, 1f)
        }
    }

    suspend fun saveActiveTunnelProfile(profile: Int?) {
        dataStore.edit { prefs ->
            if (profile == null) {
                prefs.remove(ACTIVE_TUNNEL_PROFILE)
            } else {
                prefs[ACTIVE_TUNNEL_PROFILE] = profile.coerceIn(0, VPN_PROFILE_COUNT - 1)
            }
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

    suspend fun saveRemoteCardDismissed(profile: Int, dismissed: Boolean) {
        dataStore.edit { prefs ->
            val key = getProfileKey(
                REMOTE_CARD_DISMISSED,
                profile.coerceIn(0, VPN_PROFILE_COUNT - 1)
            )
            if (dismissed) {
                prefs[key] = true
            } else {
                prefs.remove(key)
            }
        }
    }

    suspend fun saveAccessLifecycleDismissedSignature(profile: Int, signature: String) {
        dataStore.edit { prefs ->
            val key = getProfileKey(
                ACCESS_LIFECYCLE_DISMISSED_SIGNATURE,
                profile.coerceIn(0, VPN_PROFILE_COUNT - 1)
            )
            if (signature.isBlank()) {
                prefs.remove(key)
            } else {
                prefs[key] = signature
            }
        }
    }

    suspend fun resetProfile(profile: Int) {
        val index = profile.coerceIn(0, VPN_PROFILE_COUNT - 1)
        dataStore.edit { prefs ->
            PROFILE_STRING_KEYS.forEach { key ->
                prefs.remove(getProfileKey(key, index))
            }
            PROFILE_INT_KEYS.forEach { key ->
                prefs.remove(getProfileKey(key, index))
            }
            PROFILE_LONG_KEYS.forEach { key ->
                prefs.remove(getProfileKey(key, index))
            }
            PROFILE_BOOLEAN_KEYS.forEach { key ->
                prefs.remove(getProfileKey(key, index))
            }
            prefs.remove(serverMigrationCompletedKey(index))
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
            val hasConfiguredNetworks =
                parseTrustedWifiSsids(prefs[TRUSTED_WIFI_SSIDS].orEmpty()).isNotEmpty()
            val effectiveEnabled = enabled && hasConfiguredNetworks
            prefs[TRUSTED_WIFI_ENABLED] = effectiveEnabled
            if (!effectiveEnabled) {
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
            if (values.isEmpty()) {
                prefs.remove(TRUSTED_WIFI_SSIDS)
                prefs[TRUSTED_WIFI_ENABLED] = false
                prefs.remove(TRUSTED_WIFI_WAITING)
                prefs.remove(TRUSTED_WIFI_WAITING_SSID)
            } else {
                prefs[TRUSTED_WIFI_SSIDS] = JSONArray(values).toString()
            }
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

    suspend fun savePauseVpnDuringSleep(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[PAUSE_VPN_DURING_SLEEP] = enabled
        }
    }

    suspend fun saveSleepBatteryMode(
        enabled: Boolean,
        mode: SleepBatteryMode,
        pauseDelayMinutes: Int,
        resumeDelayMinutes: Int,
    ) {
        dataStore.edit { prefs ->
            prefs[PAUSE_VPN_DURING_SLEEP] = enabled
            prefs[PAUSE_VPN_DURING_SLEEP_DELAY_MINUTES] =
                normalizeSleepPauseDelayMinutes(pauseDelayMinutes)
            prefs[PAUSE_VPN_DURING_SLEEP_MODE] = mode.storedValue
            prefs[RESUME_VPN_DURING_SLEEP_DELAY_MINUTES] =
                normalizeSleepPauseDelayMinutes(resumeDelayMinutes)
            prefs[SLEEP_BATTERY_SETTINGS_CONFIGURED] = true
        }
    }

    internal suspend fun saveSleepBatteryRuntimeState(
        phase: SleepBatteryRuntimePhase,
        deadlineMs: Long = 0L,
    ) {
        dataStore.edit { prefs ->
            if (phase == SleepBatteryRuntimePhase.IDLE) {
                prefs.remove(SLEEP_BATTERY_RUNTIME_PHASE)
            } else {
                prefs[SLEEP_BATTERY_RUNTIME_PHASE] = phase.storedValue
            }
            if (deadlineMs > 0L) {
                prefs[ACTIVE_TIMED_SLEEP_RESUME_DEADLINE_MS] = deadlineMs
            } else {
                prefs.remove(ACTIVE_TIMED_SLEEP_RESUME_DEADLINE_MS)
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

    suspend fun createWdttDeepLinkApplyPlan(
        link: String,
        allowOmittedConnection: Boolean = false,
    ): WdttDeepLinkApplyPlan? {
        WdttDeepLink.parse(
            link,
            allowMissingHashes = true,
            allowOmittedConnection = allowOmittedConnection,
        ) ?: return null
        val cleanLink = link.trim()
        return appContext.dataStore.data.map { prefs ->
            val activeProfile = (prefs[ACTIVE_PROFILE] ?: 0).coerceIn(0, VPN_PROFILE_COUNT - 1)
            val freeProfile = (0 until VPN_PROFILE_COUNT).firstOrNull { profile ->
                prefs.isTunnelProfileEmpty(profile) && !prefs.hasRemoteAttachment(profile)
            }
            val blockedProfiles = (0 until VPN_PROFILE_COUNT)
                .filterTo(mutableSetOf()) { profile ->
                    prefs.protectsRemoteProfileFromReplacement(profile)
                }
            val fallbackProfile = (0 until VPN_PROFILE_COUNT)
                .firstOrNull { it !in blockedProfiles }
                ?: activeProfile
            WdttDeepLinkApplyPlan(
                link = cleanLink,
                targetProfile = freeProfile ?: fallbackProfile,
                requiresConfirmation = freeProfile == null,
                storeAsLink = false,
                blockedProfiles = blockedProfiles,
            )
        }.first()
    }

    suspend fun tunnelProfileSnapshot(profileIndex: Int? = null): TunnelProfileSnapshot =
        preferencesFlow.map { prefs ->
            val profile = (profileIndex ?: prefs[ACTIVE_PROFILE] ?: 0)
                .coerceIn(0, VPN_PROFILE_COUNT - 1)
            TunnelProfileSnapshot(
                profileIndex = profile,
                remoteManaged = prefs[getProfileKey(REMOTE_MANAGED_PROFILE, profile)] == true,
                linkMode = prefs[getProfileKey(WDTT_LINK_MODE, profile)] ?: false,
                link = prefs[getProfileKey(WDTT_LINK, profile)].orEmpty(),
                peer = prefs[getProfileKey(PEER, profile)].orEmpty(),
                vkHashes = prefs[getProfileKey(VK_HASHES, profile)].orEmpty(),
                secondaryVkHash = prefs[getProfileKey(SECONDARY_VK_HASH, profile)].orEmpty(),
                connectionPassword = readSecret(
                    prefs,
                    CONNECTION_PASSWORD_ENCRYPTED,
                    CONNECTION_PASSWORD,
                    profile
                ),
                workersPerHash = prefs[getProfileKey(WORKERS_PER_HASH, profile)] ?: 18,
                profileMaxWorkers = (prefs[getProfileKey(PROFILE_MAX_WORKERS, profile)] ?: 0)
                    .coerceIn(0, APP_MAX_WORKERS),
                manualPortsEnabled = prefs[getProfileKey(MANUAL_PORTS_ENABLED, profile)] ?: false,
                serverDtlsPort = prefs[getProfileKey(SERVER_DTLS_PORT, profile)] ?: 56000,
                listenPort = prefs[getProfileKey(LISTEN_PORT, profile)] ?: 9000,
                sni = prefs[getProfileKey(SNI, profile)].orEmpty(),
                protocol = prefs[getProfileKey(PROTOCOL, profile)] ?: "udp",
                vpnDnsSelectionId = normalizeVpnDnsSelectionId(
                    prefs[getProfileKey(VPN_DNS_SELECTION, profile)]
                ),
                vpnDnsCustomServers = decodeStoredCustomVpnDnsServers(
                    prefs[getProfileKey(VPN_DNS_CUSTOM, profile)].orEmpty()
                ),
                vkCallsPreflight = prefs[getProfileKey(VKCALLS_PREFLIGHT, profile)] ?: true,
                rtNetwork = prefs[getProfileKey(RT_NETWORK, profile)] ?: false,
                rtMasque = prefs[getProfileKey(RT_MASQUE, profile)] ?: false,
                rtMasqueServerBootstrap =
                    prefs[getProfileKey(RT_MASQUE_SERVER_BOOTSTRAP, profile)] ?: false,
                rtMasqueServerAccessReady = deploySshAccessStatus(prefs, profile).available,
                rtTurnSni = prefs[getProfileKey(RT_TURN_SNI, profile)] ?: DEFAULT_RT_TURN_SNI,
                captchaMode = prefs[getProfileKey(CAPTCHA_MODE, profile)] ?: "auto",
                captchaSolveMethod = prefs[getProfileKey(CAPTCHA_SOLVE_METHOD, profile)] ?: "auto",
                fingerprint = prefs[getProfileKey(SELECTED_FINGERPRINT, profile)] ?: "firefox",
                clientIds = prefs[getProfileKey(ACTIVE_CLIENT_IDS, profile)] ?: DEFAULT_VK_CLIENT_IDS,
                customVkCredentialsEnabled =
                    prefs[getProfileKey(CUSTOM_VK_CREDENTIALS_ENABLED, profile)] ?: false,
                customVkClientId = normalizeVkClientId(
                    prefs[getProfileKey(CUSTOM_VK_CLIENT_ID, profile)].orEmpty()
                ),
                customVkClientSecret = readSecret(
                    prefs,
                    CUSTOM_VK_CLIENT_SECRET_ENCRYPTED,
                    CUSTOM_VK_CLIENT_SECRET,
                    profile
                ),
            )
        }.first()

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
                hashes = prefs[getProfileKey(VK_HASHES, profile)].orEmpty(),
                maxWorkers = prefs[getProfileKey(PROFILE_MAX_WORKERS, profile)] ?: 0
            )
            val names = (0 until VPN_PROFILE_COUNT).map { index ->
                prefs[getProfileKey(PROFILE_NAME, index)].orEmpty()
            }
            val profileLabel = vpnProfileDisplayName(profile, names)
            val link = WdttTransferCodec.buildConnectionLink(
                parts.copy(
                    profileName = vpnProfileTransferName(profile, names),
                    maxWorkers = prefs[getProfileKey(PROFILE_MAX_WORKERS, profile)] ?: 0
                )
            )
            val validation = WdttDeepLink.validate(link)
            require(validation.canStartVpn) {
                "Профиль «$profileLabel» заполнен не полностью. Проверьте адрес, порты, пароль и VK-хеши."
            }
            link
        }.first()
    }

    /** Returns ordinary local slots that can accept one generic remote attachment. */
    suspend fun remoteAttachmentCandidates(): List<RemoteAttachmentCandidate> =
        appContext.dataStore.data.map { prefs ->
            val names = (0 until VPN_PROFILE_COUNT).map { index ->
                prefs[getProfileKey(PROFILE_NAME, index)].orEmpty()
            }
            (0 until VPN_PROFILE_COUNT).mapNotNull { profile ->
                if (
                    prefs.hasRemoteAttachment(profile) &&
                    !prefs.canReplaceRemoteAttachment(profile)
                ) {
                    return@mapNotNull null
                }
                val tunnelModified = !prefs.isTunnelProfileEmpty(profile)
                val deployModified = prefs.isDeployProfileModified(profile)
                val renamed = prefs[getProfileKey(PROFILE_NAME, profile)].orEmpty().isNotBlank()
                val candidate = prefs.completeRemoteAttachmentDocument(profile, names)
                RemoteAttachmentCandidate(
                    profileIndex = profile,
                    displayName = vpnProfileDisplayName(profile, names),
                    sourceLabel = candidate?.sourceLabel ?: when {
                        tunnelModified && deployModified -> "Туннель и Деплой"
                        tunnelModified -> "Туннель"
                        deployModified -> "Деплой"
                        renamed -> "Переименован"
                        else -> "Пустой профиль"
                    },
                    document = candidate?.document.orEmpty(),
                    modified = renamed || tunnelModified || deployModified,
                )
            }
        }.first()

    /** Builds a complete value-free document only when the selected slot is ready to act. */
    suspend fun remoteActionProfileDocument(profileIndex: Int): String? =
        preferencesFlow.map { prefs ->
            val profile = profileIndex.coerceIn(0, VPN_PROFILE_COUNT - 1)
            val names = (0 until VPN_PROFILE_COUNT).map { index ->
                prefs[getProfileKey(PROFILE_NAME, index)].orEmpty()
            }
            prefs.completeRemoteAttachmentDocument(profile, names)?.document
        }.first()

    /**
     * Builds a value-free connection document for an explicit generic attachment request.
     * Existing remotely managed profiles are deliberately excluded because each local profile
     * can own only one bound remote-management capability.
     */
    private fun Preferences.hasRemoteAttachment(profile: Int): Boolean =
        this[getProfileKey(REMOTE_MANAGED_PROFILE, profile)] == true ||
            this[getProfileKey(REMOTE_DOCUMENT_BINDING, profile)].orEmpty().isNotBlank() ||
            this[getProfileKey(REMOTE_ACTION_URL, profile)].orEmpty().isNotBlank() ||
            this[getProfileKey(ACCESS_LIFECYCLE_URL, profile)].orEmpty().isNotBlank()

    private fun Preferences.canReplaceRemoteAttachment(profile: Int): Boolean {
        val status = readStoredAccessLifecycle(this, profile).status
        return canReplaceRemoteAttachment(
            hasAttachment = hasRemoteAttachment(profile),
            remoteManaged = this[getProfileKey(REMOTE_MANAGED_PROFILE, profile)] == true,
            continuationAvailable = status?.continuationAvailable,
            dismissible = status?.dismissible,
        )
    }

    private fun Preferences.protectsRemoteProfileFromReplacement(profile: Int): Boolean {
        return protectsRemoteProfileFromReplacement(
            remoteManagedProfile =
                this[getProfileKey(REMOTE_MANAGED_PROFILE, profile)] == true,
            allowConnect = readStoredAccessLifecycle(this, profile).status?.allowConnect,
        )
    }

    private fun Preferences.completeRemoteAttachmentDocument(
        profile: Int,
        names: List<String>,
    ): RemoteAttachmentDocument? {
        val profileName = vpnProfileTransferName(profile, names)
        val maxWorkers = this[getProfileKey(PROFILE_MAX_WORKERS, profile)] ?: 0
        val storedLink = this[getProfileKey(WDTT_LINK, profile)].orEmpty()
        val storedParts = if (this[getProfileKey(WDTT_LINK_MODE, profile)] == true) {
            WdttDeepLink.parse(storedLink, allowMissingHashes = true)
        } else {
            null
        }
        val tunnelParts = storedParts ?: WdttLinkParts(
            host = this[getProfileKey(PEER, profile)].orEmpty().trim(),
            dtlsPort = this[getProfileKey(SERVER_DTLS_PORT, profile)] ?: 56000,
            wgPort = this[getProfileKey(SERVER_WG_PORT, profile)] ?: 56001,
            localPort = this[getProfileKey(LISTEN_PORT, profile)] ?: 9000,
            password = readSecret(
                this,
                CONNECTION_PASSWORD_ENCRYPTED,
                CONNECTION_PASSWORD,
                profile,
            ),
            hashes = "",
            maxWorkers = maxWorkers,
        )
        val deployParts = WdttLinkParts(
            host = this[getProfileKey(DEPLOY_IP, profile)].orEmpty().trim(),
            dtlsPort = this[getProfileKey(SERVER_DTLS_PORT, profile)] ?: 56000,
            wgPort = this[getProfileKey(SERVER_WG_PORT, profile)] ?: 56001,
            localPort = this[getProfileKey(LISTEN_PORT, profile)] ?: 9000,
            password = readSecret(
                this,
                DEPLOY_MAIN_PASSWORD_ENCRYPTED,
                DEPLOY_MAIN_PASSWORD,
                profile,
            ),
            hashes = "",
            maxWorkers = maxWorkers,
        )
        return selectRemoteAttachmentDocument(
            tunnelParts = tunnelParts,
            deployParts = deployParts,
            profileName = profileName,
            maxWorkers = maxWorkers,
            alreadyManaged = false,
        )
    }

    suspend fun exportAdminSettings(): String = appContext.dataStore.data.map { prefs ->
        val profiles = JSONArray()
        repeat(VPN_PROFILE_COUNT) { profile ->
            profiles.put(JSONObject().apply {
                put("wdttLink", prefs[getProfileKey(WDTT_LINK, profile)].orEmpty())
                put("wdttLinkMode", prefs[getProfileKey(WDTT_LINK_MODE, profile)] ?: false)
                put(
                    "connectionInputMethod",
                    prefs[getProfileKey(CONNECTION_INPUT_METHOD, profile)]
                        ?.takeIf { it == "link" || it == "manual" }
                        .orEmpty()
                )
                put("peer", prefs[getProfileKey(PEER, profile)].orEmpty())
                put("vkHashes", prefs[getProfileKey(VK_HASHES, profile)].orEmpty())
                put("secondaryVkHash", prefs[getProfileKey(SECONDARY_VK_HASH, profile)].orEmpty())
                put("workersPerHash", prefs[getProfileKey(WORKERS_PER_HASH, profile)] ?: 18)
                put("profileMaxWorkers", prefs[getProfileKey(PROFILE_MAX_WORKERS, profile)] ?: 0)
                put("protocol", prefs[getProfileKey(PROTOCOL, profile)] ?: "udp")
                put("listenPort", prefs[getProfileKey(LISTEN_PORT, profile)] ?: 9000)
                put("manualPortsEnabled", prefs[getProfileKey(MANUAL_PORTS_ENABLED, profile)] ?: false)
                put("serverDtlsPort", prefs[getProfileKey(SERVER_DTLS_PORT, profile)] ?: 56000)
                put("serverWgPort", prefs[getProfileKey(SERVER_WG_PORT, profile)] ?: 56001)
                put("sni", prefs[getProfileKey(SNI, profile)].orEmpty())
                put("noDtls", prefs[getProfileKey(NO_DTLS, profile)] ?: false)
                put("noDns", prefs[getProfileKey(NO_DNS, profile)] ?: false)
                put(
                    "vpnDnsSelection",
                    normalizeVpnDnsSelectionId(
                        prefs[getProfileKey(VPN_DNS_SELECTION, profile)]
                    )
                )
                put(
                    "vpnDnsCustom",
                    decodeStoredCustomVpnDnsServers(
                        prefs[getProfileKey(VPN_DNS_CUSTOM, profile)].orEmpty()
                    ).joinToString(",")
                )
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
                put("rtNetwork", prefs[getProfileKey(RT_NETWORK, profile)] ?: false)
                put("rtMasque", prefs[getProfileKey(RT_MASQUE, profile)] ?: false)
                put(
                    "rtMasqueServerBootstrap",
                    prefs[getProfileKey(RT_MASQUE_SERVER_BOOTSTRAP, profile)] ?: false,
                )
                put("rtTurnSni", prefs[getProfileKey(RT_TURN_SNI, profile)] ?: DEFAULT_RT_TURN_SNI)
                put("captchaMode", prefs[getProfileKey(CAPTCHA_MODE, profile)] ?: "auto")
                put("captchaSolveMethod", prefs[getProfileKey(CAPTCHA_SOLVE_METHOD, profile)] ?: "auto")
                put("captchaWbvSolveMethod", prefs[getProfileKey(CAPTCHA_WBV_SOLVE_METHOD, profile)] ?: "auto")
                put("isWhitelist", prefs[getProfileKey(IS_WHITELIST, profile)] ?: false)
                put("blacklistApps", prefs[getProfileKey(BLACKLIST_APPS, profile)].orEmpty())
                put("whitelistApps", prefs[getProfileKey(WHITELIST_APPS, profile)].orEmpty())
                put("blacklistAddresses", prefs[getProfileKey(BLACKLIST_ADDRESSES, profile)].orEmpty())
                put("whitelistAddresses", prefs[getProfileKey(WHITELIST_ADDRESSES, profile)].orEmpty())
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
        activeProfileOverride.value = null
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
                prefs.putSecret(
                    REMOTE_ACTION_KEY_ENCRYPTED,
                    REMOTE_ACTION_KEY,
                    "",
                    profile,
                )
                prefs.remove(getProfileKey(REMOTE_ACTION_URL, profile))
                prefs.remove(getProfileKey(REMOTE_DOCUMENT_BINDING, profile))
                prefs.remove(getProfileKey(REMOTE_MANAGED_PROFILE, profile))
                prefs.remove(getProfileKey(PROFILE_WORKER_LIMIT_SEEN, profile))
                prefs.clearAccessLifecycle(profile)
                val importedLink = item.optString("wdttLink")
                val importedLinkMode = item.optBoolean("wdttLinkMode")
                val importedPeer = item.optString("peer")
                val importedConnectionPassword = item.optString("connectionPassword")
                val requestedImportedMethod = item.optString("connectionInputMethod")
                    .takeIf { it == "link" || it == "manual" }
                val importedMethod = when {
                    importedLinkMode &&
                        WdttDeepLink.parse(importedLink, allowMissingHashes = true) != null -> "link"
                    requestedImportedMethod == "manual" -> "manual"
                    importedPeer.isNotBlank() && importedConnectionPassword.isNotBlank() -> "manual"
                    else -> ""
                }
                prefs[getProfileKey(WDTT_LINK, profile)] = importedLink
                prefs[getProfileKey(WDTT_LINK_MODE, profile)] = importedLinkMode
                val connectionInputMethodKey = getProfileKey(CONNECTION_INPUT_METHOD, profile)
                if (importedMethod.isBlank()) {
                    prefs.remove(connectionInputMethodKey)
                } else {
                    prefs[connectionInputMethodKey] = importedMethod
                }
                prefs[getProfileKey(PEER, profile)] = importedPeer
                prefs[getProfileKey(VK_HASHES, profile)] = item.optString("vkHashes")
                prefs[getProfileKey(SECONDARY_VK_HASH, profile)] = item.optString("secondaryVkHash")
                prefs[getProfileKey(VK_HASH_NEXT_SLOT, profile)] = 0
                prefs.remove(getProfileKey(EXCLUDED_APPS, profile))
                prefs[getProfileKey(WORKERS_PER_HASH, profile)] = item.optInt("workersPerHash", 18).coerceIn(1, 128)
                val importedProfileMaxWorkers = item.optInt("profileMaxWorkers", 0)
                if (
                    importedProfileMaxWorkers in TUNNEL_WORKERS_PER_GROUP..APP_MAX_WORKERS &&
                    importedProfileMaxWorkers % TUNNEL_WORKERS_PER_GROUP == 0
                ) {
                    prefs[getProfileKey(PROFILE_MAX_WORKERS, profile)] = importedProfileMaxWorkers
                } else {
                    prefs.remove(getProfileKey(PROFILE_MAX_WORKERS, profile))
                }
                prefs[getProfileKey(PROTOCOL, profile)] = item.optString("protocol", "udp").takeIf { it in setOf("udp", "tcp") } ?: "udp"
                prefs[getProfileKey(LISTEN_PORT, profile)] = item.safePort("listenPort", 9000)
                prefs[getProfileKey(MANUAL_PORTS_ENABLED, profile)] = item.optBoolean("manualPortsEnabled")
                prefs[getProfileKey(SERVER_DTLS_PORT, profile)] = item.safePort("serverDtlsPort", 56000)
                prefs[getProfileKey(SERVER_WG_PORT, profile)] = item.safePort("serverWgPort", 56001)
                prefs[getProfileKey(SNI, profile)] = item.optString("sni")
                prefs[getProfileKey(NO_DTLS, profile)] = item.optBoolean("noDtls")
                prefs[getProfileKey(NO_DNS, profile)] = item.optBoolean("noDns")
                val importedVpnDnsSelection = normalizeVpnDnsSelectionId(
                    item.optString("vpnDnsSelection", VPN_DNS_PROFILE_ID)
                )
                val importedVpnDnsCustom = decodeStoredCustomVpnDnsServers(
                    item.optString("vpnDnsCustom")
                )
                prefs[getProfileKey(VPN_DNS_SELECTION, profile)] =
                    if (
                        importedVpnDnsSelection == VPN_DNS_CUSTOM_ID &&
                        importedVpnDnsCustom.isEmpty()
                    ) {
                        VPN_DNS_PROFILE_ID
                    } else {
                        importedVpnDnsSelection
                    }
                if (importedVpnDnsCustom.isEmpty()) {
                    prefs.remove(getProfileKey(VPN_DNS_CUSTOM, profile))
                } else {
                    prefs[getProfileKey(VPN_DNS_CUSTOM, profile)] =
                        importedVpnDnsCustom.joinToString(",")
                }
                prefs[getProfileKey(USER_AGENT, profile)] = item.optString("userAgent")
                prefs.putSecret(
                    CONNECTION_PASSWORD_ENCRYPTED,
                    CONNECTION_PASSWORD,
                    importedConnectionPassword,
                    profile
                )
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
                prefs[getProfileKey(RT_NETWORK, profile)] = item.optBoolean("rtNetwork", false)
                prefs[getProfileKey(RT_MASQUE, profile)] = item.optBoolean("rtMasque", false)
                prefs[getProfileKey(RT_MASQUE_SERVER_BOOTSTRAP, profile)] =
                    item.optBoolean("rtMasqueServerBootstrap", false)
                prefs[getProfileKey(RT_TURN_SNI, profile)] =
                    item.optString("rtTurnSni", DEFAULT_RT_TURN_SNI)
                prefs[getProfileKey(CAPTCHA_MODE, profile)] = item.optString("captchaMode", "auto")
                prefs[getProfileKey(CAPTCHA_SOLVE_METHOD, profile)] = item.optString("captchaSolveMethod", "auto")
                prefs[getProfileKey(CAPTCHA_WBV_SOLVE_METHOD, profile)] = item.optString("captchaWbvSolveMethod", "auto")
                prefs[getProfileKey(IS_WHITELIST, profile)] = item.optBoolean("isWhitelist")
                prefs[getProfileKey(BLACKLIST_APPS, profile)] = sanitizeVpnRoutingPackages(
                    decodeStoredVpnPackages(item.optString("blacklistApps")),
                    appContext.packageName,
                ).joinToString(",")
                prefs[getProfileKey(WHITELIST_APPS, profile)] = sanitizeVpnRoutingPackages(
                    decodeStoredVpnPackages(item.optString("whitelistApps")),
                    appContext.packageName,
                ).joinToString(",")
                prefs[getProfileKey(BLACKLIST_ADDRESSES, profile)] =
                    importedVpnAddressRules(item, "blacklistAddresses")
                prefs[getProfileKey(WHITELIST_ADDRESSES, profile)] =
                    importedVpnAddressRules(item, "whitelistAddresses")
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
        activeProfileOverride.value = null
        importSharedPreferences("wdtt_outbound_forms", root.optJSONObject("outbound") ?: JSONObject())
    }

    suspend fun applyWdttDeepLink(
        plan: WdttDeepLinkApplyPlan,
        resetRemoteContinuation: Boolean = false,
        profileMaxWorkers: Int? = null,
        remoteManaged: Boolean? = null,
        preserveVkHashes: Boolean = false,
    ): WdttDeepLinkApplyResult? {
        val parts = WdttDeepLink.parse(plan.link, allowMissingHashes = true) ?: return null
        val profile = plan.targetProfile.coerceIn(0, VPN_PROFILE_COUNT - 1)
        dataStore.edit { prefs ->
            if (prefs.protectsRemoteProfileFromReplacement(profile)) {
                throw IllegalStateException(
                    "Действующий готовый профиль нельзя заменить другим подключением."
                )
            }
            prefs.applyWdttDeepLinkParts(
                plan = plan,
                parts = parts,
                profile = profile,
                resetRemoteContinuation = resetRemoteContinuation,
                profileMaxWorkers = profileMaxWorkers,
                remoteManaged = remoteManaged,
                preserveVkHashes = preserveVkHashes,
            )
        }
        return WdttDeepLinkApplyResult(
            targetProfile = profile,
            overwritten = plan.requiresConfirmation,
            storedAsLink = plan.storeAsLink
        )
    }

    suspend fun reconcileRemoteProfileWorkerLimit(profileIndex: Int? = null) {
        dataStore.edit { prefs ->
            val profile = (profileIndex ?: prefs[ACTIVE_PROFILE] ?: 0)
                .coerceIn(0, VPN_PROFILE_COUNT - 1)
            val seenKey = getProfileKey(PROFILE_WORKER_LIMIT_SEEN, profile)
            val remoteManaged = prefs[getProfileKey(REMOTE_MANAGED_PROFILE, profile)] == true
            val currentLimit = prefs[getProfileKey(PROFILE_MAX_WORKERS, profile)] ?: 0
            if (
                !remoteManaged ||
                currentLimit !in TUNNEL_WORKERS_PER_GROUP..APP_MAX_WORKERS ||
                currentLimit % TUNNEL_WORKERS_PER_GROUP != 0
            ) {
                prefs.remove(seenKey)
                return@edit
            }
            val workersKey = getProfileKey(WORKERS_PER_HASH, profile)
            prefs[workersKey] = reconcileTunnelWorkerCountForProfileLimit(
                selectedWorkers = prefs[workersKey] ?: 18,
                previousProfileMaxWorkers = prefs[seenKey],
                currentProfileMaxWorkers = currentLimit,
                remoteManaged = true,
            )
            prefs[seenKey] = currentLimit
        }
    }

    /**
     * Applies a remote profile document as one DataStore transaction.
     *
     * A remote import changes the tunnel, protected capabilities, lifecycle status and UI role
     * together. Publishing each part separately makes Compose rebuild the whole Tunnel tab
     * several times and briefly exposes incomplete combinations of those values.
     */
    suspend fun applyRemoteDocumentDelivery(
        plan: WdttDeepLinkApplyPlan,
        delivery: RemoteDocumentDelivery,
        isBoundUpdate: Boolean,
        existingProfileRedelivery: Boolean = false,
    ): WdttDeepLinkApplyResult? {
        val parts = WdttDeepLink.parse(
            plan.link,
            allowMissingHashes = true,
            allowOmittedConnection = isBoundUpdate && delivery.kind == RemoteDocumentKind.UPDATE,
        ) ?: return null
        val profile = plan.targetProfile.coerceIn(0, VPN_PROFILE_COUNT - 1)
        var alreadyApplied = false
        dataStore.edit { prefs ->
            if (
                !isBoundUpdate &&
                !existingProfileRedelivery &&
                prefs.protectsRemoteProfileFromReplacement(profile)
            ) {
                throw IllegalStateException(
                    "Действующий готовый профиль нельзя заменить другим подключением."
                )
            }
            if (
                isBoundUpdate &&
                delivery.profileRevision > 0 &&
                (prefs[getProfileKey(ACCESS_PROFILE_REVISION, profile)] ?: 0L) >=
                    delivery.profileRevision
            ) {
                alreadyApplied = true
                return@edit
            }
            val preserveExistingValues = delivery.shouldPreserveLocalVkHashes(
                existingProfileRedelivery = existingProfileRedelivery,
            )
            val existingProfileValues = if (preserveExistingValues) {
                existingProfileValuesForRemoteAttachment(
                    linkMode = prefs[getProfileKey(WDTT_LINK_MODE, profile)] == true,
                    storedLink = prefs[getProfileKey(WDTT_LINK, profile)].orEmpty(),
                    manualValues = prefs[getProfileKey(VK_HASHES, profile)].orEmpty(),
                )
            } else {
                ""
            }
            val preserveConnectionSettings =
                shouldPreserveConnectionSettingsForRemoteUpdate(
                    isBoundUpdate = isBoundUpdate,
                    remoteManaged =
                        prefs[getProfileKey(REMOTE_MANAGED_PROFILE, profile)] == true,
                    incomingHost = parts.host,
                    incomingPassword = parts.password,
                )
            prefs.applyWdttDeepLinkParts(
                plan = plan,
                parts = parts,
                profile = profile,
                resetRemoteContinuation = !isBoundUpdate,
                profileMaxWorkers = delivery.profileMaxWorkers,
                remoteManaged = if (isBoundUpdate) null else true,
                preserveVkHashes = preserveExistingValues,
                preserveConnectionSettings = preserveConnectionSettings,
                activateProfile = !shouldRestoreUiAfterBoundUpdate(isBoundUpdate),
            )
            if (
                preserveConnectionSettings &&
                prefs[getProfileKey(WDTT_LINK_MODE, profile)] != true &&
                prefs[getProfileKey(CONNECTION_INPUT_METHOD, profile)] == "link"
            ) {
                prefs[getProfileKey(CONNECTION_INPUT_METHOD, profile)] = "manual"
            }
            if (preserveExistingValues && existingProfileValues.isNotBlank()) {
                prefs[getProfileKey(VK_HASHES, profile)] = existingProfileValues
                prefs[getProfileKey(SECONDARY_VK_HASH, profile)] = ""
            }
            if (prefs[INTERFACE_ROLE].isNullOrBlank()) {
                prefs[INTERFACE_ROLE] = "user"
                if (!prefs.contains(PERMISSION_ONBOARDING_COMPLETE)) {
                    prefs[PERMISSION_ONBOARDING_COMPLETE] = false
                }
            }
            if (delivery.access.available) {
                prefs.putRemoteAccessCapability(delivery.access, profile)
                if (
                    existingProfileRedelivery &&
                    existingProfileValues.isNotBlank() &&
                    delivery.access.exchange.submitAvailable &&
                    delivery.access.exchange.submitToken.isNotBlank()
                ) {
                    prefs[getProfileKey(PROFILE_VALUES_SYNC_PENDING, profile)] = true
                }
                delivery.access.initialStatus?.let { status ->
                    prefs.putAccessLifecycleStatus(profile, status)
                }
            }
            if (
                !isBoundUpdate &&
                (delivery.binding.isNotBlank() ||
                    delivery.continuation.available ||
                    delivery.access.available)
            ) {
                prefs.putRemoteContinuation(
                    continuation = delivery.continuation,
                    binding = delivery.binding,
                    profile = profile,
                )
            }
            if (
                isBoundUpdate &&
                delivery.profileRevision > 0
            ) {
                prefs[getProfileKey(ACCESS_PROFILE_REVISION, profile)] =
                    delivery.profileRevision
            }
        }
        return WdttDeepLinkApplyResult(
            targetProfile = profile,
            overwritten = plan.requiresConfirmation,
            storedAsLink = plan.storeAsLink,
            alreadyApplied = alreadyApplied,
        )
    }

    /** Stores a generic bound capability without taking ownership of the local connection. */
    suspend fun applyRemoteCapabilityAttachment(
        profileIndex: Int,
        delivery: RemoteDocumentDelivery,
    ): Boolean {
        if (
            delivery.kind != RemoteDocumentKind.ATTACHMENT ||
            delivery.binding.isBlank() ||
            !delivery.access.available ||
            !delivery.continuation.available
        ) {
            return false
        }
        val profile = profileIndex.coerceIn(0, VPN_PROFILE_COUNT - 1)
        dataStore.edit { prefs ->
            if (prefs.hasRemoteAttachment(profile)) {
                val existingBinding =
                    prefs[getProfileKey(REMOTE_DOCUMENT_BINDING, profile)].orEmpty()
                if (existingBinding != delivery.binding) {
                    if (!prefs.canReplaceRemoteAttachment(profile)) {
                        throw IllegalStateException(
                            "К этому профилю уже привязано другое удалённое разрешение."
                        )
                    }
                    prefs.clearRemoteCapabilityAttachment(profile)
                }
            }
            prefs[ACTIVE_PROFILE] = profile
            val existingValues = existingProfileValuesForRemoteAttachment(
                linkMode = prefs[getProfileKey(WDTT_LINK_MODE, profile)] == true,
                storedLink = prefs[getProfileKey(WDTT_LINK, profile)].orEmpty(),
                manualValues = prefs[getProfileKey(VK_HASHES, profile)].orEmpty(),
            )
            prefs.putRemoteAccessCapability(delivery.access, profile)
            delivery.access.initialStatus?.let { status ->
                prefs.putAccessLifecycleStatus(profile, status)
            }
            prefs.putRemoteContinuation(
                continuation = delivery.continuation,
                binding = delivery.binding,
                profile = profile,
            )
            if (
                existingValues.isNotBlank() &&
                delivery.access.exchange.submitAvailable &&
                delivery.access.exchange.submitToken.isNotBlank()
            ) {
                prefs[getProfileKey(PROFILE_VALUES_SYNC_PENDING, profile)] = true
            }
        }
        return true
    }

    private fun MutablePreferences.applyWdttDeepLinkParts(
        plan: WdttDeepLinkApplyPlan,
        parts: WdttLinkParts,
        profile: Int,
        resetRemoteContinuation: Boolean,
        profileMaxWorkers: Int?,
        remoteManaged: Boolean?,
        preserveVkHashes: Boolean,
        preserveConnectionSettings: Boolean = false,
        activateProfile: Boolean = true,
    ) {
        if (activateProfile) {
            this[ACTIVE_PROFILE] = profile
        }
        if (resetRemoteContinuation) {
            putSecret(
                REMOTE_ACTION_KEY_ENCRYPTED,
                REMOTE_ACTION_KEY,
                "",
                profile,
            )
            remove(getProfileKey(REMOTE_ACTION_URL, profile))
            remove(getProfileKey(REMOTE_DOCUMENT_BINDING, profile))
            remove(getProfileKey(REMOTE_MANAGED_PROFILE, profile))
            remove(getProfileKey(PROFILE_WORKER_LIMIT_SEEN, profile))
            clearAccessLifecycle(profile)
        }
        remoteManaged?.let { managed ->
            val key = getProfileKey(REMOTE_MANAGED_PROFILE, profile)
            if (managed) this[key] = true else remove(key)
        }
        val maxWorkersKey = getProfileKey(PROFILE_MAX_WORKERS, profile)
        val seenLimitKey = getProfileKey(PROFILE_WORKER_LIMIT_SEEN, profile)
        val selectedWorkersKey = getProfileKey(WORKERS_PER_HASH, profile)
        val previousLimit = this[seenLimitKey] ?: this[maxWorkersKey]
        val requestedLimit = profileMaxWorkers
            ?.takeIf { it >= TUNNEL_WORKERS_PER_GROUP }
            ?: parts.maxWorkers
        val normalizedLimit = ((requestedLimit / TUNNEL_WORKERS_PER_GROUP) *
            TUNNEL_WORKERS_PER_GROUP).coerceAtMost(APP_MAX_WORKERS)
        if (normalizedLimit >= TUNNEL_WORKERS_PER_GROUP) {
            this[maxWorkersKey] = normalizedLimit
            val managed = this[getProfileKey(REMOTE_MANAGED_PROFILE, profile)] == true
            if (managed) {
                this[selectedWorkersKey] = if (remoteManaged == true) {
                    normalizedLimit
                } else {
                    reconcileTunnelWorkerCountForProfileLimit(
                        selectedWorkers = this[selectedWorkersKey] ?: 18,
                        previousProfileMaxWorkers = previousLimit,
                        currentProfileMaxWorkers = normalizedLimit,
                        remoteManaged = true,
                    )
                }
                this[seenLimitKey] = normalizedLimit
            } else {
                remove(seenLimitKey)
            }
        } else {
            remove(maxWorkersKey)
            remove(seenLimitKey)
        }
        if (!preserveConnectionSettings) {
            val importedProfileName = vpnProfileRestorableName(parts.profileName)
            if (importedProfileName.isNotBlank()) {
                this[getProfileKey(PROFILE_NAME, profile)] = importedProfileName
            }
            this[getProfileKey(WDTT_LINK_MODE, profile)] = plan.storeAsLink
            // A parsed wdtt:// import is still a link-originated connection even when its
            // sensitive fields are materialized separately instead of keeping the raw link.
            this[getProfileKey(CONNECTION_INPUT_METHOD, profile)] = "link"
            if (plan.storeAsLink) {
                this[getProfileKey(WDTT_LINK, profile)] = plan.link
                clearManualTunnelFields(profile)
            } else {
                remove(getProfileKey(WDTT_LINK, profile))
                this[getProfileKey(PEER, profile)] = parts.host
                this[getProfileKey(SERVER_DTLS_PORT, profile)] = parts.dtlsPort
                this[getProfileKey(SERVER_WG_PORT, profile)] = parts.wgPort
                this[getProfileKey(LISTEN_PORT, profile)] = parts.localPort
                putSecret(CONNECTION_PASSWORD_ENCRYPTED, CONNECTION_PASSWORD, parts.password, profile)
                this[getProfileKey(MANUAL_PORTS_ENABLED, profile)] = parts.hasNonStandardPorts()
            }
        }
        if (!preserveVkHashes) {
            this[getProfileKey(VK_HASHES, profile)] = parts.hashes
            this[getProfileKey(SECONDARY_VK_HASH, profile)] = ""
        }
    }

    suspend fun saveWdttLinkMode(enabled: Boolean) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(WDTT_LINK_MODE, profile)] = enabled
        }
    }

    suspend fun materializeActiveLinkProfile(): WdttLinkParts? {
        val snapshot = dataStore.data.first()
        val profile = (snapshot[ACTIVE_PROFILE] ?: 0).coerceIn(0, VPN_PROFILE_COUNT - 1)
        if (snapshot[getProfileKey(WDTT_LINK_MODE, profile)] != true) return null
        val storedLink = snapshot[getProfileKey(WDTT_LINK, profile)].orEmpty()
        val parts = WdttDeepLink.parse(storedLink, allowMissingHashes = true) ?: return null
        var applied = false
        dataStore.edit { prefs ->
            if (
                (prefs[ACTIVE_PROFILE] ?: 0) != profile ||
                prefs[getProfileKey(WDTT_LINK, profile)].orEmpty() != storedLink
            ) {
                return@edit
            }
            prefs[getProfileKey(WDTT_LINK_MODE, profile)] = false
            prefs[getProfileKey(CONNECTION_INPUT_METHOD, profile)] = "link"
            prefs.remove(getProfileKey(WDTT_LINK, profile))
            prefs[getProfileKey(PEER, profile)] = parts.host
            prefs[getProfileKey(SERVER_DTLS_PORT, profile)] = parts.dtlsPort
            prefs[getProfileKey(SERVER_WG_PORT, profile)] = parts.wgPort
            prefs[getProfileKey(LISTEN_PORT, profile)] = parts.localPort
            prefs.putSecret(CONNECTION_PASSWORD_ENCRYPTED, CONNECTION_PASSWORD, parts.password, profile)
            prefs[getProfileKey(VK_HASHES, profile)] = parts.hashes
            prefs[getProfileKey(SECONDARY_VK_HASH, profile)] = ""
            prefs[getProfileKey(MANUAL_PORTS_ENABLED, profile)] = parts.hasNonStandardPorts()
            if (parts.maxWorkers >= TUNNEL_WORKERS_PER_GROUP) {
                prefs[getProfileKey(PROFILE_MAX_WORKERS, profile)] =
                    parts.maxWorkers.coerceAtMost(APP_MAX_WORKERS)
            }
            val importedProfileName = vpnProfileRestorableName(parts.profileName)
            if (importedProfileName.isNotBlank()) {
                prefs[getProfileKey(PROFILE_NAME, profile)] = importedProfileName
            }
            applied = true
        }
        return parts.takeIf { applied }
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

    suspend fun applyImportedServerConnection(
        profileIndex: Int,
        host: String,
        connectionPassword: String,
        dtlsPort: Int,
        wgPort: Int,
        ownerProfile: ServerAdminProfileInfo
    ) {
        val profile = profileIndex.coerceIn(0, VPN_PROFILE_COUNT - 1)
        require(host.isNotBlank()) { "Адрес импортированного сервера пустой." }
        require(connectionPassword.isNotBlank()) { "Главный пароль импортированного сервера пустой." }
        require(dtlsPort in 1..65535 && wgPort in 1..65535 && ownerProfile.listenPort in 1..65535) {
            "В импортированном профиле указаны некорректные порты."
        }
        val importedVpnDnsSelection = normalizeVpnDnsSelectionId(ownerProfile.vpnDnsSelectionId)
        val importedVpnDnsCustom = ownerProfile.vpnDnsCustomServers
            .joinToString(",")
            .let(::decodeStoredCustomVpnDnsServers)
        val effectiveVpnDnsSelection = if (
            importedVpnDnsSelection == VPN_DNS_CUSTOM_ID && importedVpnDnsCustom.isEmpty()
        ) {
            VPN_DNS_PROFILE_ID
        } else {
            importedVpnDnsSelection
        }
        dataStore.edit { prefs ->
            prefs[getProfileKey(WDTT_LINK_MODE, profile)] = false
            prefs.remove(getProfileKey(WDTT_LINK, profile))
            prefs[getProfileKey(CONNECTION_INPUT_METHOD, profile)] = "manual"
            prefs[getProfileKey(PEER, profile)] = host.trim()
            prefs.putSecret(
                CONNECTION_PASSWORD_ENCRYPTED,
                CONNECTION_PASSWORD,
                connectionPassword,
                profile
            )
            prefs[getProfileKey(VK_HASHES, profile)] = ownerProfile.vkHashes.trim()
            prefs[getProfileKey(SECONDARY_VK_HASH, profile)] = ownerProfile.secondaryVkHash.trim()
            prefs[getProfileKey(WORKERS_PER_HASH, profile)] = ownerProfile.workersPerHash.coerceIn(1, 128)
            prefs[getProfileKey(PROTOCOL, profile)] =
                ownerProfile.protocol.trim().lowercase().takeIf { it == "udp" || it == "tcp" } ?: "udp"
            prefs[getProfileKey(LISTEN_PORT, profile)] = ownerProfile.listenPort
            prefs[getProfileKey(SERVER_DTLS_PORT, profile)] = dtlsPort
            prefs[getProfileKey(SERVER_WG_PORT, profile)] = wgPort
            prefs[getProfileKey(MANUAL_PORTS_ENABLED, profile)] =
                dtlsPort != 56000 || wgPort != 56001 || ownerProfile.listenPort != 9000
            prefs[getProfileKey(SNI, profile)] = ownerProfile.sni.trim()
            prefs[getProfileKey(NO_DNS, profile)] = ownerProfile.noDns
            if (ownerProfile.vpnDnsStored) {
                prefs[getProfileKey(VPN_DNS_SELECTION, profile)] = effectiveVpnDnsSelection
                if (importedVpnDnsCustom.isEmpty()) {
                    prefs.remove(getProfileKey(VPN_DNS_CUSTOM, profile))
                } else {
                    prefs[getProfileKey(VPN_DNS_CUSTOM, profile)] =
                        importedVpnDnsCustom.joinToString(",")
                }
            }
            vpnProfileRestorableName(ownerProfile.profileName)
                .takeIf { it.isNotBlank() }
                ?.let { prefs[getProfileKey(PROFILE_NAME, profile)] = it }
        }
    }

    suspend fun saveWorkersPerHash(workersPerHash: Int) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(WORKERS_PER_HASH, profile)] = workersPerHash.coerceIn(1, 128)
        }
    }

    suspend fun saveRemoteContinuation(
        continuation: RemoteContinuation,
        binding: String,
        profileIndex: Int? = null
    ) {
        dataStore.edit { prefs ->
            val profile = (profileIndex ?: prefs[ACTIVE_PROFILE] ?: 0)
                .coerceIn(0, VPN_PROFILE_COUNT - 1)
            prefs.putRemoteContinuation(continuation, binding, profile)
        }
    }

    suspend fun saveRemoteAccessCapability(
        capability: RemoteAccessCapability,
        profileIndex: Int,
    ) {
        if (!capability.available) return
        val profile = profileIndex.coerceIn(0, VPN_PROFILE_COUNT - 1)
        dataStore.edit { prefs ->
            prefs.putRemoteAccessCapability(capability, profile)
        }
    }

    suspend fun accessLifecycleForProfile(profileIndex: Int): StoredAccessLifecycle {
        val profile = profileIndex.coerceIn(0, VPN_PROFILE_COUNT - 1)
        return preferencesFlow.map { prefs ->
            readStoredAccessLifecycle(prefs, profile)
        }.first()
    }

    suspend fun accessLifecycleProfiles(): List<Int> = preferencesFlow.map { prefs ->
        (0 until VPN_PROFILE_COUNT).filter { profile ->
            readStoredAccessLifecycle(prefs, profile).capability.available
        }
    }.first()

    suspend fun saveAccessLifecycleAttempt(profileIndex: Int, attemptedAtMillis: Long) {
        val profile = profileIndex.coerceIn(0, VPN_PROFILE_COUNT - 1)
        dataStore.edit { prefs ->
            prefs[getProfileKey(ACCESS_LAST_ATTEMPT_AT, profile)] =
                attemptedAtMillis.coerceAtLeast(0)
        }
    }

    suspend fun saveAccessLifecycleStatus(
        profileIndex: Int,
        status: AccessLifecycleStatus,
        expectedCapability: RemoteAccessCapability? = null,
    ): Boolean {
        val profile = profileIndex.coerceIn(0, VPN_PROFILE_COUNT - 1)
        var saved = false
        dataStore.edit { prefs ->
            if (
                expectedCapability != null &&
                readStoredAccessLifecycle(prefs, profile).capability != expectedCapability
            ) {
                return@edit
            }
            prefs.putAccessLifecycleStatus(profile, status)
            saved = true
        }
        return saved
    }

    suspend fun markAccessLifecycleDenied(profileIndex: Int) {
        val profile = profileIndex.coerceIn(0, VPN_PROFILE_COUNT - 1)
        dataStore.edit { prefs ->
            if (prefs[getProfileKey(ACCESS_LIFECYCLE_URL, profile)].isNullOrBlank()) return@edit
            prefs[getProfileKey(ACCESS_ALLOW_CONNECT, profile)] = false
            prefs[getProfileKey(ACCESS_TITLE, profile)] = "Профиль недоступен"
            prefs[getProfileKey(ACCESS_MESSAGE, profile)] =
                "Откройте профиль, чтобы обновить его состояние."
            prefs[getProfileKey(ACCESS_SEVERITY, profile)] = "error"
            prefs[getProfileKey(ACCESS_CHECKED_AT, profile)] = System.currentTimeMillis()
        }
    }

    suspend fun saveAppliedAccessProfileRevision(profileIndex: Int, revision: Long) {
        val profile = profileIndex.coerceIn(0, VPN_PROFILE_COUNT - 1)
        dataStore.edit { prefs ->
            prefs[getProfileKey(ACCESS_PROFILE_REVISION, profile)] = revision.coerceAtLeast(0)
        }
    }

    suspend fun markAccessLifecycleActionLaunched(
        profileIndex: Int,
        launchedAtMillis: Long = System.currentTimeMillis(),
    ) {
        val profile = profileIndex.coerceIn(0, VPN_PROFILE_COUNT - 1)
        dataStore.edit { prefs ->
            prefs[getProfileKey(ACCESS_ACTION_LAUNCHED_AT, profile)] =
                launchedAtMillis.coerceAtLeast(0)
        }
    }

    suspend fun takeAccessLifecycleActionProfiles(): Set<Int> {
        val profiles = mutableSetOf<Int>()
        dataStore.edit { prefs ->
            repeat(VPN_PROFILE_COUNT) { profile ->
                val key = getProfileKey(ACCESS_ACTION_LAUNCHED_AT, profile)
                if ((prefs[key] ?: 0) > 0) profiles += profile
                prefs.remove(key)
            }
        }
        return profiles
    }

    suspend fun remoteBindingForProfile(profileIndex: Int): String {
        val profile = profileIndex.coerceIn(0, VPN_PROFILE_COUNT - 1)
        return preferencesFlow.map { prefs ->
            prefs[getProfileKey(REMOTE_DOCUMENT_BINDING, profile)].orEmpty()
        }.first()
    }

    suspend fun remoteAccessBindingForProfile(profileIndex: Int): String {
        val profile = profileIndex.coerceIn(0, VPN_PROFILE_COUNT - 1)
        return preferencesFlow.map { prefs ->
            prefs[getProfileKey(ACCESS_LIFECYCLE_BINDING, profile)].orEmpty()
        }.first()
    }

    suspend fun remoteDocumentBindings(): List<String> =
        appContext.dataStore.data.map { prefs ->
            buildList {
                repeat(VPN_PROFILE_COUNT) { profile ->
                    add(prefs[getProfileKey(REMOTE_DOCUMENT_BINDING, profile)].orEmpty())
                    add(prefs[getProfileKey(ACCESS_LIFECYCLE_BINDING, profile)].orEmpty())
                }
            }
                .map(String::trim)
                .filter(String::isNotBlank)
                .distinct()
        }.first()

    suspend fun remoteContinuationForProfile(profileIndex: Int): RemoteContinuation {
        val profile = profileIndex.coerceIn(0, VPN_PROFILE_COUNT - 1)
        return appContext.dataStore.data.map { prefs ->
            val key = readSecret(
                prefs,
                REMOTE_ACTION_KEY_ENCRYPTED,
                REMOTE_ACTION_KEY,
                profile
            )
            val url = prefs[getProfileKey(REMOTE_ACTION_URL, profile)].orEmpty()
            RemoteContinuation(
                available = key.isNotBlank() && url.isNotBlank(),
                key = key,
                url = url
            )
        }.first()
    }

    suspend fun profileForRemoteBinding(binding: String): Int? {
        val expected = binding.trim()
        if (expected.isBlank()) return null
        return appContext.dataStore.data.map { prefs ->
            (0 until VPN_PROFILE_COUNT).firstOrNull { profile ->
                prefs[getProfileKey(REMOTE_DOCUMENT_BINDING, profile)] == expected ||
                    prefs[getProfileKey(ACCESS_LIFECYCLE_BINDING, profile)] == expected
            }
        }.first()
    }

    /**
     * Finds an already imported copy of the same connection when an optional setup-device
     * binding was rotated. The access password is unique to the connection; matching it together
     * with the remote endpoint avoids treating another profile on the same server as the same
     * connection.
     */
    suspend fun profileForConnectionDocument(document: String): Int? {
        val expected = WdttDeepLink.parse(document, allowMissingHashes = true) ?: return null
        if (expected.host.isBlank() || expected.password.isBlank()) return null
        return appContext.dataStore.data.map { prefs ->
            (0 until VPN_PROFILE_COUNT).firstOrNull { profile ->
                val stored = if (prefs[getProfileKey(WDTT_LINK_MODE, profile)] == true) {
                    WdttDeepLink.parse(
                        prefs[getProfileKey(WDTT_LINK, profile)].orEmpty(),
                        allowMissingHashes = true,
                    )
                } else {
                    null
                }
                val host = stored?.host
                    ?: prefs[getProfileKey(PEER, profile)].orEmpty().trim()
                val dtlsPort = stored?.dtlsPort
                    ?: prefs[getProfileKey(SERVER_DTLS_PORT, profile)] ?: 56000
                val wgPort = stored?.wgPort
                    ?: prefs[getProfileKey(SERVER_WG_PORT, profile)] ?: 56001
                val password = stored?.password
                    ?: readSecret(
                        prefs,
                        CONNECTION_PASSWORD_ENCRYPTED,
                        CONNECTION_PASSWORD,
                        profile,
                    )
                host.equals(expected.host, ignoreCase = true) &&
                    dtlsPort == expected.dtlsPort &&
                    wgPort == expected.wgPort &&
                    password == expected.password
            }
        }.first()
    }

    suspend fun saveVkHashesForProfile(profile: Int, hashes: List<String>) {
        val cleaned = hashes
            .map(VkJoinLink::extractHash)
            .filter(VkJoinLink::isValidHash)
            .distinct()
        require(cleaned.size in 1..4) { "Добавьте от 1 до 4 корректных VK-хешей." }
        dataStore.edit { prefs ->
            val safeProfile = profile.coerceIn(0, VPN_PROFILE_COUNT - 1)
            prefs[getProfileKey(VK_HASHES, safeProfile)] = cleaned.joinToString(",")
            prefs[getProfileKey(SECONDARY_VK_HASH, safeProfile)] = ""
            prefs[getProfileKey(PROFILE_VALUES_SYNC_PENDING, safeProfile)] = true
        }
    }

    suspend fun markProfileValuesSyncPending(profileIndex: Int) {
        val profile = profileIndex.coerceIn(0, VPN_PROFILE_COUNT - 1)
        dataStore.edit { prefs ->
            prefs[getProfileKey(PROFILE_VALUES_SYNC_PENDING, profile)] = true
        }
    }

    suspend fun clearProfileValuesSyncPending(profileIndex: Int) {
        val profile = profileIndex.coerceIn(0, VPN_PROFILE_COUNT - 1)
        dataStore.edit { prefs ->
            prefs.remove(getProfileKey(PROFILE_VALUES_SYNC_PENDING, profile))
        }
    }

    suspend fun profileValuesSyncPending(profileIndex: Int): Boolean {
        val profile = profileIndex.coerceIn(0, VPN_PROFILE_COUNT - 1)
        return preferencesFlow.map { prefs ->
            prefs[getProfileKey(PROFILE_VALUES_SYNC_PENDING, profile)] == true
        }.first()
    }

    suspend fun mergeVkHashesForProfile(profile: Int, hashes: List<String>): Int {
        val cleaned = hashes
            .map(VkJoinLink::extractHash)
            .filter(VkJoinLink::isValidHash)
            .distinct()
            .take(4)
        if (cleaned.isEmpty()) return 0
        var added = 0
        dataStore.edit { prefs ->
            val safeProfile = profile.coerceIn(0, VPN_PROFILE_COUNT - 1)
            val key = getProfileKey(VK_HASHES, safeProfile)
            val slots = parseVkHashSlots(prefs[key].orEmpty())
            cleaned.forEach { hash ->
                if (hash !in slots) {
                    val empty = slots.indexOfFirst { it.isBlank() }
                    if (empty >= 0) {
                        slots[empty] = hash
                        added += 1
                    }
                }
            }
            if (added > 0) {
                prefs[key] = slots.joinToString(",")
                prefs[getProfileKey(SECONDARY_VK_HASH, safeProfile)] = ""
            }
        }
        return added
    }

    suspend fun getOrCreateConnectDeviceId(): String {
        preferencesFlow.first()[CONNECT_DEVICE_ID]
            ?.trim()
            ?.takeIf(DeviceIdentity::valid)
            ?.let { return it }
        val tunnelDeviceId = getOrCreateTunnelDeviceId()
        var resolved = ""
        dataStore.edit { prefs ->
            resolved = DeviceIdentity.resolve(
                existing = prefs[CONNECT_DEVICE_ID],
                platformId = tunnelDeviceId,
                generatedId = "android-${UUID.randomUUID()}",
            )
            prefs[CONNECT_DEVICE_ID] = resolved
        }
        return resolved
    }

    suspend fun getOrCreateTunnelDeviceId(): String {
        preferencesFlow.first()[TUNNEL_DEVICE_ID]
            ?.trim()
            ?.takeIf(DeviceIdentity::valid)
            ?.let { return it }
        val platformId = android.provider.Settings.Secure.getString(
            appContext.contentResolver,
            android.provider.Settings.Secure.ANDROID_ID,
        )
        var resolved = ""
        dataStore.edit { prefs ->
            resolved = DeviceIdentity.resolve(
                existing = prefs[TUNNEL_DEVICE_ID],
                platformId = platformId,
                generatedId = "android-${UUID.randomUUID()}",
            )
            prefs[TUNNEL_DEVICE_ID] = resolved
        }
        return resolved
    }

    suspend fun insertVkHashFromShare(hash: String): VkHashInsertResult {
        val cleanedHash = VkJoinLink.extractHash(hash)
        require(VkJoinLink.isValidHash(cleanedHash)) { "VK-хеш имеет неверный формат" }
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
            prefs[getProfileKey(PROFILE_VALUES_SYNC_PENDING, profile)] = true
            result = VkHashInsertResult(
                slot = slotIndex + 1,
                hash = cleanedHash,
                previousHash = previous,
                profile = profile,
                hashes = slots.filter { it.isNotBlank() },
            )
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
            .map { VkJoinLink.extractValidHash(it) }
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

    suspend fun toggleVpnAppSelected(
        packageName: String,
        whitelist: Boolean,
        profileIndex: Int? = null,
    ) {
        val normalizedPackage = packageName.trim()
        require(
            normalizedPackage.isNotEmpty() &&
                ',' !in normalizedPackage &&
                !isAlwaysBypassedVpnPackage(normalizedPackage, appContext.packageName)
        ) { "Это приложение нельзя добавить в список маршрутизации." }
        dataStore.edit { prefs ->
            val profile = profileIndex?.coerceIn(0, VPN_PROFILE_COUNT - 1)
                ?: (prefs[ACTIVE_PROFILE] ?: 0).coerceIn(0, VPN_PROFILE_COUNT - 1)
            val key = getProfileKey(if (whitelist) WHITELIST_APPS else BLACKLIST_APPS, profile)
            val packages = sanitizeVpnRoutingPackages(
                decodeStoredVpnPackages(prefs[key].orEmpty()),
                appContext.packageName,
            ).toMutableSet()
            if (!packages.add(normalizedPackage)) packages.remove(normalizedPackage)
            prefs[key] = packages.sorted().joinToString(",")
        }
    }

    suspend fun addBlacklistPackages(
        newPackages: Set<String>,
        profileIndex: Int? = null,
    ): Int {
        var addedCount = 0
        dataStore.edit { prefs ->
            val profile = profileIndex?.coerceIn(0, VPN_PROFILE_COUNT - 1)
                ?: (prefs[ACTIVE_PROFILE] ?: 0).coerceIn(0, VPN_PROFILE_COUNT - 1)
            val key = getProfileKey(BLACKLIST_APPS, profile)
            val packages = sanitizeVpnRoutingPackages(
                decodeStoredVpnPackages(prefs[key].orEmpty()),
                appContext.packageName,
            ).toMutableSet()
            val before = packages.size
            packages.addAll(sanitizeVpnRoutingPackages(newPackages, appContext.packageName))
            addedCount = packages.size - before
            prefs[key] = packages.sorted().joinToString(",")
        }
        return addedCount
    }

    internal suspend fun addVpnAddressRules(
        rawValue: String,
        whitelist: Boolean,
        profileIndex: Int? = null,
    ): List<VpnAddressRule> {
        val normalized = normalizeVpnAddressRules(rawValue)
        dataStore.edit { prefs ->
            val profile = profileIndex?.coerceIn(0, VPN_PROFILE_COUNT - 1)
                ?: (prefs[ACTIVE_PROFILE] ?: 0).coerceIn(0, VPN_PROFILE_COUNT - 1)
            val key = getProfileKey(
                if (whitelist) WHITELIST_ADDRESSES else BLACKLIST_ADDRESSES,
                profile,
            )
            val rules = decodeVpnAddressRules(prefs[key].orEmpty()).toMutableList()
            val newRules = normalized.filterNot(rules::contains)
            if (newRules.isNotEmpty()) {
                require(rules.size + newRules.size <= MAX_VPN_ADDRESS_RULES) {
                    "В одном списке может быть не больше $MAX_VPN_ADDRESS_RULES адресов."
                }
                rules += newRules
                prefs[key] = encodeVpnAddressRules(rules)
            }
        }
        return normalized
    }

    internal suspend fun removeVpnAddressRule(
        rule: VpnAddressRule,
        whitelist: Boolean,
        profileIndex: Int? = null,
    ) {
        dataStore.edit { prefs ->
            val profile = profileIndex?.coerceIn(0, VPN_PROFILE_COUNT - 1)
                ?: (prefs[ACTIVE_PROFILE] ?: 0).coerceIn(0, VPN_PROFILE_COUNT - 1)
            val key = getProfileKey(
                if (whitelist) WHITELIST_ADDRESSES else BLACKLIST_ADDRESSES,
                profile,
            )
            val rules = decodeVpnAddressRules(prefs[key].orEmpty()).filterNot { it == rule }
            prefs[key] = encodeVpnAddressRules(rules)
        }
    }

    suspend fun exportVpnRoutingSettings(profileIndex: Int? = null): String = preferencesFlow.map { prefs ->
        val profile = profileIndex?.coerceIn(0, VPN_PROFILE_COUNT - 1)
            ?: (prefs[ACTIVE_PROFILE] ?: 0).coerceIn(0, VPN_PROFILE_COUNT - 1)
        encodeVpnRoutingDocument(
            VpnRoutingDocument(
                isWhitelist = prefs[getProfileKey(IS_WHITELIST, profile)] ?: false,
                blacklistApps = sanitizeVpnRoutingPackages(
                    decodeStoredVpnPackages(prefs[getProfileKey(BLACKLIST_APPS, profile)].orEmpty()),
                    appContext.packageName,
                ),
                whitelistApps = sanitizeVpnRoutingPackages(
                    decodeStoredVpnPackages(prefs[getProfileKey(WHITELIST_APPS, profile)].orEmpty()),
                    appContext.packageName,
                ),
                blacklistAddresses = decodeVpnAddressRules(
                    prefs[getProfileKey(BLACKLIST_ADDRESSES, profile)].orEmpty()
                ),
                whitelistAddresses = decodeVpnAddressRules(
                    prefs[getProfileKey(WHITELIST_ADDRESSES, profile)].orEmpty()
                ),
            )
        )
    }.first()

    internal suspend fun importVpnRoutingSettings(
        settingsJson: String,
        profileIndex: Int? = null,
    ): VpnRoutingImportResult {
        val imported = decodeVpnRoutingDocument(settingsJson)
        val document = imported.copy(
            blacklistApps = sanitizeVpnRoutingPackages(
                imported.blacklistApps,
                appContext.packageName,
            ),
            whitelistApps = sanitizeVpnRoutingPackages(
                imported.whitelistApps,
                appContext.packageName,
            ),
        )

        dataStore.edit { prefs ->
            val profile = profileIndex?.coerceIn(0, VPN_PROFILE_COUNT - 1)
                ?: (prefs[ACTIVE_PROFILE] ?: 0).coerceIn(0, VPN_PROFILE_COUNT - 1)
            prefs[getProfileKey(IS_WHITELIST, profile)] = document.isWhitelist
            prefs[getProfileKey(BLACKLIST_APPS, profile)] = document.blacklistApps.joinToString(",")
            prefs[getProfileKey(WHITELIST_APPS, profile)] = document.whitelistApps.joinToString(",")
            prefs[getProfileKey(BLACKLIST_ADDRESSES, profile)] =
                encodeVpnAddressRules(document.blacklistAddresses)
            prefs[getProfileKey(WHITELIST_ADDRESSES, profile)] =
                encodeVpnAddressRules(document.whitelistAddresses)
        }
        return VpnRoutingImportResult(
            blacklistAppCount = document.blacklistApps.size,
            whitelistAppCount = document.whitelistApps.size,
            blacklistAddressCount = document.blacklistAddresses.size,
            whitelistAddressCount = document.whitelistAddresses.size,
            isWhitelist = document.isWhitelist,
        )
    }

    internal suspend fun saveVpnDnsSettings(
        selectionId: String,
        customServersRaw: String = "",
        profileIndex: Int? = null,
    ): VpnDnsSettingsSnapshot {
        val selection = normalizeVpnDnsSelectionId(selectionId)
        require(selection == selectionId.trim().lowercase()) {
            "Неизвестный вариант DNS."
        }
        val customServers = if (selection == VPN_DNS_CUSTOM_ID) {
            normalizeCustomVpnDnsServers(customServersRaw)
        } else {
            decodeStoredCustomVpnDnsServers(customServersRaw)
        }
        var savedProfile = 0
        dataStore.edit { prefs ->
            savedProfile = profileIndex?.coerceIn(0, VPN_PROFILE_COUNT - 1)
                ?: (prefs[ACTIVE_PROFILE] ?: 0).coerceIn(0, VPN_PROFILE_COUNT - 1)
            prefs[getProfileKey(VPN_DNS_SELECTION, savedProfile)] = selection
            if (customServers.isEmpty()) {
                prefs.remove(getProfileKey(VPN_DNS_CUSTOM, savedProfile))
            } else {
                prefs[getProfileKey(VPN_DNS_CUSTOM, savedProfile)] =
                    customServers.joinToString(",")
            }
        }
        return VpnDnsSettingsSnapshot(
            profileIndex = savedProfile,
            selectionId = selection,
            customServers = customServers,
        )
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

    suspend fun saveManualTunnelConnection(
        peer: String,
        password: String,
        manualPortsEnabled: Boolean,
        serverDtlsPort: Int,
        serverWgPort: Int,
        listenPort: Int,
    ) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(WDTT_LINK_MODE, profile)] = false
            prefs[getProfileKey(CONNECTION_INPUT_METHOD, profile)] = "manual"
            prefs.remove(getProfileKey(WDTT_LINK, profile))
            prefs[getProfileKey(PEER, profile)] = peer.trim()
            prefs.putSecret(
                CONNECTION_PASSWORD_ENCRYPTED,
                CONNECTION_PASSWORD,
                password,
                profile
            )
            prefs[getProfileKey(MANUAL_PORTS_ENABLED, profile)] = manualPortsEnabled
            prefs[getProfileKey(SERVER_DTLS_PORT, profile)] = serverDtlsPort
            prefs[getProfileKey(SERVER_WG_PORT, profile)] = serverWgPort
            prefs[getProfileKey(LISTEN_PORT, profile)] = listenPort
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

    suspend fun saveRtNetwork(enabled: Boolean, turnSni: String? = null) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(RT_NETWORK, profile)] = enabled
            if (turnSni != null) {
                prefs[getProfileKey(RT_TURN_SNI, profile)] = turnSni
            }
        }
    }

    suspend fun saveRtMasque(enabled: Boolean) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(RT_MASQUE, profile)] = enabled
        }
    }

    suspend fun saveRtMasqueServerBootstrap(enabled: Boolean) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(RT_MASQUE_SERVER_BOOTSTRAP, profile)] =
                enabled && deploySshAccessStatus(prefs, profile).available
        }
    }

    internal suspend fun sshConnectionForProfile(profileIndex: Int): SshProfileConnection? {
        val profile = profileIndex.coerceIn(0, VPN_PROFILE_COUNT - 1)
        return preferencesFlow.map { prefs ->
            val host = prefs[getProfileKey(DEPLOY_IP, profile)].orEmpty().trim()
            val user = prefs[getProfileKey(DEPLOY_LOGIN, profile)].orEmpty().trim()
            val password = readSecret(
                prefs,
                DEPLOY_PASSWORD_ENCRYPTED,
                DEPLOY_PASSWORD,
                profile,
            )
            val privateKey = readSecret(
                prefs,
                DEPLOY_SSH_PRIVATE_KEY_ENCRYPTED,
                DEPLOY_SSH_PRIVATE_KEY,
                profile,
            )
            val privateKeyPassphrase = readSecret(
                prefs,
                DEPLOY_SSH_KEY_PASSPHRASE_ENCRYPTED,
                DEPLOY_SSH_KEY_PASSPHRASE,
                profile,
            )
            val mode = prefs[getProfileKey(DEPLOY_SSH_AUTH_MODE, profile)]
                ?.takeIf { it == "password" || it == "key" }
                ?: if (privateKey.isNotBlank()) "key" else "password"
            val credentials = sshCredentialsForMode(
                mode = mode,
                password = password,
                privateKey = privateKey,
                privateKeyPassphrase = privateKeyPassphrase,
            )
            val accessStatus = sshProfileAccessStatus(
                host = host,
                authMode = mode,
                password = password,
                privateKey = privateKey,
            )
            val port = prefs[getProfileKey(DEPLOY_SSH_PORT, profile)]
                ?.trim()
                ?.toIntOrNull()
                ?.takeIf { it in 1..65535 }
                ?: 22
            if (!accessStatus.available || !credentials.hasAuthentication) {
                null
            } else {
                SshProfileConnection(
                    host = host,
                    user = user,
                    credentials = credentials,
                    port = port,
                )
            }
        }.first()
    }

    suspend fun saveCaptchaMode(mode: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(CAPTCHA_MODE, profile)] = mode
        }
    }

    suspend fun saveCaptchaPreference(autoEnabled: Boolean) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            if (autoEnabled) {
                prefs[getProfileKey(CAPTCHA_MODE, profile)] = "auto"
                prefs[getProfileKey(CAPTCHA_SOLVE_METHOD, profile)] = "auto"
            } else {
                prefs[getProfileKey(CAPTCHA_MODE, profile)] = "wv"
                prefs[getProfileKey(CAPTCHA_SOLVE_METHOD, profile)] = "manual"
                prefs[getProfileKey(CAPTCHA_WBV_SOLVE_METHOD, profile)] = "manual"
            }
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
    suspend fun saveIsWhitelist(enabled: Boolean, profileIndex: Int? = null) {
        dataStore.edit { prefs ->
            val profile = profileIndex?.coerceIn(0, VPN_PROFILE_COUNT - 1)
                ?: (prefs[ACTIVE_PROFILE] ?: 0).coerceIn(0, VPN_PROFILE_COUNT - 1)
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
                prefs.migrateSecret(
                    getProfileKey(REMOTE_ACTION_KEY_ENCRYPTED, profile),
                    getProfileKey(REMOTE_ACTION_KEY, profile)
                )
                prefs.migrateSecret(
                    getProfileKey(CUSTOM_VK_CLIENT_SECRET_ENCRYPTED, profile),
                    getProfileKey(CUSTOM_VK_CLIENT_SECRET, profile)
                )
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
                if (legacyPackages.isNotBlank()) {
                    val targetBaseKey = if (prefs[getProfileKey(IS_WHITELIST, profile)] == true) {
                        WHITELIST_APPS
                    } else {
                        BLACKLIST_APPS
                    }
                    val targetKey = getProfileKey(targetBaseKey, profile)
                    if (prefs[targetKey] == null) {
                        prefs[targetKey] = sanitizeVpnRoutingPackages(
                            decodeStoredVpnPackages(legacyPackages),
                            appContext.packageName,
                        ).joinToString(",")
                    }
                }

                listOf(BLACKLIST_APPS, WHITELIST_APPS).forEach { baseKey ->
                    val key = getProfileKey(baseKey, profile)
                    val stored = prefs[key] ?: return@forEach
                    val sanitized = sanitizeVpnRoutingPackages(
                        decodeStoredVpnPackages(stored),
                        appContext.packageName,
                    ).joinToString(",")
                    if (stored != sanitized) prefs[key] = sanitized
                }
                if (prefs[legacyKey] != null) prefs.remove(legacyKey)
            }
        }
    }

    private suspend fun repairInvalidLinkModes() {
        dataStore.edit { prefs ->
            for (profile in 0 until VPN_PROFILE_COUNT) {
                val modeKey = getProfileKey(WDTT_LINK_MODE, profile)
                val storedLink = prefs[getProfileKey(WDTT_LINK, profile)].orEmpty()
                val hasStoredLink =
                    WdttDeepLink.parse(storedLink, allowMissingHashes = true) != null
                val hasManualConnection = prefs[getProfileKey(PEER, profile)].orEmpty().isNotBlank() &&
                    readSecret(
                        prefs,
                        CONNECTION_PASSWORD_ENCRYPTED,
                        CONNECTION_PASSWORD,
                        profile
                    ).isNotBlank()
                var linkMode = prefs[modeKey] == true
                if (linkMode && !hasStoredLink && hasManualConnection) {
                    prefs[modeKey] = false
                    linkMode = false
                }

                val methodKey = getProfileKey(CONNECTION_INPUT_METHOD, profile)
                if (prefs[methodKey] != "link" && prefs[methodKey] != "manual") {
                    when {
                        linkMode && hasStoredLink -> prefs[methodKey] = "link"
                        hasManualConnection -> prefs[methodKey] = "manual"
                        else -> prefs.remove(methodKey)
                    }
                }
            }
        }
    }

    private fun readAccessLifecycleUiState(
        prefs: Preferences,
        profile: Int,
    ): AccessLifecycleUiState = readStoredAccessLifecycle(prefs, profile).toUiState()

    private fun MutablePreferences.putRemoteContinuation(
        continuation: RemoteContinuation,
        binding: String,
        profile: Int,
    ) {
        putSecret(
            REMOTE_ACTION_KEY_ENCRYPTED,
            REMOTE_ACTION_KEY,
            continuation.key.trim(),
            profile,
        )
        this[getProfileKey(REMOTE_ACTION_URL, profile)] = continuation.url.trim()
        if (binding.isBlank()) {
            remove(getProfileKey(REMOTE_DOCUMENT_BINDING, profile))
        } else {
            this[getProfileKey(REMOTE_DOCUMENT_BINDING, profile)] = binding.trim()
        }
    }

    private fun MutablePreferences.putRemoteAccessCapability(
        capability: RemoteAccessCapability,
        profile: Int,
    ) {
        val previousKey = readProtectedSecret(
            this,
            ACCESS_LIFECYCLE_KEY_ENCRYPTED,
            profile,
        )
        val previousUrl = this[getProfileKey(ACCESS_LIFECYCLE_URL, profile)].orEmpty()
        val previousBinding =
            this[getProfileKey(ACCESS_LIFECYCLE_BINDING, profile)].orEmpty()
        if (
            previousKey != capability.key ||
            previousUrl != capability.url ||
            previousBinding != capability.binding
        ) {
            clearAccessLifecycleStatus(profile)
        }
        putProtectedSecret(
            ACCESS_LIFECYCLE_KEY_ENCRYPTED,
            capability.key.trim(),
            profile,
        )
        this[getProfileKey(ACCESS_LIFECYCLE_URL, profile)] = capability.url.trim()
        this[getProfileKey(ACCESS_LIFECYCLE_BINDING, profile)] = capability.binding.trim()
        putCachedRemoteAction(capability.cachedAction, profile)
        putProfileExchange(capability.exchange, profile)
    }

    private fun MutablePreferences.putCachedRemoteAction(
        action: CachedRemoteAction,
        profile: Int,
    ) {
        putProtectedSecret(
            CACHED_ACTION_PAYLOAD_ENCRYPTED,
            action.payload.takeIf { action.available }.orEmpty(),
            profile,
        )
        val values = listOf(
            kotlin.Pair(CACHED_ACTION_URL, action.target.primaryUrl),
            kotlin.Pair(CACHED_ACTION_FALLBACK, action.target.fallbackUrl),
            kotlin.Pair(CACHED_ACTION_HANDLER, action.target.preferredHandler),
            kotlin.Pair(CACHED_ACTION_TITLE, action.title),
            kotlin.Pair(CACHED_ACTION_MESSAGE, action.message),
            kotlin.Pair(CACHED_ACTION_LABEL, action.label),
            kotlin.Pair(CACHED_ACTION_CLIPBOARD_LABEL, action.clipboardLabel),
            kotlin.Pair(CACHED_ACTION_COPIED_MESSAGE, action.copiedMessage),
            kotlin.Pair(CACHED_ACTION_FAILED_MESSAGE, action.failedMessage),
            kotlin.Pair(CACHED_ACTION_HELP_TITLE, action.helpTitle),
            kotlin.Pair(CACHED_ACTION_HELP_INTRO, action.helpIntro),
            kotlin.Pair(CACHED_ACTION_HELP_STEPS, action.helpSteps),
        )
        values.forEach { (key, value) ->
            val profileKey = getProfileKey(key, profile)
            if (action.available && value.isNotBlank()) {
                this[profileKey] = value
            } else {
                remove(profileKey)
            }
        }
    }

    private fun MutablePreferences.putProfileExchange(
        exchange: RemoteProfileExchange,
        profile: Int,
    ) {
        putProtectedSecret(
            PROFILE_EXCHANGE_SUBMIT_TOKEN_ENCRYPTED,
            exchange.submitToken.takeIf { exchange.submitAvailable }.orEmpty(),
            profile,
        )
        putProtectedSecret(
            PROFILE_EXCHANGE_ACTION_TOKEN_ENCRYPTED,
            exchange.actionToken,
            profile,
        )
        this[getProfileKey(PROFILE_EXCHANGE_ACTION_AVAILABLE, profile)] =
            exchange.actionAvailable
        this[getProfileKey(PROFILE_EXCHANGE_ACTION_LABEL, profile)] = exchange.label
        this[getProfileKey(PROFILE_EXCHANGE_ACTION_MESSAGE, profile)] = exchange.message
    }

    private fun MutablePreferences.putAccessLifecycleStatus(
        profile: Int,
        status: AccessLifecycleStatus,
    ) {
        if (status.cachedAction.available) {
            putCachedRemoteAction(status.cachedAction, profile)
        }
        status.exchange?.let { putProfileExchange(it, profile) }
        this[getProfileKey(ACCESS_ALLOW_CONNECT, profile)] = status.allowConnect
        this[getProfileKey(ACCESS_CHECKED_AT, profile)] = status.checkedAtMillis.coerceAtLeast(0)
        this[getProfileKey(ACCESS_ACTION_AVAILABLE, profile)] = status.actionAvailable
        val continuationKey = getProfileKey(ACCESS_CONTINUATION_AVAILABLE, profile)
        status.continuationAvailable?.let { this[continuationKey] = it }
            ?: remove(continuationKey)
        val continuationExpiresKey = getProfileKey(ACCESS_CONTINUATION_EXPIRES_AT, profile)
        status.continuationExpiresAtSeconds?.let {
            this[continuationExpiresKey] = it.coerceAtLeast(0L)
        } ?: remove(continuationExpiresKey)
        val dismissibleKey = getProfileKey(ACCESS_DISMISSIBLE, profile)
        status.dismissible?.let { this[dismissibleKey] = it }
            ?: remove(dismissibleKey)
        this[getProfileKey(ACCESS_DISMISSED_MESSAGE, profile)] = status.dismissedMessage
        this[getProfileKey(ACCESS_ACTION_LABEL, profile)] = status.actionLabel
        this[getProfileKey(ACCESS_ACTION_MESSAGE, profile)] = status.actionMessage
        this[getProfileKey(ACCESS_TITLE, profile)] = status.title
        this[getProfileKey(ACCESS_MESSAGE, profile)] = status.message
        this[getProfileKey(ACCESS_DETAIL_LABEL, profile)] = status.detailLabel
        this[getProfileKey(ACCESS_DETAIL_VALUE, profile)] = status.detailValue
        this[getProfileKey(ACCESS_ACTION_ICON, profile)] = status.actionIcon
        this[getProfileKey(ACCESS_SEVERITY, profile)] = status.severity.name.lowercase()
    }

    private fun readStoredAccessLifecycle(
        prefs: Preferences,
        profile: Int,
    ): StoredAccessLifecycle {
        val key = readProtectedSecret(prefs, ACCESS_LIFECYCLE_KEY_ENCRYPTED, profile)
        val url = prefs[getProfileKey(ACCESS_LIFECYCLE_URL, profile)].orEmpty()
        val binding = prefs[getProfileKey(ACCESS_LIFECYCLE_BINDING, profile)].orEmpty()
        val capability = RemoteAccessCapability(
            available = key.isNotBlank() && url.isNotBlank() && binding.isNotBlank(),
            key = key,
            url = url,
            binding = binding,
            cachedAction = readCachedRemoteAction(prefs, profile),
            exchange = readProfileExchange(prefs, profile),
        )
        val hasStatus = (prefs[getProfileKey(ACCESS_CHECKED_AT, profile)] ?: 0) > 0
        val status = if (hasStatus) {
            val allowConnect = prefs[getProfileKey(ACCESS_ALLOW_CONNECT, profile)] ?: false
            AccessLifecycleStatus(
                allowConnect = allowConnect,
                actionAvailable =
                    prefs[getProfileKey(ACCESS_ACTION_AVAILABLE, profile)] ?: false,
                actionLabel = prefs[getProfileKey(ACCESS_ACTION_LABEL, profile)].orEmpty(),
                actionMessage = prefs[getProfileKey(ACCESS_ACTION_MESSAGE, profile)].orEmpty(),
                title = prefs[getProfileKey(ACCESS_TITLE, profile)].orEmpty(),
                message = prefs[getProfileKey(ACCESS_MESSAGE, profile)].orEmpty(),
                detailLabel =
                    prefs[getProfileKey(ACCESS_DETAIL_LABEL, profile)].orEmpty(),
                detailValue =
                    prefs[getProfileKey(ACCESS_DETAIL_VALUE, profile)].orEmpty(),
                actionIcon =
                    prefs[getProfileKey(ACCESS_ACTION_ICON, profile)].orEmpty(),
                continuationAvailable = getProfileKey(
                    ACCESS_CONTINUATION_AVAILABLE,
                    profile,
                ).let { key -> prefs[key].takeIf { prefs.contains(key) } },
                continuationExpiresAtSeconds = getProfileKey(
                    ACCESS_CONTINUATION_EXPIRES_AT,
                    profile,
                ).let { key -> prefs[key].takeIf { prefs.contains(key) } },
                dismissible = getProfileKey(ACCESS_DISMISSIBLE, profile).let { key ->
                    prefs[key].takeIf { prefs.contains(key) }
                },
                dismissedMessage =
                    prefs[getProfileKey(ACCESS_DISMISSED_MESSAGE, profile)].orEmpty(),
                severity = AccessLifecycleSeverity.parse(
                    prefs[getProfileKey(ACCESS_SEVERITY, profile)].orEmpty(),
                    allowConnect,
                ),
                checkedAtMillis = prefs[getProfileKey(ACCESS_CHECKED_AT, profile)] ?: 0,
                profileRevision =
                    prefs[getProfileKey(ACCESS_PROFILE_REVISION, profile)] ?: 0,
            )
        } else {
            null
        }
        return StoredAccessLifecycle(
            managed = capability.available,
            capability = capability,
            status = status,
            appliedProfileRevision =
                prefs[getProfileKey(ACCESS_PROFILE_REVISION, profile)] ?: 0,
            lastAttemptAtMillis =
                prefs[getProfileKey(ACCESS_LAST_ATTEMPT_AT, profile)] ?: 0,
        )
    }

    private fun readCachedRemoteAction(
        prefs: Preferences,
        profile: Int,
    ): CachedRemoteAction {
        val payload = readProtectedSecret(prefs, CACHED_ACTION_PAYLOAD_ENCRYPTED, profile)
        val primary = prefs[getProfileKey(CACHED_ACTION_URL, profile)].orEmpty()
        if (payload.isBlank() || primary.isBlank()) return CachedRemoteAction.Unavailable
        return CachedRemoteAction(
            available = true,
            payload = payload,
            target = RemoteLaunchTarget(
                primaryUrl = primary,
                fallbackUrl = prefs[getProfileKey(CACHED_ACTION_FALLBACK, profile)].orEmpty(),
                preferredHandler = prefs[getProfileKey(CACHED_ACTION_HANDLER, profile)].orEmpty(),
            ),
            title = prefs[getProfileKey(CACHED_ACTION_TITLE, profile)].orEmpty(),
            message = prefs[getProfileKey(CACHED_ACTION_MESSAGE, profile)].orEmpty(),
            label = prefs[getProfileKey(CACHED_ACTION_LABEL, profile)].orEmpty(),
            clipboardLabel =
                prefs[getProfileKey(CACHED_ACTION_CLIPBOARD_LABEL, profile)].orEmpty(),
            copiedMessage =
                prefs[getProfileKey(CACHED_ACTION_COPIED_MESSAGE, profile)].orEmpty(),
            failedMessage =
                prefs[getProfileKey(CACHED_ACTION_FAILED_MESSAGE, profile)].orEmpty(),
            helpTitle = prefs[getProfileKey(CACHED_ACTION_HELP_TITLE, profile)].orEmpty(),
            helpIntro = prefs[getProfileKey(CACHED_ACTION_HELP_INTRO, profile)].orEmpty(),
            helpSteps = prefs[getProfileKey(CACHED_ACTION_HELP_STEPS, profile)].orEmpty(),
        )
    }

    private fun readProfileExchange(
        prefs: Preferences,
        profile: Int,
    ): RemoteProfileExchange {
        val submitToken = readProtectedSecret(
            prefs,
            PROFILE_EXCHANGE_SUBMIT_TOKEN_ENCRYPTED,
            profile,
        )
        val actionToken = readProtectedSecret(
            prefs,
            PROFILE_EXCHANGE_ACTION_TOKEN_ENCRYPTED,
            profile,
        )
        return if (submitToken.isNotBlank() || actionToken.isNotBlank()) {
            RemoteProfileExchange(
                submitAvailable = submitToken.isNotBlank(),
                submitToken = submitToken,
                actionAvailable =
                    prefs[getProfileKey(PROFILE_EXCHANGE_ACTION_AVAILABLE, profile)] == true &&
                        actionToken.isNotBlank(),
                actionToken = actionToken,
                label =
                    prefs[getProfileKey(PROFILE_EXCHANGE_ACTION_LABEL, profile)].orEmpty(),
                message =
                    prefs[getProfileKey(PROFILE_EXCHANGE_ACTION_MESSAGE, profile)].orEmpty(),
            )
        } else {
            RemoteProfileExchange.Unavailable
        }
    }

    private fun readProtectedSecret(
        prefs: Preferences,
        encryptedKey: Preferences.Key<String>,
        profile: Int,
    ): String = secureStore.decrypt(prefs[getProfileKey(encryptedKey, profile)]).orEmpty()

    private fun MutablePreferences.putProtectedSecret(
        encryptedKey: Preferences.Key<String>,
        value: String,
        profile: Int,
    ) {
        val key = getProfileKey(encryptedKey, profile)
        if (value.isBlank()) remove(key) else this[key] = secureStore.encrypt(value)
    }

    private fun MutablePreferences.clearAccessLifecycleStatus(profile: Int) {
        remove(getProfileKey(ACCESS_ALLOW_CONNECT, profile))
        remove(getProfileKey(ACCESS_ACTION_AVAILABLE, profile))
        remove(getProfileKey(ACCESS_CONTINUATION_AVAILABLE, profile))
        remove(getProfileKey(ACCESS_CONTINUATION_EXPIRES_AT, profile))
        remove(getProfileKey(ACCESS_DISMISSIBLE, profile))
        remove(getProfileKey(ACCESS_DISMISSED_MESSAGE, profile))
        remove(getProfileKey(ACCESS_ACTION_LABEL, profile))
        remove(getProfileKey(ACCESS_ACTION_MESSAGE, profile))
        remove(getProfileKey(ACCESS_TITLE, profile))
        remove(getProfileKey(ACCESS_MESSAGE, profile))
        remove(getProfileKey(ACCESS_DETAIL_LABEL, profile))
        remove(getProfileKey(ACCESS_DETAIL_VALUE, profile))
        remove(getProfileKey(ACCESS_ACTION_ICON, profile))
        remove(getProfileKey(ACCESS_SEVERITY, profile))
        remove(getProfileKey(ACCESS_CHECKED_AT, profile))
        remove(getProfileKey(ACCESS_LAST_ATTEMPT_AT, profile))
        remove(getProfileKey(ACCESS_ACTION_LAUNCHED_AT, profile))
    }

    private fun MutablePreferences.clearAccessLifecycle(profile: Int) {
        remove(getProfileKey(ACCESS_LIFECYCLE_KEY_ENCRYPTED, profile))
        remove(getProfileKey(ACCESS_LIFECYCLE_URL, profile))
        remove(getProfileKey(ACCESS_LIFECYCLE_BINDING, profile))
        remove(getProfileKey(ACCESS_PROFILE_REVISION, profile))
        putCachedRemoteAction(CachedRemoteAction.Unavailable, profile)
        putProfileExchange(RemoteProfileExchange.Unavailable, profile)
        clearAccessLifecycleStatus(profile)
    }

    private fun MutablePreferences.clearRemoteCapabilityAttachment(profile: Int) {
        putSecret(
            REMOTE_ACTION_KEY_ENCRYPTED,
            REMOTE_ACTION_KEY,
            "",
            profile,
        )
        remove(getProfileKey(REMOTE_ACTION_URL, profile))
        remove(getProfileKey(REMOTE_DOCUMENT_BINDING, profile))
        remove(getProfileKey(ACCESS_LIFECYCLE_DISMISSED_SIGNATURE, profile))
        clearAccessLifecycle(profile)
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

    private fun Preferences.isDeployProfileModified(profile: Int): Boolean {
        val stringValues = listOf(
            this[getProfileKey(DEPLOY_IP, profile)].orEmpty(),
            this[getProfileKey(DEPLOY_LOGIN, profile)].orEmpty(),
        )
        val secretValues = listOf(
            readSecret(this, DEPLOY_PASSWORD_ENCRYPTED, DEPLOY_PASSWORD, profile),
            readSecret(
                this,
                DEPLOY_SSH_PRIVATE_KEY_ENCRYPTED,
                DEPLOY_SSH_PRIVATE_KEY,
                profile,
            ),
            readSecret(
                this,
                DEPLOY_SSH_KEY_PASSPHRASE_ENCRYPTED,
                DEPLOY_SSH_KEY_PASSPHRASE,
                profile,
            ),
            readSecret(this, DEPLOY_MAIN_PASSWORD_ENCRYPTED, DEPLOY_MAIN_PASSWORD, profile),
            readSecret(this, DEPLOY_ADMIN_ID_ENCRYPTED, DEPLOY_ADMIN_ID, profile),
            readSecret(this, DEPLOY_BOT_TOKEN_ENCRYPTED, DEPLOY_BOT_TOKEN, profile),
        )
        val sshPort = this[getProfileKey(DEPLOY_SSH_PORT, profile)].orEmpty().trim()
        val dns1 = this[getProfileKey(DEPLOY_DNS1, profile)].orEmpty().trim()
        val dns2 = this[getProfileKey(DEPLOY_DNS2, profile)].orEmpty().trim()
        val nonDefaultPresentation =
            (sshPort.isNotBlank() && sshPort != "22") ||
                (dns1.isNotBlank() && dns1 != "1.1.1.1") ||
                (dns2.isNotBlank() && dns2 != "1.0.0.1") ||
                this[getProfileKey(DEPLOY_SSH_AUTH_MODE, profile)] == "key"
        return stringValues.any(String::isNotBlank) ||
            secretValues.any(String::isNotBlank) ||
            nonDefaultPresentation
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
            if (name == "wdtt_outbound_forms" && key.endsWith("_encrypted") && value is String) {
                secureStore.decrypt(value)?.let { decrypted ->
                    result.put(key.removeSuffix("_encrypted"), decrypted)
                }
                return@forEach
            }
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
                is String -> {
                    if (name == "wdtt_outbound_forms" && isOutboundPreferenceSecretKey(key)) {
                        if (value.isNotBlank()) {
                            editor.putString("${key}_encrypted", secureStore.encrypt(value))
                        }
                    } else {
                        editor.putString(key, value)
                    }
                }
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

    private fun isOutboundPreferenceSecretKey(key: String): Boolean =
        listOf(
            "local_proxy_password",
            "external_proxy_password",
            "wg_exit_password",
            "imported_wg_config",
        ).any { secretName -> key == secretName || key.endsWith("_$secretName") }

    private fun JSONObject.safePort(name: String, fallback: Int): Int =
        optInt(name, fallback).takeIf { it in 1..65535 } ?: fallback
}

fun vpnProfileDefaultName(profile: Int): String = "VPN ${profile.coerceIn(0, 2) + 1}"

private fun importedVpnAddressRules(item: JSONObject, key: String): String {
    if (!item.has(key)) return encodeVpnAddressRules(emptyList())
    return encodeVpnAddressRules(decodeVpnAddressRulesStrict(item.optString(key)))
}

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
