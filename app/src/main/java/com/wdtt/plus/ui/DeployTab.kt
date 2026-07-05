package com.wdtt.plus.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.HelpOutline
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.Key
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import com.wdtt.plus.TunnelService
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInParent
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.jcraft.jsch.ChannelExec
import com.jcraft.jsch.ChannelSftp
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import com.wdtt.plus.DeployManager
import com.wdtt.plus.ServerAdminClient
import com.wdtt.plus.ServerAdminProfileInfo
import com.wdtt.plus.ServerAdminTarget
import com.wdtt.plus.SettingsStore
import com.wdtt.plus.TunnelManager
import com.wdtt.plus.WDTTColors
import com.wdtt.plus.vpnProfileRestorableName
import com.wdtt.plus.vpnProfileDisplayName
import com.wdtt.plus.vpnProfileTransferName
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.time.Instant
import java.time.LocalDateTime
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Base64
import java.util.Date
import java.util.Locale
import java.util.Properties
import org.json.JSONObject

private const val CMD_TIMEOUT = 900000L // 15 minutes
private const val WGCF_VERSION = "2.2.31"
private const val WGCF_LINUX_AMD64_SHA256 = "69147e1a517c66129edd8ac8cb60484d6c9515178d7b4a2f95e3c925f225572a"
private const val WGCF_LINUX_AMD64_URL =
    "https://github.com/ViRb3/wgcf/releases/download/v$WGCF_VERSION/wgcf_${WGCF_VERSION}_linux_amd64"
private const val WGCF_LATEST_RELEASE_API = "https://api.github.com/repos/ViRb3/wgcf/releases/latest"

private enum class DeployMode {
    PreserveData,
    ResetAll
}

private enum class ServerImportMode {
    Replace,
    Merge
}

private enum class OutboundDialog {
    LocalProxy,
    ExternalProxy,
    WireGuardVps,
    FreeWarp,
    ImportedWireGuard,
    Diagnostics
}

private enum class OwnerProfileSource {
    Server,
    LocalOnly
}

private enum class ProxyKind(val label: String, val protocol: String) {
    Socks5("SOCKS5", "socks5"),
    Http("HTTP", "http")
}

private data class OutboundSshTarget(
    val host: String,
    val user: String,
    val pass: String,
    val port: Int
)

private data class ServerBackup(
    val passwordsJson: String,
    val wgKeysDat: String?,
    val createdAt: String,
    val sourceHost: String,
    val passwordCount: Int,
    val deviceCount: Int,
    val mainPassword: String,
    val adminId: String,
    val botToken: String,
    val dns: String
) {
    val hasWgKeys: Boolean
        get() = !wgKeysDat.isNullOrBlank()
}

private data class ServerImportPlan(
    val backup: ServerBackup,
    val mode: ServerImportMode
)

private data class ExistingServerConnection(
    val host: String,
    val password: String,
    val ports: Triple<Int, Int, Int>,
    val adminId: String,
    val botToken: String,
    val dns1: String,
    val dns2: String,
    val adminProfile: ServerAdminProfileInfo
)

private data class PendingExistingConnectionApply(
    val connection: ExistingServerConnection,
    val effectiveLogin: String,
    val localProfile: ServerAdminProfileInfo,
    val serverProfile: ServerAdminProfileInfo,
    val diffLines: List<String>
)

private data class DeployServerComparison(
    val overwriteLines: List<String> = emptyList(),
    val notes: List<String> = emptyList(),
    val checkError: String? = null
)

private data class DeployRequest(
    val host: String,
    val user: String,
    val pass: String,
    val sshPort: Int,
    val mainPass: String,
    val adminId: String,
    val botToken: String,
    val dtlsPort: Int,
    val wgPort: Int,
    val localPort: Int,
    val dns1: String,
    val dns2: String
)

private data class ExistingInstallInfo(
    val serviceExists: Boolean,
    val binaryExists: Boolean,
    val configDirExists: Boolean,
    val accessDbExists: Boolean,
    val wgKeysExist: Boolean,
    val active: Boolean,
    val checkError: String? = null,
    val comparison: DeployServerComparison? = null
) {
    val hasAnyTrace: Boolean
        get() = serviceExists || binaryExists || configDirExists || accessDbExists || wgKeysExist
}

private data class OutboundProfileForms(
    val localProxyPort: String,
    val localProxyLogin: String,
    val localProxyPassword: String,
    val externalProxyKindName: String,
    val externalProxyHost: String,
    val externalProxyPort: String,
    val externalProxyLogin: String,
    val externalProxyPassword: String,
    val wireGuardExitHost: String,
    val wireGuardExitSshPort: String,
    val wireGuardExitUser: String,
    val wireGuardExitPassword: String,
    val wireGuardExitPort: String,
    val wireGuardExitDns: String,
    val importedWireGuardConfig: String
)

private data class OutboundServerSnapshot(
    val mode: String,
    val detail: String,
    val updatedAt: String,
    val hasProfile: Boolean,
    val localProxyPresent: Boolean,
    val localProxyActive: Boolean,
    val localProxyPort: String,
    val localProxyLogin: String,
    val localProxyPassword: String,
    val externalProxyPresent: Boolean,
    val externalProxyActive: Boolean,
    val externalProxyKindName: String,
    val externalProxyHost: String,
    val externalProxyPort: String,
    val externalProxyLogin: String,
    val externalProxyPassword: String,
    val wireGuardPresent: Boolean,
    val wireGuardActive: Boolean,
    val wireGuardExitHost: String,
    val wireGuardExitSshPort: String,
    val wireGuardExitUser: String,
    val wireGuardExitPassword: String,
    val wireGuardExitPort: String,
    val wireGuardExitDns: String,
    val warpPresent: Boolean,
    val warpMtu: String,
    val importedWireGuardConfig: String,
    val checkedAtMillis: Long = System.currentTimeMillis()
) {
    val modeLabel: String
        get() = when (mode) {
            "direct" -> "прямой выход"
            "external_proxy" -> "внешний TCP-прокси"
            "warp_free" -> "бесплатный WARP"
            "imported_wg" -> "VPN/WireGuard-файл"
            "wireguard_vps" -> "выход через другой сервер"
            else -> mode.ifBlank { "не указан" }
        }

    fun preferredDialog(): OutboundDialog? = when {
        mode == "external_proxy" -> OutboundDialog.ExternalProxy
        mode == "wireguard_vps" -> OutboundDialog.WireGuardVps
        mode == "warp_free" -> OutboundDialog.FreeWarp
        mode == "imported_wg" -> OutboundDialog.ImportedWireGuard
        localProxyPresent -> OutboundDialog.LocalProxy
        else -> null
    }

    val activeRouteLabels: List<String>
        get() = buildList {
            if (externalProxyActive) add("внешний TCP-прокси")
            if (wireGuardActive) add("WireGuard-выход")
        }

    val hasRouteConflict: Boolean
        get() = externalProxyActive && wireGuardActive

    val routeConflictMessage: String?
        get() = if (hasRouteConflict) {
            "На сервере одновременно активны внешний TCP-прокси и WireGuard-выход. Так можно сломать выход клиентов; сначала верните прямой выход или выполните диагностику/очистку."
        } else {
            null
        }
}

private enum class OutboundModeVisualState {
    Unknown,
    Off,
    Active,
    Warning,
    Error
}

private data class OutboundModeIndicator(
    val state: OutboundModeVisualState,
    val text: String
)

private val wireGuardOutboundModes = setOf("wireguard_vps", "warp_free", "imported_wg")

private fun outboundModeIndicator(snapshot: OutboundServerSnapshot?, dialog: OutboundDialog): OutboundModeIndicator {
    if (snapshot == null) {
        return OutboundModeIndicator(OutboundModeVisualState.Unknown, "не проверено")
    }

    if (dialog == OutboundDialog.LocalProxy) {
        return when {
            snapshot.localProxyActive -> OutboundModeIndicator(OutboundModeVisualState.Active, "запущен")
            snapshot.localProxyPresent -> OutboundModeIndicator(OutboundModeVisualState.Warning, "найден")
            else -> OutboundModeIndicator(OutboundModeVisualState.Off, "выключен")
        }
    }

    if (dialog == OutboundDialog.ExternalProxy) {
        return when {
            snapshot.hasRouteConflict && snapshot.externalProxyActive -> OutboundModeIndicator(OutboundModeVisualState.Error, "конфликт")
            snapshot.mode == "external_proxy" && snapshot.externalProxyActive -> OutboundModeIndicator(OutboundModeVisualState.Active, "активен")
            snapshot.mode == "external_proxy" -> OutboundModeIndicator(OutboundModeVisualState.Error, "не запущен")
            snapshot.externalProxyActive -> OutboundModeIndicator(OutboundModeVisualState.Warning, "активен вне режима")
            snapshot.externalProxyPresent -> OutboundModeIndicator(OutboundModeVisualState.Warning, "настроен")
            else -> OutboundModeIndicator(OutboundModeVisualState.Off, "выключен")
        }
    }

    if (dialog == OutboundDialog.FreeWarp) {
        return when {
            snapshot.hasRouteConflict && snapshot.wireGuardActive && snapshot.mode == "warp_free" -> OutboundModeIndicator(OutboundModeVisualState.Error, "конфликт")
            snapshot.mode == "warp_free" && snapshot.wireGuardActive -> OutboundModeIndicator(OutboundModeVisualState.Active, "активен")
            snapshot.mode == "warp_free" && snapshot.warpPresent -> OutboundModeIndicator(OutboundModeVisualState.Error, "не запущен")
            snapshot.warpPresent -> OutboundModeIndicator(OutboundModeVisualState.Warning, "настроен")
            else -> OutboundModeIndicator(OutboundModeVisualState.Off, "выключен")
        }
    }

    val expectedMode = when (dialog) {
        OutboundDialog.WireGuardVps -> "wireguard_vps"
        OutboundDialog.ImportedWireGuard -> "imported_wg"
        else -> ""
    }
    if (expectedMode.isNotBlank()) {
        return when {
            snapshot.hasRouteConflict && snapshot.wireGuardActive -> OutboundModeIndicator(OutboundModeVisualState.Error, "конфликт")
            snapshot.mode == expectedMode && snapshot.wireGuardActive -> OutboundModeIndicator(OutboundModeVisualState.Active, "активен")
            snapshot.mode == expectedMode && snapshot.wireGuardPresent -> OutboundModeIndicator(OutboundModeVisualState.Error, "не запущен")
            snapshot.mode == expectedMode -> OutboundModeIndicator(OutboundModeVisualState.Error, "нет конфига")
            snapshot.wireGuardActive && snapshot.mode !in wireGuardOutboundModes -> OutboundModeIndicator(OutboundModeVisualState.Warning, "WG активен")
            else -> OutboundModeIndicator(OutboundModeVisualState.Off, "выключен")
        }
    }

    return OutboundModeIndicator(OutboundModeVisualState.Off, "выключен")
}

private fun OutboundServerSnapshot.outboundModeMismatchWarning(): String? = when {
    routeConflictMessage != null -> routeConflictMessage
    mode == "direct" && activeRouteLabels.isNotEmpty() ->
        "в профиле указан прямой выход, но на сервере активен ${activeRouteLabels.joinToString(" и ")}."
    mode == "external_proxy" && !externalProxyActive ->
        "режим записан как внешний TCP-прокси, но служба маршрутизации через прокси не запущена."
    mode in wireGuardOutboundModes && !wireGuardActive ->
        "режим записан как ${modeLabel}, но WireGuard-выход не запущен."
    externalProxyActive && mode != "external_proxy" ->
        "внешний TCP-прокси запущен, но профиль режима указывает «${modeLabel}»."
    wireGuardActive && mode !in wireGuardOutboundModes ->
        "WireGuard-выход запущен, но профиль режима указывает «${modeLabel}»."
    else -> null
}

private fun outboundServerShortState(snapshot: OutboundServerSnapshot): String = when {
    snapshot.hasRouteConflict -> "конфликт — ${snapshot.activeRouteLabels.joinToString(" и ")}"
    snapshot.externalProxyActive -> "внешний TCP-прокси"
    snapshot.wireGuardActive -> snapshot.modeLabel.takeIf { snapshot.mode in wireGuardOutboundModes } ?: "WireGuard-выход"
    else -> "прямой выход"
}

private fun outboundServerStateHint(snapshot: OutboundServerSnapshot): String {
    val checkedAt = formatOutboundCheckTime(snapshot.checkedAtMillis)
    val modeChangedAt = formatOutboundTimestamp(snapshot.updatedAt)
    val warning = snapshot.routeConflictMessage ?: snapshot.outboundModeMismatchWarning()
    if (warning != null) {
        return buildString {
            append(warning)
            if (checkedAt.isNotBlank()) append(" Проверено: $checkedAt.")
            if (modeChangedAt.isNotBlank()) append(" Режим изменён: $modeChangedAt.")
        }
    }
    return buildString {
        append("Конфликтных режимов не найдено.")
        if (snapshot.localProxyActive) {
            append(" Прокси VPS запущен отдельно и не переключает выход WDTT-клиентов.")
        }
        if (checkedAt.isNotBlank()) {
            append(" Проверено: $checkedAt.")
        }
        if (modeChangedAt.isNotBlank()) {
            append(" Режим изменён: $modeChangedAt.")
        }
    }
}

private fun outboundServerStateSummary(snapshot: OutboundServerSnapshot): String {
    val parts = mutableListOf<String>()
    parts += "Состояние выхода WDTT прочитано с сервера: ${outboundServerShortState(snapshot)}."
    snapshot.routeConflictMessage?.let { parts += it }
    snapshot.outboundModeMismatchWarning()?.takeIf { it != snapshot.routeConflictMessage }?.let { parts += it }
    if (snapshot.localProxyActive) {
        parts += "Прокси VPS запущен отдельно; он не конфликтует с маршрутизацией выхода WDTT."
    } else if (snapshot.localProxyPresent) {
        parts += "Прокси VPS найден, но служба не запущена."
    }
    formatOutboundCheckTime(snapshot.checkedAtMillis).takeIf { it.isNotBlank() }?.let {
        parts += "Состояние проверено: $it."
    }
    formatOutboundTimestamp(snapshot.updatedAt).takeIf { it.isNotBlank() }?.let {
        parts += "Режим последний раз изменён: $it."
    }
    return parts.joinToString(" ")
}

private fun canReturnDirect(snapshot: OutboundServerSnapshot?): Boolean =
    snapshot != null && (snapshot.mode != "direct" || snapshot.externalProxyActive || snapshot.wireGuardActive)

private fun canDisableOutboundDialog(snapshot: OutboundServerSnapshot?, dialog: OutboundDialog): Boolean {
    if (snapshot == null) return false
    return when (dialog) {
        OutboundDialog.ExternalProxy -> snapshot.externalProxyActive
        OutboundDialog.WireGuardVps -> snapshot.mode == "wireguard_vps" && snapshot.wireGuardActive
        OutboundDialog.FreeWarp -> snapshot.mode == "warp_free" && snapshot.wireGuardActive
        OutboundDialog.ImportedWireGuard -> snapshot.mode == "imported_wg" && snapshot.wireGuardActive
        else -> false
    }
}

private fun canCheckOutboundDialog(snapshot: OutboundServerSnapshot?, dialog: OutboundDialog): Boolean {
    if (snapshot == null) return false
    return when (dialog) {
        OutboundDialog.WireGuardVps -> snapshot.mode == "wireguard_vps" && snapshot.wireGuardActive
        OutboundDialog.FreeWarp -> snapshot.mode == "warp_free" && snapshot.wireGuardActive
        OutboundDialog.ImportedWireGuard -> snapshot.mode == "imported_wg" && snapshot.wireGuardActive
        else -> false
    }
}

private fun canUpdateFreeWarp(snapshot: OutboundServerSnapshot?): Boolean =
    snapshot?.warpPresent == true

private fun canDeleteFreeWarp(snapshot: OutboundServerSnapshot?): Boolean =
    snapshot?.warpPresent == true

private fun canDeleteImportedWireGuard(snapshot: OutboundServerSnapshot?): Boolean =
    snapshot != null && (snapshot.mode == "imported_wg" || snapshot.importedWireGuardConfig.isNotBlank())

private fun canStopLocalProxy(snapshot: OutboundServerSnapshot?): Boolean =
    snapshot?.localProxyActive == true

private fun canRemoveLocalProxy(snapshot: OutboundServerSnapshot?): Boolean =
    snapshot?.localProxyPresent == true

private fun outboundDialogServerStateSummary(snapshot: OutboundServerSnapshot, dialog: OutboundDialog): String {
    val indicator = outboundModeIndicator(snapshot, dialog)
    val checkedAt = formatOutboundCheckTime(snapshot.checkedAtMillis)
    val prefix = when (dialog) {
        OutboundDialog.LocalProxy -> "Прокси VPS"
        OutboundDialog.ExternalProxy -> "Внешний TCP-прокси"
        OutboundDialog.WireGuardVps -> "Выход через другой сервер"
        OutboundDialog.FreeWarp -> "Бесплатный WARP"
        OutboundDialog.ImportedWireGuard -> "VPN/WireGuard-файл"
        OutboundDialog.Diagnostics -> "Диагностика"
    }
    val parts = mutableListOf("$prefix: ${indicator.text}.")
    when (dialog) {
        OutboundDialog.LocalProxy -> when {
            snapshot.localProxyActive -> parts += "Служба прокси на сервере запущена."
            snapshot.localProxyPresent -> parts += "Настройки прокси найдены, но служба сейчас не запущена."
            else -> parts += "Настройки прокси на сервере не найдены."
        }
        OutboundDialog.ExternalProxy -> when {
            snapshot.externalProxyActive -> parts += "Маршрутизация обычного TCP-трафика WDTT через внешний прокси включена."
            snapshot.externalProxyPresent -> parts += "Настройки внешнего прокси найдены, но маршрутизация сейчас не активна."
            else -> parts += "Внешний TCP-прокси на сервере не настроен."
        }
        OutboundDialog.WireGuardVps -> when {
            snapshot.mode == "wireguard_vps" && snapshot.wireGuardActive -> parts += "WireGuard-выход через другой сервер активен."
            snapshot.mode == "wireguard_vps" && snapshot.wireGuardPresent -> parts += "Конфиг выхода через другой сервер найден, но WireGuard сейчас не запущен."
            snapshot.wireGuardExitHost.isNotBlank() || snapshot.wireGuardExitPort.isNotBlank() -> parts += "Сохранённые поля второго сервера найдены; нажмите «Настроить выход», чтобы включить режим."
            else -> parts += "Настройки выхода через другой сервер на сервере не найдены."
        }
        OutboundDialog.FreeWarp -> when {
            snapshot.mode == "warp_free" && snapshot.wireGuardActive -> parts += "WARP активен; можно выполнить глубокую проверку Cloudflare."
            snapshot.warpPresent -> parts += "Регистрация или профиль WARP найдены, но WARP сейчас не активен. Нажмите «Установить / восстановить», чтобы включить его без новой регистрации, если сохранённый аккаунт рабочий."
            else -> parts += "Регистрация WARP на сервере не найдена."
        }
        OutboundDialog.ImportedWireGuard -> when {
            snapshot.mode == "imported_wg" && snapshot.wireGuardActive -> parts += "Импортированный VPN/WireGuard-файл активен."
            snapshot.importedWireGuardConfig.isNotBlank() -> parts += "Сохранённый VPN/WireGuard-файл найден, но сейчас не активен. Нажмите «Включить», чтобы применить его."
            snapshot.mode == "imported_wg" && snapshot.wireGuardPresent -> parts += "Рабочий WireGuard-конфиг найден, но интерфейс сейчас не запущен."
            else -> parts += "Импортированный VPN/WireGuard-файл на сервере не найден."
        }
        OutboundDialog.Diagnostics -> Unit
    }
    snapshot.routeConflictMessage?.let { parts += it }
    if (checkedAt.isNotBlank()) parts += "Проверено: $checkedAt."
    return parts.joinToString(" ")
}

private fun formatOutboundTimestamp(raw: String): String {
    val cleaned = raw.trim()
    if (cleaned.isBlank()) return ""
    val ru = Locale("ru", "RU")
    val formatter = DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm", ru)
    val moscow = ZoneId.of("Europe/Moscow")
    val deviceZone = runCatching { ZoneId.systemDefault() }.getOrDefault(moscow)
    val normalized = cleaned.replace(Regex("([+-]\\d{2})(\\d{2})$"), "$1:$2")

    runCatching {
        val zoned = OffsetDateTime.parse(normalized).atZoneSameInstant(deviceZone)
        val suffix = if (deviceZone == moscow) " МСК" else " ${zoned.offset}"
        return formatter.format(zoned) + suffix
    }
    runCatching {
        val zoned = LocalDateTime.parse(normalized).atZone(moscow)
        return formatter.format(zoned) + " МСК"
    }
    return cleaned
}

private fun formatOutboundCheckTime(millis: Long): String {
    if (millis <= 0L) return ""
    val ru = Locale("ru", "RU")
    val formatter = DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm", ru)
    val moscow = ZoneId.of("Europe/Moscow")
    val deviceZone = runCatching { ZoneId.systemDefault() }.getOrDefault(moscow)
    return runCatching {
        val zoned = Instant.ofEpochMilli(millis).atZone(deviceZone)
        val suffix = if (deviceZone == moscow) " МСК" else " ${zoned.offset}"
        formatter.format(zoned) + suffix
    }.getOrDefault(
        formatter.format(Instant.ofEpochMilli(millis).atZone(moscow)) + " МСК"
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeployTab(
    scrollPosition: MutableIntState = rememberSaveable { mutableIntStateOf(0) }
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val settingsStore = remember { SettingsStore(context) }
    val deployScrollState = rememberRememberedScrollState(scrollPosition)
    val topRevealOffsetPx = with(LocalDensity.current) { 10.dp.toPx() }
    var clientsSectionY by remember { mutableStateOf(0f) }
    var outboundSectionY by remember { mutableStateOf(0f) }
    var migrationSectionY by remember { mutableStateOf(0f) }

    LaunchedEffect(Unit) { DeployManager.init(context) }

    val savedIp by settingsStore.deployIp.collectAsStateWithLifecycle(initialValue = "")
    val activeProfile by settingsStore.activeProfile.collectAsStateWithLifecycle(initialValue = 0)
    val profileNames by settingsStore.profileNames.collectAsStateWithLifecycle(initialValue = emptyList())
    val savedLogin by settingsStore.deployLogin.collectAsStateWithLifecycle(initialValue = "")
    val savedPassword by settingsStore.deployPassword.collectAsStateWithLifecycle(initialValue = "")
    val savedPeer by settingsStore.peer.collectAsStateWithLifecycle(initialValue = "")
    val savedConnectionPassword by settingsStore.connectionPassword.collectAsStateWithLifecycle(initialValue = "")
    val savedVkHashes by settingsStore.vkHashes.collectAsStateWithLifecycle(initialValue = "")
    val savedSecondaryVkHash by settingsStore.secondaryVkHash.collectAsStateWithLifecycle(initialValue = "")
    val savedWorkersPerHash by settingsStore.workersPerHash.collectAsStateWithLifecycle(initialValue = 16)
    val savedProtocol by settingsStore.protocol.collectAsStateWithLifecycle(initialValue = "udp")
    val savedSni by settingsStore.sni.collectAsStateWithLifecycle(initialValue = "")
    val savedNoDns by settingsStore.noDns.collectAsStateWithLifecycle(initialValue = false)

    var ip by remember { mutableStateOf("") }
    var login by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var loginFocused by remember { mutableStateOf(false) }
    var passwordFocused by remember { mutableStateOf(false) }

    val savedDns1 by settingsStore.deployDns1.collectAsStateWithLifecycle(initialValue = "1.1.1.1")
    val savedDns2 by settingsStore.deployDns2.collectAsStateWithLifecycle(initialValue = "1.0.0.1")
    var dns1 by remember { mutableStateOf("1.1.1.1") }
    var dns2 by remember { mutableStateOf("1.0.0.1") }

    val savedMainPass by settingsStore.deployMainPassword.collectAsStateWithLifecycle(initialValue = "")
    val savedAdminId by settingsStore.deployAdminId.collectAsStateWithLifecycle(initialValue = "")
    val savedBotToken by settingsStore.deployBotToken.collectAsStateWithLifecycle(initialValue = "")
    val savedSshPort by settingsStore.deploySshPort.collectAsStateWithLifecycle(initialValue = "22")
    val savedManualPorts by settingsStore.manualPortsEnabled.collectAsStateWithLifecycle(initialValue = false)
    val savedServerDtlsPort by settingsStore.serverDtlsPort.collectAsStateWithLifecycle(initialValue = 56000)
    val savedServerWgPort by settingsStore.serverWgPort.collectAsStateWithLifecycle(initialValue = 56001)
    val savedListenPort by settingsStore.listenPort.collectAsStateWithLifecycle(initialValue = 9000)
    val clientsSectionExpanded by remember(settingsStore) {
        settingsStore.deployClientsSectionExpanded.map { it as Boolean? }
    }.collectAsStateWithLifecycle(initialValue = null)
    val outboundSectionExpanded by remember(settingsStore) {
        settingsStore.deployOutboundSectionExpanded.map { it as Boolean? }
    }.collectAsStateWithLifecycle(initialValue = null)
    val migrationSectionExpanded by remember(settingsStore) {
        settingsStore.deployMigrationSectionExpanded.map { it as Boolean? }
    }.collectAsStateWithLifecycle(initialValue = null)

    var showSecretsDialog by remember { mutableStateOf(false) }
    var showUninstallDialog by remember { mutableStateOf(false) }
    var pendingDeployRequest by remember { mutableStateOf<DeployRequest?>(null) }
    var pendingDeployImportRequest by remember { mutableStateOf<DeployRequest?>(null) }
    var pendingDirectImportRequest by remember { mutableStateOf<DeployRequest?>(null) }
    var existingInstallInfo by remember { mutableStateOf<ExistingInstallInfo?>(null) }
    var isCheckingExistingInstall by remember { mutableStateOf(false) }
    var exportIncludeWgKeys by rememberSaveable { mutableStateOf(true) }
    var pendingExportBackup by remember { mutableStateOf<ServerBackup?>(null) }
    var selectedImportBackup by remember { mutableStateOf<ServerBackup?>(null) }
    var selectedImportModeName by rememberSaveable { mutableStateOf(ServerImportMode.Replace.name) }
    var migrationBusy by remember { mutableStateOf(false) }
    var migrationStatus by rememberSaveable { mutableStateOf("") }
    var existingConnectBusy by remember { mutableStateOf(false) }
    var existingConnectStatus by rememberSaveable { mutableStateOf("") }
    var pendingExistingConnectionApply by remember { mutableStateOf<PendingExistingConnectionApply?>(null) }
    var outboundDialog by remember { mutableStateOf<OutboundDialog?>(null) }
    var outboundBusy by remember { mutableStateOf(false) }
    var outboundProgressActive by remember { mutableStateOf(false) }
    var outboundActionTitle by remember { mutableStateOf("") }
    var outboundStatus by rememberSaveable { mutableStateOf("") }
    var outboundStatusOwner by rememberSaveable { mutableStateOf<String?>(null) }
    var outboundSnapshot by remember { mutableStateOf<OutboundServerSnapshot?>(null) }
    var outboundSnapshotBusy by remember { mutableStateOf(false) }
    var importedWgConfigText by rememberSaveable { mutableStateOf("") }
    val outboundPrefs = remember { context.getSharedPreferences("wdtt_outbound_forms", Context.MODE_PRIVATE) }
    var localProxyPortInput by rememberSaveable { mutableStateOf(outboundPrefs.getString("local_proxy_port", "1080") ?: "1080") }
    var localProxyLoginInput by rememberSaveable {
        mutableStateOf(outboundPrefs.getString("local_proxy_login", "")?.takeIf { it.isNotBlank() } ?: "wdtt_${randomToken(5).lowercase()}")
    }
    var localProxyPasswordInput by rememberSaveable {
        mutableStateOf(outboundPrefs.getString("local_proxy_password", "")?.takeIf { it.isNotBlank() } ?: randomToken(18))
    }
    var externalProxyKindName by rememberSaveable {
        mutableStateOf(outboundPrefs.getString("external_proxy_kind", ProxyKind.Socks5.name) ?: ProxyKind.Socks5.name)
    }
    var externalProxyHostInput by rememberSaveable { mutableStateOf(outboundPrefs.getString("external_proxy_host", "") ?: "") }
    var externalProxyPortInput by rememberSaveable { mutableStateOf(outboundPrefs.getString("external_proxy_port", "1080") ?: "1080") }
    var externalProxyLoginInput by rememberSaveable { mutableStateOf(outboundPrefs.getString("external_proxy_login", "") ?: "") }
    var externalProxyPasswordInput by rememberSaveable { mutableStateOf(outboundPrefs.getString("external_proxy_password", "") ?: "") }
    var wireGuardExitHostInput by rememberSaveable { mutableStateOf(outboundPrefs.getString("wg_exit_host", "") ?: "") }
    var wireGuardExitSshPortInput by rememberSaveable { mutableStateOf(outboundPrefs.getString("wg_exit_ssh_port", "22") ?: "22") }
    var wireGuardExitUserInput by rememberSaveable { mutableStateOf(outboundPrefs.getString("wg_exit_user", "root") ?: "root") }
    var wireGuardExitPasswordInput by rememberSaveable { mutableStateOf(outboundPrefs.getString("wg_exit_password", "") ?: "") }
    var wireGuardExitPortInput by rememberSaveable { mutableStateOf(outboundPrefs.getString("wg_exit_port", "51820") ?: "51820") }
    var wireGuardExitDnsInput by rememberSaveable { mutableStateOf(outboundPrefs.getString("wg_exit_dns", "1.1.1.1,8.8.8.8") ?: "1.1.1.1,8.8.8.8") }
    var freeWarpMtuInput by rememberSaveable { mutableStateOf(outboundPrefs.getString("warp_mtu", "1280") ?: "1280") }

    var showSuccessBanner by rememberSaveable { mutableStateOf(false) }
    var successCountdown by rememberSaveable { mutableIntStateOf(5) }

    LaunchedEffect(showSuccessBanner) {
        if (showSuccessBanner) {
            while (successCountdown > 0) {
                kotlinx.coroutines.delay(1000)
                successCountdown--
            }
            showSuccessBanner = false
        }
    }

    val isDeploying by DeployManager.isDeploying.collectAsStateWithLifecycle()
    val deployProgress by DeployManager.deployProgress.collectAsStateWithLifecycle()
    val currentStep by DeployManager.currentStep.collectAsStateWithLifecycle()
    val lastDeployResult by DeployManager.lastResult.collectAsStateWithLifecycle()

    LaunchedEffect(savedIp) { ip = savedIp }
    LaunchedEffect(savedLogin) { login = savedLogin }
    LaunchedEffect(savedPassword) { password = savedPassword }
    LaunchedEffect(savedDns1) { dns1 = savedDns1 }
    LaunchedEffect(savedDns2) { dns2 = savedDns2 }
    LaunchedEffect(ip.trim(), login.trim(), savedSshPort) {
        outboundSnapshot = null
    }
    LaunchedEffect(
        localProxyPortInput,
        localProxyLoginInput,
        localProxyPasswordInput,
        externalProxyKindName,
        externalProxyHostInput,
        externalProxyPortInput,
        externalProxyLoginInput,
        externalProxyPasswordInput,
        wireGuardExitHostInput,
        wireGuardExitSshPortInput,
        wireGuardExitUserInput,
        wireGuardExitPasswordInput,
        wireGuardExitPortInput,
        wireGuardExitDnsInput,
        freeWarpMtuInput
    ) {
        outboundPrefs.edit()
            .putString("local_proxy_port", localProxyPortInput)
            .putString("local_proxy_login", localProxyLoginInput)
            .putString("local_proxy_password", localProxyPasswordInput)
            .putString("external_proxy_kind", externalProxyKindName)
            .putString("external_proxy_host", externalProxyHostInput)
            .putString("external_proxy_port", externalProxyPortInput)
            .putString("external_proxy_login", externalProxyLoginInput)
            .putString("external_proxy_password", externalProxyPasswordInput)
            .putString("wg_exit_host", wireGuardExitHostInput)
            .putString("wg_exit_ssh_port", wireGuardExitSshPortInput)
            .putString("wg_exit_user", wireGuardExitUserInput)
            .putString("wg_exit_password", wireGuardExitPasswordInput)
            .putString("wg_exit_port", wireGuardExitPortInput)
            .putString("wg_exit_dns", wireGuardExitDnsInput)
            .putString("warp_mtu", freeWarpMtuInput)
            .apply()
    }
    val isServerAddressValid = ip.isValidPublicHost()
    val animatedProgress by animateFloatAsState(
        targetValue = deployProgress,
        animationSpec = tween(durationMillis = 1200, easing = androidx.compose.animation.core.FastOutSlowInEasing),
        label = "progress"
    )
    val selectedImportMode = remember(selectedImportModeName) {
        runCatching { ServerImportMode.valueOf(selectedImportModeName) }.getOrDefault(ServerImportMode.Replace)
    }
    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri: Uri? ->
        val backup = pendingExportBackup
        pendingExportBackup = null
        if (uri == null) {
            migrationStatus = "Экспорт отменён"
            migrationBusy = false
            return@rememberLauncherForActivityResult
        }
        if (backup == null) {
            migrationStatus = "Ошибка экспорта: бэкап не был подготовлен"
            migrationBusy = false
            return@rememberLauncherForActivityResult
        }
        migrationStatus = "Сохраняю файл экспорта..."
        scope.launch {
            try {
                writeServerBackupToUri(context, uri, backup)
                migrationStatus = "Экспорт готов: паролей ${backup.passwordCount}, устройств ${backup.deviceCount}${if (backup.hasWgKeys) ", WG-ключи включены" else ""}"
            } catch (e: Exception) {
                migrationStatus = "Ошибка экспорта: ${friendlyDeployError(e, "экспорт")}"
                DeployManager.writeError("Server export error: ${e.message}")
            } finally {
                migrationBusy = false
            }
        }
    }
    val importLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        migrationBusy = true
        migrationStatus = "Читаю файл импорта..."
        scope.launch {
            try {
                val backup = loadServerBackupFromUri(context, uri)
                selectedImportBackup = backup
                selectedImportModeName = ServerImportMode.Replace.name
                migrationStatus = "Импорт выбран: паролей ${backup.passwordCount}, устройств ${backup.deviceCount}${if (backup.hasWgKeys) ", полный перенос" else ", без WG-ключей"}"
            } catch (e: Exception) {
                selectedImportBackup = null
                migrationStatus = "Ошибка файла импорта: ${friendlyDeployError(e, "файл импорта")}"
                DeployManager.writeError("Server import file error: ${e.message}")
            } finally {
                migrationBusy = false
            }
        }
    }
    val wgConfigLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            try {
                importedWgConfigText = readTextFromUri(context, uri)
                outboundDialog = OutboundDialog.ImportedWireGuard
                outboundStatus = ""
                outboundStatusOwner = OutboundDialog.ImportedWireGuard.name
            } catch (e: Exception) {
                outboundStatus = "Ошибка чтения VPN/WireGuard-файла: ${friendlyDeployError(e, "импорт VPN/WireGuard")}"
                outboundStatusOwner = OutboundDialog.ImportedWireGuard.name
            }
        }
    }

    fun currentOwnerProfile(): ServerAdminProfileInfo = buildOwnerProfile(
        vkHashes = savedVkHashes,
        secondaryVkHash = savedSecondaryVkHash,
        workersPerHash = savedWorkersPerHash,
        protocol = savedProtocol,
        listenPort = savedListenPort,
        sni = savedSni,
        noDns = savedNoDns,
        dtlsPort = if (savedManualPorts) savedServerDtlsPort else 56000,
        wgPort = if (savedManualPorts) savedServerWgPort else 56001,
        profileName = vpnProfileTransferName(activeProfile, profileNames)
    )

    fun currentOutboundProfileForms(): OutboundProfileForms = OutboundProfileForms(
        localProxyPort = localProxyPortInput,
        localProxyLogin = localProxyLoginInput,
        localProxyPassword = localProxyPasswordInput,
        externalProxyKindName = externalProxyKindName,
        externalProxyHost = externalProxyHostInput,
        externalProxyPort = externalProxyPortInput,
        externalProxyLogin = externalProxyLoginInput,
        externalProxyPassword = externalProxyPasswordInput,
        wireGuardExitHost = wireGuardExitHostInput,
        wireGuardExitSshPort = wireGuardExitSshPortInput,
        wireGuardExitUser = wireGuardExitUserInput,
        wireGuardExitPassword = wireGuardExitPasswordInput,
        wireGuardExitPort = wireGuardExitPortInput,
        wireGuardExitDns = wireGuardExitDnsInput,
        importedWireGuardConfig = importedWgConfigText
    )

    suspend fun syncOwnerProfileToServer(
        requestHost: String,
        requestUser: String,
        requestPassword: String,
        requestSshPort: Int,
        requestMainPassword: String,
        profile: ServerAdminProfileInfo
    ): Result<Unit> = runCatching {
        ServerAdminClient.updateAdminProfile(
            ServerAdminTarget(
                host = requestHost,
                user = requestUser.ifBlank { "root" },
                sshPassword = requestPassword,
                sshPort = requestSshPort,
                mainPassword = requestMainPassword
            ),
            profile
        )
    }.map { }

    suspend fun applyExistingConnection(
        connection: ExistingServerConnection,
        effectiveLogin: String,
        profile: ServerAdminProfileInfo,
        source: OwnerProfileSource
    ) {
        val ports = profile.effectivePorts(connection.ports)
        val normalizedProfile = profile.copy(
            listenPort = ports.third,
            ports = ports.asPortsSpec()
        )
        settingsStore.save(
            peer = connection.host,
            vkHashes = normalizedProfile.vkHashes,
            secondaryVkHash = normalizedProfile.secondaryVkHash,
            workersPerHash = normalizedProfile.workersPerHash,
            protocol = normalizedProfile.protocol,
            listenPort = normalizedProfile.listenPort,
            sni = normalizedProfile.sni,
            noDns = normalizedProfile.noDns
        )
        settingsStore.saveConnectionPassword(connection.password)
        settingsStore.savePorts(ports.first, ports.second, ports.third)
        settingsStore.saveManualPortsEnabled(ports != Triple(56000, 56001, 9000))
        settingsStore.saveDeploySecrets(
            mainPass = savedMainPass,
            adminId = connection.adminId,
            botToken = connection.botToken,
            sshPort = savedSshPort.ifBlank { "22" }
        )
        settingsStore.saveDeploy(ip.trim(), effectiveLogin, password, savedSshPort.ifBlank { "22" }, connection.dns1, connection.dns2)
        settingsStore.saveWdttLinkMode(false)
        vpnProfileRestorableName(normalizedProfile.profileName)
            .takeIf { it.isNotBlank() }
            ?.let { settingsStore.saveProfileName(activeProfile, it) }

        existingConnectStatus = when (source) {
            OwnerProfileSource.Server -> "Готово: данные восстановлены с сервера в приложение. Сервер не изменялся. Адрес: ${connection.host}; порты: ${ports.first}, ${ports.second}, ${ports.third}."
            OwnerProfileSource.LocalOnly -> "Готово: подключение настроено по данным сервера, но сохранённого профиля владельца на нём нет — локальные поля «Туннеля» оставлены без изменений. Сервер не изменялся."
        }
    }

    fun launchDeploy(request: DeployRequest, mode: DeployMode) {
        val appContext = context.applicationContext
        val importPlan = selectedImportBackup?.let { ServerImportPlan(it, selectedImportMode) }
        val outboundProfile = currentOutboundProfileForms()
        DeployManager.scope.launch {
            try {
                DeployManager.startDeploy()
                val intent = Intent(appContext, TunnelService::class.java).apply { action = "DEPLOY_START" }
                if (Build.VERSION.SDK_INT >= 26) appContext.startForegroundService(intent)
                else appContext.startService(intent)

                val success = performDeploy(
                    context = appContext,
                    host = request.host,
                    user = request.user,
                    pass = request.pass,
                    port = request.sshPort,
                    mainPass = request.mainPass,
                    adminId = request.adminId,
                    botToken = request.botToken,
                    dtlsPort = request.dtlsPort,
                    wgPort = request.wgPort,
                    localPort = request.localPort,
                    dns1 = request.dns1,
                    dns2 = request.dns2,
                    mode = mode,
                    importPlan = importPlan,
                    onProgress = { p, s -> DeployManager.updateProgress(p, s) }
                )
                if (success) {
                    val ownerProfile = currentOwnerProfile()
                    DeployManager.updateProgress(0.97f, "Сохраняю профиль владельца на сервере...")
                    val ownerProfileSaved = syncOwnerProfileToServer(
                        requestHost = request.host,
                        requestUser = request.user,
                        requestPassword = request.pass,
                        requestSshPort = request.sshPort,
                        requestMainPassword = request.mainPass,
                        profile = ownerProfile
                    ).onFailure {
                        DeployManager.writeError("Owner profile sync after deploy error: ${it.message}")
                        TunnelManager.addDeployErrorLog("Профиль владельца после деплоя: ${friendlyDeployError(it, "сохранение")}")
                    }
                    DeployManager.updateProgress(0.985f, "Сохраняю профиль выходного IP на сервере...")
                    val outboundProfileSaved = runCatching {
                        writeOutboundProfileToServer(
                            context = appContext,
                            target = OutboundSshTarget(
                                host = request.host,
                                user = request.user.ifBlank { "root" },
                                pass = request.pass,
                                port = request.sshPort
                            ),
                            forms = outboundProfile
                        )
                    }.onFailure {
                        DeployManager.writeError("Outbound profile sync after deploy error: ${it.message}")
                        TunnelManager.addDeployErrorLog("Профиль выходного IP после деплоя: ${friendlyDeployError(it, "сохранение")}")
                    }
                    DeployManager.updateProgress(
                        1f,
                        when {
                            ownerProfileSaved.isSuccess && outboundProfileSaved.isSuccess -> "Сервер обновлён, профили сохранены."
                            ownerProfileSaved.isSuccess -> "Сервер обновлён, профиль владельца сохранён."
                            outboundProfileSaved.isSuccess -> "Сервер обновлён, профиль выходного IP сохранён."
                            else -> "Сервер обновлён. Дополнительные профили не сохранились автоматически."
                        }
                    )
                    successCountdown = 5
                    showSuccessBanner = true
                }
            } finally {
                try { appContext.startService(Intent(appContext, TunnelService::class.java).apply { action = "DEPLOY_STOP" }) } catch (_: Exception) {}
            }
        }
    }

    fun startDeployCheck(request: DeployRequest) {
        val localOwnerProfile = currentOwnerProfile()
        val localOutboundProfile = currentOutboundProfileForms()
        scope.launch {
            isCheckingExistingInstall = true
            try {
                var info = checkExistingInstall(
                    host = request.host,
                    user = request.user,
                    pass = request.pass,
                    port = request.sshPort
                )
                if (info.hasAnyTrace) {
                    val comparison = runCatching {
                        compareDeployWithServer(
                            context = context,
                            request = request,
                            localOwnerProfile = localOwnerProfile,
                            localOutboundProfile = localOutboundProfile,
                            inspectDatabase = info.accessDbExists
                        )
                    }.getOrElse {
                        DeployManager.writeError("Pre-deploy data comparison error: ${it.message}")
                        DeployServerComparison(
                            checkError = friendlyDeployError(it, "сверка данных перед установкой")
                        )
                    }
                    info = info.copy(comparison = comparison)
                    pendingDeployRequest = request
                    existingInstallInfo = info
                } else {
                    launchDeploy(request, DeployMode.PreserveData)
                }
            } catch (e: Exception) {
                val friendly = friendlyDeployError(e, "проверка сервера")
                DeployManager.writeError("Pre-deploy check error: ${e.message}")
                TunnelManager.addDeployErrorLog("Проверка сервера перед деплоем: $friendly")
                pendingDeployRequest = request
                existingInstallInfo = ExistingInstallInfo(
                    serviceExists = false,
                    binaryExists = false,
                    configDirExists = false,
                    accessDbExists = false,
                    wgKeysExist = false,
                    active = false,
                    checkError = friendly
                )
            } finally {
                isCheckingExistingInstall = false
            }
        }
    }

    fun currentOutboundTarget(): OutboundSshTarget? {
        if (!isServerAddressValid || password.isBlank()) {
            outboundStatus = "Укажите корректный домен/IP сервера без https:// и SSH-пароль в верхнем блоке деплоя."
            outboundStatusOwner = outboundDialog?.name
            return null
        }
        val effectiveLogin = if (login.isBlank()) "root" else login
        return OutboundSshTarget(
            host = ip.trim(),
            user = effectiveLogin,
            pass = password,
            port = savedSshPort.toIntOrNull() ?: 22
        )
    }

    fun refreshOutboundSnapshot(showStatus: Boolean = true) {
        val target = currentOutboundTarget() ?: return
        outboundSnapshotBusy = true
        if (showStatus) {
            outboundStatus = "Проверяю, какой выходной IP/прокси сейчас активен на сервере..."
            outboundStatusOwner = null
        }
        scope.launch {
            try {
                val snapshot = readOutboundServerSnapshot(context, target)
                outboundSnapshot = snapshot
                if (showStatus) {
                    outboundStatus = outboundServerStateSummary(snapshot)
                    outboundStatusOwner = null
                }
            } catch (e: Exception) {
                if (showStatus) {
                    outboundStatus = "Не удалось прочитать состояние выходного IP: ${friendlyDeployError(e, "выходной IP")}"
                    outboundStatusOwner = null
                }
                DeployManager.writeError("Outbound state refresh failed: ${e.message}")
            } finally {
                outboundSnapshotBusy = false
                DeployManager.updateProgress(0f, "")
            }
        }
    }

    fun runOutboundAction(
        title: String,
        preflightRouteMode: String? = null,
        action: suspend (OutboundSshTarget) -> String
    ) {
        val owner = outboundDialog?.name
        val target = currentOutboundTarget() ?: return
        outboundBusy = true
        outboundSnapshotBusy = true
        outboundProgressActive = true
        outboundActionTitle = title
        DeployManager.updateProgress(0.02f, title)
        outboundStatus = "$title..."
        outboundStatusOwner = owner
        scope.launch {
            try {
                if (preflightRouteMode != null) {
                    DeployManager.updateProgress(0.04f, "Проверяю текущий выход перед переключением...")
                    val before = readOutboundServerSnapshot(context, target)
                    outboundSnapshot = before
                    before.routeConflictMessage?.let { conflict ->
                        outboundStatus = "Установка остановлена. $conflict"
                        outboundStatusOwner = owner
                        return@launch
                    }
                }

                val actionResult = action(target).ifBlank { "$title: готово" }
                val afterSnapshot = runCatching {
                    readOutboundServerSnapshot(context, target)
                }.onSuccess {
                    outboundSnapshot = it
                }.getOrNull()
                val afterWarning = afterSnapshot?.routeConflictMessage
                    ?: afterSnapshot?.outboundModeMismatchWarning()
                outboundStatus = listOfNotNull(
                    actionResult,
                    afterWarning?.let { "Проверьте сервер: $it" }
                ).joinToString("\n")
                outboundStatusOwner = owner
            } catch (e: Exception) {
                outboundStatus = "$title: ${friendlyDeployError(e, "выходной IP")}"
                outboundStatusOwner = owner
                DeployManager.writeError("Outbound action failed: ${e.message}")
            } finally {
                outboundBusy = false
                outboundSnapshotBusy = false
                outboundProgressActive = false
                outboundActionTitle = ""
                DeployManager.updateProgress(0f, "")
            }
        }
    }

    fun applyOutboundSnapshot(snapshot: OutboundServerSnapshot) {
        snapshot.localProxyPort.takeIf { it.isNotBlank() }?.let { localProxyPortInput = it }
        snapshot.localProxyLogin.takeIf { it.isNotBlank() }?.let { localProxyLoginInput = it }
        snapshot.localProxyPassword.takeIf { it.isNotBlank() }?.let { localProxyPasswordInput = it }

        snapshot.externalProxyKindName.takeIf { name -> ProxyKind.entries.any { it.name == name } }?.let {
            externalProxyKindName = it
        }
        snapshot.externalProxyHost.takeIf { it.isNotBlank() }?.let { externalProxyHostInput = it }
        snapshot.externalProxyPort.takeIf { it.isNotBlank() }?.let { externalProxyPortInput = it }
        snapshot.externalProxyLogin.takeIf { it.isNotBlank() }?.let { externalProxyLoginInput = it }
        snapshot.externalProxyPassword.takeIf { it.isNotBlank() }?.let { externalProxyPasswordInput = it }

        snapshot.wireGuardExitHost.takeIf { it.isNotBlank() }?.let { wireGuardExitHostInput = it }
        snapshot.wireGuardExitSshPort.takeIf { it.isNotBlank() }?.let { wireGuardExitSshPortInput = it }
        snapshot.wireGuardExitUser.takeIf { it.isNotBlank() }?.let { wireGuardExitUserInput = it }
        snapshot.wireGuardExitPassword.takeIf { it.isNotBlank() }?.let { wireGuardExitPasswordInput = it }
        snapshot.wireGuardExitPort.takeIf { it.isNotBlank() }?.let { wireGuardExitPortInput = it }
        snapshot.wireGuardExitDns.takeIf { it.isNotBlank() }?.let { wireGuardExitDnsInput = it }
        snapshot.warpMtu.takeIf { raw -> raw.toIntOrNull()?.let { it in 1280..1500 } == true }
            ?.let { freeWarpMtuInput = it }

        if (snapshot.importedWireGuardConfig.isNotBlank()) {
            importedWgConfigText = snapshot.importedWireGuardConfig
        }

        val restoredDialog = snapshot.preferredDialog()
        outboundDialog = restoredDialog
        outboundStatusOwner = restoredDialog?.name
    }

    fun restoreOutboundFromServer() {
        val target = currentOutboundTarget() ?: return
        outboundBusy = true
        outboundSnapshotBusy = true
        outboundProgressActive = true
        outboundActionTitle = "Читаю выходной IP с сервера"
        outboundStatus = "Читаю настройки выходного IP и прокси с сервера..."
        outboundStatusOwner = null
        DeployManager.updateProgress(0.02f, "Читаю настройки выходного IP и прокси с сервера...")
        scope.launch {
            try {
                val snapshot = readOutboundServerSnapshot(context, target)
                outboundSnapshot = snapshot
                applyOutboundSnapshot(snapshot)
                outboundStatus = outboundRestoreSummary(snapshot)
            } catch (e: Exception) {
                outboundStatus = "Не удалось прочитать настройки выходного IP с сервера: ${friendlyDeployError(e, "выходной IP")}"
                outboundStatusOwner = null
                DeployManager.writeError("Outbound profile restore failed: ${e.message}")
            } finally {
                outboundBusy = false
                outboundSnapshotBusy = false
                outboundProgressActive = false
                outboundActionTitle = ""
                DeployManager.updateProgress(0f, "")
            }
        }
    }

    fun openOutboundDialog(dialog: OutboundDialog) {
        outboundStatus = ""
        outboundStatusOwner = dialog.name
        outboundDialog = dialog
    }

    fun dialogStatus(dialog: OutboundDialog): String =
        if (outboundStatusOwner == dialog.name) outboundStatus else ""

    LaunchedEffect(outboundSectionExpanded) {
        if (
            outboundSectionExpanded == true &&
            outboundSnapshot == null &&
            !outboundBusy &&
            !outboundSnapshotBusy &&
            isServerAddressValid &&
            password.isNotBlank()
        ) {
            val target = OutboundSshTarget(
                host = ip.trim(),
                user = login.ifBlank { "root" },
                pass = password,
                port = savedSshPort.toIntOrNull() ?: 22
            )
            outboundSnapshotBusy = true
            try {
                runCatching {
                    readOutboundServerSnapshot(context, target)
                }.onSuccess {
                    outboundSnapshot = it
                }.onFailure {
                    outboundStatus = "Не удалось автоматически проверить выходной IP: ${friendlyDeployError(it, "выходной IP")}"
                    outboundStatusOwner = null
                    DeployManager.writeError("Outbound auto refresh failed: ${it.message}")
                }
            } finally {
                outboundSnapshotBusy = false
                DeployManager.updateProgress(0f, "")
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(deployScrollState),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text(
            "Настройки сервера (${vpnProfileDisplayName(activeProfile, profileNames)})",
            style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
            color = MaterialTheme.colorScheme.onSurface
        )

        val importCanProvideMainPassword = selectedImportMode == ServerImportMode.Replace &&
            selectedImportBackup?.mainPassword?.isNotBlank() == true
        val deploySecretsReady = savedMainPass.isNotBlank() || importCanProvideMainPassword
        val deploySecretsMissing = !deploySecretsReady
        val secretsDetails = buildList {
            add("пароль")
            if (savedDns1 != "1.1.1.1" || savedDns2 != "1.0.0.1") add("DNS")
            if (savedSshPort.isNotBlank() && savedSshPort != "22") add("SSH")
            if (savedManualPorts) add("порты")
        }.joinToString(", ")

        // ═══ Установка сервера ═══
        AppSectionCard(
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                "Установка на сервер",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface
            )

            OutlinedTextField(
                value = ip,
                onValueChange = {
                    ip = it.filter { c -> !c.isWhitespace() }
                    if (ip.isBlank() || ip.isValidPublicHost()) {
                        scope.launch { settingsStore.saveDeploy(ip.trim(), login, password, savedSshPort, dns1, dns2) }
                    }
                },
                label = { Text("IP сервера или домен (без порта)") },
                placeholder = { Text("site.ru или 1.2.3.4") },
                singleLine = true,
                isError = ip.isNotBlank() && !isServerAddressValid,
                supportingText = {
                    if (ip.isNotBlank() && !isServerAddressValid) {
                        Text("Укажите домен или IPv4 без https://, без / и без порта")
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                enabled = !isDeploying,
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                OutlinedTextField(
                    value = login,
                    onValueChange = {
                        login = it.filter { c -> !c.isWhitespace() }
                        if (ip.isBlank() || ip.isValidPublicHost()) {
                            scope.launch { settingsStore.saveDeploy(ip.trim(), login, password, savedSshPort, dns1, dns2) }
                        }
                    },
                    label = { Text("Логин") },
                    placeholder = { Text("root") },
                    singleLine = true,
                    visualTransformation = if (loginFocused) VisualTransformation.None else PasswordVisualTransformation(),
                    modifier = Modifier
                        .weight(1f)
                        .onFocusChanged { loginFocused = it.isFocused },
                    shape = RoundedCornerShape(16.dp),
                    enabled = !isDeploying,
                )
                OutlinedTextField(
                    value = password,
                    onValueChange = {
                        password = it.filter { c -> !c.isWhitespace() }
                        if (ip.isBlank() || ip.isValidPublicHost()) {
                            scope.launch { settingsStore.saveDeploy(ip.trim(), login, password, savedSshPort, dns1, dns2) }
                        }
                    },
                    label = { Text("Пароль SSH") },
                    placeholder = { Text("password") },
                    singleLine = true,
                    visualTransformation = if (passwordFocused) VisualTransformation.None else PasswordVisualTransformation(),
                    modifier = Modifier
                        .weight(1f)
                        .onFocusChanged { passwordFocused = it.isFocused },
                    shape = RoundedCornerShape(16.dp),
                    enabled = !isDeploying,
                )
            }

            OutlinedButton(
                onClick = { showSecretsDialog = true },
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                shape = RoundedCornerShape(16.dp),
                colors = ButtonDefaults.outlinedButtonColors(
                    containerColor = if (deploySecretsMissing) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.surface,
                    contentColor = if (deploySecretsMissing) MaterialTheme.colorScheme.onErrorContainer else MaterialTheme.colorScheme.onSurface
                ),
                border = BorderStroke(
                    1.dp,
                    if (deploySecretsMissing) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.outline.copy(alpha = 0.5f)
                )
            ) {
                Icon(Icons.Default.Key, null, Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(
                    "Секреты ($secretsDetails)",
                    modifier = Modifier.weight(1f),
                    fontWeight = FontWeight.SemiBold
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Button(
                    onClick = {
                        if (!isServerAddressValid || password.isBlank() || !deploySecretsReady) return@Button
                        val effectiveLogin = if (login.isBlank()) "root" else login
                        val effectiveDtlsPort = if (savedManualPorts) savedServerDtlsPort.coerceIn(1, 65535) else 56000
                        val effectiveWgPort = if (savedManualPorts) savedServerWgPort.coerceIn(1, 65535) else 56001
                        val effectiveLocalPort = if (savedManualPorts) savedListenPort.coerceIn(1, 65535) else 9000
                        val importBackup = selectedImportBackup
                        val effectiveMainPass = savedMainPass.ifBlank {
                            if (selectedImportMode == ServerImportMode.Replace) importBackup?.mainPassword.orEmpty() else ""
                        }
                        val request = DeployRequest(
                            host = ip.trim(),
                            user = effectiveLogin,
                            pass = password,
                            sshPort = savedSshPort.toIntOrNull() ?: 22,
                            mainPass = effectiveMainPass,
                            adminId = savedAdminId,
                            botToken = savedBotToken,
                            dtlsPort = effectiveDtlsPort,
                            wgPort = effectiveWgPort,
                            localPort = effectiveLocalPort,
                            dns1 = dns1,
                            dns2 = dns2
                        )
                        if (selectedImportBackup != null) {
                            pendingDeployImportRequest = request
                        } else {
                            startDeployCheck(request)
                        }
                    },
                    modifier = Modifier.weight(1f).fillMaxHeight().heightIn(min = 50.dp),
                    shape = RoundedCornerShape(16.dp),
                    colors = ButtonDefaults.buttonColors(contentColor = MaterialTheme.colorScheme.onPrimary),
                    enabled = !isDeploying && !isCheckingExistingInstall && !migrationBusy && isServerAddressValid && password.isNotBlank() && deploySecretsReady,
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                ) {
                    if (isDeploying || isCheckingExistingInstall) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp), color = MaterialTheme.colorScheme.onPrimary, strokeWidth = 2.dp)
                    } else {
                        Icon(Icons.Default.CloudUpload, null, Modifier.size(18.dp))
                    }
                    Spacer(Modifier.width(6.dp))
                    Text(
                        when {
                            isDeploying -> "Установка"
                            isCheckingExistingInstall -> "Проверка..."
                            else -> "Установить"
                        },
                        fontWeight = FontWeight.Bold,
                        textAlign = TextAlign.Center
                    )
                }

                Button(
                    onClick = {
                        if (!isServerAddressValid || password.isBlank()) return@Button
                        showUninstallDialog = true
                    },
                    modifier = Modifier.weight(1f).fillMaxHeight().heightIn(min = 50.dp),
                    shape = RoundedCornerShape(16.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error,
                        contentColor = MaterialTheme.colorScheme.onError
                    ),
                    enabled = !isDeploying && isServerAddressValid && password.isNotBlank(),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                ) {
                    Icon(Icons.Default.Delete, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(
                        "Удалить",
                        fontWeight = FontWeight.Bold,
                        textAlign = TextAlign.Center
                    )
                }
            }

            if (isCheckingExistingInstall || (isDeploying && !migrationBusy)) {
                DeployProgressPanel(
                    title = if (isCheckingExistingInstall) "Проверяю сервер перед установкой..." else currentStep,
                    progress = animatedProgress,
                    determinate = !isCheckingExistingInstall
                )
            }

            if (!isDeploying &&
                !isCheckingExistingInstall &&
                lastDeployResult.isNotBlank() &&
                !lastDeployResult.equals("success", ignoreCase = true)
            ) {
                DeployResultPanel(
                    result = lastDeployResult,
                    lastStep = currentStep
                )
            }

            if (showSuccessBanner) {
                DeploySuccessBanner(successCountdown = successCountdown)
            }
        }

        AppSectionCard(
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Text(
                "Подключение к готовому серверу",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                "Подключение без установки работает только в направлении сервер → приложение: WDTT Plus проверяет главный пароль, показывает отличия и после подтверждения заполняет локальные поля. На сервер ничего не записывается, пользовательские доступы не меняются.\n\nНаправление приложение → сервер используется при установке с сохранением данных или с нуля. Настройки выходного IP восстанавливаются отдельно кнопкой «Заполнить» в соответствующем блоке.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            OutlinedButton(
                onClick = {
	                    if (!isServerAddressValid || password.isBlank()) return@OutlinedButton
                    if (savedMainPass.isBlank()) {
                        existingConnectStatus = "Укажите главный пароль администратора в «Секретах», затем повторите подключение."
                        return@OutlinedButton
                    }
                    val effectiveLogin = if (login.isBlank()) "root" else login
                    existingConnectBusy = true
                    existingConnectStatus = "Проверяю главный пароль и читаю настройки сервера..."
                    scope.launch {
                        try {
                            val connection = readExistingServerConnection(
	                                host = ip.trim(),
                                user = effectiveLogin,
                                pass = password,
                                port = savedSshPort.toIntOrNull() ?: 22,
                                adminMainPassword = savedMainPass
                            )
                            val localProfile = currentOwnerProfile()
                            val serverProfile = connection.adminProfile
                            val diffLines = existingConnectionDiffLines(
                                connection = connection,
                                localPeer = savedPeer,
                                localConnectionPassword = savedConnectionPassword,
                                localAdminId = savedAdminId,
                                localBotToken = savedBotToken,
                                localDns1 = dns1,
                                localDns2 = dns2,
                                localProfile = localProfile
                            )
                            if (diffLines.isNotEmpty()) {
                                pendingExistingConnectionApply = PendingExistingConnectionApply(
                                    connection = connection,
                                    effectiveLogin = effectiveLogin,
                                    localProfile = localProfile,
                                    serverProfile = serverProfile,
                                    diffLines = diffLines
                                )
                                existingConnectStatus = "Данные сервера отличаются от локальных полей. Проверьте изменения перед восстановлением."
                            } else {
                                val profile = if (serverProfile.hasSavedFields) serverProfile else localProfile
                                val source = if (serverProfile.hasSavedFields) OwnerProfileSource.Server else OwnerProfileSource.LocalOnly
                                applyExistingConnection(connection, effectiveLogin, profile, source)
                            }
                        } catch (e: Exception) {
                            existingConnectStatus = "Ошибка подключения к готовому серверу: ${friendlyDeployError(e, "подключение")}"
                            DeployManager.writeError("Existing server connect error: ${e.message}")
                        } finally {
                            existingConnectBusy = false
                        }
                    }
                },
                enabled = !isDeploying && !isCheckingExistingInstall && !migrationBusy && !existingConnectBusy && isServerAddressValid && password.isNotBlank(),
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                shape = RoundedCornerShape(16.dp)
            ) {
                if (existingConnectBusy) {
                    CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                } else {
                    Icon(Icons.Default.Key, contentDescription = null, modifier = Modifier.size(18.dp))
                }
                Spacer(Modifier.width(8.dp))
                Text("Подключиться (без установки)", fontWeight = FontWeight.SemiBold)
            }
            if (existingConnectStatus.isNotBlank()) {
                Text(
                    existingConnectStatus,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (existingConnectStatus.startsWith("Ошибка")) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        pendingExistingConnectionApply?.let { pending ->
            AlertDialog(
                onDismissRequest = {
                    if (!existingConnectBusy) {
                        pendingExistingConnectionApply = null
                        existingConnectStatus = "Подключение без установки отменено: локальные данные не изменены. Сервер также не изменялся."
                    }
                },
                title = { Text("Данные отличаются") },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(
                            "Подключение без установки заменит перечисленные локальные значения данными сервера. На сервер ничего записано не будет.",
                            style = MaterialTheme.typography.bodyMedium
                        )
                        HorizontalDivider()
                        pending.diffLines.forEach { line ->
                            Text("• $line", style = MaterialTheme.typography.bodySmall)
                        }
                        if (!pending.serverProfile.hasSavedFields) {
                            Text(
                                "На сервере нет сохранённого профиля владельца: поля «Туннеля» останутся локальными и не будут отправлены на сервер.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                },
                confirmButton = {
                    Button(
                        onClick = {
                            val selected = pending
                            pendingExistingConnectionApply = null
                            existingConnectBusy = true
                            existingConnectStatus = "Восстанавливаю данные с сервера в приложение..."
                            scope.launch {
                                try {
                                    val source = if (selected.serverProfile.hasSavedFields) {
                                        OwnerProfileSource.Server
                                    } else {
                                        OwnerProfileSource.LocalOnly
                                    }
                                    applyExistingConnection(
                                        connection = selected.connection,
                                        effectiveLogin = selected.effectiveLogin,
                                        profile = if (selected.serverProfile.hasSavedFields) selected.serverProfile else selected.localProfile,
                                        source = source
                                    )
                                } catch (e: Exception) {
                                    existingConnectStatus = "Ошибка восстановления данных: ${friendlyDeployError(e, "подключение")}"
                                    DeployManager.writeError("Existing server owner profile apply error: ${e.message}")
                                } finally {
                                    existingConnectBusy = false
                                }
                            }
                        },
                        enabled = !existingConnectBusy
                    ) { Text("Применить с сервера") }
                },
                dismissButton = {
                    TextButton(
                        onClick = {
                            pendingExistingConnectionApply = null
                            existingConnectStatus = "Подключение без установки отменено: локальные данные и сервер не изменены."
                        },
                        enabled = !existingConnectBusy
                    ) { Text("Отмена") }
                }
            )
        }

        clientsSectionExpanded?.let { clientsExpanded ->
            ServerClientsSection(
                host = ip.trim(),
                user = if (login.isBlank()) "root" else login,
                sshPassword = password,
                sshPort = savedSshPort.toIntOrNull() ?: 22,
                mainPassword = savedMainPass,
                defaultPorts = "${if (savedManualPorts) savedServerDtlsPort else 56000},${if (savedManualPorts) savedServerWgPort else 56001},${if (savedManualPorts) savedListenPort else 9000}",
                adminProfile = currentOwnerProfile(),
                sourceProfileName = vpnProfileTransferName(activeProfile, profileNames),
                enabled = !isDeploying && !isCheckingExistingInstall && !migrationBusy && !outboundBusy && isServerAddressValid,
                expanded = clientsExpanded,
                modifier = Modifier.onGloballyPositioned { clientsSectionY = it.positionInParent().y },
                onExpandedChange = { expanded ->
                    scope.launch { settingsStore.saveDeployClientsSectionExpanded(expanded) }
                },
                onExpanded = {
                    scope.launch {
                        kotlinx.coroutines.delay(80)
                        deployScrollState.animateScrollTo((clientsSectionY - topRevealOffsetPx).toInt().coerceAtLeast(0))
                    }
                }
            )
        }

        outboundSectionExpanded?.let { outboundExpanded ->
            OutboundRoutingSection(
                busy = outboundBusy,
                snapshot = outboundSnapshot,
                snapshotBusy = outboundSnapshotBusy,
                status = if (outboundDialog == null && outboundStatusOwner == null) outboundStatus else "",
                actionTitle = outboundActionTitle,
                enabled = !isDeploying && !migrationBusy && !outboundBusy && !outboundSnapshotBusy,
                directEnabled = canReturnDirect(outboundSnapshot),
                expanded = outboundExpanded,
                modifier = Modifier.onGloballyPositioned { outboundSectionY = it.positionInParent().y },
                onToggleExpanded = {
                    val willExpand = !outboundExpanded
                    scope.launch { settingsStore.saveDeployOutboundSectionExpanded(willExpand) }
                    if (willExpand) {
                        scope.launch {
                            kotlinx.coroutines.delay(80)
                            deployScrollState.animateScrollTo((outboundSectionY - topRevealOffsetPx).toInt().coerceAtLeast(0))
                        }
                    }
                },
                onOpen = { openOutboundDialog(it) },
                onRestore = { restoreOutboundFromServer() },
                onRefreshState = { refreshOutboundSnapshot(showStatus = true) },
                onStatus = { runOutboundAction("Проверяю текущий выход WDTT") { readOutboundStatus(it) } },
                onDirect = { runOutboundAction("Возвращаю прямой выход WDTT") { disableOutboundExit(it) } }
            )
        }

        outboundDialog?.let { dialog ->
            when (dialog) {
                OutboundDialog.LocalProxy -> LocalProxyDialog(
                    busy = outboundBusy,
                    status = dialogStatus(OutboundDialog.LocalProxy),
                    actionTitle = outboundActionTitle,
                    progressTitle = if (outboundProgressActive) currentStep else "",
                    progress = deployProgress,
                    indicator = outboundModeIndicator(outboundSnapshot, OutboundDialog.LocalProxy),
                    portInput = localProxyPortInput,
                    loginInput = localProxyLoginInput,
                    passwordInput = localProxyPasswordInput,
                    stopEnabled = canStopLocalProxy(outboundSnapshot),
                    removeEnabled = canRemoveLocalProxy(outboundSnapshot),
                    onPortChanged = { localProxyPortInput = it },
                    onLoginChanged = { localProxyLoginInput = it },
                    onPasswordChanged = { localProxyPasswordInput = it },
                    onDismiss = { if (!outboundBusy) outboundDialog = null },
                    onInstall = { proxyPort, loginValue, passwordValue ->
                        val forms = currentOutboundProfileForms().copy(
                            localProxyPort = proxyPort.toString(),
                            localProxyLogin = loginValue,
                            localProxyPassword = passwordValue
                        )
                        runOutboundAction("Устанавливаю прокси на этом сервере") {
                            val result = installLocalProxy(context, it, proxyPort, loginValue, passwordValue)
                            val saveMessage = saveOutboundProfileMessage(context, it, forms, "Поля прокси сохранены на сервере для восстановления.")
                            "$result\n$saveMessage"
                        }
                    },
                    onCheck = { proxyPort, loginValue, passwordValue ->
                        runOutboundAction("Проверяю прокси на этом сервере") {
                            checkLocalProxy(context, it, proxyPort, loginValue, passwordValue)
                        }
                    },
                    onOpenWeb = { proxyPort ->
                        runCatching {
                            val url = "http://${ip.trim()}:${proxyPort + 2}/"
                            context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                        }.onFailure {
                            outboundStatus = "Не удалось открыть браузер для веб-страницы 3proxy."
                            outboundStatusOwner = OutboundDialog.LocalProxy.name
                        }
                    },
                    onStop = {
                        runOutboundAction("Останавливаю прокси на этом сервере") { stopLocalProxy(it) }
                    },
                    onRemove = {
                        runOutboundAction("Удаляю прокси с этого сервера") { removeLocalProxy(it) }
                    }
                )
                OutboundDialog.ExternalProxy -> ExternalProxyDialog(
                    busy = outboundBusy,
                    status = dialogStatus(OutboundDialog.ExternalProxy),
                    actionTitle = outboundActionTitle,
                    progressTitle = if (outboundProgressActive) currentStep else "",
                    progress = deployProgress,
                    indicator = outboundModeIndicator(outboundSnapshot, OutboundDialog.ExternalProxy),
                    kind = ProxyKind.entries.firstOrNull { it.name == externalProxyKindName } ?: ProxyKind.Socks5,
                    hostInput = externalProxyHostInput,
                    portInput = externalProxyPortInput,
                    loginInput = externalProxyLoginInput,
                    passwordInput = externalProxyPasswordInput,
                    disableEnabled = canDisableOutboundDialog(outboundSnapshot, OutboundDialog.ExternalProxy),
                    onKindChanged = { externalProxyKindName = it.name },
                    onHostChanged = { externalProxyHostInput = it },
                    onPortChanged = { externalProxyPortInput = it },
                    onLoginChanged = { externalProxyLoginInput = it },
                    onPasswordChanged = { externalProxyPasswordInput = it },
                    onDismiss = { outboundDialog = null },
                    onCheck = { kind, hostValue, proxyPort, loginValue, passwordValue ->
                        runOutboundAction("Проверяю доступность внешнего TCP-прокси") {
                            checkExternalProxy(context, it, kind, hostValue, proxyPort, loginValue, passwordValue)
                        }
                    },
                    onEnable = { kind, hostValue, proxyPort, loginValue, passwordValue ->
                        val forms = currentOutboundProfileForms().copy(
                            externalProxyKindName = kind.name,
                            externalProxyHost = hostValue,
                            externalProxyPort = proxyPort.toString(),
                            externalProxyLogin = loginValue,
                            externalProxyPassword = passwordValue
                        )
                        runOutboundAction("Проверяю и включаю внешний TCP-прокси", preflightRouteMode = "external_proxy") {
                            val result = enableExternalProxy(context, it, kind, hostValue, proxyPort, loginValue, passwordValue)
                            val saveMessage = saveOutboundProfileMessage(context, it, forms, "Поля внешнего прокси сохранены на сервере для восстановления.")
                            "$result\n$saveMessage"
                        }
                    },
                    onDisable = {
                        runOutboundAction("Возвращаю прямой выход WDTT") { disableOutboundExit(it) }
                    }
                )
                OutboundDialog.WireGuardVps -> WireGuardExitVpsDialog(
                    busy = outboundBusy,
                    status = dialogStatus(OutboundDialog.WireGuardVps),
                    actionTitle = outboundActionTitle,
                    progressTitle = if (outboundProgressActive) currentStep else "",
                    progress = deployProgress,
                    indicator = outboundModeIndicator(outboundSnapshot, OutboundDialog.WireGuardVps),
                    hostInput = wireGuardExitHostInput,
                    sshPortInput = wireGuardExitSshPortInput,
                    userInput = wireGuardExitUserInput,
                    passwordInput = wireGuardExitPasswordInput,
                    wgPortInput = wireGuardExitPortInput,
                    dnsInput = wireGuardExitDnsInput,
                    disableEnabled = canDisableOutboundDialog(outboundSnapshot, OutboundDialog.WireGuardVps),
                    checkEnabled = true,
                    onHostChanged = { wireGuardExitHostInput = it },
                    onSshPortChanged = { wireGuardExitSshPortInput = it },
                    onUserChanged = { wireGuardExitUserInput = it },
                    onPasswordChanged = { wireGuardExitPasswordInput = it },
                    onWgPortChanged = { wireGuardExitPortInput = it },
                    onDnsChanged = { wireGuardExitDnsInput = it },
                    onDismiss = { outboundDialog = null },
                    onInstall = { foreignHost, foreignPort, foreignUser, foreignPassword, wgPort, dns ->
                        val forms = currentOutboundProfileForms().copy(
                            wireGuardExitHost = foreignHost,
                            wireGuardExitSshPort = foreignPort.toString(),
                            wireGuardExitUser = foreignUser,
                            wireGuardExitPassword = foreignPassword,
                            wireGuardExitPort = wgPort.toString(),
                            wireGuardExitDns = dns
                        )
                        runOutboundAction("Настраиваю WireGuard-выход через другой сервер", preflightRouteMode = "wireguard_vps") {
                            val result = installWireGuardExitVps(
                                context = context,
                                current = it,
                                foreignHost = foreignHost,
                                foreignPort = foreignPort,
                                foreignUser = foreignUser,
                                foreignPassword = foreignPassword,
                                wgPort = wgPort,
                                dns = dns
                            )
                            val saveMessage = saveOutboundProfileMessage(context, it, forms, "Поля выхода через другой сервер сохранены на сервере для восстановления.")
                            "$result\n$saveMessage"
                        }
                    },
                    onCheck = {
                        runOutboundAction("Проверяю выход через другой сервер") {
                            val snapshot = readOutboundServerSnapshot(context, it)
                            outboundSnapshot = snapshot
                            if (snapshot.mode == "wireguard_vps" && snapshot.wireGuardActive) {
                                checkWireGuardExit(it, expectedMode = "wireguard_vps")
                            } else {
                                outboundDialogServerStateSummary(snapshot, OutboundDialog.WireGuardVps)
                            }
                        }
                    },
                    onDisable = {
                        runOutboundAction("Возвращаю прямой выход WDTT") { disableOutboundExit(it) }
                    }
                )
                OutboundDialog.FreeWarp -> FreeWarpDialog(
                    busy = outboundBusy,
                    status = dialogStatus(OutboundDialog.FreeWarp),
                    actionTitle = outboundActionTitle,
                    progressTitle = if (outboundProgressActive) currentStep else "",
                    progress = deployProgress,
                    indicator = outboundModeIndicator(outboundSnapshot, OutboundDialog.FreeWarp),
                    mtuInput = freeWarpMtuInput,
                    disableEnabled = canDisableOutboundDialog(outboundSnapshot, OutboundDialog.FreeWarp),
                    checkEnabled = true,
                    restartEnabled = canCheckOutboundDialog(outboundSnapshot, OutboundDialog.FreeWarp),
                    updateToolEnabled = canUpdateFreeWarp(outboundSnapshot),
                    deleteEnabled = canDeleteFreeWarp(outboundSnapshot),
                    onMtuChanged = { freeWarpMtuInput = it },
                    onDismiss = { if (!outboundBusy) outboundDialog = null },
                    onInstall = { mtu ->
                        runOutboundAction("Устанавливаю и проверяю бесплатный WARP", preflightRouteMode = "warp_free") {
                            installOrRepairFreeWarp(context, it, mtu)
                        }
                    },
                    onCheck = {
                        runOutboundAction("Проверяю бесплатный WARP") {
                            val snapshot = readOutboundServerSnapshot(context, it)
                            outboundSnapshot = snapshot
                            if (snapshot.mode == "warp_free" && snapshot.wireGuardActive) {
                                checkFreeWarp(it, restartOnFailure = false)
                            } else {
                                outboundDialogServerStateSummary(snapshot, OutboundDialog.FreeWarp)
                            }
                        }
                    },
                    onRestart = {
                        runOutboundAction("Перезапускаю и проверяю бесплатный WARP") {
                            checkFreeWarp(it, restartOnFailure = true)
                        }
                    },
                    onUpdateTool = {
                        runOutboundAction("Проверяю обновление wgcf") { updateWgcfTool(context, it) }
                    },
                    onDisable = {
                        runOutboundAction("Возвращаю прямой выход WDTT") { disableOutboundExit(it) }
                    },
                    onDelete = {
                        runOutboundAction("Удаляю бесплатный WARP и возвращаю прямой выход") {
                            deleteFreeWarp(it)
                        }
                    }
                )
                OutboundDialog.ImportedWireGuard -> ImportedWireGuardDialog(
                    busy = outboundBusy,
                    status = dialogStatus(OutboundDialog.ImportedWireGuard),
                    actionTitle = outboundActionTitle,
                    progressTitle = if (outboundProgressActive) currentStep else "",
                    progress = deployProgress,
                    indicator = outboundModeIndicator(outboundSnapshot, OutboundDialog.ImportedWireGuard),
                    initialConfig = importedWgConfigText,
                    disableEnabled = canDisableOutboundDialog(outboundSnapshot, OutboundDialog.ImportedWireGuard),
                    serverCheckEnabled = true,
                    deleteEnabled = canDeleteImportedWireGuard(outboundSnapshot),
                    onConfigChanged = { importedWgConfigText = it },
                    onPickFile = { wgConfigLauncher.launch("*/*") },
                    onDismiss = { outboundDialog = null },
                    onValidate = { config ->
                        outboundStatus = validateWireGuardConfigText(config).fold(
                            onSuccess = { "Файл подходит: WDTT Plus применит его как VPN/WireGuard-выход только для WDTT-пользователей, включая собственный WARP/WARP+ WireGuard-конфиг; обычный интернет сервера не изменится." },
                            onFailure = { "Ошибка VPN/WireGuard-файла: ${it.message}" }
                        )
                        outboundStatusOwner = OutboundDialog.ImportedWireGuard.name
                    },
                    onEnable = { config ->
                        importedWgConfigText = config
                        val forms = currentOutboundProfileForms().copy(importedWireGuardConfig = config)
                        runOutboundAction("Включаю VPN/WireGuard-выход из файла", preflightRouteMode = "imported_wg") {
                            val result = enableImportedWireGuardExit(context, it, config)
                            val saveMessage = saveOutboundProfileMessage(context, it, forms, "VPN/WireGuard-файл сохранён на сервере для восстановления.")
                            "$result\n$saveMessage"
                        }
                    },
                    onDisable = {
                        runOutboundAction("Возвращаю прямой выход WDTT") { disableOutboundExit(it) }
                    },
                    onServerCheck = {
                        runOutboundAction("Проверяю установленный VPN/WireGuard-выход") {
                            val snapshot = readOutboundServerSnapshot(context, it)
                            outboundSnapshot = snapshot
                            if (snapshot.mode == "imported_wg" && snapshot.wireGuardActive) {
                                checkWireGuardExit(it, expectedMode = "imported_wg")
                            } else {
                                outboundDialogServerStateSummary(snapshot, OutboundDialog.ImportedWireGuard)
                            }
                        }
                    },
                    onDelete = {
                        importedWgConfigText = ""
                        runOutboundAction("Удаляю VPN/WireGuard-файл и возвращаю прямой выход") { deleteImportedWireGuardExit(it) }
                    }
                )
                OutboundDialog.Diagnostics -> OutboundDiagnosticsDialog(
                    busy = outboundBusy,
                    status = dialogStatus(OutboundDialog.Diagnostics),
                    actionTitle = outboundActionTitle,
                    progressTitle = if (outboundProgressActive) currentStep else "",
                    progress = deployProgress,
                    cleanupEnabled = canReturnDirect(outboundSnapshot),
                    onDismiss = { outboundDialog = null },
                    onRun = { runOutboundAction("Собираю диагностику выхода WDTT") { readOutboundDiagnostics(it) } },
                    onCleanup = { runOutboundAction("Возвращаю прямой выход WDTT") { disableOutboundExit(it) } }
                )
            }
        }

        if (showSecretsDialog) {
            DeploySecretsDialog(
                settingsStore = settingsStore,
                initialMainPass = savedMainPass,
                initialAdminId = savedAdminId,
                initialBotToken = savedBotToken,
                initialSshPort = savedSshPort,
                initialDns1 = dns1,
                initialDns2 = dns2,
                initialManualPortsEnabled = savedManualPorts,
                initialServerDtlsPort = savedServerDtlsPort.toString(),
                initialServerWgPort = savedServerWgPort.toString(),
                deployIp = ip.trim(),
                deployLogin = login,
                deployPassword = password,
                onSaved = { _, _ -> },
                onDismiss = { showSecretsDialog = false }
            )
        }

        migrationSectionExpanded?.let { migrationExpanded ->
            val migrationArrowRotation by animateFloatAsState(
                targetValue = if (migrationExpanded) 180f else 0f,
                label = "migration_arrow_rotation"
            )

            AppSectionCard(
                modifier = Modifier.onGloballyPositioned { migrationSectionY = it.positionInParent().y },
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(0.dp)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(24.dp))
                        .clickable {
                            val willExpand = !migrationExpanded
                            scope.launch { settingsStore.saveDeployMigrationSectionExpanded(willExpand) }
                            if (willExpand) {
                                scope.launch {
                                    kotlinx.coroutines.delay(80)
                                    deployScrollState.animateScrollTo((migrationSectionY - topRevealOffsetPx).toInt().coerceAtLeast(0))
                                }
                            }
                        }
                        .padding(vertical = 2.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Surface(shape = RoundedCornerShape(18.dp), color = MaterialTheme.colorScheme.primaryContainer) {
                        Box(modifier = Modifier.size(40.dp), contentAlignment = Alignment.Center) {
                            Icon(
                                imageVector = Icons.Default.CloudUpload,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    }
                    Text(
                        "Перенос сервера",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.weight(1f)
                    )
                    Icon(
                        imageVector = Icons.Default.KeyboardArrowDown,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier
                            .size(24.dp)
                            .rotate(migrationArrowRotation)
                    )
                }

            AnimatedVisibility(
                visible = migrationExpanded,
                enter = expandVertically() + fadeIn(),
                exit = shrinkVertically() + fadeOut()
            ) {
                Column(
                    modifier = Modifier.padding(top = 12.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.30f))
            Text(
                "Экспорт сохраняет пароли, Telegram-бота, привязки устройств и историю. Полный экспорт дополнительно сохраняет WireGuard-ключи сервера и клиентов.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                "Старые ссылки пользователей останутся рабочими только если в них был домен и после переноса DNS этого домена указывает на новый сервер. Если ссылки выдавались с IP, после переноса сгенерируйте и отправьте пользователям новые ссылки; пароли и привязки при полном переносе сохранятся.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                "Настройки выходного IP, прокси, WARP и VPN/WireGuard-файлы этим экспортом не переносятся. После переезда включите нужный режим выхода на новом сервере заново.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                "Файл экспорта содержит секреты доступа. Храните его как пароль от сервера.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "Полный экспорт: сохранить WireGuard-ключи",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.weight(1f)
                )
                Switch(
                    checked = exportIncludeWgKeys,
                    enabled = !migrationBusy && !isDeploying,
                    onCheckedChange = { exportIncludeWgKeys = it }
                )
            }
            Text(
                if (exportIncludeWgKeys) {
                    "Полный перенос нужен для переезда своего сервера: сохраняет WireGuard-идентичность и снижает риск перепривязки устройств."
                } else {
                    "Без WireGuard-ключей переносится только база доступа. Новый сервер создаст новые ключи, часть клиентов может потребовать повторное подключение."
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                OutlinedButton(
                    onClick = {
                        if (!isServerAddressValid || password.isBlank()) {
                            migrationStatus = "Для экспорта укажите корректный домен/IP сервера без https:// и без порта, а также SSH-пароль"
                            return@OutlinedButton
                        }
                        val effectiveLogin = if (login.isBlank()) "root" else login
                        val sshPort = savedSshPort.toIntOrNull() ?: 22
                        val includeKeys = exportIncludeWgKeys
                        migrationBusy = true
                        migrationStatus = "Проверяю сервер и готовлю экспорт..."
                        scope.launch {
                            try {
                                val backup = readServerBackup(
                                    host = ip.trim(),
                                    user = effectiveLogin,
                                    pass = password,
                                    port = sshPort,
                                    includeWgKeys = includeKeys
                                )
                                pendingExportBackup = backup
                                migrationStatus = "Бэкап подготовлен: паролей ${backup.passwordCount}, устройств ${backup.deviceCount}. Выберите место сохранения."
                                val stamp = SimpleDateFormat("yyyyMMdd-HHmm", Locale.US).format(Date())
                                val safeHost = ip.replace(Regex("[^A-Za-z0-9_.-]"), "_").ifBlank { "server" }
                                exportLauncher.launch("wdtt-backup-$safeHost-$stamp.json")
                            } catch (e: Exception) {
                                pendingExportBackup = null
                                migrationStatus = "Ошибка экспорта: ${friendlyDeployError(e, "экспорт")}"
                                DeployManager.writeError("Server export prepare error: ${e.message}")
                                migrationBusy = false
                            }
                        }
                    },
                    modifier = Modifier.weight(1f).heightIn(min = 48.dp),
                    shape = RoundedCornerShape(16.dp),
                    enabled = !migrationBusy && !isDeploying && isServerAddressValid && password.isNotBlank()
                ) {
                    Text("Экспорт", fontWeight = FontWeight.SemiBold)
                }
                Button(
                    onClick = { importLauncher.launch("*/*") },
                    modifier = Modifier.weight(1f).heightIn(min = 48.dp),
                    shape = RoundedCornerShape(16.dp),
                    enabled = !migrationBusy && !isDeploying
                ) {
                    Text("Импорт", fontWeight = FontWeight.SemiBold)
                }
            }

            selectedImportBackup?.let { backup ->
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f),
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.25f))
                ) {
                    Column(
                        modifier = Modifier.fillMaxWidth().padding(12.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(
                            "Выбран импорт: ${backup.passwordCount} паролей, ${backup.deviceCount} устройств${if (backup.hasWgKeys) ", WG-ключи есть" else ", WG-ключей нет"}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                            FilterChip(
                                selected = selectedImportMode == ServerImportMode.Replace,
                                onClick = { selectedImportModeName = ServerImportMode.Replace.name },
                                label = { Text("Заменить") },
                                enabled = !isDeploying,
                                modifier = Modifier.weight(1f)
                            )
                            FilterChip(
                                selected = selectedImportMode == ServerImportMode.Merge,
                                onClick = { selectedImportModeName = ServerImportMode.Merge.name },
                                label = { Text("Добавить") },
                                enabled = !isDeploying,
                                modifier = Modifier.weight(1f)
                            )
                        }
                        Text(
                            if (selectedImportMode == ServerImportMode.Replace) {
                                "Заменить: база сервера будет перезаписана бэкапом. Это режим для переезда на новый сервер."
                            } else {
                                "Добавить: текущие настройки сервера сохранятся, отсутствующие пароли и устройства будут добавлены без перезаписи конфликтов."
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        TextButton(
                            onClick = {
                                selectedImportBackup = null
                                migrationStatus = ""
                            },
                            enabled = !isDeploying
                        ) {
                            Text("Убрать импорт")
                        }
                        Button(
                            onClick = {
                                if (!isServerAddressValid || password.isBlank()) return@Button
                                val effectiveLogin = if (login.isBlank()) "root" else login
                                val effectiveDtlsPort = if (savedManualPorts) savedServerDtlsPort.coerceIn(1, 65535) else 56000
                                val effectiveWgPort = if (savedManualPorts) savedServerWgPort.coerceIn(1, 65535) else 56001
                                val effectiveLocalPort = if (savedManualPorts) savedListenPort.coerceIn(1, 65535) else 9000
                                val effectiveMainPass = savedMainPass.ifBlank {
                                    if (selectedImportMode == ServerImportMode.Replace) backup.mainPassword else ""
                                }
                                pendingDirectImportRequest = DeployRequest(
                                    host = ip.trim(),
                                    user = effectiveLogin,
                                    pass = password,
                                    sshPort = savedSshPort.toIntOrNull() ?: 22,
                                    mainPass = effectiveMainPass,
                                    adminId = savedAdminId,
                                    botToken = savedBotToken,
                                    dtlsPort = effectiveDtlsPort,
                                    wgPort = effectiveWgPort,
                                    localPort = effectiveLocalPort,
                                    dns1 = dns1,
                                    dns2 = dns2
                                )
                            },
                            enabled = !migrationBusy && !isDeploying && isServerAddressValid && password.isNotBlank(),
                            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                            shape = RoundedCornerShape(16.dp)
                        ) {
                            Text("Импортировать сейчас", fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }

            if (migrationBusy && isDeploying) {
                DeployProgressPanel(
                    title = currentStep,
                    progress = animatedProgress,
                    determinate = true
                )
            }

            if (migrationBusy || migrationStatus.isNotBlank()) {
                Text(
                    text = migrationStatus.ifBlank { "Операция выполняется..." },
                    style = MaterialTheme.typography.bodySmall,
                    color = if (migrationStatus.startsWith("Ошибка")) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
                }
            }
        }
        }

        if (showUninstallDialog) {
            UninstallConfirmDialog(
                onDismiss = { showUninstallDialog = false },
                onConfirm = {
                    showUninstallDialog = false
                    val effectiveLogin = if (login.isBlank()) "root" else login
                    val effectiveDtlsPort = if (savedManualPorts) savedServerDtlsPort.coerceIn(1, 65535) else 56000
                    val effectiveWgPort = if (savedManualPorts) savedServerWgPort.coerceIn(1, 65535) else 56001
                    DeployManager.scope.launch {
                        try {
                            DeployManager.startDeploy()
                            performUninstall(
	                                host = ip.trim(), user = effectiveLogin, pass = password, port = savedSshPort.toIntOrNull() ?: 22,
                                dtlsPort = effectiveDtlsPort, wgPort = effectiveWgPort,
                                onProgress = { p, s -> DeployManager.updateProgress(p, s) }
                            )
                        } catch (_: Exception) {}
                    }
                }
            )
        }

        selectedImportBackup?.let { backup ->
            pendingDeployImportRequest?.let { request ->
                ServerImportConfirmDialog(
                    title = "Деплой с импортом",
                    backup = backup,
                    request = request,
                    mode = selectedImportMode,
                    isDeploy = true,
                    onDismiss = { pendingDeployImportRequest = null },
                    onConfirm = {
                        pendingDeployImportRequest = null
                        startDeployCheck(request)
                    }
                )
            }

            pendingDirectImportRequest?.let { request ->
                ServerImportConfirmDialog(
                    title = "Импорт на работающий сервер",
                    backup = backup,
                    request = request,
                    mode = selectedImportMode,
                    isDeploy = false,
                    onDismiss = { pendingDirectImportRequest = null },
                    onConfirm = {
                        pendingDirectImportRequest = null
                        val appContext = context.applicationContext
                        migrationBusy = true
                        migrationStatus = "Импортирую состояние на сервер..."
                        DeployManager.scope.launch {
                            try {
                                DeployManager.startDeploy()
                                val intent = Intent(appContext, TunnelService::class.java).apply { action = "DEPLOY_START" }
                                if (Build.VERSION.SDK_INT >= 26) appContext.startForegroundService(intent)
                                else appContext.startService(intent)
                                val ok = performServerImportNow(
                                    context = appContext,
                                    request = request,
                                    backup = backup,
                                    mode = selectedImportMode,
                                    onProgress = { p, s -> DeployManager.updateProgress(p, s) }
                                )
                                migrationStatus = if (ok) "Импорт завершён, wdtt.service перезапущен" else "Ошибка импорта: операция не была применена, подробности записаны в лог деплоя"
                            } catch (e: Exception) {
                                migrationStatus = "Ошибка импорта: ${friendlyDeployError(e, "импорт")}"
                                DeployManager.writeError("Server direct import error: ${e.message}")
                                DeployManager.stopDeploy("Ошибка импорта")
                            } finally {
                                migrationBusy = false
                                try { appContext.startService(Intent(appContext, TunnelService::class.java).apply { action = "DEPLOY_STOP" }) } catch (_: Exception) {}
                            }
                        }
                    }
                )
            }
        }

        val deployRequest = pendingDeployRequest
        val installInfo = existingInstallInfo
        if (deployRequest != null && installInfo != null) {
            ExistingInstallDialog(
                info = installInfo,
                importMode = selectedImportBackup?.let { selectedImportMode },
                onDismiss = {
                    pendingDeployRequest = null
                    existingInstallInfo = null
                },
                onPreserve = {
                    pendingDeployRequest = null
                    existingInstallInfo = null
                    launchDeploy(deployRequest, DeployMode.PreserveData)
                },
                onReset = {
                    pendingDeployRequest = null
                    existingInstallInfo = null
                    launchDeploy(deployRequest, DeployMode.ResetAll)
                }
            )
        }

    }
}

@Composable
private fun DeployProgressPanel(
    title: String,
    progress: Float,
    determinate: Boolean
) {
    val visibleTitle = title.ifBlank { "Операция выполняется..." }
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.22f))
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Start,
                verticalAlignment = Alignment.CenterVertically
            ) {
                CircularProgressIndicator(
                    modifier = Modifier.size(18.dp),
                    strokeWidth = 2.dp,
                    color = MaterialTheme.colorScheme.primary
                )
                Spacer(Modifier.width(10.dp))
                Text(
                    text = visibleTitle,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.weight(1f)
                )
                if (determinate) {
                    Spacer(Modifier.width(10.dp))
                    Text(
                        text = "${(progress.coerceIn(0f, 1f) * 100).toInt()}%",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            if (determinate) {
                LinearProgressIndicator(
                    progress = { progress.coerceIn(0f, 1f) },
                    modifier = Modifier.fillMaxWidth().height(8.dp).clip(RoundedCornerShape(4.dp)),
                    color = MaterialTheme.colorScheme.primary,
                    trackColor = MaterialTheme.colorScheme.surfaceVariant,
                )
            } else {
                LinearProgressIndicator(
                    modifier = Modifier.fillMaxWidth().height(8.dp).clip(RoundedCornerShape(4.dp)),
                    color = MaterialTheme.colorScheme.primary,
                    trackColor = MaterialTheme.colorScheme.surfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun DeployResultPanel(
    result: String,
    lastStep: String
) {
    val isError = result.contains("ошибка", ignoreCase = true)
    val title = if (isError) result else "Итог деплоя: $result"
    val details = when {
        isError && lastStep.isNotBlank() -> "Последний шаг: $lastStep"
        lastStep.isNotBlank() -> lastStep
        else -> ""
    }
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        color = if (isError) {
            MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.7f)
        } else {
            MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f)
        },
        contentColor = if (isError) MaterialTheme.colorScheme.onErrorContainer else MaterialTheme.colorScheme.onSurface,
        border = BorderStroke(
            1.dp,
            if (isError) MaterialTheme.colorScheme.error.copy(alpha = 0.45f)
            else MaterialTheme.colorScheme.outline.copy(alpha = 0.22f)
        )
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Text(
                title,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold
            )
            if (details.isNotBlank()) {
                Text(
                    details,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun DeploySuccessBanner(successCountdown: Int) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        color = WDTTColors.connected.copy(alpha = 0.12f),
        contentColor = MaterialTheme.colorScheme.onSurface,
        border = BorderStroke(1.dp, WDTTColors.connected.copy(alpha = 0.4f))
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(Icons.Default.CheckCircle, contentDescription = null, tint = WDTTColors.connected)
            Spacer(Modifier.width(8.dp))
            Text(
                text = "Деплой успешно завершён ($successCountdown)",
                color = WDTTColors.connected,
                fontWeight = FontWeight.Bold,
                style = MaterialTheme.typography.bodyMedium
            )
        }
    }
}

@Composable
private fun OutboundRoutingSection(
    busy: Boolean,
    snapshot: OutboundServerSnapshot?,
    snapshotBusy: Boolean,
    status: String,
    actionTitle: String,
    enabled: Boolean,
    directEnabled: Boolean,
    expanded: Boolean,
    modifier: Modifier = Modifier,
    onToggleExpanded: () -> Unit,
    onOpen: (OutboundDialog) -> Unit,
    onRestore: () -> Unit,
    onRefreshState: () -> Unit,
    onStatus: () -> Unit,
    onDirect: () -> Unit
) {
    val arrowRotation by animateFloatAsState(
        targetValue = if (expanded) 180f else 0f,
        label = "outbound_arrow_rotation"
    )
    AppSectionCard(
        modifier = modifier,
        contentPadding = PaddingValues(horizontal = 18.dp, vertical = 18.dp),
        verticalArrangement = Arrangement.spacedBy(0.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(24.dp))
                .clickable(onClick = onToggleExpanded)
                .padding(vertical = 2.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Surface(shape = RoundedCornerShape(18.dp), color = MaterialTheme.colorScheme.primaryContainer) {
                Box(modifier = Modifier.size(40.dp), contentAlignment = Alignment.Center) {
                    Icon(
                        imageVector = Icons.Default.Key,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }

            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.Center) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        "Выходной IP и прокси",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    BetaBadge()
                }
            }

            Icon(
                imageVector = Icons.Default.KeyboardArrowDown,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier
                    .size(24.dp)
                    .rotate(arrowRotation)
            )
        }

        AnimatedVisibility(
            visible = expanded,
            enter = expandVertically() + fadeIn(),
            exit = shrinkVertically() + fadeOut()
        ) {
            Column(
                modifier = Modifier.padding(top = 12.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.30f))
                Text(
                    "Выбирает IP, который видят сайты и сервисы у пользователей WDTT. Сам адрес WDTT-сервера, входящие DTLS/SSH и ссылка подключения этим не скрываются.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    "Обычная сеть самого сервера не меняется. Для маскировки выходного IP используйте бесплатный WARP, внешний TCP-прокси, другой сервер или VPN/WireGuard-файл.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                OutboundServerStateCard(
                    snapshot = snapshot,
                    snapshotBusy = snapshotBusy,
                    enabled = enabled,
                    onRefreshState = onRefreshState
                )
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutboundModeButton(
                        title = "Прокси VPS",
                        description = "Создаёт SOCKS5/HTTP на этом сервере. IP не скрывает: выход будет через тот же VPS.",
                        enabled = enabled,
                        indicator = outboundModeIndicator(snapshot, OutboundDialog.LocalProxy)
                    ) {
                        onOpen(OutboundDialog.LocalProxy)
                    }
                    OutboundModeButton(
                        title = "Внешний TCP-прокси",
                        description = "Скрывает IP для обычного TCP-трафика. UDP, QUIC и часть звонков могут пройти напрямую.",
                        enabled = enabled,
                        indicator = outboundModeIndicator(snapshot, OutboundDialog.ExternalProxy)
                    ) {
                        onOpen(OutboundDialog.ExternalProxy)
                    }
                    OutboundModeButton(
                        title = "Другой сервер",
                        description = "Надёжно выносит выходной IP на отдельный VPS через WireGuard.",
                        enabled = enabled,
                        indicator = outboundModeIndicator(snapshot, OutboundDialog.WireGuardVps)
                    ) {
                        onOpen(OutboundDialog.WireGuardVps)
                    }
                    OutboundModeButton(
                        title = "Бесплатный WARP",
                        description = "Автоматически регистрирует WARP и скрывает IP VPS без покупки второго сервера.",
                        enabled = enabled,
                        indicator = outboundModeIndicator(snapshot, OutboundDialog.FreeWarp)
                    ) {
                        onOpen(OutboundDialog.FreeWarp)
                    }
                    OutboundModeButton(
                        title = "VPN/WireGuard-файл",
                        description = "Принимает готовый WireGuard .conf от VPN-провайдера, собственного WARP/WARP+ или другой совместимой службы.",
                        enabled = enabled,
                        indicator = outboundModeIndicator(snapshot, OutboundDialog.ImportedWireGuard)
                    ) {
                        onOpen(OutboundDialog.ImportedWireGuard)
                    }
                }
                Text(
                    "«Заполнить» читает сохранённые настройки с сервера и заменяет ими только локальные поля этого блока. На сервер ничего не записывается; активный режим выхода не переключается.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    OutlinedButton(
                        onClick = onRestore,
                        enabled = enabled,
                        modifier = Modifier.weight(1f).heightIn(min = 48.dp),
                        shape = RoundedCornerShape(16.dp),
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 8.dp)
                    ) {
                        val restoring = busy && actionTitle.contains("Читаю выходной IP", ignoreCase = true)
                        if (restoring) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                            Spacer(Modifier.width(6.dp))
                        }
                        Text(if (restoring) "Читаю..." else "Заполнить", fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center)
                    }
                    OutlinedButton(
                        onClick = onStatus,
                        enabled = enabled,
                        modifier = Modifier.weight(1f).heightIn(min = 48.dp),
                        shape = RoundedCornerShape(16.dp)
                    ) {
                        val readingStatus = busy && actionTitle.contains("Проверяю текущий", ignoreCase = true)
                        if (readingStatus) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                            Spacer(Modifier.width(6.dp))
                        }
                        Text(if (readingStatus) "Читаю..." else "Статус", fontWeight = FontWeight.SemiBold)
                    }
                }
                OutlinedButton(
                    onClick = { onOpen(OutboundDialog.Diagnostics) },
                    enabled = enabled,
                    modifier = Modifier.align(Alignment.CenterHorizontally).heightIn(min = 48.dp),
                    shape = RoundedCornerShape(16.dp)
                ) {
                    Text("Диагностика", fontWeight = FontWeight.SemiBold)
                }
                Button(
                    onClick = onDirect,
                    enabled = enabled && directEnabled,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                    shape = RoundedCornerShape(16.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.secondaryContainer,
                        contentColor = MaterialTheme.colorScheme.onSecondaryContainer
                    )
                ) {
                    val returningDirect = busy && actionTitle.contains("Возвращаю", ignoreCase = true)
                    if (returningDirect) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                        Spacer(Modifier.width(8.dp))
                    }
                    Text(if (returningDirect) "Возврат..." else "Вернуть прямой выход", fontWeight = FontWeight.Bold)
                }
                if (status.isNotBlank()) {
                    OutboundStatusMessage(status)
                }
            }
        }
    }
}

@Composable
private fun BetaBadge() {
    Surface(
        modifier = Modifier.size(24.dp),
        shape = CircleShape,
        color = MaterialTheme.colorScheme.tertiaryContainer,
        contentColor = MaterialTheme.colorScheme.onTertiaryContainer
    ) {
        Box(contentAlignment = Alignment.Center) {
            Text(
                "β",
                modifier = Modifier.offset(x = (-0.5).dp),
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Black,
                textAlign = TextAlign.Center
            )
        }
    }
}

@Composable
private fun OutboundServerStateCard(
    snapshot: OutboundServerSnapshot?,
    snapshotBusy: Boolean,
    enabled: Boolean,
    onRefreshState: () -> Unit
) {
    val state = when {
        snapshot == null -> OutboundModeVisualState.Unknown
        snapshot.hasRouteConflict -> OutboundModeVisualState.Error
        snapshot.outboundModeMismatchWarning() != null -> OutboundModeVisualState.Warning
        snapshot.mode == "direct" && snapshot.activeRouteLabels.isEmpty() -> OutboundModeVisualState.Off
        snapshot.activeRouteLabels.isNotEmpty() -> OutboundModeVisualState.Active
        else -> OutboundModeVisualState.Off
    }
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.40f),
        border = BorderStroke(1.dp, outboundIndicatorColor(state).copy(alpha = 0.42f))
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutboundStateDot(state)
                Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(
                        text = snapshot?.let { "На сервере: ${outboundServerShortState(it)}" }
                            ?: "На сервере: состояние ещё не проверено",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Text(
                        text = snapshot?.let { outboundServerStateHint(it) }
                            ?: "Откройте блок или нажмите «Обновить состояние», чтобы увидеть, что реально запущено на сервере.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            TextButton(
                onClick = onRefreshState,
                enabled = enabled && !snapshotBusy,
                modifier = Modifier.align(Alignment.End)
            ) {
                if (snapshotBusy) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.width(6.dp))
                }
                Text(if (snapshotBusy) "Проверяю..." else "Обновить состояние")
            }
        }
    }
}

@Composable
private fun OutboundModeButton(
    title: String,
    description: String,
    enabled: Boolean,
    indicator: OutboundModeIndicator,
    onClick: () -> Unit
) {
    OutlinedButton(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth().heightIn(min = 58.dp),
        shape = RoundedCornerShape(16.dp),
        contentPadding = PaddingValues(horizontal = 14.dp, vertical = 10.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutboundStateDot(indicator.state)
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(title, fontWeight = FontWeight.SemiBold, color = LocalContentColor.current)
                    Text(
                        indicator.text,
                        style = MaterialTheme.typography.labelSmall,
                        color = outboundIndicatorColor(indicator.state)
                    )
                }
                Text(
                    description,
                    style = MaterialTheme.typography.bodySmall,
                    color = LocalContentColor.current.copy(alpha = 0.72f)
                )
            }
        }
    }
}

@Composable
private fun OutboundStateDot(state: OutboundModeVisualState) {
    Surface(
        modifier = Modifier.size(11.dp),
        shape = CircleShape,
        color = outboundIndicatorColor(state),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.surface.copy(alpha = 0.55f))
    ) {}
}

@Composable
private fun OutboundDialogStateBanner(indicator: OutboundModeIndicator) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.38f),
        border = BorderStroke(1.dp, outboundIndicatorColor(indicator.state).copy(alpha = 0.38f))
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 9.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutboundStateDot(indicator.state)
            Text(
                "Статус на сервере",
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                indicator.text,
                style = MaterialTheme.typography.bodySmall,
                fontWeight = FontWeight.SemiBold,
                color = outboundIndicatorColor(indicator.state),
                textAlign = TextAlign.End
            )
        }
    }
}

@Composable
private fun outboundIndicatorColor(state: OutboundModeVisualState): Color = when (state) {
    OutboundModeVisualState.Active -> WDTTColors.connected
    OutboundModeVisualState.Warning -> WDTTColors.warning
    OutboundModeVisualState.Error -> MaterialTheme.colorScheme.error
    OutboundModeVisualState.Off -> MaterialTheme.colorScheme.outline
    OutboundModeVisualState.Unknown -> MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.55f)
}

@Composable
private fun LocalProxyDialog(
    busy: Boolean,
    status: String,
    actionTitle: String,
    progressTitle: String,
    progress: Float,
    indicator: OutboundModeIndicator,
    portInput: String,
    loginInput: String,
    passwordInput: String,
    stopEnabled: Boolean,
    removeEnabled: Boolean,
    onPortChanged: (String) -> Unit,
    onLoginChanged: (String) -> Unit,
    onPasswordChanged: (String) -> Unit,
    onDismiss: () -> Unit,
    onInstall: (Int, String, String) -> Unit,
    onCheck: (Int, String, String) -> Unit,
    onOpenWeb: (Int) -> Unit,
    onStop: () -> Unit,
    onRemove: () -> Unit
) {
    var passwordFocused by rememberSaveable { mutableStateOf(false) }
    val port = portInput.toIntOrNull()?.takeIf { it in 1..65533 }
    OutboundDialogFrame("Прокси VPS", status, progressTitle, progress, onDismiss) {
        OutboundDialogStateBanner(indicator)
        Text(
            "На этом же VPS будут созданы два входа с одним логином и паролем: SOCKS5 и HTTP. Это удобно как прокси, но IP не маскирует: наружу будет виден текущий сервер.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        OutlinedTextField(
            value = portInput,
            onValueChange = { onPortChanged(it.filter(Char::isDigit).take(5)) },
            label = { Text("Порт SOCKS5") },
            placeholder = { Text("1080") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp)
        )
        OutlinedTextField(
            value = loginInput,
            onValueChange = { onLoginChanged(it.filter { c -> !c.isWhitespace() }.take(40)) },
            label = { Text("Логин") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp)
        )
        OutlinedTextField(
            value = passwordInput,
            onValueChange = { onPasswordChanged(it.filter { c -> !c.isWhitespace() }.take(80)) },
            label = { Text("Пароль") },
            singleLine = true,
            visualTransformation = if (passwordFocused) VisualTransformation.None else PasswordVisualTransformation(),
            modifier = Modifier
                .fillMaxWidth()
                .onFocusChanged { passwordFocused = it.isFocused },
            shape = RoundedCornerShape(16.dp)
        )
        if (port != null) {
            Text(
                "SOCKS5: порт $port. HTTP: порт ${port + 1}. Веб-страница 3proxy: порт ${port + 2}. Логин и пароль одинаковые для всех вариантов. «Проверить» не устанавливает прокси, а подключается к уже запущенному SOCKS5 с этими данными.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        DialogButtons(
            busy = busy,
            primaryBusy = actionTitle.contains("Устанавливаю", ignoreCase = true),
            secondaryBusy = actionTitle.contains("Проверяю прокси", ignoreCase = true),
            primaryText = "Установить",
            primaryBusyText = "Установка...",
            primaryEnabled = port != null && loginInput.isNotBlank() && passwordInput.length >= 8,
            onPrimary = { onInstall(port ?: 1080, loginInput, passwordInput) },
            secondaryText = "Проверить",
            secondaryBusyText = "Проверка...",
            secondaryEnabled = port != null && loginInput.isNotBlank() && passwordInput.isNotBlank(),
            onSecondary = { onCheck(port ?: 1080, loginInput, passwordInput) }
        )
        OutlinedButton(
            onClick = { onOpenWeb(port ?: 1080) },
            enabled = !busy && port != null && stopEnabled,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
            shape = RoundedCornerShape(16.dp),
            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
        ) {
            Text("Открыть веб-страницу 3proxy", textAlign = TextAlign.Center)
        }
        Row(
            modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            OutlinedButton(
                onClick = onStop,
                enabled = !busy && stopEnabled,
                modifier = Modifier.weight(1f).fillMaxHeight().heightIn(min = 48.dp),
                shape = RoundedCornerShape(16.dp),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 8.dp)
            ) {
                val stopping = actionTitle.contains("Останавливаю", ignoreCase = true)
                if (stopping) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.width(6.dp))
                }
                Text(if (stopping) "Остановка..." else "Остановить", textAlign = TextAlign.Center)
            }
            OutlinedButton(
                onClick = onRemove,
                enabled = !busy && removeEnabled,
                modifier = Modifier.weight(1f).fillMaxHeight().heightIn(min = 48.dp),
                shape = RoundedCornerShape(16.dp),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 8.dp)
            ) {
                val removing = actionTitle.contains("Удаляю", ignoreCase = true)
                if (removing) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.width(6.dp))
                }
                Text(if (removing) "Удаление..." else "Удалить", textAlign = TextAlign.Center)
            }
        }
    }
}

@Composable
private fun ExternalProxyDialog(
    busy: Boolean,
    status: String,
    actionTitle: String,
    progressTitle: String,
    progress: Float,
    indicator: OutboundModeIndicator,
    kind: ProxyKind,
    hostInput: String,
    portInput: String,
    loginInput: String,
    passwordInput: String,
    disableEnabled: Boolean,
    onKindChanged: (ProxyKind) -> Unit,
    onHostChanged: (String) -> Unit,
    onPortChanged: (String) -> Unit,
    onLoginChanged: (String) -> Unit,
    onPasswordChanged: (String) -> Unit,
    onDismiss: () -> Unit,
    onCheck: (ProxyKind, String, Int, String, String) -> Unit,
    onEnable: (ProxyKind, String, Int, String, String) -> Unit,
    onDisable: () -> Unit
) {
    var passwordFocused by rememberSaveable { mutableStateOf(false) }
    val port = portInput.toIntOrNull()?.takeIf { it in 1..65535 }
    val hostValid = hostInput.isValidPublicHost()
    OutboundDialogFrame("Внешний TCP-прокси", status, progressTitle, progress, onDismiss) {
        OutboundDialogStateBanner(indicator)
        Text(
            "WDTT будет отправлять обычные TCP-подключения пользователей через выбранный прокси. UDP, QUIC и часть голосового/звонкового трафика могут идти напрямую.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ProxyKind.entries.forEach { item ->
                FilterChip(
                    selected = kind == item,
                    onClick = { onKindChanged(item) },
                    label = { Text(item.label) }
                )
            }
        }
        OutlinedTextField(
            value = hostInput,
            onValueChange = { onHostChanged(it.filter { c -> !c.isWhitespace() }) },
            label = { Text("Адрес внешнего прокси") },
            placeholder = { Text("proxy.example.com") },
            singleLine = true,
            isError = hostInput.isNotBlank() && !hostValid,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp)
        )
        OutlinedTextField(
            value = portInput,
            onValueChange = { onPortChanged(it.filter(Char::isDigit).take(5)) },
            label = { Text("Порт") },
            placeholder = { Text("1080") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp)
        )
        OutlinedTextField(
            value = loginInput,
            onValueChange = { onLoginChanged(it.filter { c -> !c.isWhitespace() }.take(80)) },
            label = { Text("Логин, если нужен") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp)
        )
        OutlinedTextField(
            value = passwordInput,
            onValueChange = { onPasswordChanged(it.filter { c -> !c.isWhitespace() }.take(120)) },
            label = { Text("Пароль, если нужен") },
            singleLine = true,
            visualTransformation = if (passwordFocused) VisualTransformation.None else PasswordVisualTransformation(),
            modifier = Modifier
                .fillMaxWidth()
                .onFocusChanged { passwordFocused = it.isFocused },
            shape = RoundedCornerShape(16.dp)
        )
        Text(
            "При включении прежний внешний выход WDTT будет выключен, затем начнёт работать этот прокси. Это маскирует только поддерживаемый TCP-трафик пользователей; обычный интернет самого сервера не меняется.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error
        )
        DialogButtons(
            busy = busy,
            primaryBusy = actionTitle.contains("включаю внешний TCP-прокси", ignoreCase = true),
            secondaryBusy = actionTitle.contains("Проверяю доступность", ignoreCase = true),
            primaryText = "Включить",
            primaryBusyText = "Включение...",
            primaryEnabled = hostValid && port != null,
            onPrimary = { onEnable(kind, hostInput.trim(), port ?: 1080, loginInput, passwordInput) },
            secondaryText = "Проверить",
            secondaryBusyText = "Проверка...",
            secondaryEnabled = hostValid && port != null,
            onSecondary = { onCheck(kind, hostInput.trim(), port ?: 1080, loginInput, passwordInput) }
        )
        OutlinedButton(onClick = onDisable, enabled = !busy && disableEnabled, modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp)) {
            val disabling = actionTitle.contains("Возвращаю", ignoreCase = true)
            if (disabling) {
                CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(6.dp))
            }
            Text(if (disabling) "Отключение..." else "Отключить")
        }
    }
}

@Composable
private fun WireGuardExitVpsDialog(
    busy: Boolean,
    status: String,
    actionTitle: String,
    progressTitle: String,
    progress: Float,
    indicator: OutboundModeIndicator,
    hostInput: String,
    sshPortInput: String,
    userInput: String,
    passwordInput: String,
    wgPortInput: String,
    dnsInput: String,
    disableEnabled: Boolean,
    checkEnabled: Boolean,
    onHostChanged: (String) -> Unit,
    onSshPortChanged: (String) -> Unit,
    onUserChanged: (String) -> Unit,
    onPasswordChanged: (String) -> Unit,
    onWgPortChanged: (String) -> Unit,
    onDnsChanged: (String) -> Unit,
    onDismiss: () -> Unit,
    onInstall: (String, Int, String, String, Int, String) -> Unit,
    onCheck: () -> Unit,
    onDisable: () -> Unit
) {
    var passwordFocused by rememberSaveable { mutableStateOf(false) }
    val hostValid = hostInput.isValidPublicHost()
    val sshPort = sshPortInput.toIntOrNull()?.takeIf { it in 1..65535 }
    val wgPort = wgPortInput.toIntOrNull()?.takeIf { it in 1..65535 }
    OutboundDialogFrame("Выход через другой сервер", status, progressTitle, progress, onDismiss) {
        OutboundDialogStateBanner(indicator)
        Text(
            "WDTT Plus подключит текущий сервер к другому VPS по WireGuard и будет выпускать пользователей WDTT в интернет через этот второй сервер. Это самый понятный вариант для отдельного выходного IP.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        OutlinedTextField(
            value = hostInput,
            onValueChange = { onHostChanged(it.filter { c -> !c.isWhitespace() }) },
            label = { Text("Адрес другого сервера") },
            placeholder = { Text("exit.example.com") },
            singleLine = true,
            isError = hostInput.isNotBlank() && !hostValid,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp)
        )
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
            OutlinedTextField(
                value = userInput,
                onValueChange = { onUserChanged(it.filter { c -> !c.isWhitespace() }) },
                label = { Text("Логин SSH") },
                singleLine = true,
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(16.dp)
            )
            OutlinedTextField(
                value = sshPortInput,
                onValueChange = { onSshPortChanged(it.filter(Char::isDigit).take(5)) },
                label = { Text("SSH порт") },
                singleLine = true,
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(16.dp)
            )
        }
        OutlinedTextField(
            value = passwordInput,
            onValueChange = { onPasswordChanged(it) },
            label = { Text("SSH-пароль другого сервера") },
            singleLine = true,
            visualTransformation = if (passwordFocused) VisualTransformation.None else PasswordVisualTransformation(),
            modifier = Modifier
                .fillMaxWidth()
                .onFocusChanged { passwordFocused = it.isFocused },
            shape = RoundedCornerShape(16.dp)
        )
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
            OutlinedTextField(
                value = wgPortInput,
                onValueChange = { onWgPortChanged(it.filter(Char::isDigit).take(5)) },
                label = { Text("Порт WireGuard") },
                singleLine = true,
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(16.dp)
            )
            OutlinedTextField(
                value = dnsInput,
                onValueChange = { onDnsChanged(it.filter { c -> !c.isWhitespace() }) },
                label = { Text("DNS") },
                singleLine = true,
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(16.dp)
            )
        }
        Text(
            "Если настройка не получится, WDTT Plus попытается вернуть прямой выход через текущий сервер. Приватные ключи остаются на серверах и не показываются в обычном логе.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error
        )
        DialogButtons(
            busy = busy,
            primaryBusy = actionTitle.contains("Настраиваю WireGuard", ignoreCase = true),
            secondaryBusy = actionTitle.contains("Проверяю выход", ignoreCase = true),
            primaryText = "Настроить выход",
            primaryBusyText = "Настройка...",
            primaryEnabled = hostValid && sshPort != null && wgPort != null && userInput.isNotBlank() && passwordInput.isNotBlank(),
            onPrimary = { onInstall(hostInput.trim(), sshPort ?: 22, userInput, passwordInput, wgPort ?: 51820, dnsInput) },
            secondaryText = "Проверить",
            secondaryBusyText = "Проверка...",
            secondaryEnabled = checkEnabled,
            onSecondary = onCheck
        )
        OutlinedButton(onClick = onDisable, enabled = !busy && disableEnabled, modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp)) {
            val disabling = actionTitle.contains("Возвращаю", ignoreCase = true)
            if (disabling) {
                CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(6.dp))
            }
            Text(if (disabling) "Отключение..." else "Отключить")
        }
    }
}

@Composable
private fun FreeWarpDialog(
    busy: Boolean,
    status: String,
    actionTitle: String,
    progressTitle: String,
    progress: Float,
    indicator: OutboundModeIndicator,
    mtuInput: String,
    disableEnabled: Boolean,
    checkEnabled: Boolean,
    restartEnabled: Boolean,
    updateToolEnabled: Boolean,
    deleteEnabled: Boolean,
    onMtuChanged: (String) -> Unit,
    onDismiss: () -> Unit,
    onInstall: (Int) -> Unit,
    onCheck: () -> Unit,
    onRestart: () -> Unit,
    onUpdateTool: () -> Unit,
    onDisable: () -> Unit,
    onDelete: () -> Unit
) {
    var termsAccepted by rememberSaveable { mutableStateOf(false) }
    var confirmDelete by rememberSaveable { mutableStateOf(false) }
    val mtu = mtuInput.toIntOrNull()?.takeIf { it in 1280..1500 }
    OutboundDialogFrame("Бесплатный WARP", status, progressTitle, progress, onDismiss) {
        OutboundDialogStateBanner(indicator)
        Text(
            "WDTT Plus автоматически зарегистрирует бесплатный Cloudflare WARP и направит через него только трафик WDTT-пользователей. Второй сервер и готовый конфиг не нужны.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            "Сайты будут видеть общий выходной IP Cloudflare вместо IP вашего VPS. Адрес может меняться, страну и постоянный IP выбрать нельзя; отдельные сайты могут ограничивать WARP.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            "Для регистрации используется неофициальный wgcf $WGCF_VERSION. WDTT Plus скачивает закреплённую Linux amd64-сборку и перед запуском проверяет её SHA-256. Ключи и профиль остаются на сервере с правами 600.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        OutlinedTextField(
            value = mtuInput,
            onValueChange = { onMtuChanged(it.filter(Char::isDigit).take(4)) },
            label = { Text("MTU WARP") },
            supportingText = {
                Text(
                    if (mtu == null) "Допустимо от 1280 до 1500."
                    else "1280 — максимальная совместимость; 1392/1420 иногда дают лучшую скорость."
                )
            },
            isError = mtu == null,
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp)
        )
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf(1280, 1392, 1420).forEach { value ->
                OutlinedButton(
                    onClick = { onMtuChanged(value.toString()) },
                    enabled = !busy,
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 4.dp, vertical = 6.dp),
                    shape = RoundedCornerShape(14.dp)
                ) {
                    Text(value.toString())
                }
            }
        }
        Text(
            "Изменение MTU применяется при «Установить / восстановить» без создания новой регистрации, если сохранённый аккаунт WARP уже есть на сервере. Остальные параметры WARP защищены от ручного ввода. DNS из профиля не меняет DNS самого VPS.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            "Устанавливается только бесплатный WARP, без WARP+ и Zero Trust. При нестабильном первом handshake приложение сделает до трёх попыток; если Cloudflare ограничил WARP в регионе, включение будет отменено и сохранится прямой выход.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.tertiary
        )
        Text(
            "«Отключить» только возвращает прямой выход и оставляет регистрацию WARP на сервере. «Удалить» стирает регистрацию, ключи, профиль и автопроверку; следующая установка создаст WARP заново.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Surface(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(16.dp))
                .clickable(enabled = !busy) { termsAccepted = !termsAccepted },
            shape = RoundedCornerShape(16.dp),
            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Checkbox(
                    checked = termsAccepted,
                    onCheckedChange = { termsAccepted = it },
                    enabled = !busy
                )
                Text(
                    "Я разрешаю создать WARP-регистрацию и принимаю условия Cloudflare: cloudflare.com/terms",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.weight(1f)
                )
            }
        }
        val installing = actionTitle.contains("Устанавливаю", ignoreCase = true)
        Button(
            onClick = { mtu?.let(onInstall) },
            enabled = !busy && termsAccepted && mtu != null,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
            shape = RoundedCornerShape(16.dp)
        ) {
            if (installing) {
                CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(8.dp))
            }
            Text(if (installing) "Установка..." else "Установить / восстановить", fontWeight = FontWeight.Bold)
        }
        OutlinedButton(
            onClick = onCheck,
            enabled = !busy && checkEnabled,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
            shape = RoundedCornerShape(16.dp)
        ) {
            val checking = actionTitle == "Проверяю бесплатный WARP"
            if (checking) {
                CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(6.dp))
            }
            Text(if (checking) "Проверка..." else "Проверить", fontWeight = FontWeight.SemiBold)
        }
        OutlinedButton(
            onClick = onRestart,
            enabled = !busy && restartEnabled,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
            shape = RoundedCornerShape(16.dp)
        ) {
            val restarting = actionTitle.contains("Перезапускаю", ignoreCase = true)
            if (restarting) {
                CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(6.dp))
            }
            Text(if (restarting) "Перезапуск..." else "Перезапустить и проверить", fontWeight = FontWeight.SemiBold)
        }
        OutlinedButton(
            onClick = onUpdateTool,
            enabled = !busy && updateToolEnabled,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
            shape = RoundedCornerShape(16.dp)
        ) {
            val updating = actionTitle.contains("обновление wgcf", ignoreCase = true)
            if (updating) {
                CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(6.dp))
            }
            Text(if (updating) "Обновление..." else "Проверить обновление wgcf", fontWeight = FontWeight.SemiBold)
        }
        Row(
            modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            OutlinedButton(
                onClick = onDisable,
                enabled = !busy && disableEnabled,
                modifier = Modifier.weight(1f).fillMaxHeight().heightIn(min = 48.dp),
                shape = RoundedCornerShape(16.dp),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 8.dp)
            ) {
                Text("Отключить", textAlign = TextAlign.Center)
            }
            OutlinedButton(
                onClick = { confirmDelete = true },
                enabled = !busy && deleteEnabled,
                modifier = Modifier.weight(1f).fillMaxHeight().heightIn(min = 48.dp),
                shape = RoundedCornerShape(16.dp),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 8.dp)
            ) {
                Text("Удалить", textAlign = TextAlign.Center)
            }
        }
    }
    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("Удалить бесплатный WARP?") },
            text = {
                Text("Регистрация, ключи, WireGuard-профиль и автоматическая проверка WARP будут удалены с сервера. Трафик WDTT вернётся на прямой выход через VPS.")
            },
            confirmButton = {
                Button(onClick = {
                    confirmDelete = false
                    onDelete()
                }) { Text("Удалить") }
            },
            dismissButton = {
                TextButton(onClick = { confirmDelete = false }) { Text("Отмена") }
            }
        )
    }
}

@Composable
private fun ImportedWireGuardDialog(
    busy: Boolean,
    status: String,
    actionTitle: String,
    progressTitle: String,
    progress: Float,
    indicator: OutboundModeIndicator,
    initialConfig: String,
    disableEnabled: Boolean,
    serverCheckEnabled: Boolean,
    deleteEnabled: Boolean,
    onConfigChanged: (String) -> Unit,
    onPickFile: () -> Unit,
    onDismiss: () -> Unit,
    onValidate: (String) -> Unit,
    onEnable: (String) -> Unit,
    onDisable: () -> Unit,
    onServerCheck: () -> Unit,
    onDelete: () -> Unit
) {
    var configText by rememberSaveable(initialConfig) { mutableStateOf(initialConfig) }
    val valid = configText.isNotBlank() && validateWireGuardConfigText(configText).isSuccess
    OutboundDialogFrame("VPN/WireGuard-файл", status, progressTitle, progress, onDismiss) {
        OutboundDialogStateBanner(indicator)
        Text(
            "Можно выбрать готовый WireGuard .conf от VPN-провайдера, собственного WARP/WARP+ или другой совместимой службы. Для автоматической бесплатной регистрации WARP используйте отдельный вариант «Бесплатный WARP».",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            "WDTT Plus применит файл только к пользователям WDTT и не поменяет обычный интернет самого сервера. Перед включением приложение проверит, что на сервере нет конфликтующего выходного маршрута.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        OutlinedButton(onClick = onPickFile, enabled = !busy, modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp)) {
            Text("Выбрать VPN/WireGuard-файл")
        }
        OutlinedTextField(
            value = configText,
            onValueChange = {
                configText = it
                onConfigChanged(it)
            },
            label = { Text("Содержимое WireGuard .conf") },
            minLines = 8,
            maxLines = 14,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp)
        )
        Text(
            "Команды запуска и остановки из выбранного файла не выполняются. Это защита от настроек, которые могли бы изменить сеть всего сервера.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error
        )
        Text(
            "«Отключить» возвращает прямой выход, но оставляет файл для повторного включения. «Удалить» стирает рабочий файл и сохранённую копию из серверного профиля.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        DialogButtons(
            busy = busy,
            primaryBusy = actionTitle.contains("Включаю VPN/WireGuard", ignoreCase = true),
            secondaryBusy = false,
            primaryText = "Включить",
            primaryBusyText = "Включение...",
            primaryEnabled = valid,
            onPrimary = { onEnable(configText) },
            secondaryText = "Проверить файл",
            secondaryBusyText = "Проверка...",
            onSecondary = { onValidate(configText) }
        )
        OutlinedButton(
            onClick = onServerCheck,
            enabled = !busy && serverCheckEnabled,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
            shape = RoundedCornerShape(16.dp)
        ) {
            val checkingServer = actionTitle.contains("Проверяю установленный", ignoreCase = true)
            if (checkingServer) {
                CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(6.dp))
            }
            Text(if (checkingServer) "Проверка..." else "Проверить на сервере", fontWeight = FontWeight.SemiBold)
        }
        Row(
            modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            OutlinedButton(
                onClick = onDisable,
                enabled = !busy && disableEnabled,
                modifier = Modifier.weight(1f).fillMaxHeight().heightIn(min = 48.dp),
                shape = RoundedCornerShape(16.dp),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 8.dp)
            ) {
                val disabling = actionTitle.contains("Возвращаю", ignoreCase = true)
                if (disabling) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.width(6.dp))
                }
                Text(if (disabling) "Отключение..." else "Отключить", textAlign = TextAlign.Center)
            }
            OutlinedButton(
                onClick = onDelete,
                enabled = !busy && deleteEnabled,
                modifier = Modifier.weight(1f).fillMaxHeight().heightIn(min = 48.dp),
                shape = RoundedCornerShape(16.dp),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 8.dp)
            ) {
                val deleting = actionTitle.contains("Удаляю WireGuard", ignoreCase = true)
                if (deleting) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.width(6.dp))
                }
                Text(if (deleting) "Удаление..." else "Удалить", textAlign = TextAlign.Center)
            }
        }
    }
}

@Composable
private fun OutboundDiagnosticsDialog(
    busy: Boolean,
    status: String,
    actionTitle: String,
    progressTitle: String,
    progress: Float,
    cleanupEnabled: Boolean,
    onDismiss: () -> Unit,
    onRun: () -> Unit,
    onCleanup: () -> Unit
) {
    OutboundDialogFrame("Диагностика выхода WDTT", status, progressTitle, progress, onDismiss) {
        Text(
            "Диагностика показывает, какой выход сейчас включён, какой внешний IP видит сервер и какие сетевые правила применены для WDTT.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        DialogButtons(
            busy = busy,
            primaryBusy = actionTitle.contains("диагност", ignoreCase = true),
            secondaryBusy = actionTitle.contains("Возвращаю", ignoreCase = true),
            primaryText = "Показать статус",
            primaryBusyText = "Диагностика...",
            primaryEnabled = true,
            onPrimary = onRun,
            secondaryText = "Вернуть прямой выход",
            secondaryBusyText = "Возврат...",
            secondaryEnabled = cleanupEnabled,
            onSecondary = onCleanup
        )
    }
}

@Composable
private fun OutboundStatusMessage(status: String) {
    val isError = status.startsWith("Ошибка", true) ||
        status.contains("не удалось", true) ||
        status.contains("запрещ", true) ||
        status.startsWith("error:", true)
    Surface(
        shape = RoundedCornerShape(14.dp),
        color = if (isError) {
            MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.55f)
        } else {
            MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f)
        },
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.22f))
    ) {
        Text(
            status,
            modifier = Modifier.fillMaxWidth().padding(12.dp),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurface
        )
    }
}

@Composable
private fun OutboundDialogFrame(
    title: String,
    status: String,
    progressTitle: String,
    progress: Float,
    onDismiss: () -> Unit,
    content: @Composable ColumnScope.() -> Unit
) {
    androidx.compose.ui.window.Dialog(onDismissRequest = onDismiss) {
        BoxWithConstraints(
            modifier = Modifier.fillMaxSize().padding(8.dp),
            contentAlignment = Alignment.Center
        ) {
            Surface(
                modifier = Modifier
                    .fillMaxWidth(0.96f)
                    .widthIn(max = 720.dp)
                    .heightIn(max = maxHeight * 0.92f),
                shape = RoundedCornerShape(24.dp),
                color = MaterialTheme.colorScheme.surface,
                contentColor = MaterialTheme.colorScheme.onSurface,
                tonalElevation = 8.dp
            ) {
                Column(
                    modifier = Modifier
                        .padding(24.dp)
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(14.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            title,
                            modifier = Modifier.weight(1f),
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold
                        )
                        IconButton(onClick = onDismiss) {
                            Icon(Icons.Default.Close, contentDescription = "Закрыть")
                        }
                    }
                    content()
                    if (progressTitle.isNotBlank()) {
                        DeployProgressPanel(
                            title = progressTitle,
                            progress = progress,
                            determinate = true
                        )
                    }
                    if (status.isNotBlank()) {
                        OutboundStatusMessage(status)
                    }
                    Spacer(Modifier.height(4.dp))
                }
            }
        }
    }
}

@Composable
private fun DialogButtons(
    busy: Boolean,
    primaryBusy: Boolean = busy,
    secondaryBusy: Boolean = false,
    primaryText: String,
    primaryBusyText: String = busyButtonText(primaryText),
    primaryEnabled: Boolean,
    onPrimary: () -> Unit,
    secondaryText: String,
    secondaryBusyText: String = busyButtonText(secondaryText),
    secondaryEnabled: Boolean = true,
    onSecondary: () -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min),
        horizontalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        OutlinedButton(
            onClick = onSecondary,
            enabled = !busy && secondaryEnabled,
            modifier = Modifier.weight(1f).fillMaxHeight().heightIn(min = 48.dp),
            shape = RoundedCornerShape(16.dp),
            contentPadding = PaddingValues(horizontal = if (secondaryBusy) 6.dp else 10.dp, vertical = 8.dp)
        ) {
            if (secondaryBusy) {
                CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(6.dp))
            }
            Text(
                if (secondaryBusy) secondaryBusyText else secondaryText,
                fontWeight = FontWeight.SemiBold,
                textAlign = TextAlign.Center
            )
        }
        Button(
            onClick = onPrimary,
            enabled = !busy && primaryEnabled,
            modifier = Modifier.weight(1f).fillMaxHeight().heightIn(min = 48.dp),
            shape = RoundedCornerShape(16.dp),
            contentPadding = PaddingValues(horizontal = if (primaryBusy) 6.dp else 10.dp, vertical = 8.dp)
        ) {
            if (primaryBusy) {
                CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(6.dp))
            }
            Text(
                if (primaryBusy) primaryBusyText else primaryText,
                fontWeight = FontWeight.Bold,
                textAlign = TextAlign.Center
            )
        }
    }
}

private fun busyButtonText(text: String): String = when {
    text.contains("Установ", ignoreCase = true) -> "Установка..."
    text.contains("Провер", ignoreCase = true) -> "Проверка..."
    text.contains("Включ", ignoreCase = true) -> "Включение..."
    text.contains("Настро", ignoreCase = true) -> "Настройка..."
    text.contains("Отключ", ignoreCase = true) -> "Отключение..."
    text.contains("Удал", ignoreCase = true) -> "Удаление..."
    text.contains("Вернуть", ignoreCase = true) -> "Возврат..."
    text.contains("Показать", ignoreCase = true) -> "Проверка..."
    else -> "Выполняю..."
}

// ==================== SSH ====================

private class SSHClient(private val session: Session, private val pass: String) {

    fun exec(command: String, timeout: Long = CMD_TIMEOUT): String {
        if (!session.isConnected) {
            DeployManager.writeError("SSH exec: сессия разорвана перед командой: ${command.take(80)}")
            return "error: session is down"
        }

        var channel: ChannelExec? = null
        val result = StringBuilder()

        return try {
            channel = session.openChannel("exec") as ChannelExec
            val cmd = if (command.contains("sudo") && !command.contains("sudo -S")) {
                command.replace("sudo ", "sudo -S ")
            } else command

            channel.setCommand(cmd)
            val outStream = channel.outputStream
            val input = channel.inputStream
            val err = channel.errStream
            channel.connect(15000)

            if (cmd.contains("sudo -S")) {
                outStream.write("$pass\n".toByteArray())
                outStream.flush()
            }

            val reader = input.bufferedReader()
            val errReader = err.bufferedReader()
            val startTime = System.currentTimeMillis()
            val progressRegex = Regex("^WDTT_PROGRESS\\|(\\d+\\.?\\d*)\\|(.+)$")

            while (!channel.isClosed || reader.ready() || errReader.ready()) {
                if (System.currentTimeMillis() - startTime > timeout) {
                    DeployManager.writeError("SSH timeout (${timeout/1000}s): ${command.take(80)}")
                    try { channel.disconnect() } catch (_: Exception) {}
                    return "error: timeout"
                }

                if (reader.ready()) {
                    val line = reader.readLine()
                    if (line != null) {
                        val match = progressRegex.find(line.trim())
                        if (match != null) {
                            val p = match.groupValues[1].toFloatOrNull() ?: 0f
                            DeployManager.updateProgress(p, match.groupValues[2])
                        } else if (!line.contains("WDTT_PROGRESS")) {
                            val clean = line.replace(Regex("\u001B\\[[;\\d]*m"), "")
                            result.appendLine(clean)
                            if (clean.contains("[✗]") || clean.contains("FAIL") ||
                                (clean.contains("error", true) && !clean.contains("2>/dev/null"))) {
                                DeployManager.writeError("REMOTE: $clean")
                                TunnelManager.addDeployErrorLog("REMOTE: $clean")
                            }
                        }
                    }
                }
                if (errReader.ready()) {
                    val line = errReader.readLine()
                    if (line != null && !line.contains("password for")) {
                        val clean = line.replace(Regex("\u001B\\[[;\\d]*m"), "")
                        result.appendLine(clean)
                        if (clean.isNotBlank() && !clean.startsWith("Warning:")) {
                            DeployManager.writeError("STDERR: $clean")
                            TunnelManager.addDeployErrorLog("STDERR: $clean")
                        }
                    }
                }
                if (!reader.ready() && !errReader.ready()) Thread.sleep(100)
            }

            result.toString()
        } catch (e: Exception) {
            DeployManager.writeError("SSH exec error: ${e.message} | cmd: ${command.take(80)}")
            TunnelManager.addDeployErrorLog("SSH exec error: ${e.message}")
            "error: ${e.message}"
        } finally {
            try { channel?.disconnect() } catch (_: Exception) {}
        }
    }

    fun upload(localFile: File, remotePath: String) {
        if (!session.isConnected) {
            DeployManager.writeError("SSH upload: сессия разорвана")
            throw Exception("Session is down")
        }
        var sftp: ChannelSftp? = null
        try {
            sftp = session.openChannel("sftp") as ChannelSftp
            sftp.connect(15000)
            sftp.put(localFile.absolutePath, remotePath)
        } catch (e: Exception) {
            DeployManager.writeError("SFTP upload error: ${e.message} | file: ${localFile.name}")
            throw e
        } finally {
            try { sftp?.disconnect() } catch (_: Exception) {}
        }
    }
}

private fun createSSHSession(host: String, user: String, pass: String, port: Int = 22): Session {
    val jsch = JSch()
    val session = jsch.getSession(user, host, port)
    session.setPassword(pass)
    session.setConfig(Properties().apply {
        put("StrictHostKeyChecking", "no")
        put("ServerAliveInterval", "10")
        put("ServerAliveCountMax", "6")
        put("ConnectTimeout", "15000")
        put("PreferredAuthentications", "password,keyboard-interactive")
    })
    session.connect(20000)
    return session
}

private fun shellQuote(value: String): String {
    return "'" + value.replace("'", "'\"'\"'") + "'"
}

private fun rootCommand(command: String): String {
    val quoted = shellQuote(command)
    return "if command -v sudo >/dev/null 2>&1; then sudo bash -c $quoted; " +
        "elif [ \"\$(id -u)\" = \"0\" ]; then bash -c $quoted; " +
        "else echo 'error: root privileges required and sudo not found'; exit 1; fi"
}

private fun shellScript(vararg blocks: String): String =
    blocks.joinToString("\n") { it.trimIndent().trim('\n') }.trim() + "\n"

private fun randomToken(length: Int): String {
    val alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    val random = SecureRandom()
    return buildString(length) {
        repeat(length) { append(alphabet[random.nextInt(alphabet.length)]) }
    }
}

private suspend fun readTextFromUri(context: Context, uri: Uri): String = withContext(Dispatchers.IO) {
    context.contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
        ?: throw IllegalArgumentException("не удалось открыть файл")
}

private suspend fun runRootScript(
    context: Context,
    target: OutboundSshTarget,
    script: String,
    timeout: Long = CMD_TIMEOUT
): String = withContext(Dispatchers.IO) {
    var session: Session? = null
    val scriptFile = File(context.cacheDir, "wdtt-outbound-${System.currentTimeMillis()}.sh")
    val remotePath = "/tmp/${scriptFile.name}"
    try {
        scriptFile.writeText(script.trimIndent() + "\n")
        session = createSSHSession(target.host, target.user, target.pass, target.port)
        val ssh = SSHClient(session, target.pass)
        ssh.upload(scriptFile, remotePath)
        val output = ssh.exec(
            rootCommand("chmod 700 $remotePath; bash $remotePath; code=\$?; rm -f $remotePath; exit \$code"),
            timeout = timeout
        )
        markerValue(output, "WDTT_ERROR")?.let { throw IllegalStateException(output.trim().take(1200)) }
        if (output.startsWith("error:", ignoreCase = true) || output.contains("\nerror:", ignoreCase = true)) {
            throw IllegalStateException(output.trim().take(500))
        }
        output.trim()
    } finally {
        scriptFile.delete()
        try { session?.disconnect() } catch (_: Exception) {}
    }
}

private fun outboundShellPrelude(): String = """
    set -e
    WDTT_SUBNET="${'$'}(ip -4 route show dev wdtt0 scope link 2>/dev/null | awk '{print ${'$'}1; exit}')"
    [ -n "${'$'}WDTT_SUBNET" ] || WDTT_SUBNET="10.66.66.0/24"
    WDTT_IFACE="wdtt0"
    WDTT_TABLE="100"
    WDTT_WG_IFACE="wg-wdtt-exit"
    mkdir -p /etc/wdtt /etc/wdtt/outbound /etc/wdtt-plus/wg-exit
    wdtt_ext_iface() {
      ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if (${'$'}i=="dev") {print ${'$'}(i+1); exit}}'
    }
    wdtt_test_source() {
      ip -4 -o addr show dev "${'$'}WDTT_IFACE" scope global 2>/dev/null | awk '{split(${'$'}4, value, "/"); print value[1]; exit}'
    }
    wdtt_install_pkg() {
      if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y >/dev/null 2>&1 || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${'$'}@" >/dev/null
      elif command -v dnf >/dev/null 2>&1; then
        dnf install -y "${'$'}@" >/dev/null
      elif command -v yum >/dev/null 2>&1; then
        yum install -y "${'$'}@" >/dev/null
      elif command -v zypper >/dev/null 2>&1; then
        zypper --non-interactive install -y "${'$'}@" >/dev/null
      elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache "${'$'}@" >/dev/null
      elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm --needed "${'$'}@" >/dev/null
      else
        return 1
      fi
    }
    wdtt_install_redsocks_tools() {
      if command -v apt-get >/dev/null 2>&1; then
        wdtt_install_pkg redsocks curl iptables psmisc iproute2
      elif command -v dnf >/dev/null 2>&1; then
        wdtt_install_pkg redsocks curl iptables psmisc iproute
      elif command -v yum >/dev/null 2>&1; then
        wdtt_install_pkg redsocks curl iptables psmisc iproute
      elif command -v zypper >/dev/null 2>&1; then
        wdtt_install_pkg redsocks curl iptables psmisc iproute2
      elif command -v apk >/dev/null 2>&1; then
        wdtt_install_pkg redsocks curl iptables psmisc iproute2
      elif command -v pacman >/dev/null 2>&1; then
        wdtt_install_pkg redsocks curl iptables psmisc iproute2
      else
        return 1
      fi
    }
    wdtt_install_wireguard_tools() {
      if command -v apt-get >/dev/null 2>&1; then
        wdtt_install_pkg wireguard-tools curl ca-certificates iptables iproute2
      elif command -v dnf >/dev/null 2>&1; then
        wdtt_install_pkg wireguard-tools curl ca-certificates iptables iproute
      elif command -v yum >/dev/null 2>&1; then
        wdtt_install_pkg wireguard-tools curl ca-certificates iptables iproute
      elif command -v zypper >/dev/null 2>&1; then
        wdtt_install_pkg wireguard-tools curl ca-certificates iptables iproute2
      elif command -v apk >/dev/null 2>&1; then
        wdtt_install_pkg wireguard-tools curl ca-certificates iptables iproute2
      elif command -v pacman >/dev/null 2>&1; then
        wdtt_install_pkg wireguard-tools curl ca-certificates iptables iproute2
      else
        return 1
      fi
    }
    wdtt_clear_external_out() {
      systemctl disable --now wdtt-warp-watchdog.timer 2>/dev/null || true
      systemctl disable --now wdtt-wg-exit.service 2>/dev/null || true
      if command -v iptables >/dev/null 2>&1; then
        iptables -t nat -D PREROUTING -i "${'$'}WDTT_IFACE" -p tcp -j WDTT_PROXY_OUT 2>/dev/null || true
        iptables -t nat -F WDTT_PROXY_OUT 2>/dev/null || true
        iptables -t nat -X WDTT_PROXY_OUT 2>/dev/null || true
        iptables -t nat -D POSTROUTING -s "${'$'}WDTT_SUBNET" -o "${'$'}WDTT_WG_IFACE" -m comment --comment WDTT_EXIT -j MASQUERADE 2>/dev/null || true
      fi
      ip rule del from "${'$'}WDTT_SUBNET" table "${'$'}WDTT_TABLE" priority 100 2>/dev/null || true
      ip route flush table "${'$'}WDTT_TABLE" 2>/dev/null || true
      systemctl disable --now wdtt-redsocks 2>/dev/null || systemctl stop wdtt-redsocks 2>/dev/null || true
      wdtt_kill_redsocks_listener
      wg-quick down "${'$'}WDTT_WG_IFACE" 2>/dev/null || true
    }
    wdtt_kill_redsocks_listener() {
      rm -f /run/wdtt-redsocks.pid 2>/dev/null || true
      if command -v fuser >/dev/null 2>&1; then
        fuser -k 12345/tcp >/dev/null 2>&1 || true
      elif command -v ss >/dev/null 2>&1; then
        ss -ltnp 2>/dev/null | awk '/127\\.0\\.0\\.1:12345|\\*:12345/ {print}' | sed -n 's/.*pid=\\([0-9][0-9]*\\).*/\\1/p' | while read -r pid; do
          [ -n "${'$'}pid" ] && kill "${'$'}pid" 2>/dev/null || true
        done
      fi
      if command -v ss >/dev/null 2>&1 && ss -ltnp 2>/dev/null | grep -q ':12345'; then
        pkill -x redsocks 2>/dev/null || true
      fi
      systemctl reset-failed wdtt-redsocks 2>/dev/null || true
    }
    wdtt_proxy_reserved_returns() {
      chain="${'$'}1"
      proxy_ip="${'$'}2"
      for net in 0.0.0.0/8 10.0.0.0/8 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4; do
        iptables -t nat -A "${'$'}chain" -d "${'$'}net" -j RETURN
      done
      [ -n "${'$'}proxy_ip" ] && iptables -t nat -A "${'$'}chain" -d "${'$'}proxy_ip" -j RETURN 2>/dev/null || true
    }
    wdtt_cleanup_proxy_test() {
      iptables -t nat -D OUTPUT -p tcp -m owner --uid-owner 0 -j WDTT_PROXY_TEST 2>/dev/null || true
      iptables -t nat -F WDTT_PROXY_TEST 2>/dev/null || true
      iptables -t nat -X WDTT_PROXY_TEST 2>/dev/null || true
    }
    wdtt_test_redsocks_path() {
      proxy_ip="${'$'}1"
      systemctl is-active --quiet wdtt-redsocks || { echo WDTT_ERROR=external_proxy_service_inactive; return 1; }
      command -v curl >/dev/null 2>&1 || { echo WDTT_ERROR=curl_not_installed; return 1; }
      wdtt_cleanup_proxy_test
      iptables -t nat -N WDTT_PROXY_TEST 2>/dev/null || true
      iptables -t nat -F WDTT_PROXY_TEST
      wdtt_proxy_reserved_returns WDTT_PROXY_TEST "${'$'}proxy_ip"
      iptables -t nat -A WDTT_PROXY_TEST -p tcp -j REDIRECT --to-ports 12345
      if ! iptables -t nat -I OUTPUT -p tcp -m owner --uid-owner 0 -j WDTT_PROXY_TEST 2>/dev/null; then
        wdtt_cleanup_proxy_test
        return 0
      fi
      test_ip="${'$'}(curl -4fsS --connect-timeout 5 --max-time 18 https://api.ipify.org 2>/tmp/wdtt-redsocks-test.err || true)"
      wdtt_cleanup_proxy_test
      [ -n "${'$'}test_ip" ] || { echo WDTT_ERROR=external_proxy_apply_failed; tail -n 20 /var/log/wdtt-redsocks.log 2>/dev/null || true; cat /tmp/wdtt-redsocks-test.err 2>/dev/null || true; return 1; }
      echo "Проверка пути через внешний TCP-прокси успешна. IP через прокси: ${'$'}test_ip"
      return 0
    }
    wdtt_write_mode() {
      mode="${'$'}1"
      detail="${'$'}2"
      cat >/etc/wdtt/outbound.json <<EOF
    {
      "outboundMode": "${'$'}mode",
      "detail": "${'$'}detail",
      "wdttSubnet": "${'$'}WDTT_SUBNET",
      "interface": "${'$'}WDTT_IFACE",
      "routingTable": ${'$'}WDTT_TABLE,
      "updatedAt": "$(date -Is)"
    }
    EOF
    }
""".trimIndent()

private fun outboundReadPrelude(): String = """
    set -e
    WDTT_WG_IFACE="wg-wdtt-exit"
""".trimIndent()

private fun outboundStatusScript(): String = shellScript(
    outboundShellPrelude(),
    """
    MODE="direct"
    if [ -f /etc/wdtt/outbound.json ]; then
      MODE="${'$'}(grep -o '"outboundMode"[[:space:]]*:[[:space:]]*"[^"]*"' /etc/wdtt/outbound.json | sed 's/.*"outboundMode"[[:space:]]*:[[:space:]]*"//;s/".*//' | head -1)"
      [ -n "${'$'}MODE" ] || MODE="direct"
    fi
    case "${'$'}MODE" in
      direct) MODE_LABEL="прямой выход";;
      external_proxy) MODE_LABEL="внешний TCP-прокси";;
      warp_free) MODE_LABEL="бесплатный WARP";;
      imported_wg) MODE_LABEL="VPN/WireGuard-файл";;
      wireguard_vps) MODE_LABEL="выход через другой сервер";;
      *) MODE_LABEL="${'$'}MODE";;
    esac
    SERVER_IP="${'$'}(curl -4fsS --max-time 8 https://api.ipify.org 2>/dev/null || echo 'не удалось определить')"
    echo "Текущий выход WDTT: ${'$'}MODE_LABEL"
    echo "Подсеть клиентов WDTT: ${'$'}WDTT_SUBNET"
    echo "Интерфейс клиентов: ${'$'}WDTT_IFACE"
    echo "Внешний IP самого сервера: ${'$'}SERVER_IP"
    case "${'$'}MODE" in
      direct)
        echo "Проверочный выход WDTT: ${'$'}SERVER_IP (прямой выход)"
        ;;
      warp_free|imported_wg|wireguard_vps)
        TEST_SOURCE="${'$'}(wdtt_test_source)"
        WDTT_EXIT_IP=""
        [ -n "${'$'}TEST_SOURCE" ] && WDTT_EXIT_IP="${'$'}(curl -4fsS --interface "${'$'}TEST_SOURCE" --max-time 12 https://api.ipify.org 2>/dev/null || true)"
        if [ -n "${'$'}WDTT_EXIT_IP" ]; then
          echo "Проверочный выход WDTT: ${'$'}WDTT_EXIT_IP"
        else
          echo "Проверочный выход WDTT: не удалось проверить через ${'$'}WDTT_WG_IFACE"
        fi
        if [ "${'$'}MODE" = "warp_free" ]; then
          WARP_TRACE=""
          [ -n "${'$'}TEST_SOURCE" ] && WARP_TRACE="${'$'}(curl -4fsS --interface "${'$'}TEST_SOURCE" --max-time 15 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null || true)"
          WARP_STATE="${'$'}(printf '%s\n' "${'$'}WARP_TRACE" | sed -n 's/^warp=//p' | head -n 1)"
          echo "Cloudflare WARP: ${'$'}{WARP_STATE:-проверка не пройдена}"
          echo "Автопроверка WARP: ${'$'}(systemctl is-active wdtt-warp-watchdog.timer 2>/dev/null || echo не запущена)"
          echo "wgcf: ${'$'}(cat /etc/wdtt-plus/warp/wgcf-version 2>/dev/null || echo версия неизвестна)"
        fi
        ;;
      external_proxy)
        echo "Проверочный выход WDTT: через внешний TCP-прокси; точный IP смотрите при проверке/диагностике прокси"
        ;;
      *)
        echo "Проверочный выход WDTT: режим не распознан"
        ;;
    esac
    if systemctl is-active wdtt-3proxy >/dev/null 2>&1; then echo "Прокси VPS: служба запущена"; else echo "Прокси VPS: служба остановлена"; fi
    if systemctl is-active wdtt-redsocks >/dev/null 2>&1; then echo "Внешний TCP-прокси для WDTT: включён"; else echo "Внешний TCP-прокси для WDTT: выключен"; fi
    if command -v wg >/dev/null 2>&1 && wg show "${'$'}WDTT_WG_IFACE" >/dev/null 2>&1; then
      echo "WireGuard ${'$'}WDTT_WG_IFACE:"
      wg show "${'$'}WDTT_WG_IFACE" | sed -E 's/(private key: ).*/\1(скрыт)/'
    else
      echo "WireGuard ${'$'}WDTT_WG_IFACE: не запущен"
    fi
    """
)

private suspend fun readOutboundStatus(target: OutboundSshTarget): String = withContext(Dispatchers.IO) {
    var session: Session? = null
    try {
        DeployManager.updateProgress(0.25f, "Подключаюсь к серверу и читаю текущий режим выхода...")
        session = createSSHSession(target.host, target.user, target.pass, target.port)
        val ssh = SSHClient(session, target.pass)
        DeployManager.updateProgress(0.70f, "Проверяю службы прокси и WireGuard...")
        val output = ssh.exec(rootCommand(outboundStatusScript()), timeout = 30000L).trim()
        DeployManager.updateProgress(1f, "Статус выхода получен.")
        output
    } finally {
        try { session?.disconnect() } catch (_: Exception) {}
    }
}

private fun outboundProfileSaveScript(forms: OutboundProfileForms): String {
    val kindName = ProxyKind.entries.firstOrNull { it.name == forms.externalProxyKindName }?.name.orEmpty()
    fun port(value: String): String = value.filter(Char::isDigit).take(5)
    fun line(name: String, value: String): String = "$name=$value"
    fun b64Line(name: String, value: String): String = "$name=${encodeBase64Text(value)}"
    val profileLines = listOf(
        line("VERSION", "1"),
        line("LOCAL_PROXY_PORT", port(forms.localProxyPort)),
        b64Line("LOCAL_PROXY_LOGIN_B64", forms.localProxyLogin),
        b64Line("LOCAL_PROXY_PASSWORD_B64", forms.localProxyPassword),
        line("EXTERNAL_PROXY_KIND", kindName),
        b64Line("EXTERNAL_PROXY_HOST_B64", forms.externalProxyHost),
        line("EXTERNAL_PROXY_PORT", port(forms.externalProxyPort)),
        b64Line("EXTERNAL_PROXY_LOGIN_B64", forms.externalProxyLogin),
        b64Line("EXTERNAL_PROXY_PASSWORD_B64", forms.externalProxyPassword),
        b64Line("WG_VPS_HOST_B64", forms.wireGuardExitHost),
        line("WG_VPS_SSH_PORT", port(forms.wireGuardExitSshPort)),
        b64Line("WG_VPS_USER_B64", forms.wireGuardExitUser),
        b64Line("WG_VPS_PASSWORD_B64", forms.wireGuardExitPassword),
        line("WG_VPS_PORT", port(forms.wireGuardExitPort)),
        b64Line("WG_VPS_DNS_B64", forms.wireGuardExitDns),
        b64Line("IMPORTED_WG_CONFIG_B64", forms.importedWireGuardConfig)
    ).joinToString("\n")
    val profileScript = """
        PROFILE_FILE=/etc/wdtt/outbound-profile.env
        TMP_FILE="${'$'}PROFILE_FILE.tmp"
        cat >"${'$'}TMP_FILE" <<'WDTT_OUTBOUND_PROFILE'
    """.trimIndent() + "\n" + profileLines + "\n" + """
        WDTT_OUTBOUND_PROFILE
        printf 'UPDATED_AT=%s\n' "$(date -Is)" >>"${'$'}TMP_FILE"
        chmod 600 "${'$'}TMP_FILE"
        mv "${'$'}TMP_FILE" "${'$'}PROFILE_FILE"
        echo "Профиль полей выходного IP сохранён на сервере."
    """.trimIndent()
    return shellScript(outboundShellPrelude(), profileScript)
}

private suspend fun writeOutboundProfileToServer(
    context: Context,
    target: OutboundSshTarget,
    forms: OutboundProfileForms
): String = runRootScript(
    context = context,
    target = target,
    script = outboundProfileSaveScript(forms),
    timeout = 30000L
)

private suspend fun saveOutboundProfileMessage(
    context: Context,
    target: OutboundSshTarget,
    forms: OutboundProfileForms,
    successMessage: String
): String = runCatching {
    writeOutboundProfileToServer(context, target, forms)
}.fold(
    onSuccess = { successMessage },
    onFailure = {
        DeployManager.writeError("Outbound profile save failed: ${it.message}")
        "Режим включён, но профиль полей не сохранился на сервере: ${friendlyDeployError(it, "сохранение")}."
    }
)

private fun outboundSnapshotScript(): String = shellScript(
    outboundReadPrelude(),
    """
    PROFILE_FILE=/etc/wdtt/outbound-profile.env
    wdtt_profile_value() {
      key="${'$'}1"
      [ -f "${'$'}PROFILE_FILE" ] || return 0
      grep -E "^${'$'}key=" "${'$'}PROFILE_FILE" 2>/dev/null | tail -n 1 | sed 's/^[^=]*=//'
    }
    wdtt_b64() {
      command -v base64 >/dev/null 2>&1 || return 0
      printf '%s' "${'$'}1" | base64 | tr -d '\n'
    }
    wdtt_file_b64() {
      file="${'$'}1"
      [ -f "${'$'}file" ] || return 0
      command -v base64 >/dev/null 2>&1 || return 0
      base64 "${'$'}file" 2>/dev/null | tr -d '\n'
    }
    wdtt_json_string() {
      file="${'$'}1"
      key="${'$'}2"
      [ -f "${'$'}file" ] || return 0
      grep -o "\"${'$'}key\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "${'$'}file" 2>/dev/null | sed "s/.*\"${'$'}key\"[[:space:]]*:[[:space:]]*\"//;s/\".*//" | head -n 1
    }
    wdtt_json_number() {
      file="${'$'}1"
      key="${'$'}2"
      [ -f "${'$'}file" ] || return 0
      grep -o "\"${'$'}key\"[[:space:]]*:[[:space:]]*[0-9][0-9]*" "${'$'}file" 2>/dev/null | sed "s/.*\"${'$'}key\"[[:space:]]*:[[:space:]]*//" | head -n 1
    }
    wdtt_redsocks_value() {
      key="${'$'}1"
      [ -f /etc/wdtt/redsocks.conf ] || return 0
      sed -n "s/^[[:space:]]*${'$'}key[[:space:]]*=[[:space:]]*//Ip" /etc/wdtt/redsocks.conf 2>/dev/null | head -n 1 | sed 's/[;[:space:]]*$//;s/^"//;s/"$//'
    }
    wdtt_3proxy_login() {
      [ -f /etc/wdtt/3proxy.cfg ] || return 0
      grep -E '^[[:space:]]*users[[:space:]]+' /etc/wdtt/3proxy.cfg 2>/dev/null | head -n 1 | sed -E 's/^[[:space:]]*users[[:space:]]+([^:]+):CL:.*/\1/'
    }
    wdtt_3proxy_password() {
      [ -f /etc/wdtt/3proxy.cfg ] || return 0
      grep -E '^[[:space:]]*users[[:space:]]+' /etc/wdtt/3proxy.cfg 2>/dev/null | head -n 1 | sed -E 's/^[[:space:]]*users[[:space:]]+[^:]+:CL:(.*)$/\1/'
    }
    wdtt_3proxy_port() {
      [ -f /etc/wdtt/3proxy.cfg ] || return 0
      grep -E '^[[:space:]]*socks[[:space:]].*-p[0-9]+' /etc/wdtt/3proxy.cfg 2>/dev/null | head -n 1 | sed -E 's/.*-p([0-9]+).*/\1/'
    }

    MODE="${'$'}(wdtt_json_string /etc/wdtt/outbound.json outboundMode)"
    [ -n "${'$'}MODE" ] || MODE="direct"
    DETAIL="${'$'}(wdtt_json_string /etc/wdtt/outbound.json detail)"
    UPDATED_AT="${'$'}(wdtt_json_string /etc/wdtt/outbound.json updatedAt)"
    HAS_PROFILE=0
    [ -f "${'$'}PROFILE_FILE" ] && HAS_PROFILE=1
    PROFILE_UPDATED_AT="${'$'}(wdtt_profile_value UPDATED_AT)"
    [ -n "${'$'}UPDATED_AT" ] || UPDATED_AT="${'$'}PROFILE_UPDATED_AT"

    LOCAL_PRESENT=0
    if [ -f /etc/wdtt/local-proxy.json ] || [ -f /etc/wdtt/3proxy.cfg ]; then
      LOCAL_PRESENT=1
    fi
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet wdtt-3proxy 2>/dev/null; then
      LOCAL_ACTIVE=1
      LOCAL_PRESENT=1
    else
      LOCAL_ACTIVE=0
    fi
    LOCAL_PORT="${'$'}(wdtt_profile_value LOCAL_PROXY_PORT)"
    [ -n "${'$'}LOCAL_PORT" ] || LOCAL_PORT="${'$'}(wdtt_json_number /etc/wdtt/local-proxy.json socks5Port)"
    [ -n "${'$'}LOCAL_PORT" ] || LOCAL_PORT="${'$'}(wdtt_3proxy_port)"
    LOCAL_LOGIN_B64="${'$'}(wdtt_profile_value LOCAL_PROXY_LOGIN_B64)"
    if [ -z "${'$'}LOCAL_LOGIN_B64" ]; then
      LOCAL_LOGIN="${'$'}(wdtt_json_string /etc/wdtt/local-proxy.json login)"
      [ -n "${'$'}LOCAL_LOGIN" ] || LOCAL_LOGIN="${'$'}(wdtt_3proxy_login)"
      LOCAL_LOGIN_B64="${'$'}(wdtt_b64 "${'$'}LOCAL_LOGIN")"
    fi
    LOCAL_PASSWORD_B64="${'$'}(wdtt_profile_value LOCAL_PROXY_PASSWORD_B64)"
    if [ -z "${'$'}LOCAL_PASSWORD_B64" ]; then
      LOCAL_PASSWORD="${'$'}(wdtt_json_string /etc/wdtt/local-proxy.json password)"
      [ -n "${'$'}LOCAL_PASSWORD" ] || LOCAL_PASSWORD="${'$'}(wdtt_3proxy_password)"
      LOCAL_PASSWORD_B64="${'$'}(wdtt_b64 "${'$'}LOCAL_PASSWORD")"
    fi

    DETAIL_KIND=""
    DETAIL_HOST=""
    DETAIL_PORT=""
    case "${'$'}DETAIL" in
      socks5://*|http://*)
        DETAIL_KIND="${'$'}{DETAIL%%://*}"
        DETAIL_REST="${'$'}{DETAIL#*://}"
        DETAIL_HOST="${'$'}{DETAIL_REST%:*}"
        DETAIL_PORT="${'$'}{DETAIL_REST##*:}"
        ;;
    esac
    REDSOCKS_TYPE="${'$'}(wdtt_redsocks_value type)"
    REDSOCKS_KIND=""
    case "${'$'}REDSOCKS_TYPE" in
      socks5) REDSOCKS_KIND="Socks5";;
      http|http-connect) REDSOCKS_KIND="Http";;
    esac
    EXTERNAL_KIND="${'$'}(wdtt_profile_value EXTERNAL_PROXY_KIND)"
    if [ -z "${'$'}EXTERNAL_KIND" ]; then
      case "${'$'}DETAIL_KIND" in
        socks5) EXTERNAL_KIND="Socks5";;
        http) EXTERNAL_KIND="Http";;
        *) EXTERNAL_KIND="${'$'}REDSOCKS_KIND";;
      esac
    fi
    EXTERNAL_HOST_B64="${'$'}(wdtt_profile_value EXTERNAL_PROXY_HOST_B64)"
    if [ -z "${'$'}EXTERNAL_HOST_B64" ]; then
      EXTERNAL_HOST="${'$'}DETAIL_HOST"
      [ -n "${'$'}EXTERNAL_HOST" ] || EXTERNAL_HOST="${'$'}(wdtt_redsocks_value ip)"
      EXTERNAL_HOST_B64="${'$'}(wdtt_b64 "${'$'}EXTERNAL_HOST")"
    fi
    EXTERNAL_PORT="${'$'}(wdtt_profile_value EXTERNAL_PROXY_PORT)"
    [ -n "${'$'}EXTERNAL_PORT" ] || EXTERNAL_PORT="${'$'}DETAIL_PORT"
    [ -n "${'$'}EXTERNAL_PORT" ] || EXTERNAL_PORT="${'$'}(wdtt_redsocks_value port)"
    EXTERNAL_LOGIN_B64="${'$'}(wdtt_profile_value EXTERNAL_PROXY_LOGIN_B64)"
    [ -n "${'$'}EXTERNAL_LOGIN_B64" ] || EXTERNAL_LOGIN_B64="${'$'}(wdtt_b64 "$(wdtt_redsocks_value login)")"
    EXTERNAL_PASSWORD_B64="${'$'}(wdtt_profile_value EXTERNAL_PROXY_PASSWORD_B64)"
    [ -n "${'$'}EXTERNAL_PASSWORD_B64" ] || EXTERNAL_PASSWORD_B64="${'$'}(wdtt_b64 "$(wdtt_redsocks_value password)")"
    EXTERNAL_PRESENT=0
    if [ -f /etc/wdtt/redsocks.conf ] || [ "${'$'}MODE" = "external_proxy" ] || [ -n "${'$'}EXTERNAL_HOST_B64" ] || [ -n "${'$'}EXTERNAL_PORT" ]; then
      EXTERNAL_PRESENT=1
    fi
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet wdtt-redsocks 2>/dev/null; then
      EXTERNAL_ACTIVE=1
      EXTERNAL_PRESENT=1
    else
      EXTERNAL_ACTIVE=0
    fi

    WG_CONF=""
    [ -f /etc/wireguard/wg-wdtt-exit.conf ] && WG_CONF=/etc/wireguard/wg-wdtt-exit.conf
    [ -z "${'$'}WG_CONF" ] && [ -f /etc/wdtt-plus/wg-exit/wg-wdtt-exit.conf ] && WG_CONF=/etc/wdtt-plus/wg-exit/wg-wdtt-exit.conf
    WG_PRESENT=0
    [ -n "${'$'}WG_CONF" ] && WG_PRESENT=1
    if command -v wg >/dev/null 2>&1 && wg show "${'$'}WDTT_WG_IFACE" >/dev/null 2>&1; then
      WG_ACTIVE=1
      WG_PRESENT=1
    else
      WG_ACTIVE=0
    fi
    WG_ENDPOINT=""
    WG_DNS=""
    WG_MTU=""
    if [ -n "${'$'}WG_CONF" ]; then
      WG_ENDPOINT="${'$'}(sed -n 's/^[[:space:]]*Endpoint[[:space:]]*=[[:space:]]*//Ip' "${'$'}WG_CONF" 2>/dev/null | head -n 1 | tr -d ' ')"
      WG_DNS="${'$'}(sed -n 's/^[[:space:]]*DNS[[:space:]]*=[[:space:]]*//Ip' "${'$'}WG_CONF" 2>/dev/null | head -n 1 | tr -d ' ')"
      WG_MTU="${'$'}(sed -n 's/^[[:space:]]*MTU[[:space:]]*=[[:space:]]*//Ip' "${'$'}WG_CONF" 2>/dev/null | head -n 1 | tr -d ' ')"
    fi
    WG_ENDPOINT_HOST=""
    WG_ENDPOINT_PORT=""
    if [ -n "${'$'}WG_ENDPOINT" ]; then
      WG_ENDPOINT_HOST="${'$'}{WG_ENDPOINT%:*}"
      WG_ENDPOINT_PORT="${'$'}{WG_ENDPOINT##*:}"
      WG_ENDPOINT_HOST="${'$'}{WG_ENDPOINT_HOST#[}"
      WG_ENDPOINT_HOST="${'$'}{WG_ENDPOINT_HOST%]}"
    fi
    WG_VPS_HOST_B64="${'$'}(wdtt_profile_value WG_VPS_HOST_B64)"
    [ -n "${'$'}WG_VPS_HOST_B64" ] || WG_VPS_HOST_B64="${'$'}(wdtt_b64 "${'$'}WG_ENDPOINT_HOST")"
    WG_VPS_SSH_PORT="${'$'}(wdtt_profile_value WG_VPS_SSH_PORT)"
    WG_VPS_USER_B64="${'$'}(wdtt_profile_value WG_VPS_USER_B64)"
    WG_VPS_PASSWORD_B64="${'$'}(wdtt_profile_value WG_VPS_PASSWORD_B64)"
    WG_VPS_PORT="${'$'}(wdtt_profile_value WG_VPS_PORT)"
    [ -n "${'$'}WG_VPS_PORT" ] || WG_VPS_PORT="${'$'}WG_ENDPOINT_PORT"
    WG_VPS_DNS_B64="${'$'}(wdtt_profile_value WG_VPS_DNS_B64)"
    [ -n "${'$'}WG_VPS_DNS_B64" ] || WG_VPS_DNS_B64="${'$'}(wdtt_b64 "${'$'}WG_DNS")"
    if [ -n "${'$'}WG_VPS_HOST_B64" ] || [ -n "${'$'}WG_VPS_PORT" ]; then
      WG_PRESENT=1
    fi
    IMPORTED_WG_CONFIG_B64="${'$'}(wdtt_profile_value IMPORTED_WG_CONFIG_B64)"
    if [ "${'$'}MODE" = "imported_wg" ] && [ -z "${'$'}IMPORTED_WG_CONFIG_B64" ] && [ -n "${'$'}WG_CONF" ]; then
      IMPORTED_WG_CONFIG_B64="${'$'}(wdtt_file_b64 "${'$'}WG_CONF")"
    fi
    [ -n "${'$'}IMPORTED_WG_CONFIG_B64" ] && WG_PRESENT=1
    WARP_PRESENT=0
    if [ -f /etc/wdtt-plus/warp/wgcf-account.toml ] || [ -f /etc/wdtt-plus/warp/wgcf-profile.conf ]; then
      WARP_PRESENT=1
    fi

    printf 'WDTT_OUTBOUND_MODE=%s\n' "${'$'}MODE"
    printf 'WDTT_OUTBOUND_DETAIL_B64=%s\n' "$(wdtt_b64 "${'$'}DETAIL")"
    printf 'WDTT_OUTBOUND_UPDATED_AT=%s\n' "${'$'}UPDATED_AT"
    printf 'WDTT_HAS_PROFILE=%s\n' "${'$'}HAS_PROFILE"
    printf 'WDTT_LOCAL_PROXY_PRESENT=%s\n' "${'$'}LOCAL_PRESENT"
    printf 'WDTT_LOCAL_PROXY_ACTIVE=%s\n' "${'$'}LOCAL_ACTIVE"
    printf 'WDTT_LOCAL_PROXY_PORT=%s\n' "${'$'}LOCAL_PORT"
    printf 'WDTT_LOCAL_PROXY_LOGIN_B64=%s\n' "${'$'}LOCAL_LOGIN_B64"
    printf 'WDTT_LOCAL_PROXY_PASSWORD_B64=%s\n' "${'$'}LOCAL_PASSWORD_B64"
    printf 'WDTT_EXTERNAL_PROXY_PRESENT=%s\n' "${'$'}EXTERNAL_PRESENT"
    printf 'WDTT_EXTERNAL_PROXY_ACTIVE=%s\n' "${'$'}EXTERNAL_ACTIVE"
    printf 'WDTT_EXTERNAL_PROXY_KIND_NAME=%s\n' "${'$'}EXTERNAL_KIND"
    printf 'WDTT_EXTERNAL_PROXY_HOST_B64=%s\n' "${'$'}EXTERNAL_HOST_B64"
    printf 'WDTT_EXTERNAL_PROXY_PORT=%s\n' "${'$'}EXTERNAL_PORT"
    printf 'WDTT_EXTERNAL_PROXY_LOGIN_B64=%s\n' "${'$'}EXTERNAL_LOGIN_B64"
    printf 'WDTT_EXTERNAL_PROXY_PASSWORD_B64=%s\n' "${'$'}EXTERNAL_PASSWORD_B64"
    printf 'WDTT_WG_PRESENT=%s\n' "${'$'}WG_PRESENT"
    printf 'WDTT_WG_ACTIVE=%s\n' "${'$'}WG_ACTIVE"
    printf 'WDTT_WG_VPS_HOST_B64=%s\n' "${'$'}WG_VPS_HOST_B64"
    printf 'WDTT_WG_VPS_SSH_PORT=%s\n' "${'$'}WG_VPS_SSH_PORT"
    printf 'WDTT_WG_VPS_USER_B64=%s\n' "${'$'}WG_VPS_USER_B64"
    printf 'WDTT_WG_VPS_PASSWORD_B64=%s\n' "${'$'}WG_VPS_PASSWORD_B64"
    printf 'WDTT_WG_VPS_PORT=%s\n' "${'$'}WG_VPS_PORT"
    printf 'WDTT_WG_VPS_DNS_B64=%s\n' "${'$'}WG_VPS_DNS_B64"
    printf 'WDTT_WARP_PRESENT=%s\n' "${'$'}WARP_PRESENT"
    printf 'WDTT_WARP_MTU=%s\n' "${'$'}WG_MTU"
    printf 'WDTT_IMPORTED_WG_CONFIG_B64=%s\n' "${'$'}IMPORTED_WG_CONFIG_B64"
    """
)

private suspend fun readOutboundServerSnapshot(
    context: Context,
    target: OutboundSshTarget
): OutboundServerSnapshot {
    DeployManager.updateProgress(0.25f, "Подключаюсь к серверу и ищу профиль выходного IP...")
    val output = runRootScript(
        context = context,
        target = target,
        script = outboundSnapshotScript(),
        timeout = 30000L
    )
    DeployManager.updateProgress(1f, "Настройки выходного IP прочитаны.")
    return parseOutboundServerSnapshot(output)
}

private fun parseOutboundServerSnapshot(output: String): OutboundServerSnapshot {
    fun value(name: String): String = markerValue(output, name).orEmpty()
    fun decoded(name: String): String {
        val raw = value(name)
        if (raw.isBlank()) return ""
        return runCatching { decodeBase64Text(raw) }.getOrDefault("")
    }
    fun flag(name: String): Boolean = value(name) == "1"
    return OutboundServerSnapshot(
        mode = value("WDTT_OUTBOUND_MODE").ifBlank { "direct" },
        detail = decoded("WDTT_OUTBOUND_DETAIL_B64"),
        updatedAt = value("WDTT_OUTBOUND_UPDATED_AT"),
        hasProfile = flag("WDTT_HAS_PROFILE"),
        localProxyPresent = flag("WDTT_LOCAL_PROXY_PRESENT"),
        localProxyActive = flag("WDTT_LOCAL_PROXY_ACTIVE"),
        localProxyPort = value("WDTT_LOCAL_PROXY_PORT"),
        localProxyLogin = decoded("WDTT_LOCAL_PROXY_LOGIN_B64"),
        localProxyPassword = decoded("WDTT_LOCAL_PROXY_PASSWORD_B64"),
        externalProxyPresent = flag("WDTT_EXTERNAL_PROXY_PRESENT"),
        externalProxyActive = flag("WDTT_EXTERNAL_PROXY_ACTIVE"),
        externalProxyKindName = value("WDTT_EXTERNAL_PROXY_KIND_NAME").takeIf { name -> ProxyKind.entries.any { it.name == name } }.orEmpty(),
        externalProxyHost = decoded("WDTT_EXTERNAL_PROXY_HOST_B64"),
        externalProxyPort = value("WDTT_EXTERNAL_PROXY_PORT"),
        externalProxyLogin = decoded("WDTT_EXTERNAL_PROXY_LOGIN_B64"),
        externalProxyPassword = decoded("WDTT_EXTERNAL_PROXY_PASSWORD_B64"),
        wireGuardPresent = flag("WDTT_WG_PRESENT"),
        wireGuardActive = flag("WDTT_WG_ACTIVE"),
        wireGuardExitHost = decoded("WDTT_WG_VPS_HOST_B64"),
        wireGuardExitSshPort = value("WDTT_WG_VPS_SSH_PORT"),
        wireGuardExitUser = decoded("WDTT_WG_VPS_USER_B64"),
        wireGuardExitPassword = decoded("WDTT_WG_VPS_PASSWORD_B64"),
        wireGuardExitPort = value("WDTT_WG_VPS_PORT"),
        wireGuardExitDns = decoded("WDTT_WG_VPS_DNS_B64"),
        warpPresent = flag("WDTT_WARP_PRESENT"),
        warpMtu = value("WDTT_WARP_MTU"),
        importedWireGuardConfig = decoded("WDTT_IMPORTED_WG_CONFIG_B64")
    )
}

private fun outboundRestoreSummary(snapshot: OutboundServerSnapshot): String {
    val parts = mutableListOf<String>()
    parts += "Поля выходного IP прочитаны с сервера."
    parts += "Активный режим: ${snapshot.modeLabel}."
    if (snapshot.hasProfile) parts += "Сохранённый профиль найден."
    if (snapshot.localProxyPresent) {
        parts += if (snapshot.localProxyActive) "Прокси VPS найден и запущен." else "Прокси VPS найден, служба не запущена."
    }
    if (snapshot.externalProxyPresent) {
        parts += if (snapshot.externalProxyActive) "Внешний TCP-прокси включён." else "Поля внешнего TCP-прокси заполнены."
    }
    if (snapshot.wireGuardPresent) {
        parts += if (snapshot.wireGuardActive) "WireGuard-выход найден и запущен." else "Поля WireGuard-выхода заполнены."
    }
    if (snapshot.mode == "warp_free") {
        parts += if (snapshot.wireGuardActive) {
            "Бесплатный WARP найден; откройте его окно для проверки Cloudflare и автопроверки."
        } else {
            "Профиль бесплатного WARP найден, но WireGuard сейчас не запущен. Нажмите «Установить / восстановить»."
        }
    }
    if (snapshot.localProxyPresent && snapshot.localProxyPassword.isBlank()) {
        parts += "Пароль прокси не найден в старом серверном конфиге; введите его вручную."
    }
    if (snapshot.mode == "wireguard_vps" && snapshot.wireGuardExitPassword.isBlank()) {
        parts += "SSH-пароль второго сервера можно восстановить только из сохранённого профиля; если его нет, введите пароль вручную."
    }
    return parts.joinToString(" ")
}

private suspend fun checkWireGuardExit(
    target: OutboundSshTarget,
    expectedMode: String
): String = withContext(Dispatchers.IO) {
    var session: Session? = null
    try {
        DeployManager.updateProgress(0.25f, "Подключаюсь к серверу и проверяю WireGuard-выход...")
        session = createSSHSession(target.host, target.user, target.pass, target.port)
        val ssh = SSHClient(session, target.pass)
        val expectedLabel = when (expectedMode) {
            "wireguard_vps" -> "выход через другой сервер"
            "warp_free" -> "бесплатный WARP"
            "imported_wg" -> "VPN/WireGuard-файл"
            else -> expectedMode
        }
        val script = shellScript(
            outboundShellPrelude(),
            """
            MODE="${'$'}(grep -o '"outboundMode"[[:space:]]*:[[:space:]]*"[^"]*"' /etc/wdtt/outbound.json 2>/dev/null | sed 's/.*"outboundMode"[[:space:]]*:[[:space:]]*"//;s/".*//' | head -n 1)"
            [ -n "${'$'}MODE" ] || MODE="direct"
            case "${'$'}MODE" in
              warp_free) MODE_LABEL="бесплатный WARP";;
              imported_wg) MODE_LABEL="VPN/WireGuard-файл";;
              wireguard_vps) MODE_LABEL="выход через другой сервер";;
              external_proxy) MODE_LABEL="внешний TCP-прокси";;
              direct) MODE_LABEL="прямой выход";;
              *) MODE_LABEL="${'$'}MODE";;
            esac
            echo "Активный режим WDTT: ${'$'}MODE_LABEL"
            if [ "${'$'}MODE" != ${shellQuote(expectedMode)} ]; then
              echo "Предупреждение: сейчас включён не режим «$expectedLabel»."
            fi
            command -v wg >/dev/null 2>&1 || { echo WDTT_ERROR=wireguard_tools_required; exit 2; }
            wg show "${'$'}WDTT_WG_IFACE" >/dev/null 2>&1 || { echo WDTT_ERROR=wireguard_not_active; exit 3; }
            echo "WireGuard ${'$'}WDTT_WG_IFACE запущен."
            TEST_SOURCE="${'$'}(wdtt_test_source)"
            [ -n "${'$'}TEST_SOURCE" ] || { echo WDTT_ERROR=wdtt_test_source_missing; exit 3; }
            EXIT_IP="${'$'}(curl -4fsS --interface "${'$'}TEST_SOURCE" --max-time 12 https://api.ipify.org 2>/dev/null || true)"
            if [ -n "${'$'}EXIT_IP" ]; then
              echo "Проверка успешна: WDTT-пользователи выходят через WireGuard. Проверочный IP: ${'$'}EXIT_IP"
            else
              echo WDTT_ERROR=wireguard_exit_check_failed
              exit 3
            fi
            wg show "${'$'}WDTT_WG_IFACE" | sed -E 's/(private key: ).*/\1(скрыт)/' || true
            """
        )
        DeployManager.updateProgress(0.70f, "Проверяю внешний IP через WireGuard-интерфейс...")
        val output = ssh.exec(rootCommand(script), timeout = 30000L).trim()
        markerValue(output, "WDTT_ERROR")?.let { throw IllegalStateException(it) }
        DeployManager.updateProgress(1f, "WireGuard-выход проверен.")
        output
    } finally {
        try { session?.disconnect() } catch (_: Exception) {}
    }
}

private suspend fun readOutboundDiagnostics(target: OutboundSshTarget): String = withContext(Dispatchers.IO) {
    var session: Session? = null
    try {
        DeployManager.updateProgress(0.20f, "Подключаюсь к серверу для диагностики...")
        session = createSSHSession(target.host, target.user, target.pass, target.port)
        val ssh = SSHClient(session, target.pass)
        DeployManager.updateProgress(0.45f, "Читаю режим выхода, службы и внешний IP...")
        val script = shellScript(
            outboundStatusScript(),
            """
            echo
            echo "Правила, которые выбирают выход для WDTT-пользователей:"
            ROUTE_RULES="${'$'}(ip rule show | grep -E '100|wdtt|10\.66\.66' || true)"
            if [ -n "${'$'}ROUTE_RULES" ]; then
              printf '%s\n' "${'$'}ROUTE_RULES"
            else
              echo "Отдельных правил выбора маршрута для WDTT сейчас нет."
            fi
            echo
            echo "Маршрутная таблица WDTT-пользователей:"
            WDTT_ROUTES="${'$'}(ip route show table 100 2>/dev/null || true)"
            if [ -n "${'$'}WDTT_ROUTES" ]; then
              printf '%s\n' "${'$'}WDTT_ROUTES"
            else
              echo "Маршрутная таблица WDTT сейчас пуста."
            fi
            echo
            echo "Правила перенаправления через прокси или WireGuard:"
            REDIRECT_RULES="${'$'}(iptables -t nat -S 2>/dev/null | grep -E 'WDTT_PROXY_OUT|WDTT_EXIT|WDTT_LOCAL_PROXY' || true)"
            if [ -n "${'$'}REDIRECT_RULES" ]; then
              printf '%s\n' "${'$'}REDIRECT_RULES"
            else
              echo "Правил перенаправления WDTT через прокси или WireGuard сейчас нет."
            fi
            echo
            echo "Служба внешнего TCP-прокси WDTT:"
            systemctl status wdtt-redsocks --no-pager -l 2>/dev/null | sed -n '1,12p' || echo "Служба wdtt-redsocks не найдена или systemctl недоступен."
            echo
            echo "Локальный порт redsocks:"
            if command -v ss >/dev/null 2>&1; then
              REDSOCKS_LISTEN="${'$'}(ss -ltnp 2>/dev/null | grep ':12345' || true)"
              if [ -n "${'$'}REDSOCKS_LISTEN" ]; then
                printf '%s\n' "${'$'}REDSOCKS_LISTEN"
                if printf '%s\n' "${'$'}REDSOCKS_LISTEN" | grep -q '127\\.0\\.0\\.1:12345'; then
                  echo "Внимание: redsocks слушает только 127.0.0.1. Для трафика WDTT из PREROUTING нужен 0.0.0.0:12345, иначе пинги могут работать, а сайты у пользователей не открываться."
                fi
              else
                echo "redsocks сейчас не слушает порт 12345."
              fi
            else
              echo "Команда ss недоступна."
            fi
            echo
            echo "Последние сообщения redsocks:"
            tail -n 20 /var/log/wdtt-redsocks.log 2>/dev/null || echo "Лог redsocks пуст или недоступен."
            """
        )
        DeployManager.updateProgress(0.75f, "Собираю маршруты и правила перенаправления...")
        val output = ssh.exec(rootCommand(script), timeout = 30000L).trim()
        DeployManager.updateProgress(1f, "Диагностика собрана.")
        output
    } finally {
        try { session?.disconnect() } catch (_: Exception) {}
    }
}

private suspend fun disableOutboundExit(target: OutboundSshTarget): String = withContext(Dispatchers.IO) {
    var session: Session? = null
    try {
        session = createSSHSession(target.host, target.user, target.pass, target.port)
        val ssh = SSHClient(session, target.pass)
        val script = shellScript(
            outboundShellPrelude(),
            """
            echo "WDTT_PROGRESS|0.25|Останавливаю внешний TCP-прокси и WireGuard-выход, если они включены..."
            wdtt_clear_external_out
            echo "WDTT_PROGRESS|0.75|Сохраняю режим прямого выхода через текущий сервер..."
            wdtt_write_mode "direct" "прямой выход"
            echo "WDTT_PROGRESS|1.0|Прямой выход включён."
            echo "Внешний TCP-прокси или WireGuard-выход отключён. WDTT-пользователи снова идут напрямую через текущий сервер."
            """
        )
        ssh.exec(rootCommand(script), timeout = 30000L).trim()
    } finally {
        try { session?.disconnect() } catch (_: Exception) {}
    }
}

private suspend fun installLocalProxy(
    context: Context,
    target: OutboundSshTarget,
    port: Int,
    login: String,
    proxyPassword: String
): String {
    val httpPort = (port + 1).coerceAtMost(65535)
    val script = shellScript(
        outboundShellPrelude(),
        """
        PROXY_PORT=$port
        HTTP_PORT=$httpPort
        ADMIN_PORT=${httpPort + 1}
        PROXY_LOGIN=${shellQuote(login)}
        PROXY_PASSWORD=${shellQuote(proxyPassword)}
        wdtt_progress() { echo "WDTT_PROGRESS|${'$'}1|${'$'}2"; }
        install_pkg() {
          if command -v apt-get >/dev/null 2>&1; then
            apt-get update -y >/dev/null 2>&1 || true
            DEBIAN_FRONTEND=noninteractive apt-get install -y "${'$'}@" >/dev/null 2>&1
          elif command -v dnf >/dev/null 2>&1; then
            dnf install -y "${'$'}@" >/dev/null 2>&1
          elif command -v yum >/dev/null 2>&1; then
            yum install -y "${'$'}@" >/dev/null 2>&1
          elif command -v zypper >/dev/null 2>&1; then
            zypper --non-interactive install -y "${'$'}@" >/dev/null 2>&1
          elif command -v apk >/dev/null 2>&1; then
            apk add --no-cache "${'$'}@" >/dev/null 2>&1
          elif command -v pacman >/dev/null 2>&1; then
            pacman -Sy --noconfirm --needed "${'$'}@" >/dev/null 2>&1
          else
            return 1
          fi
        }
        install_3proxy_build_deps() {
          if command -v apt-get >/dev/null 2>&1; then
            install_pkg curl ca-certificates tar gzip make gcc libc6-dev libssl-dev
          elif command -v dnf >/dev/null 2>&1; then
            install_pkg curl ca-certificates tar gzip make gcc glibc-devel openssl-devel
          elif command -v yum >/dev/null 2>&1; then
            install_pkg curl ca-certificates tar gzip make gcc glibc-devel openssl-devel
          elif command -v zypper >/dev/null 2>&1; then
            install_pkg curl ca-certificates tar gzip make gcc glibc-devel libopenssl-devel
          elif command -v apk >/dev/null 2>&1; then
            install_pkg curl ca-certificates tar gzip make gcc musl-dev linux-headers openssl-dev
          elif command -v pacman >/dev/null 2>&1; then
            install_pkg curl ca-certificates tar gzip make gcc glibc openssl
          else
            return 1
          fi
        }
        install_3proxy_from_source() {
          TMP_DIR="${'$'}(mktemp -d)"
          cleanup() { rm -rf "${'$'}TMP_DIR"; }
          trap cleanup EXIT
          wdtt_progress 0.50 "Пакета 3proxy нет, готовлю сборку из исходников..."
          install_3proxy_build_deps || true
          command -v curl >/dev/null 2>&1 || { echo WDTT_ERROR=3proxy_source_no_curl; exit 2; }
          command -v tar >/dev/null 2>&1 || { echo WDTT_ERROR=3proxy_source_no_tar; exit 2; }
          command -v gzip >/dev/null 2>&1 || { echo WDTT_ERROR=3proxy_source_no_gzip; exit 2; }
          command -v make >/dev/null 2>&1 || { echo WDTT_ERROR=3proxy_source_no_make; exit 2; }
          (command -v gcc >/dev/null 2>&1 || command -v cc >/dev/null 2>&1) || { echo WDTT_ERROR=3proxy_source_no_compiler; exit 2; }
          [ -f /usr/include/openssl/evp.h ] || [ -f /usr/local/include/openssl/evp.h ] || { echo WDTT_ERROR=3proxy_source_no_openssl_headers; exit 2; }
          cd "${'$'}TMP_DIR"
          wdtt_progress 0.58 "Скачиваю исходники 3proxy..."
          curl -fsSL -o 3proxy.tar.gz https://github.com/3proxy/3proxy/archive/refs/heads/master.tar.gz || { echo WDTT_ERROR=3proxy_source_download_failed; exit 2; }
          tar -xzf 3proxy.tar.gz || { echo WDTT_ERROR=3proxy_source_unpack_failed; exit 2; }
          cd 3proxy-*
          wdtt_progress 0.68 "Собираю 3proxy на сервере..."
          ln -sf Makefile.Linux Makefile
          make >/tmp/wdtt-3proxy-build.log 2>&1 || { echo WDTT_ERROR=3proxy_source_build_failed; tail -n 20 /tmp/wdtt-3proxy-build.log; exit 2; }
          BUILT_BIN="${'$'}(find . -type f -name 3proxy -perm -111 | head -n1)"
          [ -n "${'$'}BUILT_BIN" ] || { echo WDTT_ERROR=3proxy_source_binary_missing; exit 2; }
          install -m 755 "${'$'}BUILT_BIN" /usr/local/bin/3proxy || { echo WDTT_ERROR=3proxy_source_install_failed; exit 2; }
        }
        wdtt_progress 0.08 "Определяю систему и права..."
        command -v systemctl >/dev/null 2>&1 || { echo WDTT_ERROR=systemd_required; exit 2; }
        wdtt_progress 0.18 "Готовлю пакетный менеджер..."
        install_pkg curl ca-certificates || true
        wdtt_progress 0.32 "Пробую установить 3proxy из репозитория..."
        install_pkg 3proxy || true
        THREEPROXY_BIN="${'$'}(command -v 3proxy || true)"
        if [ -z "${'$'}THREEPROXY_BIN" ]; then
          install_3proxy_from_source || true
          THREEPROXY_BIN="${'$'}(command -v 3proxy || true)"
        fi
        [ -n "${'$'}THREEPROXY_BIN" ] || { echo WDTT_ERROR=3proxy_install_failed; exit 2; }
        wdtt_progress 0.76 "Пишу настройки SOCKS5 и HTTP..."
        cat >/etc/wdtt/3proxy.cfg <<EOF
        daemon
        nserver 1.1.1.1
        nserver 8.8.8.8
        nscache 65536
        timeouts 1 5 30 60 180 1800 15 60
        auth strong
        users ${'$'}PROXY_LOGIN:CL:${'$'}PROXY_PASSWORD
        allow ${'$'}PROXY_LOGIN
        socks -p${'$'}PROXY_PORT -i0.0.0.0 -e0.0.0.0
        proxy -p${'$'}HTTP_PORT -i0.0.0.0 -e0.0.0.0
        admin -p${'$'}ADMIN_PORT -i0.0.0.0
        EOF
        chmod 600 /etc/wdtt/3proxy.cfg
        wdtt_progress 0.82 "Настраиваю службу wdtt-3proxy..."
        cat >/etc/systemd/system/wdtt-3proxy.service <<EOF
        [Unit]
        Description=WDTT Plus authenticated proxy
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=forking
        ExecStart=${'$'}THREEPROXY_BIN /etc/wdtt/3proxy.cfg
        ExecReload=/bin/kill -HUP ${'$'}MAINPID
        Restart=on-failure

        [Install]
        WantedBy=multi-user.target
        EOF
        systemctl daemon-reload
        wdtt_progress 0.88 "Запускаю прокси-службу..."
        systemctl enable --now wdtt-3proxy >/dev/null
        systemctl is-active --quiet wdtt-3proxy || { echo WDTT_ERROR=local_proxy_service_inactive; exit 3; }
        wdtt_progress 0.92 "Открываю порты в firewall, если он есть..."
        if command -v iptables >/dev/null 2>&1; then
          iptables -C INPUT -p tcp --dport "${'$'}PROXY_PORT" -m comment --comment WDTT_LOCAL_PROXY -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "${'$'}PROXY_PORT" -m comment --comment WDTT_LOCAL_PROXY -j ACCEPT
          iptables -C INPUT -p tcp --dport "${'$'}HTTP_PORT" -m comment --comment WDTT_LOCAL_PROXY -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "${'$'}HTTP_PORT" -m comment --comment WDTT_LOCAL_PROXY -j ACCEPT
          iptables -C INPUT -p tcp --dport "${'$'}ADMIN_PORT" -m comment --comment WDTT_LOCAL_PROXY -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "${'$'}ADMIN_PORT" -m comment --comment WDTT_LOCAL_PROXY -j ACCEPT
        fi
        wdtt_progress 0.96 "Проверяю подключение через установленный SOCKS5..."
        TEST_IP="${'$'}(curl --socks5-hostname "${'$'}PROXY_LOGIN:${'$'}PROXY_PASSWORD@127.0.0.1:${'$'}PROXY_PORT" -4fsS --max-time 12 https://api.ipify.org 2>/dev/null || true)"
        [ -n "${'$'}TEST_IP" ] || { echo WDTT_ERROR=local_proxy_check_failed; exit 3; }
        SERVER_IP="${'$'}(curl -4fsS --max-time 8 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print ${'$'}1}')"
        cat >/etc/wdtt/local-proxy.json <<EOF
        {
          "enabled": true,
          "type": "socks5,http",
          "host": "${'$'}SERVER_IP",
          "socks5Port": ${'$'}PROXY_PORT,
          "httpPort": ${'$'}HTTP_PORT,
          "webPort": ${'$'}ADMIN_PORT,
          "login": "${'$'}PROXY_LOGIN",
          "password": "${'$'}PROXY_PASSWORD"
        }
        EOF
        chmod 600 /etc/wdtt/local-proxy.json
        wdtt_progress 1.0 "Прокси установлен и проверен."
        echo "Прокси VPS включён."
        echo "SOCKS5-прокси: socks5://${'$'}PROXY_LOGIN:********@${'$'}SERVER_IP:${'$'}PROXY_PORT"
        echo "HTTP-прокси: http://${'$'}PROXY_LOGIN:********@${'$'}SERVER_IP:${'$'}HTTP_PORT"
        echo "Веб-страница 3proxy: http://${'$'}SERVER_IP:${'$'}ADMIN_PORT/"
        """
    )
    return runRootScript(context, target, script, timeout = CMD_TIMEOUT)
}

private suspend fun checkLocalProxy(
    context: Context,
    target: OutboundSshTarget,
    port: Int,
    login: String,
    proxyPassword: String
): String {
    val script = """
        PROXY_PORT=$port
        PROXY_LOGIN=${shellQuote(login)}
        PROXY_PASSWORD=${shellQuote(proxyPassword)}
        echo "WDTT_PROGRESS|0.15|Проверяю, запущена ли служба прокси..."
        if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files wdtt-3proxy.service >/dev/null 2>&1; then
          systemctl is-active --quiet wdtt-3proxy || { echo WDTT_ERROR=local_proxy_service_inactive; exit 3; }
        fi
        echo "WDTT_PROGRESS|0.45|Проверяю curl на сервере..."
        command -v curl >/dev/null 2>&1 || { echo WDTT_ERROR=curl_not_installed; exit 2; }
        echo "WDTT_PROGRESS|0.70|Подключаюсь через SOCKS5 127.0.0.1:${'$'}PROXY_PORT..."
        IP="${'$'}(curl --socks5-hostname "${'$'}PROXY_LOGIN:${'$'}PROXY_PASSWORD@127.0.0.1:${'$'}PROXY_PORT" -4fsS --max-time 12 https://api.ipify.org 2>/dev/null || true)"
        [ -n "${'$'}IP" ] || { echo WDTT_ERROR=local_proxy_check_failed; exit 3; }
        echo "WDTT_PROGRESS|1.0|Прокси отвечает."
        echo "Проверка успешна: SOCKS5 на 127.0.0.1:${'$'}PROXY_PORT отвечает с указанными логином и паролем. Выходной IP: ${'$'}IP"
    """.trimIndent()
    return runRootScript(context, target, script, timeout = 30000L)
}

private suspend fun stopLocalProxy(target: OutboundSshTarget): String = withContext(Dispatchers.IO) {
    var session: Session? = null
    try {
        session = createSSHSession(target.host, target.user, target.pass, target.port)
        val ssh = SSHClient(session, target.pass)
        val script = """
            echo "WDTT_PROGRESS|0.35|Останавливаю службу прокси на этом сервере..."
            systemctl stop wdtt-3proxy 2>/dev/null || true
            echo "WDTT_PROGRESS|0.85|Проверяю, что прокси больше не запущен..."
            if systemctl is-active --quiet wdtt-3proxy 2>/dev/null; then
              echo WDTT_ERROR=local_proxy_service_still_active
              exit 3
            fi
            echo "WDTT_PROGRESS|1.0|Прокси остановлен."
            echo "Прокси VPS остановлен. Настройки сохранены, его можно снова включить кнопкой «Установить»."
        """.trimIndent()
        ssh.exec(rootCommand(script), timeout = 20000L).trim()
    } finally {
        try { session?.disconnect() } catch (_: Exception) {}
    }
}

private suspend fun removeLocalProxy(target: OutboundSshTarget): String = withContext(Dispatchers.IO) {
    var session: Session? = null
    try {
        session = createSSHSession(target.host, target.user, target.pass, target.port)
        val ssh = SSHClient(session, target.pass)
        val script = shellScript(
            """
            echo "WDTT_PROGRESS|0.25|Останавливаю службу прокси..."
            systemctl disable --now wdtt-3proxy 2>/dev/null || true
            echo "WDTT_PROGRESS|0.55|Удаляю файлы настроек прокси..."
            rm -f /etc/systemd/system/wdtt-3proxy.service /etc/wdtt/3proxy.cfg /etc/wdtt/local-proxy.json
            systemctl daemon-reload 2>/dev/null || true
            echo "WDTT_PROGRESS|0.80|Удаляю правила доступа к портам прокси..."
            if command -v iptables >/dev/null 2>&1; then
              iptables -S INPUT 2>/dev/null | grep WDTT_LOCAL_PROXY | sed 's/^-A /iptables -D /' | while read -r cmd; do ${'$'}cmd 2>/dev/null || true; done
            fi
            echo "WDTT_PROGRESS|1.0|Прокси удалён."
            echo "Прокси VPS удалён: служба, настройки и правила доступа к портам очищены."
            """
        )
        ssh.exec(rootCommand(script), timeout = 30000L).trim()
    } finally {
        try { session?.disconnect() } catch (_: Exception) {}
    }
}

private suspend fun checkExternalProxy(
    context: Context,
    target: OutboundSshTarget,
    kind: ProxyKind,
    host: String,
    port: Int,
    login: String,
    proxyPassword: String
): String {
    val scheme = if (kind == ProxyKind.Socks5) "socks5h" else "http"
    val auth = if (login.isNotBlank()) "${login}:${proxyPassword}@" else ""
    val proxyUri = "$scheme://$auth$host:$port"
    val script = """
        echo "WDTT_PROGRESS|0.25|Проверяю curl на сервере..."
        command -v curl >/dev/null 2>&1 || { echo WDTT_ERROR=curl_not_installed; exit 2; }
        echo "WDTT_PROGRESS|0.55|Пробую выйти в интернет через указанный ${kind.label}..."
        PROXY_URI=${shellQuote(proxyUri)}
        IP="${'$'}(curl --proxy "${'$'}PROXY_URI" -4fsS --max-time 15 https://api.ipify.org 2>/dev/null || true)"
        [ -n "${'$'}IP" ] || { echo WDTT_ERROR=external_proxy_check_failed; exit 3; }
        echo "WDTT_PROGRESS|1.0|Внешний TCP-прокси отвечает."
        echo "Проверка успешна: ${kind.label} отвечает, сервер смог открыть проверочный сайт через него. IP через прокси: ${'$'}IP"
    """.trimIndent()
    return runRootScript(context, target, script, timeout = 30000L)
}

private suspend fun enableExternalProxy(
    context: Context,
    target: OutboundSshTarget,
    kind: ProxyKind,
    host: String,
    port: Int,
    login: String,
    proxyPassword: String
): String {
    val redsocksType = if (kind == ProxyKind.Socks5) "socks5" else "http-connect"
    val script = shellScript(
        outboundShellPrelude(),
        """
        PROXY_KIND=${shellQuote(kind.protocol)}
        REDSOCKS_TYPE=${shellQuote(redsocksType)}
        PROXY_HOST=${shellQuote(host)}
        PROXY_PORT=$port
        PROXY_LOGIN=${shellQuote(login)}
        PROXY_PASSWORD=${shellQuote(proxyPassword)}
        wdtt_progress() { echo "WDTT_PROGRESS|${'$'}1|${'$'}2"; }
        wdtt_progress 0.12 "Готовлю компонент перенаправления через внешний TCP-прокси..."
        wdtt_install_redsocks_tools || true
        REDSOCKS_BIN="${'$'}(command -v redsocks || true)"
        [ -n "${'$'}REDSOCKS_BIN" ] || { echo WDTT_ERROR=redsocks_not_installed; exit 2; }
        wdtt_progress 0.30 "Проверяю сетевые инструменты и интерфейс WDTT..."
        command -v iptables >/dev/null 2>&1 || { echo WDTT_ERROR=iptables_required; exit 2; }
        [ -d /sys/class/net/"${'$'}WDTT_IFACE" ] || { echo WDTT_ERROR=wdtt_iface_not_found; exit 2; }
        wdtt_progress 0.45 "Определяю адрес внешнего прокси..."
        PROXY_IP="${'$'}(getent ahostsv4 "${'$'}PROXY_HOST" | awk '{print ${'$'}1; exit}')"
        [ -n "${'$'}PROXY_IP" ] || PROXY_IP="${'$'}PROXY_HOST"
        wdtt_progress 0.55 "Отключаю прежний внешний выход WDTT..."
        wdtt_clear_external_out
        wdtt_progress 0.65 "Записываю настройки внешнего прокси..."
        cat >/etc/wdtt/redsocks.conf <<EOF
        base {
          log_debug = off;
          log_info = on;
          log = "file:/var/log/wdtt-redsocks.log";
          daemon = on;
          redirector = iptables;
        }
        redsocks {
          local_ip = 0.0.0.0;
          local_port = 12345;
          ip = ${'$'}PROXY_IP;
          port = ${'$'}PROXY_PORT;
          type = ${'$'}REDSOCKS_TYPE;
        EOF
        if [ -n "${'$'}PROXY_LOGIN" ]; then
          printf '  login = "%s";\n' "${'$'}PROXY_LOGIN" >>/etc/wdtt/redsocks.conf
          printf '  password = "%s";\n' "${'$'}PROXY_PASSWORD" >>/etc/wdtt/redsocks.conf
        fi
        cat >>/etc/wdtt/redsocks.conf <<EOF
        }
        EOF
        chmod 600 /etc/wdtt/redsocks.conf
        wdtt_progress 0.76 "Настраиваю службу перенаправления WDTT..."
        cat >/etc/systemd/system/wdtt-redsocks.service <<EOF
        [Unit]
        Description=WDTT Plus external proxy redirector
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=forking
        ExecStart=${'$'}REDSOCKS_BIN -c /etc/wdtt/redsocks.conf -p /run/wdtt-redsocks.pid
        PIDFile=/run/wdtt-redsocks.pid
        Restart=on-failure

        [Install]
        WantedBy=multi-user.target
        EOF
        systemctl daemon-reload
        wdtt_progress 0.84 "Запускаю службу внешнего TCP-прокси..."
        systemctl enable --now wdtt-redsocks >/dev/null
        systemctl is-active --quiet wdtt-redsocks || { echo WDTT_ERROR=external_proxy_service_inactive; journalctl -u wdtt-redsocks -n 30 --no-pager 2>/dev/null || true; exit 3; }
        wdtt_progress 0.92 "Направляю обычные TCP-подключения WDTT через внешний TCP-прокси..."
        iptables -t nat -N WDTT_PROXY_OUT 2>/dev/null || true
        iptables -t nat -F WDTT_PROXY_OUT
        wdtt_proxy_reserved_returns WDTT_PROXY_OUT "${'$'}PROXY_IP"
        iptables -t nat -A WDTT_PROXY_OUT -p tcp -j REDIRECT --to-ports 12345
        iptables -t nat -C PREROUTING -i "${'$'}WDTT_IFACE" -p tcp -j WDTT_PROXY_OUT 2>/dev/null || iptables -t nat -A PREROUTING -i "${'$'}WDTT_IFACE" -p tcp -j WDTT_PROXY_OUT
        wdtt_progress 0.96 "Проверяю путь WDTT через внешний TCP-прокси..."
        if ! wdtt_test_redsocks_path "${'$'}PROXY_IP"; then
          wdtt_clear_external_out
          wdtt_write_mode "direct" "rollback after external proxy error"
          exit 3
        fi
        wdtt_write_mode "external_proxy" "${'$'}PROXY_KIND://${'$'}PROXY_HOST:${'$'}PROXY_PORT"
        wdtt_progress 1.0 "Внешний TCP-прокси включён."
        echo "Внешний TCP-прокси включён для обычных TCP-подключений WDTT-пользователей. UDP, QUIC и голосовой трафик через него не перенаправляются."
        echo "Подсеть клиентов WDTT: ${'$'}WDTT_SUBNET"
        echo "Прокси: ${'$'}PROXY_KIND://${'$'}PROXY_HOST:${'$'}PROXY_PORT"
        """
    )
    return runRootScript(context, target, script, timeout = CMD_TIMEOUT)
}

internal fun validateWireGuardConfigText(config: String): Result<Unit> = runCatching {
    val raw = config.trim()
    require(raw.toByteArray(Charsets.UTF_8).size <= 64 * 1024) { "файл больше 64 КБ" }
    require('\u0000' !in raw) { "файл содержит недопустимые нулевые байты" }
    require(raw.contains(Regex("(?im)^\\s*\\[Interface]\\s*$"))) { "не найден раздел с настройками вашего WireGuard-клиента" }
    require(raw.contains(Regex("(?im)^\\s*PrivateKey\\s*=\\s*\\S+"))) { "в файле нет приватного ключа клиента" }
    require(raw.contains(Regex("(?im)^\\s*Address\\s*=\\s*\\S+"))) { "в файле нет адреса клиента" }
    require(raw.contains(Regex("(?im)^\\s*\\[Peer]\\s*$"))) { "не найден раздел с настройками удалённого сервера" }
    require(raw.contains(Regex("(?im)^\\s*PublicKey\\s*=\\s*\\S+"))) { "в файле нет публичного ключа удалённого сервера" }
    require(raw.contains(Regex("(?im)^\\s*Endpoint\\s*=\\s*\\S+"))) { "в файле нет адреса удалённого сервера" }
    require(raw.contains(Regex("(?im)^\\s*AllowedIPs\\s*=\\s*\\S+"))) { "в файле нет маршрутов для WireGuard" }
    require(!raw.contains(Regex("(?im)^\\s*(PreUp|PostUp|PreDown|PostDown)\\s*="))) {
        "команды запуска и остановки запрещены для безопасного импорта"
    }
    val interfaceKeys = setOf("privatekey", "address", "dns", "mtu", "table", "listenport")
    val peerKeys = setOf("publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive")
    var section = ""
    var interfaceCount = 0
    var peerCount = 0
    raw.lineSequence().forEachIndexed { index, sourceLine ->
        val line = sourceLine.trim()
        if (line.isBlank() || line.startsWith("#") || line.startsWith(";")) return@forEachIndexed
        if (line.startsWith("[") && line.endsWith("]")) {
            section = line.substring(1, line.length - 1).trim().lowercase(Locale.ROOT)
            when (section) {
                "interface" -> interfaceCount++
                "peer" -> peerCount++
                else -> throw IllegalArgumentException("неподдерживаемый раздел в строке ${index + 1}")
            }
            return@forEachIndexed
        }
        val separator = line.indexOf('=')
        require(separator in 1 until line.lastIndex) { "неверная строка ${index + 1}" }
        val key = line.substring(0, separator).trim().lowercase(Locale.ROOT)
        val value = line.substring(separator + 1).trim()
        require(value.isNotBlank()) { "пустое значение в строке ${index + 1}" }
        val allowed = when (section) {
            "interface" -> interfaceKeys
            "peer" -> peerKeys
            else -> emptySet()
        }
        require(key in allowed) { "параметр ${line.substring(0, separator).trim()} не разрешён для безопасного импорта" }
        if (key == "mtu") {
            val mtuValue = value.toIntOrNull()
            require(mtuValue != null && mtuValue in 576..9000) { "MTU должен быть от 576 до 9000" }
        }
        if (key == "endpoint") {
            val port = value.substringAfterLast(':', "").toIntOrNull()
            require(port != null && port in 1..65535 && !value.any(Char::isWhitespace)) { "Endpoint должен содержать адрес и порт от 1 до 65535" }
        }
    }
    require(interfaceCount == 1) { "должен быть ровно один раздел [Interface]" }
    require(peerCount == 1) { "должен быть ровно один раздел [Peer]" }
    val allowedIps = Regex("(?im)^\\s*AllowedIPs\\s*=\\s*(.+)$")
        .find(raw)?.groupValues?.getOrNull(1).orEmpty()
        .split(',').map(String::trim)
    require("0.0.0.0/0" in allowedIps) { "для выходного VPN в AllowedIPs должен быть маршрут 0.0.0.0/0" }
}

internal fun sanitizeWireGuardConfigForWdttExit(config: String): String {
    validateWireGuardConfigText(config).getOrThrow()
    val lines = config.trim().lines()
    val out = mutableListOf<String>()
    var inInterface = false
    var tableInserted = false
    lines.forEach { line ->
        val trimmed = line.trim()
        if (trimmed.equals("[Interface]", ignoreCase = true)) {
            inInterface = true
            tableInserted = false
            out += "[Interface]"
            return@forEach
        }
        if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
            if (inInterface && !tableInserted) {
                out += "Table = off"
                tableInserted = true
            }
            inInterface = false
            out += trimmed
            return@forEach
        }
        if (trimmed.startsWith("Table", ignoreCase = true) ||
            trimmed.startsWith("DNS", ignoreCase = true)
        ) return@forEach
        if (trimmed.startsWith("PreUp", ignoreCase = true) ||
            trimmed.startsWith("PostUp", ignoreCase = true) ||
            trimmed.startsWith("PreDown", ignoreCase = true) ||
            trimmed.startsWith("PostDown", ignoreCase = true)
        ) return@forEach
        out += line
    }
    if (inInterface && !tableInserted) out += "Table = off"
    return out.joinToString("\n").trim() + "\n"
}

private fun wireGuardPolicyScript(mode: String, detail: String): String = shellScript(
    outboundShellPrelude(),
    """
    [ -d /sys/class/net/"${'$'}WDTT_IFACE" ] || { echo WDTT_ERROR=wdtt_iface_not_found; exit 2; }
    command -v wg-quick >/dev/null 2>&1 || { echo WDTT_ERROR=wireguard_tools_required; exit 2; }
    command -v iptables >/dev/null 2>&1 || { echo WDTT_ERROR=iptables_required; exit 2; }
    sed -i -E '/^[[:space:]]*DNS[[:space:]]*=/Id' /etc/wireguard/wg-wdtt-exit.conf
    echo "WDTT_PROGRESS|0.72|Отключаю прежний внешний выход WDTT..."
    wdtt_clear_external_out
    echo "WDTT_PROGRESS|0.78|Создаю постоянную службу WireGuard-выхода..."
    mkdir -p /usr/local/lib/wdtt
    cat >/usr/local/lib/wdtt/wg-exit-up <<'WDTT_WG_UP'
    #!/bin/sh
    set -eu
    WDTT_IFACE=wdtt0
    WDTT_WG_IFACE=wg-wdtt-exit
    WDTT_TABLE=100
    WDTT_SUBNET="${'$'}(ip -4 route show dev "${'$'}WDTT_IFACE" scope link 2>/dev/null | awk '{print ${'$'}1; exit}')"
    [ -n "${'$'}WDTT_SUBNET" ] || WDTT_SUBNET=10.66.66.0/24
    wg-quick down "${'$'}WDTT_WG_IFACE" >/dev/null 2>&1 || true
    wg-quick up "${'$'}WDTT_WG_IFACE"
    ip rule del from "${'$'}WDTT_SUBNET" table "${'$'}WDTT_TABLE" priority 100 2>/dev/null || true
    ip rule add from "${'$'}WDTT_SUBNET" table "${'$'}WDTT_TABLE" priority 100
    ip route replace default dev "${'$'}WDTT_WG_IFACE" table "${'$'}WDTT_TABLE"
    iptables -t nat -C POSTROUTING -s "${'$'}WDTT_SUBNET" -o "${'$'}WDTT_WG_IFACE" -m comment --comment WDTT_EXIT -j MASQUERADE 2>/dev/null || \
      iptables -t nat -A POSTROUTING -s "${'$'}WDTT_SUBNET" -o "${'$'}WDTT_WG_IFACE" -m comment --comment WDTT_EXIT -j MASQUERADE
    WDTT_WG_UP
    cat >/usr/local/lib/wdtt/wg-exit-down <<'WDTT_WG_DOWN'
    #!/bin/sh
    WDTT_IFACE=wdtt0
    WDTT_WG_IFACE=wg-wdtt-exit
    WDTT_TABLE=100
    WDTT_SUBNET="${'$'}(ip -4 route show dev "${'$'}WDTT_IFACE" scope link 2>/dev/null | awk '{print ${'$'}1; exit}')"
    [ -n "${'$'}WDTT_SUBNET" ] || WDTT_SUBNET=10.66.66.0/24
    iptables -t nat -D POSTROUTING -s "${'$'}WDTT_SUBNET" -o "${'$'}WDTT_WG_IFACE" -m comment --comment WDTT_EXIT -j MASQUERADE 2>/dev/null || true
    ip rule del from "${'$'}WDTT_SUBNET" table "${'$'}WDTT_TABLE" priority 100 2>/dev/null || true
    ip route flush table "${'$'}WDTT_TABLE" 2>/dev/null || true
    wg-quick down "${'$'}WDTT_WG_IFACE" >/dev/null 2>&1 || true
    WDTT_WG_DOWN
    chmod 700 /usr/local/lib/wdtt/wg-exit-up /usr/local/lib/wdtt/wg-exit-down
    cat >/etc/systemd/system/wdtt-wg-exit.service <<'WDTT_WG_SERVICE'
    [Unit]
    Description=WDTT Plus policy-routed WireGuard exit
    After=network-online.target wdtt.service
    Wants=network-online.target

    [Service]
    Type=oneshot
    RemainAfterExit=yes
    ExecStart=/usr/local/lib/wdtt/wg-exit-up
    ExecStop=/usr/local/lib/wdtt/wg-exit-down

    [Install]
    WantedBy=multi-user.target
    WDTT_WG_SERVICE
    systemctl daemon-reload
    echo "WDTT_PROGRESS|0.84|Поднимаю WireGuard-интерфейс и маршруты WDTT..."
    systemctl enable --now wdtt-wg-exit.service >/dev/null
    systemctl is-active --quiet wdtt-wg-exit.service || { echo WDTT_ERROR=wireguard_exit_service_inactive; exit 3; }
    echo "WDTT_PROGRESS|0.95|Сохраняю новый режим выхода WDTT..."
    wdtt_write_mode ${shellQuote(mode)} ${shellQuote(detail)}
    sleep 1
    echo "WDTT_PROGRESS|1.0|WireGuard-выход включён."
    echo "Выход через WireGuard включён только для WDTT-пользователей."
    echo "Подсеть клиентов WDTT: ${'$'}WDTT_SUBNET"
    wg show "${'$'}WDTT_WG_IFACE" | sed -E 's/(private key: ).*/\1(скрыт)/' || true
    """
)

private fun wgcfToolManagementScript(): String = """
    WGCF_BASELINE_VERSION=${shellQuote(WGCF_VERSION)}
    WGCF_BASELINE_URL=${shellQuote(WGCF_LINUX_AMD64_URL)}
    WGCF_BASELINE_SHA256=${shellQuote(WGCF_LINUX_AMD64_SHA256)}
    WGCF_LATEST_API=${shellQuote(WGCF_LATEST_RELEASE_API)}
    WGCF_BIN=/usr/local/bin/wgcf
    WGCF_STATE_DIR=/etc/wdtt-plus/warp

    wdtt_wgcf_compatible() {
      candidate="${'$'}1"
      [ -x "${'$'}candidate" ] || return 1
      "${'$'}candidate" register --help 2>&1 | grep -q -- '--accept-tos' || return 1
      "${'$'}candidate" generate --help 2>&1 | grep -q -- '--profile' || return 1
      "${'$'}candidate" status --help >/dev/null 2>&1 || return 1
    }

    wdtt_fetch_wgcf_release() {
      version="${'$'}1"
      tag="v${'$'}version"
      file="wgcf_${'$'}{version}_linux_amd64"
      base="https://github.com/ViRb3/wgcf/releases/download/${'$'}tag"
      curl -fsSL --retry 2 --connect-timeout 12 --max-time 180 "${'$'}base/checksums.txt" -o "${'$'}WGCF_TMP/checksums.txt" || return 1
      curl -fsSL --retry 2 --connect-timeout 12 --max-time 300 "${'$'}base/${'$'}file" -o "${'$'}WGCF_TMP/wgcf.candidate" || return 1
      expected="${'$'}(awk -v name="${'$'}file" '${'$'}2 == name {print ${'$'}1; exit}' "${'$'}WGCF_TMP/checksums.txt")"
      [ -n "${'$'}expected" ] || return 1
      actual="${'$'}(sha256sum "${'$'}WGCF_TMP/wgcf.candidate" | awk '{print ${'$'}1}')"
      [ "${'$'}actual" = "${'$'}expected" ] || return 1
      chmod 700 "${'$'}WGCF_TMP/wgcf.candidate"
      wdtt_wgcf_compatible "${'$'}WGCF_TMP/wgcf.candidate" || return 1
      WGCF_SELECTED_VERSION="${'$'}version"
      WGCF_SELECTED_SHA256="${'$'}actual"
      return 0
    }

    wdtt_fetch_wgcf_baseline() {
      curl -fsSL --retry 2 --connect-timeout 12 --max-time 300 "${'$'}WGCF_BASELINE_URL" -o "${'$'}WGCF_TMP/wgcf.candidate" || return 1
      actual="${'$'}(sha256sum "${'$'}WGCF_TMP/wgcf.candidate" | awk '{print ${'$'}1}')"
      [ "${'$'}actual" = "${'$'}WGCF_BASELINE_SHA256" ] || return 1
      chmod 700 "${'$'}WGCF_TMP/wgcf.candidate"
      wdtt_wgcf_compatible "${'$'}WGCF_TMP/wgcf.candidate" || return 1
      WGCF_SELECTED_VERSION="${'$'}WGCF_BASELINE_VERSION"
      WGCF_SELECTED_SHA256="${'$'}actual"
      return 0
    }

    wdtt_install_or_update_wgcf() {
      arch="${'$'}(uname -m)"
      case "${'$'}arch" in
        x86_64|amd64) ;;
        *) echo WDTT_ERROR=warp_unsupported_arch; return 2;;
      esac
      command -v curl >/dev/null 2>&1 || { echo WDTT_ERROR=warp_download_tools_missing; return 2; }
      command -v sha256sum >/dev/null 2>&1 || { echo WDTT_ERROR=warp_checksum_tool_missing; return 2; }
      mkdir -p "${'$'}WGCF_STATE_DIR"
      chmod 700 "${'$'}WGCF_STATE_DIR"
      WGCF_TMP="${'$'}(mktemp -d)"
      WGCF_SELECTED_VERSION=""
      WGCF_SELECTED_SHA256=""
      latest_json="${'$'}WGCF_TMP/latest.json"
      latest_version=""
      if curl -fL --retry 1 --connect-timeout 10 --max-time 30 -H 'Accept: application/vnd.github+json' "${'$'}WGCF_LATEST_API" -o "${'$'}latest_json" 2>/dev/null; then
        latest_tag="${'$'}(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\(v[0-9][0-9.]*\)".*/\1/p' "${'$'}latest_json" | head -n 1)"
        latest_version="${'$'}{latest_tag#v}"
        printf '%s' "${'$'}latest_version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+${'$'}' || latest_version=""
      fi
      if [ -n "${'$'}latest_version" ]; then
        wdtt_fetch_wgcf_release "${'$'}latest_version" || true
      fi
      if [ -z "${'$'}WGCF_SELECTED_VERSION" ]; then
        if wdtt_wgcf_compatible "${'$'}WGCF_BIN"; then
          WGCF_SELECTED_VERSION="${'$'}(cat "${'$'}WGCF_STATE_DIR/wgcf-version" 2>/dev/null || echo установленная)"
          WGCF_SELECTED_SHA256="${'$'}(sha256sum "${'$'}WGCF_BIN" | awk '{print ${'$'}1}')"
          printf '%s\n' "${'$'}WGCF_SELECTED_VERSION" >"${'$'}WGCF_STATE_DIR/wgcf-version"
          printf '%s\n' "${'$'}WGCF_SELECTED_SHA256" >"${'$'}WGCF_STATE_DIR/wgcf-sha256"
          chmod 600 "${'$'}WGCF_STATE_DIR/wgcf-version" "${'$'}WGCF_STATE_DIR/wgcf-sha256"
          rm -rf "${'$'}WGCF_TMP"
          echo "Свежий выпуск wgcf сейчас не проверен; сохранена установленная совместимая версия ${'$'}WGCF_SELECTED_VERSION."
          return 0
        fi
        wdtt_fetch_wgcf_baseline || { rm -rf "${'$'}WGCF_TMP"; echo WDTT_ERROR=warp_wgcf_download_failed; return 2; }
      fi
      current_sha=""
      [ -x "${'$'}WGCF_BIN" ] && current_sha="${'$'}(sha256sum "${'$'}WGCF_BIN" | awk '{print ${'$'}1}')"
      if [ "${'$'}current_sha" != "${'$'}WGCF_SELECTED_SHA256" ]; then
        [ -x "${'$'}WGCF_BIN" ] && cp -f "${'$'}WGCF_BIN" "${'$'}WGCF_BIN.previous" || true
        install -m 700 "${'$'}WGCF_TMP/wgcf.candidate" "${'$'}WGCF_BIN"
        if [ -f "${'$'}WGCF_STATE_DIR/wgcf-account.toml" ] &&
           ! "${'$'}WGCF_BIN" --config "${'$'}WGCF_STATE_DIR/wgcf-account.toml" status >/dev/null 2>&1; then
          if [ -x "${'$'}WGCF_BIN.previous" ]; then
            install -m 700 "${'$'}WGCF_BIN.previous" "${'$'}WGCF_BIN"
            rm -rf "${'$'}WGCF_TMP"
            echo WDTT_ERROR=warp_wgcf_update_rolled_back
            return 2
          fi
        fi
      fi
      printf '%s\n' "${'$'}WGCF_SELECTED_VERSION" >"${'$'}WGCF_STATE_DIR/wgcf-version"
      printf '%s\n' "${'$'}WGCF_SELECTED_SHA256" >"${'$'}WGCF_STATE_DIR/wgcf-sha256"
      chmod 600 "${'$'}WGCF_STATE_DIR/wgcf-version" "${'$'}WGCF_STATE_DIR/wgcf-sha256"
      rm -rf "${'$'}WGCF_TMP"
      echo "Версия wgcf: ${'$'}WGCF_SELECTED_VERSION; SHA-256 проверен."
    }
""".trimIndent()

private fun freeWarpWatchdogInstallScript(): String = """
    mkdir -p /usr/local/lib/wdtt /etc/wdtt-plus/warp
    cat >/usr/local/lib/wdtt/warp-watchdog <<'WDTT_WARP_WATCHDOG'
    #!/bin/sh
    set -u
    MODE="${'$'}(sed -n 's/.*"outboundMode"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /etc/wdtt/outbound.json 2>/dev/null | head -n 1)"
    [ "${'$'}MODE" = warp_free ] || exit 0
    STATE_DIR=/etc/wdtt-plus/warp
    IFACE=wg-wdtt-exit
    TEST_SOURCE="${'$'}(ip -4 -o addr show dev wdtt0 scope global 2>/dev/null | awk '{split(${'$'}4, value, "/"); print value[1]; exit}')"
    check_warp() {
      [ -n "${'$'}TEST_SOURCE" ] || return 1
      trace="${'$'}(curl -4fsS --interface "${'$'}TEST_SOURCE" --connect-timeout 8 --max-time 20 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null || true)"
      printf '%s\n' "${'$'}trace" | grep -Eq '^warp=(on|plus)${'$'}'
    }
    write_state() {
      status="${'$'}1"
      printf 'STATUS=%s\nCHECKED_AT=%s\n' "${'$'}status" "${'$'}(date -Is)" >"${'$'}STATE_DIR/health.env"
      chmod 600 "${'$'}STATE_DIR/health.env"
    }
    if check_warp; then
      write_state healthy
      exit 0
    fi
    systemctl restart wdtt-wg-exit.service >/dev/null 2>&1 || true
    sleep 8
    if check_warp; then
      write_state recovered
      exit 0
    fi
    write_state failed
    exit 1
    WDTT_WARP_WATCHDOG
    chmod 700 /usr/local/lib/wdtt/warp-watchdog
    cat >/etc/systemd/system/wdtt-warp-watchdog.service <<'WDTT_WARP_WATCHDOG_SERVICE'
    [Unit]
    Description=WDTT Plus free WARP health check
    After=network-online.target wdtt-wg-exit.service

    [Service]
    Type=oneshot
    ExecStart=/usr/local/lib/wdtt/warp-watchdog
    WDTT_WARP_WATCHDOG_SERVICE
    cat >/etc/systemd/system/wdtt-warp-watchdog.timer <<'WDTT_WARP_WATCHDOG_TIMER'
    [Unit]
    Description=Check WDTT Plus free WARP every five minutes

    [Timer]
    OnBootSec=2min
    OnUnitActiveSec=5min
    RandomizedDelaySec=30
    Persistent=true

    [Install]
    WantedBy=timers.target
    WDTT_WARP_WATCHDOG_TIMER
    systemctl daemon-reload
    systemctl enable --now wdtt-warp-watchdog.timer >/dev/null
""".trimIndent()

private suspend fun updateWgcfTool(context: Context, target: OutboundSshTarget): String =
    runRootScript(
        context = context,
        target = target,
        script = shellScript(
            outboundShellPrelude(),
            wgcfToolManagementScript(),
            """
            echo "WDTT_PROGRESS|0.15|Проверяю архитектуру и инструменты загрузки..."
            wdtt_install_wireguard_tools || true
            echo "WDTT_PROGRESS|0.45|Проверяю свежий выпуск wgcf и контрольную сумму..."
            wdtt_install_or_update_wgcf
            echo "WDTT_PROGRESS|1.0|Проверка обновления wgcf завершена."
            """
        ),
        timeout = 8 * 60 * 1000L
    )

internal fun buildFreeWarpInstallScript(mtu: Int = 1280): String {
    require(mtu in 1280..1500) { "MTU WARP должен быть от 1280 до 1500" }
    return shellScript(
        "WARP_MTU=$mtu",
        outboundShellPrelude(),
        wgcfToolManagementScript(),
        """
        echo "WDTT_PROGRESS|0.08|Проверяю сервер и устанавливаю WireGuard-инструменты..."
        [ -d /sys/class/net/"${'$'}WDTT_IFACE" ] || { echo WDTT_ERROR=wdtt_iface_not_found; exit 2; }
        wdtt_install_wireguard_tools || true
        command -v wg-quick >/dev/null 2>&1 || { echo WDTT_ERROR=wireguard_tools_required; exit 2; }
        echo "WDTT_PROGRESS|0.24|Проверяю выпуск и SHA-256 инструмента wgcf..."
        wdtt_install_or_update_wgcf
        WARP_DIR=/etc/wdtt-plus/warp
        ACCOUNT="${'$'}WARP_DIR/wgcf-account.toml"
        RAW_PROFILE="${'$'}WARP_DIR/wgcf-profile.raw.conf"
        SAFE_PROFILE="${'$'}WARP_DIR/wgcf-profile.conf"
        mkdir -p "${'$'}WARP_DIR" /etc/wireguard /etc/wdtt-plus/wg-exit
        chmod 700 "${'$'}WARP_DIR"
        umask 077
        echo "WDTT_PROGRESS|0.38|Проверяю сохранённую регистрацию WARP..."
        NEED_REGISTER=0
        if [ -f "${'$'}ACCOUNT" ]; then
          if ! /usr/local/bin/wgcf --config "${'$'}ACCOUNT" status >/dev/null 2>&1; then
            mv "${'$'}ACCOUNT" "${'$'}ACCOUNT.invalid-$(date +%s)"
            NEED_REGISTER=1
          fi
        else
          NEED_REGISTER=1
        fi
        if [ "${'$'}NEED_REGISTER" = 1 ]; then
          echo "WDTT_PROGRESS|0.46|Регистрирую бесплатный профиль Cloudflare WARP..."
          if ! /usr/local/bin/wgcf --config "${'$'}ACCOUNT" register --accept-tos --name "WDTT Plus" --model "WDTT Plus Server" >/tmp/wdtt-wgcf-register.log 2>&1; then
            if [ ! -f "${'$'}ACCOUNT" ] || ! /usr/local/bin/wgcf --config "${'$'}ACCOUNT" status >/dev/null 2>&1; then
              rm -f /tmp/wdtt-wgcf-register.log
              echo WDTT_ERROR=warp_registration_failed
              exit 3
            fi
            echo "Cloudflare вернул ошибку регистрации, но созданный профиль прошёл повторную проверку; продолжаю."
          fi
        fi
        echo "WDTT_PROGRESS|0.56|Создаю WireGuard-профиль WARP..."
        /usr/local/bin/wgcf --config "${'$'}ACCOUNT" generate --profile "${'$'}RAW_PROFILE" >/tmp/wdtt-wgcf-generate.log 2>&1 || {
          rm -f /tmp/wdtt-wgcf-generate.log
          echo WDTT_ERROR=warp_profile_generation_failed
          exit 3
        }
        rm -f /tmp/wdtt-wgcf-register.log /tmp/wdtt-wgcf-generate.log
        grep -Eq '^[[:space:]]*\[Interface\][[:space:]]*${'$'}' "${'$'}RAW_PROFILE" || { echo WDTT_ERROR=warp_profile_invalid; exit 3; }
        grep -Eq '^[[:space:]]*PrivateKey[[:space:]]*=' "${'$'}RAW_PROFILE" || { echo WDTT_ERROR=warp_profile_invalid; exit 3; }
        grep -Eq '^[[:space:]]*Address[[:space:]]*=' "${'$'}RAW_PROFILE" || { echo WDTT_ERROR=warp_profile_invalid; exit 3; }
        grep -Eq '^[[:space:]]*\[Peer\][[:space:]]*${'$'}' "${'$'}RAW_PROFILE" || { echo WDTT_ERROR=warp_profile_invalid; exit 3; }
        grep -Eq '^[[:space:]]*Endpoint[[:space:]]*=' "${'$'}RAW_PROFILE" || { echo WDTT_ERROR=warp_profile_invalid; exit 3; }
        grep -Eq '^[[:space:]]*AllowedIPs[[:space:]]*=.*0\.0\.0\.0/0' "${'$'}RAW_PROFILE" || { echo WDTT_ERROR=warp_profile_invalid; exit 3; }
        [ "${'$'}(wc -c <"${'$'}RAW_PROFILE")" -le 65536 ] || { echo WDTT_ERROR=warp_profile_invalid; exit 3; }
        [ "${'$'}(grep -Eic '^[[:space:]]*\[Interface\][[:space:]]*${'$'}' "${'$'}RAW_PROFILE")" = 1 ] || { echo WDTT_ERROR=warp_profile_invalid; exit 3; }
        [ "${'$'}(grep -Eic '^[[:space:]]*\[Peer\][[:space:]]*${'$'}' "${'$'}RAW_PROFILE")" = 1 ] || { echo WDTT_ERROR=warp_profile_invalid; exit 3; }
        ! grep -Eqi '^[[:space:]]*(PreUp|PostUp|PreDown|PostDown)[[:space:]]*=' "${'$'}RAW_PROFILE" || { echo WDTT_ERROR=warp_profile_invalid; exit 3; }
        printf '%s' "${'$'}WARP_MTU" | grep -Eq '^(12[89][0-9]|1[3-4][0-9][0-9]|1500)${'$'}' || { echo WDTT_ERROR=warp_mtu_invalid; exit 3; }
        awk -v mtu="${'$'}WARP_MTU" '
          BEGIN { in_interface=0 }
          /^[[:space:]]*\[Interface\][[:space:]]*${'$'}/ { print "[Interface]"; print "Table = off"; print "MTU = " mtu; in_interface=1; next }
          /^[[:space:]]*\[/ { in_interface=0; print; next }
          /^[[:space:]]*(Table|MTU|DNS|PreUp|PostUp|PreDown|PostDown)[[:space:]]*=/ { next }
          { print }
        ' "${'$'}RAW_PROFILE" >"${'$'}SAFE_PROFILE"
        chmod 600 "${'$'}ACCOUNT" "${'$'}RAW_PROFILE" "${'$'}SAFE_PROFILE"
        install -m 600 "${'$'}SAFE_PROFILE" /etc/wireguard/wg-wdtt-exit.conf
        install -m 600 "${'$'}SAFE_PROFILE" /etc/wdtt-plus/wg-exit/wg-wdtt-exit.conf
        """,
        wireGuardPolicyScript("warp_free", "бесплатный Cloudflare WARP"),
        freeWarpWatchdogInstallScript(),
        """
        echo "WDTT_PROGRESS|0.96|Проверяю, что трафик действительно выходит через WARP..."
        TEST_SOURCE="${'$'}(wdtt_test_source)"
        [ -n "${'$'}TEST_SOURCE" ] || { echo WDTT_ERROR=wdtt_test_source_missing; exit 3; }
        TRACE=""
        for attempt in 1 2 3; do
          TRACE="${'$'}(curl -4fsS --interface "${'$'}TEST_SOURCE" --connect-timeout 8 --max-time 25 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null || true)"
          printf '%s\n' "${'$'}TRACE" | grep -Eq '^warp=(on|plus)${'$'}' && break
          [ "${'$'}attempt" = 3 ] || {
            echo "WDTT_PROGRESS|0.97|WARP пока не ответил, переподключаю канал (${'$'}attempt/3)..."
            systemctl restart wdtt-wg-exit.service >/dev/null 2>&1 || true
            sleep 6
          }
        done
        if ! printf '%s\n' "${'$'}TRACE" | grep -Eq '^warp=(on|plus)${'$'}'; then
          systemctl disable --now wdtt-warp-watchdog.timer 2>/dev/null || true
          wdtt_clear_external_out
          wdtt_write_mode "direct" "rollback after WARP check error"
          echo WDTT_ERROR=warp_trace_check_failed
          exit 3
        fi
        EXIT_IP="${'$'}(curl -4fsS --interface "${'$'}TEST_SOURCE" --connect-timeout 8 --max-time 20 https://api.ipify.org 2>/dev/null || true)"
        printf 'STATUS=healthy\nCHECKED_AT=%s\n' "${'$'}(date -Is)" >/etc/wdtt-plus/warp/health.env
        chmod 600 /etc/wdtt-plus/warp/health.env
        echo "WDTT_PROGRESS|1.0|Бесплатный WARP установлен и проверен."
        echo "Бесплатный WARP включён только для WDTT-пользователей."
        [ -n "${'$'}EXIT_IP" ] && echo "Проверочный выходной IP Cloudflare: ${'$'}EXIT_IP"
        echo "Автоматическая проверка запускается каждые 5 минут и один раз перезапускает WireGuard при сбое."
        """
    )
}

private suspend fun installOrRepairFreeWarp(
    context: Context,
    target: OutboundSshTarget,
    mtu: Int
): String = runRootScript(context, target, buildFreeWarpInstallScript(mtu), timeout = CMD_TIMEOUT)

private suspend fun checkFreeWarp(
    target: OutboundSshTarget,
    restartOnFailure: Boolean
): String = withContext(Dispatchers.IO) {
    var session: Session? = null
    try {
        session = createSSHSession(target.host, target.user, target.pass, target.port)
        val ssh = SSHClient(session, target.pass)
        val restart = if (restartOnFailure) "1" else "0"
        val script = shellScript(
            outboundShellPrelude(),
            """
            MODE="${'$'}(sed -n 's/.*"outboundMode"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /etc/wdtt/outbound.json 2>/dev/null | head -n 1)"
            [ "${'$'}MODE" = "warp_free" ] || { echo WDTT_ERROR=warp_mode_not_active; exit 3; }
            [ -f /etc/wdtt-plus/warp/wgcf-account.toml ] || { echo WDTT_ERROR=warp_account_missing; exit 3; }
            [ -f /etc/wireguard/wg-wdtt-exit.conf ] || { echo WDTT_ERROR=warp_profile_missing; exit 3; }
            command -v wg >/dev/null 2>&1 || { echo WDTT_ERROR=wireguard_tools_required; exit 2; }
            if [ "$restart" = 1 ]; then
              systemctl restart wdtt-wg-exit.service >/dev/null 2>&1 || { echo WDTT_ERROR=wireguard_exit_service_inactive; exit 3; }
              sleep 4
            fi
            wg show "${'$'}WDTT_WG_IFACE" >/dev/null 2>&1 || { echo WDTT_ERROR=wireguard_not_active; exit 3; }
            TEST_SOURCE="${'$'}(wdtt_test_source)"
            [ -n "${'$'}TEST_SOURCE" ] || { echo WDTT_ERROR=wdtt_test_source_missing; exit 3; }
            TRACE="${'$'}(curl -4fsS --interface "${'$'}TEST_SOURCE" --connect-timeout 8 --max-time 25 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null || true)"
            printf '%s\n' "${'$'}TRACE" | grep -Eq '^warp=(on|plus)${'$'}' || { echo WDTT_ERROR=warp_trace_check_failed; exit 3; }
            EXIT_IP="${'$'}(curl -4fsS --interface "${'$'}TEST_SOURCE" --connect-timeout 8 --max-time 20 https://api.ipify.org 2>/dev/null || true)"
            WARP_KIND="${'$'}(printf '%s\n' "${'$'}TRACE" | sed -n 's/^warp=//p' | head -n 1)"
            VERSION="${'$'}(cat /etc/wdtt-plus/warp/wgcf-version 2>/dev/null || echo неизвестна)"
            TIMER="${'$'}(systemctl is-active wdtt-warp-watchdog.timer 2>/dev/null || true)"
            HANDSHAKE="${'$'}(wg show "${'$'}WDTT_WG_IFACE" latest-handshakes 2>/dev/null | awk '{print ${'$'}2}' | sort -nr | head -n 1)"
            printf 'STATUS=healthy\nCHECKED_AT=%s\n' "${'$'}(date -Is)" >/etc/wdtt-plus/warp/health.env
            chmod 600 /etc/wdtt-plus/warp/health.env
            echo "Проверка успешна: Cloudflare сообщает warp=${'$'}WARP_KIND."
            [ -n "${'$'}EXIT_IP" ] && echo "Выходной IP: ${'$'}EXIT_IP"
            echo "wgcf: ${'$'}VERSION"
            echo "Автопроверка: ${'$'}{TIMER:-не запущена}"
            [ -n "${'$'}HANDSHAKE" ] && [ "${'$'}HANDSHAKE" != 0 ] && echo "Последнее WireGuard-рукопожатие: $(date -d @${'$'}HANDSHAKE -Is 2>/dev/null || echo ${'$'}HANDSHAKE)"
            """
        )
        val output = ssh.exec(rootCommand(script), timeout = 45000L).trim()
        markerValue(output, "WDTT_ERROR")?.let { throw IllegalStateException(output.take(1200)) }
        output
    } finally {
        try { session?.disconnect() } catch (_: Exception) {}
    }
}

private suspend fun deleteFreeWarp(target: OutboundSshTarget): String = withContext(Dispatchers.IO) {
    var session: Session? = null
    try {
        session = createSSHSession(target.host, target.user, target.pass, target.port)
        val ssh = SSHClient(session, target.pass)
        val script = shellScript(
            outboundShellPrelude(),
            """
            MODE="${'$'}(sed -n 's/.*"outboundMode"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /etc/wdtt/outbound.json 2>/dev/null | head -n 1)"
            echo "WDTT_PROGRESS|0.20|Останавливаю автоматическую проверку WARP..."
            systemctl disable --now wdtt-warp-watchdog.timer wdtt-warp-watchdog.service 2>/dev/null || true
            if [ "${'$'}MODE" = "warp_free" ]; then
              echo "WDTT_PROGRESS|0.45|Возвращаю прямой выход WDTT..."
              wdtt_clear_external_out
              rm -f /etc/wireguard/wg-wdtt-exit.conf /etc/wdtt-plus/wg-exit/wg-wdtt-exit.conf
              wdtt_write_mode "direct" "прямой выход"
            fi
            echo "WDTT_PROGRESS|0.70|Удаляю регистрацию, ключи и профиль WARP..."
            rm -rf /etc/wdtt-plus/warp
            rm -f /usr/local/bin/wgcf /usr/local/bin/wgcf.previous /usr/local/lib/wdtt/warp-watchdog
            rm -f /etc/systemd/system/wdtt-warp-watchdog.service /etc/systemd/system/wdtt-warp-watchdog.timer
            systemctl daemon-reload 2>/dev/null || true
            systemctl reset-failed wdtt-warp-watchdog.service 2>/dev/null || true
            echo "WDTT_PROGRESS|1.0|Бесплатный WARP удалён."
            echo "Регистрация, ключи, профиль и автоматическая проверка WARP удалены с сервера."
            if [ "${'$'}MODE" = "warp_free" ]; then
              echo "WDTT-пользователи снова выходят напрямую через текущий VPS."
            else
              echo "Другой активный режим выхода не изменён."
            fi
            """
        )
        val output = ssh.exec(rootCommand(script), timeout = 60000L).trim()
        markerValue(output, "WDTT_ERROR")?.let { throw IllegalStateException(output.take(1200)) }
        output
    } finally {
        try { session?.disconnect() } catch (_: Exception) {}
    }
}

private suspend fun enableImportedWireGuardExit(
    context: Context,
    target: OutboundSshTarget,
    config: String
): String = withContext(Dispatchers.IO) {
    val sanitized = sanitizeWireGuardConfigForWdttExit(config)
    var session: Session? = null
    val configFile = File(context.cacheDir, "wdtt-imported-wg.conf")
    try {
        configFile.writeText(sanitized)
        session = createSSHSession(target.host, target.user, target.pass, target.port)
        val ssh = SSHClient(session, target.pass)
        ssh.upload(configFile, "/tmp/wdtt-imported-wg.conf")
        val script = shellScript(
            outboundShellPrelude(),
            """
            echo "WDTT_PROGRESS|0.18|Готовлю инструменты WireGuard на текущем сервере..."
            wdtt_install_wireguard_tools || true
            echo "WDTT_PROGRESS|0.45|Сохраняю выбранный VPN/WireGuard-файл без опасных команд..."
            mkdir -p /etc/wdtt-plus/wg-exit /etc/wireguard
            install -m 600 /tmp/wdtt-imported-wg.conf /etc/wdtt-plus/wg-exit/wg-wdtt-exit.conf
            install -m 600 /tmp/wdtt-imported-wg.conf /etc/wireguard/wg-wdtt-exit.conf
            rm -f /tmp/wdtt-imported-wg.conf
            """,
            wireGuardPolicyScript("imported_wg", "VPN/WireGuard-файл")
        )
        val output = ssh.exec(rootCommand(script), timeout = CMD_TIMEOUT)
        markerValue(output, "WDTT_ERROR")?.let { throw IllegalStateException(it) }
        output.trim()
    } finally {
        configFile.delete()
        try { session?.disconnect() } catch (_: Exception) {}
    }
}

private suspend fun deleteImportedWireGuardExit(target: OutboundSshTarget): String = withContext(Dispatchers.IO) {
    var session: Session? = null
    try {
        session = createSSHSession(target.host, target.user, target.pass, target.port)
        val ssh = SSHClient(session, target.pass)
        val script = shellScript(
            outboundShellPrelude(),
            """
            echo "WDTT_PROGRESS|0.25|Отключаю WireGuard-выход, если он запущен..."
            wdtt_clear_external_out
            echo "WDTT_PROGRESS|0.60|Удаляю сохранённый VPN/WireGuard-файл..."
            rm -f /etc/wdtt-plus/wg-exit/wg-wdtt-exit.conf /etc/wireguard/wg-wdtt-exit.conf
            if [ -f /etc/wdtt/outbound-profile.env ]; then
              tmp_profile=/etc/wdtt/outbound-profile.env.tmp
              grep -v '^IMPORTED_WG_CONFIG_B64=' /etc/wdtt/outbound-profile.env >"${'$'}tmp_profile" 2>/dev/null || true
              chmod 600 "${'$'}tmp_profile"
              mv "${'$'}tmp_profile" /etc/wdtt/outbound-profile.env
            fi
            echo "WDTT_PROGRESS|0.85|Возвращаю прямой выход через текущий сервер..."
            wdtt_write_mode "direct" "прямой выход"
            echo "WDTT_PROGRESS|1.0|VPN/WireGuard-файл удалён."
            echo "VPN/WireGuard-файл удалён, выход WDTT возвращён напрямую через текущий сервер."
            """
        )
        ssh.exec(rootCommand(script), timeout = 30000L).trim()
    } finally {
        try { session?.disconnect() } catch (_: Exception) {}
    }
}

private suspend fun installWireGuardExitVps(
    context: Context,
    current: OutboundSshTarget,
    foreignHost: String,
    foreignPort: Int,
    foreignUser: String,
    foreignPassword: String,
    wgPort: Int,
    dns: String
): String = withContext(Dispatchers.IO) {
    var currentSession: Session? = null
    var foreignSession: Session? = null
    try {
        DeployManager.updateProgress(0.10f, "Подключаюсь к текущему серверу WDTT...")
        currentSession = createSSHSession(current.host, current.user, current.pass, current.port)
        DeployManager.updateProgress(0.18f, "Подключаюсь к другому серверу для WireGuard-выхода...")
        foreignSession = createSSHSession(foreignHost, foreignUser, foreignPassword, foreignPort)
        val currentSsh = SSHClient(currentSession, current.pass)
        val foreignSsh = SSHClient(foreignSession, foreignPassword)

        val prepareKeys = """
            echo "WDTT_PROGRESS|0.26|Готовлю WireGuard-инструменты и ключи..."
            wdtt_install_wireguard_tools || true
            command -v wg >/dev/null 2>&1 || { echo WDTT_ERROR=wireguard_tools_required; exit 2; }
            mkdir -p /etc/wdtt-plus/wg-exit
            umask 077
            [ -f /etc/wdtt-plus/wg-exit/private.key ] || wg genkey >/etc/wdtt-plus/wg-exit/private.key
            wg pubkey </etc/wdtt-plus/wg-exit/private.key >/etc/wdtt-plus/wg-exit/public.key
            printf 'WDTT_WG_PUB='; cat /etc/wdtt-plus/wg-exit/public.key; printf '\n'
        """.trimIndent()
        DeployManager.updateProgress(0.28f, "Готовлю WireGuard-ключи на текущем сервере...")
        val currentPub = markerValue(currentSsh.exec(rootCommand(prepareKeys), timeout = CMD_TIMEOUT), "WDTT_WG_PUB")
            ?: throw IllegalStateException("текущий сервер не отдал публичный ключ WireGuard")
        DeployManager.updateProgress(0.38f, "Готовлю WireGuard-ключи на другом сервере...")
        val foreignPub = markerValue(foreignSsh.exec(rootCommand(prepareKeys), timeout = CMD_TIMEOUT), "WDTT_WG_PUB")
            ?: throw IllegalStateException("другой сервер не отдал публичный ключ WireGuard")

        val foreignConfigScript = shellScript(
            """
            CURRENT_PUB=${shellQuote(currentPub)}
            WG_PORT=$wgPort
            """,
            outboundShellPrelude(),
            """
            echo "WDTT_PROGRESS|0.50|Определяю внешний интерфейс другого сервера..."
            EXT_IFACE="${'$'}(wdtt_ext_iface)"
            [ -n "${'$'}EXT_IFACE" ] || { echo WDTT_ERROR=foreign_ext_iface_not_found; exit 2; }
            echo "WDTT_PROGRESS|0.56|Включаю пересылку трафика на другом сервере..."
            sysctl -w net.ipv4.ip_forward=1 >/dev/null
            mkdir -p /etc/sysctl.d /etc/wireguard
            printf 'net.ipv4.ip_forward=1\n' >/etc/sysctl.d/99-wdtt-exit-forward.conf
            PRIV="${'$'}(cat /etc/wdtt-plus/wg-exit/private.key)"
            echo "WDTT_PROGRESS|0.62|Записываю WireGuard-настройки другого сервера..."
            cat >/etc/wireguard/wg-wdtt-exit.conf <<EOF
            [Interface]
            Address = 10.77.77.1/30
            ListenPort = ${'$'}WG_PORT
            PrivateKey = ${'$'}PRIV

            [Peer]
            PublicKey = ${'$'}CURRENT_PUB
            AllowedIPs = 10.77.77.2/32
            EOF
            chmod 600 /etc/wireguard/wg-wdtt-exit.conf
            echo "WDTT_PROGRESS|0.68|Запускаю WireGuard на другом сервере..."
            systemctl enable --now wg-quick@wg-wdtt-exit >/dev/null
            echo "WDTT_PROGRESS|0.70|Открываю порт WireGuard и добавляю NAT на другом сервере..."
            iptables -C INPUT -p udp --dport "${'$'}WG_PORT" -m comment --comment WDTT_EXIT_FOREIGN -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport "${'$'}WG_PORT" -m comment --comment WDTT_EXIT_FOREIGN -j ACCEPT
            iptables -t nat -C POSTROUTING -s 10.77.77.0/30 -o "${'$'}EXT_IFACE" -m comment --comment WDTT_EXIT_FOREIGN -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.77.77.0/30 -o "${'$'}EXT_IFACE" -m comment --comment WDTT_EXIT_FOREIGN -j MASQUERADE
            echo "WireGuard на другом сервере запущен: ${'$'}EXT_IFACE"
            """
        )
        DeployManager.updateProgress(0.48f, "Настраиваю WireGuard на другом сервере...")
        foreignSsh.exec(rootCommand(foreignConfigScript), timeout = CMD_TIMEOUT)

        val currentConfigScript = shellScript(
            """
            FOREIGN_PUB=${shellQuote(foreignPub)}
            FOREIGN_HOST=${shellQuote(foreignHost)}
            WG_PORT=$wgPort
            DNS_VALUE=${shellQuote(dns.ifBlank { "1.1.1.1,8.8.8.8" })}
            """,
            outboundShellPrelude(),
            """
            echo "WDTT_PROGRESS|0.72|Записываю WireGuard-настройки текущего сервера..."
            mkdir -p /etc/wireguard /etc/wdtt-plus/wg-exit
            PRIV="${'$'}(cat /etc/wdtt-plus/wg-exit/private.key)"
            cat >/etc/wireguard/wg-wdtt-exit.conf <<EOF
            [Interface]
            Address = 10.77.77.2/30
            PrivateKey = ${'$'}PRIV
            DNS = ${'$'}DNS_VALUE
            Table = off

            [Peer]
            PublicKey = ${'$'}FOREIGN_PUB
            Endpoint = ${'$'}FOREIGN_HOST:${'$'}WG_PORT
            AllowedIPs = 0.0.0.0/0
            PersistentKeepalive = 25
            EOF
            chmod 600 /etc/wireguard/wg-wdtt-exit.conf
            install -m 600 /etc/wireguard/wg-wdtt-exit.conf /etc/wdtt-plus/wg-exit/wg-wdtt-exit.conf
            """,
            wireGuardPolicyScript("wireguard_vps", "другой сервер ${foreignHost}:${wgPort}")
        )
        DeployManager.updateProgress(0.72f, "Применяю WireGuard-выход на текущем сервере...")
        val output = currentSsh.exec(rootCommand(currentConfigScript), timeout = CMD_TIMEOUT)
        if (output.contains("WDTT_ERROR=")) throw IllegalStateException(output.trim().take(400))
        DeployManager.updateProgress(1f, "WireGuard-выход через другой сервер включён.")
        output.trim().ifBlank { "Выход через WireGuard включён для WDTT-пользователей." }
    } catch (e: Exception) {
        try { currentSession?.let { SSHClient(it, current.pass).exec(rootCommand("${outboundShellPrelude()}\nwdtt_clear_external_out\nwdtt_write_mode \"direct\" \"rollback\""), timeout = 30000L) } } catch (_: Exception) {}
        throw e
    } finally {
        try { currentSession?.disconnect() } catch (_: Exception) {}
        try { foreignSession?.disconnect() } catch (_: Exception) {}
    }
}

private fun File.containsBinaryToken(token: String): Boolean {
    val data = readBytes()
    val needle = token.toByteArray()
    if (needle.isEmpty() || data.size < needle.size) return false
    for (i in 0..data.size - needle.size) {
        var matched = true
        for (j in needle.indices) {
            if (data[i + j] != needle[j]) {
                matched = false
                break
            }
        }
        if (matched) return true
    }
    return false
}

private fun isUnsafeLegacyServerAsset(serverFile: File): Boolean {
	val hasCurrentLayout = serverFile.containsBinaryToken("/etc/wdtt") &&
		serverFile.containsBinaryToken("wdtt0")
	val hasLegacyMarkers = serverFile.containsBinaryToken("/etc/wireguard") ||
		serverFile.containsBinaryToken("wg0")
	return hasLegacyMarkers && !hasCurrentLayout
}

private suspend fun checkExistingInstall(
	host: String,
	user: String,
	pass: String,
	port: Int
): ExistingInstallInfo = withContext(Dispatchers.IO) {
	var session: Session? = null
	try {
		session = createSSHSession(host, user, pass, port)
		val ssh = SSHClient(session, pass)
		val output = ssh.exec(
			rootCommand(
				"printf 'SERVICE=%s\\n' \"$([ -f /etc/systemd/system/wdtt.service ] && echo 1 || echo 0)\"; " +
					"printf 'BINARY=%s\\n' \"$([ -f /usr/local/bin/wdtt-server ] && echo 1 || echo 0)\"; " +
					"printf 'CONFIG_DIR=%s\\n' \"$([ -d /etc/wdtt ] && echo 1 || echo 0)\"; " +
					"printf 'ACCESS_DB=%s\\n' \"$([ -f /etc/wdtt/passwords.json ] && echo 1 || echo 0)\"; " +
					"printf 'WG_KEYS=%s\\n' \"$([ -f /etc/wdtt/wg-keys.dat ] && echo 1 || echo 0)\"; " +
					"printf 'ACTIVE=%s\\n' \"$(systemctl is-active wdtt 2>/dev/null || true)\""
			),
			timeout = 15000L
		)
		if (output.startsWith("error:", ignoreCase = true) || output.contains("\nerror:", ignoreCase = true)) {
			throw IllegalStateException(output.trim().take(300))
		}
		fun flag(name: String): Boolean = Regex("^$name=1$", RegexOption.MULTILINE).containsMatchIn(output)
		ExistingInstallInfo(
			serviceExists = flag("SERVICE"),
			binaryExists = flag("BINARY"),
			configDirExists = flag("CONFIG_DIR"),
			accessDbExists = flag("ACCESS_DB"),
			wgKeysExist = flag("WG_KEYS"),
			active = Regex("^ACTIVE=active$", RegexOption.MULTILINE).containsMatchIn(output)
		)
	} finally {
		try { session?.disconnect() } catch (_: Exception) {}
	}
}

private fun markerValue(output: String, name: String): String? =
    Regex("^$name=(.*)$", setOf(RegexOption.MULTILINE)).find(output)?.groupValues?.getOrNull(1)?.trim()

private fun compactRemoteTail(raw: String): String {
    val lines = raw.lineSequence()
        .map { it.trim() }
        .filter { it.isNotBlank() && !it.startsWith("WDTT_PROGRESS|") && !it.startsWith("WDTT_ERROR=") }
        .toList()
    return lines.takeLast(4).joinToString(" ").take(260)
}

private fun friendlyDeployError(error: Throwable, operation: String): String {
    val rawFull = listOfNotNull(error.message, error.cause?.message)
        .joinToString(" ")
        .ifBlank { error.toString() }
    val raw = rawFull
        .replace(Regex("\\s+"), " ")
        .trim()
    val lower = raw.lowercase(Locale.ROOT)
    val remoteTail = compactRemoteTail(rawFull)
    val withTail: (String) -> String = { message ->
        if (remoteTail.isBlank()) message else "$message Последние строки сервера: $remoteTail"
    }
    val hint = when {
        operation.contains("экспорт", ignoreCase = true) && "permission denied" in lower ->
            "Android не разрешил записать файл экспорта в выбранное место."
        "3proxy_source_no_curl" in lower ->
            "не удалось скачать исходники 3proxy: на сервере нет curl, и пакетный менеджер не смог его поставить."
        "3proxy_source_no_tar" in lower ->
            "не удалось распаковать исходники 3proxy: на сервере нет tar, и пакетный менеджер не смог его поставить."
        "3proxy_source_no_gzip" in lower ->
            "не удалось распаковать исходники 3proxy: на сервере нет gzip, и пакетный менеджер не смог его поставить."
        "3proxy_source_no_make" in lower ->
            "не удалось собрать 3proxy: на сервере нет make, и пакетный менеджер не смог его поставить."
        "3proxy_source_no_compiler" in lower ->
            "не удалось собрать 3proxy: на сервере нет компилятора gcc/cc, и пакетный менеджер не смог его поставить."
        "3proxy_source_no_openssl_headers" in lower ->
            "не удалось собрать 3proxy: на сервере нет OpenSSL-заголовков. Нужен пакет libssl-dev, openssl-devel, libopenssl-devel или openssl-dev в зависимости от Linux-дистрибутива."
        "3proxy_source_download_failed" in lower ->
            "не удалось скачать исходники 3proxy с GitHub. Проверьте, открывается ли github.com с сервера и не блокирует ли сеть исходящие HTTPS-подключения."
        "3proxy_source_unpack_failed" in lower ->
            "архив 3proxy скачался, но сервер не смог его распаковать. Возможен битый архив, нехватка места или проблема с tar/gzip."
        "3proxy_source_build_failed" in lower ->
            withTail("исходники 3proxy скачались, но сборка на сервере не завершилась. Часто причина в отсутствующих dev-пакетах libc, нестандартной ОС или ошибке компилятора.")
        "3proxy_source_binary_missing" in lower ->
            "сборка 3proxy завершилась без явной ошибки, но готовый файл 3proxy не найден."
        "3proxy_source_install_failed" in lower ->
            "3proxy собрался, но сервер не дал записать файл в /usr/local/bin. Проверьте root-права SSH-пользователя и sudo."
        "3proxy_install_failed" in lower || "3proxy_not_installed" in lower ->
            "не удалось установить 3proxy: пакет не найден в репозиториях сервера, а сборка из исходников не дала готовый файл. Повторите установку: теперь приложение покажет конкретный шаг, на котором она сорвалась."
        "systemd_required" in lower ->
            "для прокси на этом сервере нужна systemd-служба. На сервере не найден systemctl, поэтому приложение не может безопасно запустить 3proxy как сервис."
        "curl_not_installed" in lower ->
            "на сервере не найден curl, поэтому проверка внешнего IP не выполнилась."
        "local_proxy_check_failed" in lower ->
            "проверка не устанавливает прокси: она подключается к уже запущенному SOCKS5 на 127.0.0.1 с указанными портом, логином и паролем. Подключение не удалось. Нажмите «Установить» или проверьте эти данные."
        "local_proxy_service_inactive" in lower ->
            "служба wdtt-3proxy не запущена. Нажмите «Установить», чтобы создать или обновить прокси на сервере."
        "local_proxy_service_still_active" in lower ->
            "приложение отправило команду остановки, но служба wdtt-3proxy всё ещё запущена. Проверьте права пользователя SSH или остановите службу вручную."
        "external_proxy_check_failed" in lower ->
            "внешний TCP-прокси не ответил на проверку. Проверьте адрес, порт, логин и пароль."
        "external_proxy_service_inactive" in lower ->
            "служба перенаправления через внешний TCP-прокси не запустилась. Приложение откатило правила и вернуло прямой выход, чтобы интернет через VPN не остался сломанным."
        "external_proxy_apply_failed" in lower ->
            withTail("внешний TCP-прокси отвечает напрямую, но путь WDTT через redsocks не заработал. Приложение откатило правила и вернуло прямой выход, чтобы VPN-интернет не пропал.")
        "redsocks_not_installed" in lower ->
            "не удалось установить компонент перенаправления через внешний TCP-прокси. Проверьте пакетный менеджер и доступ сервера к интернету."
        "iptables_required" in lower ->
            "на сервере не найдены правила межсетевого экрана iptables, без них этот режим не включить."
        "wdtt_iface_not_found" in lower ->
            "на сервере не найден интерфейс WDTT. Сначала запустите сервер WDTT Plus и проверьте подключение."
        "wdtt_test_source_missing" in lower ->
            "интерфейс WDTT запущен без IPv4-адреса, поэтому безопасно проверить реальный путь клиентского трафика не получилось."
        "wireguard_tools_required" in lower ->
            "на сервере не найдены инструменты WireGuard, без них этот режим не включить."
        "wireguard_exit_service_inactive" in lower ->
            "служба WireGuard-выхода не запустилась. Приложение не будет оставлять неполные маршруты; проверьте конфигурацию и журнал systemd."
        "wireguard_not_active" in lower ->
            "WireGuard-выход WDTT сейчас не запущен. Включите «Бесплатный WARP», «Другой сервер» или «VPN/WireGuard-файл», затем повторите проверку."
        "wireguard_exit_check_failed" in lower ->
            "WireGuard-интерфейс запущен, но проверочный сайт через него не открылся. Проверьте конфиг, endpoint, NAT и доступ второго сервера/VPN к интернету."
        "warp_unsupported_arch" in lower ->
            "автоматический WARP поддерживает Linux amd64 — ту же архитектуру, для которой собирается сервер WDTT Plus. На этом сервере определена другая архитектура."
        "warp_download_tools_missing" in lower ->
            "на сервере нет curl, поэтому безопасно скачать wgcf не получилось. Проверьте пакетный менеджер и доступ сервера к интернету."
        "warp_checksum_tool_missing" in lower ->
            "на сервере нет sha256sum, поэтому приложение отказалось запускать wgcf без проверки контрольной суммы."
        "warp_wgcf_download_failed" in lower ->
            "не удалось получить совместимый wgcf с корректной SHA-256. Проверены свежий выпуск и закреплённая резервная версия; ни один файл не был запущен."
        "warp_wgcf_update_rolled_back" in lower ->
            "новый wgcf прошёл проверку файла, но не смог прочитать действующую WARP-регистрацию. Приложение вернуло предыдущий бинарник."
        "warp_registration_failed" in lower ->
            withTail("Cloudflare не принял регистрацию бесплатного WARP. Проверьте доступ сервера к api.cloudflareclient.com и повторите позже.")
        "warp_profile_generation_failed" in lower ->
            withTail("регистрация WARP найдена, но wgcf не смог создать WireGuard-профиль. Существующие ключи сохранены; повторите восстановление.")
        "warp_profile_invalid" in lower ->
            "wgcf создал неполный WireGuard-профиль. Он не был применён к серверу."
        "warp_mtu_invalid" in lower ->
            "сервер отклонил MTU WARP: допустимо только целое значение от 1280 до 1500."
        "warp_trace_check_failed" in lower ->
            "WireGuard запустился, но Cloudflare не подтвердил warp=on/plus. Возможны временный сбой endpoint или региональное ограничение WARP. При установке приложение вернуло прямой выход; при обычной проверке можно попробовать перезапуск или восстановление."
        "warp_mode_not_active" in lower ->
            "бесплатный WARP сейчас не выбран как активный выход WDTT. Сначала нажмите «Установить / восстановить»."
        "warp_account_missing" in lower ->
            "на сервере не найдена регистрация бесплатного WARP. Нажмите «Установить / восстановить» и подтвердите условия Cloudflare."
        "warp_profile_missing" in lower ->
            "регистрация WARP есть, но WireGuard-профиль отсутствует. Нажмите «Установить / восстановить»."
        "foreign_ext_iface_not_found" in lower ->
            "на другом сервере не удалось определить основной сетевой интерфейс."
        "root privileges required" in lower ||
            "sudo not found" in lower ->
            "для операции нужны права администратора на сервере: войдите под root или установите sudo."
        "auth fail" in lower ||
            "authentication failed" in lower ||
            "auth cancel" in lower ||
            "permission denied" in lower ->
            "не удалось войти по SSH. Проверьте логин, SSH-пароль и порт."
        "connection refused" in lower ->
            "сервер доступен, но SSH-порт отклоняет подключение. Проверьте SSH-порт и правила межсетевого экрана."
        "unknownhost" in lower ||
            "unknown host" in lower ||
            "name or service not known" in lower ||
            "no address associated" in lower ->
            "не удалось найти сервер. Проверьте IP или домен."
        "timeout" in lower ||
            "timed out" in lower ->
            "сервер не ответил вовремя. Проверьте сеть, IP, SSH-порт и правила межсетевого экрана."
        "network is unreachable" in lower ||
            "no route to host" in lower ->
            "сервер недоступен из текущей сети. Проверьте интернет, IP и правила межсетевого экрана."
        "session is down" in lower ->
            "SSH-сессия оборвалась во время операции. Повторите действие после проверки соединения."
        "no_passwords_json" in lower ||
            "passwords.json" in lower && ("не найден" in lower || "не отдал" in lower) ->
            "на сервере не найдена база WDTT Plus. Сначала выполните деплой или проверьте путь /etc/wdtt/passwords.json."
        "главный пароль" in lower ||
            "main_password" in lower && "пуст" !in lower ->
            "главный пароль администратора не совпадает с сервером."
        "это не файл бэкапа" in lower ||
            "format" in lower && "wdtt-server-backup" in lower ->
            "выбран файл не того формата. Нужен JSON-экспорт WDTT Plus."
        "passwords должен быть объектом" in lower ||
            "devices должен быть объектом" in lower ||
            "некоррект" in lower ||
            "неподдерживаемая версия" in lower ||
            "слишком" in lower ->
            "файл импорта повреждён или не соответствует ожидаемой структуре: ${raw.take(160)}"
        "wdtt.service" in lower && "active" in lower ->
            "импорт записан, но сервис wdtt.service не запустился. Проверьте журнал сервиса на сервере."
        else -> raw.take(180).ifBlank { "операция «$operation» завершилась с неизвестной ошибкой" }
    }
    return hint
}

private fun decodeBase64Text(value: String): String =
    String(Base64.getDecoder().decode(value), Charsets.UTF_8)

private fun encodeBase64Text(value: String): String =
    Base64.getEncoder().encodeToString(value.toByteArray(Charsets.UTF_8))

private fun JSONObject.childObject(name: String): JSONObject {
    val current = optJSONObject(name)
    if (current != null) return current
    val created = JSONObject()
    put(name, created)
    return created
}

private fun dbSummary(dbJson: String): JSONObject = JSONObject(dbJson)

private fun String.isValidBase64Key(): Boolean =
    runCatching { Base64.getDecoder().decode(this) }.getOrNull()?.size == 32

private fun String.isValidPortsSpec(): Boolean {
    val parts = split(",").map { it.trim() }
    return parts.size == 3 && parts.all { it.toIntOrNull()?.let { port -> port in 1..65535 } == true }
}

private fun String.isValidPublicHost(): Boolean {
    val value = trim()
    if (value.isBlank() || value.length > 253 || value.any { it == '/' || it == '\\' || it == ':' || it == '@' }) return false
    val ipv4 = Regex("^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$")
    if (ipv4.matches(value)) return true
    if (value.startsWith(".") || value.endsWith(".") || value.contains("..")) return false
    val labels = value.split(".")
    if (labels.size < 2) return false
    return labels.all { label ->
        label.isNotBlank() &&
            label.length <= 63 &&
            !label.startsWith("-") &&
            !label.endsWith("-") &&
            label.all { it.isLetterOrDigit() || it == '-' }
    }
}

private fun JSONObject.optStringLength(name: String, limit: Int, owner: String) {
    require(optString(name, "").length <= limit) { "$name у $owner слишком длинный" }
}

private fun validateBindHistoryEntry(pass: String, index: Int, event: JSONObject) {
    val owner = "bind_history[$index] пароля $pass"
    event.optStringLength("device_id", 256, owner)
    event.optStringLength("device_name", 120, owner)
    event.optStringLength("device_ip", 64, owner)
    event.optStringLength("remote_ip", 64, owner)
    event.optStringLength("country", 32, owner)
    event.optStringLength("note", 256, owner)
    val status = event.optString("status", "")
    require(status in setOf("active", "unbound", "denied_mismatch")) { "неизвестный status у $owner" }
    listOf("bound_at", "unbound_at", "event_at").forEach { field ->
        require(event.optLong(field, 0) >= 0) { "$field у $owner должен быть >= 0" }
    }
}

private fun validateTrafficBucket(owner: String, index: Int, bucket: JSONObject) {
    val date = bucket.optString("date", "")
    require(Regex("^\\d{4}-\\d{2}-\\d{2}$").matches(date)) { "traffic[$index] у $owner должен содержать дату YYYY-MM-DD" }
    require(bucket.optLong("down_bytes", 0) >= 0) { "down_bytes traffic[$index] у $owner должен быть >= 0" }
    require(bucket.optLong("up_bytes", 0) >= 0) { "up_bytes traffic[$index] у $owner должен быть >= 0" }
}

private fun validatePasswordEntry(pass: String, entry: JSONObject) {
    require(pass.isNotBlank()) { "пустой пароль в passwords" }
    entry.optStringLength("device_id", 256, "пароля $pass")
    entry.optStringLength("label", 120, "пароля $pass")
    entry.optStringLength("vk_hash", 512, "пароля $pass")
    require(entry.optLong("expires_at", 0) >= 0) { "expires_at у пароля $pass должен быть >= 0" }
    require(entry.optLong("down_bytes", 0) >= 0) { "down_bytes у пароля $pass должен быть >= 0" }
    require(entry.optLong("up_bytes", 0) >= 0) { "up_bytes у пароля $pass должен быть >= 0" }
    val ports = entry.optString("ports", "")
    require(ports.isBlank() || ports.isValidPortsSpec()) { "некорректные ports у пароля $pass" }
    val history = entry.optJSONArray("bind_history")
    if (history != null) {
        require(history.length() <= 500) { "bind_history у пароля $pass слишком большой" }
        for (i in 0 until history.length()) {
            val event = history.optJSONObject(i)
                ?: throw IllegalArgumentException("bind_history у пароля $pass должен содержать объекты")
            validateBindHistoryEntry(pass, i, event)
        }
    }
    val traffic = entry.optJSONArray("traffic")
    if (traffic != null) {
        require(traffic.length() <= 500) { "traffic у пароля $pass слишком большой" }
        for (i in 0 until traffic.length()) {
            val bucket = traffic.optJSONObject(i)
                ?: throw IllegalArgumentException("traffic у пароля $pass должен содержать объекты")
            validateTrafficBucket("пароля $pass", i, bucket)
        }
    }
}

private fun validateDeviceEntry(deviceId: String, device: JSONObject) {
    require(deviceId.isNotBlank()) { "пустой ключ устройства в devices" }
    val storedId = device.optString("device_id", deviceId)
    require(storedId.isNotBlank()) { "device_id устройства $deviceId пустой" }
    val ip = device.optString("ip")
    require(ip.isBlank() || Regex("^10\\.66\\.66\\.([2-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|250)$").matches(ip)) {
        "некорректный IP устройства $deviceId"
    }
    val priv = device.optString("priv_key")
    val pub = device.optString("pub_key")
    require(priv.isBlank() || priv.isValidBase64Key()) { "некорректный priv_key устройства $deviceId" }
    require(pub.isBlank() || pub.isValidBase64Key()) { "некорректный pub_key устройства $deviceId" }
    listOf("name", "model").forEach { device.optStringLength(it, 120, "устройства $deviceId") }
    listOf("manufacturer", "brand", "android_version", "abi", "app_version", "locale", "country").forEach {
        device.optStringLength(it, 64, "устройства $deviceId")
    }
    device.optStringLength("time_zone", 96, "устройства $deviceId")
    device.optStringLength("remote_ip", 64, "устройства $deviceId")
    require(device.optInt("sdk", 0) >= 0) { "sdk устройства $deviceId должен быть >= 0" }
    require(device.optLong("last_seen_at", 0) >= 0) { "last_seen_at устройства $deviceId должен быть >= 0" }
}

private fun validatePasswordsDbStructure(db: JSONObject) {
    require(db.has("main_password")) { "в базе нет main_password" }
    require(db.optString("main_password").isNotBlank()) { "main_password пустой" }
    val passwords = db.optJSONObject("passwords") ?: throw IllegalArgumentException("passwords должен быть объектом")
    val devices = db.optJSONObject("devices") ?: throw IllegalArgumentException("devices должен быть объектом")
    val dns = db.optString("dns", "")
    require(dns.isBlank() || dns.length <= 256) { "dns слишком длинный" }
    val publicHost = db.optString("public_ip", "")
    require(publicHost.isBlank() || publicHost.isValidPublicHost()) {
        "public_ip должен быть доменом или IPv4 без http:// и без порта"
    }
    val defaultPorts = db.optString("default_ports", "")
    require(defaultPorts.isBlank() || defaultPorts.isValidPortsSpec()) { "default_ports должен быть в формате DTLS,WG,TUN" }
    val maxPasswords = db.optInt("max_passwords", 50)
    require(maxPasswords in 0..500) { "max_passwords должен быть 0..500" }
    require(db.optLong("admin_down_bytes", 0) >= 0) { "admin_down_bytes должен быть >= 0" }
    require(db.optLong("admin_up_bytes", 0) >= 0) { "admin_up_bytes должен быть >= 0" }
    val adminTraffic = db.optJSONArray("admin_traffic")
    if (adminTraffic != null) {
        require(adminTraffic.length() <= 500) { "admin_traffic слишком большой" }
        for (i in 0 until adminTraffic.length()) {
            val bucket = adminTraffic.optJSONObject(i)
                ?: throw IllegalArgumentException("admin_traffic должен содержать объекты")
            validateTrafficBucket("admin_traffic", i, bucket)
        }
    }
    passwords.keys().forEach { pass ->
        val entry = passwords.optJSONObject(pass) ?: throw IllegalArgumentException("passwords.$pass должен быть объектом")
        validatePasswordEntry(pass, entry)
    }
    devices.keys().forEach { deviceId ->
        val device = devices.optJSONObject(deviceId) ?: throw IllegalArgumentException("devices.$deviceId должен быть объектом")
        validateDeviceEntry(deviceId, device)
    }
}

private fun validateWgKeysDat(value: String) {
    val lines = value.trim().lines().map { it.trim() }.filter { it.isNotBlank() }
    require(lines.size >= 4) { "wg-keys.dat должен содержать 4 ключа" }
    lines.take(4).forEachIndexed { index, key ->
        require(key.isValidBase64Key()) { "ключ WireGuard #${index + 1} некорректен" }
    }
}

private fun parseBackup(passwordsJson: String, wgKeysDat: String?, createdAt: String, sourceHost: String): ServerBackup {
    val db = dbSummary(passwordsJson)
    validatePasswordsDbStructure(db)
    if (!wgKeysDat.isNullOrBlank()) {
        validateWgKeysDat(wgKeysDat)
    }
    val passwords = db.optJSONObject("passwords") ?: JSONObject()
    val devices = db.optJSONObject("devices") ?: JSONObject()
    return ServerBackup(
        passwordsJson = passwordsJson,
        wgKeysDat = wgKeysDat,
        createdAt = createdAt,
        sourceHost = sourceHost,
        passwordCount = passwords.length(),
        deviceCount = devices.length(),
        mainPassword = db.optString("main_password"),
        adminId = db.optString("admin_id"),
        botToken = db.optString("bot_token"),
        dns = db.optString("dns")
    )
}

private fun backupToJson(backup: ServerBackup): String {
    val obj = JSONObject()
        .put("format", "wdtt-server-backup")
        .put("version", 1)
        .put("created_at", backup.createdAt)
        .put("source_host", backup.sourceHost)
        .put("passwords_json_b64", encodeBase64Text(backup.passwordsJson))
        .put("password_count", backup.passwordCount)
        .put("device_count", backup.deviceCount)
    if (!backup.wgKeysDat.isNullOrBlank()) {
        obj.put("wg_keys_dat_b64", encodeBase64Text(backup.wgKeysDat))
    }
    return obj.toString(2)
}

private fun parseBackupFile(raw: String): ServerBackup {
    val obj = JSONObject(raw)
    require(obj.optString("format") == "wdtt-server-backup") { "это не файл бэкапа WDTT Plus" }
    require(obj.optInt("version", 0) == 1) { "неподдерживаемая версия бэкапа" }
    val passwordsB64 = obj.optString("passwords_json_b64")
    require(passwordsB64.isNotBlank()) { "в бэкапе нет базы passwords.json" }
    val passwordsJson = decodeBase64Text(passwordsB64)
    require(passwordsJson.length <= 5_000_000) { "база в бэкапе слишком большая" }
    val wgKeysB64 = obj.optString("wg_keys_dat_b64")
    val wgKeys = if (wgKeysB64.isNotBlank()) decodeBase64Text(wgKeysB64) else null
    return parseBackup(
        passwordsJson = passwordsJson,
        wgKeysDat = wgKeys,
        createdAt = obj.optString("created_at", "неизвестно"),
        sourceHost = obj.optString("source_host", "неизвестно")
    )
}

private suspend fun loadServerBackupFromUri(context: Context, uri: Uri): ServerBackup = withContext(Dispatchers.IO) {
    val raw = context.contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
        ?: throw IllegalArgumentException("не удалось открыть файл")
    parseBackupFile(raw)
}

private suspend fun writeServerBackupToUri(context: Context, outputUri: Uri, backup: ServerBackup) = withContext(Dispatchers.IO) {
    context.contentResolver.openOutputStream(outputUri)?.use { out ->
        out.write(backupToJson(backup).toByteArray(Charsets.UTF_8))
    } ?: throw IllegalStateException("не удалось записать файл")
}

private suspend fun readServerBackup(
    host: String,
    user: String,
    pass: String,
    port: Int,
    includeWgKeys: Boolean
): ServerBackup = withContext(Dispatchers.IO) {
    var session: Session? = null
    try {
        session = createSSHSession(host, user, pass, port)
        val ssh = SSHClient(session, pass)
        val command = buildString {
            append("[ -f /etc/wdtt/passwords.json ] || { echo WDTT_ERROR=no_passwords_json; exit 2; }; ")
            append("printf 'WDTT_DB_B64='; base64 /etc/wdtt/passwords.json | tr -d '\\n'; printf '\\n'; ")
            if (includeWgKeys) {
                append("if [ -f /etc/wdtt/wg-keys.dat ]; then printf 'WDTT_WG_KEYS_B64='; base64 /etc/wdtt/wg-keys.dat | tr -d '\\n'; printf '\\n'; fi; ")
            }
        }
        val output = ssh.exec(rootCommand(command), timeout = 30000L)
        markerValue(output, "WDTT_ERROR")?.let { throw IllegalStateException("сервер не отдал базу: $it") }
        val dbB64 = markerValue(output, "WDTT_DB_B64") ?: throw IllegalStateException("сервер не отдал passwords.json")
        val passwordsJson = decodeBase64Text(dbB64)
        val wgKeys = markerValue(output, "WDTT_WG_KEYS_B64")?.takeIf { it.isNotBlank() }?.let { decodeBase64Text(it) }
        parseBackup(
            passwordsJson = passwordsJson,
            wgKeysDat = wgKeys,
            createdAt = SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(Date()),
            sourceHost = host
        )
    } finally {
        try { session?.disconnect() } catch (_: Exception) {}
    }
}

private fun readRemotePasswordsJson(ssh: SSHClient): String? {
    val output = ssh.exec(
        rootCommand("if [ -f /etc/wdtt/passwords.json ]; then printf 'WDTT_DB_B64='; base64 /etc/wdtt/passwords.json | tr -d '\\n'; printf '\\n'; fi"),
        timeout = 20000L
    )
    val dbB64 = markerValue(output, "WDTT_DB_B64") ?: return null
    return decodeBase64Text(dbB64)
}

private fun parsePortsTriple(value: String): Triple<Int, Int, Int> {
    val parts = value.split(",").map { it.trim().toIntOrNull() }
    require(parts.size == 3 && parts.all { it != null && it in 1..65535 }) { "некорректные порты подключения" }
    return Triple(parts[0] ?: 56000, parts[1] ?: 56001, parts[2] ?: 9000)
}

private fun parsePortsTripleOrNull(value: String): Triple<Int, Int, Int>? {
    val parts = value.split(",").map { it.trim().toIntOrNull() }
    if (parts.size != 3 || parts.any { it == null || it !in 1..65535 }) return null
    return Triple(parts[0] ?: return null, parts[1] ?: return null, parts[2] ?: return null)
}

private fun Triple<Int, Int, Int>.asPortsSpec(): String = "$first,$second,$third"

private fun buildOwnerProfile(
    vkHashes: String,
    secondaryVkHash: String,
    workersPerHash: Int,
    protocol: String,
    listenPort: Int,
    sni: String,
    noDns: Boolean,
    dtlsPort: Int,
    wgPort: Int,
    profileName: String = ""
): ServerAdminProfileInfo {
    val safeListenPort = listenPort.coerceIn(1, 65535)
    val ports = Triple(
        dtlsPort.coerceIn(1, 65535),
        wgPort.coerceIn(1, 65535),
        safeListenPort
    )
    return ServerAdminProfileInfo(
        vkHashes = vkHashes.trim(),
        secondaryVkHash = secondaryVkHash.trim(),
        profileName = vpnProfileRestorableName(profileName),
        workersPerHash = workersPerHash.coerceIn(1, 128),
        protocol = protocol.trim().lowercase().takeIf { it == "udp" || it == "tcp" } ?: "udp",
        listenPort = safeListenPort,
        sni = sni.trim(),
        noDns = noDns,
        ports = ports.asPortsSpec()
    )
}

private fun parseOwnerProfileFromDb(json: JSONObject?, defaultPorts: String): ServerAdminProfileInfo {
    val fallbackPorts = parsePortsTripleOrNull(defaultPorts) ?: Triple(56000, 56001, 9000)
    val ports = parsePortsTripleOrNull(json?.optString("ports", defaultPorts).orEmpty())
        ?: fallbackPorts
    val listenPort = json?.optInt("listen_port", 0)
        ?.takeIf { it in 1..65535 }
        ?: ports.third
    val deviceIds = buildList {
        val raw = json?.optJSONArray("device_ids") ?: return@buildList
        for (i in 0 until raw.length()) {
            raw.optString(i).trim().takeIf { it.isNotBlank() }?.let(::add)
        }
    }
    return ServerAdminProfileInfo(
        vkHashes = json?.optString("vk_hashes", "").orEmpty().trim(),
        secondaryVkHash = json?.optString("secondary_vk_hash", "").orEmpty().trim(),
        profileName = vpnProfileRestorableName(json?.optString("profile_name", "").orEmpty()),
        workersPerHash = (json?.optInt("workers_per_hash", 16) ?: 16).coerceIn(1, 128),
        protocol = json?.optString("protocol", "udp").orEmpty().lowercase().takeIf { it == "udp" || it == "tcp" } ?: "udp",
        listenPort = listenPort,
        sni = json?.optString("sni", "").orEmpty().trim(),
        noDns = json?.optBoolean("no_dns", false) ?: false,
        ports = Triple(ports.first, ports.second, listenPort).asPortsSpec(),
        deviceIds = deviceIds,
        updatedAt = json?.optLong("updated_at", 0L) ?: 0L
    )
}

private fun ServerAdminProfileInfo.effectivePorts(fallback: Triple<Int, Int, Int>): Triple<Int, Int, Int> {
    val parsed = parsePortsTripleOrNull(ports) ?: fallback
    val safeListenPort = listenPort.takeIf { it in 1..65535 } ?: parsed.third
    return Triple(parsed.first, parsed.second, safeListenPort)
}

private data class OwnerProfileComparable(
    val vkHashes: String,
    val secondaryVkHash: String,
    val profileName: String,
    val workersPerHash: Int,
    val protocol: String,
    val listenPort: Int,
    val sni: String,
    val noDns: Boolean,
    val ports: String
)

private fun ServerAdminProfileInfo.comparableOwnerProfile(): OwnerProfileComparable {
    val ports = effectivePorts(Triple(56000, 56001, 9000))
    return OwnerProfileComparable(
        vkHashes = vkHashes.trim(),
        secondaryVkHash = secondaryVkHash.trim(),
        profileName = vpnProfileRestorableName(profileName),
        workersPerHash = workersPerHash.coerceIn(1, 128),
        protocol = protocol.trim().lowercase().takeIf { it == "udp" || it == "tcp" } ?: "udp",
        listenPort = ports.third,
        sni = sni.trim(),
        noDns = noDns,
        ports = ports.asPortsSpec()
    )
}

private fun ownerProfilesDiffer(server: ServerAdminProfileInfo, local: ServerAdminProfileInfo): Boolean =
    server.comparableOwnerProfile().let { serverComparable ->
        local.comparableOwnerProfile().let { localComparable ->
            serverComparable.copy(profileName = "") != localComparable.copy(profileName = "") ||
                (serverComparable.profileName.isNotBlank() && serverComparable.profileName != localComparable.profileName)
        }
    }

private fun ownerProfileDiffLines(server: ServerAdminProfileInfo, local: ServerAdminProfileInfo): List<String> {
    val serverComparable = server.comparableOwnerProfile()
    val localComparable = local.comparableOwnerProfile()
    val lines = mutableListOf<String>()
    if (serverComparable.vkHashes != localComparable.vkHashes) {
        lines += "VK-хеши: сервер — ${secretPresenceLabel(serverComparable.vkHashes)}, приложение — ${secretPresenceLabel(localComparable.vkHashes)}"
    }
    if (serverComparable.secondaryVkHash != localComparable.secondaryVkHash) {
        lines += "Резервный VK-хеш: сервер — ${secretPresenceLabel(serverComparable.secondaryVkHash)}, приложение — ${secretPresenceLabel(localComparable.secondaryVkHash)}"
    }
    if (serverComparable.profileName.isNotBlank() && serverComparable.profileName != localComparable.profileName) {
        lines += "Название профиля: сервер — ${serverComparable.profileName.ifBlank { "стандартное" }}, приложение — ${localComparable.profileName.ifBlank { "стандартное" }}"
    }
    if (serverComparable.workersPerHash != localComparable.workersPerHash) {
        lines += "Потоки на хеш: сервер — ${serverComparable.workersPerHash}, приложение — ${localComparable.workersPerHash}"
    }
    if (serverComparable.protocol != localComparable.protocol) {
        lines += "Протокол: сервер — ${serverComparable.protocol}, приложение — ${localComparable.protocol}"
    }
    if (serverComparable.listenPort != localComparable.listenPort) {
        lines += "Локальный порт: сервер — ${serverComparable.listenPort}, приложение — ${localComparable.listenPort}"
    }
    if (serverComparable.ports != localComparable.ports) {
        lines += "Порты ссылки: сервер — ${serverComparable.ports}, приложение — ${localComparable.ports}"
    }
    if (serverComparable.sni != localComparable.sni) {
        lines += "SNI: сервер — ${serverComparable.sni.ifBlank { "не задан" }}, приложение — ${localComparable.sni.ifBlank { "не задан" }}"
    }
    if (serverComparable.noDns != localComparable.noDns) {
        lines += "No DNS: сервер — ${if (serverComparable.noDns) "включено" else "выключено"}, приложение — ${if (localComparable.noDns) "включено" else "выключено"}"
    }
    return lines.ifEmpty { listOf("Отличия есть только в служебных данных профиля.") }
}

private fun existingConnectionDiffLines(
    connection: ExistingServerConnection,
    localPeer: String,
    localConnectionPassword: String,
    localAdminId: String,
    localBotToken: String,
    localDns1: String,
    localDns2: String,
    localProfile: ServerAdminProfileInfo
): List<String> = buildList {
    if (!connection.host.equals(localPeer.trim(), ignoreCase = true)) {
        add("Адрес подключения: локальное значение будет заменено адресом сервера ${connection.host}")
    }
    if (connection.password != localConnectionPassword) {
        add("Пароль VPN-подключения будет заменён главным паролем владельца с сервера")
    }
    if (connection.adminId != localAdminId.trim()) {
        add("Telegram Admin ID отличается")
    }
    if (connection.botToken != localBotToken.trim()) {
        add("Telegram Bot Token отличается")
    }
    if (normalizeDnsValues(connection.dns1, connection.dns2) != normalizeDnsValues(localDns1, localDns2)) {
        add("DNS: сервер — ${normalizeDnsValues(connection.dns1, connection.dns2)}, приложение — ${normalizeDnsValues(localDns1, localDns2)}")
    }
    if (connection.adminProfile.hasSavedFields && ownerProfilesDiffer(connection.adminProfile, localProfile)) {
        addAll(ownerProfileDiffLines(connection.adminProfile, localProfile))
    }
}

private fun normalizeDnsValues(first: String, second: String = ""): String =
    listOf(first, second)
        .flatMap { it.split(',') }
        .map { it.trim() }
        .filter { it.isNotBlank() }
        .joinToString(",")

private fun outboundProfilesDiffer(server: OutboundServerSnapshot, local: OutboundProfileForms): Boolean {
    fun value(raw: String): String = raw.trim().replace("\r\n", "\n")
    val serverValues = listOf(
        server.localProxyPort,
        server.localProxyLogin,
        server.localProxyPassword,
        server.externalProxyKindName,
        server.externalProxyHost,
        server.externalProxyPort,
        server.externalProxyLogin,
        server.externalProxyPassword,
        server.wireGuardExitHost,
        server.wireGuardExitSshPort,
        server.wireGuardExitUser,
        server.wireGuardExitPassword,
        server.wireGuardExitPort,
        server.wireGuardExitDns,
        server.importedWireGuardConfig
    ).map(::value)
    val localValues = listOf(
        local.localProxyPort,
        local.localProxyLogin,
        local.localProxyPassword,
        local.externalProxyKindName,
        local.externalProxyHost,
        local.externalProxyPort,
        local.externalProxyLogin,
        local.externalProxyPassword,
        local.wireGuardExitHost,
        local.wireGuardExitSshPort,
        local.wireGuardExitUser,
        local.wireGuardExitPassword,
        local.wireGuardExitPort,
        local.wireGuardExitDns,
        local.importedWireGuardConfig
    ).map(::value)
    return serverValues != localValues
}

private suspend fun compareDeployWithServer(
    context: Context,
    request: DeployRequest,
    localOwnerProfile: ServerAdminProfileInfo,
    localOutboundProfile: OutboundProfileForms,
    inspectDatabase: Boolean
): DeployServerComparison {
    val overwriteLines = mutableListOf<String>()
    val notes = mutableListOf<String>()
    val errors = mutableListOf<String>()

    if (inspectDatabase) {
        runCatching {
            withContext(Dispatchers.IO) {
                var session: Session? = null
                try {
                    session = createSSHSession(request.host, request.user, request.pass, request.sshPort)
                    val ssh = SSHClient(session, request.pass)
                    val raw = readRemotePasswordsJson(ssh)
                        ?: throw IllegalStateException("на сервере не найдена база доступа")
                    val db = JSONObject(raw)
                    validatePasswordsDbStructure(db)

                    if (db.optString("main_password") != request.mainPass) {
                        overwriteLines += "Главный пароль владельца"
                    }
                    if (request.adminId.isNotBlank() && db.optString("admin_id") != request.adminId) {
                        overwriteLines += "Telegram Admin ID"
                    }
                    if (request.botToken.isNotBlank() && db.optString("bot_token") != request.botToken) {
                        overwriteLines += "Telegram Bot Token"
                    }
                    val serverDns = normalizeDnsValues(db.optString("dns"))
                    val localDns = normalizeDnsValues(
                        request.dns1.ifBlank { "1.1.1.1" },
                        request.dns2
                    )
                    if (serverDns != localDns) {
                        overwriteLines += "DNS: сервер — ${serverDns.ifBlank { "не задан" }}, приложение — $localDns"
                    }

                    val defaultPorts = db.optString("default_ports").ifBlank { "56000,56001,9000" }
                    val serverProfile = parseOwnerProfileFromDb(db.optJSONObject("admin_profile"), defaultPorts)
                    if (serverProfile.hasSavedFields && ownerProfilesDiffer(serverProfile, localOwnerProfile)) {
                        overwriteLines += "Профиль владельца («Туннель» и порты)"
                        overwriteLines += ownerProfileDiffLines(serverProfile, localOwnerProfile).map { "  $it" }
                    } else if (!serverProfile.hasSavedFields) {
                        notes += "На сервере ещё нет профиля владельца; установка создаст его из текущих полей приложения."
                    }
                } finally {
                    try { session?.disconnect() } catch (_: Exception) {}
                }
            }
        }.onFailure {
            errors += friendlyDeployError(it, "сверка профиля сервера")
        }
    }

    runCatching {
        val target = OutboundSshTarget(
            host = request.host,
            user = request.user.ifBlank { "root" },
            pass = request.pass,
            port = request.sshPort
        )
        val output = runRootScript(
            context = context,
            target = target,
            script = outboundSnapshotScript(),
            timeout = 30000L
        )
        val snapshot = parseOutboundServerSnapshot(output)
        if (snapshot.hasProfile && outboundProfilesDiffer(snapshot, localOutboundProfile)) {
            overwriteLines += "Сохранённые поля «Выходной IP и прокси»"
        } else if (!snapshot.hasProfile) {
            notes += "На сервере нет профиля полей выходного IP; установка создаст его из текущих полей приложения."
        }
    }.onFailure {
        errors += friendlyDeployError(it, "сверка выходного IP")
    }

    return DeployServerComparison(
        overwriteLines = overwriteLines.distinct(),
        notes = notes.distinct(),
        checkError = errors.takeIf { it.isNotEmpty() }?.joinToString(" ")
    )
}

private fun secretPresenceLabel(value: String): String {
    val count = value.split(',', ' ', '\n', '\t')
        .map { it.trim() }
        .count { it.isNotBlank() }
    return if (count == 0) "не заданы" else "заданы ($count)"
}

private fun selectExistingServerConnection(
    dbJson: String,
    fallbackHost: String,
    adminMainPassword: String
): ExistingServerConnection {
    val db = JSONObject(dbJson)
    validatePasswordsDbStructure(db)
    val mainPassword = db.optString("main_password")
    require(adminMainPassword.isNotBlank() && adminMainPassword == mainPassword) {
        "главный пароль администратора не совпадает с сервером"
    }
    val serverAdminId = db.optString("admin_id")
    val serverBotToken = db.optString("bot_token")
    val dnsParts = db.optString("dns")
        .split(",")
        .map { it.trim() }
        .filter { it.isNotBlank() }
    val serverDns1 = dnsParts.getOrNull(0) ?: "1.1.1.1"
    val serverDns2 = dnsParts.getOrNull(1) ?: "1.0.0.1"
    val publicHost = db.optString("public_ip").ifBlank { fallbackHost }
    val defaultPorts = db.optString("default_ports").ifBlank { "56000,56001,9000" }
    return ExistingServerConnection(
        host = publicHost,
        password = mainPassword,
        ports = parsePortsTriple(defaultPorts),
        adminId = serverAdminId,
        botToken = serverBotToken,
        dns1 = serverDns1,
        dns2 = serverDns2,
        adminProfile = parseOwnerProfileFromDb(db.optJSONObject("admin_profile"), defaultPorts)
    )
}

private suspend fun readExistingServerConnection(
    host: String,
    user: String,
    pass: String,
    port: Int,
    adminMainPassword: String
): ExistingServerConnection = withContext(Dispatchers.IO) {
    var session: Session? = null
    try {
        session = createSSHSession(host, user, pass, port)
        val ssh = SSHClient(session, pass)
        val dbJson = readRemotePasswordsJson(ssh) ?: throw IllegalStateException("на сервере не найден /etc/wdtt/passwords.json")
        selectExistingServerConnection(dbJson, host, adminMainPassword)
    } finally {
        try { session?.disconnect() } catch (_: Exception) {}
    }
}

private fun normalizeDbForTarget(
    backup: ServerBackup,
    currentDbJson: String?,
    mode: ServerImportMode,
    request: DeployRequest
): String {
    val portsSpec = "${request.dtlsPort},${request.wgPort},${request.localPort}"
    val dnsValue = listOf(request.dns1, request.dns2).filter { it.isNotBlank() }.joinToString(",").ifBlank { backup.dns.ifBlank { "1.1.1.1,1.0.0.1" } }
    val source = JSONObject(backup.passwordsJson)
    val target = if (mode == ServerImportMode.Replace) {
        JSONObject(source.toString())
    } else {
        currentDbJson?.takeIf { it.isNotBlank() }?.let { JSONObject(it) } ?: JSONObject()
    }

    if (mode == ServerImportMode.Merge) {
        val sourcePasswords = source.optJSONObject("passwords") ?: JSONObject()
        val targetPasswords = target.childObject("passwords")
        sourcePasswords.keys().forEach { key ->
            if (!targetPasswords.has(key)) {
                val entry = JSONObject(sourcePasswords.getJSONObject(key).toString())
                entry.put("ports", portsSpec)
                targetPasswords.put(key, entry)
            }
        }
        val sourceDevices = source.optJSONObject("devices") ?: JSONObject()
        val targetDevices = target.childObject("devices")
        sourceDevices.keys().forEach { key ->
            if (!targetDevices.has(key)) {
                targetDevices.put(key, JSONObject(sourceDevices.getJSONObject(key).toString()))
            }
        }
        if (!target.has("main_password") || target.optString("main_password").isBlank()) {
            target.put("main_password", backup.mainPassword)
        }
        if (!target.has("admin_id") || target.optString("admin_id").isBlank()) {
            target.put("admin_id", backup.adminId)
        }
        if (!target.has("bot_token") || target.optString("bot_token").isBlank()) {
            target.put("bot_token", backup.botToken)
        }
    } else {
        val passwords = target.optJSONObject("passwords") ?: JSONObject()
        passwords.keys().forEach { key ->
            passwords.optJSONObject(key)?.put("ports", portsSpec)
        }
    }

    if (request.mainPass.isNotBlank()) target.put("main_password", request.mainPass)
    if (request.adminId.isNotBlank()) target.put("admin_id", request.adminId)
    if (request.botToken.isNotBlank()) target.put("bot_token", request.botToken)
    target.put("dns", dnsValue)
    target.put("default_ports", portsSpec)
    target.put("public_ip", request.host)
    if (!target.has("passwords")) target.put("passwords", JSONObject())
    if (!target.has("devices")) target.put("devices", JSONObject())
    if (!target.has("max_passwords")) target.put("max_passwords", 50)
    validatePasswordsDbStructure(target)
    return target.toString(2)
}

private fun applyServerImport(
    context: Context,
    ssh: SSHClient,
    request: DeployRequest,
    backup: ServerBackup,
    mode: ServerImportMode,
    restartService: Boolean
) {
    val currentDb = if (mode == ServerImportMode.Merge) readRemotePasswordsJson(ssh) else null
    val preparedDb = normalizeDbForTarget(backup, currentDb, mode, request)
    val dbFile = File(context.cacheDir, "wdtt-import-passwords.json")
    val wgFile = File(context.cacheDir, "wdtt-import-wg-keys.dat")
    dbFile.writeText(preparedDb)
    try {
        ssh.upload(dbFile, "/tmp/wdtt-import-passwords.json")
        val replaceWgKeys = mode == ServerImportMode.Replace && backup.hasWgKeys
        if (replaceWgKeys) {
            wgFile.writeText(backup.wgKeysDat.orEmpty())
            ssh.upload(wgFile, "/tmp/wdtt-import-wg-keys.dat")
        }
        val command = buildString {
            append("systemctl stop wdtt 2>/dev/null || true; ")
            append("mkdir -p /etc/wdtt; ")
            append("install -m 600 /tmp/wdtt-import-passwords.json /etc/wdtt/passwords.json; ")
            append("rm -f /tmp/wdtt-import-passwords.json; ")
            if (replaceWgKeys) {
                append("install -m 600 /tmp/wdtt-import-wg-keys.dat /etc/wdtt/wg-keys.dat; rm -f /tmp/wdtt-import-wg-keys.dat; ")
            }
            if (restartService) {
                append("systemctl restart wdtt 2>/dev/null || true; ")
                append("systemctl is-active wdtt 2>/dev/null || true; ")
            }
        }
        val output = ssh.exec(rootCommand(command), timeout = 60000L)
        if (restartService && !Regex("^active$", RegexOption.MULTILINE).containsMatchIn(output)) {
            throw IllegalStateException("wdtt.service не стал active после импорта")
        }
    } finally {
        dbFile.delete()
        wgFile.delete()
    }
}

private suspend fun performServerImportNow(
    context: Context,
    request: DeployRequest,
    backup: ServerBackup,
    mode: ServerImportMode,
    onProgress: (Float, String) -> Unit
): Boolean = withContext(Dispatchers.IO) {
    var session: Session? = null
    try {
        onProgress(0.05f, "Подключение...")
        session = createSSHSession(request.host, request.user, request.pass, request.sshPort)
        DeployManager.activeSession = session
        val ssh = SSHClient(session, request.pass)
        onProgress(0.30f, "Подготовка импорта...")
        applyServerImport(context, ssh, request, backup, mode, restartService = true)
        onProgress(1.0f, "Импорт завершён")
        DeployManager.stopDeploy("success")
        TunnelManager.addDeploySuccessLog("Импорт состояния WDTT Plus завершён.")
        true
    } catch (e: Exception) {
        DeployManager.writeError("Server import critical: ${e.message}\n${e.stackTraceToString().take(500)}")
        DeployManager.stopDeploy("Ошибка импорта")
        throw e
    } finally {
        try { session?.disconnect() } catch (_: Exception) {}
        DeployManager.activeSession = null
    }
}

// ==================== Deploy ====================

private const val SERVER_UPDATE_BACKUP_DIR = "/var/tmp/wdtt-plus-update-backup"

private fun sha256File(file: File): String {
    val digest = MessageDigest.getInstance("SHA-256")
    file.inputStream().use { input ->
        val buffer = ByteArray(64 * 1024)
        while (true) {
            val read = input.read(buffer)
            if (read <= 0) break
            digest.update(buffer, 0, read)
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}

private fun prepareServerUpdateRollback(ssh: SSHClient) {
    val command = """
        set -e
        BACKUP=${shellQuote(SERVER_UPDATE_BACKUP_DIR)}
        rm -rf "${'$'}BACKUP"
        install -d -m 700 "${'$'}BACKUP"
        if [ -d /etc/wdtt ]; then cp -a /etc/wdtt "${'$'}BACKUP/config"; touch "${'$'}BACKUP/had_config"; fi
        if [ -f /usr/local/bin/wdtt-server ]; then cp -a /usr/local/bin/wdtt-server "${'$'}BACKUP/wdtt-server"; touch "${'$'}BACKUP/had_binary"; fi
        if [ -f /etc/systemd/system/wdtt.service ]; then cp -a /etc/systemd/system/wdtt.service "${'$'}BACKUP/wdtt.service"; touch "${'$'}BACKUP/had_service"; fi
        if systemctl is-active --quiet wdtt; then touch "${'$'}BACKUP/was_active"; fi
        echo WDTT_UPDATE_BACKUP=ready
    """.trimIndent()
    val output = ssh.exec(rootCommand(command), timeout = 30000L)
    require(Regex("^WDTT_UPDATE_BACKUP=ready$", RegexOption.MULTILINE).containsMatchIn(output)) {
        "не удалось подготовить страховочную копию обновления"
    }
}

private fun cleanupServerUpdateRollback(ssh: SSHClient) {
    ssh.exec(rootCommand("rm -rf ${shellQuote(SERVER_UPDATE_BACKUP_DIR)}"), timeout = 10000L)
}

private fun rollbackServerUpdate(ssh: SSHClient) {
    val command = """
        set -e
        BACKUP=${shellQuote(SERVER_UPDATE_BACKUP_DIR)}
        [ -d "${'$'}BACKUP" ] || { echo WDTT_ROLLBACK=missing; exit 2; }
        systemctl stop wdtt 2>/dev/null || true
        if [ -f "${'$'}BACKUP/had_binary" ]; then install -m 755 "${'$'}BACKUP/wdtt-server" /usr/local/bin/wdtt-server; else rm -f /usr/local/bin/wdtt-server; fi
        if [ -f "${'$'}BACKUP/had_service" ]; then install -m 644 "${'$'}BACKUP/wdtt.service" /etc/systemd/system/wdtt.service; else rm -f /etc/systemd/system/wdtt.service; fi
        if [ -f "${'$'}BACKUP/had_config" ]; then rm -rf /etc/wdtt; cp -a "${'$'}BACKUP/config" /etc/wdtt; else rm -rf /etc/wdtt; fi
        systemctl daemon-reload
        if [ -f "${'$'}BACKUP/was_active" ]; then systemctl restart wdtt; sleep 2; systemctl is-active --quiet wdtt; fi
        rm -rf "${'$'}BACKUP"
        echo WDTT_ROLLBACK=ok
    """.trimIndent()
    val output = ssh.exec(rootCommand(command), timeout = 60000L)
    require(Regex("^WDTT_ROLLBACK=ok$", RegexOption.MULTILINE).containsMatchIn(output)) {
        "сервер не подтвердил откат обновления"
    }
}

private fun validatePreservedServerState(beforeJson: String, afterJson: String) {
    val before = JSONObject(beforeJson)
    val after = JSONObject(afterJson)
    validatePasswordsDbStructure(after)
    val beforePasswords = before.optJSONObject("passwords") ?: JSONObject()
    val afterPasswords = after.optJSONObject("passwords") ?: JSONObject()
    val afterDevices = after.optJSONObject("devices") ?: JSONObject()
    val safeExpiryCutoff = System.currentTimeMillis() / 1000L + 300L
    beforePasswords.keys().forEach { password ->
        val oldEntry = beforePasswords.optJSONObject(password) ?: return@forEach
        val expiresAt = oldEntry.optLong("expires_at", 0)
        if (expiresAt != 0L && expiresAt <= safeExpiryCutoff) return@forEach
        val newEntry = afterPasswords.optJSONObject(password)
            ?: throw IllegalStateException("после обновления пропал действующий клиент ${password.take(4)}…")
        listOf("device_id", "label", "vk_hash", "ports").forEach { field ->
            require(oldEntry.optString(field, "") == newEntry.optString(field, "")) {
                "после обновления изменилось поле $field у клиента ${password.take(4)}…"
            }
        }
        require(oldEntry.optLong("expires_at", 0) == newEntry.optLong("expires_at", 0)) {
            "после обновления изменился срок клиента ${password.take(4)}…"
        }
        require(oldEntry.optBoolean("is_deactivated", false) == newEntry.optBoolean("is_deactivated", false)) {
            "после обновления изменился статус клиента ${password.take(4)}…"
        }
        val deviceId = oldEntry.optString("device_id", "")
        if (deviceId.isNotBlank()) {
            require(afterDevices.has(deviceId)) { "после обновления пропала привязка устройства клиента ${password.take(4)}…" }
        }
    }
}

private suspend fun performDeploy(
	context: Context,
	host: String, user: String, pass: String, port: Int,
	mainPass: String, adminId: String, botToken: String,
	dtlsPort: Int, wgPort: Int, localPort: Int, dns1: String, dns2: String,
	mode: DeployMode,
	importPlan: ServerImportPlan?,
	onProgress: (Float, String) -> Unit
): Boolean = withContext(Dispatchers.IO) {
    var session: Session? = null
    var sshClient: SSHClient? = null
    var rollbackPrepared = false
    var preservedDbJson: String? = null
    try {
        onProgress(0.02f, "Подключение...")
        session = createSSHSession(host, user, pass, port)
        DeployManager.activeSession = session
        val ssh = SSHClient(session, pass)
        sshClient = ssh

        onProgress(0.05f, "Подготовка файлов...")
        val passArg = if (mainPass.isNotBlank()) "-password $mainPass " else ""
        val adminArg = if (adminId.isNotBlank()) "-admin $adminId " else ""
        val botArg = if (botToken.isNotBlank()) "-bot-token $botToken " else ""
        val dnsArg = "-dns ${if(dns1.isNotBlank()) dns1 else "1.1.1.1"}${if(dns2.isNotBlank()) ",$dns2" else ""} "
        val args = "$passArg$adminArg$botArg$dnsArg".trim()

        val scriptFile = File(context.cacheDir, "deploy.sh")
        val serverFile = File(context.cacheDir, "server")
        try {
            context.assets.open("deploy.sh").use { inp -> FileOutputStream(scriptFile).use { out -> inp.copyTo(out) } }
            context.assets.open("server").use { inp -> FileOutputStream(serverFile).use { out -> inp.copyTo(out) } }
        } catch (e: Exception) {
            DeployManager.writeError("Assets extraction failed: ${e.message}")
            DeployManager.failDeploy("файлы deploy.sh/server не найдены внутри APK. Переустановите свежий APK.")
            return@withContext false
        }
        if (isUnsafeLegacyServerAsset(serverFile)) {
            scriptFile.delete()
            serverFile.delete()
            DeployManager.writeError("Unsafe legacy server asset: найдено wg0 или /etc/wireguard. Нужна пересборка server под wdtt0 и /etc/wdtt.")
            DeployManager.failDeploy("server asset выглядит устаревшим. Соберите APK заново.")
            return@withContext false
        }
        val expectedServerSha256 = sha256File(serverFile)
        if (mode == DeployMode.PreserveData) {
            onProgress(0.055f, "Проверка сохранённых данных...")
            val currentDbJson = readRemotePasswordsJson(ssh)?.also {
                validatePasswordsDbStructure(JSONObject(it))
            }
            if (importPlan == null) preservedDbJson = currentDbJson
            prepareServerUpdateRollback(ssh)
            rollbackPrepared = true
        }

        onProgress(0.06f, "Загрузка на сервер...")
        ssh.upload(scriptFile, "/tmp/deploy.sh")
        ssh.upload(serverFile, "/tmp/wdtt-server")
        scriptFile.delete()
        serverFile.delete()

		onProgress(0.08f, "Установка...")
		if (mode == DeployMode.ResetAll) {
			onProgress(0.075f, "Сброс старых данных...")
			ssh.exec(
				rootCommand(
					"systemctl stop wdtt 2>/dev/null || true; " +
						"pkill -x wdtt-server 2>/dev/null || true; " +
						"rm -rf /etc/wdtt; " +
						"rm -f /etc/systemd/system/wdtt.service /usr/local/bin/wdtt-server; " +
						"systemctl daemon-reload 2>/dev/null || true"
				),
				timeout = 30000L
			)
		}
        if (importPlan != null) {
            onProgress(0.085f, "Импорт состояния сервера...")
            applyServerImport(
                context = context,
                ssh = ssh,
                request = DeployRequest(
                    host = host,
                    user = user,
                    pass = pass,
                    sshPort = port,
                    mainPass = mainPass,
                    adminId = adminId,
                    botToken = botToken,
                    dtlsPort = dtlsPort,
                    wgPort = wgPort,
                    localPort = localPort,
                    dns1 = dns1,
                    dns2 = dns2
                ),
                backup = importPlan.backup,
                mode = importPlan.mode,
                restartService = false
            )
        }
		val output = ssh.exec(
			rootCommand("env WDTT_ARGS=${shellQuote(args)} WDTT_DTLS_PORT=$dtlsPort WDTT_WG_PORT=$wgPort WDTT_SSH_PORT=$port WDTT_PRESERVE_DATA=${if (mode == DeployMode.PreserveData) 1 else 0} bash /tmp/deploy.sh"),
			timeout = CMD_TIMEOUT
        )

        if (output.contains("✅") || output.contains("Деплой успешно") || output.contains("active")) {
			val verifyOutput = ssh.exec(
				rootCommand(
					"sleep 2; printf 'BINARY=%s\\n' \"$([ -x /usr/local/bin/wdtt-server ] && echo 1 || echo 0)\"; " +
						"printf 'CONFIG=%s\\n' \"$([ -d /etc/wdtt ] && echo 1 || echo 0)\"; " +
						"printf 'SERVICE=%s\\n' \"$(systemctl is-active wdtt 2>/dev/null || true)\"; " +
						"printf 'ADMIN_SOCKET=%s\\n' \"$([ -S /run/wdtt/admin.sock ] && echo 1 || echo 0)\"; " +
						"printf 'SERVER_SHA256=%s\\n' \"$(sha256sum /usr/local/bin/wdtt-server 2>/dev/null | awk '{print ${'$'}1}')\""
				),
                timeout = 20000L
            )
            val binaryOk = Regex("^BINARY=1$", RegexOption.MULTILINE).containsMatchIn(verifyOutput)
			val configOk = Regex("^CONFIG=1$", RegexOption.MULTILINE).containsMatchIn(verifyOutput)
			val serviceActive = Regex("^SERVICE=active$", RegexOption.MULTILINE).containsMatchIn(verifyOutput)
			val adminSocketOk = Regex("^ADMIN_SOCKET=1$", RegexOption.MULTILINE).containsMatchIn(verifyOutput)
			val installedSha256 = Regex("^SERVER_SHA256=([0-9a-fA-F]{64})$", RegexOption.MULTILINE)
				.find(verifyOutput)?.groupValues?.getOrNull(1)?.lowercase()
			val binaryCurrent = installedSha256 == expectedServerSha256
			if (!binaryOk || !configOk || !serviceActive || !adminSocketOk || !binaryCurrent) {
				DeployManager.writeError("Deploy verify failed: ${verifyOutput.take(500)}")
				val missing = buildList {
					if (!binaryOk) add("бинарник")
					if (!configOk) add("конфиг /etc/wdtt")
					if (!serviceActive) add("служба wdtt")
					if (!adminSocketOk) add("admin-сокет новой версии")
					if (!binaryCurrent) add("актуальная версия бинарника")
				}.joinToString(", ")
				throw IllegalStateException("скрипт завершился, но проверка не прошла: $missing")
			}
			val updatedDbJson = readRemotePasswordsJson(ssh)
				?: throw IllegalStateException("после обновления не найдена база passwords.json")
			validatePasswordsDbStructure(JSONObject(updatedDbJson))
			preservedDbJson?.let { validatePreservedServerState(it, updatedDbJson) }
			if (rollbackPrepared) {
				cleanupServerUpdateRollback(ssh)
				rollbackPrepared = false
			}
            DeployManager.stopDeploy("success")
            TunnelManager.addDeploySuccessLog("Деплой успешно завершён. Сервис активен.")
            return@withContext true
        } else if (output.contains("error:")) {
            DeployManager.writeError("Deploy script output contains error")
            throw IllegalStateException("скрипт установки вернул ошибку; подробности сохранены в errors.log")
        } else {
            DeployManager.writeError("Deploy unclear output: ${output.take(500)}")
            throw IllegalStateException("не удалось подтвердить установку: нет признака active/успеха от скрипта")
        }

	} catch (e: Exception) {
		if (rollbackPrepared) {
			runCatching { sshClient?.let(::rollbackServerUpdate) }
				.onFailure { rollbackError -> DeployManager.writeError("Update rollback failed: ${rollbackError.message}") }
			rollbackPrepared = false
		}
		DeployManager.writeError("Deploy critical: ${e.message}\n${e.stackTraceToString().take(500)}")
        DeployManager.failDeploy(e.message?.take(120) ?: "неизвестная ошибка")
        return@withContext false
    } finally {
        try { session?.disconnect() } catch (_: Exception) {}
        DeployManager.activeSession = null
    }
}


// ==================== Uninstall ====================

private suspend fun performUninstall(
    host: String, user: String, pass: String, port: Int,
    dtlsPort: Int, wgPort: Int,
    onProgress: (Float, String) -> Unit
) = withContext(Dispatchers.IO) {
    var session: Session? = null
    try {
        onProgress(0.05f, "Подключение...")
        session = createSSHSession(host, user, pass, port)
        DeployManager.activeSession = session
        val ssh = SSHClient(session, pass)

        onProgress(0.15f, "Остановка сервиса...")
        ssh.exec(
            rootCommand(
                "systemctl unmask wdtt 2>/dev/null || true; " +
                    "systemctl stop wdtt 2>/dev/null || true; " +
                    "systemctl disable wdtt 2>/dev/null || true; " +
                    "rm -f /etc/systemd/system/wdtt.service; " +
                    "systemctl daemon-reload 2>/dev/null || true"
            ),
            timeout = 15000L
        )

        onProgress(0.30f, "Удаление через deploy.sh...")
        ssh.exec(rootCommand("[ -f /tmp/deploy.sh ] && env WDTT_DTLS_PORT=$dtlsPort WDTT_WG_PORT=$wgPort WDTT_SSH_PORT=$port bash /tmp/deploy.sh uninstall 2>/dev/null || true"), timeout = 30000L)

        onProgress(0.45f, "Удаление бинарника...")
        ssh.exec(rootCommand("pkill -x wdtt-server 2>/dev/null || true; rm -f /usr/local/bin/wdtt-server"), timeout = 10000L)

        onProgress(0.60f, "Очистка firewall...")
        ssh.exec(
            rootCommand(
                "if command -v iptables >/dev/null 2>&1; then " +
                    "for i in 1 2 3 4 5; do " +
                    "for iface in $(ls /sys/class/net 2>/dev/null || true); do " +
                    "iptables -t nat -D POSTROUTING -s 10.66.66.0/24 -o \"${'$'}iface\" -m comment --comment WDTT_MANAGED -j MASQUERADE 2>/dev/null || true; " +
                    "done; " +
                    "iptables -D INPUT -p udp --dport $dtlsPort -m comment --comment WDTT_MANAGED -j ACCEPT 2>/dev/null || true; " +
                    "iptables -D INPUT -p udp --dport $wgPort -m comment --comment WDTT_MANAGED -j ACCEPT 2>/dev/null || true; " +
                    "iptables -D INPUT -p udp --dport 56000 -m comment --comment WDTT_MANAGED -j ACCEPT 2>/dev/null || true; " +
                    "iptables -D INPUT -p udp --dport 56001 -m comment --comment WDTT_MANAGED -j ACCEPT 2>/dev/null || true; " +
                    "iptables -D INPUT -p tcp --dport $port -m comment --comment WDTT_MANAGED -j ACCEPT 2>/dev/null || true; " +
                    "iptables -D INPUT -p tcp --dport 22 -m comment --comment WDTT_MANAGED -j ACCEPT 2>/dev/null || true; " +
                    "iptables -D FORWARD -i wdtt0 -m comment --comment WDTT_MANAGED -j ACCEPT 2>/dev/null || true; " +
                    "iptables -D FORWARD -o wdtt0 -m comment --comment WDTT_MANAGED -j ACCEPT 2>/dev/null || true; " +
                    "done; fi; " +
                    "if command -v nft >/dev/null 2>&1; then " +
                    "nft delete table ip wdtt 2>/dev/null || true; " +
                    "nft delete table inet wdtt 2>/dev/null || true; " +
                    "nft delete table inet wdtt_mangle 2>/dev/null || true; " +
                    "fi"
            ),
            timeout = 15000L
        )

        onProgress(0.75f, "Удаление VPN-интерфейса...")
        ssh.exec(
            rootCommand(
                "ip link show wdtt0 >/dev/null 2>&1 && ip link del wdtt0 2>/dev/null || true; " +
                    "[ -d /etc/wdtt ] && find /etc/wdtt -mindepth 1 -maxdepth 1 ! -name passwords.json ! -name wg-keys.dat -exec rm -rf {} + 2>/dev/null || true; " +
                    "[ -f /etc/wdtt/passwords.json ] && chmod 600 /etc/wdtt/passwords.json 2>/dev/null || true; " +
                    "[ -f /etc/wdtt/wg-keys.dat ] && chmod 600 /etc/wdtt/wg-keys.dat 2>/dev/null || true"
            ),
            timeout = 10000L
        )

        onProgress(0.90f, "Очистка sysctl...")
        ssh.exec(rootCommand("rm -f /etc/sysctl.d/99-wdtt.conf; sysctl --system >/dev/null 2>&1 || true"), timeout = 15000L)

        onProgress(1.0f, "Готово!")
        DeployManager.stopDeploy("success")

    } catch (e: Exception) {
        DeployManager.writeError("Uninstall error: ${e.message}")
        DeployManager.stopDeploy("Ошибка: ${e.message?.take(100)}")
    } finally {
        try { session?.disconnect() } catch (_: Exception) {}
        DeployManager.activeSession = null
    }
}

// ==================== Dialogs ====================

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ServerImportConfirmDialog(
    title: String,
    backup: ServerBackup,
    request: DeployRequest,
    mode: ServerImportMode,
    isDeploy: Boolean,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit
) {
    val portsSpec = "${request.dtlsPort},${request.wgPort},${request.localPort}"
    val dnsValue = listOf(request.dns1, request.dns2).filter { it.isNotBlank() }.joinToString(",")
    val modeText = if (mode == ServerImportMode.Replace) "Заменить базу сервера бэкапом" else "Добавить отсутствующие пароли и устройства"
    val mainPasswordText = when {
        request.mainPass.isNotBlank() -> "из текущих секретов деплоя"
        mode == ServerImportMode.Replace && backup.mainPassword.isNotBlank() -> "из бэкапа"
        else -> "оставить текущий на сервере"
    }
    val adminText = when {
        request.adminId.isNotBlank() || request.botToken.isNotBlank() -> "поля деплоя заменят значения из бэкапа/сервера"
        mode == ServerImportMode.Replace -> "из бэкапа"
        else -> "оставить текущие на сервере"
    }
    val wgText = when {
        mode == ServerImportMode.Replace && backup.hasWgKeys -> "заменить WG-ключи из бэкапа"
        mode == ServerImportMode.Replace -> "WG-ключей в бэкапе нет, сервер создаст новые"
        else -> "не трогать WG-ключи текущего сервера"
    }

    androidx.compose.ui.window.Dialog(onDismissRequest = onDismiss) {
        BoxWithConstraints(
            modifier = Modifier.fillMaxSize().padding(8.dp),
            contentAlignment = Alignment.Center
        ) {
            Surface(
                modifier = Modifier.heightIn(max = maxHeight * 0.92f),
                shape = RoundedCornerShape(24.dp),
                color = MaterialTheme.colorScheme.surface,
                contentColor = MaterialTheme.colorScheme.onSurface,
                tonalElevation = 8.dp
            ) {
                Column(
                    modifier = Modifier
                        .padding(24.dp)
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(14.dp)
                ) {
                Text(
                    title,
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary
                )
                Text(
                    if (isDeploy) {
                        "Перед деплоем приложение подготовит импорт под текущие поля нового сервера. Старые IP и порты быстрых ссылок из бэкапа не будут перенесены вслепую."
                    } else {
                        "Импорт остановит wdtt.service, обновит базу и перезапустит сервис. Текущие подключения на короткое время оборвутся."
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f),
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.25f))
                ) {
                    Column(
                        modifier = Modifier.fillMaxWidth().padding(14.dp),
                        verticalArrangement = Arrangement.spacedBy(7.dp)
                    ) {
                        ConfirmLine("Режим", modeText)
                        ConfirmLine("Бэкап", "${backup.sourceHost}, ${backup.createdAt}")
                        ConfirmLine("Данные", "${backup.passwordCount} паролей, ${backup.deviceCount} устройств")
                        ConfirmLine("Адрес сервера для ссылок", request.host)
                        ConfirmLine("Порты быстрых ссылок", portsSpec)
                        ConfirmLine("Главный пароль", mainPasswordText)
                        ConfirmLine("Telegram-админ/бот", adminText)
                        ConfirmLine("DNS", dnsValue.ifBlank { "из бэкапа или стандартный" })
                        ConfirmLine("WireGuard-ключи", wgText)
                    }
                }
                Text(
                    if (mode == ServerImportMode.Replace) {
                        "В режиме «Заменить» текущая база паролей и устройств на целевом сервере будет перезаписана. Используйте это для переезда на новый сервер."
                    } else {
                        "В режиме «Добавить» совпадающие пароли и устройства не перезаписываются. Это безопаснее для уже используемого сервера."
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    OutlinedButton(
                        onClick = onDismiss,
                        modifier = Modifier.weight(1f).heightIn(min = 48.dp),
                        shape = RoundedCornerShape(16.dp)
                    ) {
                        Text("Назад")
                    }
                    Button(
                        onClick = onConfirm,
                        modifier = Modifier.weight(1f).heightIn(min = 48.dp),
                        shape = RoundedCornerShape(16.dp)
                    ) {
                        Text(if (isDeploy) "Продолжить" else "Импорт", fontWeight = FontWeight.Bold)
                    }
                    Spacer(Modifier.height(4.dp))
                }
            }
        }
    }
}
}

@Composable
private fun ConfirmLine(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.Top
    ) {
        Text(
            label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(0.9f)
        )
        Text(
            value,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurface,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.weight(1.1f)
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeploySecretsDialog(
    settingsStore: SettingsStore,
    initialMainPass: String,
    initialAdminId: String,
    initialBotToken: String,
    initialSshPort: String,
    initialDns1: String,
    initialDns2: String,
    initialManualPortsEnabled: Boolean,
    initialServerDtlsPort: String,
    initialServerWgPort: String,
    deployIp: String,
    deployLogin: String,
    deployPassword: String,
    onSaved: (String, String) -> Unit,
    onDismiss: () -> Unit
) {
    val scope = rememberCoroutineScope()
    var passInput by rememberSaveable { mutableStateOf(initialMainPass) }
    var adminIdInput by rememberSaveable { mutableStateOf(initialAdminId) }
    var botTokenInput by rememberSaveable { mutableStateOf(initialBotToken) }
    var showTelegramBotHelp by rememberSaveable { mutableStateOf(false) }
    var passInputFocused by remember { mutableStateOf(false) }
    var botTokenFocused by remember { mutableStateOf(false) }
    var sshPortInput by rememberSaveable { mutableStateOf(if (initialSshPort.isBlank()) "22" else initialSshPort) }
    var dns1Input by rememberSaveable { mutableStateOf(initialDns1.ifBlank { "1.1.1.1" }) }
    var dns2Input by rememberSaveable { mutableStateOf(initialDns2.ifBlank { "1.0.0.1" }) }
    var manualDnsInput by rememberSaveable {
        mutableStateOf(
            initialDns1.isNotBlank() && initialDns1 != "1.1.1.1" ||
                initialDns2.isNotBlank() && initialDns2 != "1.0.0.1"
        )
    }
    var manualSshInput by rememberSaveable { mutableStateOf(initialSshPort.isNotBlank() && initialSshPort != "22") }
    var manualPortsInput by rememberSaveable {
        mutableStateOf(
            initialManualPortsEnabled &&
                (initialServerDtlsPort.ifBlank { "56000" } != "56000" ||
                    initialServerWgPort.ifBlank { "56001" } != "56001")
        )
    }
    var dtlsPortInput by rememberSaveable { mutableStateOf(initialServerDtlsPort.ifBlank { "56000" }) }
    var wgPortInput by rememberSaveable { mutableStateOf(initialServerWgPort.ifBlank { "56001" }) }

    fun normalizePort(value: String, fallback: String): String {
        return value.toIntOrNull()?.takeIf { it in 1..65535 }?.toString() ?: fallback
    }

    androidx.compose.ui.window.Dialog(onDismissRequest = onDismiss) {
        BoxWithConstraints(
            modifier = Modifier.fillMaxSize().padding(8.dp),
            contentAlignment = Alignment.Center
        ) {
            Surface(
                modifier = Modifier.heightIn(max = maxHeight * 0.92f),
                shape = RoundedCornerShape(24.dp),
                color = MaterialTheme.colorScheme.surface,
                contentColor = MaterialTheme.colorScheme.onSurface,
                tonalElevation = 8.dp
            ) {
                Column(modifier = Modifier.padding(24.dp).fillMaxWidth().verticalScroll(rememberScrollState())) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("Секреты Деплоя", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Default.Close, contentDescription = "Закрыть")
                    }
                }

                Spacer(Modifier.height(16.dp))

                val isPasswordValid = passInput.isNotEmpty() && passInput.matches(Regex("^[a-zA-Z0-9_.!?:#/-]+$"))

                OutlinedTextField(
                    value = passInput,
                    onValueChange = { passInput = it.filter { c -> !c.isWhitespace() } },
                    label = { Text("Задайте пароль туннеля (любой)") },
                    placeholder = { Text("Придумайте надежный пароль") },
                    singleLine = true,
                    visualTransformation = if (passInputFocused) VisualTransformation.None else PasswordVisualTransformation(),
                    modifier = Modifier
                        .fillMaxWidth()
                        .onFocusChanged { passInputFocused = it.isFocused },
                    shape = RoundedCornerShape(16.dp),
                    isError = passInput.isNotEmpty() && !isPasswordValid
                )
                Text(
                    if (passInput.isNotEmpty() && !isPasswordValid) {
                        "Разрешены только буквы, цифры и симв: _ . ! ? : # - /"
                    } else {
                        "Это первый пароль для подключения к VPN, обычно пароль администратора сервера."
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = if (passInput.isNotEmpty() && !isPasswordValid) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                    modifier = Modifier.padding(top = 4.dp)
                )

                Spacer(Modifier.height(16.dp))
                HorizontalDivider()
                Spacer(Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        "Telegram-бот для управления",
                        color = MaterialTheme.colorScheme.primary,
                        fontWeight = FontWeight.SemiBold,
                        style = MaterialTheme.typography.titleSmall,
                        modifier = Modifier.weight(1f)
                    )
                    IconButton(
                        onClick = { showTelegramBotHelp = true },
                        modifier = Modifier.size(36.dp)
                    ) {
                        Icon(
                            Icons.AutoMirrored.Filled.HelpOutline,
                            contentDescription = "Как создать и подключить Telegram-бота",
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }
                Text(
                    "Можно оставить пустым, если бот не нужен. При подключении без установки приложение проверяет SSH-доступ и главный пароль, а Telegram-поля читает с сервера и подставляет автоматически.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(8.dp))

                OutlinedTextField(
                    value = adminIdInput,
                    onValueChange = { adminIdInput = it },
                    label = { Text("ID Админа (опционально)") },
                    placeholder = { Text("ID из @userinfobot") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                        keyboardType = androidx.compose.ui.text.input.KeyboardType.Number
                    )
                )

                Spacer(Modifier.height(8.dp))

                OutlinedTextField(
                    value = botTokenInput,
                    onValueChange = { botTokenInput = it },
                    label = { Text("Токен Бота (опционально)") },
                    placeholder = { Text("Токен от BotFather") },
                    singleLine = true,
                    visualTransformation = if (botTokenFocused) VisualTransformation.None else PasswordVisualTransformation(),
                    modifier = Modifier
                        .fillMaxWidth()
                        .onFocusChanged { botTokenFocused = it.isFocused },
                    shape = RoundedCornerShape(16.dp)
                )

                Spacer(Modifier.height(16.dp))
                HorizontalDivider()
                Spacer(Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("DNS сервера", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.SemiBold)
                        Text(
                            "Оставьте выключенным, если подходят стандартные DNS 1.1.1.1 и 1.0.0.1.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Switch(
                        checked = manualDnsInput,
                        onCheckedChange = { manualDnsInput = it }
                    )
                }

                if (manualDnsInput) {
                    Spacer(Modifier.height(8.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        OutlinedTextField(
                            value = dns1Input,
                            onValueChange = { dns1Input = it.filter { c -> !c.isWhitespace() } },
                            label = { Text("Основной DNS") },
                            placeholder = { Text("1.1.1.1") },
                            singleLine = true,
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(16.dp)
                        )
                        OutlinedTextField(
                            value = dns2Input,
                            onValueChange = { dns2Input = it.filter { c -> !c.isWhitespace() } },
                            label = { Text("Резервный DNS") },
                            placeholder = { Text("1.0.0.1") },
                            singleLine = true,
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(16.dp)
                        )
                    }
                }

                Spacer(Modifier.height(16.dp))
                HorizontalDivider()
                Spacer(Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("SSH-порт", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.SemiBold)
                        Text(
                            "Оставьте выключенным, если SSH работает на стандартном порту 22.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Switch(
                        checked = manualSshInput,
                        onCheckedChange = { manualSshInput = it }
                    )
                }

                if (manualSshInput) {
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = sshPortInput,
                        onValueChange = { sshPortInput = it.filter(Char::isDigit).take(5) },
                        label = { Text("Порт для деплоя SSH") },
                        placeholder = { Text("22") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                            keyboardType = androidx.compose.ui.text.input.KeyboardType.Number
                        )
                    )
                }

                Spacer(Modifier.height(16.dp))
                HorizontalDivider()
                Spacer(Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Порты сервера", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.SemiBold)
                        Text(
                            "Оставьте выключенным, если подходят стандартные порты: DTLS 56000 и WireGuard 56001.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Switch(
                        checked = manualPortsInput,
                        onCheckedChange = { manualPortsInput = it }
                    )
                }

                if (manualPortsInput) {
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = dtlsPortInput,
                        onValueChange = { dtlsPortInput = it.filter(Char::isDigit).take(5) },
                        label = { Text("Порт DTLS сервера") },
                        placeholder = { Text("56000") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                            keyboardType = androidx.compose.ui.text.input.KeyboardType.Number
                        )
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = wgPortInput,
                        onValueChange = { wgPortInput = it.filter(Char::isDigit).take(5) },
                        label = { Text("Порт WireGuard сервера") },
                        placeholder = { Text("56001") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                            keyboardType = androidx.compose.ui.text.input.KeyboardType.Number
                        )
                    )
                }

                Spacer(Modifier.height(24.dp))
                Button(
                    onClick = {
                        val finalPort = if (manualSshInput) normalizePort(sshPortInput, "22") else "22"
                        val finalDtls = if (manualPortsInput) normalizePort(dtlsPortInput, "56000") else "56000"
                        val finalWg = if (manualPortsInput) normalizePort(wgPortInput, "56001") else "56001"
                        val finalDns1 = if (manualDnsInput) dns1Input.ifBlank { "1.1.1.1" } else "1.1.1.1"
                        val finalDns2 = if (manualDnsInput) dns2Input.ifBlank { "1.0.0.1" } else "1.0.0.1"
                        val effectiveManualPorts = manualPortsInput && (finalDtls != "56000" || finalWg != "56001")
                        scope.launch {
                            settingsStore.saveDeploySecrets(passInput, adminIdInput, botTokenInput, finalPort)
                            settingsStore.saveDeploy(deployIp, deployLogin, deployPassword, finalPort, finalDns1, finalDns2)
                            settingsStore.saveManualPortsEnabled(effectiveManualPorts)
                            settingsStore.savePorts(finalDtls.toInt(), finalWg.toInt(), settingsStore.listenPort.first())
                            onSaved(finalDtls, finalWg)
                            onDismiss()
                        }
                    },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                    shape = RoundedCornerShape(16.dp),
                    enabled = isPasswordValid,
                    colors = ButtonDefaults.buttonColors(contentColor = MaterialTheme.colorScheme.onPrimary)
                ) { Text("Сохранить", fontWeight = FontWeight.SemiBold) }
                    Spacer(Modifier.height(4.dp))
                }
            }
        }
    }

    if (showTelegramBotHelp) {
        TelegramBotHelpDialog(onDismiss = { showTelegramBotHelp = false })
    }
}

@Composable
private fun TelegramBotHelpDialog(onDismiss: () -> Unit) {
    val context = LocalContext.current

    fun openTelegramBot(username: String, miniApp: Boolean = false) {
        val tgUri = if (miniApp) {
            "tg://resolve?domain=$username&startapp="
        } else {
            "tg://resolve?domain=$username"
        }
        val webUri = if (miniApp) {
            "https://t.me/$username?startapp"
        } else {
            "https://t.me/$username"
        }
        val tgIntent = Intent(Intent.ACTION_VIEW, Uri.parse(tgUri)).apply {
            addCategory(Intent.CATEGORY_BROWSABLE)
        }
        val webIntent = Intent(Intent.ACTION_VIEW, Uri.parse(webUri)).apply {
            addCategory(Intent.CATEGORY_BROWSABLE)
        }
        val intent = if (tgIntent.resolveActivity(context.packageManager) != null) tgIntent else webIntent
        runCatching {
            context.startActivity(intent)
        }.onFailure {
            Toast.makeText(context, "Не удалось открыть Telegram", Toast.LENGTH_SHORT).show()
        }
    }

    fun copyTelegramHandle(handle: String) {
        val clipboard = context.getSystemService(ClipboardManager::class.java)
        clipboard?.setPrimaryClip(ClipData.newPlainText("Telegram", handle))
        Toast.makeText(context, "$handle скопирован", Toast.LENGTH_SHORT).show()
    }

    androidx.compose.ui.window.Dialog(onDismissRequest = onDismiss) {
        BoxWithConstraints(
            modifier = Modifier.fillMaxSize().padding(8.dp),
            contentAlignment = Alignment.Center
        ) {
            Surface(
                modifier = Modifier.heightIn(max = maxHeight * 0.92f),
                shape = RoundedCornerShape(24.dp),
                color = MaterialTheme.colorScheme.surface,
                contentColor = MaterialTheme.colorScheme.onSurface,
                tonalElevation = 8.dp
            ) {
                Column(
                    modifier = Modifier
                        .padding(22.dp)
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            "Подключение Telegram-бота",
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.weight(1f)
                        )
                        IconButton(onClick = onDismiss) {
                            Icon(Icons.Default.Close, contentDescription = "Закрыть")
                        }
                    }

                    Text(
                        "1. Откройте мини-приложение BotFather и создайте бота без ручной отправки команд. Если мини-приложение недоступно в вашей версии Telegram, откройте обычный чат @BotFather, нажмите «Запустить» и отправьте /newbot. Задайте имя и username, который заканчивается на bot, затем скопируйте выданный токен.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    TelegramBotActionRow(
                        buttonText = "Мини-приложение BotFather",
                        handle = "@BotFather",
                        onOpen = { openTelegramBot("BotFather", miniApp = true) },
                        onCopy = { copyTelegramHandle("@BotFather") }
                    )
                    TelegramBotActionRow(
                        buttonText = "Обычный чат @BotFather",
                        handle = "@BotFather",
                        onOpen = { openTelegramBot("BotFather") },
                        onCopy = { copyTelegramHandle("@BotFather") }
                    )

                    Text(
                        "2. Откройте @userinfobot, нажмите «Запустить» и скопируйте свой числовой Telegram ID.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    TelegramBotActionRow(
                        buttonText = "Открыть @userinfobot",
                        handle = "@userinfobot",
                        onOpen = { openTelegramBot("userinfobot") },
                        onCopy = { copyTelegramHandle("@userinfobot") }
                    )

                    Text(
                        "3. Вставьте ID в поле администратора, токен — в поле бота и нажмите «Сохранить». Чтобы передать эти данные серверу, выполните установку во вкладке «Деплой» — при обновлении сервера можно выбрать установку с сохранением данных.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        "Токен даёт доступ к управлению ботом. Не отправляйте его другим людям и не публикуйте; при утечке перевыпустите токен через @BotFather.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )

                    Button(
                        onClick = onDismiss,
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                        shape = RoundedCornerShape(16.dp)
                    ) {
                        Text("Понятно", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
    }
}

@Composable
private fun TelegramBotActionRow(
    buttonText: String,
    handle: String,
    onOpen: () -> Unit,
    onCopy: () -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        OutlinedButton(
            onClick = onOpen,
            modifier = Modifier
                .weight(1f)
                .heightIn(min = 48.dp),
            shape = RoundedCornerShape(16.dp)
        ) {
            Text(buttonText, textAlign = TextAlign.Center)
        }
        FilledTonalIconButton(
            onClick = onCopy,
            modifier = Modifier.size(48.dp)
        ) {
            Icon(
                Icons.Default.ContentCopy,
                contentDescription = "Скопировать $handle",
                modifier = Modifier.size(20.dp)
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ExistingInstallDialog(
	info: ExistingInstallInfo,
	importMode: ServerImportMode? = null,
	onDismiss: () -> Unit,
	onPreserve: () -> Unit,
	onReset: () -> Unit
) {
	val checkError = info.checkError
	androidx.compose.ui.window.Dialog(onDismissRequest = onDismiss) {
		BoxWithConstraints(
			modifier = Modifier.fillMaxSize().padding(8.dp),
			contentAlignment = Alignment.Center
		) {
			Surface(
				modifier = Modifier.heightIn(max = maxHeight * 0.92f),
				shape = RoundedCornerShape(24.dp),
				color = MaterialTheme.colorScheme.surface,
				contentColor = MaterialTheme.colorScheme.onSurface,
				tonalElevation = 8.dp
			) {
				Column(
					modifier = Modifier
						.padding(24.dp)
						.fillMaxWidth()
						.verticalScroll(rememberScrollState()),
					verticalArrangement = Arrangement.spacedBy(16.dp)
				) {
				Text(
					if (checkError == null) "WDTT Plus уже найден на сервере" else "Проверка сервера не завершилась",
					style = MaterialTheme.typography.titleLarge,
					fontWeight = FontWeight.Bold,
					color = MaterialTheme.colorScheme.primary
				)
				Text(
					if (checkError == null) {
						"На сервере есть следы установленного WDTT Plus. Выберите, как продолжить деплой."
					} else {
						"Не удалось надежно проверить, установлен ли WDTT Plus на сервере. Можно продолжить обновление с сохранением данных, но лучше сначала убедиться, что SSH-доступ работает стабильно."
					},
					style = MaterialTheme.typography.bodyMedium,
					color = MaterialTheme.colorScheme.onSurfaceVariant
				)
				if (checkError != null) {
					Surface(
						shape = RoundedCornerShape(14.dp),
						color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.55f),
						border = BorderStroke(1.dp, MaterialTheme.colorScheme.error.copy(alpha = 0.35f))
					) {
						Text(
							text = checkError.take(180),
							modifier = Modifier.fillMaxWidth().padding(12.dp),
							style = MaterialTheme.typography.bodySmall,
							color = MaterialTheme.colorScheme.onErrorContainer
						)
					}
				}
				Surface(
					shape = RoundedCornerShape(16.dp),
					color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f),
					border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.25f))
				) {
					Column(
						modifier = Modifier.fillMaxWidth().padding(14.dp),
						verticalArrangement = Arrangement.spacedBy(6.dp)
					) {
						InstallTraceLine("Сервис systemd", info.serviceExists)
						InstallTraceLine("Бинарник сервера", info.binaryExists)
						InstallTraceLine("Каталог /etc/wdtt", info.configDirExists)
						InstallTraceLine("База паролей", info.accessDbExists)
						InstallTraceLine("WireGuard-ключи", info.wgKeysExist)
						InstallTraceLine("Сервис активен", info.active)
					}
				}
				Surface(
					shape = RoundedCornerShape(14.dp),
					color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.45f),
					border = BorderStroke(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.25f))
				) {
					Text(
						"Направление установки: приложение → сервер. После подтверждения текущие поля приложения будут записаны на сервер; подключение без установки действует в обратном направлении и здесь не выполняется.",
						modifier = Modifier.fillMaxWidth().padding(12.dp),
						style = MaterialTheme.typography.bodySmall,
						color = MaterialTheme.colorScheme.onPrimaryContainer
					)
				}
				info.comparison?.let { comparison ->
					when {
						comparison.checkError != null -> Surface(
							shape = RoundedCornerShape(14.dp),
							color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.55f),
							border = BorderStroke(1.dp, MaterialTheme.colorScheme.error.copy(alpha = 0.35f))
						) {
							Text(
								"Не удалось сравнить сохранённые поля сервера с приложением. При продолжении они могут быть заменены локальными значениями: ${comparison.checkError.take(180)}",
								modifier = Modifier.fillMaxWidth().padding(12.dp),
								style = MaterialTheme.typography.bodySmall,
								color = MaterialTheme.colorScheme.onErrorContainer
							)
						}
						comparison.overwriteLines.isNotEmpty() -> Surface(
							shape = RoundedCornerShape(14.dp),
							color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.55f),
							border = BorderStroke(1.dp, MaterialTheme.colorScheme.error.copy(alpha = 0.35f))
						) {
							Column(
								modifier = Modifier.fillMaxWidth().padding(12.dp),
								verticalArrangement = Arrangement.spacedBy(6.dp)
							) {
								Text("Будут заменены серверные значения:", fontWeight = FontWeight.SemiBold)
								comparison.overwriteLines.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
								Text(
									"Если нужны значения сервера, отмените установку и сначала выполните «Подключиться (без установки)». Для выходного IP используйте «Заполнить».",
									style = MaterialTheme.typography.bodySmall
								)
							}
						}
						else -> Text(
							"Сверка завершена: конфликтующих сохранённых значений не найдено.",
							style = MaterialTheme.typography.bodySmall,
							color = MaterialTheme.colorScheme.onSurfaceVariant
						)
					}
					comparison.notes.forEach {
						Text("• $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
					}
				}
				Text(
					"С сохранением данных: обновится бинарник, серверные настройки будут взяты из приложения, а клиентские пароли, привязки устройств, история и ключи сохранятся. Перед изменением создаётся страховочная копия.\n\nС нуля: данные WDTT Plus на сервере будут удалены, все выданные ссылки и привязки пропадут; затем сервер получит текущие поля приложения.",
					style = MaterialTheme.typography.bodySmall,
					color = MaterialTheme.colorScheme.onSurfaceVariant
				)
				if (importMode != null) {
					Surface(
						shape = RoundedCornerShape(14.dp),
						color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.45f),
						border = BorderStroke(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.25f))
					) {
						Text(
							text = if (importMode == ServerImportMode.Replace) {
								"Выбран импорт с заменой. При любом варианте база будет подготовлена из бэкапа, а IP и порты быстрых ссылок будут взяты из текущих полей деплоя."
							} else {
								"Выбран импорт с добавлением. При обновлении с сохранением новые записи добавятся к текущей базе без перезаписи конфликтов. При варианте «с нуля» сервер сначала очистится, затем будут добавлены данные из бэкапа."
							},
							modifier = Modifier.fillMaxWidth().padding(12.dp),
							style = MaterialTheme.typography.bodySmall,
							color = MaterialTheme.colorScheme.onPrimaryContainer
						)
					}
				}
				Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
					Button(
						onClick = onPreserve,
						modifier = Modifier.fillMaxWidth().heightIn(min = 50.dp),
						shape = RoundedCornerShape(16.dp)
					) {
						Icon(Icons.Default.CloudUpload, null, Modifier.size(18.dp))
						Spacer(Modifier.width(8.dp))
						Text(
							if (checkError == null) "Обновить с сохранением" else "Продолжить с сохранением",
							modifier = Modifier.weight(1f),
							fontWeight = FontWeight.Bold
						)
					}
					OutlinedButton(
						onClick = onReset,
						modifier = Modifier.fillMaxWidth().heightIn(min = 50.dp),
						shape = RoundedCornerShape(16.dp),
						colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
						border = BorderStroke(1.dp, MaterialTheme.colorScheme.error.copy(alpha = 0.6f))
					) {
						Icon(Icons.Default.Delete, null, Modifier.size(18.dp))
						Spacer(Modifier.width(8.dp))
						Text("Начать с нуля", fontWeight = FontWeight.Bold)
					}
					TextButton(
						onClick = onDismiss,
						modifier = Modifier.fillMaxWidth()
					) {
						Text("Отмена")
					}
					Spacer(Modifier.height(4.dp))
				}
			}
		}
	}
}
}

@Composable
private fun InstallTraceLine(label: String, present: Boolean) {
	Row(
		modifier = Modifier.fillMaxWidth(),
		verticalAlignment = Alignment.CenterVertically,
		horizontalArrangement = Arrangement.spacedBy(8.dp)
	) {
		Icon(
			imageVector = if (present) Icons.Default.CheckCircle else Icons.Default.Close,
			contentDescription = null,
			tint = if (present) WDTTColors.connected else MaterialTheme.colorScheme.onSurfaceVariant,
			modifier = Modifier.size(16.dp)
		)
		Text(
			text = label,
			style = MaterialTheme.typography.bodySmall,
			color = MaterialTheme.colorScheme.onSurface,
			modifier = Modifier.weight(1f)
		)
		Text(
			text = if (present) "найдено" else "нет",
			style = MaterialTheme.typography.bodySmall,
			color = MaterialTheme.colorScheme.onSurfaceVariant
		)
	}
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun UninstallConfirmDialog(onDismiss: () -> Unit, onConfirm: () -> Unit) {
    var confirmText by remember { mutableStateOf("") }
    val isConfirmed = confirmText.trim().lowercase() == "да"

    androidx.compose.ui.window.Dialog(onDismissRequest = onDismiss) {
        BoxWithConstraints(
            modifier = Modifier.fillMaxSize().padding(8.dp),
            contentAlignment = Alignment.Center
        ) {
            Surface(
                modifier = Modifier.heightIn(max = maxHeight * 0.92f),
                shape = RoundedCornerShape(24.dp),
                color = MaterialTheme.colorScheme.surface,
                contentColor = MaterialTheme.colorScheme.onSurface,
                tonalElevation = 8.dp
            ) {
                Column(
                    modifier = Modifier
                        .padding(24.dp)
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                Text(
                    "Удаление WDTT Plus с сервера",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.error
                )
                Text(
                    "Будут удалены: бинарник, systemd-сервис, бот, конфигурация WDTT Plus и только помеченные правила firewall/NAT для WDTT Plus.\n\nЭто действие необратимо.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                OutlinedTextField(
                    value = confirmText,
                    onValueChange = { confirmText = it },
                    label = { Text("Введите «да» для подтверждения") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = MaterialTheme.colorScheme.error,
                        unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f)
                    )
                )
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    OutlinedButton(
                        onClick = onDismiss, modifier = Modifier.weight(1f).heightIn(min = 48.dp),
                        shape = RoundedCornerShape(16.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.onSurface)
                    ) { Text("Отмена") }
                    Button(
                        onClick = onConfirm, modifier = Modifier.weight(1f).heightIn(min = 48.dp),
                        shape = RoundedCornerShape(16.dp), enabled = isConfirmed,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.error,
                            contentColor = MaterialTheme.colorScheme.onError
                        )
                    ) {
                        Icon(Icons.Default.Delete, null, Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Удалить", fontWeight = FontWeight.Bold)
                    }
                    Spacer(Modifier.height(4.dp))
                }
            }
        }
    }
}
}
