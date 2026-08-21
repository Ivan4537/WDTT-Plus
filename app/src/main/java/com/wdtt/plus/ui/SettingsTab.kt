package com.wdtt.plus.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.ContextWrapper
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Handler
import android.os.Looper
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.HelpOutline
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Tag
import androidx.compose.material.icons.filled.Update
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.PointerEventType
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.LinkAnnotation
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextLinkStyles
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.text.withLink
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import com.wdtt.plus.BuildConfig
import com.wdtt.plus.CachedRemoteAction
import com.wdtt.plus.AccessLifecycleCoordinator
import com.wdtt.plus.AccessLifecycleRefreshResult
import com.wdtt.plus.AccessLifecycleSeverity
import com.wdtt.plus.AccessLifecycleUiState
import com.wdtt.plus.AccessStartDecision
import com.wdtt.plus.CaptchaWebViewManager
import com.wdtt.plus.ConnectionIssueKind
import com.wdtt.plus.DEFAULT_VK_CLIENT_IDS
import com.wdtt.plus.DEFAULT_RT_TURN_SNI
import com.wdtt.plus.ManlCaptchaWebViewManager
import com.wdtt.plus.MainActivity
import com.wdtt.plus.MANAGED_CONFIG_FIRST_START_EXTRA
import com.wdtt.plus.RemoteContinuation
import com.wdtt.plus.RemoteContinuationLauncher
import com.wdtt.plus.RemoteActionCatalogGateway
import com.wdtt.plus.RemoteDocumentGateway
import com.wdtt.plus.RemoteLaunchTarget
import com.wdtt.plus.RemoteUiAction
import com.wdtt.plus.RemoteUiActionLauncher
import com.wdtt.plus.RT_MASQUE_CONFIG_FILE_NAME
import com.wdtt.plus.SettingsStore
import com.wdtt.plus.TunnelManager
import com.wdtt.plus.TunnelService
import com.wdtt.plus.TunnelStopCoordinator
import com.wdtt.plus.TunnelStopResult
import com.wdtt.plus.TunnelTransition
import com.wdtt.plus.TUNNEL_PROFILE_INDEX_EXTRA
import com.wdtt.plus.VpnDnsSettingsSnapshot
import com.wdtt.plus.normalizeTunnelWorkerCount
import com.wdtt.plus.normalizeRtTurnSni
import com.wdtt.plus.shouldUseManagedConfigFirstStart
import com.wdtt.plus.TrustedWifiManager
import com.wdtt.plus.VkJoinLink
import com.wdtt.plus.WDTTColors
import com.wdtt.plus.WdttDeepLink
import com.wdtt.plus.WdttDeepLinkApplyPlan
import com.wdtt.plus.isValidVkClientId
import com.wdtt.plus.isStandaloneUiIssue
import com.wdtt.plus.accessLifecycleDismissalSignature
import com.wdtt.plus.accessLifecycleCanDismiss
import com.wdtt.plus.boundContinuationAvailable
import com.wdtt.plus.fallbackTitle
import com.wdtt.plus.vpnProfileDisplayName
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import kotlinx.coroutines.CancellationException
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import kotlin.math.roundToInt
import java.io.File

private const val WORKERS_PER_GROUP = 9
private const val REMOTE_ACTION_REFRESH_MS = 10 * 60 * 1000L

private fun launchRemoteTarget(context: Context, target: RemoteLaunchTarget) {
    var current: Context? = context
    while (current != null) {
        if (current is MainActivity) {
            current.launchRemoteContinuation(target)
            return
        }
        current = (current as? ContextWrapper)?.baseContext
    }
    RemoteContinuationLauncher.launch(context, target)
}

internal fun usesCompactTunnelInterface(interfaceRole: String): Boolean = interfaceRole == "user"

internal fun resolveConnectionInputMethod(
    savedMethod: String,
    hasStoredLink: Boolean,
    hasManualConnection: Boolean,
    userInterface: Boolean,
): String = when (savedMethod) {
    "link" -> "link"
    "manual" -> "manual"
    else -> when {
        hasStoredLink -> "link"
        hasManualConnection -> "manual"
        userInterface -> "link"
        else -> "manual"
    }
}

internal fun hasTunnelConnectionSource(
    linkMode: Boolean,
    linkValid: Boolean,
    peer: String,
    password: String,
): Boolean = (linkMode && linkValid) || peer.isNotBlank() && password.isNotBlank()

internal fun shouldShowRemoteActionCard(
    audience: Boolean,
    hasConnectionSource: Boolean,
    dismissed: Boolean,
    dismissCountdown: Int,
    actionResolved: Boolean,
    actionAvailable: Boolean,
): Boolean =
    audience &&
        !hasConnectionSource &&
        (!actionResolved || actionAvailable) &&
        (!dismissed || dismissCountdown > 0)

internal fun shouldShowTunnelRemoteActionCard(
    interfaceRole: String,
    preview: Boolean,
    hasConnectionSource: Boolean,
    dismissed: Boolean,
    dismissCountdown: Int,
    actionResolved: Boolean,
    actionAvailable: Boolean,
): Boolean {
    val adminInterface = interfaceRole == "admin"
    return shouldShowRemoteActionCard(
        audience = preview || interfaceRole == "user" || adminInterface,
        hasConnectionSource = hasConnectionSource && !adminInterface,
        dismissed = dismissed,
        dismissCountdown = dismissCountdown,
        actionResolved = actionResolved,
        actionAvailable = actionAvailable,
    )
}

internal fun shouldShowManagedHashStatusCard(
    continuationAvailable: Boolean,
    lifecycle: AccessLifecycleUiState,
): Boolean =
    !continuationAvailable &&
        lifecycle.managed &&
        lifecycle.allowConnect &&
        lifecycle.severity == AccessLifecycleSeverity.NORMAL &&
        (
            lifecycle.title.isNotBlank() ||
                lifecycle.message.isNotBlank() ||
                lifecycle.detailValue.isNotBlank()
            )

internal fun isSelectedCompactConnectionReady(
    selectedMethod: String,
    savedMethod: String,
    storedLinkMode: Boolean,
    linkPresent: Boolean,
    linkValid: Boolean,
    manualValid: Boolean,
): Boolean = when (selectedMethod) {
    "link" -> when {
        storedLinkMode && linkPresent -> linkValid
        savedMethod == "link" -> manualValid
        else -> false
    }
    "manual" -> !storedLinkMode &&
        (savedMethod == "manual" || savedMethod.isBlank()) &&
        manualValid
    else -> false
}

private fun isValidTunnelHost(value: String): Boolean {
    val host = value.trim()
    if (host.isBlank() || host.length > 253 || host.any { it == '/' || it == '\\' || it == ':' || it == '@' }) return false
    val ipv4 = Regex("^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$")
    if (ipv4.matches(host)) return true
    if (host.startsWith(".") || host.endsWith(".") || host.contains("..")) return false
    val labels = host.split(".")
    if (labels.size < 2) return false
    return labels.all { label ->
        label.isNotBlank() &&
            label.length <= 63 &&
            !label.startsWith("-") &&
            !label.endsWith("-") &&
            label.all { it.isLetterOrDigit() || it == '-' }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsTab(
    settingsStore: SettingsStore,
    scrollPosition: MutableIntState = rememberSaveable { mutableIntStateOf(0) },
    onVkHashesSaved: (Int, List<String>) -> Unit = { _, _ -> },
    onOpenProjectSupport: () -> Unit = {},
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    val currentDensity = LocalDensity.current
    CompositionLocalProvider(
        LocalDensity provides Density(currentDensity.density, fontScale = 1f)
    ) {
        SettingsTabContent(
            context = context,
            scope = scope,
            settingsStore = settingsStore,
            scrollPosition = scrollPosition,
            onVkHashesSaved = onVkHashesSaved,
            onOpenProjectSupport = onOpenProjectSupport,
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsTabContent(
    context: android.content.Context,
    scope: kotlinx.coroutines.CoroutineScope,
    settingsStore: SettingsStore,
    scrollPosition: MutableIntState,
    onVkHashesSaved: (Int, List<String>) -> Unit,
    onOpenProjectSupport: () -> Unit,
) {
    val profileSnapshotState by
        settingsStore.activeTunnelProfileContentUiSnapshot.collectAsStateWithLifecycle()
    val profileSnapshot = profileSnapshotState ?: return
    val savedConnectionPassword = profileSnapshot.connectionPassword
    val savedPeer = profileSnapshot.peer
    val savedWorkers = profileSnapshot.workersPerHash
    val savedManualPortsEnabled = profileSnapshot.manualPortsEnabled
    val savedServerDtlsPort = profileSnapshot.serverDtlsPort
    val savedServerWgPort = profileSnapshot.serverWgPort
    val savedListenPort = profileSnapshot.listenPort
    val savedSni = profileSnapshot.sni
    val vpnDnsSettings = VpnDnsSettingsSnapshot(
        profileIndex = profileSnapshot.profileIndex,
        selectionId = profileSnapshot.vpnDnsSelectionId,
        customServers = profileSnapshot.vpnDnsCustomServers,
    )
    val savedCaptchaMode = profileSnapshot.captchaMode
    val savedCaptchaMethod = profileSnapshot.captchaSolveMethod
    val activeProfile = profileSnapshot.profileIndex
    val profileNames = profileSnapshot.profileNames
    val wdttLinkMode = profileSnapshot.linkMode
    val wdttLink = profileSnapshot.link
    val savedConnectionInputMethod = profileSnapshot.connectionInputMethod
    val savedVkHashesState = profileSnapshot.vkHashes
    val activeFingerprint = profileSnapshot.fingerprint
    val activeClientIds = profileSnapshot.clientIds
    val customVkCredentialsEnabled = profileSnapshot.customVkCredentialsEnabled
    val customVkClientId = profileSnapshot.customVkClientId
    val customVkClientSecret = profileSnapshot.customVkClientSecret
    val vkCallsPreflight = profileSnapshot.vkCallsPreflight
    val rtNetwork = profileSnapshot.rtNetwork
    val rtMasque = profileSnapshot.rtMasque
    val rtMasqueServerBootstrap = profileSnapshot.rtMasqueServerBootstrap
    val rtMasqueServerAccess = profileSnapshot.rtMasqueServerAccessStatus
    val effectiveRtMasqueServerBootstrap =
        rtMasqueServerBootstrap && rtMasqueServerAccess.available
    val savedRtTurnSni = profileSnapshot.rtTurnSni
    val remoteActionKey = profileSnapshot.remoteActionKey
    val remoteActionUrl = profileSnapshot.remoteActionUrl
    val remoteManagedProfile = profileSnapshot.remoteManaged
    val interfaceRole = if (remoteManagedProfile) "user" else profileSnapshot.interfaceRole
    val cachedRemoteAction = profileSnapshot.cachedRemoteAction
    val remoteCardDismissed = profileSnapshot.remoteCardDismissed
    val profileMaxWorkers = profileSnapshot.profileMaxWorkers

    LaunchedEffect(
        activeProfile,
        rtMasqueServerBootstrap,
        rtMasqueServerAccess.available,
    ) {
        if (rtMasqueServerBootstrap && !rtMasqueServerAccess.available) {
            settingsStore.saveRtMasqueServerBootstrap(false)
        }
    }

    val compactTunnelInterface = usesCompactTunnelInterface(interfaceRole)

    val tunnelRunning by TunnelManager.running.collectAsStateWithLifecycle()
    val activeWorkers by TunnelManager.activeWorkers.collectAsStateWithLifecycle()
    val warpResetBlockedMessage = "Для сброса отключите VPN"
    val tunnelTransition by TunnelManager.transition.collectAsStateWithLifecycle()
    val trustedWifiState by TrustedWifiManager.state.collectAsStateWithLifecycle()
    val trustedWifiWaiting = trustedWifiState.waiting
    val underlyingNetworkAvailable = rememberUnderlyingNetworkAvailable()
    val connectionIssue by TunnelManager.connectionIssue.collectAsStateWithLifecycle()
    val standaloneConnectionIssue =
        connectionIssue?.takeIf { it.isStandaloneUiIssue }

    val cooldownActive by TunnelManager.cooldownActive.collectAsStateWithLifecycle()

    val loadedHashSlots = remember(activeProfile, savedVkHashesState) {
        parseVkHashSlots(savedVkHashesState)
    }
    var peerInput by remember(activeProfile, savedPeer) { mutableStateOf(savedPeer) }
    var vkHash1 by remember(activeProfile, savedVkHashesState) {
        mutableStateOf(loadedHashSlots.getOrElse(0) { "" })
    }
    var vkHash2 by remember(activeProfile, savedVkHashesState) {
        mutableStateOf(loadedHashSlots.getOrElse(1) { "" })
    }
    var vkHash3 by remember(activeProfile, savedVkHashesState) {
        mutableStateOf(loadedHashSlots.getOrElse(2) { "" })
    }
    var vkHash4 by remember(activeProfile, savedVkHashesState) {
        mutableStateOf(loadedHashSlots.getOrElse(3) { "" })
    }
    val loadedWorkers = remember(
        activeProfile,
        savedWorkers,
        savedVkHashesState,
        profileMaxWorkers,
    ) {
        val normalized = normalizeTunnelWorkerCount(savedWorkers, profileMaxWorkers)
        roundToGroup(
            normalized.toFloat(),
            maxWorkersForHashSlots(loadedHashSlots, profileMaxWorkers)
        )
    }
    var workersInput by remember(activeProfile, loadedWorkers) {
        mutableFloatStateOf(loadedWorkers)
    }
    var showHashesDialog by rememberSaveable { mutableStateOf(false) }
    var profileRemoteAction by remember(activeProfile) {
        mutableStateOf(RemoteActionCatalogGateway.cached().at("profile"))
    }
    LaunchedEffect(showHashesDialog, activeProfile) {
        if (showHashesDialog) {
            profileRemoteAction = RemoteActionCatalogGateway.fetch().at("profile")
        }
    }
    var autoCaptchaEnabled by remember(activeProfile, savedCaptchaMode, savedCaptchaMethod) {
        mutableStateOf(savedCaptchaMode != "wv" || savedCaptchaMethod != "manual")
    }
    var manualPortsEnabled by remember(activeProfile, savedManualPortsEnabled) {
        mutableStateOf(savedManualPortsEnabled)
    }
    var showPowerHelp by rememberSaveable { mutableStateOf(false) }
    var showVkCallsHelp by rememberSaveable { mutableStateOf(false) }
    var showAutoCaptchaHelp by rememberSaveable { mutableStateOf(false) }
    var showRtNetworkSettings by rememberSaveable { mutableStateOf(false) }
    var showRtNetworkHelp by rememberSaveable { mutableStateOf(false) }
    var showRtMasqueHelp by rememberSaveable { mutableStateOf(false) }
    var showRtMasqueServerBootstrapHelp by rememberSaveable { mutableStateOf(false) }
    var showRtMasqueConsent by rememberSaveable { mutableStateOf(false) }
    var showRtMasqueResetConfirm by rememberSaveable { mutableStateOf(false) }
    var showVpnDnsSettings by rememberSaveable { mutableStateOf(false) }
    var showLaunchParameters by rememberSaveable { mutableStateOf(false) }
    var serverDtlsPortInput by remember(activeProfile, savedServerDtlsPort) {
        mutableStateOf(savedServerDtlsPort.toString())
    }
    var serverWgPortInput by remember(activeProfile, savedServerWgPort) {
        mutableStateOf(savedServerWgPort.toString())
    }
    var userConnectionEditor by remember(activeProfile) { mutableStateOf("") }
    var userLinkInput by remember(activeProfile) { mutableStateOf("") }
    val storedLinkSelected = remember(activeProfile, savedConnectionInputMethod, wdttLinkMode) {
        wdttLinkMode && WdttDeepLink.parse(wdttLink, allowMissingHashes = true) != null
    }
    var userConnectionMethod by remember(
        activeProfile,
        savedConnectionInputMethod,
        wdttLinkMode,
        wdttLink,
        savedPeer,
        savedConnectionPassword,
        interfaceRole,
    ) {
        mutableStateOf(
            resolveConnectionInputMethod(
                savedMethod = savedConnectionInputMethod,
                hasStoredLink = storedLinkSelected,
                hasManualConnection = savedPeer.isNotBlank() && savedConnectionPassword.isNotBlank(),
                userInterface = compactTunnelInterface,
            )
        )
    }

    val allHashes = remember(vkHash1, vkHash2, vkHash3, vkHash4) {
        listOf(vkHash1, vkHash2, vkHash3, vkHash4).map { stripVkUrlStatic(it) }
    }
    val validHashes = remember(allHashes) { allHashes.filter(VkJoinLink::isValidHash) }
    val uniqueHashes = remember(validHashes) { validHashes.distinct() }
    val wdttLinkValidation = remember(wdttLink) { WdttDeepLink.validate(wdttLink) }
    val parsedWdttLink = remember(wdttLinkValidation) { wdttLinkValidation.parts }
    val parsedLinkHashes = remember(parsedWdttLink) { parsedWdttLink?.hashes?.split(",")?.filter { it.isNotBlank() } ?: emptyList() }
    val filledHashCount = remember(vkHash1, vkHash2, vkHash3, vkHash4, wdttLinkMode, parsedLinkHashes) { 
        if (wdttLinkMode) parsedLinkHashes.size else validHashes.size
    }
    val combinedHashes = remember(vkHash1, vkHash2, vkHash3, vkHash4) { uniqueHashes.joinToString(",") }
    val hashSlotsForStorage = remember(vkHash1, vkHash2, vkHash3, vkHash4) {
        encodeVkHashSlots(vkHash1, vkHash2, vkHash3, vkHash4)
    }
    val dynamicMaxWorkers = remember(filledHashCount, profileMaxWorkers) {
        maxWorkersForHashCount(filledHashCount, profileMaxWorkers)
    }
    var portInput by remember(activeProfile, savedListenPort) {
        mutableStateOf(savedListenPort.toString())
    }
    var sniInput by remember(activeProfile, savedSni) { mutableStateOf(savedSni) }
    var rtTurnSniInput by remember(activeProfile, savedRtTurnSni) {
        mutableStateOf(savedRtTurnSni)
    }

    val currentWorkers = workersInput.coerceIn(WORKERS_PER_GROUP.toFloat(), dynamicMaxWorkers)
    val launchParametersSummary = remember(
        currentWorkers,
        vpnDnsSettings,
        vkCallsPreflight,
        autoCaptchaEnabled,
        rtNetwork,
        rtMasque,
    ) {
        tunnelLaunchParametersSummary(
            workers = currentWorkers.toInt(),
            dnsSettings = vpnDnsSettings,
            vkCallsPreflight = vkCallsPreflight,
            autoCaptchaEnabled = autoCaptchaEnabled,
            rtNetwork = rtNetwork,
            rtMasque = rtMasque,
        )
    }

    val hashErrors = remember(vkHash1, vkHash2, vkHash3, vkHash4) {
        buildList {
            allHashes.forEachIndexed { i, h ->
                if (h.isNotBlank() && !VkJoinLink.isValidHash(h)) {
                    add("Хеш ${i + 1} имеет неверный формат")
                }
            }
            val filled = allHashes.filter(VkJoinLink::isValidHash)
            if (filled.size != filled.distinct().size) add("Есть дубликаты хешей")
        }
    }
    val hasInputHashErrors = remember(vkHash1, vkHash2, vkHash3, vkHash4) { hashErrors.isNotEmpty() }

    var showSecretsDialog by rememberSaveable { mutableStateOf(false) }

    LaunchedEffect(activeProfile, savedWorkers, profileMaxWorkers) {
        val normalizedWorkers = normalizeTunnelWorkerCount(savedWorkers, profileMaxWorkers)
        if (normalizedWorkers != savedWorkers) {
            settingsStore.saveWorkersPerHash(normalizedWorkers)
        }
    }

    var saveJob by remember { mutableStateOf<Job?>(null) }

    fun saveTunnelSettingsNow(
        hashes: String = hashSlotsForStorage,
        workers: Float = workersInput,
        onSaved: (() -> Unit)? = null
    ) {
        saveJob?.cancel()
        scope.launch {
            val normalizedWorkers = normalizeTunnelWorkerCount(workers.toInt(), profileMaxWorkers)
            val savedLocalPort = if (manualPortsEnabled) portInput.toIntOrNull()?.coerceIn(1, 65535) ?: 9000 else 9000
            settingsStore.save(
                peerInput, hashes, "",
                normalizedWorkers, "udp", savedLocalPort, sniInput, false
            )
            onVkHashesSaved(
                activeProfile,
                parseVkHashSlots(hashes).filter { it.isNotBlank() },
            )
            onSaved?.invoke()
        }
    }

    fun saveWorkersNow(workers: Float) {
        scope.launch {
            settingsStore.saveWorkersPerHash(
                normalizeTunnelWorkerCount(workers.toInt(), profileMaxWorkers)
            )
        }
    }

    fun scheduleSave() {
        saveJob?.cancel()
        saveJob = scope.launch {
            val normalizedWorkers = normalizeTunnelWorkerCount(workersInput.toInt(), profileMaxWorkers)
            delay(300)
            val savedLocalPort = if (manualPortsEnabled) portInput.toIntOrNull()?.coerceIn(1, 65535) ?: 9000 else 9000
            settingsStore.save(
                peerInput, hashSlotsForStorage, "",
                normalizedWorkers, "udp", savedLocalPort, sniInput, false
            )
        }
    }

    val scrollState = rememberRememberedScrollState(scrollPosition)

    val isPeerValid = isValidTunnelHost(peerInput)
    val isHashesValid = combinedHashes.isNotBlank()
    val isLinkValid = wdttLinkValidation.canStartVpn
    val isManualValid = isPeerValid && isHashesValid && savedConnectionPassword.isNotBlank() && !hasInputHashErrors
    val linkConnectionPresent = remember(wdttLink) {
        WdttDeepLink.parse(wdttLink, allowMissingHashes = true) != null
    }
    val selectedCompactMethodValid = isSelectedCompactConnectionReady(
        selectedMethod = userConnectionMethod,
        savedMethod = savedConnectionInputMethod,
        storedLinkMode = wdttLinkMode,
        linkPresent = linkConnectionPresent,
        linkValid = isLinkValid,
        manualValid = isManualValid,
    )
    val rtSniValid = !rtNetwork || normalizeRtTurnSni(rtTurnSniInput) != null
    val isValid = selectedCompactMethodValid && rtSniValid
    val hasConnectionSource = hasTunnelConnectionSource(
        linkMode = wdttLinkMode,
        linkValid = linkConnectionPresent,
        peer = peerInput,
        password = savedConnectionPassword,
    )
    val showManualConnectionFields = false
    val effectiveServerDtlsPort = if (manualPortsEnabled) serverDtlsPortInput.toIntOrNull()?.coerceIn(1, 65535) ?: 56000 else 56000
    val effectiveLocalPort = if (manualPortsEnabled) portInput.toIntOrNull()?.coerceIn(1, 65535) ?: 9000 else 9000
    var pendingStartAfterVpnPermission by remember { mutableStateOf(false) }

    fun startTunnelService() {
        val effectiveCaptchaMode = if (autoCaptchaEnabled) "auto" else "wv"
        val effectiveCaptchaSolveMethod = if (autoCaptchaEnabled) "auto" else "manual"
        val normalizedWorkers = normalizeTunnelWorkerCount(workersInput.toInt(), profileMaxWorkers)
        saveJob?.cancel()
        scope.launch {
            settingsStore.save(
                peerInput, hashSlotsForStorage, "",
                normalizedWorkers, "udp", effectiveLocalPort, sniInput, false
            )
            settingsStore.saveCaptchaMode(effectiveCaptchaMode)
            settingsStore.saveCaptchaSolveMethod(effectiveCaptchaSolveMethod)
        }

        var finalPeer = "$peerInput:$effectiveServerDtlsPort"
        var finalHashes = combinedHashes
        var finalLocalPort = effectiveLocalPort
        var finalPassword = savedConnectionPassword

        if (wdttLinkMode) {
            if (parsedWdttLink != null) {
                finalPeer = "${parsedWdttLink.host}:${parsedWdttLink.dtlsPort}"
                finalLocalPort = parsedWdttLink.localPort
                finalPassword = parsedWdttLink.password
                finalHashes = parsedWdttLink.hashes
            }
        }

        val intent = Intent(context, TunnelService::class.java).apply {
            action = "START"
            putExtra("peer", finalPeer)
            putExtra("vk_hashes", finalHashes)
            putExtra("secondary_vk_hash", "")
            putExtra("workers_per_hash", normalizedWorkers)
            putExtra("port", finalLocalPort)
            putExtra("sni", sniInput)
            putExtra("connection_password", finalPassword)
            putExtra("vkcalls_preflight", vkCallsPreflight)
            putExtra("rt_network", rtNetwork)
            putExtra("rt_masque", rtMasque)
            putExtra("rt_masque_server_bootstrap", effectiveRtMasqueServerBootstrap)
            putExtra("rt_turn_sni", rtTurnSniInput)
            putExtra("captcha_mode", effectiveCaptchaMode)
            putExtra("captcha_solve_method", effectiveCaptchaSolveMethod)
            putExtra("fingerprint", activeFingerprint)
            putExtra("client_ids", activeClientIds)
            putExtra("custom_vk_credentials_enabled", customVkCredentialsEnabled)
            putExtra("custom_vk_client_id", customVkClientId)
            putExtra("custom_vk_client_secret", customVkClientSecret)
            putExtra("profile_max_workers", profileMaxWorkers)
            putExtra(
                MANAGED_CONFIG_FIRST_START_EXTRA,
                shouldUseManagedConfigFirstStart(
                    remoteManaged = remoteManagedProfile,
                    profileMaxWorkers = profileMaxWorkers,
                ),
            )
            putExtra(TUNNEL_PROFILE_INDEX_EXTRA, activeProfile)
        }
        if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(intent)
        else context.startService(intent)
    }

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) {
        if (pendingStartAfterVpnPermission) {
            pendingStartAfterVpnPermission = false
            if (VpnService.prepare(context) == null) {
                TunnelManager.clearConnectionIssue()
                startTunnelService()
            } else {
                TunnelManager.reportConnectionIssue(
                    "VPN-разрешение не выдано",
                    "Разрешите WDTT Plus создать VPN-подключение в системном окне Android и нажмите «Подключить» ещё раз."
                )
                TunnelManager.clearTransition()
                Toast.makeText(context, "VPN-разрешение не выдано", Toast.LENGTH_SHORT).show()
            }
        }
    }

    fun requestVpnAndStart() {
        val vpnIntent = VpnService.prepare(context)
        if (vpnIntent != null) {
            pendingStartAfterVpnPermission = true
            vpnPermissionLauncher.launch(vpnIntent)
        } else {
            TunnelManager.clearConnectionIssue()
            startTunnelService()
        }
    }

    fun checkAccessAndStart() {
        TunnelManager.noteStartRequested()
        scope.launch {
            try {
                when (
                    val decision = AccessLifecycleCoordinator.prepareStart(
                        context,
                        activeProfile,
                    )
                ) {
                    AccessStartDecision.Allowed -> requestVpnAndStart()
                    is AccessStartDecision.Denied -> {
                        TunnelManager.clearConnectionIssue(ConnectionIssueKind.ACCESS)
                        TunnelManager.clearTransition()
                    }
                }
            } catch (cancelled: CancellationException) {
                TunnelManager.clearTransition()
                throw cancelled
            } catch (error: Exception) {
                TunnelManager.clearTransition()
                TunnelManager.reportConnectionIssue(
                    if (remoteManagedProfile) {
                        "Не удалось проверить доступ"
                    } else {
                        "Не удалось начать подключение"
                    },
                    error.message ?: "Проверьте интернет и повторите попытку.",
                )
            }
        }
    }

    fun openHashesSettings() {
        if (!wdttLinkMode) {
            showHashesDialog = true
            return
        }
        scope.launch {
            val parts = settingsStore.materializeActiveLinkProfile()
            if (parts == null) {
                Toast.makeText(
                    context,
                    "Не удалось подготовить профиль. Получите или добавьте ссылку подключения заново.",
                    Toast.LENGTH_LONG
                ).show()
                return@launch
            }
            val slots = parseVkHashSlots(parts.hashes)
            vkHash1 = slots.getOrElse(0) { "" }
            vkHash2 = slots.getOrElse(1) { "" }
            vkHash3 = slots.getOrElse(2) { "" }
            vkHash4 = slots.getOrElse(3) { "" }
            userConnectionEditor = ""
            showHashesDialog = true
        }
    }

    fun openUserLinkEditor() {
        userConnectionMethod = "link"
        userLinkInput = if (wdttLinkMode) wdttLink else ""
        userConnectionEditor = "link"
    }

    fun openRemoteUpdateEditor() {
        userLinkInput = ""
        userConnectionEditor = "remote-update"
    }

    fun openUserManualEditor() {
        userConnectionMethod = "manual"
        scope.launch {
            if (wdttLinkMode && linkConnectionPresent) {
                val materialized = settingsStore.materializeActiveLinkProfile()
                if (materialized == null) {
                    Toast.makeText(
                        context,
                        "Не удалось подготовить ссылку для ручного изменения.",
                        Toast.LENGTH_LONG
                    ).show()
                    return@launch
                }
            } else if (wdttLinkMode) {
                settingsStore.saveWdttLinkMode(false)
                settingsStore.saveWdttLink("")
            }
            userLinkInput = ""
            userConnectionEditor = "manual"
        }
    }

    fun saveUserWdttLink() {
        val cleanLink = userLinkInput.filterNot(Char::isWhitespace)
        val remoteDocument = RemoteDocumentGateway.extractLink(cleanLink)
        if (remoteManagedProfile && remoteDocument == null) {
            Toast.makeText(
                context,
                "Вставьте короткую HTTPS-ссылку обновления для этого профиля.",
                Toast.LENGTH_LONG
            ).show()
            return
        }
        if (remoteDocument != null) {
            val opened = runCatching {
                context.startActivity(
                    Intent(context, MainActivity::class.java)
                        .setAction(Intent.ACTION_VIEW)
                        .setData(Uri.parse(remoteDocument.url))
                        .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
                )
            }.isSuccess
            if (opened) {
                userLinkInput = ""
                userConnectionEditor = ""
            } else {
                Toast.makeText(
                    context,
                    "Не удалось открыть ссылку обновления.",
                    Toast.LENGTH_LONG
                ).show()
            }
            return
        }
        if (WdttDeepLink.parse(cleanLink, allowMissingHashes = true) == null) return
        scope.launch {
            val managedAccess = withContext(Dispatchers.IO) {
                settingsStore.accessLifecycleForProfile(activeProfile).managed
            }
            val result = settingsStore.applyWdttDeepLink(
                plan = WdttDeepLinkApplyPlan(
                    link = cleanLink,
                    targetProfile = activeProfile,
                    requiresConfirmation = hasConnectionSource,
                    storeAsLink = false
                ),
                resetRemoteContinuation = !managedAccess,
                remoteManaged = false
            )
            if (result == null) {
                Toast.makeText(context, "Ссылка WDTT не распознана.", Toast.LENGTH_LONG).show()
            } else {
                userConnectionMethod = "link"
                userLinkInput = ""
                userConnectionEditor = ""
                Toast.makeText(context, "Подключение сохранено", Toast.LENGTH_SHORT).show()
            }
        }
    }

    // ═══ Dialogs ═══
    if (userConnectionEditor == "link" || userConnectionEditor == "remote-update") {
        UserWdttLinkDialog(
            linkText = userLinkInput,
            onLinkTextChange = { userLinkInput = it.filterNot(Char::isWhitespace) },
            onPaste = {
                val clipboard = context.getSystemService(ClipboardManager::class.java)
                val pasted = clipboard
                    ?.primaryClip
                    ?.takeIf { it.itemCount > 0 }
                    ?.getItemAt(0)
                    ?.coerceToText(context)
                    ?.toString()
                    .orEmpty()
                    .filterNot(Char::isWhitespace)
                if (pasted.isBlank()) {
                    Toast.makeText(context, "В буфере обмена нет ссылки", Toast.LENGTH_SHORT).show()
                } else {
                    userLinkInput = pasted
                }
            },
            onSave = ::saveUserWdttLink,
            allowMissingHashes = true,
            remoteUpdateOnly = userConnectionEditor == "remote-update" || remoteManagedProfile,
            cachedAction = cachedRemoteAction,
            onCachedAction = {
                val clipboard = context.getSystemService(ClipboardManager::class.java)
                clipboard?.setPrimaryClip(
                    ClipData.newPlainText(
                        cachedRemoteAction.clipboardLabel.ifBlank { "WDTT Plus" },
                        cachedRemoteAction.payload,
                    )
                )
                val opened = runCatching {
                    launchRemoteTarget(context, cachedRemoteAction.target)
                }.isSuccess
                Toast.makeText(
                    context,
                    if (opened) {
                        cachedRemoteAction.copiedMessage.ifBlank {
                            "Данные скопированы. Продолжите в открывшемся приложении."
                        }
                    } else {
                        cachedRemoteAction.failedMessage.ifBlank {
                            "Данные скопированы, но страницу не удалось открыть."
                        }
                    },
                    Toast.LENGTH_LONG,
                ).show()
            },
            title = if (userConnectionEditor == "remote-update" || remoteManagedProfile) {
                "Обновить маршрут"
            } else if (compactTunnelInterface) {
                "Добавить ссылку WDTT"
            } else {
                "Ссылка WDTT"
            },
            subtitle = if (userConnectionEditor == "remote-update" || remoteManagedProfile) {
                ""
            } else if (compactTunnelInterface) {
                "Ссылку может бесплатно выдать владелец любого совместимого сервера."
            } else {
                "Вставьте ссылку подключения для текущего профиля."
            },
            onDismiss = {
                userLinkInput = ""
                userConnectionEditor = ""
            }
        )
    }

    if (userConnectionEditor == "manual" && !remoteManagedProfile) {
        UserManualConnectionDialog(
            initialPeer = peerInput,
            initialPassword = savedConnectionPassword,
            initialManualPortsEnabled = manualPortsEnabled,
            initialServerDtlsPort = serverDtlsPortInput,
            initialServerWgPort = serverWgPortInput,
            initialLocalPort = portInput,
            portsHint = if (compactTunnelInterface) {
                "Включите, только если владелец сервера выдал другие порты."
            } else {
                "Включите, если сервер настроен на другие порты."
            },
            onSave = { draft ->
                scope.launch {
                    settingsStore.saveManualTunnelConnection(
                        peer = draft.peer,
                        password = draft.password,
                        manualPortsEnabled = draft.manualPortsEnabled,
                        serverDtlsPort = draft.serverDtlsPort,
                        serverWgPort = draft.serverWgPort,
                        listenPort = draft.localPort,
                    )
                    peerInput = draft.peer
                    manualPortsEnabled = draft.manualPortsEnabled
                    serverDtlsPortInput = draft.serverDtlsPort.toString()
                    serverWgPortInput = draft.serverWgPort.toString()
                    portInput = draft.localPort.toString()
                    userConnectionEditor = ""
                    Toast.makeText(context, "Подключение сохранено", Toast.LENGTH_SHORT).show()
                }
            },
            onDismiss = { userConnectionEditor = "" }
        )
    }

    if (showSecretsDialog) {
        SecretsDialog(
            settingsStore = settingsStore,
            title = if (compactTunnelInterface) "Пароль и порты" else "Секреты",
            passwordLabel = if (compactTunnelInterface) {
                "Пароль подключения"
            } else {
                "Пароль туннеля"
            },
            passwordPlaceholder = if (compactTunnelInterface) {
                "Введите пароль, выданный владельцем сервера"
            } else {
                "Введите пароль туннеля"
            },
            allowPortsSelection = compactTunnelInterface,
            initialPassword = savedConnectionPassword,
            manualPortsEnabled = manualPortsEnabled,
            initialServerDtlsPort = serverDtlsPortInput,
            initialServerWgPort = serverWgPortInput,
            initialLocalPort = portInput,
            onSaved = { dtls, wg, local ->
                serverDtlsPortInput = dtls
                serverWgPortInput = wg
                portInput = local
            },
            onDismiss = { showSecretsDialog = false }
        )
    }

    if (showHashesDialog) {
        val activeAccessSnapshot by
            settingsStore.activeTunnelAccessUiSnapshot.collectAsStateWithLifecycle()
        val accessLifecycle = activeAccessSnapshot
            ?.takeIf { it.profileIndex == activeProfile }
            ?.lifecycle
            ?: AccessLifecycleUiState.Unmanaged
        val hashCheckCaptchaMode = if (autoCaptchaEnabled) "auto" else "wv"
        HashesDialog(
            settingsStore = settingsStore,
            profileIndex = activeProfile,
            hash1 = vkHash1,
            hash2 = vkHash2,
            hash3 = vkHash3,
            hash4 = vkHash4,
            activeFingerprint = activeFingerprint,
            activeClientIds = activeClientIds,
            customVkCredentialsEnabled = customVkCredentialsEnabled,
            customVkClientId = customVkClientId,
            customVkClientSecret = customVkClientSecret,
            remoteContinuation = RemoteContinuation(
                available = boundContinuationAvailable(
                    hasCredential = remoteActionKey.isNotBlank(),
                    hasEndpoint = remoteActionUrl.isNotBlank(),
                    remoteAvailability = accessLifecycle.continuationAvailable,
                    expiresAtSeconds = accessLifecycle.continuationExpiresAtSeconds,
                ),
                key = remoteActionKey,
                url = remoteActionUrl
            ),
            remoteAccessLifecycle = accessLifecycle,
            remoteAction = profileRemoteAction,
            vkCallsPreflight = vkCallsPreflight,
            captchaMode = hashCheckCaptchaMode,
            selectedWebViewManual = !autoCaptchaEnabled,
            onOpenProjectSupport = onOpenProjectSupport,
            onSave = { h1, h2, h3, h4 ->
                val cleaned1 = stripVkUrlStatic(h1)
                val cleaned2 = stripVkUrlStatic(h2)
                val cleaned3 = stripVkUrlStatic(h3)
                val cleaned4 = stripVkUrlStatic(h4)
                vkHash1 = cleaned1
                vkHash2 = cleaned2
                vkHash3 = cleaned3
                vkHash4 = cleaned4
                val maxWorkers = maxWorkersForHashSlots(
                    listOf(cleaned1, cleaned2, cleaned3, cleaned4),
                    profileMaxWorkers
                )
                val savedWorkers = if (workersInput > maxWorkers) {
                    roundToGroup(workersInput, maxWorkers).also { workersInput = it }
                } else {
                    workersInput
                }
                saveTunnelSettingsNow(
                    hashes = encodeVkHashSlots(cleaned1, cleaned2, cleaned3, cleaned4),
                    workers = savedWorkers
                ) {
                    showHashesDialog = false
                }
            },
            onDismiss = { showHashesDialog = false }
        )
    }

    if (showLaunchParameters) {
        TunnelLaunchParametersDialog(
            vpnDnsSettings = vpnDnsSettings,
            onOpenDnsSettings = { showVpnDnsSettings = true },
            currentWorkers = currentWorkers,
            dynamicMaxWorkers = dynamicMaxWorkers,
            profileMaxWorkers = profileMaxWorkers,
            tunnelRunning = tunnelRunning,
            vkCallsPreflight = vkCallsPreflight,
            autoCaptchaEnabled = autoCaptchaEnabled,
            rtNetwork = rtNetwork,
            onWorkersChange = { selected ->
                workersInput = roundToGroup(selected, dynamicMaxWorkers)
            },
            onWorkersChangeFinished = { selected ->
                saveWorkersNow(roundToGroup(selected, dynamicMaxWorkers))
            },
            onPowerHelp = { showPowerHelp = true },
            onVkCallsHelp = { showVkCallsHelp = true },
            onVkCallsChange = { enabled ->
                scope.launch { settingsStore.saveVkCallsPreflight(enabled) }
            },
            onAutoCaptchaHelp = { showAutoCaptchaHelp = true },
            onAutoCaptchaChange = { enabled ->
                autoCaptchaEnabled = enabled
                scope.launch { settingsStore.saveCaptchaPreference(enabled) }
            },
            onRtNetworkSettings = { showRtNetworkSettings = true },
            onRtNetworkHelp = { showRtNetworkHelp = true },
            onRtNetworkChange = { enabled ->
                saveJob?.cancel()
                val nextSni = if (enabled) {
                    normalizeRtTurnSni(rtTurnSniInput) ?: DEFAULT_RT_TURN_SNI
                } else {
                    rtTurnSniInput.trim()
                }
                rtTurnSniInput = nextSni
                scope.launch { settingsStore.saveRtNetwork(enabled, nextSni) }
                if (enabled) showRtNetworkSettings = true
            },
            onDismiss = { showLaunchParameters = false },
        )
    }

    if (showVpnDnsSettings) {
        VpnDnsSettingsDialog(
            initialSettings = vpnDnsSettings,
            onApply = { selectionId, customServers ->
                scope.launch {
                    runCatching {
                        settingsStore.saveVpnDnsSettings(
                            selectionId = selectionId,
                            customServersRaw = customServers,
                            profileIndex = activeProfile,
                        )
                    }.onSuccess { saved ->
                        showVpnDnsSettings = false
                        TunnelManager.noteVpnDnsEvent(
                            key = "settings_${saved.profileIndex}_${saved.selectionId}",
                            message = buildString {
                                append("Для профиля «")
                                append(vpnProfileDisplayName(saved.profileIndex, profileNames))
                                append("» выбран режим DNS «")
                                append(saved.title)
                                append("».")
                                if (
                                    tunnelRunning &&
                                    TunnelManager.activeTunnelProfile.value == saved.profileIndex
                                ) {
                                    append(" Обновляем системный VPN-интерфейс.")
                                } else {
                                    append(" Настройка применится при следующем подключении этого профиля.")
                                }
                            },
                            warning = false,
                        )
                        TunnelManager.scheduleWireGuardReload(saved.profileIndex)
                    }.onFailure { error ->
                        Toast.makeText(
                            context,
                            error.message ?: "Не удалось сохранить DNS.",
                            Toast.LENGTH_LONG,
                        ).show()
                    }
                }
            },
            onDismiss = { showVpnDnsSettings = false },
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Column {
            TunnelRemoteActionSection(
                settingsStore = settingsStore,
                activeProfile = activeProfile,
                interfaceRole = interfaceRole,
                hasConnectionSource = hasConnectionSource,
                dismissed = remoteCardDismissed,
                onOpenProjectSupport = onOpenProjectSupport,
            )

            Text(
                "Настройки туннеля (${vpnProfileDisplayName(activeProfile, profileNames)})",
                style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                color = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.padding(bottom = 12.dp)
            )

            ManagedAccessLifecycleSection(
                settingsStore = settingsStore,
                activeProfile = activeProfile,
                routeUpdateAvailable = remoteManagedProfile,
                onRouteUpdate = ::openRemoteUpdateEditor,
            )

            if (!remoteManagedProfile) {
                CompactTunnelProfileCard(
                    hasConnection = hasConnectionSource,
                    connectionMethod = userConnectionMethod,
                    savedConnectionMethod = savedConnectionInputMethod,
                    onConnectionMethodChange = { method ->
                        userConnectionMethod = method
                        userLinkInput = ""
                        userConnectionEditor = ""
                    },
                    onAddLinkClick = ::openUserLinkEditor,
                    onManualClick = ::openUserManualEditor,
                )
                Spacer(Modifier.height(8.dp))
            }
            AppSectionCard(
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 10.dp),
                verticalArrangement = Arrangement.spacedBy(0.dp)
            ) {
                OutlinedButton(
                    onClick = ::openHashesSettings,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                    shape = RoundedCornerShape(16.dp),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp)
                ) {
                    Icon(Icons.Default.Tag, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    FlexibleButtonText(
                        "Настройка VK Хешей ($filledHashCount/4)",
                        fontWeight = FontWeight.SemiBold
                    )
                }
            }

            if (showManualConnectionFields) {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    // ═══ Настройки туннеля ═══
                    AppSectionCard(
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        OutlinedTextField(
                            value = peerInput,
                            onValueChange = {
                                peerInput = it.filter { c -> !c.isWhitespace() }
                                scheduleSave()
                            },
                            label = { Text("IP сервера или домен (без порта)") },
                            placeholder = { Text("1.2.3.4 (или test.com)") },
                            singleLine = true,
                            isError = !isPeerValid && peerInput.isNotEmpty(),
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(16.dp),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = MaterialTheme.colorScheme.primary,
                                unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f),
                            )
                        )

                        OutlinedButton(
                            onClick = ::openHashesSettings,
                            modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp),
                            shape = RoundedCornerShape(16.dp),
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp),
                            colors = ButtonDefaults.outlinedButtonColors(
                                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                                contentColor = MaterialTheme.colorScheme.onSurface
                            ),
                            border = BorderStroke(
                                1.dp,
                                if (hasInputHashErrors) MaterialTheme.colorScheme.error
                                else MaterialTheme.colorScheme.outline.copy(alpha = 0.5f)
                            )
                        ) {
                            Icon(Icons.Default.Tag, null, Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            FlexibleButtonText("Настройка VK Хешей ($filledHashCount/4)", fontWeight = FontWeight.SemiBold)
                        }

                        val errorTexts = hashErrors.filter { !it.contains("короткий") }
                        if (errorTexts.isNotEmpty()) {
                            Text(
                                text = errorTexts.joinToString(", "),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error
                            )
                        }

                    }
                }
            }

            Spacer(Modifier.height(8.dp))

            AppSectionCard(
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedButton(
                    onClick = { showLaunchParameters = true },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                    shape = RoundedCornerShape(16.dp),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp)
                ) {
                    FlexibleButtonText("Параметры", fontWeight = FontWeight.SemiBold)
                }
                Text(
                    text = launchParametersSummary,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    lineHeight = 17.sp
                )
            }

        // ═══ Кнопки: Секреты + Подключить ═══
        val tunnelSecretsMissing = savedConnectionPassword.isBlank()

        Column(
            modifier = Modifier.fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            if (showManualConnectionFields) {
                OutlinedButton(
                    onClick = { showSecretsDialog = true },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp),
                    shape = RoundedCornerShape(16.dp),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 8.dp),
                    colors = ButtonDefaults.outlinedButtonColors(
                        containerColor = if (tunnelSecretsMissing) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.surface,
                        contentColor = if (tunnelSecretsMissing) MaterialTheme.colorScheme.onErrorContainer else MaterialTheme.colorScheme.onSurface
                    ),
                    border = BorderStroke(
                        1.dp,
                        if (tunnelSecretsMissing) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.outline.copy(alpha = 0.5f)
                    )
                ) {
                    Icon(imageVector = Icons.Default.Key, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    FlexibleButtonText(
                        if (compactTunnelInterface) "Пароль и порты" else "Секреты",
                        fontWeight = FontWeight.SemiBold
                    )
                }
            }

            AnimatedTunnelPowerButton(
                running = tunnelRunning,
                waiting = trustedWifiWaiting,
                transition = tunnelTransition,
                activeWorkers = activeWorkers,
                targetWorkers = currentWorkers.toInt(),
                cooldownActive = cooldownActive,
                underlyingNetworkAvailable = underlyingNetworkAvailable,
                connectionErrorTitle = standaloneConnectionIssue
                    ?.takeIf { it.isError }
                    ?.title,
                enabled = tunnelTransition == TunnelTransition.IDLE &&
                    ((isValid && !cooldownActive) || tunnelRunning || trustedWifiWaiting),
                onClick = {
                    if (tunnelTransition != TunnelTransition.IDLE) return@AnimatedTunnelPowerButton
                    if (tunnelRunning || trustedWifiWaiting) {
                        TunnelManager.noteStopRequested()
                        context.startService(
                            Intent(context, TunnelService::class.java).apply { action = "STOP" }
                        )
                    } else {
                        TunnelManager.clearConnectionIssue()
                        checkAccessAndStart()
                    }
                },
            )
        }

        if (trustedWifiWaiting) {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                color = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.72f),
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.secondary.copy(alpha = 0.35f))
            ) {
                Column(
                    modifier = Modifier.fillMaxWidth().padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(5.dp)
                ) {
                    Text(
                        "Ожидание доверенной сети",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSecondaryContainer
                    )
                    Text(
                        trustedWifiState.status.ifBlank {
                            "VPN выключен в сети «${trustedWifiState.ssid}» и восстановится после выхода из неё."
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSecondaryContainer
                    )
                }
            }
        }

        standaloneConnectionIssue?.let { issue ->
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                color = if (issue.isError) {
                    MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.72f)
                } else {
                    MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f)
                },
                border = BorderStroke(
                    1.dp,
                    if (issue.isError) MaterialTheme.colorScheme.error.copy(alpha = 0.35f)
                    else MaterialTheme.colorScheme.outline.copy(alpha = 0.25f)
                )
            ) {
                Column(
                    modifier = Modifier.fillMaxWidth().padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(5.dp)
                ) {
                    Text(
                        text = issue.title,
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold,
                        color = if (issue.isError) MaterialTheme.colorScheme.onErrorContainer else MaterialTheme.colorScheme.onSurface
                    )
                    Text(
                        text = issue.action,
                        style = MaterialTheme.typography.bodySmall,
                        color = if (issue.isError) MaterialTheme.colorScheme.onErrorContainer else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
    }

    if (showRtNetworkSettings) {
        RtNetworkSettingsDialog(
            rtNetwork = rtNetwork,
            turnSni = rtTurnSniInput,
            turnSniValid = normalizeRtTurnSni(rtTurnSniInput) != null,
            rtMasque = rtMasque,
            rtMasqueServerBootstrap = effectiveRtMasqueServerBootstrap,
            serverAccess = rtMasqueServerAccess,
            tunnelRunning = tunnelRunning,
            onTurnSniChange = { value ->
                val nextSni = value.filterNot(Char::isWhitespace).take(253)
                rtTurnSniInput = nextSni
                saveJob?.cancel()
                saveJob = scope.launch {
                    delay(300)
                    settingsStore.saveRtNetwork(enabled = true, turnSni = nextSni)
                }
            },
            onRtMasqueChange = { enabled ->
                if (enabled) {
                    showRtMasqueConsent = true
                } else {
                    scope.launch { settingsStore.saveRtMasque(false) }
                }
            },
            onServerBootstrapChange = { enabled ->
                scope.launch { settingsStore.saveRtMasqueServerBootstrap(enabled) }
            },
            onShowRtHelp = { showRtNetworkHelp = true },
            onShowMasqueHelp = { showRtMasqueHelp = true },
            onShowServerHelp = { showRtMasqueServerBootstrapHelp = true },
            onDismiss = { showRtNetworkSettings = false },
        )
    }
    if (showPowerHelp) {
        PowerHelpDialog(
            minWorkers = WORKERS_PER_GROUP,
            maxWorkers = dynamicMaxWorkers.toInt(),
            currentWorkers = currentWorkers.toInt(),
            profileMaxWorkers = profileMaxWorkers,
            onDismiss = { showPowerHelp = false }
        )
    }
    if (showVkCallsHelp) {
        SettingsHelpDialog(
            title = "Быстрый VKCalls",
            paragraphs = listOf(
                "Первым приложение пробует современный анонимный путь VKCalls через системный VK Connect. Ему не нужны ваш Client ID, Client secret или VK Smart Captcha — обычно это самый быстрый и стабильный вариант.",
                "Если VKCalls временно недоступен, приложение автоматически пробует собственные legacy-реквизиты (если они включены), затем выбранные встроенные legacy Client ID. В legacy-ветке полностью сохраняется авторешение капчи.",
                "Переключатель отключает только первый быстрый провайдер. Для обычной работы рекомендуется оставить VKCalls включённым."
            ),
            onDismiss = { showVkCallsHelp = false }
        )
    }
    if (showAutoCaptchaHelp) {
        SettingsHelpDialog(
            title = "Режим капчи",
            paragraphs = listOf(
                "Эта настройка применяется только к резервным legacy-провайдерам: основной быстрый VKCalls обычно получает TURN-данные без капчи.",
                "Авто капча: каждый свежий challenge сначала решается через Auto WebView. Go v2 и ручной WebView используются как запасные этапы, если автоматический WebView не дал рабочий токен или VK потребовал более строгую проверку.",
                "Всегда вручную: если legacy-провайдер получил капчу, приложение сразу открывает WebView для самостоятельного прохождения проверки."
            ),
            onDismiss = { showAutoCaptchaHelp = false }
        )
    }
    if (showRtNetworkHelp) {
        SettingsHelpDialog(
            title = "Сеть РТ",
            paragraphs = listOf(
                "Режим предназначен для мобильной сети Ростелекома с белыми списками: разрешённые сайты открываются, но обычный WDTT Plus не подключается. В сети РТ без таких ограничений, у других операторов и по обычному Wi‑Fi он, как правило, не нужен.",
                "При включении порядок меняется только для этого профиля: TURN/TLS с указанным SNI → TURN/TCP ко всем адресам, полученным от VK, с разделением первого STUN-запроса → MASQUE HTTP/2 и HTTP/3, если он включён → TURN/UDP как последний резерв. При выключенном режиме сохраняется обычный порядок с приоритетом UDP.",
                "SNI по умолчанию — ya.ru; его можно заменить доступным доменом из белого списка. Это только имя во внешнем TLS-рукопожатии TURN/TLS и MASQUE: трафик не становится трафиком этого сайта, а TURN/TCP и TURN/UDP вообще не содержат SNI.",
                "Для TURN/TLS приложение продолжает проверять публичную цепочку сертификата, но при подмене SNI не сопоставляет имя сертификата с доменом белого списка. MASQUE проверяет конечную точку по публичному ключу из регистрации WARP. Пароль подключения и шифрование WRAP не меняются.",
                "Оператор может одновременно учитывать SNI, IP, порт и протокол, поэтому один SNI не гарантирует результат. TURN/TLS/TCP и MASQUE используют разные адреса и механизмы: рабочий вариант определяется только проверкой в конкретном регионе и тарифе.",
                "TLS и TCP обычно дают большую задержку и хуже переносят потери, а MASQUE дополнительно расходует батарею и трафик. Если обычный режим работает, оставьте «Сеть РТ» выключенной.",
                "После заблокированной UDP-попытки сеть иногда несколько минут плохо пропускает DNS или другой трафик. Перед повторной проверкой остановите VPN, дождитесь восстановления сайтов или переподключите мобильную сеть, затем запускайте режим заново."
            ),
            highlightedParagraphIndices = setOf(6),
            onDismiss = { showRtNetworkHelp = false }
        )
    }
    if (showRtMasqueHelp) {
        SettingsHelpDialog(
            title = "MASQUE в сети РТ",
            paragraphs = listOf(
                "Экспериментальный резерв только внутри «Сети РТ». После прямых TURN/TLS и TURN/TCP приложение пробует WARP CONNECT-IP с SNI из поля настроек; TURN/UDP остаётся последним аварийным путём.",
                "Сначала проверяется HTTP/2 по TCP/443, затем HTTP/3 по QUIC/443. Успешный вариант совместно используется воркерами до остановки VPN; при новом запуске проверка выполняется заново, потому что доступность путей могла измениться.",
                "Для первого запуска приложение регистрирует отдельное устройство Cloudflare WARP. Корректная регистрация хранится только в приватном каталоге WDTT Plus и повторно используется после перезапуска приложения и выключения рубильников — заново создавать её при каждом подключении не требуется.",
                "Регистрация сначала выполняется через системную сеть и DNS Android с проверкой сертификата Cloudflare. Если прямой TLS не проходит до отправки данных и включён «Через сервер», последняя попытка регистрации идёт по SSH через сервер активного профиля. Обычный MASQUE-трафик через этот сервер не направляется.",
                "Cloudflare обрабатывает внешний туннель и может видеть служебные метаданные и адреса назначения. Конечная точка MASQUE проверяется по публичному ключу сохранённой регистрации WARP, а шифрование WRAP между приложением и вашим WDTT-сервером сохраняется.",
                "Режим может увеличить первый запуск, задержку, расход батареи и трафика и не гарантирует обход блокировки IP, TCP/443 или QUIC/443. Он активен только при одновременно включённых «Сеть РТ» и MASQUE; остальные режимы не меняются.",
                "Сбрасывайте регистрацию WARP только при сообщении о повреждённых или отклонённых данных. Сброс удаляет локальные ключи, и следующему запуску снова понадобится регистрация; обычную сетевую блокировку это не исправляет."
            ),
            onDismiss = { showRtMasqueHelp = false },
            secondaryActionLabel = "Сбросить регистрацию WARP",
            secondaryActionEnabled = !tunnelRunning,
            onSecondaryActionDisabled = {
                Toast.makeText(context, warpResetBlockedMessage, Toast.LENGTH_LONG).show()
            },
            onSecondaryAction = {
                if (tunnelRunning) {
                    Toast.makeText(context, warpResetBlockedMessage, Toast.LENGTH_LONG).show()
                } else {
                    showRtMasqueHelp = false
                    showRtMasqueResetConfirm = true
                }
            },
        )
    }
    if (showRtMasqueServerBootstrapHelp) {
        SettingsHelpDialog(
            title = "Регистрация через сервер",
            paragraphs = listOf(
                "Помогает выполнить первоначальную регистрацию WARP, если Android не может напрямую установить TLS-соединение с API Cloudflare. Режим работает лишь вместе с «Сеть РТ» и MASQUE; обычный трафик WDTT, TURN и последующие соединения MASQUE через сервер не проходят.",
                "Рубильник доступен, если в активном профиле раздела «Деплой» указан адрес сервера и выбран рабочий вход по SSH: пароль либо корректный приватный ключ. Если данных не хватает, рядом с выключенным рубильником указана точная причина.",
                "Вероятнее всего, нужен иностранный сервер за пределами РФ — российский сервер может встретить те же ограничения доступа к Cloudflare.",
                "SSH-сервер должен быть доступен из текущей сети и разрешать TCP-переадресацию.",
                "На сервер ничего не устанавливается. WDTT Plus временно использует стандартную SSH-переадресацию только для HTTPS-запросов регистрации; сертификат Cloudflare проверяется сквозным TLS. Cloudflare видит IP сервера, а владелец сервера — факт соединения и объём, но не содержимое HTTPS.",
                "Сначала приложение всё равно пробует прямые безопасные HTTPS-пути. К SSH оно переходит только при сбое до отправки регистрационных данных, поэтому запрос не дублируется небезопасным образом. Ошибка SSH записывается в журнал, а незавершённая регистрация не сохраняется.",
                "После успешной регистрации SSH-выход закрывается, а данные WARP сохраняются в приватном хранилище. Пока сохранённая регистрация корректна, приложение не создаёт новую и рубильник фактически не используется — даже после перезапуска или временного выключения «Сети РТ» и MASQUE."
            ),
            highlightedParagraphIndices = setOf(2),
            onDismiss = { showRtMasqueServerBootstrapHelp = false },
        )
    }
    if (showRtMasqueConsent) {
        val linkColor = MaterialTheme.colorScheme.primary
        val cloudflareTerms = buildAnnotatedString {
            append("Включая механизм, вы соглашаетесь с ")
            withLink(
                LinkAnnotation.Url(
                    url = "https://www.cloudflare.com/application/terms/",
                    styles = TextLinkStyles(
                        style = SpanStyle(
                            color = linkColor,
                            fontWeight = FontWeight.SemiBold,
                            textDecoration = TextDecoration.Underline,
                        ),
                    ),
                ),
            ) {
                append("условиями Cloudflare")
            }
            append(" и разрешаете WDTT Plus зарегистрировать отдельное устройство WARP.")
        }
        AlertDialog(
            onDismissRequest = { showRtMasqueConsent = false },
            title = { Text("Включить MASQUE?") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("Это внешний экспериментальный транспорт. Cloudflare будет обрабатывать туннель и сможет видеть метаданные подключений. При первом запуске VPN приложение в фоне зарегистрирует отдельное устройство WARP; для этого может потребоваться обычный интернет.")
                    Text(cloudflareTerms)
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        showRtMasqueConsent = false
                        scope.launch { settingsStore.saveRtMasque(true) }
                    },
                ) { Text("Согласен, включить") }
            },
            dismissButton = {
                TextButton(onClick = { showRtMasqueConsent = false }) {
                    Text("Отмена")
                }
            },
        )
    }
    if (showRtMasqueResetConfirm) {
        AlertDialog(
            onDismissRequest = { showRtMasqueResetConfirm = false },
            title = { Text("Сбросить регистрацию WARP?") },
            text = {
                Text(
                    "Будут удалены только локальные ключи и токен WARP. При следующем запуске VPN с включённым MASQUE приложение зарегистрирует новое устройство. Используйте это при сообщении о повреждённой или отклонённой конфигурации; обычную блокировку HTTP/2 или HTTP/3 такой сброс не исправляет."
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        if (TunnelManager.running.value) {
                            showRtMasqueResetConfirm = false
                            Toast.makeText(context, warpResetBlockedMessage, Toast.LENGTH_LONG).show()
                            return@TextButton
                        }
                        showRtMasqueResetConfirm = false
                        scope.launch {
                            val result = withContext(Dispatchers.IO) {
                                val config = File(context.filesDir, RT_MASQUE_CONFIG_FILE_NAME)
                                when {
                                    !config.exists() -> "Регистрация WARP ещё не создана"
                                    config.delete() -> "Локальная регистрация WARP сброшена"
                                    else -> "Не удалось удалить регистрацию WARP"
                                }
                            }
                            Toast.makeText(context, result, Toast.LENGTH_LONG).show()
                        }
                    },
                ) { Text("Сбросить") }
            },
            dismissButton = {
                TextButton(onClick = { showRtMasqueResetConfirm = false }) {
                    Text("Отмена")
                }
            },
        )
    }
}

@Composable
private fun TunnelRemoteActionSection(
    settingsStore: SettingsStore,
    activeProfile: Int,
    interfaceRole: String,
    hasConnectionSource: Boolean,
    dismissed: Boolean,
    onOpenProjectSupport: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val lifecycleOwner = LocalLifecycleOwner.current
    val fetchAllowed =
        usesCompactTunnelInterface(interfaceRole) ||
            interfaceRole == "admin" ||
            BuildConfig.REMOTE_ACTION_PREVIEW
    var actionCatalog by remember { mutableStateOf(RemoteActionCatalogGateway.cached()) }
    var actionResolved by remember {
        mutableStateOf(RemoteActionCatalogGateway.hasFreshCache())
    }
    var dismissCountdown by remember(activeProfile) { mutableIntStateOf(0) }

    LaunchedEffect(fetchAllowed, lifecycleOwner) {
        if (!fetchAllowed) {
            actionCatalog = com.wdtt.plus.RemoteActionCatalog.Empty
            actionResolved = true
            return@LaunchedEffect
        }
        if (RemoteActionCatalogGateway.hasFreshCache()) {
            actionCatalog = RemoteActionCatalogGateway.cached()
            actionResolved = true
        } else {
            actionResolved = false
        }
        lifecycleOwner.lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            while (isActive) {
                actionCatalog = RemoteActionCatalogGateway.fetch(force = true)
                actionResolved = true
                delay(REMOTE_ACTION_REFRESH_MS)
            }
        }
    }
    LaunchedEffect(activeProfile, dismissCountdown > 0) {
        if (dismissCountdown <= 0) return@LaunchedEffect
        while (dismissCountdown > 0) {
            delay(1_000)
            dismissCountdown--
        }
    }

    val action = actionCatalog.at("tunnel")
    if (!shouldShowTunnelRemoteActionCard(
            interfaceRole = interfaceRole,
            preview = BuildConfig.REMOTE_ACTION_PREVIEW,
            hasConnectionSource = hasConnectionSource,
            dismissed = dismissed,
            dismissCountdown = dismissCountdown,
            actionResolved = actionResolved,
            actionAvailable = action != null,
        )
    ) {
        return
    }
    if (dismissCountdown > 0) {
        DismissedNoticeCard(
            title = "Предложение скрыто",
            message = "Ссылку всегда можно найти в «Инфо» → «Поддержать проект».",
            countdown = dismissCountdown,
            onProjectSupportClick = onOpenProjectSupport,
        )
    } else if (action != null) {
        RemoteActionCard(
            action = action,
            onLinkClick = onOpenProjectSupport,
            onClick = {
                scope.launch {
                    val opened = RemoteUiActionLauncher.open(context, action)
                    if (!opened) {
                        Toast.makeText(
                            context,
                            "Не удалось открыть страницу. Проверьте браузер.",
                            Toast.LENGTH_LONG,
                        ).show()
                    }
                }
            },
            onDismiss = {
                dismissCountdown = 5
                scope.launch {
                    settingsStore.saveRemoteCardDismissed(activeProfile, true)
                }
            },
        )
    }
    Spacer(Modifier.height(12.dp))
}

@Composable
private fun ManagedAccessLifecycleSection(
    settingsStore: SettingsStore,
    activeProfile: Int,
    routeUpdateAvailable: Boolean,
    onRouteUpdate: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val activeAccessSnapshot by
        settingsStore.activeTunnelAccessUiSnapshot.collectAsStateWithLifecycle()
    val lifecycle = activeAccessSnapshot
        ?.takeIf { it.profileIndex == activeProfile }
        ?.lifecycle
        ?: AccessLifecycleUiState.Unmanaged
    val dismissedSignature = activeAccessSnapshot
        ?.takeIf { it.profileIndex == activeProfile }
        ?.dismissedSignature
        .orEmpty()
    val refreshingProfiles by
        AccessLifecycleCoordinator.refreshingProfiles.collectAsStateWithLifecycle()
    val refreshing = activeProfile in refreshingProfiles
    var actionBusy by remember(activeProfile) { mutableStateOf(false) }
    var manualRefreshBusy by remember(activeProfile) { mutableStateOf(false) }
    var dismissCountdown by remember(activeProfile) { mutableIntStateOf(0) }

    LaunchedEffect(activeProfile, lifecycle.managed) {
        if (lifecycle.managed) {
            AccessLifecycleCoordinator.refreshProfile(context, activeProfile, force = false)
        } else {
            TunnelManager.clearConnectionIssue(ConnectionIssueKind.ACCESS)
        }
    }
    LaunchedEffect(activeProfile, dismissCountdown > 0) {
        if (dismissCountdown <= 0) return@LaunchedEffect
        while (dismissCountdown > 0) {
            delay(1_000)
            dismissCountdown--
        }
    }

    if (!lifecycle.managed) return
    val canDismiss = accessLifecycleCanDismiss(lifecycle)
    val signature = accessLifecycleDismissalSignature(lifecycle)
    val dismissed = canDismiss && signature.isNotBlank() && signature == dismissedSignature
    val keepVisibleForRouteUpdate = routeUpdateAvailable && lifecycle.dismissible != true
    val cardDismissed =
        dismissed && dismissCountdown <= 0 && !keepVisibleForRouteUpdate
    if (cardDismissed) return

    if (dismissCountdown > 0 && !keepVisibleForRouteUpdate) {
        DismissedNoticeCard(
            title = "Карточка скрыта",
            message = lifecycle.dismissedMessage.ifBlank {
                "Актуальная информация и доступные действия остаются у поставщика профиля."
            },
            countdown = dismissCountdown,
        )
    } else {
        AccessLifecycleCard(
            lifecycle = lifecycle,
            refreshing = refreshing || manualRefreshBusy,
            actionBusy = actionBusy,
            onRouteUpdate = if (routeUpdateAvailable) onRouteUpdate else null,
            onDismiss = if (canDismiss) {
                {
                    dismissCountdown = 5
                    scope.launch {
                        settingsStore.saveAccessLifecycleDismissedSignature(
                            activeProfile,
                            signature,
                        )
                    }
                }
            } else {
                null
            },
            onRefresh = {
                if (manualRefreshBusy) return@AccessLifecycleCard
                manualRefreshBusy = true
                scope.launch {
                    val startedAt = System.currentTimeMillis()
                    try {
                        when (
                            val result = AccessLifecycleCoordinator.refreshProfile(
                                context,
                                activeProfile,
                                force = true,
                            )
                        ) {
                            is AccessLifecycleRefreshResult.Success -> Toast.makeText(
                                context,
                                "Данные обновлены",
                                Toast.LENGTH_SHORT,
                            ).show()
                            is AccessLifecycleRefreshResult.Cached -> Toast.makeText(
                                context,
                                "Данные уже актуальны",
                                Toast.LENGTH_SHORT,
                            ).show()
                            is AccessLifecycleRefreshResult.Throttled -> Toast.makeText(
                                context,
                                "Проверено недавно. Повторите через несколько секунд",
                                Toast.LENGTH_SHORT,
                            ).show()
                            is AccessLifecycleRefreshResult.Failed -> Toast.makeText(
                                context,
                                result.message,
                                Toast.LENGTH_LONG,
                            ).show()
                            AccessLifecycleRefreshResult.Unmanaged -> Toast.makeText(
                                context,
                                "Проверка недоступна",
                                Toast.LENGTH_SHORT,
                            ).show()
                        }
                    } finally {
                        val visibleFor = System.currentTimeMillis() - startedAt
                        if (visibleFor < 450) delay(450 - visibleFor)
                        manualRefreshBusy = false
                    }
                }
            },
            onAction = {
                if (actionBusy) return@AccessLifecycleCard
                actionBusy = true
                scope.launch {
                    runCatching {
                        AccessLifecycleCoordinator.beginAction(context, activeProfile)
                    }.onSuccess { target ->
                        runCatching {
                            launchRemoteTarget(context, target)
                        }.onFailure { error ->
                            if (error is CancellationException) throw error
                            Toast.makeText(
                                context,
                                error.message ?: "Не удалось открыть страницу.",
                                Toast.LENGTH_LONG,
                            ).show()
                        }
                    }.onFailure { error ->
                        if (error is CancellationException) throw error
                        TunnelManager.noteAccessLifecycleEvent(
                            key = "action_unavailable_$activeProfile",
                            message = error.message ?: "Действие сейчас недоступно",
                            warning = true,
                        )
                        Toast.makeText(
                            context,
                            error.message ?: "Действие сейчас недоступно.",
                            Toast.LENGTH_LONG,
                        ).show()
                    }
                    actionBusy = false
                }
            },
        )
    }
    Spacer(Modifier.height(12.dp))
}

@Composable
private fun AccessLifecycleCard(
    lifecycle: AccessLifecycleUiState,
    refreshing: Boolean,
    actionBusy: Boolean,
    onRouteUpdate: (() -> Unit)?,
    onDismiss: (() -> Unit)?,
    onRefresh: () -> Unit,
    onAction: () -> Unit,
) {
    val severity = lifecycle.severity
    val accent = when {
        severity == AccessLifecycleSeverity.ERROR -> MaterialTheme.colorScheme.error
        severity == AccessLifecycleSeverity.WARNING -> MaterialTheme.colorScheme.tertiary
        else -> MaterialTheme.colorScheme.primary
    }
    val container = when {
        severity == AccessLifecycleSeverity.ERROR ->
            MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.68f)
        severity == AccessLifecycleSeverity.WARNING ->
            MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.62f)
        else -> MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.52f)
    }
    val icon = when {
        lifecycle.checkedAtMillis <= 0 -> Icons.Default.Schedule
        !lifecycle.allowConnect -> Icons.Default.Lock
        severity == AccessLifecycleSeverity.WARNING ||
            severity == AccessLifecycleSeverity.ERROR -> Icons.Default.WarningAmber
        else -> Icons.Default.CheckCircle
    }
    val title = lifecycle.title.ifBlank {
        if (lifecycle.checkedAtMillis <= 0) {
            "Проверяем профиль"
        } else {
            lifecycle.fallbackTitle()
        }
    }

    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        color = container,
        border = BorderStroke(1.dp, accent.copy(alpha = 0.36f)),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = accent,
                    modifier = Modifier.size(23.dp),
                )
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.weight(1f),
                )
                if (onRouteUpdate != null) {
                    IconButton(
                        onClick = onRouteUpdate,
                        enabled = !actionBusy,
                        modifier = Modifier.size(36.dp),
                    ) {
                        Icon(
                            Icons.Default.WarningAmber,
                            contentDescription = "Обновить маршрут",
                            tint = accent,
                            modifier = Modifier.size(20.dp),
                        )
                    }
                }
                IconButton(
                    onClick = onRefresh,
                    enabled = !refreshing && !actionBusy,
                    modifier = Modifier.size(36.dp),
                ) {
                    if (refreshing) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(19.dp),
                            strokeWidth = 2.dp,
                            color = accent,
                        )
                    } else {
                        Icon(
                            Icons.Default.Refresh,
                            contentDescription = "Проверить профиль",
                            tint = accent,
                            modifier = Modifier.size(20.dp),
                        )
                    }
                }
                if (onDismiss != null) {
                    CardDismissButton(
                        contentDescription = "Скрыть напоминание",
                        onClick = onDismiss,
                    )
                }
            }
            if (lifecycle.message.isNotBlank()) {
                Text(
                    text = lifecycle.message,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (lifecycle.actionMessage.isNotBlank() && !lifecycle.actionAvailable) {
                Text(
                    text = lifecycle.actionMessage,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (lifecycle.detailValue.isNotBlank() || lifecycle.actionAvailable) {
                val actionLabel = lifecycle.actionLabel.ifBlank { "Продолжить" }
                val textMeasurer = rememberTextMeasurer()
                val density = LocalDensity.current
                val detailLabelWidth = with(density) {
                    textMeasurer.measure(
                        text = lifecycle.detailLabel,
                        style = MaterialTheme.typography.bodySmall,
                        maxLines = 1,
                        softWrap = false,
                    ).size.width.toDp()
                }
                val detailValueWidth = with(density) {
                    textMeasurer.measure(
                        text = lifecycle.detailValue,
                        style = MaterialTheme.typography.bodyMedium.copy(
                            fontWeight = FontWeight.SemiBold,
                        ),
                        maxLines = 1,
                        softWrap = false,
                    ).size.width.toDp()
                }
                val actionLabelWidth = with(density) {
                    textMeasurer.measure(
                        text = actionLabel,
                        style = MaterialTheme.typography.labelLarge.copy(
                            fontWeight = FontWeight.SemiBold,
                        ),
                        maxLines = 1,
                        softWrap = false,
                    ).size.width.toDp()
                }

                BoxWithConstraints(modifier = Modifier.fillMaxWidth()) {
                    val hasDetail = lifecycle.detailValue.isNotBlank()
                    val hasAction = lifecycle.actionAvailable
                    val detailPreferredWidth = maxOf(
                        120.dp,
                        detailLabelWidth,
                        detailValueWidth,
                    )
                    val actionPreferredWidth = maxOf(
                        132.dp,
                        actionLabelWidth + 46.dp,
                    )
                    val stackContent = hasAction && (
                        !hasDetail ||
                            detailPreferredWidth + 12.dp + actionPreferredWidth > maxWidth
                        )

                    if (stackContent) {
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            verticalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            if (hasDetail) {
                                AccessLifecycleDetail(
                                    lifecycle = lifecycle,
                                    accent = accent,
                                    modifier = Modifier.fillMaxWidth(),
                                )
                            }
                            AccessLifecycleActionButton(
                                lifecycle = lifecycle,
                                label = actionLabel,
                                refreshing = refreshing,
                                actionBusy = actionBusy,
                                onAction = onAction,
                                modifier = Modifier.fillMaxWidth(),
                            )
                        }
                    } else {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            if (hasDetail) {
                                AccessLifecycleDetail(
                                    lifecycle = lifecycle,
                                    accent = accent,
                                    modifier = Modifier.weight(1f),
                                )
                            }
                            if (hasAction) {
                                AccessLifecycleActionButton(
                                    lifecycle = lifecycle,
                                    label = actionLabel,
                                    refreshing = refreshing,
                                    actionBusy = actionBusy,
                                    onAction = onAction,
                                    modifier = Modifier.width(actionPreferredWidth),
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun AccessLifecycleDetail(
    lifecycle: AccessLifecycleUiState,
    accent: Color,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier,
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        if (lifecycle.detailLabel.isNotBlank()) {
            Text(
                text = lifecycle.detailLabel,
                style = MaterialTheme.typography.bodySmall,
                color = accent.copy(alpha = 0.78f),
            )
        }
        Text(
            text = lifecycle.detailValue,
            style = MaterialTheme.typography.bodyMedium,
            color = accent,
            fontWeight = FontWeight.SemiBold,
        )
    }
}

@Composable
private fun AccessLifecycleActionButton(
    lifecycle: AccessLifecycleUiState,
    label: String,
    refreshing: Boolean,
    actionBusy: Boolean,
    onAction: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Button(
        onClick = onAction,
        enabled = !refreshing && !actionBusy,
        modifier = modifier.heightIn(min = 46.dp),
        shape = RoundedCornerShape(14.dp),
        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 6.dp),
    ) {
        if (actionBusy) {
            CircularProgressIndicator(
                modifier = Modifier.size(17.dp),
                strokeWidth = 2.dp,
                color = MaterialTheme.colorScheme.onPrimary,
            )
        } else {
            Icon(
                imageVector = if (lifecycle.actionIcon == "update") {
                    Icons.Default.Update
                } else {
                    Icons.Default.Link
                },
                contentDescription = null,
                modifier = Modifier.size(17.dp),
            )
            Spacer(Modifier.width(5.dp))
            FlexibleButtonText(label)
        }
    }
}

private fun tunnelLaunchParametersSummary(
    workers: Int,
    dnsSettings: VpnDnsSettingsSnapshot,
    vkCallsPreflight: Boolean,
    autoCaptchaEnabled: Boolean,
    rtNetwork: Boolean,
    rtMasque: Boolean,
): String {
    val rtText = when {
        rtNetwork && rtMasque -> "РТ + MASQUE"
        rtNetwork -> "РТ вкл"
        else -> "РТ выкл"
    }
    return buildList {
        add("$workers потоков")
        add("DNS: ${dnsSettings.title}")
        add(if (vkCallsPreflight) "VKCalls вкл" else "VKCalls выкл")
        add(if (autoCaptchaEnabled) "Капча авто" else "Капча вручную")
        add(rtText)
    }.joinToString(" · ")
}

@Composable
private fun TunnelLaunchParametersDialog(
    vpnDnsSettings: VpnDnsSettingsSnapshot,
    onOpenDnsSettings: () -> Unit,
    currentWorkers: Float,
    dynamicMaxWorkers: Float,
    profileMaxWorkers: Int,
    tunnelRunning: Boolean,
    vkCallsPreflight: Boolean,
    autoCaptchaEnabled: Boolean,
    rtNetwork: Boolean,
    onWorkersChange: (Float) -> Unit,
    onWorkersChangeFinished: (Float) -> Unit,
    onPowerHelp: () -> Unit,
    onVkCallsHelp: () -> Unit,
    onVkCallsChange: (Boolean) -> Unit,
    onAutoCaptchaHelp: () -> Unit,
    onAutoCaptchaChange: (Boolean) -> Unit,
    onRtNetworkSettings: () -> Unit,
    onRtNetworkHelp: () -> Unit,
    onRtNetworkChange: (Boolean) -> Unit,
    onDismiss: () -> Unit,
) {
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        BoxWithConstraints(
            modifier = Modifier.fillMaxSize().padding(8.dp),
            contentAlignment = Alignment.Center,
        ) {
            Surface(
                modifier = Modifier
                    .fillMaxWidth(0.95f)
                    .heightIn(max = maxHeight * 0.92f),
                shape = RoundedCornerShape(24.dp),
                color = MaterialTheme.colorScheme.surface,
                contentColor = MaterialTheme.colorScheme.onSurface,
                tonalElevation = 8.dp,
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            "Параметры",
                            modifier = Modifier.weight(1f),
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary,
                        )
                        IconButton(onClick = onDismiss) {
                            Icon(Icons.Default.Close, contentDescription = "Закрыть")
                        }
                    }

                    Column(
                        modifier = Modifier
                            .weight(1f, fill = false)
                            .verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        Text(
                            "Изменения сохраняются сразу и будут использованы при следующем запуске VPN.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )

                        VpnDnsSettingsCard(
                            settings = vpnDnsSettings,
                            onClick = onOpenDnsSettings,
                        )

                        AppSectionCard(
                            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 14.dp),
                            verticalArrangement = Arrangement.spacedBy(0.dp),
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                                ) {
                                    Text(
                                        "Мощность",
                                        style = MaterialTheme.typography.titleMedium,
                                        color = MaterialTheme.colorScheme.primary,
                                        fontWeight = FontWeight.SemiBold,
                                    )
                                    IconButton(
                                        onClick = onPowerHelp,
                                        modifier = Modifier.size(28.dp),
                                    ) {
                                        Icon(
                                            Icons.AutoMirrored.Filled.HelpOutline,
                                            contentDescription = "Что такое мощность",
                                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                            modifier = Modifier.size(18.dp),
                                        )
                                    }
                                }
                                Text(
                                    text = "${currentWorkers.toInt()}",
                                    style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                                    color = MaterialTheme.colorScheme.primary,
                                )
                            }

                            Spacer(Modifier.height(2.dp))

                            val minWorkers = WORKERS_PER_GROUP.toFloat()
                            val currentWorkersVal = roundToGroup(
                                currentWorkers.coerceIn(minWorkers, dynamicMaxWorkers),
                                dynamicMaxWorkers,
                            )

                            CompactSteppedSlider(
                                value = currentWorkersVal,
                                onValueChange = onWorkersChange,
                                onValueChangeFinished = onWorkersChangeFinished,
                                valueRange = minWorkers..dynamicMaxWorkers,
                                stepSize = WORKERS_PER_GROUP.toFloat(),
                                enabled = !tunnelRunning && dynamicMaxWorkers > minWorkers,
                                modifier = Modifier.fillMaxWidth(),
                            )

                            if (profileMaxWorkers >= WORKERS_PER_GROUP) {
                                Text(
                                    text = "Для этого профиля доступен выбор от ${WORKERS_PER_GROUP.toInt()} до $profileMaxWorkers потоков. Повысить значение выше нельзя.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Spacer(Modifier.height(4.dp))
                            }

                            HorizontalDivider(
                                modifier = Modifier.padding(vertical = 2.dp),
                                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
                            )

                            LaunchParameterSwitchRow(
                                title = "Быстрый VKCalls",
                                checked = vkCallsPreflight,
                                enabled = !tunnelRunning,
                                onCheckedChange = onVkCallsChange,
                                onHelp = onVkCallsHelp,
                                helpDescription = "Как работает VKCalls",
                            )

                            HorizontalDivider(
                                modifier = Modifier.padding(vertical = 2.dp),
                                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
                            )

                            LaunchParameterSwitchRow(
                                title = if (autoCaptchaEnabled) "Авто капча" else "Всегда вручную",
                                checked = autoCaptchaEnabled,
                                enabled = true,
                                onCheckedChange = onAutoCaptchaChange,
                                onHelp = onAutoCaptchaHelp,
                                helpDescription = "Как работает режим капчи",
                            )

                            HorizontalDivider(
                                modifier = Modifier.padding(vertical = 2.dp),
                                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
                            )

                            LaunchParameterSwitchRow(
                                title = "Сеть РТ",
                                checked = rtNetwork,
                                enabled = !tunnelRunning,
                                onCheckedChange = onRtNetworkChange,
                                onHelp = onRtNetworkHelp,
                                helpDescription = "Как работает Сеть РТ",
                                onTitleClick = onRtNetworkSettings,
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun LaunchParameterSwitchRow(
    title: String,
    checked: Boolean,
    enabled: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    onHelp: () -> Unit,
    helpDescription: String,
    onTitleClick: (() -> Unit)? = null,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Row(
            modifier = Modifier.weight(1f),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(
                title,
                modifier = if (onTitleClick != null) {
                    Modifier.clickable(onClick = onTitleClick).padding(vertical = 10.dp)
                } else {
                    Modifier
                },
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium,
            )
            IconButton(
                onClick = onHelp,
                modifier = Modifier.size(28.dp),
            ) {
                Icon(
                    Icons.AutoMirrored.Filled.HelpOutline,
                    contentDescription = helpDescription,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(18.dp),
                )
            }
        }
        Switch(
            checked = checked,
            enabled = enabled,
            onCheckedChange = onCheckedChange,
        )
    }
}

@Composable
private fun AnimatedTunnelPowerButton(
    running: Boolean,
    waiting: Boolean,
    transition: TunnelTransition,
    activeWorkers: Int,
    targetWorkers: Int,
    cooldownActive: Boolean,
    underlyingNetworkAvailable: Boolean,
    connectionErrorTitle: String?,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    val primary = MaterialTheme.colorScheme.primary
    val onPrimary = MaterialTheme.colorScheme.onPrimary
    val outline = MaterialTheme.colorScheme.outline
    val error = MaterialTheme.colorScheme.error
    val isStarting = transition == TunnelTransition.STARTING
    val isStopping = transition == TunnelTransition.STOPPING
    val boundedTargetWorkers = targetWorkers.coerceAtLeast(0)
    val connectionVisible = running || waiting || isStarting || isStopping
    val statusState = tunnelPowerVisualState(
        running = running,
        waitingForTrustedWifi = waiting,
        starting = isStarting,
        stopping = isStopping,
        activeWorkers = activeWorkers,
        underlyingNetworkAvailable = underlyingNetworkAvailable,
        hasConnectionError = connectionErrorTitle != null,
        cooldownActive = cooldownActive,
    )
    val activeWorkerProgress by animateFloatAsState(
        targetValue = activeWorkers.coerceIn(0, boundedTargetWorkers).toFloat(),
        animationSpec = tween(durationMillis = 700),
        label = "tunnel_active_workers_progress",
    )
    val connectionAlpha by animateFloatAsState(
        targetValue = if (connectionVisible) 1f else 0f,
        animationSpec = tween(durationMillis = 350),
        label = "tunnel_connection_alpha",
    )
    // Импульсы запуска живут независимо от того, насколько быстро сменится
    // состояние туннеля: короткий STARTING не должен обрывать волну.
    val startBurst = remember { Animatable(1f) }
    val stopBurst = remember { Animatable(1f) }
    val fullWorkersBurst = remember { Animatable(1f) }
    val workerGrowthBurst = remember { Animatable(1f) }
    var fullWorkersBurstPlayed by remember { mutableStateOf(false) }
    var observedWorkerCount by remember { mutableIntStateOf(activeWorkers.coerceAtLeast(0)) }
    var startBurstRequest by remember { mutableIntStateOf(0) }
    var stopBurstRequest by remember { mutableIntStateOf(0) }
    var fullWorkersBurstRequest by remember { mutableIntStateOf(0) }
    var workerGrowthBurstRequest by remember { mutableIntStateOf(0) }
    LaunchedEffect(startBurstRequest) {
        if (startBurstRequest > 0) {
            startBurst.snapTo(0f)
            startBurst.animateTo(1f, animationSpec = tween(durationMillis = 2_800))
        }
    }
    LaunchedEffect(stopBurstRequest) {
        if (stopBurstRequest > 0) {
            stopBurst.snapTo(0f)
            stopBurst.animateTo(1f, animationSpec = tween(durationMillis = 2_800))
        }
    }
    LaunchedEffect(running, isStarting) {
        if (!running && !isStarting) {
            fullWorkersBurstPlayed = false
            fullWorkersBurst.snapTo(1f)
            workerGrowthBurst.snapTo(1f)
        }
    }
    // Небольшой импульс сообщает именно о появлении очередного рабочего
    // потока. При полной мощности остаётся отдельная, более заметная волна.
    LaunchedEffect(running, activeWorkers, boundedTargetWorkers) {
        val currentWorkers = activeWorkers.coerceIn(0, boundedTargetWorkers)
        if (
            running &&
            currentWorkers > observedWorkerCount &&
            currentWorkers < boundedTargetWorkers
        ) {
            workerGrowthBurstRequest++
        }
        observedWorkerCount = currentWorkers
    }
    LaunchedEffect(running, boundedTargetWorkers, activeWorkers) {
        if (
            running &&
            boundedTargetWorkers > 0 &&
            activeWorkers >= boundedTargetWorkers &&
            !fullWorkersBurstPlayed
        ) {
            fullWorkersBurstPlayed = true
            fullWorkersBurstRequest++
        }
    }
    LaunchedEffect(fullWorkersBurstRequest) {
        if (fullWorkersBurstRequest > 0) {
            fullWorkersBurst.snapTo(0f)
            fullWorkersBurst.animateTo(1f, animationSpec = tween(durationMillis = 3_000))
        }
    }
    LaunchedEffect(workerGrowthBurstRequest) {
        if (workerGrowthBurstRequest > 0) {
            workerGrowthBurst.snapTo(0f)
            workerGrowthBurst.animateTo(1f, animationSpec = tween(durationMillis = 1_650))
        }
    }
    val status = when (statusState) {
        TunnelPowerVisualState.Stopping -> TunnelPowerStatus("Отключение…", primary)
        TunnelPowerVisualState.Connecting -> TunnelPowerStatus(
            if (boundedTargetWorkers > 0) "Подключение… · 0/$boundedTargetWorkers потоков"
            else "Подключение…",
            primary,
        )
        TunnelPowerVisualState.Connected -> TunnelPowerStatus(
            if (boundedTargetWorkers > 0) {
                "Подключено · ${activeWorkers.coerceIn(0, boundedTargetWorkers)}/$boundedTargetWorkers потоков"
            } else {
                "Подключено"
            },
            primary,
        )
        TunnelPowerVisualState.NoNetwork -> TunnelPowerStatus("Нет сети", MaterialTheme.colorScheme.tertiary)
        TunnelPowerVisualState.WaitingForTrustedWifi -> TunnelPowerStatus(
            "Ожидание выхода из доверенной сети",
            MaterialTheme.colorScheme.secondary,
        )
        TunnelPowerVisualState.Error -> TunnelPowerStatus(connectionErrorTitle.orEmpty(), error)
        TunnelPowerVisualState.CoolingDown -> TunnelPowerStatus(
            "Подождите…",
            MaterialTheme.colorScheme.onSurfaceVariant,
        )
        TunnelPowerVisualState.Off -> TunnelPowerStatus(
            "Выключено",
            MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
    val enabledAlpha = if (enabled) 1f else 0.48f
    val centerColor = when (statusState) {
        TunnelPowerVisualState.Error -> error
        TunnelPowerVisualState.NoNetwork -> MaterialTheme.colorScheme.tertiary
        TunnelPowerVisualState.Stopping,
        TunnelPowerVisualState.WaitingForTrustedWifi -> MaterialTheme.colorScheme.secondary
        TunnelPowerVisualState.Connecting,
        TunnelPowerVisualState.Connected -> primary
        TunnelPowerVisualState.CoolingDown,
        TunnelPowerVisualState.Off -> primary.copy(alpha = 0.58f)
    }
    val icon = when (statusState) {
        TunnelPowerVisualState.Error,
        TunnelPowerVisualState.NoNetwork -> Icons.Default.WarningAmber
        TunnelPowerVisualState.WaitingForTrustedWifi -> Icons.Default.Schedule
        TunnelPowerVisualState.Stopping,
        TunnelPowerVisualState.Connected -> Icons.Default.Stop
        TunnelPowerVisualState.Connecting,
        TunnelPowerVisualState.CoolingDown,
        TunnelPowerVisualState.Off -> Icons.Default.PowerSettingsNew
    }

    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Box(
            modifier = Modifier
                .padding(top = 2.dp)
                .size(184.dp),
            contentAlignment = Alignment.Center,
        ) {
            Canvas(modifier = Modifier.matchParentSize()) {
                val center = Offset(size.width / 2f, size.height / 2f)
                val minSide = minOf(size.width, size.height)
                val buttonRadius = minSide * 0.25f
                // Ячейки почти касаются кнопки, но сохраняют тонкий "воздух"
                // между собой и центральным кругом.
                val segmentRadius = minSide * 0.315f

                fun drawPulse(
                    progress: Float,
                    color: Color,
                    strength: Float,
                    reverse: Boolean = false,
                ) {
                    repeat(3) { index ->
                        val delay = index * 0.17f
                        if (progress < delay) return@repeat
                        val localProgress = ((progress - delay) / (1f - delay)).coerceIn(0f, 1f)
                        val phase = if (reverse) 1f - localProgress else localProgress
                        if (phase > 0f) {
                            val maxRadius = minSide * 0.49f
                            val waveRadius = buttonRadius + 3.dp.toPx() +
                                phase * (maxRadius - buttonRadius - 3.dp.toPx())
                            // Цвет у источника плотнее, а с удалением от
                            // кнопки постепенно растворяется в прозрачности.
                            val fadeRadius = maxRadius
                            drawCircle(
                                brush = Brush.radialGradient(
                                    colorStops = arrayOf(
                                        0f to color.copy(alpha = strength * 0.44f * enabledAlpha),
                                        (buttonRadius / fadeRadius).coerceIn(0f, 1f) to
                                            color.copy(alpha = strength * 0.38f * enabledAlpha),
                                        0.82f to color.copy(alpha = strength * 0.11f * enabledAlpha),
                                        1f to Color.Transparent,
                                    ),
                                    center = center,
                                    radius = fadeRadius,
                                ),
                                radius = waveRadius,
                                center = center,
                                style = Stroke(width = (6f - phase * 2.4f).dp.toPx()),
                            )
                        }
                    }
                }
                if (startBurst.value < 1f) {
                    drawPulse(startBurst.value, primary, strength = 0.82f)
                }
                if (stopBurst.value < 1f) {
                    drawPulse(stopBurst.value, primary, strength = 0.70f, reverse = true)
                }
                if (fullWorkersBurst.value < 1f) {
                    drawPulse(fullWorkersBurst.value, primary, strength = 1f)
                }
                if (workerGrowthBurst.value < 1f) {
                    // Во время набора потоков волна заметна только вблизи
                    // кнопки и ячеек. Она не конкурирует с полной волной,
                    // которая проигрывается один раз при максимуме.
                    repeat(2) { index ->
                        val delay = index * 0.26f
                        if (workerGrowthBurst.value < delay) return@repeat
                        val phase = ((workerGrowthBurst.value - delay) / (1f - delay))
                            .coerceIn(0f, 1f)
                        val maxRadius = minSide * 0.385f
                        val waveRadius = buttonRadius + 3.dp.toPx() +
                            phase * (maxRadius - buttonRadius - 3.dp.toPx())
                        drawCircle(
                            brush = Brush.radialGradient(
                                colorStops = arrayOf(
                                    0f to primary.copy(alpha = 0.14f * enabledAlpha),
                                    (buttonRadius / maxRadius).coerceIn(0f, 1f) to
                                        primary.copy(alpha = 0.11f * enabledAlpha),
                                    0.78f to primary.copy(alpha = 0.035f * enabledAlpha),
                                    1f to Color.Transparent,
                                ),
                                center = center,
                                radius = maxRadius,
                            ),
                            radius = waveRadius,
                            center = center,
                            style = Stroke(width = (3.5f - phase * 1.6f).dp.toPx()),
                        )
                    }
                }

                val segmentCount = boundedTargetWorkers.coerceIn(1, 128)
                val step = 360f / segmentCount
                // Сегменты всегда делят всё кольцо: при малом числе потоков
                // каждый становится шире, а не оставляет вокруг себя пустоту.
                // Толщина уменьшается только для очень большого числа ячеек.
                val stepRadians = Math.toRadians(step.toDouble()).toFloat()
                val segmentStroke = minOf(
                    11.dp.toPx(),
                    segmentRadius * stepRadians * 0.72f,
                )
                val visualGap = minOf(2.dp.toPx(), maxOf(0.75.dp.toPx(), segmentStroke * 0.18f))
                val gapAngle = Math.toDegrees((visualGap / segmentRadius).toDouble()).toFloat()
                val sweep = (step - gapAngle).coerceAtLeast(step * 0.32f)
                val outerRadius = segmentRadius + segmentStroke / 2f
                val innerRadius = segmentRadius - segmentStroke / 2f

                fun segmentPath(startAngle: Float, segmentSweep: Float): Path {
                    val outerBounds = Rect(
                        center.x - outerRadius,
                        center.y - outerRadius,
                        center.x + outerRadius,
                        center.y + outerRadius,
                    )
                    val innerBounds = Rect(
                        center.x - innerRadius,
                        center.y - innerRadius,
                        center.x + innerRadius,
                        center.y + innerRadius,
                    )
                    return Path().apply {
                        arcTo(outerBounds, startAngle, segmentSweep, forceMoveTo = true)
                        arcTo(innerBounds, startAngle + segmentSweep, -segmentSweep, forceMoveTo = false)
                        close()
                    }
                }
                repeat(segmentCount) { index ->
                    val activeFraction = (activeWorkerProgress - index).coerceIn(0f, 1f)
                    val startAngle = -90f + index * step + (step - sweep) / 2f
                    val outlinePath = segmentPath(startAngle, sweep)
                    drawPath(
                        path = outlinePath,
                        color = outline.copy(alpha = (if (connectionVisible) 0.24f else 0.15f) * enabledAlpha),
                    )
                    if (activeFraction > 0f && connectionAlpha > 0.01f) {
                        val fillSweep = sweep * activeFraction
                        val fillPath = segmentPath(startAngle, fillSweep)
                        // Свечение остаётся в пределах небольшой щели между
                        // секторными ячейками и не превращает кольцо в дугу.
                        drawPath(
                            path = fillPath,
                            color = primary.copy(alpha = 0.16f * activeFraction * connectionAlpha * enabledAlpha),
                            style = Stroke(width = 2.5.dp.toPx()),
                        )
                        drawPath(
                            path = fillPath,
                            color = primary.copy(alpha = (0.58f + 0.42f * activeFraction) * connectionAlpha * enabledAlpha),
                        )
                    }
                }
            }

            Surface(
                modifier = Modifier
                    .size(96.dp)
                    .clip(CircleShape)
                    .clickable(
                        enabled = enabled,
                        onClick = {
                            if (running || waiting) {
                                stopBurstRequest++
                            } else {
                                startBurstRequest++
                            }
                            onClick()
                        },
                    ),
                shape = CircleShape,
                color = centerColor.copy(alpha = if (running || waiting || isStarting || isStopping) 0.96f else 0.72f),
                contentColor = onPrimary,
                tonalElevation = if (connectionVisible) 10.dp else 2.dp,
                shadowElevation = if (connectionVisible) 10.dp else 3.dp,
            ) {
                Box(contentAlignment = Alignment.Center) {
                    if (statusState == TunnelPowerVisualState.Connecting) {
                        ConnectingTunnelParticleRing(
                            modifier = Modifier.size(52.dp),
                            color = onPrimary.copy(alpha = enabledAlpha),
                        )
                    } else {
                        Icon(
                            imageVector = icon,
                            contentDescription = status.text,
                            modifier = Modifier.size(42.dp),
                            tint = onPrimary.copy(alpha = enabledAlpha),
                        )
                    }
                }
            }
        }
        Text(
            text = status.text,
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.SemiBold,
            textAlign = TextAlign.Center,
            color = status.color.copy(alpha = enabledAlpha),
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
        )
    }
}

private data class TunnelPowerStatus(
    val text: String,
    val color: Color,
)

internal enum class TunnelPowerVisualState {
    Off,
    Connecting,
    Connected,
    NoNetwork,
    WaitingForTrustedWifi,
    Stopping,
    Error,
    CoolingDown,
}

/**
 * Системный TUN может быть создан и без внешней сети. Не называем такое
 * состояние подключённым: для этого нужен хотя бы один живой поток.
 */
internal fun tunnelPowerVisualState(
    running: Boolean,
    waitingForTrustedWifi: Boolean,
    starting: Boolean,
    stopping: Boolean,
    activeWorkers: Int,
    underlyingNetworkAvailable: Boolean,
    hasConnectionError: Boolean,
    cooldownActive: Boolean,
): TunnelPowerVisualState = when {
    stopping -> TunnelPowerVisualState.Stopping
    waitingForTrustedWifi -> TunnelPowerVisualState.WaitingForTrustedWifi
    (starting || running) && !underlyingNetworkAvailable -> TunnelPowerVisualState.NoNetwork
    hasConnectionError -> TunnelPowerVisualState.Error
    starting || running && activeWorkers <= 0 -> TunnelPowerVisualState.Connecting
    running -> TunnelPowerVisualState.Connected
    cooldownActive -> TunnelPowerVisualState.CoolingDown
    else -> TunnelPowerVisualState.Off
}

@Composable
private fun rememberUnderlyingNetworkAvailable(): Boolean {
    val context = LocalContext.current.applicationContext
    var available by remember(context) {
        mutableStateOf(hasUnderlyingInternetNetwork(context))
    }
    DisposableEffect(context) {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        val mainHandler = Handler(Looper.getMainLooper())
        if (connectivity == null) {
            onDispose { }
        } else {
            fun refresh() {
                mainHandler.post {
                    available = hasUnderlyingInternetNetwork(context)
                }
            }
            val callback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) = refresh()
                override fun onLost(network: Network) = refresh()
                override fun onCapabilitiesChanged(
                    network: Network,
                    networkCapabilities: NetworkCapabilities,
                ) = refresh()
            }
            runCatching {
                connectivity.registerNetworkCallback(
                    NetworkRequest.Builder()
                        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                        .build(),
                    callback,
                )
            }
            onDispose {
                runCatching { connectivity.unregisterNetworkCallback(callback) }
            }
        }
    }
    return available
}

private fun hasUnderlyingInternetNetwork(context: Context): Boolean = runCatching {
    val connectivity = context.getSystemService(ConnectivityManager::class.java) ?: return@runCatching false
    connectivity.allNetworks.any { network ->
        val capabilities = connectivity.getNetworkCapabilities(network) ?: return@any false
        capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
    }
}.getOrDefault(false)

/**
 * Индикатор запуска не вращается: частицы образуют цельное кольцо и вместе
 * мягко "дышат". Он существует только пока видна фаза STARTING, поэтому не
 * держит кадры и анимацию в работающем/фоновом состоянии.
 */
@Composable
private fun ConnectingTunnelParticleRing(
    modifier: Modifier = Modifier,
    color: Color,
) {
    val breathing = rememberInfiniteTransition(label = "tunnel_connecting_breathing")
    val pulse by breathing.animateFloat(
        initialValue = 0.93f,
        targetValue = 1.07f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1_150),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "tunnel_connecting_breathing_scale",
    )
    Canvas(modifier = modifier) {
        val center = Offset(size.width / 2f, size.height / 2f)
        val radius = size.minDimension * 0.31f * pulse
        val dotRadius = size.minDimension * 0.055f * (0.94f + (pulse - 0.93f) * 0.7f)
        repeat(12) { index ->
            val angle = Math.toRadians((-90f + index * 30f).toDouble())
            val point = Offset(
                x = center.x + kotlin.math.cos(angle).toFloat() * radius,
                y = center.y + kotlin.math.sin(angle).toFloat() * radius,
            )
            drawCircle(
                color = color.copy(alpha = 0.52f + (index % 3) * 0.12f),
                radius = dotRadius,
                center = point,
            )
        }
    }
}

@Composable
private fun SettingsHelpDialog(
    title: String,
    paragraphs: List<String>,
    onDismiss: () -> Unit,
    highlightedParagraphIndices: Set<Int> = emptySet(),
    secondaryActionLabel: String? = null,
    onSecondaryAction: (() -> Unit)? = null,
    secondaryActionEnabled: Boolean = true,
    onSecondaryActionDisabled: (() -> Unit)? = null,
) {
    Dialog(onDismissRequest = onDismiss) {
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
                            title,
                            modifier = Modifier.weight(1f),
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary
                        )
                        IconButton(onClick = onDismiss) {
                            Icon(Icons.Default.Close, contentDescription = "Закрыть")
                        }
                    }
                    paragraphs.forEachIndexed { index, paragraph ->
                        if (index in highlightedParagraphIndices) {
                            Surface(
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(14.dp),
                                color = MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.72f),
                                contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
                                border = BorderStroke(
                                    1.dp,
                                    MaterialTheme.colorScheme.tertiary.copy(alpha = 0.32f),
                                ),
                            ) {
                                Text(
                                    paragraph,
                                    modifier = Modifier.padding(12.dp),
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.SemiBold,
                                )
                            }
                        } else {
                            Text(
                                paragraph,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                    if (secondaryActionLabel != null && onSecondaryAction != null) {
                        Box(modifier = Modifier.fillMaxWidth()) {
                            OutlinedButton(
                                onClick = onSecondaryAction,
                                enabled = secondaryActionEnabled,
                                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                                shape = RoundedCornerShape(16.dp),
                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp),
                            ) {
                                FlexibleButtonText(secondaryActionLabel)
                            }
                            if (!secondaryActionEnabled && onSecondaryActionDisabled != null) {
                                Box(
                                    modifier = Modifier
                                        .matchParentSize()
                                        .clickable(onClick = onSecondaryActionDisabled),
                                )
                            }
                        }
                    }
                    Button(
                        onClick = onDismiss,
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                        shape = RoundedCornerShape(16.dp),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                    ) {
                        FlexibleButtonText("Понятно", fontWeight = FontWeight.Bold)
                    }
                    Spacer(Modifier.height(4.dp))
                }
            }
        }
    }
}

@Composable
private fun PowerHelpDialog(
    minWorkers: Int,
    maxWorkers: Int,
    currentWorkers: Int,
    profileMaxWorkers: Int,
    onDismiss: () -> Unit
) {
    Dialog(onDismissRequest = onDismiss) {
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
                            "Мощность",
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary
                        )
                        IconButton(onClick = onDismiss) {
                            Icon(Icons.Default.Close, contentDescription = "Закрыть")
                        }
                    }
                    Text(
                        "Мощность задаёт количество параллельных рабочих потоков TURN/DTLS для VK-звонка. Чем выше значение, тем больше каналов приложение пытается держать одновременно.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        "На что влияет: устойчивость при потерях сети, скорость восстановления, расход батареи, нагрев, нагрузка на сервер и вероятность чаще упираться в ограничения или капчу VK.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        "Ориентир: 9-18 для экономного режима, 18-36 обычно достаточно, выше 36 имеет смысл только если сеть нестабильная, сервер справляется и капча не мешает.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    if (profileMaxWorkers >= WORKERS_PER_GROUP) {
                        Text(
                            "Владелец этого профиля установил предел $profileMaxWorkers потоков с учётом возможностей сервера. Приложение не позволит выбрать больше для этого профиля. Ограничение не действует на другие самостоятельно настроенные профили.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.primary,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                    Text(
                        "Сейчас: $currentWorkers. Доступный диапазон для текущего числа VK-хешей: $minWorkers-$maxWorkers.",
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Button(
                        onClick = onDismiss,
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                        shape = RoundedCornerShape(16.dp),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                    ) {
                        FlexibleButtonText("Понятно", fontWeight = FontWeight.Bold)
                    }
                    Spacer(Modifier.height(4.dp))
                }
            }
        }
    }
}

@Composable
private fun FlexibleButtonText(
    text: String,
    fontWeight: FontWeight = FontWeight.SemiBold,
    color: Color = LocalContentColor.current
) {
    Text(
        text = text,
        fontWeight = fontWeight,
        color = color,
        textAlign = TextAlign.Center
    )
}

@Composable
private fun FullWidthFieldMessage(text: String, color: Color) {
    Text(
        text = text,
        modifier = Modifier.fillMaxWidth(),
        style = MaterialTheme.typography.bodySmall,
        color = color
    )
}

// ═══ Reusable mode chip ═══
@Composable
private fun ProtocolChip(label: String, selected: Boolean, enabled: Boolean = true, isError: Boolean = false, onClick: () -> Unit) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        enabled = enabled,
        label = {
            Text(
                label,
                fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium,
                color = if (isError) MaterialTheme.colorScheme.error else (if (selected) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface)
            )
        },
        shape = RoundedCornerShape(16.dp),
        colors = FilterChipDefaults.filterChipColors(
            selectedContainerColor = MaterialTheme.colorScheme.primary,
            selectedLabelColor = MaterialTheme.colorScheme.onPrimary,
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
            labelColor = MaterialTheme.colorScheme.onSurface,
            disabledLabelColor = if (isError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f)
        ),
        border = FilterChipDefaults.filterChipBorder(
            enabled = true,
            selected = selected,
            borderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f),
            selectedBorderColor = MaterialTheme.colorScheme.primary
        )
    )
}

@Composable
private fun CompactSteppedSlider(
    value: Float,
    onValueChange: (Float) -> Unit,
    onValueChangeFinished: (Float) -> Unit,
    valueRange: ClosedFloatingPointRange<Float>,
    stepSize: Float,
    enabled: Boolean,
    modifier: Modifier = Modifier
) {
    val activeColor = MaterialTheme.colorScheme.primary.copy(alpha = if (enabled) 1f else 0.38f)
    val inactiveColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = if (enabled) 1f else 0.55f)
    val thumbStrokeColor = MaterialTheme.colorScheme.surface
    val density = LocalDensity.current
    val thumbRadiusPx = with(density) { 9.dp.toPx() }
    val trackWidthPx = with(density) { 5.dp.toPx() }
    val currentValue by rememberUpdatedState(value)
    val currentOnValueChange by rememberUpdatedState(onValueChange)
    val currentOnValueChangeFinished by rememberUpdatedState(onValueChangeFinished)

    fun snap(raw: Float): Float {
        val min = valueRange.start
        val max = valueRange.endInclusive
        val snapped = (((raw - min) / stepSize).roundToInt() * stepSize) + min
        return snapped.coerceIn(min, max)
    }

    fun positionToValue(x: Float, width: Float): Float {
        val left = thumbRadiusPx
        val right = (width - thumbRadiusPx).coerceAtLeast(left + 1f)
        val fraction = ((x.coerceIn(left, right) - left) / (right - left)).coerceIn(0f, 1f)
        return snap(valueRange.start + fraction * (valueRange.endInclusive - valueRange.start))
    }

    Canvas(
        modifier = modifier
            .height(30.dp)
            .pointerInput(enabled, valueRange, stepSize) {
                if (!enabled) return@pointerInput
                detectTapGestures { offset ->
                    val selected = positionToValue(offset.x, size.width.toFloat())
                    currentOnValueChange(selected)
                    currentOnValueChangeFinished(selected)
                }
            }
            .pointerInput(enabled, valueRange, stepSize) {
                if (!enabled) return@pointerInput
                var selected = currentValue
                detectDragGestures(
                    onDragStart = { selected = currentValue },
                    onDragEnd = { currentOnValueChangeFinished(selected) },
                    onDragCancel = { currentOnValueChangeFinished(selected) },
                ) { change, _ ->
                    selected = positionToValue(change.position.x, size.width.toFloat())
                    currentOnValueChange(selected)
                }
            }
    ) {
        val centerY = size.height / 2f
        val left = thumbRadiusPx
        val right = size.width - thumbRadiusPx
        val range = (valueRange.endInclusive - valueRange.start).coerceAtLeast(1f)
        val fraction = ((value - valueRange.start) / range).coerceIn(0f, 1f)
        val thumbX = left + (right - left) * fraction

        drawLine(
            color = inactiveColor,
            start = Offset(left, centerY),
            end = Offset(right, centerY),
            strokeWidth = trackWidthPx,
            cap = StrokeCap.Round
        )
        drawLine(
            color = activeColor,
            start = Offset(left, centerY),
            end = Offset(thumbX, centerY),
            strokeWidth = trackWidthPx,
            cap = StrokeCap.Round
        )

        val tickCount = (((valueRange.endInclusive - valueRange.start) / stepSize).roundToInt()).coerceAtLeast(1)
        repeat(tickCount + 1) { index ->
            val tickFraction = index / tickCount.toFloat()
            val tickX = left + (right - left) * tickFraction
            drawCircle(
                color = if (tickX <= thumbX) activeColor else inactiveColor,
                radius = 2.dp.toPx(),
                center = Offset(tickX, centerY)
            )
        }

        drawCircle(
            color = activeColor,
            radius = thumbRadiusPx,
            center = Offset(thumbX, centerY)
        )
        drawCircle(
            color = thumbStrokeColor,
            radius = thumbRadiusPx,
            center = Offset(thumbX, centerY),
            style = androidx.compose.ui.graphics.drawscope.Stroke(width = 2.dp.toPx())
        )
    }
}

// ═══ Important Info Dialog ═══
@Composable
fun ImportantInfoDialog(onDismiss: () -> Unit) {
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        BoxWithConstraints(
            modifier = Modifier.fillMaxSize().padding(8.dp),
            contentAlignment = Alignment.Center
        ) {
            Surface(
                modifier = Modifier
                    .fillMaxWidth(0.95f)
                    .heightIn(max = maxHeight * 0.92f),
                shape = RoundedCornerShape(24.dp),
                color = MaterialTheme.colorScheme.surface,
                contentColor = MaterialTheme.colorScheme.onSurface,
                tonalElevation = 6.dp,
            ) {
                Column(
                    modifier = Modifier
                        .padding(24.dp)
                        .verticalScroll(rememberScrollState())
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("Важная информация", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                        IconButton(onClick = onDismiss) {
                            Icon(Icons.Default.Close, null)
                        }
                    }

                    Spacer(Modifier.height(16.dp))

                    InfoSection(
                        "Профили VPN",
                        "В боковых настройках доступны VPN 1, VPN 2 и VPN 3. Короткое нажатие выбирает профиль и закрывает настройки, долгое открывает переименование и полную локальную очистку профиля."
                    )
                    InfoSection(
                        "VK-хеши",
                        "VK-хеш нужен для работы туннеля. В настройке VK-хешей можно проверить каждый слот, скопировать отдельный хеш или все заполненные хеши сразу."
                    )
                    InfoSection(
                        "Клиенты и сервер",
                        "В режиме «Я — админ» блок «Деплой» → «Клиенты и сервер» управляет клиентами без Telegram-бота: создание, продление, отключение, смена пароля, экспорт и импорт отдельного клиента."
                    )
                    InfoSection(
                        "Передача подключения",
                        "Обычное подключение передаётся через «Настройки» → «Получить или передать». Перенос отдельного клиента выполняется именно в блоке «Клиенты и сервер»."
                    )
                    InfoSection(
                        "После новых серверных функций",
                        "Если приложение пишет, что сервер не поддерживает действие, выполните во вкладке «Деплой» установку сервера с сохранением данных."
                    )
                    InfoSection(
                        "Капча и мощность",
                        "Сначала работает быстрый VKCalls без капчи; авторешение подключается только для резервного способа. Несколько VK-хешей распределяют нагрузку, а мощность лучше держать умеренной: чем она выше, тем больше расход батареи и шанс чаще видеть капчу."
                    )

                    Spacer(Modifier.height(20.dp))
                    Button(
                        onClick = onDismiss,
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                        shape = RoundedCornerShape(16.dp),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp),
                        colors = ButtonDefaults.buttonColors(contentColor = MaterialTheme.colorScheme.onPrimary)
                    ) {
                        FlexibleButtonText("Понятно")
                    }
                    Spacer(Modifier.height(4.dp))
                }
            }
        }
    }
}

@Composable
private fun InfoSection(title: String, body: String) {
    Spacer(Modifier.height(12.dp))
    Text(
        title,
        style = MaterialTheme.typography.titleMedium,
        color = MaterialTheme.colorScheme.primary,
        fontWeight = FontWeight.Bold
    )
    Spacer(Modifier.height(4.dp))
    Text(body, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurface)
    Spacer(Modifier.height(4.dp))
}

// Округление до ближайшего кратного WORKERS_PER_GROUP
private fun roundToGroup(value: Float, maxW: Float = 96f): Float {
    val rounded = (Math.round(value / WORKERS_PER_GROUP) * WORKERS_PER_GROUP).toFloat()
    return rounded.coerceIn(WORKERS_PER_GROUP.toFloat(), maxW)
}

private fun maxWorkersForHashCount(hashCount: Int, profileMaxWorkers: Int = 0): Float {
    val hashMaximum = hashCount.coerceAtLeast(1) * 27
    return if (profileMaxWorkers >= WORKERS_PER_GROUP) {
        minOf(hashMaximum, profileMaxWorkers).toFloat()
    } else {
        hashMaximum.toFloat()
    }
}

private fun maxWorkersForHashSlots(
    hashSlots: List<String>,
    profileMaxWorkers: Int = 0
): Float {
    return maxWorkersForHashCount(
        hashSlots.count { slot ->
            val hash = stripVkUrlStatic(slot)
            VkJoinLink.isValidHash(hash)
        },
        profileMaxWorkers
    )
}

/** Извлекает хеш из VK ссылки */
private fun stripVkUrlStatic(input: String): String {
    return VkJoinLink.extractHash(input)
}

private fun parseVkHashSlots(raw: String): List<String> {
    val tokens = if (raw.contains(",")) {
        raw.split(",")
    } else {
        raw.split(Regex("[\\s\\n]+"))
    }
    return tokens
        .map { stripVkUrlStatic(it) }
        .take(4)
        .let { slots -> slots + List((4 - slots.size).coerceAtLeast(0)) { "" } }
}

internal fun parseBulkVkHashes(raw: String): List<String> {
    val normalized = raw
        .replace(Regex("(?i)%2c"), ",")
        .replace(Regex("(?i)%3b"), ";")
        .replace(Regex("(?i)%20"), " ")
        .replace(Regex("(?i)%09"), " ")
        .replace(Regex("(?i)%0d%0a|%0a|%0d"), "\n")
    return normalized
        .split(Regex("[,;\\s]+"))
        .asSequence()
        .map { stripVkUrlStatic(it) }
        .filter(VkJoinLink::isValidHash)
        .distinct()
        .take(4)
        .toList()
}

internal enum class BulkVkHashPasteMode {
    FillEmpty,
    ReplaceAll
}

internal data class BulkVkHashPasteResult(
    val slots: List<String>,
    val insertedCount: Int,
    val skippedCount: Int
)

private data class PendingBulkVkHashes(
    val hashes: List<String>
)

internal fun mergeBulkVkHashes(
    existingSlots: List<String>,
    incomingHashes: List<String>,
    mode: BulkVkHashPasteMode
): BulkVkHashPasteResult {
    val normalizedExisting = existingSlots
        .map { stripVkUrlStatic(it) }
        .take(4)
        .let { values -> values + List((4 - values.size).coerceAtLeast(0)) { "" } }
    val incoming = incomingHashes
        .map { stripVkUrlStatic(it) }
        .filter(VkJoinLink::isValidHash)
        .distinct()
        .take(4)
    return when (mode) {
        BulkVkHashPasteMode.ReplaceAll -> {
            val slots = incoming + List((4 - incoming.size).coerceAtLeast(0)) { "" }
            BulkVkHashPasteResult(
                slots = slots,
                insertedCount = incoming.size,
                skippedCount = 0
            )
        }
        BulkVkHashPasteMode.FillEmpty -> {
            val slots = normalizedExisting.toMutableList()
            var inserted = 0
            var skipped = 0
            val occupied = slots.filter(VkJoinLink::isValidHash).toMutableSet()
            incoming.forEach { hash ->
                if (hash in occupied) {
                    skipped++
                    return@forEach
                }
                val emptyIndex = slots.indexOfFirst { !VkJoinLink.isValidHash(it) }
                if (emptyIndex < 0) {
                    skipped++
                } else {
                    slots[emptyIndex] = hash
                    occupied += hash
                    inserted++
                }
            }
            BulkVkHashPasteResult(
                slots = slots,
                insertedCount = inserted,
                skippedCount = skipped
            )
        }
    }
}

private fun encodeVkHashSlots(vararg hashes: String): String {
    val slots = hashes
        .map { stripVkUrlStatic(it) }
        .take(4)
        .let { values -> values + List((4 - values.size).coerceAtLeast(0)) { "" } }
    return slots.joinToString(",")
}

private fun normalizeVkHashSlots(raw: String): String {
    return encodeVkHashSlots(*parseVkHashSlots(raw).toTypedArray())
}

private fun copyVkHashesToClipboard(context: android.content.Context, label: String, value: String) {
    if (value.isBlank()) return
    val clipboard = context.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as ClipboardManager
    clipboard.setPrimaryClip(ClipData.newPlainText(label, value))
    Toast.makeText(context, "Скопировано", Toast.LENGTH_SHORT).show()
}

private fun Int.hashPlural(): String {
    val mod100 = this % 100
    val mod10 = this % 10
    return when {
        mod100 in 11..14 -> "хешей"
        mod10 == 1 -> "хеш"
        mod10 in 2..4 -> "хеша"
        else -> "хешей"
    }
}

@Composable
private fun CompactTunnelProfileCard(
    hasConnection: Boolean,
    connectionMethod: String,
    savedConnectionMethod: String,
    onConnectionMethodChange: (String) -> Unit,
    onAddLinkClick: () -> Unit,
    onManualClick: () -> Unit,
) {
    AppSectionCard(
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Text(
            "Способ подключения",
            style = MaterialTheme.typography.labelLarge,
            fontWeight = FontWeight.SemiBold
        )
        SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
            listOf("link" to "Ссылка WDTT", "manual" to "Вручную")
                .forEachIndexed { index, (mode, label) ->
                    SegmentedButton(
                        selected = connectionMethod == mode,
                        onClick = { onConnectionMethodChange(mode) },
                        shape = SegmentedButtonDefaults.itemShape(index, 2),
                        icon = {
                            StableSegmentedButtonIcon(selected = connectionMethod == mode)
                        },
                    ) {
                        Text(label, textAlign = TextAlign.Center)
                    }
                }
        }
        val selectedMethodConfigured = hasConnection && (
            savedConnectionMethod == connectionMethod ||
                savedConnectionMethod.isBlank() && connectionMethod == "manual"
            )
        if (connectionMethod == "link") {
            OutlinedButton(
                onClick = onAddLinkClick,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                shape = RoundedCornerShape(16.dp),
                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp)
            ) {
                Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(6.dp))
                FlexibleButtonText(
                    if (selectedMethodConfigured) "Изменить ссылку" else "Вставить ссылку WDTT",
                    fontWeight = FontWeight.SemiBold
                )
            }
        } else {
            OutlinedButton(
                onClick = onManualClick,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                shape = RoundedCornerShape(16.dp),
                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp)
            ) {
                Icon(Icons.Default.Key, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(6.dp))
                FlexibleButtonText(
                    if (selectedMethodConfigured) "Изменить настройки" else "Настроить вручную",
                    fontWeight = FontWeight.SemiBold
                )
            }
        }
    }
}

private data class ManualTunnelConnectionDraft(
    val peer: String,
    val password: String,
    val manualPortsEnabled: Boolean,
    val serverDtlsPort: Int,
    val serverWgPort: Int,
    val localPort: Int,
)

@Composable
private fun UserManualConnectionDialog(
    initialPeer: String,
    initialPassword: String,
    initialManualPortsEnabled: Boolean,
    initialServerDtlsPort: String,
    initialServerWgPort: String,
    initialLocalPort: String,
    portsHint: String,
    onSave: (ManualTunnelConnectionDraft) -> Unit,
    onDismiss: () -> Unit,
) {
    val focusManager = LocalFocusManager.current
    var peer by rememberSaveable { mutableStateOf(initialPeer) }
    var password by rememberSaveable { mutableStateOf(initialPassword) }
    var passwordFocused by remember { mutableStateOf(false) }
    var manualPortsEnabled by rememberSaveable { mutableStateOf(initialManualPortsEnabled) }
    var serverDtlsPort by rememberSaveable {
        mutableStateOf(initialServerDtlsPort.ifBlank { "56000" })
    }
    var serverWgPort by rememberSaveable {
        mutableStateOf(initialServerWgPort.ifBlank { "56001" })
    }
    var localPort by rememberSaveable {
        mutableStateOf(initialLocalPort.ifBlank { "9000" })
    }

    val passwordValid = password.isNotEmpty() &&
        password.matches(Regex("^[a-zA-Z0-9_.!?:#/-]+$"))
    val parsedDtlsPort = serverDtlsPort.toIntOrNull()
    val parsedWgPort = serverWgPort.toIntOrNull()
    val parsedLocalPort = localPort.toIntOrNull()
    val portsValid = !manualPortsEnabled || listOf(
        parsedDtlsPort,
        parsedWgPort,
        parsedLocalPort
    ).all { it != null && it in 1..65535 }
    val canSave = isValidTunnelHost(peer) && passwordValid && portsValid

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        BoxWithConstraints(
            modifier = Modifier
                .fillMaxSize()
                .padding(8.dp)
                .pointerInput(focusManager) {
                    awaitPointerEventScope {
                        while (true) {
                            val event = awaitPointerEvent(PointerEventPass.Initial)
                            if (event.type == PointerEventType.Press) {
                                focusManager.clearFocus()
                            }
                        }
                    }
                },
            contentAlignment = Alignment.Center
        ) {
            Surface(
                modifier = Modifier
                    .fillMaxWidth(0.92f)
                    .widthIn(max = 560.dp)
                    .heightIn(max = maxHeight * 0.92f),
                shape = RoundedCornerShape(24.dp),
                color = MaterialTheme.colorScheme.surface,
                contentColor = MaterialTheme.colorScheme.onSurface,
                tonalElevation = 8.dp
            ) {
                Column(
                    modifier = Modifier.padding(22.dp).verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(
                            "Подключение вручную",
                            modifier = Modifier.weight(1f),
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary
                        )
                        IconButton(onClick = onDismiss) {
                            Icon(Icons.Default.Close, contentDescription = "Закрыть ручную настройку")
                        }
                    }

                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        val peerInvalid = peer.isNotBlank() && !isValidTunnelHost(peer)
                        OutlinedTextField(
                            value = peer,
                            onValueChange = { peer = it.filterNot(Char::isWhitespace) },
                            label = { Text("IP сервера или домен") },
                            placeholder = { Text("1.2.3.4 или server.example") },
                            singleLine = true,
                            isError = peerInvalid,
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(16.dp)
                        )
                        if (peerInvalid) {
                            FullWidthFieldMessage(
                                text = "Укажите адрес без порта",
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                    }

                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        val passwordInvalid = password.isNotBlank() && !passwordValid
                        OutlinedTextField(
                            value = password,
                            onValueChange = { password = it.filterNot(Char::isWhitespace) },
                            label = { Text("Пароль подключения") },
                            placeholder = { Text("Введите пароль туннеля") },
                            singleLine = true,
                            isError = passwordInvalid,
                            visualTransformation = if (passwordFocused) {
                                VisualTransformation.None
                            } else {
                                PasswordVisualTransformation()
                            },
                            modifier = Modifier
                                .fillMaxWidth()
                                .onFocusChanged { passwordFocused = it.isFocused },
                            shape = RoundedCornerShape(16.dp)
                        )
                        if (passwordInvalid) {
                            FullWidthFieldMessage(
                                text = "Разрешены буквы, цифры и знаки . ! ? : # - _ /",
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                    }

                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 12.dp)) {
                            Text("Нестандартные порты", fontWeight = FontWeight.SemiBold)
                            Text(
                                portsHint,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Switch(
                            checked = manualPortsEnabled,
                            onCheckedChange = { manualPortsEnabled = it }
                        )
                    }

                    if (manualPortsEnabled) {
                        listOf(
                            Triple(serverDtlsPort, "Порт сервера DTLS", { value: String -> serverDtlsPort = value }),
                            Triple(serverWgPort, "Порт сервера WireGuard", { value: String -> serverWgPort = value }),
                            Triple(localPort, "Локальный порт VPN", { value: String -> localPort = value }),
                        ).forEach { (value, label, update) ->
                            val parsed = value.toIntOrNull()
                            OutlinedTextField(
                                value = value,
                                onValueChange = { update(it.filter(Char::isDigit).take(5)) },
                                label = { Text(label) },
                                singleLine = true,
                                isError = value.isNotBlank() && (parsed == null || parsed !in 1..65535),
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(16.dp),
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                            )
                        }
                    }

                    Button(
                        onClick = {
                            onSave(
                                ManualTunnelConnectionDraft(
                                    peer = peer.trim(),
                                    password = password,
                                    manualPortsEnabled = manualPortsEnabled,
                                    serverDtlsPort = if (manualPortsEnabled) parsedDtlsPort!! else 56000,
                                    serverWgPort = if (manualPortsEnabled) parsedWgPort!! else 56001,
                                    localPort = if (manualPortsEnabled) parsedLocalPort!! else 9000,
                                )
                            )
                        },
                        enabled = canSave,
                        modifier = Modifier.fillMaxWidth().heightIn(min = 50.dp),
                        shape = RoundedCornerShape(16.dp)
                    ) {
                        FlexibleButtonText("Сохранить подключение", fontWeight = FontWeight.Bold)
                    }
                    Spacer(Modifier.height(2.dp))
                }
            }
        }
    }
}

@Composable
private fun UserWdttLinkDialog(
    linkText: String,
    onLinkTextChange: (String) -> Unit,
    onPaste: () -> Unit,
    onSave: () -> Unit,
    allowMissingHashes: Boolean,
    remoteUpdateOnly: Boolean,
    cachedAction: CachedRemoteAction = CachedRemoteAction.Unavailable,
    onCachedAction: () -> Unit = {},
    title: String,
    subtitle: String,
    onDismiss: () -> Unit,
) {
    var showRemoteUpdateHelp by rememberSaveable { mutableStateOf(false) }
    val remoteDocument = remember(linkText) {
        RemoteDocumentGateway.extractLink(linkText) != null
    }
    val parsed = remember(linkText, allowMissingHashes) {
        if (remoteUpdateOnly) {
            null
        } else {
            WdttDeepLink.parse(linkText, allowMissingHashes = allowMissingHashes)
        }
    }
    val validation = remember(linkText, allowMissingHashes) {
        WdttDeepLink.validate(linkText, allowMissingHashes = allowMissingHashes)
    }
    val invalid =
        linkText.isNotBlank() && parsed == null && !remoteDocument

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        BoxWithConstraints(
            modifier = Modifier.fillMaxSize().padding(8.dp),
            contentAlignment = Alignment.Center
        ) {
            Surface(
                modifier = Modifier
                    .fillMaxWidth(0.92f)
                    .widthIn(max = 560.dp)
                    .heightIn(max = maxHeight * 0.92f),
                shape = RoundedCornerShape(24.dp),
                color = MaterialTheme.colorScheme.surface,
                contentColor = MaterialTheme.colorScheme.onSurface,
                tonalElevation = 8.dp
            ) {
                Column(
                    modifier = Modifier.padding(22.dp).verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                title,
                                style = MaterialTheme.typography.titleLarge,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.primary
                            )
                            if (subtitle.isNotBlank()) {
                                Text(
                                    subtitle,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                        if (remoteUpdateOnly) {
                            IconButton(
                                onClick = { showRemoteUpdateHelp = true },
                                modifier = Modifier.size(40.dp),
                            ) {
                                Icon(
                                    Icons.AutoMirrored.Filled.HelpOutline,
                                    contentDescription = "Как обновить маршрут",
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.size(22.dp),
                                )
                            }
                        }
                        IconButton(onClick = onDismiss) {
                            Icon(Icons.Default.Close, contentDescription = "Закрыть ввод ссылки")
                        }
                    }

                    if (remoteUpdateOnly && cachedAction.available) {
                        ElevatedCard(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.elevatedCardColors(
                                containerColor =
                                    MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.55f)
                            ),
                        ) {
                            Column(
                                modifier = Modifier.padding(14.dp),
                                verticalArrangement = Arrangement.spacedBy(10.dp),
                            ) {
                                if (cachedAction.title.isNotBlank()) {
                                    Text(
                                        cachedAction.title,
                                        style = MaterialTheme.typography.titleSmall,
                                        fontWeight = FontWeight.SemiBold,
                                        color = MaterialTheme.colorScheme.onSecondaryContainer,
                                    )
                                }
                                Text(
                                    cachedAction.message,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSecondaryContainer,
                                )
                                OutlinedButton(
                                    onClick = onCachedAction,
                                    modifier = Modifier.fillMaxWidth(),
                                    shape = RoundedCornerShape(14.dp),
                                ) {
                                    Icon(
                                        Icons.AutoMirrored.Filled.OpenInNew,
                                        contentDescription = null,
                                    )
                                    Spacer(Modifier.width(8.dp))
                                    FlexibleButtonText(
                                        cachedAction.label.ifBlank { "Открыть другой способ" }
                                    )
                                }
                            }
                        }
                    }

                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        OutlinedTextField(
                            value = linkText,
                            onValueChange = onLinkTextChange,
                            label = {
                                Text(if (remoteUpdateOnly) "Ссылка обновления" else "Ссылка wdtt://")
                            },
                            placeholder = {
                                Text(if (remoteUpdateOnly) "https://…" else "wdtt://...")
                            },
                            minLines = 2,
                            maxLines = 4,
                            isError = invalid,
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(16.dp)
                        )
                        if (linkText.isNotBlank()) {
                        FullWidthFieldMessage(
                            text = when {
                                remoteDocument ->
                                    "Короткая ссылка откроет обновление в WDTT Plus."
                                remoteUpdateOnly ->
                                    "Вставьте короткую HTTPS-ссылку обновления."
                                parsed == null -> validation.userMessage()
                                validation.canStartVpn -> "Ссылка распознана и готова к подключению."
                                else -> "Ссылка распознана. VK-хеши можно добавить после сохранения."
                                },
                                color = if (invalid) {
                                    MaterialTheme.colorScheme.error
                                } else {
                                    MaterialTheme.colorScheme.onSurfaceVariant
                                }
                            )
                        }
                    }

                    OutlinedButton(
                        onClick = onPaste,
                        modifier = Modifier.fillMaxWidth().heightIn(min = 46.dp),
                        shape = RoundedCornerShape(14.dp)
                    ) {
                        Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        FlexibleButtonText("Вставить из буфера")
                    }

                    Button(
                        onClick = onSave,
                        enabled = if (remoteUpdateOnly) {
                            remoteDocument
                        } else {
                            parsed != null || remoteDocument
                        },
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                        shape = RoundedCornerShape(16.dp)
                    ) {
                        FlexibleButtonText("Сохранить подключение", fontWeight = FontWeight.Bold)
                    }

                    Text(
                        if (remoteUpdateOnly) {
                            "Ссылка предназначена только для этого профиля и устройства — не публикуйте её."
                        } else {
                            "Ссылку также можно отправить в WDTT Plus через системное меню «Поделиться». Она содержит пароль подключения — не публикуйте её."
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    Spacer(Modifier.height(2.dp))
                }
            }
        }
    }
    if (remoteUpdateOnly && showRemoteUpdateHelp) {
        RemoteUpdateHelpDialog(
            cachedAction = cachedAction,
            onDismiss = { showRemoteUpdateHelp = false },
        )
    }
}

@Composable
private fun RemoteUpdateHelpDialog(
    cachedAction: CachedRemoteAction,
    onDismiss: () -> Unit,
) {
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        BoxWithConstraints(
            modifier = Modifier.fillMaxSize().padding(8.dp),
            contentAlignment = Alignment.Center,
        ) {
            Surface(
                modifier = Modifier
                    .fillMaxWidth(0.92f)
                    .widthIn(max = 540.dp)
                    .heightIn(max = maxHeight * 0.92f),
                shape = RoundedCornerShape(24.dp),
                color = MaterialTheme.colorScheme.surface,
                contentColor = MaterialTheme.colorScheme.onSurface,
                tonalElevation = 10.dp,
            ) {
                Column(
                    modifier = Modifier.padding(20.dp).verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(14.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            cachedAction.helpTitle.ifBlank { "Как обновить маршрут" },
                            modifier = Modifier.weight(1f),
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary,
                        )
                        IconButton(onClick = onDismiss) {
                            Icon(
                                Icons.Default.Close,
                                contentDescription = "Вернуться к обновлению маршрута",
                            )
                        }
                    }
                    Text(
                        cachedAction.helpIntro.ifBlank {
                            ("Обычно профиль обновляется автоматически. Это меню понадобится, "
                                + "если короткая ссылка не открыла WDTT Plus."
                            )
                        },
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        cachedAction.helpSteps.ifBlank {
                            ("1. Откройте полученную короткую HTTPS-ссылку на телефоне с "
                                + "WDTT Plus.\n\n"
                                + "2. Если приложение не открылось автоматически, скопируйте "
                                + "эту же ссылку, вставьте её в поле «Ссылка обновления» и "
                                + "нажмите «Сохранить подключение».\n\n"
                                + "3. Если доступен другой способ, используйте отдельную кнопку "
                                + "над полем ссылки."
                            )
                        },
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
            }
        }
    }
}

@Composable
private fun ManagedHashStatusCard(lifecycle: AccessLifecycleUiState) {
    val accent = MaterialTheme.colorScheme.primary
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.52f),
        contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        border = BorderStroke(1.dp, accent.copy(alpha = 0.36f)),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(9.dp),
            ) {
                Icon(
                    Icons.Default.CheckCircle,
                    contentDescription = null,
                    tint = accent,
                    modifier = Modifier.size(21.dp),
                )
                Text(
                    lifecycle.title.ifBlank { "Автоматическое получение VK-хешей" },
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                )
            }
            if (lifecycle.message.isNotBlank()) {
                Text(
                    lifecycle.message,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.86f),
                )
            }
            if (lifecycle.detailLabel.isNotBlank() || lifecycle.detailValue.isNotBlank()) {
                AccessLifecycleDetail(
                    lifecycle = lifecycle,
                    accent = accent,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
}

@Composable
private fun RemoteActionCard(
    action: RemoteUiAction,
    onClick: () -> Unit,
    onLinkClick: (() -> Unit)? = null,
    onDismiss: (() -> Unit)? = null,
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        color = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.48f),
        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
        border = BorderStroke(
            1.dp,
            MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.45f)
        )
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(9.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(9.dp)
            ) {
                Icon(Icons.Default.Cloud, contentDescription = null, modifier = Modifier.size(21.dp))
                Text(
                    action.title,
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold
                )
                if (onDismiss != null) {
                    CardDismissButton(
                        contentDescription = "Скрыть карточку",
                        onClick = onDismiss,
                    )
                }
            }
            RemoteActionLinkedText(
                text = action.compactMessage.ifBlank { action.message },
                linkText = action.compactLinkText,
                color = MaterialTheme.colorScheme.onSecondaryContainer.copy(alpha = 0.86f),
                onClick = onLinkClick ?: onClick,
            )
            if (action.compactButtonVisible) {
                OutlinedButton(
                    onClick = onClick,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 44.dp),
                    shape = RoundedCornerShape(14.dp),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 7.dp)
                ) {
                    FlexibleButtonText(
                        action.compactLabel.ifBlank { action.label },
                        fontWeight = FontWeight.SemiBold,
                    )
                    Spacer(Modifier.width(6.dp))
                    Icon(
                        Icons.AutoMirrored.Filled.OpenInNew,
                        contentDescription = null,
                        modifier = Modifier.size(17.dp),
                    )
                }
            }
        }
    }
}

@Composable
private fun RemoteActionLinkedText(
    text: String,
    linkText: String,
    color: Color,
    onClick: (() -> Unit)?,
) {
    val linkStart = text.indexOf(linkText)
        .takeIf { onClick != null && linkText.isNotBlank() && it >= 0 }
    if (linkStart == null) {
        Text(text = text, style = MaterialTheme.typography.bodySmall, color = color)
        return
    }
    val linkColor = MaterialTheme.colorScheme.primary
    val annotatedText = buildAnnotatedString {
        append(text.substring(0, linkStart))
        withLink(
            LinkAnnotation.Clickable(
                tag = "remote-action",
                styles = TextLinkStyles(
                    style = SpanStyle(
                        color = linkColor,
                        fontWeight = FontWeight.SemiBold,
                        textDecoration = TextDecoration.Underline,
                    ),
                    pressedStyle = SpanStyle(color = linkColor.copy(alpha = 0.68f)),
                ),
                linkInteractionListener = { onClick?.invoke() },
            )
        ) {
            append(linkText)
        }
        append(text.substring(linkStart + linkText.length))
    }
    Text(
        text = annotatedText,
        style = MaterialTheme.typography.bodySmall,
        color = color,
    )
}

@Composable
private fun CardDismissButton(
    contentDescription: String,
    onClick: () -> Unit,
) {
    IconButton(
        onClick = onClick,
        modifier = Modifier.size(32.dp),
    ) {
        Icon(
            imageVector = Icons.Default.Close,
            contentDescription = contentDescription,
            modifier = Modifier.size(18.dp),
            tint = MaterialTheme.colorScheme.onSecondaryContainer,
        )
    }
}

@Composable
private fun DismissedNoticeCard(
    title: String,
    message: String,
    countdown: Int,
    onProjectSupportClick: (() -> Unit)? = null,
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        color = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.48f),
        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
        border = BorderStroke(
            1.dp,
            MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.45f)
        )
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(7.dp)
        ) {
            Text(
                title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold
            )
            RemoteActionLinkedText(
                text = message,
                linkText = "«Инфо» → «Поддержать проект»",
                color = MaterialTheme.colorScheme.onSecondaryContainer.copy(alpha = 0.86f),
                onClick = onProjectSupportClick,
            )
            Text(
                "Карточка исчезнет через $countdown с",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSecondaryContainer.copy(alpha = 0.68f)
            )
        }
    }
}

// ═══ Модальное окно хешей ═══
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HashesDialog(
    settingsStore: SettingsStore,
    profileIndex: Int,
    hash1: String,
    hash2: String,
    hash3: String,
    hash4: String,
    activeFingerprint: String,
    activeClientIds: String,
    customVkCredentialsEnabled: Boolean,
    customVkClientId: String,
    customVkClientSecret: String,
    remoteContinuation: RemoteContinuation,
    remoteAccessLifecycle: AccessLifecycleUiState,
    remoteAction: RemoteUiAction?,
    vkCallsPreflight: Boolean,
    captchaMode: String,
    selectedWebViewManual: Boolean,
    onOpenProjectSupport: () -> Unit,
    onSave: (String, String, String, String) -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var h1 by remember(hash1) { mutableStateOf(hash1) }
    var h2 by remember(hash2) { mutableStateOf(hash2) }
    var h3 by remember(hash3) { mutableStateOf(hash3) }
    var h4 by remember(hash4) { mutableStateOf(hash4) }
    var isChecking by remember { mutableStateOf(false) }
    var checkJob by remember { mutableStateOf<Job?>(null) }
    var isRemoteActionRunning by remember { mutableStateOf(false) }
    var remoteActionJob by remember { mutableStateOf<Job?>(null) }
    var remoteActionMessage by rememberSaveable { mutableStateOf<String?>(null) }
    var remoteActionHasError by rememberSaveable { mutableStateOf(false) }
    var bulkPasteMessage by rememberSaveable { mutableStateOf<String?>(null) }
    var bulkPasteHasError by rememberSaveable { mutableStateOf(false) }
    var pendingBulkPasteHashes by remember { mutableStateOf<PendingBulkVkHashes?>(null) }
    var showRemoteActionInfo by rememberSaveable { mutableStateOf(false) }
    var showHashesHelp by rememberSaveable { mutableStateOf(false) }
    var checkResults by remember { mutableStateOf<Map<Int, HashCheckResult>>(emptyMap()) }
    var detailSlot by remember { mutableStateOf<Int?>(null) }
    val dialogScrollState = rememberScrollState()
    val currentHashes = remember(h1, h2, h3, h4) {
        listOf(h1, h2, h3, h4).map { stripVkUrlStatic(it) }
    }
    val copiedHashesText = remember(currentHashes) {
        currentHashes
            .filter { it.isNotBlank() }
            .joinToString(",")
    }
    val checkableHashes = remember(currentHashes) {
        currentHashes.mapIndexedNotNull { index, hash ->
            if (VkJoinLink.isValidHash(hash)) index + 1 to hash else null
        }
    }
    val dialogHashErrors = remember(currentHashes) {
        buildList {
            currentHashes.forEachIndexed { index, hash ->
                if (hash.isNotBlank() && !VkJoinLink.isValidHash(hash)) {
                    add("VK Хеш ${index + 1} имеет неверный формат")
                }
            }
            val filled = currentHashes.filter(VkJoinLink::isValidHash)
            if (filled.size != filled.distinct().size) add("Есть дубликаты VK-хешей")
        }
    }
    val canSaveHashes = dialogHashErrors.isEmpty()
    val completedChecks = checkResults.values.count { it.status !in setOf("pending", "checking", "solving_captcha") }
    val currentCheckSlot = checkResults.entries.firstOrNull { it.value.status in setOf("checking", "solving_captcha") }?.key
    val detailResult = detailSlot?.let { slot -> checkResults[slot]?.let { slot to it } }
    fun cancelHashCheck(updateUi: Boolean = true) {
        checkJob?.cancel(CancellationException("Hash check cancelled by user"))
        checkJob = null
        ManlCaptchaWebViewManager.cancelCaptcha()
        if (updateUi) {
            isChecking = false
            val activeSlots = checkResults.filterValues { it.status in setOf("pending", "checking", "solving_captcha") }
            if (activeSlots.isNotEmpty()) {
                checkResults = checkResults + activeSlots.mapValues { (_, result) ->
                    result.copy(status = "cancelled", message = "Проверка остановлена пользователем")
                }
            }
        }
    }
    fun cancelRemoteAction(updateUi: Boolean = true) {
        remoteActionJob?.cancel(CancellationException("Remote action cancelled by user"))
        remoteActionJob = null
        isRemoteActionRunning = false
        if (updateUi) {
            remoteActionMessage = remoteAction?.cancelledMessage
                ?.takeIf { it.isNotBlank() }
                ?: "Действие остановлено."
        }
    }
    fun applyBulkHashes(
        hashes: List<String>,
        mode: BulkVkHashPasteMode
    ) {
        val result = mergeBulkVkHashes(
            existingSlots = listOf(h1, h2, h3, h4),
            incomingHashes = hashes,
            mode = mode
        )
        h1 = result.slots[0]
        h2 = result.slots[1]
        h3 = result.slots[2]
        h4 = result.slots[3]
        bulkPasteHasError = when (mode) {
            BulkVkHashPasteMode.ReplaceAll -> result.insertedCount < 4
            BulkVkHashPasteMode.FillEmpty -> result.insertedCount == 0
        }
        bulkPasteMessage = when (mode) {
            BulkVkHashPasteMode.ReplaceAll -> {
                if (result.insertedCount == 4) {
                    "Готово: все четыре поля перезаписаны из буфера обмена."
                } else {
                    "Перезаписал поля: найдено ${result.insertedCount} ${result.insertedCount.hashPlural()}."
                }
            }
            BulkVkHashPasteMode.FillEmpty -> {
                when {
                    result.insertedCount == 0 ->
                        "Пустых мест для новых хешей нет или все найденные хеши уже были в полях."
                    result.skippedCount > 0 ->
                        "Заполнил ${result.insertedCount} ${result.insertedCount.hashPlural()} в пустых полях, ${result.skippedCount} пропущено."
                    else ->
                        "Заполнил ${result.insertedCount} ${result.insertedCount.hashPlural()} в пустых полях."
                }
            }
        }
        pendingBulkPasteHashes = null
    }
    fun startRemoteAction() {
        cancelHashCheck()
        remoteActionJob?.cancel(CancellationException("Restarting remote action"))
        if (!remoteContinuation.available) {
            isRemoteActionRunning = false
            remoteActionHasError = true
            remoteActionMessage = remoteAction?.message
                ?.takeIf { it.isNotBlank() }
                ?: remoteContinuation.message.takeIf { it.isNotBlank() }
                ?: "Автоматическое заполнение недоступно. Данные можно добавить вручную."
            return
        }
        remoteActionJob = scope.launch {
            val runningJob = coroutineContext[Job]
            isRemoteActionRunning = true
            remoteActionHasError = false
            remoteActionMessage = remoteAction?.preparingMessage
                ?.takeIf { it.isNotBlank() }
                ?: "Подготавливаю переход..."
            try {
                if (
                    TunnelManager.running.value ||
                    TunnelManager.transition.value != TunnelTransition.IDLE
                ) {
                    remoteActionMessage = remoteAction?.stoppingMessage
                        ?.takeIf { it.isNotBlank() }
                        ?: "Останавливаю VPN перед продолжением..."
                }
                val stopResult = TunnelStopCoordinator.stopAndAwait(context)
                if (!stopResult.succeeded) {
                    throw IllegalStateException(
                        if (stopResult == TunnelStopResult.TIMED_OUT) {
                            "VPN не остановился за 20 секунд. Повторите попытку."
                        } else {
                            "Не удалось запросить остановку VPN. Остановите туннель и повторите попытку."
                        }
                    )
                }
                if (stopResult == TunnelStopResult.STOPPED) {
                    delay(TunnelStopCoordinator.DIRECT_NETWORK_SETTLE_MS)
                }
                remoteActionMessage = remoteAction?.openingMessage
                    ?.takeIf { it.isNotBlank() }
                    ?: "Открываю продолжение..."
                val target = RemoteContinuationLauncher.begin(
                    capability = remoteContinuation,
                    device = settingsStore.getOrCreateConnectDeviceId(),
                    localDocument = settingsStore.remoteActionProfileDocument(profileIndex),
                )
                try {
                    launchRemoteTarget(context, target)
                } catch (error: Exception) {
                    throw IllegalStateException(
                        error.message
                            ?: "Не удалось открыть страницу. Проверьте доступные приложения и браузер."
                    )
                }
                remoteActionMessage = remoteAction?.successMessage
                    ?.takeIf { it.isNotBlank() }
                    ?: "Страница открыта. Завершите действие и вернитесь в WDTT Plus."
            } catch (cancelled: CancellationException) {
                remoteActionMessage = remoteAction?.cancelledMessage
                    ?.takeIf { it.isNotBlank() }
                    ?: "Действие остановлено."
            } catch (error: Exception) {
                remoteActionHasError = true
                remoteActionMessage = error.message
                    ?: remoteAction?.failureMessage?.takeIf { it.isNotBlank() }
                    ?: "Не удалось выполнить действие."
            } finally {
                if (remoteActionJob === runningJob) {
                    isRemoteActionRunning = false
                }
                if (remoteActionJob === runningJob) {
                    remoteActionJob = null
                }
            }
        }
    }
    fun pasteHashesFromClipboard() {
        val clipboard = context.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as ClipboardManager
        val raw = clipboard.primaryClip
            ?.takeIf { it.itemCount > 0 }
            ?.getItemAt(0)
            ?.coerceToText(context)
            ?.toString()
            .orEmpty()
        val hashes = parseBulkVkHashes(raw)
        if (hashes.isEmpty()) {
            bulkPasteHasError = true
            bulkPasteMessage = "В буфере обмена не нашёл VK-хеши или ссылки VK Звонков."
            return
        }
        val hasExistingHashes = listOf(h1, h2, h3, h4)
            .map { stripVkUrlStatic(it) }
            .any(VkJoinLink::isValidHash)
        if (hasExistingHashes) {
            pendingBulkPasteHashes = PendingBulkVkHashes(hashes)
        } else {
            applyBulkHashes(hashes, BulkVkHashPasteMode.ReplaceAll)
        }
    }
    fun closeDialog() {
        cancelHashCheck()
        cancelRemoteAction(updateUi = false)
        onDismiss()
    }

    DisposableEffect(Unit) {
        onDispose {
            cancelHashCheck(updateUi = false)
            cancelRemoteAction(updateUi = false)
        }
    }

    detailResult?.let { (slot, result) ->
        AlertDialog(
            onDismissRequest = { detailSlot = null },
            title = { Text("VK Хеш $slot: ${hashStatusLabel(result.status)}") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(result.message)
                    Text(
                        result.hash,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            },
            confirmButton = {
                TextButton(
                    onClick = { detailSlot = null },
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                ) {
                    FlexibleButtonText("Понятно")
                }
            }
        )
    }

    if (showRemoteActionInfo) {
        AlertDialog(
            onDismissRequest = { showRemoteActionInfo = false },
            title = {
                Text(
                    remoteAction?.confirmationTitle
                        ?.takeIf { it.isNotBlank() }
                        ?: remoteAction?.title?.takeIf { it.isNotBlank() }
                        ?: "Получение VK-хешей",
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    (
                        remoteAction?.confirmationMessage
                            ?.takeIf { it.isNotBlank() }
                            ?: remoteAction?.message?.takeIf { it.isNotBlank() }
                            ?: "Продолжите действие на открывшейся странице."
                        )
                        .split("\n\n")
                        .filter { it.isNotBlank() }
                        .forEach { paragraph -> Text(paragraph) }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        showRemoteActionInfo = false
                        startRemoteAction()
                    },
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                ) {
                    FlexibleButtonText(
                        remoteAction?.confirmationLabel
                            ?.takeIf { it.isNotBlank() }
                            ?: remoteAction?.label?.takeIf { it.isNotBlank() }
                            ?: "Получить 4 хеша через VK",
                    )
                }
            },
            dismissButton = {
                TextButton(
                    onClick = { showRemoteActionInfo = false },
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                ) {
                    FlexibleButtonText("Отмена")
                }
            }
        )
    }

    pendingBulkPasteHashes?.let { pending ->
        val hashes = pending.hashes
        val titleText = "Вставить хеши из буфера?"
        val sourceText = "В буфере найдено"
        AlertDialog(
            onDismissRequest = { pendingBulkPasteHashes = null },
            title = {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(titleText)
                    IconButton(
                        onClick = { pendingBulkPasteHashes = null },
                        modifier = Modifier.size(42.dp)
                    ) {
                        Surface(
                            shape = CircleShape,
                            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.72f),
                            modifier = Modifier.size(32.dp)
                        ) {
                            Box(contentAlignment = Alignment.Center) {
                                Icon(
                                    Icons.Default.Close,
                                    contentDescription = "Отмена",
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.size(20.dp)
                                )
                            }
                        }
                    }
                }
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("В полях уже есть сохранённые хеши. $sourceText ${hashes.size} ${hashes.size.hashPlural()}.")
                    Text("«Заполнить пустые» сохранит уже заполненные поля и вставит новые хеши только в свободные места.")
                    Text(
                        if (hashes.size >= 4) {
                            "«Перезаписать все 4» полностью заменит текущие четыре поля хешами из буфера."
                        } else {
                            "«Перезаписать» заменит поля найденными хешами, а оставшиеся позиции очистит."
                        },
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            },
            confirmButton = {
                TextButton(
                    onClick = { applyBulkHashes(hashes, BulkVkHashPasteMode.ReplaceAll) },
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                ) {
                    FlexibleButtonText(
                        if (hashes.size >= 4) "Перезаписать все 4" else "Перезаписать",
                        color = MaterialTheme.colorScheme.error
                    )
                }
            },
            dismissButton = {
                TextButton(
                    onClick = { applyBulkHashes(hashes, BulkVkHashPasteMode.FillEmpty) },
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                ) {
                    FlexibleButtonText("Заполнить пустые")
                }
            }
        )
    }

    Dialog(
        onDismissRequest = { closeDialog() },
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        BoxWithConstraints(
            modifier = Modifier
                .fillMaxSize()
                .padding(8.dp),
            contentAlignment = Alignment.Center
        ) {
            Surface(
                shape = RoundedCornerShape(24.dp),
                color = MaterialTheme.colorScheme.surface,
                contentColor = MaterialTheme.colorScheme.onSurface,
                tonalElevation = 8.dp,
                modifier = Modifier
                    .fillMaxWidth(0.96f)
                    .widthIn(max = 720.dp)
                    .heightIn(max = maxHeight * 0.92f)
            ) {
                Column(
                    modifier = Modifier
                        .padding(24.dp)
                        .fillMaxWidth()
                        .verticalScroll(dialogScrollState),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Tag, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(24.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("VK Хеши", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                            Spacer(Modifier.width(4.dp))
                            IconButton(
                                onClick = { showHashesHelp = true },
                                modifier = Modifier.size(36.dp)
                            ) {
                                Surface(
                                    shape = CircleShape,
                                    color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.72f),
                                    modifier = Modifier.size(28.dp)
                                ) {
                                    Box(contentAlignment = Alignment.Center) {
                                        Icon(
                                            Icons.AutoMirrored.Filled.HelpOutline,
                                            contentDescription = "Как получить VK-хеши",
                                            tint = MaterialTheme.colorScheme.onPrimaryContainer,
                                            modifier = Modifier.size(18.dp)
                                        )
                                    }
                                }
                            }
                        }
                        IconButton(
                            onClick = { closeDialog() },
                            modifier = Modifier.size(44.dp)
                        ) {
                            Surface(
                                shape = CircleShape,
                                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.78f),
                                modifier = Modifier.size(34.dp)
                            ) {
                                Box(contentAlignment = Alignment.Center) {
                                    Icon(
                                        Icons.Default.Close,
                                        contentDescription = "Закрыть",
                                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                        modifier = Modifier.size(22.dp)
                                    )
                                }
                            }
                        }
                    }

                    Text(
                        text = if (isChecking) {
                            val current = currentCheckSlot?.let { " Сейчас: VK Хеш $it." } ?: ""
                            "Проверено $completedChecks из ${checkableHashes.size}.$current"
                        } else if (isRemoteActionRunning) {
                            remoteActionMessage
                                ?: remoteAction?.progressLabel?.takeIf { it.isNotBlank() }
                                ?: "Выполняется…"
                        } else {
                            "Больше хешей — выше лимит потоков и лучшее распределение нагрузки."
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(bottom = 4.dp)
                    )

                    remoteActionMessage?.takeIf { it.isNotBlank() && !isRemoteActionRunning }?.let { message ->
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(16.dp),
                            color = if (remoteActionHasError) {
                                MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.72f)
                            } else {
                                MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.55f)
                            },
                            contentColor = if (remoteActionHasError) {
                                MaterialTheme.colorScheme.onErrorContainer
                            } else {
                                MaterialTheme.colorScheme.onSecondaryContainer
                            }
                        ) {
                            Text(
                                text = message,
                                modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }

                    OutlinedButton(
                        onClick = { pasteHashesFromClipboard() },
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                        shape = RoundedCornerShape(16.dp),
                        enabled = !isChecking && !isRemoteActionRunning,
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                    ) {
                        Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        FlexibleButtonText("Вставить хеши из буфера", fontWeight = FontWeight.SemiBold)
                    }

                    bulkPasteMessage?.takeIf { it.isNotBlank() }?.let { message ->
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(14.dp),
                            color = if (bulkPasteHasError) {
                                MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.62f)
                            } else {
                                MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.48f)
                            },
                            contentColor = if (bulkPasteHasError) {
                                MaterialTheme.colorScheme.onErrorContainer
                            } else {
                                MaterialTheme.colorScheme.onSecondaryContainer
                            }
                        ) {
                            Text(
                                text = message,
                                modifier = Modifier.padding(horizontal = 14.dp, vertical = 9.dp),
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }

                listOf(
                    Triple("VK Хеш 1", h1) { v: String -> h1 = v },
                    Triple("VK Хеш 2", h2) { v: String -> h2 = v },
                    Triple("VK Хеш 3", h3) { v: String -> h3 = v },
                    Triple("VK Хеш 4", h4) { v: String -> h4 = v }
                ).forEachIndexed { idx, (label, value, onChange) ->
                    val slot = idx + 1
                    val cleanedValue = stripVkUrlStatic(value)
                    HashInputField(
                        slot = slot,
                        label = label,
                        value = value,
                        onValueChange = { raw ->
                            val cleaned = raw.filter { c -> c != ' ' && c != '\n' }
                            onChange(stripVkUrlStatic(cleaned))
                        },
                        result = checkResults[slot],
                        onInfoClick = { detailSlot = slot },
                        canCopy = cleanedValue.isNotBlank(),
                        onCopyClick = { copyVkHashesToClipboard(context, "VK Хеш $slot", cleanedValue) },
                        canClear = value.isNotBlank(),
                        onClearClick = {
                            onChange("")
                            checkResults = checkResults - slot
                        }
                    )
                }

                OutlinedButton(
                    onClick = { copyVkHashesToClipboard(context, "VK Хеши WDTT Plus", copiedHashesText) },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                    shape = RoundedCornerShape(16.dp),
                    enabled = copiedHashesText.isNotBlank(),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                ) {
                    Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    FlexibleButtonText("Скопировать все хеши", fontWeight = FontWeight.SemiBold)
                }

                if (remoteContinuation.available) {
                    OutlinedButton(
                        onClick = { showRemoteActionInfo = true },
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                        shape = RoundedCornerShape(16.dp),
                        enabled = !isChecking && !isRemoteActionRunning,
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                    ) {
                        if (isRemoteActionRunning) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(18.dp),
                                strokeWidth = 2.dp,
                                color = MaterialTheme.colorScheme.primary
                            )
                            Spacer(Modifier.width(6.dp))
                            FlexibleButtonText(
                                remoteAction?.progressLabel
                                    ?.takeIf { it.isNotBlank() }
                                    ?: "Выполняется…",
                            )
                        } else {
                            Icon(Icons.Default.Key, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            FlexibleButtonText(
                                remoteAction?.label
                                    ?.takeIf { it.isNotBlank() }
                                    ?: "Получить 4 хеша через VK",
                                fontWeight = FontWeight.SemiBold,
                            )
                        }
                    }
                } else if (
                    shouldShowManagedHashStatusCard(
                        continuationAvailable = remoteContinuation.available,
                        lifecycle = remoteAccessLifecycle,
                    )
                ) {
                    ManagedHashStatusCard(remoteAccessLifecycle)
                } else if (remoteAction != null) {
                    RemoteActionCard(
                        action = remoteAction,
                        onLinkClick = {
                            closeDialog()
                            onOpenProjectSupport()
                        },
                        onClick = {
                            scope.launch {
                                val opened = RemoteUiActionLauncher.open(context, remoteAction)
                                if (!opened) {
                                    Toast.makeText(
                                        context,
                                        "Не удалось открыть страницу. Проверьте браузер.",
                                        Toast.LENGTH_LONG,
                                    ).show()
                                }
                            }
                        },
                    )
                }

                if (isRemoteActionRunning) {
                    TextButton(
                        onClick = { cancelRemoteAction() },
                        modifier = Modifier.fillMaxWidth().heightIn(min = 44.dp),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                    ) {
                        FlexibleButtonText(
                            remoteAction?.cancelLabel?.takeIf { it.isNotBlank() } ?: "Остановить",
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }

                OutlinedButton(
                    onClick = {
                        checkJob?.cancel(CancellationException("Restarting hash check"))
                        checkJob = scope.launch {
                            isChecking = true
                            checkResults = checkableHashes.associate { (slot, hash) ->
                                slot to HashCheckResult(hash = hash, status = "pending", message = "Ожидает проверки")
                            }
                            val finalResults = runCatching {
                                checkVkHashes(
                                    context = context,
                                    hashes = checkableHashes,
                                    fingerprint = activeFingerprint,
                                    clientIds = activeClientIds,
                                    customVkCredentialsEnabled = customVkCredentialsEnabled,
                                    customVkClientId = customVkClientId,
                                    customVkClientSecret = customVkClientSecret,
                                    vkCallsPreflight = vkCallsPreflight,
                                    captchaMode = captchaMode,
                                    selectedWebViewManual = selectedWebViewManual,
                                    onUpdate = { slot, result ->
                                        checkResults = checkResults + (slot to result)
                                    }
                                )
                            }.getOrElse { error ->
                                if (error is CancellationException) {
                                    checkableHashes.associate { (slot, hash) ->
                                        slot to (checkResults[slot] ?: HashCheckResult(hash = hash, status = "cancelled", message = "Проверка остановлена"))
                                    }
                                } else {
                                val message = error.message ?: "Не удалось выполнить проверку"
                                checkableHashes.associate { (slot, hash) ->
                                    slot to HashCheckResult(hash = hash, status = "error", message = message)
                                }
                                }
                            }
                            checkResults = checkResults + finalResults
                            isChecking = false
                            checkJob = null
                        }
                    },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                    shape = RoundedCornerShape(16.dp),
                    enabled = !isChecking && checkableHashes.isNotEmpty(),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                ) {
                    if (isChecking) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Spacer(Modifier.width(6.dp))
                        FlexibleButtonText("Проверка $completedChecks/${checkableHashes.size}")
                    } else {
                        FlexibleButtonText("Проверить хеши", fontWeight = FontWeight.SemiBold)
                    }
                }

                if (isChecking) {
                    TextButton(
                        onClick = { cancelHashCheck() },
                        modifier = Modifier.fillMaxWidth().heightIn(min = 44.dp),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                    ) {
                        FlexibleButtonText("Остановить проверку", color = MaterialTheme.colorScheme.error)
                    }
                }

                dialogHashErrors.firstOrNull()?.let { error ->
                    Text(
                        text = error,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall
                    )
                }

                Button(
                    onClick = {
                        cancelHashCheck()
                        onSave(h1, h2, h3, h4)
                    },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                    shape = RoundedCornerShape(16.dp),
                    enabled = canSaveHashes,
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp),
                    colors = ButtonDefaults.buttonColors(contentColor = MaterialTheme.colorScheme.onPrimary)
                ) {
                    FlexibleButtonText("Сохранить", fontWeight = FontWeight.SemiBold)
                }
            }
        }
    }

    if (showHashesHelp) {
        VkHashesInstructionDialog(
            remoteAction = remoteAction,
            onOpenProjectSupport = {
                showHashesHelp = false
                closeDialog()
                onOpenProjectSupport()
            },
            onDismiss = { showHashesHelp = false },
        )
    }
}
}

@Composable
private fun VkHashesInstructionDialog(
    remoteAction: RemoteUiAction?,
    onOpenProjectSupport: () -> Unit,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        BoxWithConstraints(
            modifier = Modifier.fillMaxSize().padding(8.dp),
            contentAlignment = Alignment.Center
        ) {
            Surface(
                modifier = Modifier
                    .fillMaxWidth(0.96f)
                    .widthIn(max = 680.dp)
                    .heightIn(max = maxHeight * 0.92f),
                shape = RoundedCornerShape(24.dp),
                color = MaterialTheme.colorScheme.surface,
                contentColor = MaterialTheme.colorScheme.onSurface,
                tonalElevation = 8.dp
            ) {
                Box {
                    Column(
                        modifier = Modifier
                            .padding(22.dp)
                            .fillMaxWidth()
                            .verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(14.dp)
                    ) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(end = 44.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Surface(
                                shape = CircleShape,
                                color = MaterialTheme.colorScheme.primaryContainer,
                                modifier = Modifier.size(38.dp)
                            ) {
                                Box(contentAlignment = Alignment.Center) {
                                    Icon(
                                        Icons.AutoMirrored.Filled.HelpOutline,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.onPrimaryContainer,
                                        modifier = Modifier.size(22.dp)
                                    )
                                }
                            }
                            Text(
                                "Как получить VK-хеши",
                                style = MaterialTheme.typography.titleLarge,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.primary
                            )
                        }
                    }

                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                        color = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.55f),
                        contentColor = MaterialTheme.colorScheme.onSecondaryContainer
                    ) {
                        Text(
                            "VK-хеш не нужно вычислять: это часть ссылки-приглашения в групповой звонок VK.",
                            modifier = Modifier.padding(14.dp),
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.SemiBold
                        )
                    }

                    Text(
                        "Самый простой способ",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    VkHashInstructionStep(1, "Откройте приложение VK или VK Звонки.")
                    VkHashInstructionStep(2, "Создайте либо откройте групповой звонок.")
                    VkHashInstructionStep(3, "Нажмите приглашение участников и выберите «Поделиться ссылкой».")
                    VkHashInstructionStep(4, "В системном меню Android выберите WDTT Plus.")
                    VkHashInstructionStep(5, "Приложение извлечёт хэш и добавит его в первое свободное поле активного профиля.")
                    VkHashInstructionStep(6, "Для дополнительных хэшей повторите действия с другими звонками. Можно использовать до четырёх хэшей.")

                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

                    Text(
                        "Как добавить вручную",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        "Скопируйте ссылку из VK Звонков и вставьте её целиком в поле либо нажмите «Вставить хеши из буфера».",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(14.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.72f)
                    ) {
                        Column(
                            modifier = Modifier.padding(14.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Text(
                                "https://vk.ru/call/join/AbCdEf123456789",
                                style = MaterialTheme.typography.bodySmall,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                "Хэш — часть после /join/:",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Text(
                                "AbCdEf123456789",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.primary
                            )
                        }
                    }
                    Text(
                        "Параметр ?from=share необязателен. Если после хэша есть знак ? или #, он и всё после него в хэш не входят. Поддерживаются ссылки vk.ru и vk.com.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                        color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.72f),
                        contentColor = MaterialTheme.colorScheme.onErrorContainer
                    ) {
                        Column(
                            modifier = Modifier.padding(14.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Text("Важно", fontWeight = FontWeight.Bold)
                            Text(
                                "Не выбирайте «Завершить для всех»: после закрытия комнаты ссылка может перестать работать. Можно просто выйти из звонка — постоянно оставаться в нём не требуется.",
                                style = MaterialTheme.typography.bodyMedium
                            )
                        }
                    }

                    if (remoteAction != null) {
                        RemoteActionCard(
                            action = remoteAction,
                            onLinkClick = onOpenProjectSupport,
                            onClick = {
                                scope.launch {
                                    RemoteUiActionLauncher.open(context, remoteAction)
                                }
                            },
                        )
                    }

                    Spacer(Modifier.height(4.dp))
                }
                    IconButton(
                        onClick = onDismiss,
                        modifier = Modifier.align(Alignment.TopEnd).padding(top = 10.dp, end = 10.dp)
                    ) {
                        Surface(
                            shape = CircleShape,
                            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.78f),
                            modifier = Modifier.size(34.dp)
                        ) {
                            Box(contentAlignment = Alignment.Center) {
                                Icon(
                                    Icons.Default.Close,
                                    contentDescription = "Вернуться к настройке VK-хешей",
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.size(22.dp)
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun VkHashInstructionStep(number: Int, text: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Surface(
            shape = CircleShape,
            color = MaterialTheme.colorScheme.primaryContainer,
            contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
            modifier = Modifier.size(28.dp)
        ) {
            Box(contentAlignment = Alignment.Center) {
                Text(
                    number.toString(),
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold
                )
            }
        }
        Text(
            text,
            modifier = Modifier.weight(1f).padding(top = 3.dp),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

private data class HashCheckResult(
    val hash: String,
    val status: String,
    val message: String
)

@Composable
private fun HashInputField(
    slot: Int,
    label: String,
    value: String,
    onValueChange: (String) -> Unit,
    result: HashCheckResult?,
    onInfoClick: () -> Unit,
    canCopy: Boolean,
    onCopyClick: () -> Unit,
    canClear: Boolean,
    onClearClick: () -> Unit
) {
    val isInvalid = value.isNotBlank() && !VkJoinLink.isValidHash(value)
    val visibleResult = result?.takeIf { it.status != "pending" }
    val statusColor = visibleResult?.let { hashStatusColor(it.status) }
    val borderColor = when {
        isInvalid -> MaterialTheme.colorScheme.error
        statusColor != null -> statusColor
        else -> MaterialTheme.colorScheme.outline.copy(alpha = 0.45f)
    }
    val progressMessage = visibleResult
        ?.takeIf { it.status in setOf("checking", "solving_captcha") }
        ?.message

    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            label = { Text(label) },
            placeholder = { Text("Ссылка звонка или хеш") },
            singleLine = true,
            isError = isInvalid,
            trailingIcon = {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(2.dp)
            ) {
                if (canClear) {
                    IconButton(
                        onClick = onClearClick,
                        modifier = Modifier.size(34.dp)
                    ) {
                        Icon(
                            Icons.Default.Close,
                            contentDescription = "Очистить VK Хеш $slot",
                            modifier = Modifier.size(18.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                IconButton(
                    onClick = onCopyClick,
                    enabled = canCopy,
                    modifier = Modifier.size(34.dp)
                ) {
                    Icon(
                        Icons.Default.ContentCopy,
                        contentDescription = "Скопировать VK Хеш $slot",
                        modifier = Modifier.size(18.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = if (canCopy) 1f else 0.38f)
                    )
                }
                if (visibleResult != null) {
                    IconButton(
                        onClick = onInfoClick,
                        modifier = Modifier.size(34.dp)
                    ) {
                        Surface(
                            shape = CircleShape,
                            color = borderColor.copy(alpha = 0.14f),
                            border = BorderStroke(1.dp, borderColor.copy(alpha = 0.7f)),
                            modifier = Modifier.size(22.dp)
                        ) {
                            Box(contentAlignment = Alignment.Center) {
                                Text(
                                    "?",
                                    color = borderColor,
                                    style = MaterialTheme.typography.labelSmall,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                        }
                    }
                }
            }
            },
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = borderColor,
                unfocusedBorderColor = borderColor,
                errorBorderColor = MaterialTheme.colorScheme.error,
                focusedLabelColor = MaterialTheme.colorScheme.onSurfaceVariant,
                unfocusedLabelColor = MaterialTheme.colorScheme.onSurfaceVariant,
                errorLabelColor = MaterialTheme.colorScheme.error,
                cursorColor = MaterialTheme.colorScheme.primary
            )
        )
        when {
            isInvalid -> FullWidthFieldMessage(
                text = "Хеш $slot имеет неверный формат",
                color = MaterialTheme.colorScheme.error
            )
            progressMessage != null -> FullWidthFieldMessage(
                text = progressMessage,
                color = borderColor
            )
        }
    }
}

@Composable
private fun hashStatusColor(status: String): Color {
    return when (status) {
        "ok" -> WDTTColors.connected
        "dead", "blocked" -> MaterialTheme.colorScheme.error
        "full", "captcha", "solving_captcha", "limited", "network" -> WDTTColors.warning
        "checking" -> MaterialTheme.colorScheme.primary
        "pending" -> MaterialTheme.colorScheme.outline
        "cancelled" -> MaterialTheme.colorScheme.outline
        else -> MaterialTheme.colorScheme.error
    }
}

private fun hashStatusLabel(status: String): String {
    return when (status) {
        "ok" -> "живой"
        "dead" -> "закрыт"
        "blocked" -> "вход запрещён"
        "full" -> "заполнен"
        "captcha" -> "капча"
        "solving_captcha" -> "решаем капчу"
        "limited" -> "лимит VK"
        "network" -> "сеть"
        "checking" -> "проверяется"
        "pending" -> "ожидает"
        "cancelled" -> "остановлено"
        else -> "ошибка"
    }
}

private suspend fun emitHashCheckResult(
    slot: Int,
    result: HashCheckResult,
    parsed: MutableMap<Int, HashCheckResult>,
    onUpdate: (Int, HashCheckResult) -> Unit
) {
    parsed[slot] = result
    withContext(Dispatchers.Main) {
        onUpdate(slot, result)
    }
}

private suspend fun solveHashCheckCaptcha(
    context: android.content.Context,
    mode: String,
    redirectUri: String,
    sessionToken: String,
    selectedWebViewManual: Boolean,
    onProgress: suspend (String) -> Unit
): String {
    val normalizedMode = mode.lowercase().trim()
    if (normalizedMode == "manual" || (normalizedMode == "selected" && selectedWebViewManual)) {
        onProgress("Открыта ручная VK Captcha")
        return ManlCaptchaWebViewManager.solveCaptchaAsync(context, redirectUri, sessionToken)
    }

    onProgress("Авто капча")
    return CaptchaWebViewManager.solveCaptchaAsync(redirectUri, sessionToken) { step ->
        // Go управляет fresh challenge и fallback-стадиями; здесь решается ровно одна сессия.
        android.util.Log.d("HashCheck", "Captcha step: $step")
    }
}

private suspend fun checkVkHashes(
    context: android.content.Context,
    hashes: List<Pair<Int, String>>,
    fingerprint: String,
    clientIds: String,
    customVkCredentialsEnabled: Boolean,
    customVkClientId: String,
    customVkClientSecret: String,
    vkCallsPreflight: Boolean,
    captchaMode: String,
    selectedWebViewManual: Boolean,
    onUpdate: (Int, HashCheckResult) -> Unit
): Map<Int, HashCheckResult> = withContext(Dispatchers.IO) {
    if (hashes.isEmpty()) return@withContext emptyMap()
    if (customVkCredentialsEnabled && (!isValidVkClientId(customVkClientId) || customVkClientSecret.isBlank())) {
        error("Заполните Client ID и Client secret в настройках собственных резервных реквизитов")
    }
    val binaryPath = context.applicationInfo.nativeLibraryDir + "/libclient.so"
    val command = mutableListOf(
        binaryPath,
        "-check-hashes",
        "-vk",
        hashes.joinToString(",") { it.second },
        "-captcha-mode",
        captchaMode,
        "-vkcalls-preflight=$vkCallsPreflight",
        "-device-id",
        SettingsStore(context).getOrCreateTunnelDeviceId()
    )
    if (fingerprint.isNotBlank()) {
        command += listOf("-fingerprint", fingerprint)
    }
    if (clientIds.isNotBlank()) {
        command += listOf("-client-ids", clientIds)
    }

    val process = ProcessBuilder(command)
        .redirectErrorStream(true)
        .apply {
            environment()["LD_LIBRARY_PATH"] = context.applicationInfo.nativeLibraryDir
            if (customVkCredentialsEnabled) {
                environment()["WDTT_CUSTOM_VK_CLIENT_ID"] = customVkClientId
                environment()["WDTT_CUSTOM_VK_CLIENT_SECRET"] = customVkClientSecret
            } else {
                environment().remove("WDTT_CUSTOM_VK_CLIENT_ID")
                environment().remove("WDTT_CUSTOM_VK_CLIENT_SECRET")
            }
        }
        .start()

    val byOrder = hashes.mapIndexed { order, pair -> order + 1 to pair }.toMap()
    val parsed = mutableMapOf<Int, HashCheckResult>()
    val startedAutoWebView = !TunnelManager.running.value
    var timedOut = false
    var currentSlot: Int? = null
    val timeoutMs = (hashes.size * 120_000L).coerceAtLeast(120_000L)
    var cleanedUp = false

    fun cleanupCheckProcess() {
        if (cleanedUp) return
        cleanedUp = true
        if (process.isAlive) {
            process.destroyForcibly()
        }
        ManlCaptchaWebViewManager.cancelCaptcha()
        if (startedAutoWebView && !TunnelManager.running.value) {
            CaptchaWebViewManager.onTunnelStop()
        }
    }

    if (startedAutoWebView) {
        CaptchaWebViewManager.onTunnelStart(context.applicationContext)
    }

    val cancellationHandle = kotlinx.coroutines.currentCoroutineContext()[Job]?.invokeOnCompletion { cause ->
        if (cause != null) {
            cleanupCheckProcess()
        }
    }

    val killerThread = Thread {
        try {
            Thread.sleep(timeoutMs)
            if (process.isAlive) {
                timedOut = true
                process.destroyForcibly()
            }
        } catch (_: InterruptedException) {
        }
    }.apply {
        isDaemon = true
        start()
    }

    try {
        val writer = process.outputStream.bufferedWriter(Charsets.UTF_8)
        val reader = process.inputStream.bufferedReader()

        readLoop@ while (true) {
            val line = reader.readLine() ?: break
            when {
                line.startsWith("HASH_CHECK_START|") -> {
                    val parts = line.split("|", limit = 3)
                    val order = parts.getOrNull(1)?.toIntOrNull() ?: continue@readLoop
                    val original = byOrder[order] ?: continue@readLoop
                    currentSlot = original.first
                    emitHashCheckResult(
                        original.first,
                        HashCheckResult(
                            hash = original.second,
                            status = "checking",
                            message = "Проверяется VK Хеш ${original.first}"
                        ),
                        parsed,
                        onUpdate
                    )
                }
                line.startsWith("CAPTCHA_SOLVE|") -> {
                    val payload = line.substringAfter("CAPTCHA_SOLVE|")
                    val parts = payload.split("|", limit = 4)
                    val slot = currentSlot
                    val requestId = if (parts.size == 4) parts[0] else ""
                    val mode = if (parts.size == 4) parts[1] else parts.getOrNull(0)
                    val redirectUri = if (parts.size == 4) parts[2] else parts.getOrNull(1)
                    val sessionToken = if (parts.size == 4) parts[3] else parts.getOrNull(2)
                    if (mode != null && redirectUri != null && sessionToken != null && slot != null) {
                        val currentHash = parsed[slot]?.hash ?: hashes.firstOrNull { it.first == slot }?.second ?: ""
                        emitHashCheckResult(
                            slot,
                            HashCheckResult(
                                hash = currentHash,
                                status = "solving_captcha",
                                message = "VK запросил капчу, решаем..."
                            ),
                            parsed,
                            onUpdate
                        )
                        val captchaResult = runCatching {
                            solveHashCheckCaptcha(
                                context,
                                mode,
                                redirectUri,
                                sessionToken,
                                selectedWebViewManual
                            ) { progress ->
                                emitHashCheckResult(
                                    slot,
                                    HashCheckResult(hash = currentHash, status = "solving_captcha", message = progress),
                                    parsed,
                                    onUpdate
                                )
                            }
                        }.getOrElse { error ->
                            "error:${error.message ?: "captcha failed"}"
                        }
                        val resultPayload = if (requestId.isBlank()) captchaResult else "$requestId|$captchaResult"
                        writer.write("CAPTCHA_RESULT|$resultPayload\n")
                        writer.flush()
                    } else {
                        val resultPayload = if (requestId.isBlank()) {
                            "error:invalid CAPTCHA_SOLVE format"
                        } else {
                            "$requestId|error:invalid CAPTCHA_SOLVE format"
                        }
                        writer.write("CAPTCHA_RESULT|$resultPayload\n")
                        writer.flush()
                    }
                }
                line.startsWith("HASH_CHECK|") -> {
                    val parts = line.split("|", limit = 5)
                    if (parts.size >= 5) {
                        val order = parts[1].toIntOrNull() ?: continue@readLoop
                        val original = byOrder[order] ?: continue@readLoop
                        currentSlot = null
                        emitHashCheckResult(
                            original.first,
                            HashCheckResult(
                                hash = parts[2],
                                status = parts[3],
                                message = parts[4].ifBlank { hashStatusMessage(parts[3]) }
                            ),
                            parsed,
                            onUpdate
                        )
                    }
                }
            }
        }

        process.waitFor()
    } finally {
        cancellationHandle?.dispose()
        killerThread.interrupt()
        cleanupCheckProcess()
    }

    hashes.associate { (slot, hash) ->
        val fallbackMessage = if (timedOut) "Проверка не завершилась за отведённое время" else "Нет ответа проверки"
        val fallbackStatus = if (timedOut) "network" else "error"
        slot to (parsed[slot] ?: HashCheckResult(hash = hash, status = fallbackStatus, message = fallbackMessage))
    }
}

private fun hashStatusMessage(status: String): String {
    return when (status) {
        "ok" -> "Хеш работает, TURN-креды получены"
        "dead" -> "Звонок не найден или закрыт"
        "blocked" -> "Звонок существует, но в нём запрещён анонимный вход"
        "full" -> "Звонок существует, но сейчас в нём нет свободных мест"
        "captcha" -> "VK запросил капчу, но решить её не удалось"
        "limited" -> "VK временно ограничил запросы"
        "network" -> "Сетевая ошибка при проверке"
        "cancelled" -> "Проверка остановлена"
        else -> "Не удалось проверить хеш"
    }
}

// ═══ Модальное окно секретов ═══
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecretsDialog(
    settingsStore: SettingsStore,
    title: String = "Секреты",
    passwordLabel: String = "Заданный пароль туннеля",
    passwordPlaceholder: String = "Придумайте надежный пароль",
    allowPortsSelection: Boolean = false,
    initialPassword: String,
    manualPortsEnabled: Boolean,
    initialServerDtlsPort: String,
    initialServerWgPort: String,
    initialLocalPort: String,
    onSaved: (String, String, String) -> Unit,
    onDismiss: () -> Unit
) {
    val scope = rememberCoroutineScope()
    var passwordInput by rememberSaveable { mutableStateOf(initialPassword) }
    var passwordFocused by remember { mutableStateOf(false) }
    var serverDtlsPort by rememberSaveable { mutableStateOf(initialServerDtlsPort.ifBlank { "56000" }) }
    var serverWgPort by rememberSaveable { mutableStateOf(initialServerWgPort.ifBlank { "56001" }) }
    var localPort by rememberSaveable { mutableStateOf(initialLocalPort.ifBlank { "9000" }) }
    var portsEnabled by rememberSaveable { mutableStateOf(manualPortsEnabled) }

    fun normalizePort(value: String, fallback: String): String {
        return value.toIntOrNull()?.takeIf { it in 1..65535 }?.toString() ?: fallback
    }

    Dialog(onDismissRequest = onDismiss) {
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
                    modifier = Modifier.padding(24.dp).fillMaxWidth().verticalScroll(rememberScrollState())
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Default.Key,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(24.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(title, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                        }
                        IconButton(onClick = onDismiss) {
                            Icon(imageVector = Icons.Default.Close, contentDescription = "Закрыть")
                        }
                    }

                Spacer(modifier = Modifier.height(16.dp))

                val isPasswordValid = passwordInput.isNotEmpty() && passwordInput.matches(Regex("^[a-zA-Z0-9_.!?:#/-]+$"))

                val passwordInvalid = passwordInput.isNotEmpty() && !isPasswordValid
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    OutlinedTextField(
                        value = passwordInput,
                        onValueChange = { passwordInput = it.filter { c -> !c.isWhitespace() } },
                        label = { Text(passwordLabel) },
                        placeholder = { Text(passwordPlaceholder) },
                        singleLine = true,
                        isError = passwordInvalid,
                        visualTransformation = if (passwordFocused) VisualTransformation.None else PasswordVisualTransformation(),
                        modifier = Modifier
                            .fillMaxWidth()
                            .onFocusChanged { passwordFocused = it.isFocused },
                        shape = RoundedCornerShape(16.dp),
                    )
                    if (passwordInvalid) {
                        FullWidthFieldMessage(
                            text = "Разрешены только буквы, цифры и знаки . ! ? : # - _ /",
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                }

                if (allowPortsSelection) {
                    Spacer(modifier = Modifier.height(12.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 12.dp)) {
                            Text(
                                "Нестандартные порты",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                "Включите, если владелец сервера выдал порты, отличающиеся от стандартных.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Switch(
                            checked = portsEnabled,
                            onCheckedChange = { portsEnabled = it }
                        )
                    }
                }

                if (portsEnabled) {
                    Spacer(modifier = Modifier.height(16.dp))
                    HorizontalDivider()
                    Spacer(modifier = Modifier.height(8.dp))
                    Text("Порты", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.SemiBold)
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = serverDtlsPort,
                        onValueChange = { serverDtlsPort = it.filter(Char::isDigit).take(5) },
                        label = { Text("Порт сервера DTLS") },
                        placeholder = { Text("56000") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = serverWgPort,
                        onValueChange = { serverWgPort = it.filter(Char::isDigit).take(5) },
                        label = { Text("Порт сервера WireGuard") },
                        placeholder = { Text("56001") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = localPort,
                        onValueChange = { localPort = it.filter(Char::isDigit).take(5) },
                        label = { Text("Локальный порт VPN") },
                        placeholder = { Text("9000") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                    )
                }

                Spacer(modifier = Modifier.height(20.dp))

                    Button(
                        onClick = {
                            val finalDtls = normalizePort(serverDtlsPort, "56000")
                            val finalWg = normalizePort(serverWgPort, "56001")
                            val finalLocal = normalizePort(localPort, "9000")
                            scope.launch {
                                settingsStore.saveConnectionPassword(passwordInput)
                                if (allowPortsSelection) {
                                    settingsStore.saveManualPortsEnabled(portsEnabled)
                                }
                                settingsStore.savePorts(finalDtls.toInt(), finalWg.toInt(), finalLocal.toInt())
                                onSaved(finalDtls, finalWg, finalLocal)
                                onDismiss()
                            }
                        },
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                        shape = RoundedCornerShape(16.dp),
                        enabled = isPasswordValid,
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp),
                        colors = ButtonDefaults.buttonColors(contentColor = MaterialTheme.colorScheme.onPrimary)
                    ) {
                        FlexibleButtonText("Сохранить", fontWeight = FontWeight.SemiBold)
                    }
                    Spacer(Modifier.height(4.dp))
                }
            }
        }
    }
}

// extension
private fun androidx.compose.ui.graphics.Color.luminance(): Float {
    val r = red
    val g = green
    val b = blue
    return 0.2126f * r + 0.7152f * g + 0.0722f * b
}
