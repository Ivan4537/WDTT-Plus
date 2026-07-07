package com.wdtt.plus.ui

import android.content.ClipData
import android.content.ClipboardManager
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
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
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Tag
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.wdtt.plus.CaptchaWebViewManager
import com.wdtt.plus.ManlCaptchaWebViewManager
import com.wdtt.plus.SettingsStore
import com.wdtt.plus.TunnelManager
import com.wdtt.plus.TunnelService
import com.wdtt.plus.TrustedWifiManager
import com.wdtt.plus.VkJoinLink
import com.wdtt.plus.WDTTColors
import com.wdtt.plus.WdttDeepLink
import com.wdtt.plus.vpnProfileDisplayName
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import kotlinx.coroutines.CancellationException
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import kotlin.math.roundToInt

private const val WORKERS_PER_GROUP = 9

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
    scrollPosition: MutableIntState = rememberSaveable { mutableIntStateOf(0) }
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val settingsStore = remember { SettingsStore(context) }

    val currentDensity = LocalDensity.current
    CompositionLocalProvider(
        LocalDensity provides Density(currentDensity.density, fontScale = 1f)
    ) {
        SettingsTabContent(context, scope, settingsStore, scrollPosition)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsTabContent(
    context: android.content.Context,
    scope: kotlinx.coroutines.CoroutineScope,
    settingsStore: SettingsStore,
    scrollPosition: MutableIntState
) {
    val savedConnectionPassword by settingsStore.connectionPassword.collectAsStateWithLifecycle(initialValue = "")
    val savedManualPortsEnabled by settingsStore.manualPortsEnabled.collectAsStateWithLifecycle(initialValue = false)
    val savedServerDtlsPort by settingsStore.serverDtlsPort.collectAsStateWithLifecycle(initialValue = 56000)
    val savedServerWgPort by settingsStore.serverWgPort.collectAsStateWithLifecycle(initialValue = 56001)
    val savedListenPort by settingsStore.listenPort.collectAsStateWithLifecycle(initialValue = 9000)

    val activeProfile by settingsStore.activeProfile.collectAsStateWithLifecycle(initialValue = 0)
    val profileNames by settingsStore.profileNames.collectAsStateWithLifecycle(initialValue = emptyList())
    val wdttLinkMode by settingsStore.wdttLinkMode.collectAsStateWithLifecycle(initialValue = false)
    val wdttLink by settingsStore.wdttLink.collectAsStateWithLifecycle(initialValue = "")
    val savedVkHashesState by remember(settingsStore) {
        settingsStore.vkHashes.map<String, String?> { hashes -> hashes }
    }.collectAsStateWithLifecycle(initialValue = null)

    val activeFingerprint by settingsStore.selectedFingerprint.collectAsStateWithLifecycle(initialValue = "firefox")
    val activeClientIds by settingsStore.activeClientIds.collectAsStateWithLifecycle(initialValue = "6287487,8202606")
    val vkCallsPreflight by settingsStore.vkCallsPreflight.collectAsStateWithLifecycle(initialValue = true)

    val tunnelRunning by TunnelManager.running.collectAsStateWithLifecycle()
    val trustedWifiState by TrustedWifiManager.state.collectAsStateWithLifecycle()
    val trustedWifiWaiting = trustedWifiState.waiting
    val connectionIssue by TunnelManager.connectionIssue.collectAsStateWithLifecycle()

    val cooldownActive by TunnelManager.cooldownActive.collectAsStateWithLifecycle()
    var wasRunning by remember { mutableStateOf(false) }

    LaunchedEffect(tunnelRunning) {
        if (wasRunning && !tunnelRunning) {
            TunnelManager.startCooldown(1500L)
        }
        wasRunning = tunnelRunning
    }

    var peerInput by rememberSaveable { mutableStateOf("") }
    var vkHash1 by rememberSaveable { mutableStateOf("") }
    var vkHash2 by rememberSaveable { mutableStateOf("") }
    var vkHash3 by rememberSaveable { mutableStateOf("") }
    var vkHash4 by rememberSaveable { mutableStateOf("") }
    var workersInput by rememberSaveable { mutableFloatStateOf(18f) }
    var showHashesDialog by rememberSaveable { mutableStateOf(false) }
    var autoCaptchaEnabled by rememberSaveable { mutableStateOf(true) }
    var manualPortsEnabled by rememberSaveable { mutableStateOf(false) }
    var showPowerHelp by rememberSaveable { mutableStateOf(false) }
    var showVkCallsHelp by rememberSaveable { mutableStateOf(false) }
    var showAutoCaptchaHelp by rememberSaveable { mutableStateOf(false) }
    var serverDtlsPortInput by rememberSaveable { mutableStateOf("56000") }
    var serverWgPortInput by rememberSaveable { mutableStateOf("56001") }
    var initialized by remember { mutableStateOf(false) }

    val allHashes = remember(vkHash1, vkHash2, vkHash3, vkHash4) {
        listOf(vkHash1, vkHash2, vkHash3, vkHash4).map { stripVkUrlStatic(it) }
    }
    val validHashes = remember(allHashes) { allHashes.filter { it.isNotBlank() && it.length >= 16 } }
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
    val dynamicMaxWorkers = remember(filledHashCount) { maxWorkersForHashCount(filledHashCount) }
    var portInput by rememberSaveable { mutableStateOf("9000") }
    var sniInput by rememberSaveable { mutableStateOf("") }

    val currentWorkers = workersInput.coerceIn(WORKERS_PER_GROUP.toFloat(), dynamicMaxWorkers)

    val hashErrors = remember(vkHash1, vkHash2, vkHash3, vkHash4) {
        buildList {
            allHashes.forEachIndexed { i, h ->
                if (h.isNotBlank() && h.length < 16) add("Хеш ${i + 1} — короткий")
            }
            val filled = allHashes.filter { it.isNotBlank() && it.length >= 16 }
            if (filled.size != filled.distinct().size) add("Есть дубликаты хешей")
        }
    }
    val hasInputHashErrors = remember(vkHash1, vkHash2, vkHash3, vkHash4) { hashErrors.isNotEmpty() }

    var showSecretsDialog by rememberSaveable { mutableStateOf(false) }

    LaunchedEffect(activeProfile) {
        initialized = false
        val peer = settingsStore.peer.first()
        val hashes = settingsStore.vkHashes.first()
        val workers = settingsStore.workersPerHash.first()
        val port = settingsStore.listenPort.first()
        val manualPorts = settingsStore.manualPortsEnabled.first()
        val serverDtlsPort = settingsStore.serverDtlsPort.first()
        val serverWgPort = settingsStore.serverWgPort.first()
        val sni = settingsStore.sni.first()
        val captchaMode = settingsStore.captchaMode.first()
        val captchaMethod = settingsStore.captchaSolveMethod.first()
        val hashSlots = parseVkHashSlots(hashes)
        
        peerInput = peer
        vkHash1 = hashSlots.getOrElse(0) { "" }
        vkHash2 = hashSlots.getOrElse(1) { "" }
        vkHash3 = hashSlots.getOrElse(2) { "" }
        vkHash4 = hashSlots.getOrElse(3) { "" }
        workersInput = roundToGroup(
            workers.toFloat(),
            maxWorkersForHashSlots(hashSlots)
        )
        portInput = port.toString()
        manualPortsEnabled = manualPorts
        serverDtlsPortInput = serverDtlsPort.toString()
        serverWgPortInput = serverWgPort.toString()
        sniInput = sni
        // В интерфейсе остаются только реально отличающиеся стратегии:
        // комбинированная автоцепочка и немедленный ручной WebView.
        // Устаревшие режимы rjs и wv+auto работают как автоматические.
        autoCaptchaEnabled = captchaMode != "wv" || captchaMethod != "manual"
        
        initialized = true
    }

    LaunchedEffect(savedVkHashesState) {
        val savedVkHashes = savedVkHashesState ?: return@LaunchedEffect
        if (initialized && normalizeVkHashSlots(savedVkHashes) != hashSlotsForStorage) {
            val hashSlots = parseVkHashSlots(savedVkHashes)
            vkHash1 = hashSlots.getOrElse(0) { "" }
            vkHash2 = hashSlots.getOrElse(1) { "" }
            vkHash3 = hashSlots.getOrElse(2) { "" }
            vkHash4 = hashSlots.getOrElse(3) { "" }
            val maxWorkers = maxWorkersForHashSlots(hashSlots)
            if (workersInput > maxWorkers) {
                val clamped = roundToGroup(workersInput, maxWorkers)
                workersInput = clamped
                settingsStore.saveWorkersPerHash(clamped.toInt())
            }
        }
    }

    LaunchedEffect(savedManualPortsEnabled) {
        manualPortsEnabled = savedManualPortsEnabled
    }

    LaunchedEffect(savedServerDtlsPort) {
        serverDtlsPortInput = savedServerDtlsPort.toString()
    }

    LaunchedEffect(savedServerWgPort) {
        serverWgPortInput = savedServerWgPort.toString()
    }

    LaunchedEffect(savedListenPort) {
        portInput = savedListenPort.toString()
    }

    if (!initialized) {
        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
        }
        return
    }

    var saveJob by remember { mutableStateOf<Job?>(null) }

    fun saveTunnelSettingsNow(
        hashes: String = hashSlotsForStorage,
        workers: Float = workersInput,
        onSaved: (() -> Unit)? = null
    ) {
        saveJob?.cancel()
        scope.launch {
            val savedLocalPort = if (manualPortsEnabled) portInput.toIntOrNull()?.coerceIn(1, 65535) ?: 9000 else 9000
            settingsStore.save(
                peerInput, hashes, "",
                workers.toInt(), "udp", savedLocalPort, sniInput, false
            )
            onSaved?.invoke()
        }
    }

    fun saveWorkersNow(workers: Float) {
        scope.launch {
            settingsStore.saveWorkersPerHash(workers.toInt())
        }
    }

    fun scheduleSave() {
        saveJob?.cancel()
        saveJob = scope.launch {
            delay(300)
            val savedLocalPort = if (manualPortsEnabled) portInput.toIntOrNull()?.coerceIn(1, 65535) ?: 9000 else 9000
            settingsStore.save(
                peerInput, hashSlotsForStorage, "",
                workersInput.toInt(), "udp", savedLocalPort, sniInput, false
            )
        }
    }

    val scrollState = rememberRememberedScrollState(scrollPosition)

    val isPeerValid = isValidTunnelHost(peerInput)
    val isHashesValid = combinedHashes.isNotBlank()
    val isLinkValid = wdttLinkValidation.canStartVpn
    val isManualValid = isPeerValid && isHashesValid && savedConnectionPassword.isNotBlank() && !hasInputHashErrors
    val isValid = if (wdttLinkMode) isLinkValid else isManualValid
    val effectiveServerDtlsPort = if (manualPortsEnabled) serverDtlsPortInput.toIntOrNull()?.coerceIn(1, 65535) ?: 56000 else 56000
    val effectiveLocalPort = if (manualPortsEnabled) portInput.toIntOrNull()?.coerceIn(1, 65535) ?: 9000 else 9000
    var pendingStartAfterVpnPermission by remember { mutableStateOf(false) }

    fun startTunnelService() {
        val effectiveCaptchaMode = if (autoCaptchaEnabled) "auto" else "wv"
        val effectiveCaptchaSolveMethod = if (autoCaptchaEnabled) "auto" else "manual"
        saveJob?.cancel()
        scope.launch {
            settingsStore.save(
                peerInput, hashSlotsForStorage, "",
                workersInput.toInt(), "udp", effectiveLocalPort, sniInput, false
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
            putExtra("workers_per_hash", workersInput.toInt())
            putExtra("port", finalLocalPort)
            putExtra("sni", sniInput)
            putExtra("connection_password", finalPassword)
            putExtra("vkcalls_preflight", vkCallsPreflight)
            putExtra("captcha_mode", effectiveCaptchaMode)
            putExtra("captcha_solve_method", effectiveCaptchaSolveMethod)
            putExtra("fingerprint", activeFingerprint)
            putExtra("client_ids", activeClientIds)
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

    // ═══ Dialogs ═══
    if (showSecretsDialog) {
        SecretsDialog(
            settingsStore = settingsStore,
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
        val hashCheckCaptchaMode = if (autoCaptchaEnabled) "auto" else "wv"
        HashesDialog(
            hash1 = vkHash1,
            hash2 = vkHash2,
            hash3 = vkHash3,
            hash4 = vkHash4,
            activeFingerprint = activeFingerprint,
            activeClientIds = activeClientIds,
            vkCallsPreflight = vkCallsPreflight,
            captchaMode = hashCheckCaptchaMode,
            selectedWebViewManual = !autoCaptchaEnabled,
            onSave = { h1, h2, h3, h4 ->
                val cleaned1 = stripVkUrlStatic(h1)
                val cleaned2 = stripVkUrlStatic(h2)
                val cleaned3 = stripVkUrlStatic(h3)
                val cleaned4 = stripVkUrlStatic(h4)
                vkHash1 = cleaned1
                vkHash2 = cleaned2
                vkHash3 = cleaned3
                vkHash4 = cleaned4
                val maxWorkers = maxWorkersForHashSlots(listOf(cleaned1, cleaned2, cleaned3, cleaned4))
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

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            if (!wdttLinkMode) {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    // ═══ Заголовок раздела ═══
                    Text(
                        "Настройки туннеля (${vpnProfileDisplayName(activeProfile, profileNames)})",
                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                        color = MaterialTheme.colorScheme.onSurface
                    )

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
                            onClick = { showHashesDialog = true },
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

            // ═══ Мощность + Капча ═══
                AppSectionCard(
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(0.dp)
                ) {
                    // — Мощность —
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Text(
                                "Мощность",
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.primary,
                                fontWeight = FontWeight.SemiBold
                            )
                            IconButton(
                                onClick = { showPowerHelp = true },
                                modifier = Modifier.size(28.dp)
                            ) {
                                Icon(
                                    Icons.AutoMirrored.Filled.HelpOutline,
                                    contentDescription = "Что такое мощность",
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.size(18.dp)
                                )
                            }
                        }
                        Text(
                            text = "${currentWorkers.toInt()}",
                            style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                            color = MaterialTheme.colorScheme.primary
                        )
                    }

                    Spacer(Modifier.height(4.dp))

                    val maxWorkers = dynamicMaxWorkers
                    val minWorkers = WORKERS_PER_GROUP.toFloat()
                    val currentWorkersVal = roundToGroup(currentWorkers.coerceIn(minWorkers, maxWorkers), maxWorkers)

                    CompactSteppedSlider(
                        value = currentWorkersVal,
                        onValueChange = { raw ->
                            val rounded = roundToGroup(raw, maxWorkers)
                            workersInput = rounded
                            saveWorkersNow(rounded)
                        },
                        valueRange = minWorkers..maxWorkers,
                        stepSize = WORKERS_PER_GROUP.toFloat(),
                        enabled = !tunnelRunning,
                        modifier = Modifier.fillMaxWidth()
                    )

                    // — Разделитель —
                    HorizontalDivider(
                        modifier = Modifier.padding(vertical = 4.dp),
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                    )

                    // — VKCalls preflight —
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(
                            modifier = Modifier.weight(1f),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Text(
                                "VKCalls",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.Medium
                            )
                            IconButton(
                                onClick = { showVkCallsHelp = true },
                                modifier = Modifier.size(28.dp)
                            ) {
                                Icon(
                                    Icons.AutoMirrored.Filled.HelpOutline,
                                    contentDescription = "Как работает VKCalls",
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.size(18.dp)
                                )
                            }
                        }
                        Switch(
                            checked = vkCallsPreflight,
                            enabled = !tunnelRunning,
                            onCheckedChange = { enabled ->
                                scope.launch { settingsStore.saveVkCallsPreflight(enabled) }
                            }
                        )
                    }

                    HorizontalDivider(
                        modifier = Modifier.padding(vertical = 4.dp),
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                    )

                    // — Режим капчи —
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column(
                            modifier = Modifier.weight(1f),
                            verticalArrangement = Arrangement.spacedBy(2.dp)
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                Text(
                                    if (autoCaptchaEnabled) "Авто капча" else "Всегда вручную",
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.Medium
                                )
                                IconButton(
                                    onClick = { showAutoCaptchaHelp = true },
                                    modifier = Modifier.size(28.dp)
                                ) {
                                    Icon(
                                        Icons.AutoMirrored.Filled.HelpOutline,
                                        contentDescription = "Как работает режим капчи",
                                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                        modifier = Modifier.size(18.dp)
                                    )
                                }
                            }
                        }
                        Switch(
                            checked = autoCaptchaEnabled,
                            onCheckedChange = { enabled ->
                                autoCaptchaEnabled = enabled
                                scope.launch {
                                    if (enabled) {
                                        settingsStore.saveCaptchaMode("auto")
                                        settingsStore.saveCaptchaSolveMethod("auto")
                                    } else {
                                        settingsStore.saveCaptchaMode("wv")
                                        settingsStore.saveCaptchaSolveMethod("manual")
                                        settingsStore.saveWbvCaptchaSolveMethod("manual")
                                    }
                                }
                            }
                        )
                    }

                    HorizontalDivider(
                        modifier = Modifier.padding(vertical = 4.dp),
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                    )

                    // — Режим ссылки —
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 8.dp, bottom = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            "Режим ссылки",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium,
                            modifier = Modifier.weight(1f)
                        )
                        Switch(
                            checked = wdttLinkMode,
                            onCheckedChange = { enabled ->
                                scope.launch {
                                    settingsStore.saveWdttLinkMode(enabled)
                                }
                            }
                        )
                    }

                    if (wdttLinkMode) {
                        Column {
                            var linkText by remember(wdttLink) { mutableStateOf(wdttLink) }
                            val linkValidation = remember(linkText) { WdttDeepLink.validate(linkText) }
                            val linkInvalid = linkText.isNotBlank() && !linkValidation.canStartVpn
                            OutlinedTextField(
                                value = linkText,
                                onValueChange = {
                                    val cleaned = it.filter { c -> !c.isWhitespace() }
                                    linkText = cleaned
                                    scope.launch { settingsStore.saveWdttLink(cleaned) }
                                },
                                label = { Text("Ссылка wdtt://") },
                                placeholder = { Text("Ссылка wdtt://") },
                                isError = linkInvalid,
                                supportingText = {
                                    if (linkText.isNotBlank()) {
                                        Text(linkValidation.userMessage())
                                    }
                                },
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(16.dp),
                                colors = OutlinedTextFieldDefaults.colors(
                                    focusedBorderColor = MaterialTheme.colorScheme.primary,
                                    unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f),
                                )
                            )
                        }
                    }
                }
            }

        // ═══ Кнопки: Секреты + Подключить ═══
        val tunnelSecretsMissing = savedConnectionPassword.isBlank()

        Row(
            modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            if (!wdttLinkMode) {
                OutlinedButton(
                    onClick = { showSecretsDialog = true },
                    modifier = Modifier.weight(1f).fillMaxHeight().heightIn(min = 52.dp),
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
                    FlexibleButtonText("Секреты", fontWeight = FontWeight.SemiBold)
                }
            }

            val buttonColor by animateColorAsState(
                targetValue = if (tunnelRunning || trustedWifiWaiting) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                animationSpec = tween(400),
                label = "btn_color"
            )

            Button(
                onClick = {
                    if (tunnelRunning || trustedWifiWaiting) {
                        context.startService(
                            Intent(context, TunnelService::class.java).apply { action = "STOP" }
                        )
                    } else {
                        TunnelManager.clearConnectionIssue()
                        requestVpnAndStart()
                    }
                },
                enabled = (isValid && !cooldownActive) || tunnelRunning || trustedWifiWaiting,
                modifier = Modifier
                    .weight(1f)
                    .fillMaxHeight()
                    .heightIn(min = 52.dp),
                shape = RoundedCornerShape(16.dp),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 8.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = buttonColor,
                    contentColor = MaterialTheme.colorScheme.onPrimary
                )
            ) {
                Icon(
                    imageVector = if (tunnelRunning || trustedWifiWaiting) Icons.Default.Stop else Icons.Default.PowerSettingsNew,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(Modifier.width(6.dp))
                FlexibleButtonText(
                    text = when {
                        tunnelRunning -> "Остановить"
                        trustedWifiWaiting -> "Отменить ожидание"
                        cooldownActive -> "Подождите..."
                        else -> "Подключить"
                    },
                    fontWeight = FontWeight.Bold
                )
            }
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

        connectionIssue?.let { issue ->
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

    if (showPowerHelp) {
        PowerHelpDialog(
            minWorkers = WORKERS_PER_GROUP,
            maxWorkers = dynamicMaxWorkers.toInt(),
            currentWorkers = currentWorkers.toInt(),
            onDismiss = { showPowerHelp = false }
        )
    }
    if (showVkCallsHelp) {
        SettingsHelpDialog(
            title = "VKCalls",
            paragraphs = listOf(
                "Сначала приложение пробует получить TURN-учётные данные через анонимный режим VKCalls без VK Smart Captcha.",
                "Обычно это быстрее и стабильнее. Если VKCalls не сработал, VK временно ограничил анонимный вход или всё равно запросил проверку, приложение автоматически переходит к обычной captcha-цепочке."
            ),
            onDismiss = { showVkCallsHelp = false }
        )
    }
    if (showAutoCaptchaHelp) {
        SettingsHelpDialog(
            title = "Режим капчи",
            paragraphs = listOf(
                "Авто капча: каждый свежий challenge сначала решается через Auto WebView. Go v2 и ручной WebView используются как запасные этапы, если автоматический WebView не дал рабочий токен или VK потребовал более строгую проверку.",
                "Всегда вручную: при запросе капчи приложение сразу открывает WebView для самостоятельного прохождения проверки."
            ),
            onDismiss = { showAutoCaptchaHelp = false }
        )
    }
}

@Composable
private fun SettingsHelpDialog(
    title: String,
    paragraphs: List<String>,
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
                            title,
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary
                        )
                        IconButton(onClick = onDismiss) {
                            Icon(Icons.Default.Close, contentDescription = "Закрыть")
                        }
                    }
                    paragraphs.forEach { paragraph ->
                        Text(
                            paragraph,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
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
            .height(34.dp)
            .pointerInput(enabled, valueRange, stepSize) {
                if (!enabled) return@pointerInput
                detectTapGestures { offset ->
                    onValueChange(positionToValue(offset.x, size.width.toFloat()))
                }
            }
            .pointerInput(enabled, valueRange, stepSize) {
                if (!enabled) return@pointerInput
                detectDragGestures { change, _ ->
                    onValueChange(positionToValue(change.position.x, size.width.toFloat()))
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
                        "В боковых настройках доступны VPN 1, VPN 2 и VPN 3. Короткое нажатие переключает профиль, долгое нажатие позволяет переименовать его."
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
                        "Обычное подключение передаётся через «Настройки» → «Передать или получить». Перенос отдельного клиента выполняется именно в блоке «Клиенты и сервер»."
                    )
                    InfoSection(
                        "После новых серверных функций",
                        "Если приложение пишет, что сервер не поддерживает действие, выполните во вкладке «Деплой» установку сервера с сохранением данных."
                    )
                    InfoSection(
                        "Капча и мощность",
                        "Авто-режим старается пройти капчу сам. Несколько VK-хешей распределяют нагрузку, а мощность лучше держать умеренной: чем она выше, тем больше расход батареи и шанс чаще видеть капчу."
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

private fun maxWorkersForHashCount(hashCount: Int): Float {
    return (hashCount.coerceAtLeast(1) * 27).toFloat()
}

private fun maxWorkersForHashSlots(hashSlots: List<String>): Float {
    return maxWorkersForHashCount(
        hashSlots.count { slot ->
            val hash = stripVkUrlStatic(slot)
            hash.isNotBlank() && hash.length >= 16
        }
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

// ═══ Модальное окно хешей ═══
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HashesDialog(
    hash1: String,
    hash2: String,
    hash3: String,
    hash4: String,
    activeFingerprint: String,
    activeClientIds: String,
    vkCallsPreflight: Boolean,
    captchaMode: String,
    selectedWebViewManual: Boolean,
    onSave: (String, String, String, String) -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var h1 by remember { mutableStateOf(hash1) }
    var h2 by remember { mutableStateOf(hash2) }
    var h3 by remember { mutableStateOf(hash3) }
    var h4 by remember { mutableStateOf(hash4) }
    var isChecking by remember { mutableStateOf(false) }
    var checkJob by remember { mutableStateOf<Job?>(null) }
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
            if (hash.length >= 16) index + 1 to hash else null
        }
    }
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
    fun closeDialog() {
        cancelHashCheck()
        onDismiss()
    }

    DisposableEffect(Unit) {
        onDispose {
            cancelHashCheck(updateUi = false)
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
                        }
                        IconButton(onClick = { closeDialog() }) {
                            Icon(Icons.Default.Close, contentDescription = "Закрыть")
                        }
                    }

                    Text(
                        text = if (isChecking) {
                            val current = currentCheckSlot?.let { " Сейчас: VK Хеш $it." } ?: ""
                            "Проверено $completedChecks из ${checkableHashes.size}.$current"
                        } else {
                            "Больше хешей — выше лимит потоков и лучшее распределение нагрузки."
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(bottom = 4.dp)
                    )

                listOf(
                    Triple("VK Хеш 1 *", h1) { v: String -> h1 = v },
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
                        onCopyClick = { copyVkHashesToClipboard(context, "VK Хеш $slot", cleanedValue) }
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

                Button(
                    onClick = {
                        cancelHashCheck()
                        onSave(h1, h2, h3, h4)
                    },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                    shape = RoundedCornerShape(16.dp),
                    enabled = h1.isNotBlank() && h1.length >= 16,
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp),
                    colors = ButtonDefaults.buttonColors(contentColor = MaterialTheme.colorScheme.onPrimary)
                ) {
                    FlexibleButtonText("Сохранить", fontWeight = FontWeight.SemiBold)
                }
            }
        }
    }
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
    onCopyClick: () -> Unit
) {
    val isShort = value.isNotBlank() && value.length < 16
    val visibleResult = result?.takeIf { it.status != "pending" }
    val statusColor = visibleResult?.let { hashStatusColor(it.status) }
    val borderColor = when {
        isShort -> MaterialTheme.colorScheme.error
        statusColor != null -> statusColor
        else -> MaterialTheme.colorScheme.outline.copy(alpha = 0.45f)
    }
    val progressMessage = visibleResult
        ?.takeIf { it.status in setOf("checking", "solving_captcha") }
        ?.message

    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        placeholder = { Text("Ссылка звонка или хеш") },
        singleLine = true,
        isError = isShort,
        supportingText = when {
            isShort -> {
                { Text("Хеш $slot — короткий (мин. 16)", color = MaterialTheme.colorScheme.error) }
            }
            progressMessage != null -> {
                { Text(progressMessage, color = borderColor) }
            }
            else -> null
        },
        trailingIcon = {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(2.dp)
            ) {
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
            focusedLabelColor = borderColor,
            cursorColor = MaterialTheme.colorScheme.primary
        )
    )
}

@Composable
private fun hashStatusColor(status: String): Color {
    return when (status) {
        "ok" -> WDTTColors.connected
        "dead" -> MaterialTheme.colorScheme.error
        "captcha", "solving_captcha", "limited", "network" -> WDTTColors.warning
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
    vkCallsPreflight: Boolean,
    captchaMode: String,
    selectedWebViewManual: Boolean,
    onUpdate: (Int, HashCheckResult) -> Unit
): Map<Int, HashCheckResult> = withContext(Dispatchers.IO) {
    if (hashes.isEmpty()) return@withContext emptyMap()
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
        android.provider.Settings.Secure.getString(
            context.contentResolver,
            android.provider.Settings.Secure.ANDROID_ID
        ) ?: "unknown"
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
                            Text("Секреты", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                        }
                        IconButton(onClick = onDismiss) {
                            Icon(imageVector = Icons.Default.Close, contentDescription = "Закрыть")
                        }
                    }

                Spacer(modifier = Modifier.height(16.dp))

                val isPasswordValid = passwordInput.isNotEmpty() && passwordInput.matches(Regex("^[a-zA-Z0-9_.!?:#/-]+$"))

                OutlinedTextField(
                    value = passwordInput,
                    onValueChange = { passwordInput = it.filter { c -> !c.isWhitespace() } },
                    label = { Text("Заданный пароль туннеля") },
                    placeholder = { Text("Придумайте надежный пароль") },
                    singleLine = true,
                    isError = passwordInput.isNotEmpty() && !isPasswordValid,
                    supportingText = if (passwordInput.isNotEmpty() && !isPasswordValid) {
                        { Text("Разрешены только буквы, цифры и знаки . ! ? : # - _ /", color = MaterialTheme.colorScheme.error) }
                    } else null,
                    visualTransformation = if (passwordFocused) VisualTransformation.None else PasswordVisualTransformation(),
                    modifier = Modifier
                        .fillMaxWidth()
                        .onFocusChanged { passwordFocused = it.isFocused },
                    shape = RoundedCornerShape(16.dp),
                )

                if (manualPortsEnabled) {
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
