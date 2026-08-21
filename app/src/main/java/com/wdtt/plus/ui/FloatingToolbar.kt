package com.wdtt.plus.ui

import android.content.Intent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.wdtt.plus.SettingsStore
import com.wdtt.plus.SleepBatteryMode
import com.wdtt.plus.TunnelManager
import com.wdtt.plus.TunnelService
import com.wdtt.plus.TunnelStopCoordinator
import com.wdtt.plus.TunnelStopResult
import com.wdtt.plus.sanitizeVpnProfileNameInput
import com.wdtt.plus.vpnProfileDefaultName
import com.wdtt.plus.vpnProfileDisplayName
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.wdtt.plus.R
import android.os.Build
import androidx.compose.ui.graphics.Color
import kotlin.math.roundToInt

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Share
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import android.widget.Toast
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

private const val PROFILE_RESET_TIMEOUT_MS = 10_000L

@OptIn(ExperimentalLayoutApi::class, ExperimentalFoundationApi::class)
@Composable
fun FloatingToolbar(
    settingsStore: SettingsStore,
    activeProfile: Int,
    profileNames: List<String>,
    onActiveProfileChange: (Int) -> Unit,
    onProfileNameChange: (Int, String) -> Unit,
    interfaceRole: String,
    adminModeAllowed: Boolean,
    onInterfaceRoleChange: (String) -> Unit,
    currentTheme: String,
    onThemeChange: (String) -> Unit,
    isDynamicColor: Boolean,
    onDynamicColorChange: (Boolean) -> Unit,
    currentPalette: String,
    onPaletteChange: (String) -> Unit,
    activeFingerprint: String,
    onFingerprintChange: (String) -> Unit,
    activeClientIds: String,
    onClientIdsChange: (String) -> Unit,
    onTransferRequested: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val trustedWifiEnabled by settingsStore.trustedWifiEnabled.collectAsStateWithLifecycle(initialValue = false)
    val trustedWifiSsids by settingsStore.trustedWifiSsids.collectAsStateWithLifecycle(initialValue = emptyList())
    val trustedWifiRuntime by com.wdtt.plus.TrustedWifiManager.state.collectAsStateWithLifecycle()
    val pauseVpnDuringSleep by settingsStore.pauseVpnDuringSleep.collectAsStateWithLifecycle(initialValue = false)
    val pauseVpnDuringSleepDelayMinutes by
        settingsStore.pauseVpnDuringSleepDelayMinutes.collectAsStateWithLifecycle(initialValue = 5)
    val sleepBatteryMode by
        settingsStore.sleepBatteryMode.collectAsStateWithLifecycle(initialValue = SleepBatteryMode.DELAYED_PAUSE)
    val resumeVpnDuringSleepDelayMinutes by
        settingsStore.resumeVpnDuringSleepDelayMinutes.collectAsStateWithLifecycle(initialValue = 5)
    val sleepBatterySettingsConfigured by
        settingsStore.sleepBatterySettingsConfigured.collectAsStateWithLifecycle(initialValue = false)
    val customVkCredentialsEnabled by settingsStore.customVkCredentialsEnabled.collectAsStateWithLifecycle(initialValue = false)
    val customVkCredentialsComplete by settingsStore.customVkCredentialsComplete.collectAsStateWithLifecycle(initialValue = false)
    val savedToolbarYFraction by settingsStore.floatingToolbarYFraction.collectAsStateWithLifecycle(
        initialValue = -2f
    )
    val tunnelRunning by TunnelManager.running.collectAsStateWithLifecycle()
    val tunnelTransition by TunnelManager.transition.collectAsStateWithLifecycle()
    val connectedProfile by TunnelManager.activeTunnelProfile.collectAsStateWithLifecycle()
    val configuration = LocalConfiguration.current
    val density = LocalDensity.current
    val screenHeightPx = remember(configuration.screenHeightDp, density) {
        with(density) { configuration.screenHeightDp.dp.toPx() }
    }
    val screenWidthPx = remember(configuration.screenWidthDp, density) {
        with(density) { configuration.screenWidthDp.dp.toPx() }
    }

    var parentWidthPx by remember { mutableFloatStateOf(0f) }
    var parentHeightPx by remember { mutableFloatStateOf(0f) }

    var offsetY by remember { mutableFloatStateOf(-1f) }
    var toolbarPositionRestored by remember { mutableStateOf(false) }
    var isRightSide by rememberSaveable { mutableStateOf(true) }
    var isExpanded by rememberSaveable { mutableStateOf(false) }
    var tabHeightPx by remember { mutableFloatStateOf(0f) }
    var panelHeightPx by remember { mutableFloatStateOf(0f) }
    var renamingProfile by remember { mutableStateOf<Int?>(null) }
    var resettingProfile by remember { mutableStateOf<Int?>(null) }
    var resetCountdown by remember { mutableIntStateOf(5) }
    var resetInProgress by remember { mutableStateOf(false) }
    var profileNameInput by rememberSaveable { mutableStateOf("") }
    var showTrustedWifiSettings by rememberSaveable { mutableStateOf(false) }
    var enableTrustedWifiAfterSetup by rememberSaveable { mutableStateOf(false) }
    var showVkClientSettings by rememberSaveable { mutableStateOf(false) }
    var showSleepTimerSettings by rememberSaveable { mutableStateOf(false) }

    val tabWidthDp = 42.dp
    val tabHeightDp = 52.dp
    val panelWidthDp = 220.dp
    // Move the thumb immediately on tap instead of waiting for the DataStore round trip.
    // The persisted value still remains the source of truth and resynchronizes this state.
    var displayedInterfaceRole by remember(interfaceRole, adminModeAllowed) {
        mutableStateOf(if (adminModeAllowed) interfaceRole else "user")
    }
    val isAdminRole = adminModeAllowed && displayedInterfaceRole == "admin"

    LaunchedEffect(resettingProfile) {
        resetCountdown = 5
        if (resettingProfile != null) {
            while (resetCountdown > 0) {
                delay(1_000L)
                resetCountdown--
            }
        }
    }

    val tabWidthPx = remember(density) { with(density) { tabWidthDp.toPx() } }
    val fallbackTabHeightPx = remember(density) { with(density) { tabHeightDp.toPx() } }
    val edgePaddingPx = remember(density) { with(density) { 8.dp.toPx() } }
    val safeTopPx = WindowInsets.safeDrawing.getTop(density).toFloat()
    val safeBottomPx = WindowInsets.safeDrawing.getBottom(density).toFloat()
    val effectiveTabHeightPx = maxOf(tabHeightPx, fallbackTabHeightPx)
    val floatingHeightPx = if (isExpanded && panelHeightPx > 0f) {
        maxOf(effectiveTabHeightPx, panelHeightPx)
    } else {
        effectiveTabHeightPx
    }
    
    val currentParentHeight = if (parentHeightPx > 0f) parentHeightPx else screenHeightPx
    val currentParentWidth = if (parentWidthPx > 0f) parentWidthPx else screenWidthPx

    val minOffsetY = safeTopPx + edgePaddingPx
    val maxOffsetY = (currentParentHeight - safeBottomPx - floatingHeightPx - edgePaddingPx)
        .coerceAtLeast(minOffsetY)
    val defaultOffsetY = (currentParentHeight * 0.30f).coerceIn(minOffsetY, maxOffsetY)

    val targetXPx = if (isRightSide) currentParentWidth - tabWidthPx else 0f

    val animatedTabXPx by animateFloatAsState(
        targetValue = targetXPx,
        animationSpec = spring(stiffness = Spring.StiffnessLow),
        label = "tab_shift"
    )

    LaunchedEffect(savedToolbarYFraction, minOffsetY, maxOffsetY) {
        if (savedToolbarYFraction < -1f) return@LaunchedEffect
        offsetY = if (!toolbarPositionRestored || offsetY < 0f) {
            if (savedToolbarYFraction >= 0f && maxOffsetY > minOffsetY) {
                minOffsetY + (maxOffsetY - minOffsetY) * savedToolbarYFraction
            } else {
                defaultOffsetY
            }
        } else {
            offsetY.coerceIn(minOffsetY, maxOffsetY)
        }
        toolbarPositionRestored = true
    }

    fun persistToolbarPosition() {
        if (!toolbarPositionRestored) return
        val availableRange = maxOffsetY - minOffsetY
        val fraction = if (availableRange > 0f) {
            ((offsetY - minOffsetY) / availableRange).coerceIn(0f, 1f)
        } else {
            0f
        }
        scope.launch { settingsStore.saveFloatingToolbarYFraction(fraction) }
    }

    Box(
        modifier = modifier
            .fillMaxSize()
            .onGloballyPositioned { coordinates ->
                parentWidthPx = coordinates.size.width.toFloat()
                parentHeightPx = coordinates.size.height.toFloat()
            }
    ) {
        Surface(
            onClick = { isExpanded = !isExpanded },
            modifier = Modifier
                .offset { IntOffset(animatedTabXPx.roundToInt(), offsetY.roundToInt()) }
                .onGloballyPositioned { coordinates ->
                    tabHeightPx = coordinates.size.height.toFloat()
                }
                .pointerInput(minOffsetY, maxOffsetY) {
                    detectDragGestures(
                        onDragEnd = { persistToolbarPosition() },
                        onDragCancel = { persistToolbarPosition() },
                        onDrag = { change, dragAmount ->
                            change.consume()
                            offsetY = (offsetY + dragAmount.y).coerceIn(minOffsetY, maxOffsetY)
                        }
                    )
                },
            shape = if (isRightSide)
                RoundedCornerShape(topStart = 14.dp, bottomStart = 14.dp)
            else
                RoundedCornerShape(topEnd = 14.dp, bottomEnd = 14.dp),
            color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.9f),
            shadowElevation = 0.dp,
            tonalElevation = 0.dp,
        ) {
            Box(
                modifier = Modifier.size(tabWidthDp, tabHeightDp),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Filled.Settings,
                    contentDescription = "Настройки",
                    modifier = Modifier.size(22.dp),
                    tint = MaterialTheme.colorScheme.onPrimaryContainer
                )
            }
        }

        if (isExpanded) {
            Dialog(
                onDismissRequest = { isExpanded = false },
                properties = DialogProperties(usePlatformDefaultWidth = false)
            ) {
                val dialogMaxHeight = (configuration.screenHeightDp.dp - 32.dp).coerceAtLeast(360.dp)
                Surface(
                    shape = RoundedCornerShape(32.dp),
                    color = MaterialTheme.colorScheme.surface,
                    shadowElevation = 8.dp,
                    tonalElevation = 8.dp,
                    modifier = Modifier
                        .fillMaxWidth(0.9f)
                        .heightIn(max = dialogMaxHeight)
                ) {
                    Column(
                        modifier = Modifier
                            .padding(16.dp)
                            .fillMaxWidth()
                            .animateContentSize(animationSpec = spring(stiffness = Spring.StiffnessMediumLow))
                            .verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            "Настройки",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        IconButton(
                            onClick = { isExpanded = false },
                            modifier = Modifier.size(24.dp)
                        ) {
                            Icon(
                                Icons.Filled.Close,
                                contentDescription = "Close",
                                tint = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }

                    FlowRow(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        listOf(0, 1, 2).forEach { profile ->
                            val selected = profile == activeProfile
                            val profileLabel = vpnProfileDisplayName(profile, profileNames)
                            val profileShape = RoundedCornerShape(12.dp)
                            Surface(
                                shape = profileShape,
                                color = if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                                modifier = Modifier
                                    .widthIn(min = 72.dp, max = 180.dp)
                                    .clip(profileShape)
                                    .combinedClickable(
                                        onClick = {
                                            onActiveProfileChange(profile)
                                            isExpanded = false
                                        },
                                        onLongClick = {
                                            renamingProfile = profile
                                            profileNameInput = profileLabel
                                        }
                                    )
                            ) {
                                Box(
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 8.dp),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Text(
                                        text = profileLabel,
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
                                        color = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
                                        fontSize = 12.sp,
                                        textAlign = TextAlign.Center
                                    )
                                }
                            }
                        }
                    }

                    OutlinedButton(
                        onClick = {
                            onTransferRequested()
                        },
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Icon(Icons.Filled.Share, contentDescription = null, modifier = Modifier.size(18.dp))
                        Text(" Получить или передать", fontSize = 12.sp)
                    }

                    HorizontalDivider(
                        modifier = Modifier.padding(vertical = 4.dp),
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                    )

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 4.dp, vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(
                            modifier = Modifier
                                .weight(1f)
                                .clickable {
                                    enableTrustedWifiAfterSetup = false
                                    showTrustedWifiSettings = true
                                }
                                .padding(end = 10.dp)
                        ) {
                            Text(
                                "Доверенные сети Wi‑Fi",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Text(
                                when {
                                    trustedWifiRuntime.waiting -> "VPN ожидает выхода из сети"
                                    trustedWifiSsids.isEmpty() ->
                                        "Сети не настроены · нажмите для настройки"
                                    trustedWifiEnabled ->
                                        "Включено · сетей: ${trustedWifiSsids.size}"
                                    else ->
                                        "Выключено · сохранено сетей: ${trustedWifiSsids.size}"
                                },
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                lineHeight = 15.sp
                            )
                        }
                        Switch(
                            checked = trustedWifiEnabled,
                            onCheckedChange = { enabled ->
                                if (enabled && trustedWifiSsids.isEmpty()) {
                                    enableTrustedWifiAfterSetup = true
                                    showTrustedWifiSettings = true
                                } else {
                                    scope.launch {
                                        settingsStore.saveTrustedWifiEnabled(enabled)
                                        if (TunnelManager.running.value || trustedWifiRuntime.waiting) {
                                            runCatching {
                                                context.startService(
                                                    Intent(context, TunnelService::class.java).apply {
                                                        action = "TRUSTED_WIFI_RECHECK"
                                                    }
                                                )
                                            }
                                        }
                                    }
                                }
                            },
                            modifier = Modifier.scale(0.85f)
                        )
                    }

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { showSleepTimerSettings = true }
                            .padding(horizontal = 4.dp, vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 10.dp)) {
                            Text(
                                "Экономия батареи во сне",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Text(
                                if (pauseVpnDuringSleep) {
                                    when (sleepBatteryMode) {
                                        SleepBatteryMode.DELAYED_PAUSE ->
                                            if (pauseVpnDuringSleepDelayMinutes == 0) {
                                                "Отключение сразу после выключения экрана"
                                            } else {
                                                "Отключение через ${formatSleepTimerDuration(pauseVpnDuringSleepDelayMinutes)}"
                                            }
                                        SleepBatteryMode.TIMED_PAUSE ->
                                            if (resumeVpnDuringSleepDelayMinutes == 0) {
                                                "Таймер 0 мин · VPN останется активным"
                                            } else {
                                                "Сразу выключится · включение через ${formatSleepTimerDuration(resumeVpnDuringSleepDelayMinutes)}"
                                            }
                                    }
                                } else {
                                    if (sleepBatterySettingsConfigured) {
                                        when (sleepBatteryMode) {
                                            SleepBatteryMode.DELAYED_PAUSE ->
                                                if (pauseVpnDuringSleepDelayMinutes == 0) {
                                                    "Выключено · сохранено немедленное отключение"
                                                } else {
                                                    "Выключено · сохранено отключение через ${formatSleepTimerDuration(pauseVpnDuringSleepDelayMinutes)}"
                                                }
                                            SleepBatteryMode.TIMED_PAUSE ->
                                                if (resumeVpnDuringSleepDelayMinutes == 0) {
                                                    "Выключено · сохранён таймер 0 мин"
                                                } else {
                                                    "Выключено · сохранено включение через ${formatSleepTimerDuration(resumeVpnDuringSleepDelayMinutes)}"
                                                }
                                        }
                                    } else {
                                        "VPN остаётся активным · нажмите для настройки"
                                    }
                                },
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                lineHeight = 15.sp
                            )
                        }
                        Switch(
                            checked = pauseVpnDuringSleep,
                            onCheckedChange = { enabled ->
                                if (enabled) {
                                    if (sleepBatterySettingsConfigured) {
                                        scope.launch {
                                            settingsStore.savePauseVpnDuringSleep(true)
                                            TunnelManager.noteSleepBatteryEvent(
                                                "settings_enabled",
                                                "Экономия батареи во сне включена; сохранённый сценарий применится при следующем выключении экрана.",
                                            )
                                        }
                                    } else {
                                        showSleepTimerSettings = true
                                    }
                                } else {
                                    scope.launch {
                                        settingsStore.savePauseVpnDuringSleep(false)
                                        TunnelManager.noteSleepBatteryEvent(
                                            "settings_disabled",
                                            "Экономия батареи во сне выключена.",
                                        )
                                    }
                                }
                            },
                            modifier = Modifier.scale(0.85f)
                        )
                    }

                    HorizontalDivider(
                        modifier = Modifier.padding(vertical = 4.dp),
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 10.dp)) {
                            Text(
                                if (isAdminRole) "Режим: Админ" else "Режим: Юзер",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Text(
                                when {
                                    !adminModeAllowed ->
                                        "Режим «Админ» доступен для самостоятельного профиля"
                                    isAdminRole ->
                                        "VPN и настройка своего сервера"
                                    else ->
                                        "Подключение и работа VPN"
                                },
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                lineHeight = 15.sp
                            )
                        }
                        Switch(
                            checked = isAdminRole,
                            onCheckedChange = { checked ->
                                val role = if (checked) "admin" else "user"
                                if (role != displayedInterfaceRole) {
                                    displayedInterfaceRole = role
                                    onInterfaceRoleChange(role)
                                }
                            },
                            enabled = adminModeAllowed,
                            modifier = Modifier.scale(0.85f)
                        )
                    }

                    HorizontalDivider(
                        modifier = Modifier.padding(vertical = 4.dp),
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                    )

                    Text(
                        "Тема",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.padding(start = 4.dp, bottom = 4.dp)
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        ThemeOption(
                            icon = R.drawable.ic_auto,
                            contentDescription = "Системная тема",
                            selected = currentTheme == "system",
                            onClick = { onThemeChange("system") },
                            modifier = Modifier.weight(1f)
                        )
                        ThemeOption(
                            icon = R.drawable.ic_light_mode,
                            contentDescription = "Светлая тема",
                            selected = currentTheme == "light",
                            onClick = { onThemeChange("light") },
                            modifier = Modifier.weight(1f)
                        )
                        ThemeOption(
                            icon = R.drawable.ic_dark_mode,
                            contentDescription = "Тёмная тема",
                            selected = currentTheme == "dark",
                            onClick = { onThemeChange("dark") },
                            modifier = Modifier.weight(1f)
                        )
                    }

                    val supportsDynamicColor = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
                    val showDynamicColorOn = isDynamicColor && supportsDynamicColor
                    val showPalettes = !showDynamicColorOn

                    Row(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            "Динамические",
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Medium,
                            color = if (supportsDynamicColor) {
                                MaterialTheme.colorScheme.onSurfaceVariant
                            } else {
                                MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                            }
                        )
                        Switch(
                            checked = showDynamicColorOn,
                            onCheckedChange = { onDynamicColorChange(it) },
                            enabled = supportsDynamicColor,
                            modifier = Modifier.scale(0.8f)
                        )
                    }

                    AnimatedVisibility(
                        visible = showPalettes,
                        enter = expandVertically(animationSpec = spring(stiffness = Spring.StiffnessMediumLow)) + fadeIn(),
                        exit = shrinkVertically(animationSpec = spring(stiffness = Spring.StiffnessMediumLow)) + fadeOut()
                    ) {
                        Column(modifier = Modifier.fillMaxWidth()) {
                            HorizontalDivider(
                                modifier = Modifier.padding(vertical = 4.dp),
                                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                            )
                            Text(
                                "Палитра",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(bottom = 6.dp, start = 4.dp)
                            )
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceEvenly
                            ) {
                                PaletteCircle("indigo", 0xFF5B588D, currentPalette, onPaletteChange)
                                PaletteCircle("forest", 0xFF5F5D68, currentPalette, onPaletteChange)
                                PaletteCircle("espresso", 0xFF6D4C41, currentPalette, onPaletteChange)
                            }
                            Spacer(modifier = Modifier.height(6.dp))
                        }
                    }

                    HorizontalDivider(
                        modifier = Modifier.padding(vertical = 4.dp),
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                    )

                    Text(
                        "Отпечаток",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.padding(start = 4.dp, bottom = 4.dp)
                    )

                    val fingerprints = listOf("firefox", "chrome", "safari")
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp),
                        horizontalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        fingerprints.forEach { fp ->
                            val selected = fp == activeFingerprint
                            Surface(
                                onClick = { onFingerprintChange(fp) },
                                shape = RoundedCornerShape(8.dp),
                                color = if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                                modifier = Modifier.weight(1f)
                            ) {
                                Box(
                                    modifier = Modifier.padding(vertical = 10.dp),
                                    contentAlignment = Alignment.Center
                                ) {
                                    val fpName = when(fp) {
                                        "chrome" -> "Chrome"
                                        "safari" -> "Safari"
                                        "firefox" -> "Firefox"
                                        else -> fp.replaceFirstChar { it.uppercaseChar() }
                                    }
                                    Text(
                                        text = fpName,
                                        style = MaterialTheme.typography.bodySmall,
                                        fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
                                        color = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
                                        fontSize = 11.sp
                                    )
                                }
                            }
                        }
                    }

                    HorizontalDivider(
                        modifier = Modifier.padding(vertical = 4.dp),
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                    )

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { showVkClientSettings = true }
                            .padding(horizontal = 4.dp, vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 10.dp)) {
                            Text(
                                "Клиенты VK",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Text(
                                when {
                                    !customVkCredentialsEnabled -> "VKCalls → встроенный резерв"
                                    customVkCredentialsComplete -> "VKCalls → свой → встроенный резерв"
                                    else -> "Заполните резервные реквизиты"
                                },
                                style = MaterialTheme.typography.bodySmall,
                                color = if (customVkCredentialsEnabled && !customVkCredentialsComplete) {
                                    MaterialTheme.colorScheme.error
                                } else {
                                    MaterialTheme.colorScheme.onSurfaceVariant
                                },
                                lineHeight = 15.sp
                            )
                        }
                        Switch(
                            checked = customVkCredentialsEnabled,
                            onCheckedChange = null,
                            modifier = Modifier.scale(0.85f)
                        )
                    }
                }
            }
        }
    }

    renamingProfile?.let { profile ->
        ProfileMenuDialog(
            profileNameInput = profileNameInput,
            onProfileNameInputChange = { profileNameInput = sanitizeVpnProfileNameInput(it) },
            onResetRequested = {
                resetCountdown = 5
                resettingProfile = profile
            },
            onSave = {
                onProfileNameChange(profile, profileNameInput)
                renamingProfile = null
            },
            onDismiss = { renamingProfile = null }
        )
    }

    resettingProfile?.let { profile ->
        val profileLabel = vpnProfileDisplayName(profile, profileNames)
        val potentiallyConnectedProfile = profile == (connectedProfile ?: activeProfile)
        val resetsConnectedProfile = potentiallyConnectedProfile &&
            (tunnelRunning || tunnelTransition != com.wdtt.plus.TunnelTransition.IDLE)
        ProfileResetDialog(
            profileLabel = profileLabel,
            defaultProfileLabel = vpnProfileDefaultName(profile),
            countdown = resetCountdown,
            inProgress = resetInProgress,
            disconnectsActiveVpn = resetsConnectedProfile,
            onConfirm = {
                if (resetCountdown > 0 || resetInProgress) return@ProfileResetDialog
                resetInProgress = true
                scope.launch {
                    runCatching {
                        if (potentiallyConnectedProfile) {
                            val stopResult = TunnelStopCoordinator.stopAndAwait(context)
                            check(stopResult.succeeded) {
                                when (stopResult) {
                                    TunnelStopResult.TIMED_OUT ->
                                        "VPN не остановился за отведённое время"
                                    else -> "Не удалось остановить VPN"
                                }
                            }
                        }
                        val resetCompleted = withTimeoutOrNull(PROFILE_RESET_TIMEOUT_MS) {
                            settingsStore.resetProfile(profile)
                            true
                        } == true
                        check(resetCompleted) {
                            "Очистка профиля не завершилась за 10 секунд. Повторите попытку."
                        }
                    }.onSuccess {
                        profileNameInput = vpnProfileDefaultName(profile)
                        resettingProfile = null
                        renamingProfile = null
                        isExpanded = false
                        Toast.makeText(context, "Профиль «$profileLabel» очищен", Toast.LENGTH_SHORT).show()
                    }.onFailure { error ->
                        Toast.makeText(
                            context,
                            error.message ?: "Не удалось очистить профиль",
                            Toast.LENGTH_LONG
                        ).show()
                    }
                    resetInProgress = false
                }
            },
            onDismiss = {
                if (!resetInProgress) resettingProfile = null
            }
        )
    }

    if (showTrustedWifiSettings) {
        TrustedWifiSettingsDialog(
            settingsStore = settingsStore,
            enableAfterFirstNetworkAdded = enableTrustedWifiAfterSetup,
            onDismiss = {
                enableTrustedWifiAfterSetup = false
                showTrustedWifiSettings = false
            }
        )
    }

    if (showVkClientSettings) {
        VkClientSettingsDialog(
            settingsStore = settingsStore,
            activeClientIds = activeClientIds,
            onClientIdsChange = onClientIdsChange,
            onDismiss = { showVkClientSettings = false }
        )
    }

    if (showSleepTimerSettings) {
        SleepTimerDialog(
            initialMode = sleepBatteryMode,
            initialPauseDelayMinutes = pauseVpnDuringSleepDelayMinutes,
            initialResumeDelayMinutes = resumeVpnDuringSleepDelayMinutes,
            onApply = { mode, pauseDelayMinutes, resumeDelayMinutes ->
                scope.launch {
                    settingsStore.saveSleepBatteryMode(
                        enabled = true,
                        mode = mode,
                        pauseDelayMinutes = pauseDelayMinutes,
                        resumeDelayMinutes = resumeDelayMinutes,
                    )
                    val description = when (mode) {
                        SleepBatteryMode.DELAYED_PAUSE ->
                            "отключение VPN через ${formatSleepTimerDuration(pauseDelayMinutes)} после выключения экрана"
                        SleepBatteryMode.TIMED_PAUSE -> if (resumeDelayMinutes == 0) {
                            "VPN остаётся активным при таймере 0 мин"
                        } else {
                            "немедленное отключение VPN и включение примерно через ${formatSleepTimerDuration(resumeDelayMinutes)}"
                        }
                    }
                    TunnelManager.noteSleepBatteryEvent(
                        "settings_saved",
                        "Настройки сохранены: $description.",
                    )
                }
                showSleepTimerSettings = false
            },
            onDismiss = { showSleepTimerSettings = false },
        )
    }
}
}

@Composable
private fun ProfileMenuDialog(
    profileNameInput: String,
    onProfileNameInputChange: (String) -> Unit,
    onResetRequested: () -> Unit,
    onSave: () -> Unit,
    onDismiss: () -> Unit
) {
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
                Box {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(22.dp)
                            .verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(14.dp)
                    ) {
                        Text(
                            "Профиль",
                            modifier = Modifier.padding(end = 48.dp),
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary
                        )
                        OutlinedTextField(
                            value = profileNameInput,
                            onValueChange = onProfileNameInputChange,
                            label = { Text("Название") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            OutlinedButton(
                                onClick = onResetRequested,
                                modifier = Modifier.weight(1f).heightIn(min = 48.dp),
                                shape = RoundedCornerShape(16.dp),
                                colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
                                border = BorderStroke(1.dp, MaterialTheme.colorScheme.error),
                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                            ) {
                                Text("Очистить", fontWeight = FontWeight.SemiBold)
                            }
                            Button(
                                onClick = onSave,
                                modifier = Modifier.weight(1f).heightIn(min = 48.dp),
                                shape = RoundedCornerShape(16.dp),
                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                            ) {
                                Text("Сохранить", fontWeight = FontWeight.SemiBold)
                            }
                        }
                        Spacer(Modifier.height(4.dp))
                    }

                    ProfileDialogCloseButton(
                        contentDescription = "Вернуться в настройки",
                        onClick = onDismiss,
                        modifier = Modifier.align(Alignment.TopEnd).padding(top = 10.dp, end = 10.dp)
                    )
                }
            }
        }
    }
}

@Composable
private fun ProfileResetDialog(
    profileLabel: String,
    defaultProfileLabel: String,
    countdown: Int,
    inProgress: Boolean,
    disconnectsActiveVpn: Boolean,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    Dialog(
        onDismissRequest = { if (!inProgress) onDismiss() },
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
                Box {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(22.dp)
                            .verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(14.dp)
                    ) {
                        Text(
                            "Очистить профиль?",
                            modifier = Modifier.padding(end = 48.dp),
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.error
                        )

                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(16.dp),
                            color = MaterialTheme.colorScheme.errorContainer,
                            contentColor = MaterialTheme.colorScheme.onErrorContainer
                        ) {
                            Column(
                                modifier = Modifier.padding(15.dp),
                                verticalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Text(
                                    "Будет полностью очищена вся локальная информация профиля «$profileLabel».",
                                    fontWeight = FontWeight.Bold,
                                    style = MaterialTheme.typography.bodyLarge
                                )
                                Text(
                                    "Удалятся настройки подключения, VK-хеши, ссылки, пароли и SSH-ключи, параметры сервера, списки приложений и остальные данные этого профиля.",
                                    style = MaterialTheme.typography.bodyMedium
                                )
                                Text(
                                    "Название вернётся к стандартному: «$defaultProfileLabel». Операция необратима. Вы уверены?",
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.SemiBold
                                )
                            }
                        }

                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(14.dp),
                            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.72f)
                        ) {
                            Text(
                                buildString {
                                    append("На самом VPS и в других профилях ничего не удаляется.")
                                    if (disconnectsActiveVpn) append(" Активное VPN-подключение этого профиля будет остановлено.")
                                },
                                modifier = Modifier.padding(14.dp),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }

                        Button(
                            onClick = onConfirm,
                            enabled = countdown <= 0 && !inProgress,
                            modifier = Modifier.fillMaxWidth().heightIn(min = 50.dp),
                            shape = RoundedCornerShape(16.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.error,
                                contentColor = MaterialTheme.colorScheme.onError,
                                disabledContainerColor = MaterialTheme.colorScheme.errorContainer,
                                disabledContentColor = MaterialTheme.colorScheme.onErrorContainer.copy(alpha = 0.68f)
                            )
                        ) {
                            Text(
                                when {
                                    inProgress -> "Очищаю профиль…"
                                    countdown > 0 -> "Очистить через $countdown с"
                                    else -> "Полностью очистить профиль"
                                },
                                fontWeight = FontWeight.Bold
                            )
                        }
                        Spacer(Modifier.height(4.dp))
                    }

                    ProfileDialogCloseButton(
                        contentDescription = "Вернуться к профилю",
                        onClick = onDismiss,
                        enabled = !inProgress,
                        modifier = Modifier.align(Alignment.TopEnd).padding(top = 10.dp, end = 10.dp)
                    )
                }
            }
        }
    }
}

@Composable
private fun ProfileDialogCloseButton(
    contentDescription: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true
) {
    IconButton(onClick = onClick, modifier = modifier, enabled = enabled) {
        Surface(
            shape = CircleShape,
            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.78f),
            modifier = Modifier.size(34.dp)
        ) {
            Box(contentAlignment = Alignment.Center) {
                Icon(
                    Icons.Filled.Close,
                    contentDescription = contentDescription,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(22.dp)
                )
            }
        }
    }
}

@Composable
private fun ThemeOption(
    icon: Int,
    contentDescription: String,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(24.dp),
        color = if (selected) MaterialTheme.colorScheme.primaryContainer
        else MaterialTheme.colorScheme.surface,
        modifier = modifier.height(42.dp)
    ) {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                painter = painterResource(id = icon),
                contentDescription = contentDescription,
                modifier = Modifier.size(20.dp),
                tint = if (selected) MaterialTheme.colorScheme.primary
                else MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
fun PaletteCircle(
    paletteId: String,
    colorHex: Long,
    selectedId: String,
    onClick: (String) -> Unit
) {
    val isSelected = paletteId == selectedId
    Box(
        modifier = Modifier
            .size(30.dp)
            .clip(CircleShape)
            .background(Color(colorHex))
            .clickable { onClick(paletteId) }
            .then(
                if (isSelected) Modifier.border(3.dp, MaterialTheme.colorScheme.primary, CircleShape)
                else Modifier
            )
    )
}
