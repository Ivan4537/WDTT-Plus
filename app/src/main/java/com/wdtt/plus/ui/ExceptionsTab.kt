package com.wdtt.plus.ui

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.Orientation
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.gestures.rememberScrollableState
import androidx.compose.foundation.gestures.scrollable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.HelpOutline
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.FileUpload
import androidx.compose.material.icons.filled.Hub
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableIntState
import androidx.compose.runtime.Stable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.input.nestedscroll.NestedScrollConnection
import androidx.compose.ui.input.nestedscroll.NestedScrollSource
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.layout.Layout
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.compose.LifecycleResumeEffect
import com.wdtt.plus.MAX_VPN_ADDRESS_IMPORT_BYTES
import com.wdtt.plus.SettingsStore
import com.wdtt.plus.TunnelManager
import com.wdtt.plus.VpnAddressRule
import com.wdtt.plus.VpnAddressType
import com.wdtt.plus.isAlwaysBypassedVpnPackage
import com.wdtt.plus.normalizeVpnAddressRules
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.math.abs
import kotlin.math.roundToInt

@Stable
data class AppItem(
    val name: String,
    val packageName: String,
    val icon: ImageBitmap?,
    val isSystem: Boolean,
    val isInstalled: Boolean = true,
)

object AppCache {
    var cachedList: List<AppItem>? = null
}

private enum class RoutingSection { APPS, ADDRESSES }

private enum class AddressFilter { ALL, DOMAIN, IP, SUBNET }

private enum class RoutingHelp { MODE, QUICK_EXCLUSIONS, ADDRESSES }

private val RoutingControlHeight = 60.dp

private fun Modifier.routingSectionSwipe(
    selectedSection: RoutingSection,
    thresholdPx: Float,
    onSectionChanged: (RoutingSection) -> Unit,
): Modifier = pointerInput(selectedSection, thresholdPx) {
    var totalDragPx = 0f
    detectHorizontalDragGestures(
        onDragStart = { totalDragPx = 0f },
        onDragCancel = { totalDragPx = 0f },
        onDragEnd = {
            if (abs(totalDragPx) >= thresholdPx) {
                val target = if (totalDragPx < 0f) {
                    RoutingSection.ADDRESSES
                } else {
                    RoutingSection.APPS
                }
                if (target != selectedSection) onSectionChanged(target)
            }
            totalDragPx = 0f
        },
    ) { change, dragAmount ->
        change.consume()
        totalDragPx += dragAmount
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExceptionsTab(
    firstVisibleItemIndex: MutableIntState = rememberSaveable { androidx.compose.runtime.mutableIntStateOf(0) },
    firstVisibleItemScrollOffset: MutableIntState = rememberSaveable { androidx.compose.runtime.mutableIntStateOf(0) },
) {
    val context = LocalContext.current.applicationContext
    val scope = rememberCoroutineScope()
    val settingsStore = remember { SettingsStore(context) }
    val routingSettings by settingsStore.vpnRoutingSettings.collectAsStateWithLifecycle(initialValue = null)
    val showSystemAppsOpt by settingsStore.showSystemApps.collectAsStateWithLifecycle(initialValue = null)
    val routingReady = routingSettings != null
    val savedPackages = routingSettings?.appPackages.orEmpty()
    val addressRules = routingSettings?.addressRules.orEmpty()
    val isWhitelist = routingSettings?.isWhitelist ?: false
    val visibleProfileIndex = routingSettings?.profileIndex ?: 0
    val selectedPackages = remember(savedPackages) { savedPackages.toVpnPackageSet() }

    var appsList by remember { mutableStateOf(AppCache.cachedList.orEmpty()) }
    var isLoadingApps by remember { mutableStateOf(AppCache.cachedList == null) }
    var appSearchQuery by rememberSaveable { mutableStateOf("") }
    var addressSearchQuery by rememberSaveable { mutableStateOf("") }
    var selectedSectionName by rememberSaveable { mutableStateOf(RoutingSection.APPS.name) }
    var addressFilterName by rememberSaveable { mutableStateOf(AddressFilter.ALL.name) }
    var quickExcludeStatus by rememberSaveable { mutableStateOf("") }
    var showAddAddressDialog by rememberSaveable { mutableStateOf(false) }
    var shownHelpName by rememberSaveable { mutableStateOf<String?>(null) }
    var pendingExportProfileIndex by rememberSaveable { mutableStateOf<Int?>(null) }
    var pendingImportProfileIndex by rememberSaveable { mutableStateOf<Int?>(null) }
    var modeChangeInFlight by remember { mutableStateOf(false) }

    val selectedSection = runCatching { RoutingSection.valueOf(selectedSectionName) }
        .getOrDefault(RoutingSection.APPS)
    val addressFilter = runCatching { AddressFilter.valueOf(addressFilterName) }
        .getOrDefault(AddressFilter.ALL)

    fun scheduleWireGuardReload(profileIndex: Int) {
        TunnelManager.scheduleWireGuardReload(profileIndex)
    }

    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"),
    ) { uri: Uri? ->
        val targetProfile = pendingExportProfileIndex
        pendingExportProfileIndex = null
        if (uri == null || targetProfile == null) return@rememberLauncherForActivityResult
        scope.launch {
            runCatching {
                val exportText = settingsStore.exportVpnRoutingSettings(targetProfile)
                writeRoutingFile(context, uri, exportText)
            }.onSuccess {
                Toast.makeText(context, "Маршрутизация экспортирована.", Toast.LENGTH_SHORT).show()
            }.onFailure { error ->
                Toast.makeText(
                    context,
                    error.message ?: "Не удалось сохранить файл.",
                    Toast.LENGTH_LONG,
                ).show()
            }
        }
    }
    val importLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri: Uri? ->
        val targetProfile = pendingImportProfileIndex
        pendingImportProfileIndex = null
        if (uri == null || targetProfile == null) return@rememberLauncherForActivityResult
        scope.launch {
            runCatching {
                val text = readRoutingFile(context, uri)
                settingsStore.importVpnRoutingSettings(text, targetProfile)
            }.onSuccess { result ->
                scheduleWireGuardReload(targetProfile)
                val mode = if (result.isWhitelist) "БС" else "ЧС"
                val apps = if (result.isWhitelist) result.whitelistAppCount else result.blacklistAppCount
                val addresses = if (result.isWhitelist) {
                    result.whitelistAddressCount
                } else {
                    result.blacklistAddressCount
                }
                Toast.makeText(
                    context,
                    "Импортировано в VPN ${targetProfile + 1}: $mode, " +
                        "приложений $apps, адресов $addresses.",
                    Toast.LENGTH_LONG,
                ).show()
            }.onFailure { error ->
                Toast.makeText(
                    context,
                    error.message ?: "Не удалось импортировать маршрутизацию.",
                    Toast.LENGTH_LONG,
                ).show()
            }
        }
    }

    LifecycleResumeEffect(Unit) {
        val refreshJob = scope.launch {
            if (appsList.isEmpty()) isLoadingApps = true
            val list = withContext(Dispatchers.IO) { loadInstalledApps(context) }
            appsList = list
            AppCache.cachedList = list
            isLoadingApps = false
        }
        onPauseOrDispose { refreshJob.cancel() }
    }

    val filteredApps by remember(selectedPackages) {
        derivedStateOf {
            val installedPackageNames = appsList.mapTo(hashSetOf(), AppItem::packageName)
            val unavailableSelectedApps = selectedPackages
                .asSequence()
                .filterNot(installedPackageNames::contains)
                .map { packageName ->
                    AppItem(
                        name = "Приложение не установлено",
                        packageName = packageName,
                        icon = null,
                        isSystem = false,
                        isInstalled = false,
                    )
                }
                .toList()
            val visibleInstalledApps = if (showSystemAppsOpt == true) {
                appsList
            } else {
                appsList.filter {
                    !it.isSystem ||
                        it.packageName in selectedPackages ||
                        it.packageName == "com.google.android.youtube" ||
                        it.packageName == "com.android.vending"
                }
            }
            val visibleApps = unavailableSelectedApps + visibleInstalledApps
            if (appSearchQuery.isBlank()) {
                visibleApps
            } else {
                visibleApps.filter {
                    it.name.contains(appSearchQuery, ignoreCase = true) ||
                        it.packageName.contains(appSearchQuery, ignoreCase = true)
                }
            }
        }
    }
    val filteredAddresses = remember(addressRules, addressSearchQuery, addressFilter) {
        addressRules.filter { rule ->
            val typeMatches = when (addressFilter) {
                AddressFilter.ALL -> true
                AddressFilter.DOMAIN -> rule.type == VpnAddressType.DOMAIN
                AddressFilter.IP -> rule.type == VpnAddressType.IP
                AddressFilter.SUBNET -> rule.type == VpnAddressType.SUBNET
            }
            typeMatches && (
                addressSearchQuery.isBlank() ||
                    rule.value.contains(addressSearchQuery.trim(), ignoreCase = true)
                )
        }
    }
    val appListState = rememberRememberedLazyListState(
        firstVisibleItemIndex,
        firstVisibleItemScrollOffset,
    )
    val addressListState = rememberLazyListState()
    val activeListState = when (selectedSection) {
        RoutingSection.APPS -> appListState
        RoutingSection.ADDRESSES -> addressListState
    }
    var topBlockHeightPx by remember { mutableFloatStateOf(0f) }
    var topBlockOffsetPx by rememberSaveable { mutableStateOf(0f) }
    var initializedSectionName by rememberSaveable { mutableStateOf<String?>(null) }

    LaunchedEffect(selectedSection, topBlockHeightPx) {
        if (topBlockHeightPx <= 0f) return@LaunchedEffect
        if (initializedSectionName != selectedSection.name) {
            topBlockOffsetPx = if (
                activeListState.firstVisibleItemIndex > 0 ||
                activeListState.firstVisibleItemScrollOffset > 0
            ) {
                -topBlockHeightPx
            } else {
                0f
            }
            initializedSectionName = selectedSection.name
        } else {
            topBlockOffsetPx = topBlockOffsetPx.coerceIn(-topBlockHeightPx, 0f)
        }
    }

    fun consumeHeaderScroll(deltaPx: Float, allowExpand: Boolean): Float {
        val previousOffset = topBlockOffsetPx
        val nextOffset = collapsingHeaderOffsetAfterScroll(
            currentOffsetPx = previousOffset,
            headerHeightPx = topBlockHeightPx,
            deltaPx = deltaPx,
            allowExpand = allowExpand,
        )
        if (nextOffset != previousOffset) {
            topBlockOffsetPx = nextOffset
            initializedSectionName = selectedSection.name
        }
        return nextOffset - previousOffset
    }

    val collapsingHeaderConnection = remember(topBlockHeightPx, activeListState, selectedSection) {
        object : NestedScrollConnection {
            override fun onPreScroll(available: Offset, source: NestedScrollSource): Offset {
                if (topBlockHeightPx <= 0f) return Offset.Zero
                val consumed = consumeHeaderScroll(
                    deltaPx = available.y,
                    allowExpand = !activeListState.canScrollBackward,
                )
                return Offset(x = 0f, y = consumed)
            }

            override fun onPostScroll(
                consumed: Offset,
                available: Offset,
                source: NestedScrollSource,
            ): Offset {
                if (available.y <= 0f) return Offset.Zero
                val headerConsumed = consumeHeaderScroll(
                    deltaPx = available.y,
                    allowExpand = true,
                )
                return Offset(x = 0f, y = headerConsumed)
            }
        }
    }
    val searchHeaderScrollState = rememberScrollableState { deltaPx ->
        consumeHeaderScroll(deltaPx = deltaPx, allowExpand = true)
    }
    val collapseFraction = if (topBlockHeightPx > 0f) {
        (-topBlockOffsetPx / topBlockHeightPx).coerceIn(0f, 1f)
    } else {
        0f
    }
    val sectionSwipeThresholdPx = with(LocalDensity.current) { 48.dp.toPx() }
    val sectionSwipeModifier = Modifier.routingSectionSwipe(
        selectedSection = selectedSection,
        thresholdPx = sectionSwipeThresholdPx,
        onSectionChanged = { selectedSectionName = it.name },
    )

    Column(
        modifier = Modifier
            .fillMaxSize()
            .nestedScroll(collapsingHeaderConnection)
            .padding(horizontal = 16.dp),
    ) {
        CollapsingExceptionsHeader(
            offsetPx = topBlockOffsetPx,
            onHeightChanged = { measuredHeight ->
                if (measuredHeight > 0 && topBlockHeightPx != measuredHeight.toFloat()) {
                    topBlockHeightPx = measuredHeight.toFloat()
                }
            },
        ) {
            Column {
                RoutingTitleRow(
                    enabled = routingReady,
                    onExport = {
                        pendingExportProfileIndex = visibleProfileIndex
                        exportLauncher.launch("WDTT-Plus-routing-VPN-${visibleProfileIndex + 1}.json")
                    },
                    onImport = {
                        pendingImportProfileIndex = visibleProfileIndex
                        importLauncher.launch(arrayOf("application/json", "text/plain"))
                    },
                )

                RoutingModeCard(
                    isWhitelist = isWhitelist,
                    enabled = routingReady && !modeChangeInFlight,
                    onHelp = { shownHelpName = RoutingHelp.MODE.name },
                    onModeChanged = { whitelist ->
                        if (whitelist == isWhitelist || modeChangeInFlight) return@RoutingModeCard
                        modeChangeInFlight = true
                        scope.launch {
                            runCatching {
                                settingsStore.saveIsWhitelist(whitelist, visibleProfileIndex)
                            }
                                .onSuccess { scheduleWireGuardReload(visibleProfileIndex) }
                                .onFailure { error ->
                                    Toast.makeText(
                                        context,
                                        error.message ?: "Не удалось изменить режим списка.",
                                        Toast.LENGTH_LONG,
                                    ).show()
                                }
                            modeChangeInFlight = false
                        }
                    },
                )

                TabRow(
                    selectedTabIndex = selectedSection.ordinal,
                    modifier = sectionSwipeModifier,
                    containerColor = Color.Transparent,
                    contentColor = MaterialTheme.colorScheme.primary,
                ) {
                    RoutingSection.entries.forEach { section ->
                        Tab(
                            selected = selectedSection == section,
                            onClick = { selectedSectionName = section.name },
                            text = {
                                Text(
                                    if (section == RoutingSection.APPS) "Приложения" else "Адреса",
                                    fontWeight = if (selectedSection == section) {
                                        FontWeight.Bold
                                    } else {
                                        FontWeight.Medium
                                    },
                                )
                            },
                        )
                    }
                }
                Spacer(Modifier.height(10.dp))

                if (routingReady) {
                    when (selectedSection) {
                        RoutingSection.APPS -> AppsRoutingHeader(
                            isWhitelist = isWhitelist,
                            showSystemApps = showSystemAppsOpt,
                            isLoading = isLoadingApps,
                            quickExcludeStatus = quickExcludeStatus,
                            onShowSystemChanged = { enabled ->
                                scope.launch { settingsStore.saveShowSystemApps(enabled) }
                            },
                            onQuickExclusions = {
                                val detectedPackages = appsList
                                    .filter { matchesQuickExclusionApp(it.name, it.packageName) }
                                    .map(AppItem::packageName)
                                    .toSet()
                                if (detectedPackages.isEmpty()) {
                                    quickExcludeStatus = "Подходящие приложения не найдены."
                                } else {
                                    scope.launch {
                                        runCatching {
                                            settingsStore.addBlacklistPackages(
                                                detectedPackages,
                                                visibleProfileIndex,
                                            )
                                        }.onSuccess { addedCount ->
                                            quickExcludeStatus =
                                                "Найдено: ${detectedPackages.size}, добавлено: $addedCount."
                                            scheduleWireGuardReload(visibleProfileIndex)
                                        }.onFailure { error ->
                                            quickExcludeStatus =
                                                error.message ?: "Не удалось изменить ЧС."
                                        }
                                    }
                                }
                            },
                            onQuickHelp = {
                                shownHelpName = RoutingHelp.QUICK_EXCLUSIONS.name
                            },
                            sectionSwipeModifier = sectionSwipeModifier,
                        )

                        RoutingSection.ADDRESSES -> AddressesRoutingHeader(
                            rules = addressRules,
                            filter = addressFilter,
                            onFilterChanged = { addressFilterName = it.name },
                            onAdd = { showAddAddressDialog = true },
                            onHelp = { shownHelpName = RoutingHelp.ADDRESSES.name },
                            sectionSwipeModifier = sectionSwipeModifier,
                        )
                    }
                }
            }
        }

        if (!routingReady) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
        } else {
            val searchQuery = when (selectedSection) {
                RoutingSection.APPS -> appSearchQuery
                RoutingSection.ADDRESSES -> addressSearchQuery
            }
            SearchField(
                value = searchQuery,
                onValueChange = { value ->
                    when (selectedSection) {
                        RoutingSection.APPS -> appSearchQuery = value
                        RoutingSection.ADDRESSES -> addressSearchQuery = value
                    }
                },
                placeholder = if (selectedSection == RoutingSection.APPS) {
                    "Поиск приложений..."
                } else {
                    "Поиск адресов..."
                },
                modifier = Modifier
                    .padding(top = 16.dp * collapseFraction, bottom = 12.dp)
                    .scrollable(
                        state = searchHeaderScrollState,
                        orientation = Orientation.Vertical,
                    ),
            )

            when (selectedSection) {
                RoutingSection.APPS -> AppsRoutingList(
                    modifier = Modifier.weight(1f),
                    showSystemApps = showSystemAppsOpt,
                    isLoading = isLoadingApps,
                    apps = filteredApps,
                    selectedPackages = selectedPackages,
                    searchQuery = appSearchQuery,
                    listState = appListState,
                    onAppClick = { packageName ->
                        scope.launch {
                            runCatching {
                                settingsStore.toggleVpnAppSelected(
                                    packageName,
                                    isWhitelist,
                                    visibleProfileIndex,
                                )
                            }.onSuccess {
                                scheduleWireGuardReload(visibleProfileIndex)
                            }.onFailure { error ->
                                Toast.makeText(
                                    context,
                                    error.message ?: "Не удалось изменить список приложений.",
                                    Toast.LENGTH_LONG,
                                ).show()
                            }
                        }
                    },
                )

                RoutingSection.ADDRESSES -> AddressesRoutingList(
                    modifier = Modifier.weight(1f),
                    rules = addressRules,
                    filteredRules = filteredAddresses,
                    listState = addressListState,
                    onRemove = { rule ->
                        scope.launch {
                            runCatching {
                                settingsStore.removeVpnAddressRule(
                                    rule,
                                    isWhitelist,
                                    visibleProfileIndex,
                                )
                            }.onSuccess {
                                scheduleWireGuardReload(visibleProfileIndex)
                            }.onFailure { error ->
                                Toast.makeText(
                                    context,
                                    error.message ?: "Не удалось удалить адрес.",
                                    Toast.LENGTH_LONG,
                                ).show()
                            }
                        }
                    },
                )
            }
        }
    }

    if (showAddAddressDialog) {
        AddAddressDialog(
            onDismiss = { showAddAddressDialog = false },
            onAdd = { value, onError ->
                scope.launch {
                    runCatching {
                        settingsStore.addVpnAddressRules(
                            value,
                            isWhitelist,
                            visibleProfileIndex,
                        )
                    }
                        .onSuccess {
                            showAddAddressDialog = false
                            scheduleWireGuardReload(visibleProfileIndex)
                        }
                        .onFailure { error -> onError(error.message ?: "Некорректный адрес.") }
                }
            },
        )
    }

    shownHelpName?.let { helpName ->
        val help = runCatching { RoutingHelp.valueOf(helpName) }.getOrNull()
        if (help != null) {
            RoutingHelpDialog(help = help, onDismiss = { shownHelpName = null })
        }
    }
}

@Composable
private fun CollapsingExceptionsHeader(
    offsetPx: Float,
    onHeightChanged: (Int) -> Unit,
    content: @Composable () -> Unit,
) {
    Layout(
        modifier = Modifier
            .fillMaxWidth()
            .clipToBounds(),
        content = {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .onSizeChanged { onHeightChanged(it.height) },
            ) {
                content()
            }
        },
    ) { measurables, constraints ->
        val placeable = measurables.single().measure(constraints.copy(minHeight = 0))
        val safeOffset = offsetPx.roundToInt().coerceIn(-placeable.height, 0)
        val visibleHeight = (placeable.height + safeOffset).coerceAtLeast(0)
        layout(placeable.width, visibleHeight) {
            placeable.placeRelative(0, safeOffset)
        }
    }
}

@Composable
private fun RoutingTitleRow(
    enabled: Boolean,
    onExport: () -> Unit,
    onImport: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 12.dp, bottom = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            "Маршрутизация",
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onSurface,
        )
        val iconButtonColors = IconButtonDefaults.iconButtonColors(
            contentColor = MaterialTheme.colorScheme.onSurface,
            disabledContentColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f),
        )
        IconButton(
            onClick = onImport,
            enabled = enabled,
            colors = iconButtonColors,
        ) {
            Icon(Icons.Default.FileDownload, contentDescription = "Импорт маршрутизации")
        }
        IconButton(
            onClick = onExport,
            enabled = enabled,
            colors = iconButtonColors,
        ) {
            Icon(Icons.Default.FileUpload, contentDescription = "Экспорт маршрутизации")
        }
    }
}

@Composable
private fun RoutingModeCard(
    isWhitelist: Boolean,
    enabled: Boolean,
    onHelp: () -> Unit,
    onModeChanged: (Boolean) -> Unit,
) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 8.dp),
        shape = RoundedCornerShape(18.dp),
        color = MaterialTheme.colorScheme.surfaceContainerHighest,
        contentColor = MaterialTheme.colorScheme.onSurface,
        tonalElevation = 0.dp,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Режим списка", fontWeight = FontWeight.SemiBold)
                    IconButton(
                        onClick = onHelp,
                        modifier = Modifier.size(30.dp),
                    ) {
                        Icon(
                            Icons.AutoMirrored.Filled.HelpOutline,
                            contentDescription = "Инструкция по режиму списка",
                            modifier = Modifier.size(18.dp),
                        )
                    }
                }
                Text(
                    "Применяется к приложениям и адресам",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                ModeChip("ЧС", selected = !isWhitelist, enabled = enabled) { onModeChanged(false) }
                ModeChip("БС", selected = isWhitelist, enabled = enabled) { onModeChanged(true) }
            }
        }
    }
}

@Composable
private fun AppsRoutingHeader(
    isWhitelist: Boolean,
    showSystemApps: Boolean?,
    isLoading: Boolean,
    quickExcludeStatus: String,
    onShowSystemChanged: (Boolean) -> Unit,
    onQuickExclusions: () -> Unit,
    onQuickHelp: () -> Unit,
    sectionSwipeModifier: Modifier,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        CompactControlSurface(
            modifier = Modifier
                .fillMaxWidth()
                .then(sectionSwipeModifier),
        ) {
            Text(
                "Системные приложения",
                modifier = Modifier.weight(1f),
                fontSize = 13.sp,
                maxLines = 1,
            )
            Switch(
                checked = showSystemApps ?: false,
                onCheckedChange = onShowSystemChanged,
                enabled = showSystemApps != null,
                modifier = Modifier.heightIn(max = 42.dp),
            )
        }
        CompactControlSurface(
            modifier = Modifier
                .fillMaxWidth()
                .then(sectionSwipeModifier),
        ) {
            TextButton(
                onClick = onQuickExclusions,
                enabled = !isWhitelist && !isLoading,
                contentPadding = PaddingValues(horizontal = 2.dp),
                modifier = Modifier.weight(1f),
            ) {
                if (quickExcludeStatus.isBlank()) {
                    Text(
                        if (isWhitelist) "Доступно только для ЧС" else "Быстрые исключения",
                        fontSize = 13.sp,
                        maxLines = 1,
                    )
                } else {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            if (isWhitelist) "Доступно только для ЧС" else "Быстрые исключения",
                            fontSize = 13.sp,
                            maxLines = 1,
                        )
                        Text(
                            quickExcludeStatus,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            fontSize = 9.sp,
                            lineHeight = 10.sp,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
            }
            IconButton(onClick = onQuickHelp, modifier = Modifier.size(38.dp)) {
                Icon(
                    Icons.AutoMirrored.Filled.HelpOutline,
                    contentDescription = "Инструкция по быстрым исключениям",
                    modifier = Modifier.size(20.dp),
                )
            }
        }
    }
}

@Composable
private fun AppsRoutingList(
    modifier: Modifier,
    showSystemApps: Boolean?,
    isLoading: Boolean,
    apps: List<AppItem>,
    selectedPackages: Set<String>,
    searchQuery: String,
    listState: androidx.compose.foundation.lazy.LazyListState,
    onAppClick: (String) -> Unit,
) {
    Column(modifier = modifier.fillMaxWidth()) {
        when {
            isLoading || showSystemApps == null -> {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator()
                }
            }

            apps.isEmpty() -> EmptyListMessage(
                if (searchQuery.isBlank()) "Приложения не найдены" else "По запросу ничего не найдено"
            )

            else -> LazyColumn(
                state = listState,
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(bottom = 16.dp),
                verticalArrangement = Arrangement.spacedBy(7.dp),
            ) {
                items(apps, key = AppItem::packageName) { app ->
                    AppRow(
                        app = app,
                        isSelected = app.packageName in selectedPackages,
                        onClick = { onAppClick(app.packageName) },
                    )
                }
            }
        }
    }
}

@Composable
private fun AddressesRoutingHeader(
    rules: List<VpnAddressRule>,
    filter: AddressFilter,
    onFilterChanged: (AddressFilter) -> Unit,
    onAdd: () -> Unit,
    onHelp: () -> Unit,
    sectionSwipeModifier: Modifier,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(RoutingControlHeight),
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .align(Alignment.Center)
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                AddressFilterChip("Все", rules.size, filter == AddressFilter.ALL) {
                    onFilterChanged(AddressFilter.ALL)
                }
                AddressFilterChip(
                    "Домены",
                    rules.count { it.type == VpnAddressType.DOMAIN },
                    filter == AddressFilter.DOMAIN,
                ) { onFilterChanged(AddressFilter.DOMAIN) }
                AddressFilterChip(
                    "IP",
                    rules.count { it.type == VpnAddressType.IP },
                    filter == AddressFilter.IP,
                ) { onFilterChanged(AddressFilter.IP) }
                AddressFilterChip(
                    "Подсети",
                    rules.count { it.type == VpnAddressType.SUBNET },
                    filter == AddressFilter.SUBNET,
                ) { onFilterChanged(AddressFilter.SUBNET) }
            }
            Box(
                Modifier
                    .fillMaxWidth()
                    .height(10.dp)
                    .align(Alignment.TopCenter)
                    .then(sectionSwipeModifier),
            )
            Box(
                Modifier
                    .fillMaxWidth()
                    .height(10.dp)
                    .align(Alignment.BottomCenter)
                    .then(sectionSwipeModifier),
            )
        }

        Surface(
            onClick = onAdd,
            modifier = Modifier
                .fillMaxWidth()
                .height(RoutingControlHeight)
                .then(sectionSwipeModifier),
            shape = RoundedCornerShape(16.dp),
            color = MaterialTheme.colorScheme.surfaceContainerHighest,
            contentColor = MaterialTheme.colorScheme.onSurface,
        ) {
            Row(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.primaryContainer,
                ) {
                    Icon(
                        Icons.Default.Add,
                        contentDescription = null,
                        modifier = Modifier.padding(9.dp).size(22.dp),
                        tint = MaterialTheme.colorScheme.onPrimaryContainer,
                    )
                }
                Column(modifier = Modifier.weight(1f).padding(horizontal = 12.dp)) {
                    Text("Добавить адрес", fontWeight = FontWeight.SemiBold)
                    Text(
                        "Домен, URL, IPv4, CIDR или диапазон",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        lineHeight = 15.sp,
                        maxLines = 2,
                    )
                }
                IconButton(onClick = onHelp) {
                    Icon(
                        Icons.AutoMirrored.Filled.HelpOutline,
                        contentDescription = "Инструкция по адресам",
                    )
                }
            }
        }
    }
}

@Composable
private fun AddressesRoutingList(
    modifier: Modifier,
    rules: List<VpnAddressRule>,
    filteredRules: List<VpnAddressRule>,
    listState: androidx.compose.foundation.lazy.LazyListState,
    onRemove: (VpnAddressRule) -> Unit,
) {
    Column(modifier = modifier.fillMaxWidth()) {
        if (filteredRules.isEmpty()) {
            EmptyListMessage(
                if (rules.isEmpty()) "Адреса пока не добавлены" else "По фильтру ничего не найдено"
            )
        } else {
            LazyColumn(
                state = listState,
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(bottom = 16.dp),
                verticalArrangement = Arrangement.spacedBy(7.dp),
            ) {
                items(
                    items = filteredRules,
                    key = { "${it.type.storedValue}:${it.value}" },
                ) { rule ->
                    AddressRow(rule = rule, onRemove = { onRemove(rule) })
                }
            }
        }
    }
}

@Composable
private fun AddAddressDialog(
    onDismiss: () -> Unit,
    onAdd: (String, (String) -> Unit) -> Unit,
) {
    var value by rememberSaveable { mutableStateOf("") }
    var error by rememberSaveable { mutableStateOf("") }
    val previewRules = remember(value) {
        if (value.isBlank()) null else runCatching { normalizeVpnAddressRules(value) }.getOrNull()
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    "Добавить адрес",
                    modifier = Modifier.weight(1f),
                )
                IconButton(onClick = onDismiss) {
                    Icon(
                        Icons.Default.Close,
                        contentDescription = "Закрыть добавление адреса",
                    )
                }
            }
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Введите домен, ссылку сайта, IPv4, подсеть CIDR или диапазон IPv4. " +
                        "Несколько значений добавляйте с новой строки.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                OutlinedTextField(
                    value = value,
                    onValueChange = {
                        value = it
                        error = ""
                    },
                    modifier = Modifier.fillMaxWidth(),
                    placeholder = {
                        Text("example.org\n192.168.1.0/24\n1.1.1.1 - 1.1.1.10")
                    },
                    singleLine = false,
                    minLines = 3,
                    maxLines = 6,
                    isError = error.isNotBlank(),
                    supportingText = {
                        when {
                            error.isNotBlank() -> Text(error)
                            previewRules?.size == 1 -> Text(
                                "Будет добавлено как: ${previewRules.single().type.label}"
                            )
                            !previewRules.isNullOrEmpty() -> Text(
                                "Будет добавлено правил: ${previewRules.size}"
                            )
                            else -> Text("Типы определятся автоматически")
                        }
                    },
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    if (value.isBlank()) {
                        error = "Введите адрес."
                    } else {
                        onAdd(value) { message -> error = message }
                    }
                },
            ) { Text("Добавить") }
        },
    )
}

@Composable
private fun RoutingHelpDialog(help: RoutingHelp, onDismiss: () -> Unit) {
    val title: String
    val body: String
    when (help) {
        RoutingHelp.MODE -> {
            title = "Режим списка"
            body = "Режим общий для приложений и адресов текущего профиля VPN.\n\n" +
                "ЧС: выбранные приложения полностью обходят VPN, а выбранные адреса идут напрямую для остальных приложений.\n\n" +
                "БС: если выбраны и приложения, и адреса, через VPN идут только выбранные приложения к выбранным адресам. Если заполнена только одна категория, ограничение второй категории не добавляется."
        }

        RoutingHelp.QUICK_EXCLUSIONS -> {
            title = "Быстрые исключения"
            body = "Работают только в режиме ЧС. WDTT Plus найдёт установленные приложения, которым часто нужен прямой мобильный интернет, и добавит их в ЧС. Уже выбранные приложения не дублируются; список можно изменить вручную."
        }

        RoutingHelp.ADDRESSES -> {
            title = "Маршрутизация адресов"
            body = "В ЧС выбранные адреса идут напрямую, в БС — только выбранные адреса идут через VPN. Можно вставить несколько строк: точные домены, ссылки, домены или IPv4 с портом, отдельные IPv4, подсети CIDR и диапазоны IPv4. Порт удаляется, а диапазон преобразуется в минимальный набор подсетей. Домен при запуске VPN преобразуется в его текущие IPv4-адреса, поэтому после смены DNS-адресов перезапустите VPN. Маска *.example.org не равна DNS-имени и требует отдельного DNS-перехватчика; обычный WireGuard принимает только IP-маршруты, поэтому такие маски и IPv6 сейчас не применяются. Если в БС заполнены приложения и адреса, через VPN пойдёт трафик выбранных приложений к выбранным адресам."
        }
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    title,
                    modifier = Modifier.weight(1f),
                )
                IconButton(onClick = onDismiss) {
                    Icon(
                        Icons.Default.Close,
                        contentDescription = "Закрыть инструкцию",
                    )
                }
            }
        },
        text = {
            Text(
                body,
                modifier = Modifier
                    .heightIn(max = 360.dp)
                    .verticalScroll(rememberScrollState()),
            )
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Понятно") } },
    )
}

@Composable
private fun ModeChip(
    label: String,
    selected: Boolean,
    enabled: Boolean = true,
    onClick: () -> Unit,
) {
    FilterChip(
        selected = selected,
        enabled = enabled,
        onClick = onClick,
        label = {
            Text(
                label,
                modifier = Modifier.fillMaxWidth(),
                textAlign = TextAlign.Center,
                fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium,
            )
        },
        modifier = Modifier.width(58.dp),
        shape = RoundedCornerShape(12.dp),
        colors = FilterChipDefaults.filterChipColors(
            selectedContainerColor = MaterialTheme.colorScheme.primary,
            selectedLabelColor = MaterialTheme.colorScheme.onPrimary,
            containerColor = MaterialTheme.colorScheme.surfaceContainerHighest,
            labelColor = MaterialTheme.colorScheme.onSurface,
        ),
    )
}

@Composable
private fun CompactControlSurface(
    modifier: Modifier,
    content: @Composable androidx.compose.foundation.layout.RowScope.() -> Unit,
) {
    Surface(
        modifier = modifier.height(RoutingControlHeight),
        shape = RoundedCornerShape(15.dp),
        color = MaterialTheme.colorScheme.surfaceContainerHighest,
        contentColor = MaterialTheme.colorScheme.onSurface,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            content = content,
        )
    }
}

@Composable
private fun SearchField(
    value: String,
    onValueChange: (String) -> Unit,
    placeholder: String,
    modifier: Modifier = Modifier,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        textStyle = MaterialTheme.typography.bodyMedium,
        placeholder = {
            Text(
                placeholder,
                style = MaterialTheme.typography.bodyMedium,
                maxLines = 1,
            )
        },
        modifier = modifier
            .fillMaxWidth()
            .height(52.dp),
        shape = RoundedCornerShape(14.dp),
        leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, modifier = Modifier.size(20.dp)) },
        singleLine = true,
    )
}

@Composable
private fun AddressFilterChip(
    label: String,
    count: Int,
    selected: Boolean,
    onClick: () -> Unit,
) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = { Text("$label  $count", maxLines = 1) },
        shape = RoundedCornerShape(13.dp),
    )
}

@Composable
private fun AddressRow(rule: VpnAddressRule, onRemove: () -> Unit) {
    val accentColor = when (rule.type) {
        VpnAddressType.DOMAIN -> MaterialTheme.colorScheme.primary
        VpnAddressType.IP -> MaterialTheme.colorScheme.secondary
        VpnAddressType.SUBNET -> MaterialTheme.colorScheme.tertiary
    }
    val onAccentColor = when (rule.type) {
        VpnAddressType.DOMAIN -> MaterialTheme.colorScheme.onPrimary
        VpnAddressType.IP -> MaterialTheme.colorScheme.onSecondary
        VpnAddressType.SUBNET -> MaterialTheme.colorScheme.onTertiary
    }
    val badgeColor = when (rule.type) {
        VpnAddressType.DOMAIN -> MaterialTheme.colorScheme.primaryContainer
        VpnAddressType.IP -> MaterialTheme.colorScheme.secondaryContainer
        VpnAddressType.SUBNET -> MaterialTheme.colorScheme.tertiaryContainer
    }
    val onBadgeColor = when (rule.type) {
        VpnAddressType.DOMAIN -> MaterialTheme.colorScheme.onPrimaryContainer
        VpnAddressType.IP -> MaterialTheme.colorScheme.onSecondaryContainer
        VpnAddressType.SUBNET -> MaterialTheme.colorScheme.onTertiaryContainer
    }
    val icon = when (rule.type) {
        VpnAddressType.DOMAIN -> Icons.Default.Language
        VpnAddressType.IP -> Icons.Default.Dns
        VpnAddressType.SUBNET -> Icons.Default.Hub
    }
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surfaceContainerHighest,
        contentColor = MaterialTheme.colorScheme.onSurface,
    ) {
        Row(
            modifier = Modifier.padding(start = 10.dp, top = 6.dp, bottom = 6.dp, end = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Surface(shape = CircleShape, color = accentColor) {
                Icon(
                    icon,
                    contentDescription = null,
                    tint = onAccentColor,
                    modifier = Modifier.padding(7.dp).size(18.dp),
                )
            }
            Text(
                rule.value,
                modifier = Modifier.weight(1f).padding(horizontal = 10.dp),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                fontWeight = FontWeight.Medium,
            )
            Surface(
                shape = RoundedCornerShape(8.dp),
                color = badgeColor,
            ) {
                Text(
                    rule.type.label,
                    modifier = Modifier.padding(horizontal = 9.dp, vertical = 4.dp),
                    color = onBadgeColor,
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.SemiBold,
                )
            }
            IconButton(onClick = onRemove, modifier = Modifier.size(40.dp)) {
                Icon(Icons.Default.Close, contentDescription = "Удалить ${rule.value}")
            }
        }
    }
}

@Composable
private fun EmptyListMessage(text: String) {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Text(text, color = MaterialTheme.colorScheme.onSurfaceVariant, textAlign = TextAlign.Center)
    }
}

@Composable
fun AppRow(app: AppItem, isSelected: Boolean, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surfaceContainerHighest,
        contentColor = MaterialTheme.colorScheme.onSurface,
        tonalElevation = if (isSelected) 3.dp else 0.dp,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (app.icon != null) {
                Image(
                    bitmap = app.icon,
                    contentDescription = null,
                    modifier = Modifier.size(40.dp).clip(RoundedCornerShape(9.dp)),
                )
            } else {
                Box(
                    Modifier
                        .size(40.dp)
                        .background(
                            MaterialTheme.colorScheme.surfaceVariant,
                            RoundedCornerShape(9.dp),
                        ),
                )
            }
            Column(modifier = Modifier.weight(1f).padding(horizontal = 12.dp)) {
                Text(
                    app.name,
                    fontWeight = FontWeight.SemiBold,
                    color = if (app.isInstalled) {
                        MaterialTheme.colorScheme.onSurface
                    } else {
                        MaterialTheme.colorScheme.error
                    },
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    app.packageName,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Checkbox(
                checked = isSelected,
                onCheckedChange = null,
                colors = CheckboxDefaults.colors(checkedColor = MaterialTheme.colorScheme.primary),
            )
        }
    }
}

private val VpnAddressType.label: String
    get() = when (this) {
        VpnAddressType.DOMAIN -> "Домен"
        VpnAddressType.IP -> "IP"
        VpnAddressType.SUBNET -> "Подсеть"
    }

private fun String.toVpnPackageSet(): Set<String> =
    split(',').map(String::trim).filter(String::isNotEmpty).toSet()

private fun loadInstalledApps(context: Context): List<AppItem> {
    val packageManager = context.packageManager
    return packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
        .asSequence()
        .filterNot { isAlwaysBypassedVpnPackage(it.packageName, context.packageName) }
        .map { app ->
            AppItem(
                name = app.loadLabel(packageManager).toString(),
                packageName = app.packageName,
                icon = runCatching { app.loadIcon(packageManager).toBitmap().asImageBitmap() }.getOrNull(),
                isSystem = app.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0,
            )
        }
        .sortedBy { it.name.lowercase() }
        .toList()
}

private suspend fun writeRoutingFile(context: Context, uri: Uri, text: String) =
    withContext(Dispatchers.IO) {
        context.contentResolver.openOutputStream(uri, "wt")?.bufferedWriter(Charsets.UTF_8)?.use {
            it.write(text)
        } ?: throw IllegalArgumentException("Не удалось открыть файл для записи.")
    }

private suspend fun readRoutingFile(context: Context, uri: Uri): String =
    withContext(Dispatchers.IO) {
        val bytes = context.contentResolver.openInputStream(uri)?.use { input ->
            val output = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(8 * 1024)
            var total = 0
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                total += count
                require(total <= MAX_VPN_ADDRESS_IMPORT_BYTES) { "Файл маршрутизации слишком большой." }
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        } ?: throw IllegalArgumentException("Не удалось открыть выбранный файл.")
        bytes.toString(Charsets.UTF_8).removePrefix("\uFEFF").trim()
    }
