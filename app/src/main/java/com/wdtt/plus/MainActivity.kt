package com.wdtt.plus

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import android.view.HapticFeedbackConstants
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.GenericShape
import androidx.compose.foundation.shape.RoundedCornerShape
import kotlinx.coroutines.launch
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BatterySaver
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material.icons.outlined.Cloud
import androidx.compose.material.icons.outlined.FilterList
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Terminal
import androidx.compose.material.icons.outlined.VpnKey
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.PointerEventType
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.unit.dp
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.sp
import androidx.compose.ui.zIndex
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.lifecycleScope
import androidx.compose.ui.platform.LocalContext
import com.wdtt.plus.ui.AppUpdateDialog
import com.wdtt.plus.ui.FloatingToolbar
import com.wdtt.plus.ui.LogsTab
import com.wdtt.plus.ui.SettingsTab
import com.wdtt.plus.ui.DeployTab
import com.wdtt.plus.ui.DeviceCompatibilityDialog
import com.wdtt.plus.ui.ExceptionsTab
import com.wdtt.plus.ui.InfoTab
import com.wdtt.plus.ui.AdminImportDialog
import com.wdtt.plus.ui.TransferCenterDialog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.sin

class MainActivity : ComponentActivity() {
    private var sharedVkHashResult by mutableStateOf<VkHashInsertResult?>(null)
    private var sharedVkHashError by mutableStateOf<String?>(null)
    private var wdttDeepLinkMessage by mutableStateOf<String?>(null)
    private var pendingWdttDeepLinkPlan by mutableStateOf<WdttDeepLinkApplyPlan?>(null)
    private var pendingAdminTransfer by mutableStateOf<String?>(null)

    companion object {
        var activeActivities = 0
        var isForeground: Boolean
            get() = activeActivities > 0
            set(value) {}
    }

    override fun onStart() {
        super.onStart()
        activeActivities++
        ManlCaptchaWebViewManager.checkAndShowPendingCaptcha(this)
    }

    override fun onStop() {
        super.onStop()
        activeActivities--
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        TunnelManager.initObservers(this)

        enableEdgeToEdge()

        setContent {
            val settingsStore = remember { SettingsStore(this) }
            val themeMode by settingsStore.themeMode.collectAsStateWithLifecycle(initialValue = "system")
            val isDynamicColor by settingsStore.isDynamicColor.collectAsStateWithLifecycle(initialValue = false)
            val themePalette by settingsStore.themePalette.collectAsStateWithLifecycle(initialValue = "indigo")
            val activeFingerprint by settingsStore.selectedFingerprint.collectAsStateWithLifecycle(initialValue = "firefox")
            val activeClientIds by settingsStore.activeClientIds.collectAsStateWithLifecycle(initialValue = "6287487,8202606")
            val scope = rememberCoroutineScope()

            WDTTTheme(themeMode = themeMode, dynamicColor = isDynamicColor, themePalette = themePalette) {
                MainScreen(
                    settingsStore = settingsStore,
                    sharedVkHashResult = sharedVkHashResult,
                    sharedVkHashError = sharedVkHashError,
                    onSharedVkHashMessageShown = {
                        sharedVkHashResult = null
                        sharedVkHashError = null
                    },
                    wdttDeepLinkMessage = wdttDeepLinkMessage,
                    onWdttDeepLinkMessageShown = { wdttDeepLinkMessage = null },
                    pendingWdttDeepLinkPlan = pendingWdttDeepLinkPlan,
                    pendingAdminTransfer = pendingAdminTransfer,
                    onIncomingTransferContent = ::handleIncomingTransferText,
                    onAdminTransferDismissed = { pendingAdminTransfer = null },
                    onAdminTransferFinished = { message ->
                        pendingAdminTransfer = null
                        wdttDeepLinkMessage = message
                    },
                    onSelectWdttDeepLinkOverwriteProfile = { profile ->
                        pendingWdttDeepLinkPlan = pendingWdttDeepLinkPlan?.copy(targetProfile = profile)
                    },
                    onConfirmWdttDeepLinkOverwrite = { plan ->
                        pendingWdttDeepLinkPlan = null
                        applyWdttDeepLinkPlan(plan)
                    },
                    onCancelWdttDeepLinkOverwrite = {
                        pendingWdttDeepLinkPlan = null
                        wdttDeepLinkMessage = "Импорт wdtt:// ссылки отменён."
                    },
                    themeMode = themeMode,
                    onThemeChange = { mode ->
                        scope.launch {
                            settingsStore.saveThemeMode(mode)
                        }
                    },
                    isDynamicColor = isDynamicColor,
                    onDynamicColorChange = { enabled ->
                        scope.launch { settingsStore.saveDynamicColor(enabled) }
                    },
                    currentPalette = themePalette,
                    onPaletteChange = { palette ->
                        scope.launch { settingsStore.saveThemePalette(palette) }
                    },
                    activeFingerprint = activeFingerprint,
                    onFingerprintChange = { fp ->
                        scope.launch { settingsStore.saveFingerprint(fp) }
                    },
                    activeClientIds = activeClientIds,
                    onClientIdsChange = { ids ->
                        scope.launch { settingsStore.saveActiveClientIds(ids) }
                    }
                )
            }
        }
        handleIncomingIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIncomingIntent(intent)
    }

    private fun handleIncomingIntent(intent: Intent?) {
        when (intent?.action) {
            Intent.ACTION_VIEW -> {
                val data = intent.data ?: return
                if (data.scheme.equals("wdtt", ignoreCase = true)) {
                    handleIncomingTransferText(data.toString())
                } else {
                    handleIncomingUri(data, intent.type)
                }
            }
            Intent.ACTION_SEND -> {
                val streamUri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(Intent.EXTRA_STREAM) as? Uri
                } ?: intent.clipData?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.uri
                val streamFirst = intent.type?.let { type ->
                    type.startsWith("image/") || type == "application/json" ||
                        type == "application/vnd.wdtt.plus.transfer" ||
                            type == "application/vnd.wdtt.plus.client" ||
                            type == "application/octet-stream"
                } == true
                if (streamFirst && streamUri != null) {
                    handleIncomingUri(streamUri, intent.type)
                    return
                }
                val sharedText = intent.getStringExtra(Intent.EXTRA_TEXT)
                    ?: intent.clipData?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text?.toString()
                if (!sharedText.isNullOrBlank()) {
                    handleIncomingTransferText(sharedText)
                    return
                }
                if (streamUri != null) handleIncomingUri(streamUri, intent.type)
            }
        }
    }

    private fun handleIncomingUri(uri: Uri, mimeType: String?) {
        lifecycleScope.launch {
            runCatching {
                kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                    if (mimeType?.startsWith("image/") == true) {
                        TransferFiles.decodeQrImage(this@MainActivity, uri)
                    } else {
                        TransferFiles.readText(this@MainActivity, uri)
                    }
                }
            }.onSuccess(::handleIncomingTransferText)
                .onFailure { wdttDeepLinkMessage = it.message ?: "Не удалось прочитать переданные данные." }
        }
    }

    private fun handleIncomingTransferText(value: String) {
        val link = WdttTransferCodec.extractWdttLink(value)
        when {
            ClientTransferCodec.isClientTransfer(value) -> {
                ClientTransferInbox.offer(value)
                wdttDeepLinkMessage = "Распознан перенос клиента. В режиме «Я — админ» откройте «Деплой» → «Клиенты и сервер»: перед импортом приложение покажет проверку данных и целевого сервера."
            }
            link != null -> handleIncomingWdttLink(link)
            WdttTransferCodec.isAdminTransfer(value) -> pendingAdminTransfer = value.trim()
            WdttTransferCodec.documentFormat(value) == "wdtt-server-backup" -> {
                wdttDeepLinkMessage = "Распознана резервная копия сервера. Она применяется к выбранному серверу во вкладке «Деплой» → «Перенос сервера» → «Импорт»."
            }
            WdttTransferCodec.documentFormat(value) == "wdtt-plus-admin-settings" -> {
                wdttDeepLinkMessage = "Распознаны незашифрованные настройки администратора. В целях безопасности импортируется только защищённый файл, созданный через раздел «Передача»."
            }
            else -> handleIncomingVkShare(value)
        }
    }

    private fun handleIncomingWdttLink(link: String) {
        lifecycleScope.launch {
            val store = SettingsStore(this@MainActivity)
            runCatching {
                store.createWdttDeepLinkApplyPlan(link)
            }.onSuccess { plan ->
                if (plan == null) {
                    wdttDeepLinkMessage = WdttDeepLink.validate(link).userMessage()
                } else if (plan.requiresConfirmation) {
                    pendingWdttDeepLinkPlan = plan
                } else {
                    applyWdttDeepLinkPlan(plan)
                }
            }.onFailure { error ->
                wdttDeepLinkMessage = error.message ?: "Не удалось применить wdtt:// ссылку."
            }
        }
    }

    private fun applyWdttDeepLinkPlan(plan: WdttDeepLinkApplyPlan) {
        lifecycleScope.launch {
            val store = SettingsStore(this@MainActivity)
            runCatching {
                store.applyWdttDeepLink(plan)
            }.onSuccess { result ->
                wdttDeepLinkMessage = if (result == null) {
                    WdttDeepLink.validate(plan.link).userMessage()
                } else {
                    val profileLabel = vpnProfileDisplayName(result.targetProfile, store.profileNames.first())
                    val action = if (result.overwritten) "перезаписана" else "добавлена"
                    val mode = if (result.storedAsLink) "сохранена в режиме ссылки" else "разобрана, поля подключения заполнены"
                    "Ссылка wdtt:// $action в профиль $profileLabel: $mode."
                }
            }.onFailure { error ->
                wdttDeepLinkMessage = error.message ?: "Не удалось применить wdtt:// ссылку."
            }
        }
    }

    private fun handleIncomingVkShare(sharedText: String) {
        val trimmed = sharedText.trim().trim('<', '>', '"', '\'')
        val looksLikeJoinLink = trimmed.contains("/call/join/", ignoreCase = true)
        val looksLikeRawHash = Regex("^[A-Za-z0-9_-]{16,512}$").matches(trimmed)
        if (!looksLikeJoinLink && !looksLikeRawHash) {
            sharedVkHashError = "Данные не распознаны. Поддерживаются ссылка подключения wdtt://, файл или QR WDTT Plus и ссылка VK-звонка."
            return
        }
        val hash = VkJoinLink.extractHash(sharedText)
        if (hash.length < 16) {
            sharedVkHashError = "В переданной ссылке не найден VK-хеш звонка."
            return
        }
        lifecycleScope.launch {
            runCatching {
                SettingsStore(this@MainActivity).insertVkHashFromShare(hash)
            }.onSuccess { result ->
                sharedVkHashResult = result
                sharedVkHashError = null
            }.onFailure { error ->
                sharedVkHashError = error.message ?: "Не удалось сохранить VK-хеш."
            }
        }
    }

}

// ═══ Навигация ═══

@Composable
private fun RoleSelectionScreen(
    onRoleSelected: (String) -> Unit
) {
    Box(modifier = Modifier.fillMaxSize()) {
        AppBackdrop(modifier = Modifier.matchParentSize())
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Surface(
                shape = RoundedCornerShape(28.dp),
                color = MaterialTheme.colorScheme.surface.copy(alpha = 0.94f),
                tonalElevation = 8.dp,
                shadowElevation = 8.dp,
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(22.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        "Как вы будете использовать WDTT Plus?",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurface,
                        textAlign = TextAlign.Center
                    )
                    Text(
                        "Выбор можно поменять позже в шестерёнке настроек.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                        lineHeight = 20.sp
                    )

                    RoleChoiceButton(
                        title = "Я - юзер",
                        body = "Хочу подключиться к VPN, управлять подключением, исключениями и смотреть логи.",
                        icon = Icons.Filled.VpnKey,
                        onClick = { onRoleSelected("user") }
                    )
                    RoleChoiceButton(
                        title = "Я - админ",
                        body = "Хочу подключаться к VPN и дополнительно настраивать, переносить или обслуживать свой сервер.",
                        icon = Icons.Filled.Cloud,
                        onClick = { onRoleSelected("admin") }
                    )
                }
            }
        }
    }
}

@Composable
private fun RoleChoiceButton(
    title: String,
    body: String,
    icon: ImageVector,
    onClick: () -> Unit
) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(18.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.45f)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Surface(
                shape = RoundedCornerShape(14.dp),
                color = MaterialTheme.colorScheme.primaryContainer,
                contentColor = MaterialTheme.colorScheme.onPrimaryContainer
            ) {
                Box(modifier = Modifier.size(44.dp), contentAlignment = Alignment.Center) {
                    Icon(icon, contentDescription = null, modifier = Modifier.size(22.dp))
                }
            }
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text(
                    title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                    body,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    lineHeight = 17.sp
                )
            }
        }
    }
}

private enum class PermissionOnboardingStep {
    Notifications,
    Background
}

@Composable
private fun PermissionOnboardingScreen(
    onComplete: () -> Unit
) {
    val context = LocalContext.current
    var step by rememberSaveable { mutableStateOf(PermissionOnboardingStep.Notifications.name) }
    var batteryFallbackVisible by rememberSaveable { mutableStateOf(false) }
    val currentStep = PermissionOnboardingStep.valueOf(step)
    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) {
        step = PermissionOnboardingStep.Background.name
    }
    val batteryLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) {
        val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
        if (pm.isIgnoringBatteryOptimizations(context.packageName)) {
            onComplete()
        } else {
            batteryFallbackVisible = true
        }
    }

    fun requestNotificationsOrNext() {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            step = PermissionOnboardingStep.Background.name
        }
    }

    fun requestBackgroundOrFinish() {
        val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
        if (pm.isIgnoringBatteryOptimizations(context.packageName)) {
            onComplete()
        } else if (batteryFallbackVisible) {
            runCatching {
                val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                    data = Uri.parse("package:${context.packageName}")
                }
                context.startActivity(intent)
            }.onFailure {
                onComplete()
            }
        } else {
            runCatching {
                val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                    data = Uri.parse("package:${context.packageName}")
                }
                batteryLauncher.launch(intent)
            }.onFailure {
                batteryFallbackVisible = true
            }
        }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        AppBackdrop(modifier = Modifier.matchParentSize())
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Surface(
                shape = RoundedCornerShape(28.dp),
                color = MaterialTheme.colorScheme.surface.copy(alpha = 0.94f),
                tonalElevation = 8.dp,
                shadowElevation = 8.dp,
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(22.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    val isNotifications = currentStep == PermissionOnboardingStep.Notifications
                    Surface(
                        shape = RoundedCornerShape(22.dp),
                        color = MaterialTheme.colorScheme.primaryContainer,
                        contentColor = MaterialTheme.colorScheme.onPrimaryContainer
                    ) {
                        Box(modifier = Modifier.size(58.dp), contentAlignment = Alignment.Center) {
                            Icon(
                                imageVector = if (isNotifications) Icons.Filled.Notifications else Icons.Filled.BatterySaver,
                                contentDescription = null,
                                modifier = Modifier.size(30.dp)
                            )
                        }
                    }
                    Text(
                        if (isNotifications) "Уведомления" else "Фоновая работа",
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Black,
                        color = MaterialTheme.colorScheme.onSurface,
                        textAlign = TextAlign.Center
                    )
                    Text(
                        if (isNotifications) {
                            "WDTT Plus использует уведомление, чтобы показывать состояние туннеля, ошибки подключения и важные действия вроде капчи. Для полноценной работы приложения без ошибок очень рекомендуется выдать этот доступ."
                        } else if (batteryFallbackVisible) {
                            "Системное окно фонового режима не открылось или разрешение не было выдано. Откройте настройки приложения и отключите ограничения батареи для WDTT Plus; это очень рекомендуется для стабильной работы без ошибок."
                        } else {
                            "Фоновый режим помогает туннелю не засыпать при выключенном экране, смене сети и долгой работе VPN. Для полноценной работы приложения без ошибок очень рекомендуется разрешить фоновую работу."
                        },
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                        lineHeight = 21.sp
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        OutlinedButton(
                            onClick = {
                                if (isNotifications) step = PermissionOnboardingStep.Background.name else onComplete()
                            },
                            modifier = Modifier.weight(1f).fillMaxHeight().heightIn(min = 50.dp),
                            shape = RoundedCornerShape(16.dp),
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                        ) {
                            Text("Отказать", fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center)
                        }
                        Button(
                            onClick = {
                                if (isNotifications) requestNotificationsOrNext() else requestBackgroundOrFinish()
                            },
                            modifier = Modifier.weight(1f).fillMaxHeight().heightIn(min = 50.dp),
                            shape = RoundedCornerShape(16.dp),
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                        ) {
                            Text(
                                if (!isNotifications && batteryFallbackVisible) "Открыть настройки" else "Разрешить",
                                fontWeight = FontWeight.Bold,
                                textAlign = TextAlign.Center
                            )
                        }
                    }
                }
            }
        }
    }
}

private data class NavItem(
    val id: Int,
    val label: String,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector,
)

private val navItems = listOf(
    NavItem(0, "Туннель", Icons.Filled.VpnKey, Icons.Outlined.VpnKey),
    NavItem(1, "Деплой", Icons.Filled.Cloud, Icons.Outlined.Cloud),
    NavItem(2, "Исключ.", Icons.Filled.FilterList, Icons.Outlined.FilterList),
    NavItem(3, "Логи", Icons.Filled.Terminal, Icons.Outlined.Terminal),
    NavItem(4, "Инфо", Icons.Filled.Info, Icons.Outlined.Info),
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    settingsStore: SettingsStore,
    sharedVkHashResult: VkHashInsertResult? = null,
    sharedVkHashError: String? = null,
    onSharedVkHashMessageShown: () -> Unit = {},
    wdttDeepLinkMessage: String? = null,
    onWdttDeepLinkMessageShown: () -> Unit = {},
    pendingWdttDeepLinkPlan: WdttDeepLinkApplyPlan? = null,
    pendingAdminTransfer: String? = null,
    onIncomingTransferContent: (String) -> Unit = {},
    onAdminTransferDismissed: () -> Unit = {},
    onAdminTransferFinished: (String) -> Unit = {},
    onSelectWdttDeepLinkOverwriteProfile: (Int) -> Unit = {},
    onConfirmWdttDeepLinkOverwrite: (WdttDeepLinkApplyPlan) -> Unit = {},
    onCancelWdttDeepLinkOverwrite: () -> Unit = {},
    themeMode: String = "system",
    onThemeChange: (String) -> Unit = {},
    isDynamicColor: Boolean = false,
    onDynamicColorChange: (Boolean) -> Unit = {},
    currentPalette: String = "indigo",
    onPaletteChange: (String) -> Unit = {},
    activeFingerprint: String = "firefox",
    onFingerprintChange: (String) -> Unit = {},
    activeClientIds: String = "6287487,8202606",
    onClientIdsChange: (String) -> Unit = {}
) {
    val unreadErrors by TunnelManager.unreadErrorCount.collectAsStateWithLifecycle()
    val tunnelRunning by TunnelManager.running.collectAsStateWithLifecycle()
    val view = LocalView.current
    val context = LocalContext.current
    val density = LocalDensity.current
    val focusManager = LocalFocusManager.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val scope = rememberCoroutineScope()
    val updateCheckMutex = remember { Mutex() }
    val settingsReady by settingsStore.settingsReady.collectAsStateWithLifecycle(initialValue = false)
    if (!settingsReady) {
        Box(modifier = Modifier.fillMaxSize()) {
            AppBackdrop(modifier = Modifier.matchParentSize())
        }
        return
    }
    val activeProfile by settingsStore.activeProfile.collectAsStateWithLifecycle(initialValue = 0)
    val profileNames by settingsStore.profileNames.collectAsStateWithLifecycle(initialValue = emptyList())
    val wdttLinkMode by settingsStore.wdttLinkMode.collectAsStateWithLifecycle(initialValue = false)
    val migrationDeployHost by settingsStore.deployIp.collectAsStateWithLifecycle(initialValue = "")
    val migrationSshPassword by settingsStore.deployPassword.collectAsStateWithLifecycle(initialValue = "")
    val migrationSshPrivateKey by settingsStore.deploySshPrivateKey.collectAsStateWithLifecycle(initialValue = "")
    val migrationSshAuthMode by settingsStore.deploySshAuthMode.collectAsStateWithLifecycle(initialValue = "password")
    val migrationMainPassword by settingsStore.deployMainPassword.collectAsStateWithLifecycle(initialValue = "")
    val interfaceRole by settingsStore.interfaceRole.collectAsStateWithLifecycle(initialValue = "")
    val permissionOnboardingComplete by settingsStore.permissionOnboardingComplete.collectAsStateWithLifecycle(initialValue = false)
    val serverMigrationState by settingsStore.serverMigrationState.collectAsStateWithLifecycle(initialValue = null)
    val deviceCompatibilityCheckComplete by settingsStore.deviceCompatibilityCheckComplete.collectAsStateWithLifecycle(
        initialValue = true
    )
    val isAdminInterface = interfaceRole == "admin"
    val isUpdatedInstall = remember(context) {
        runCatching {
            context.packageManager.getPackageInfo(context.packageName, 0).let { info ->
                info.lastUpdateTime > info.firstInstallTime
            }
        }.getOrDefault(false)
    }
    LaunchedEffect(settingsStore, isUpdatedInstall) {
        settingsStore.initializeServerMigrationState(
            currentVersionCode = BuildConfig.VERSION_CODE,
            isUpdatedInstall = isUpdatedInstall
        )
    }
    var selectedTab by rememberSaveable { mutableIntStateOf(0) }
    val tunnelScrollPosition = rememberSaveable { mutableIntStateOf(0) }
    val deployScrollPosition = rememberSaveable { mutableIntStateOf(0) }
    val exceptionsFirstVisibleItemIndex = rememberSaveable { mutableIntStateOf(0) }
    val exceptionsFirstVisibleItemScrollOffset = rememberSaveable { mutableIntStateOf(0) }
    val logsFirstVisibleItemIndex = rememberSaveable { mutableIntStateOf(0) }
    val logsFirstVisibleItemScrollOffset = rememberSaveable { mutableIntStateOf(0) }
    val infoScrollPosition = rememberSaveable { mutableIntStateOf(0) }
    var dragTargetIndex by remember { mutableIntStateOf(-1) }
    var dragProgress by remember { mutableFloatStateOf(0f) }
    val updateCheckIntervalMinutes by settingsStore.updateCheckIntervalMinutes.collectAsStateWithLifecycle(
        initialValue = DEFAULT_UPDATE_CHECK_INTERVAL_MINUTES
    )
    var pendingUpdateCandidate by remember { mutableStateOf<AppUpdateCandidate?>(null) }
    var updateDownloadProgress by remember { mutableStateOf<AppUpdateDownloadProgress?>(null) }
    var updateDownloadStatus by rememberSaveable { mutableStateOf("") }
    var updateDownloadBusy by remember { mutableStateOf(false) }
    var pendingUpdateApkPath by rememberSaveable { mutableStateOf<String?>(null) }
    var startupUpdateCheckComplete by remember { mutableStateOf(false) }
    val startupUpdateCheckCompleteState by rememberUpdatedState(startupUpdateCheckComplete)
    val currentVersion = remember { "v${BuildConfig.VERSION_NAME.removePrefix("v")}" }
    val safeBottomInset = with(density) { WindowInsets.safeDrawing.getBottom(density).toDp() }
    val navOverlayReserve = safeBottomInset + 96.dp
    var showTransferCenter by rememberSaveable { mutableStateOf(false) }
    var startupDeviceReport by remember { mutableStateOf<DeviceCompatibilityReport?>(null) }
    var startupDeviceCheckRunning by remember { mutableStateOf(false) }
    val updateInstallPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) {
        val apkFile = pendingUpdateApkPath?.let(::File)
        if (apkFile != null && apkFile.exists() && canRequestApkInstall(context)) {
            runCatching {
                installUpdateApk(context, apkFile)
                pendingUpdateCandidate = null
                updateDownloadStatus = ""
                updateDownloadProgress = null
            }.onFailure { error ->
                updateDownloadStatus = error.message ?: "Не удалось открыть установку APK."
                Toast.makeText(context, updateDownloadStatus, Toast.LENGTH_LONG).show()
            }
        } else if (apkFile != null) {
            updateDownloadStatus = "Разрешение на установку из WDTT Plus не выдано."
            Toast.makeText(context, updateDownloadStatus, Toast.LENGTH_LONG).show()
        }
    }

    fun requestDownloadedUpdateInstall(apkFile: File) {
        pendingUpdateApkPath = apkFile.absolutePath
        if (!canRequestApkInstall(context)) {
            updateDownloadStatus = "Разрешите установку из WDTT Plus в настройках Android."
            val intent = Intent(
                Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                Uri.parse("package:${context.packageName}")
            )
            updateInstallPermissionLauncher.launch(intent)
            return
        }

        runCatching {
            installUpdateApk(context, apkFile)
            pendingUpdateCandidate = null
            updateDownloadStatus = ""
            updateDownloadProgress = null
        }.onFailure { error ->
            updateDownloadStatus = error.message ?: "Не удалось открыть установку APK."
            Toast.makeText(context, updateDownloadStatus, Toast.LENGTH_LONG).show()
        }
    }

    fun dismissStartupDeviceReport() {
        startupDeviceReport = null
        scope.launch {
            settingsStore.saveDeviceCompatibilityCheckComplete(true)
        }
    }

    LaunchedEffect(deviceCompatibilityCheckComplete) {
        if (!deviceCompatibilityCheckComplete && !startupDeviceCheckRunning) {
            startupDeviceCheckRunning = true
            val report = withContext(Dispatchers.Default) {
                DeviceCompatibility.check(
                    context = context.applicationContext,
                    includeRuntimeChecks = false
                )
            }.firstLaunchReport()

            if (report.items.isEmpty()) {
                settingsStore.saveDeviceCompatibilityCheckComplete(true)
            } else {
                startupDeviceReport = report
            }
            startupDeviceCheckRunning = false
        }
    }

    if (interfaceRole.isBlank()) {
        RoleSelectionScreen(
            onRoleSelected = { role ->
                scope.launch { settingsStore.saveInterfaceRole(role) }
            }
        )
        startupDeviceReport?.let { report ->
            DeviceCompatibilityDialog(
                report = report,
                title = "Проверка устройства",
                subtitle = "WDTT Plus нашёл нюансы совместимости. Запуск не блокируется — это предупреждение, чтобы было понятно, куда смотреть при проблемах.",
                note = "Первый запуск проверяет только базовую совместимость устройства: Android, ABI, нативный клиент, память и page size. Активен ли VPN сейчас — на этом этапе не важно.",
                onDismiss = ::dismissStartupDeviceReport
            )
        }
        return
    }

    if (!permissionOnboardingComplete) {
        PermissionOnboardingScreen(
            onComplete = {
                scope.launch { settingsStore.savePermissionOnboardingComplete(true) }
            }
        )
        startupDeviceReport?.let { report ->
            DeviceCompatibilityDialog(
                report = report,
                title = "Проверка устройства",
                subtitle = "WDTT Plus нашёл нюансы совместимости. Запуск не блокируется — это предупреждение, чтобы было понятно, куда смотреть при проблемах.",
                note = "Первый запуск проверяет только базовую совместимость устройства: Android, ABI, нативный клиент, память и page size. Активен ли VPN сейчас — на этом этапе не важно.",
                onDismiss = ::dismissStartupDeviceReport
            )
        }
        return
    }

    val activeNavItems = remember(wdttLinkMode, isAdminInterface) {
        navItems.filter { item ->
            val allowedByRole = isAdminInterface || item.id != 1
            val allowedByLinkMode = !wdttLinkMode || item.id != 1
            allowedByRole && allowedByLinkMode
        }
    }
    val actionsExpanded = rememberSaveable { mutableStateOf(false) }
    val projectExpanded = rememberSaveable { mutableStateOf(false) }
    val tabStateHolder = rememberSaveableStateHolder()



    LaunchedEffect(wdttLinkMode, interfaceRole) {
        if (activeNavItems.none { it.id == selectedTab }) {
            selectedTab = 0
        }
    }

    LaunchedEffect(sharedVkHashResult, sharedVkHashError) {
        if (sharedVkHashResult != null || sharedVkHashError != null) {
            selectedTab = 0
        }
    }

    LaunchedEffect(wdttDeepLinkMessage) {
        if (wdttDeepLinkMessage != null) {
            selectedTab = 0
        }
    }

    LaunchedEffect(pendingWdttDeepLinkPlan) {
        if (pendingWdttDeepLinkPlan != null) {
            selectedTab = 0
        }
    }

    LaunchedEffect(selectedTab) {
        if (selectedTab == 3) TunnelManager.clearUnreadErrors()
    }

    suspend fun runUpdateCheck(
        reason: String,
        shouldRun: suspend () -> Boolean = { true }
    ) {
        if (updateCheckIntervalMinutes == UPDATE_CHECK_NEVER) return

        updateCheckMutex.withLock {
            if (!shouldRun()) return@withLock
            val checkedAt = System.currentTimeMillis()
            var release: AppReleaseInfo? = null
            var updateCandidate: AppUpdateCandidate? = null
            var errorMessage = ""
            runCatching {
                release = fetchLatestReleaseInfo(currentVersion)
                if (release == null) {
                    errorMessage = "Не удалось проверить"
                    return@runCatching
                }
                updateCandidate = resolveAppUpdateCandidate(context, currentVersion, release)
            }.onFailure { error ->
                errorMessage = error.message ?: "Не удалось проверить"
                Log.w("WDTT", "[WARN] Update check failed unexpectedly, local=$currentVersion reason=$reason", error)
            }
            settingsStore.saveUpdateState(
                lastCheckAt = checkedAt,
                latestVersion = release?.versionTag ?: "",
                error = errorMessage
            )

            if (release == null) {
                Log.w("WDTT", "[WARN] Update check: no release info, local=$currentVersion reason=$reason")
                return@withLock
            }

            val candidate = updateCandidate
            val hasUpdate = candidate != null
            val postponeVer = settingsStore.updatePostponeVersion.first()
            val postponeUntil = settingsStore.updatePostponeUntil.first()
            val isPostponed = candidate != null && postponeVer == candidate.postponeKey && checkedAt < postponeUntil
            Log.i(
                "WDTT",
                "Update check: local=$currentVersion remote=${release?.versionTag} candidate=${candidate?.kind} newer=$hasUpdate postponed=$isPostponed reason=$reason"
            )

            if (candidate != null && !isPostponed) {
                settingsStore.saveUpdateDialogShown(candidate.postponeKey, checkedAt)
                pendingUpdateCandidate = candidate
            }
        }
    }

    DisposableEffect(lifecycleOwner, updateCheckIntervalMinutes) {
        val observer = LifecycleEventObserver { _, event ->
            if (
                event == Lifecycle.Event.ON_START &&
                startupUpdateCheckCompleteState &&
                updateCheckIntervalMinutes != UPDATE_CHECK_NEVER
            ) {
                scope.launch {
                    runUpdateCheck("foreground") {
                        val now = System.currentTimeMillis()
                        val lastCheckAt = settingsStore.updateLastCheckAt.first()
                        shouldRunForegroundUpdateCheck(lastCheckAt, now)
                    }
                }
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
        }
    }

    LaunchedEffect(updateCheckIntervalMinutes) {
        if (updateCheckIntervalMinutes == UPDATE_CHECK_NEVER) return@LaunchedEffect

        val intervalMillis = updateIntervalMinutesToMillis(updateCheckIntervalMinutes)
            ?: updateIntervalMinutesToMillis(DEFAULT_UPDATE_CHECK_INTERVAL_MINUTES)
            ?: DEFAULT_UPDATE_CHECK_INTERVAL_MINUTES * 60L * 1000L

        runUpdateCheck("startup")
        startupUpdateCheckComplete = true

        while (isActive) {
            val now = System.currentTimeMillis()
            val lastCheck = settingsStore.updateLastCheckAt.first()
            val nextCheckAt = lastCheck + intervalMillis
            val waitMs = (nextCheckAt - now).coerceAtLeast(intervalMillis)
            delay(waitMs)
            if (isActive) {
                runUpdateCheck("periodic") {
                    val currentTime = System.currentTimeMillis()
                    val currentLastCheck = settingsStore.updateLastCheckAt.first()
                    currentTime - currentLastCheck >= intervalMillis
                }
            }
        }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        AppBackdrop(modifier = Modifier.matchParentSize())

        Scaffold(
            contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal + WindowInsetsSides.Top),
            containerColor = Color.Transparent,
        ) { padding ->
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .consumeWindowInsets(padding)
                    .pointerInput(focusManager) {
                        awaitPointerEventScope {
                            while (true) {
                                val event = awaitPointerEvent(PointerEventPass.Initial)
                                if (event.type == PointerEventType.Press) {
                                    focusManager.clearFocus()
                                }
                            }
                        }
                    }
                    .pointerInput(selectedTab, wdttLinkMode) {
                        var totalDrag = 0f
                        detectHorizontalDragGestures(
                            onDragStart = {
                                totalDrag = 0f
                                dragTargetIndex = -1
                                dragProgress = 0f
                            },
                            onDragCancel = {
                                dragTargetIndex = -1
                                dragProgress = 0f
                            },
                            onDragEnd = {
                                if (dragTargetIndex in activeNavItems.indices && dragProgress >= 0.5f) {
                                    selectedTab = activeNavItems[dragTargetIndex].id
                                    if (selectedTab == 3) TunnelManager.clearUnreadErrors()
                                }
                                dragTargetIndex = -1
                                dragProgress = 0f
                            }
                        ) { change, dragAmount ->
                            if (change.isConsumed) return@detectHorizontalDragGestures
                            change.consume()
                            totalDrag += dragAmount
                            if (abs(totalDrag) < 12f) {
                                dragTargetIndex = -1
                                dragProgress = 0f
                                return@detectHorizontalDragGestures
                            }

                            val currentActiveIndex = activeNavItems.indexOfFirst { it.id == selectedTab }
                            val candidate = if (totalDrag < 0f) currentActiveIndex + 1 else currentActiveIndex - 1
                            if (candidate !in activeNavItems.indices) {
                                dragTargetIndex = -1
                                dragProgress = 0f
                                return@detectHorizontalDragGestures
                            }

                            dragTargetIndex = candidate
                            dragProgress = (abs(totalDrag) / 180f).coerceIn(0f, 1f)
                        }
                    }
            ) {
                val deployVisible = selectedTab == 1 && !wdttLinkMode
                val deployAvailable = activeNavItems.any { it.id == 1 } && !wdttLinkMode
                val deployAlpha by animateFloatAsState(
                    targetValue = if (deployVisible) 1f else 0f,
                    animationSpec = tween(durationMillis = if (deployVisible) 300 else 225),
                    label = "deploy_tab_fade"
                )
                if (deployAvailable) {
                    tabStateHolder.SaveableStateProvider("deploy_persistent") {
                        DeployTab(
                            scrollPosition = deployScrollPosition,
                            visible = deployVisible,
                            modifier = Modifier
                                .fillMaxSize()
                                .padding(bottom = navOverlayReserve)
                                .graphicsLayer { alpha = deployAlpha }
                                .zIndex(if (deployVisible || deployAlpha > 0f) 1f else -1f)
                        )
                    }
                }

                AnimatedContent(
                    targetState = if (deployVisible) -1 else selectedTab,
                    transitionSpec = {
                        fadeIn(tween(300)) togetherWith fadeOut(tween(225))
                    },
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(bottom = navOverlayReserve),
                    label = "tab_content"
                ) { tab ->
                    tabStateHolder.SaveableStateProvider(tab) {
                        when (tab) {
                            -1 -> Spacer(modifier = Modifier.fillMaxSize())
                            0 -> SettingsTab(scrollPosition = tunnelScrollPosition)
                            1 -> Spacer(modifier = Modifier.fillMaxSize())
                            2 -> ExceptionsTab(
                                firstVisibleItemIndex = exceptionsFirstVisibleItemIndex,
                                firstVisibleItemScrollOffset = exceptionsFirstVisibleItemScrollOffset
                            )
                            3 -> LogsTab(
                                firstVisibleItemIndex = logsFirstVisibleItemIndex,
                                firstVisibleItemScrollOffset = logsFirstVisibleItemScrollOffset
                            )
                            4 -> InfoTab(
                                actionsExpandedState = actionsExpanded,
                                projectExpandedState = projectExpanded,
                                scrollPosition = infoScrollPosition
                            )
                        }
                    }
                }

                ProxyNavigationBar(
                    navItems = activeNavItems,
                    selectedTab = selectedTab,
                    dragTargetIndex = dragTargetIndex,
                    dragProgress = dragProgress,
                    unreadErrors = unreadErrors,
                    tunnelRunning = tunnelRunning,
                    onTabSelected = { index ->
                        if (selectedTab != index) {
                            view.performHapticFeedback(HapticFeedbackConstants.CLOCK_TICK)
                            selectedTab = index
                            if (index == 3) TunnelManager.clearUnreadErrors()
                        }
                        dragTargetIndex = -1
                        dragProgress = 0f
                    },
                    modifier = Modifier.align(Alignment.BottomCenter)
                )
            }
        }

        // Floating theme toolbar overlay
        FloatingToolbar(
            activeProfile = activeProfile,
            profileNames = profileNames,
            onActiveProfileChange = { profile ->
                scope.launch { settingsStore.saveActiveProfile(profile) }
            },
            onProfileNameChange = { profile, name ->
                scope.launch { settingsStore.saveProfileName(profile, name) }
            },
            interfaceRole = interfaceRole,
            onInterfaceRoleChange = { role ->
                scope.launch { settingsStore.saveInterfaceRole(role) }
            },
            currentTheme = themeMode,
            onThemeChange = onThemeChange,
            isDynamicColor = isDynamicColor,
            onDynamicColorChange = onDynamicColorChange,
            currentPalette = currentPalette,
            onPaletteChange = onPaletteChange,
            activeFingerprint = activeFingerprint,
            onFingerprintChange = onFingerprintChange,
            activeClientIds = activeClientIds,
            onClientIdsChange = onClientIdsChange,
            onTransferRequested = { showTransferCenter = true }
        )
    }

    val migrationNotice = serverMigrationState
    val activeProfileManagesServer = hasManagedServerCredentials(
        host = migrationDeployHost,
        sshAuthMode = migrationSshAuthMode,
        sshPassword = migrationSshPassword,
        mainPassword = migrationMainPassword,
        sshPrivateKey = migrationSshPrivateKey
    )
    if (
        isAdminInterface &&
        activeProfileManagesServer &&
        migrationNotice?.noticeRequired == true &&
        pendingUpdateCandidate == null &&
        startupDeviceReport == null
    ) {
        AlertDialog(
            onDismissRequest = {},
            properties = DialogProperties(
                dismissOnBackPress = false,
                dismissOnClickOutside = false
            ),
            title = { Text("Обновите серверную часть") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(
                        "В новых версиях WDTT Plus была изменена серверная часть. Для корректной работы приложения с сервером выполните установку сервера с сохранением данных во вкладке «Деплой».\n\n" +
                            "Клиенты, выданные доступы и настройки сохранятся. Установку с нуля выполнять не нужно."
                    )
                    Text(
                        "После успешной установки приложение отметит обновление для выбранного VPN-профиля.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        scope.launch {
                            settingsStore.acknowledgeServerMigrationNotice(migrationNotice.pendingLevel)
                            selectedTab = 1
                        }
                    }
                ) {
                    Text("Перейти в Деплой")
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        scope.launch {
                            settingsStore.acknowledgeServerMigrationNotice(migrationNotice.pendingLevel)
                        }
                    }
                ) {
                    Text("Позже")
                }
            }
        )
    }

    startupDeviceReport?.let { report ->
        DeviceCompatibilityDialog(
            report = report,
            title = "Проверка устройства",
            subtitle = "WDTT Plus нашёл нюансы совместимости. Запуск не блокируется — это предупреждение, чтобы было понятно, куда смотреть при проблемах.",
            note = "Первый запуск проверяет только базовую совместимость устройства: Android, ABI, нативный клиент, память и page size. Активен ли VPN сейчас — на этом этапе не важно.",
            onDismiss = ::dismissStartupDeviceReport
        )
    }

    if (showTransferCenter) {
        TransferCenterDialog(
            settingsStore = settingsStore,
            activeProfile = activeProfile,
            isAdmin = isAdminInterface,
            onIncomingContent = {
                showTransferCenter = false
                onIncomingTransferContent(it)
            },
            onDismiss = { showTransferCenter = false }
        )
    }

    pendingAdminTransfer?.let { document ->
        AdminImportDialog(
            settingsStore = settingsStore,
            encryptedDocument = document,
            onFinished = onAdminTransferFinished,
            onDismiss = onAdminTransferDismissed
        )
    }

    pendingUpdateCandidate?.let { candidate ->
        val release = candidate.release
        val apkAsset = remember(release) { selectUpdateApkAsset(release) }
        AppUpdateDialog(
            release = release,
            updateKind = candidate.kind,
            apkAsset = apkAsset,
            isDownloading = updateDownloadBusy,
            downloadProgress = updateDownloadProgress,
            downloadStatus = updateDownloadStatus,
            onPostpone = {
                pendingUpdateCandidate = null
                updateDownloadStatus = ""
                updateDownloadProgress = null
                Toast.makeText(context, "Обновление отложено на 24 часа.", Toast.LENGTH_SHORT).show()
                scope.launch {
                    val now = System.currentTimeMillis()
                    settingsStore.saveUpdatePostpone(
                        version = candidate.postponeKey,
                        until = now + 24L * 60L * 60L * 1000L
                    )
                    settingsStore.saveUpdateDialogAction(
                        version = candidate.postponeKey,
                        action = UPDATE_DIALOG_ACTION_POSTPONED,
                        actedAt = now
                    )
                }
            },
            onUpdate = {
                scope.launch {
                    settingsStore.saveUpdateDialogAction(
                        version = candidate.postponeKey,
                        action = UPDATE_DIALOG_ACTION_UPDATE,
                        actedAt = System.currentTimeMillis()
                    )
                    if (apkAsset == null) {
                        pendingUpdateCandidate = null
                        openReleaseUrl(context, release.releaseUrl)
                        return@launch
                    }

                    updateDownloadBusy = true
                    updateDownloadStatus = "Подготовка скачивания..."
                    updateDownloadProgress = null
                    runCatching {
                        val apkFile = downloadUpdateApk(context, apkAsset) { progress ->
                            updateDownloadProgress = progress
                            updateDownloadStatus = if (progress.percent != null) {
                                "Скачивание APK"
                            } else {
                                "Скачивание APK..."
                            }
                        }
                        updateDownloadStatus = if (apkAsset.sha256 != null) {
                            "APK скачан и проверен. Открываю установку..."
                        } else {
                            "APK скачан. Открываю установку..."
                        }
                        requestDownloadedUpdateInstall(apkFile)
                    }.onFailure { error ->
                        updateDownloadStatus = error.message ?: "Не удалось скачать обновление."
                        Toast.makeText(context, updateDownloadStatus, Toast.LENGTH_LONG).show()
                    }
                    updateDownloadBusy = false
                }
            },
            onOpenRelease = {
                pendingUpdateCandidate = null
                updateDownloadStatus = ""
                updateDownloadProgress = null
                openReleaseUrl(context, release.releaseUrl)
            }
        )
    }

    sharedVkHashResult?.let { result ->
        SharedVkHashDialog(
            result = result,
            onDismiss = onSharedVkHashMessageShown
        )
    }

    sharedVkHashError?.let { error ->
        AlertDialog(
            onDismissRequest = onSharedVkHashMessageShown,
            title = { Text("Данные не импортированы") },
            text = { Text(error) },
            confirmButton = {
                TextButton(onClick = onSharedVkHashMessageShown) {
                    Text("Понятно")
                }
            }
        )
    }

    wdttDeepLinkMessage?.let { message ->
        AlertDialog(
            onDismissRequest = onWdttDeepLinkMessageShown,
            title = { Text("Передача WDTT") },
            text = { Text(message) },
            confirmButton = {
                TextButton(onClick = onWdttDeepLinkMessageShown) {
                    Text("ОК")
                }
            }
        )
    }

    pendingWdttDeepLinkPlan?.let { plan ->
        val profileLabel = vpnProfileDisplayName(plan.targetProfile, profileNames)
        val incomingProfileName = WdttDeepLink.parse(plan.link)?.profileName.orEmpty()
        AlertDialog(
            onDismissRequest = onCancelWdttDeepLinkOverwrite,
            title = { Text("Профили VPN заполнены") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("Свободных профилей VPN нет. Выберите профиль, который можно перезаписать:")
                    if (incomingProfileName.isNotBlank()) {
                        Text("Название из подключения: «$incomingProfileName».")
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        repeat(3) { profile ->
                            FilterChip(
                                selected = plan.targetProfile == profile,
                                onClick = { onSelectWdttDeepLinkOverwriteProfile(profile) },
                                label = { Text(vpnProfileDisplayName(profile, profileNames)) }
                            )
                        }
                    }
                    Text("Будет полностью заменено подключение в профиле $profileLabel.")
                }
            },
            confirmButton = {
                TextButton(onClick = { onConfirmWdttDeepLinkOverwrite(plan) }) {
                    Text("Да")
                }
            },
            dismissButton = {
                TextButton(onClick = onCancelWdttDeepLinkOverwrite) {
                    Text("Нет")
                }
            }
        )
    }
}

@Composable
private fun SharedVkHashDialog(
    result: VkHashInsertResult,
    onDismiss: () -> Unit
) {
    val previous = result.previousHash
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("VK-хеш добавлен") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Слот VK Хеш ${result.slot} обновлён.")
                Text(
                    text = result.hash,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.primary
                )
                if (previous.isNotBlank()) {
                    Text(
                        text = "Предыдущее значение было перезаписано: $previous",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("Понятно")
            }
        }
    )
}

@Composable
private fun ProxyNavigationBar(
    navItems: List<NavItem>,
    selectedTab: Int,
    dragTargetIndex: Int,
    dragProgress: Float,
    unreadErrors: Int,
    tunnelRunning: Boolean,
    onTabSelected: (Int) -> Unit,
    modifier: Modifier = Modifier
) {
    val colors = MaterialTheme.colorScheme
    val isDark = colors.background.luminance() < 0.22f
    val selectedColor = colors.primary
    val unselectedColor = colors.onSurfaceVariant.copy(alpha = 0.55f)
    val shellColor = if (isDark) {
        colors.surface.copy(alpha = 0.78f)
    } else {
        lerp(colors.surface, colors.surfaceVariant, 0.48f).copy(alpha = 0.95f)
    }
    val shellBorder = if (isDark) {
        colors.outlineVariant.copy(alpha = 0.42f)
    } else {
        colors.outline.copy(alpha = 0.16f)
    }
    val indicatorColor = if (isDark) {
        colors.primaryContainer.copy(alpha = 0.84f)
    } else {
        lerp(colors.primaryContainer, colors.surface, 0.18f).copy(alpha = 0.97f)
    }
    val selectedVisualIndex = remember(selectedTab, navItems) {
        navItems.indexOfFirst { it.id == selectedTab }.coerceAtLeast(0)
    }
    val indicatorIndex = remember { Animatable(selectedVisualIndex.toFloat()) }
    val dragVisualIndex = indicatorIndex.value

    LaunchedEffect(selectedVisualIndex) {
        if (dragTargetIndex !in navItems.indices) {
            indicatorIndex.animateTo(
                targetValue = selectedVisualIndex.toFloat(),
                animationSpec = tween(
                    durationMillis = 720,
                    easing = CubicBezierEasing(0.2f, 0.9f, 0.24f, 1f)
                )
            )
        }
    }

    LaunchedEffect(selectedVisualIndex, dragTargetIndex, dragProgress) {
        if (dragTargetIndex in navItems.indices) {
            val target = selectedVisualIndex.toFloat() + (dragTargetIndex - selectedVisualIndex) * dragProgress
            indicatorIndex.snapTo(target)
        }
    }

    BoxWithConstraints(
        modifier = modifier
            .fillMaxWidth()
            .windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal + WindowInsetsSides.Bottom))
            .padding(horizontal = 22.dp, vertical = 12.dp)
    ) {
        val trackPadding = 8.dp
        val itemWidth = (maxWidth - trackPadding * 2) / navItems.size
        val indicatorOffset = trackPadding + itemWidth * dragVisualIndex

        Surface(
            shape = RoundedCornerShape(28.dp),
            color = shellColor,
            border = BorderStroke(1.dp, shellBorder),
            tonalElevation = 0.dp,
            shadowElevation = if (isDark) 10.dp else 8.dp,
            modifier = Modifier.fillMaxWidth()
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(72.dp)
            ) {
                Surface(
                    shape = RoundedCornerShape(22.dp),
                    color = indicatorColor,
                    modifier = Modifier
                        .offset(x = indicatorOffset)
                        .padding(vertical = 6.dp)
                        .width(itemWidth)
                        .fillMaxHeight()
                ) {}

                Row(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = trackPadding, vertical = 6.dp)
                ) {
                    navItems.forEachIndexed { index, item ->
                        val emphasis = (1f - abs(index - dragVisualIndex)).coerceIn(0f, 1f)
                        val iconColor = lerp(unselectedColor, selectedColor, emphasis)

                        Column(
                            modifier = Modifier
                                .weight(1f)
                                .fillMaxHeight()
                                .clip(RoundedCornerShape(22.dp))
                                .clickable { onTabSelected(item.id) },
                            verticalArrangement = Arrangement.Center,
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Box(contentAlignment = Alignment.TopEnd) {
                                Icon(
                                    imageVector = if (emphasis > 0.55f) item.selectedIcon else item.unselectedIcon,
                                    contentDescription = item.label,
                                    modifier = Modifier.size(22.dp),
                                    tint = iconColor
                                )
                                if (item.id == 3 && unreadErrors > 0) {
                                    Badge(
                                        containerColor = if (tunnelRunning) colors.primary else WDTTColors.warning,
                                        contentColor = colors.onPrimary,
                                        modifier = Modifier.offset(x = 12.dp, y = (-8).dp)
                                    ) {
                                        Text("$unreadErrors")
                                    }
                                }
                            }
                            Spacer(Modifier.height(4.dp))
                            Text(
                                text = item.label,
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = if (emphasis > 0.55f) FontWeight.SemiBold else FontWeight.Medium,
                                color = iconColor,
                                maxLines = 1
                            )
                        }
                    }
                }
            }
        }
    }
}

private fun openReleaseUrl(context: Context, url: String) {
    try {
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url)).apply {
            addCategory(Intent.CATEGORY_BROWSABLE)
        }
        context.startActivity(intent)
    } catch (_: Exception) {
        Toast.makeText(context, "Не удалось открыть ссылку", Toast.LENGTH_SHORT).show()
    }
}

private fun android16OrbShape(points: Int, innerRatio: Float): Shape = GenericShape { size, _ ->
    val centerX = size.width / 2f
    val centerY = size.height / 2f
    val outerRadius = min(size.width, size.height) / 2f
    val innerRadius = outerRadius * innerRatio

    for (i in 0 until points * 2) {
        val angle = (-PI / 2.0) + (i * PI / points)
        val radius = if (i % 2 == 0) outerRadius else innerRadius
        val x = centerX + (radius * cos(angle)).toFloat()
        val y = centerY + (radius * sin(angle)).toFloat()
        if (i == 0) moveTo(x, y) else lineTo(x, y)
    }
    close()
}

private val Android16OrbLarge: Shape = android16OrbShape(points = 18, innerRatio = 0.90f)
private val Android16OrbMedium: Shape = android16OrbShape(points = 20, innerRatio = 0.92f)
private val Android16OrbSmall: Shape = android16OrbShape(points = 16, innerRatio = 0.88f)

@Composable
private fun AppBackdrop(modifier: Modifier = Modifier) {
    val colors = MaterialTheme.colorScheme
    val isDark = colors.background.luminance() < 0.22f
    val baseBrush = remember(colors.background, colors.surface, colors.surfaceVariant) {
        Brush.verticalGradient(
            colors = if (isDark) {
                listOf(
                    lerp(colors.background, colors.surface, 0.18f),
                    colors.background,
                    lerp(colors.surfaceVariant, colors.background, 0.72f)
                )
            } else {
                listOf(
                    lerp(colors.background, colors.surface, 0.78f),
                    colors.background,
                    lerp(colors.surfaceVariant, colors.background, 0.30f)
                )
            }
        )
    }
    val topGlow = colors.primary.copy(alpha = if (isDark) 0.055f else 0.09f)
    val leftGlow = if (isDark) {
        colors.tertiary.copy(alpha = 0.045f)
    } else {
        lerp(colors.tertiary, colors.secondaryContainer, 0.74f).copy(alpha = 0.24f)
    }
    val bottomGlow = if (isDark) {
        colors.primary.copy(alpha = 0.04f)
    } else {
        lerp(colors.secondary, colors.primaryContainer, 0.70f).copy(alpha = 0.22f)
    }
    val lightOrbOutline = colors.outlineVariant.copy(alpha = 0.26f)
    val topOrbGlow = if (isDark) {
        topGlow
    } else {
        lerp(colors.primary, colors.primaryContainer, 0.72f).copy(alpha = 0.32f)
    }

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(baseBrush)
    ) {
        Box(
            modifier = Modifier
                .align(Alignment.TopStart)
                .offset(x = (-86).dp, y = (-126).dp)
                .size(258.dp)
                .clip(Android16OrbLarge)
                .background(topOrbGlow)
                .then(
                    if (isDark) Modifier else Modifier.border(1.dp, lightOrbOutline, Android16OrbLarge)
                )
        )
        Box(
            modifier = Modifier
                .align(Alignment.CenterStart)
                .offset(x = (-44).dp, y = 28.dp)
                .size(146.dp)
                .clip(Android16OrbSmall)
                .background(leftGlow)
                .then(
                    if (isDark) Modifier else Modifier.border(1.dp, lightOrbOutline.copy(alpha = 0.22f), Android16OrbSmall)
                )
        )
        Box(
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .offset(x = 62.dp, y = (-208).dp)
                .size(198.dp)
                .clip(Android16OrbMedium)
                .background(bottomGlow)
                .then(
                    if (isDark) Modifier else Modifier.border(1.dp, lightOrbOutline.copy(alpha = 0.20f), Android16OrbMedium)
                )
        )
    }
}
