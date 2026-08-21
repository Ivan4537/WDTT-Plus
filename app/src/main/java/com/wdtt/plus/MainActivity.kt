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
import android.view.ViewTreeObserver
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.browser.auth.AuthTabIntent
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.SizeTransform
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.tween
import androidx.compose.animation.core.snap
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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.sin

private const val STATE_EXTERNAL_INTENT_CONSUMED = "external_intent_consumed"

internal fun isOneShotIncomingIntentAction(action: String?): Boolean =
    action == Intent.ACTION_VIEW || action == Intent.ACTION_SEND

internal fun shouldHandleIncomingIntent(
    action: String?,
    restoredAsConsumed: Boolean,
): Boolean = !isOneShotIncomingIntentAction(action) || !restoredAsConsumed

private sealed interface WdttConnectFlow {
    data class Progress(val message: String) : WdttConnectFlow
    data class SelectAttachmentProfile(
        val link: RemoteDocumentLink,
        val candidates: List<RemoteAttachmentCandidate>,
        val selectedProfile: Int,
    ) : WdttConnectFlow
    data class SelectProfile(
        val plan: WdttDeepLinkApplyPlan,
        val delivery: RemoteDocumentDelivery
    ) : WdttConnectFlow
    data class ConfirmLimitedSetup(
        val plan: WdttDeepLinkApplyPlan,
        val delivery: RemoteDocumentDelivery
    ) : WdttConnectFlow
    data class SelectHashes(
        val profile: Int,
        val continuation: RemoteContinuation,
        val access: RemoteAccessCapability,
    ) : WdttConnectFlow
    data class ExternalAction(
        val profile: Int,
        val continuation: RemoteContinuation,
        val access: RemoteAccessCapability,
        val message: String
    ) : WdttConnectFlow
    data class Complete(val message: String) : WdttConnectFlow
    data class Failed(
        val message: String,
        val action: RemoteDocumentFailureAction? = null,
    ) : WdttConnectFlow
}

class MainActivity : ComponentActivity() {
    private var sharedVkHashResult by mutableStateOf<VkHashInsertResult?>(null)
    private var sharedVkHashError by mutableStateOf<String?>(null)
    private var wdttDeepLinkMessage by mutableStateOf<String?>(null)
    private var pendingWdttDeepLinkPlan by mutableStateOf<WdttDeepLinkApplyPlan?>(null)
    private var wdttConnectFlow by mutableStateOf<WdttConnectFlow?>(null)
    private var pendingAdminTransfer by mutableStateOf<String?>(null)
    private var connectActionJob: Job? = null
    private lateinit var settingsStore: SettingsStore
    private var externalIntentConsumed = false
    @Volatile
    private var uiReadyForFirstDraw = false
    private val remoteAuthTabLauncher = AuthTabIntent.registerActivityResultLauncher(this) { result ->
        if (result.resultCode != AuthTabIntent.RESULT_OK) return@registerActivityResultLauncher
        if (RemoteContinuationLauncher.isCancellationCallback(result.resultUri)) {
            connectActionJob?.cancel()
            connectActionJob = null
            wdttConnectFlow = null
            return@registerActivityResultLauncher
        }
        val documentUri = RemoteContinuationLauncher.callbackDocumentUri(result.resultUri)
        if (documentUri == null) {
            wdttDeepLinkMessage = "WDTT Plus получил повреждённый результат автоматической настройки."
            return@registerActivityResultLauncher
        }
        handleRemoteDocument(documentUri)
    }

    companion object {
        private val remoteDocumentRequests = ConcurrentHashMap.newKeySet<String>()
        var activeActivities = 0
        var isForeground: Boolean
            get() = activeActivities > 0
            set(value) {}
    }

    override fun onStart() {
        super.onStart()
        activeActivities++
        ManlCaptchaWebViewManager.checkAndShowPendingCaptcha(this)
        lifecycleScope.launch(Dispatchers.IO) {
            val profiles = AccessLifecycleCoordinator.takePendingExternalRefreshProfiles() +
                settingsStore.takeAccessLifecycleActionProfiles()
            profiles.forEach { profile ->
                launch {
                    AccessLifecycleCoordinator.refreshAfterExternalAction(
                        this@MainActivity,
                        profile,
                    )
                }
            }
            AccessLifecycleCoordinator.refreshAllOnForeground(
                context = this@MainActivity,
                alreadyScheduledProfiles = profiles,
            )
        }
    }

    override fun onStop() {
        super.onStop()
        activeActivities--
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        settingsStore = SettingsStore(this)

        val contentView = findViewById<android.view.View>(android.R.id.content)
        contentView.viewTreeObserver.addOnPreDrawListener(
            object : ViewTreeObserver.OnPreDrawListener {
                override fun onPreDraw(): Boolean {
                    if (uiReadyForFirstDraw && contentView.viewTreeObserver.isAlive) {
                        contentView.viewTreeObserver.removeOnPreDrawListener(this)
                    }
                    return uiReadyForFirstDraw
                }
            }
        )

        TunnelManager.initObservers(this)

        enableEdgeToEdge()

        setContent {
            val settingsStore = remember { this@MainActivity.settingsStore }
            val themeMode by settingsStore.themeMode.collectAsStateWithLifecycle(initialValue = "system")
            val isDynamicColor by settingsStore.isDynamicColor.collectAsStateWithLifecycle(initialValue = false)
            val themePalette by settingsStore.themePalette.collectAsStateWithLifecycle(initialValue = "indigo")
            val activeFingerprint by settingsStore.selectedFingerprint.collectAsStateWithLifecycle(initialValue = "firefox")
            val activeClientIds by settingsStore.activeClientIds.collectAsStateWithLifecycle(initialValue = "6287487,8202606")
            val scope = rememberCoroutineScope()

            WDTTTheme(themeMode = themeMode, dynamicColor = isDynamicColor, themePalette = themePalette) {
                MainScreen(
                    settingsStore = settingsStore,
                    onUiReadyForFirstDraw = { uiReadyForFirstDraw = true },
                    sharedVkHashResult = sharedVkHashResult,
                    sharedVkHashError = sharedVkHashError,
                    onSharedVkHashMessageShown = {
                        sharedVkHashResult = null
                        sharedVkHashError = null
                    },
                    wdttDeepLinkMessage = wdttDeepLinkMessage,
                    onWdttDeepLinkMessageShown = { wdttDeepLinkMessage = null },
                    pendingWdttDeepLinkPlan = pendingWdttDeepLinkPlan,
                    wdttConnectFlow = wdttConnectFlow,
                    pendingAdminTransfer = pendingAdminTransfer,
                    onIncomingTransferContent = ::handleIncomingTransferText,
                    onAdminTransferDismissed = { pendingAdminTransfer = null },
                    onAdminTransferFinished = { message ->
                        pendingAdminTransfer = null
                        wdttDeepLinkMessage = message
                    },
                    onSelectWdttDeepLinkOverwriteProfile = { profile ->
                        pendingWdttDeepLinkPlan = pendingWdttDeepLinkPlan?.let { plan ->
                            if (profile in plan.blockedProfiles) plan else plan.copy(targetProfile = profile)
                        }
                    },
                    onConfirmWdttDeepLinkOverwrite = { plan ->
                        pendingWdttDeepLinkPlan = null
                        applyWdttDeepLinkPlan(plan)
                    },
                    onCancelWdttDeepLinkOverwrite = {
                        pendingWdttDeepLinkPlan = null
                        wdttDeepLinkMessage = "Импорт wdtt:// ссылки отменён."
                    },
                    onSelectWdttConnectProfile = { profile ->
                        (wdttConnectFlow as? WdttConnectFlow.SelectProfile)?.let { flow ->
                            if (profile !in flow.plan.blockedProfiles) {
                                wdttConnectFlow = flow.copy(
                                    plan = flow.plan.copy(targetProfile = profile)
                                )
                            }
                        }
                    },
                    onSelectWdttAttachmentProfile = { profile ->
                        (wdttConnectFlow as? WdttConnectFlow.SelectAttachmentProfile)?.let { flow ->
                            if (flow.candidates.any { it.profileIndex == profile }) {
                                wdttConnectFlow = flow.copy(selectedProfile = profile)
                            }
                        }
                    },
                    onConfirmWdttAttachmentProfile = {
                        (wdttConnectFlow as? WdttConnectFlow.SelectAttachmentProfile)?.let { flow ->
                            flow.candidates.firstOrNull {
                                it.profileIndex == flow.selectedProfile
                            }?.let { candidate ->
                                receiveRemoteDocument(
                                    flow.link,
                                    candidate.document,
                                    candidate.profileIndex,
                                )
                            }
                        }
                    },
                    onConfirmWdttConnectProfile = { plan ->
                        (wdttConnectFlow as? WdttConnectFlow.SelectProfile)?.delivery?.let { delivery ->
                            applyWdttDeepLinkPlan(
                                plan,
                                fromRemoteDocument = true,
                                delivery = delivery
                            )
                        }
                    },
                    onContinueLimitedWdttSetup = { plan, delivery ->
                        if (plan.requiresConfirmation) {
                            wdttConnectFlow = WdttConnectFlow.SelectProfile(plan, delivery)
                        } else {
                            applyWdttDeepLinkPlan(
                                plan,
                                fromRemoteDocument = true,
                                delivery = delivery,
                            )
                        }
                    },
                    onStartWdttConnectAction = ::startConnectAction,
                    onCancelWdttConnectAction = ::cancelConnectAction,
                    onSaveWdttConnectManualHashes = ::saveConnectManualHashes,
                    onRestoreWdttConnectHashes = ::restoreConnectHashes,
                    onVkHashesSaved = { profile, hashes ->
                        lifecycleScope.launch {
                            runCatching {
                                AccessLifecycleCoordinator.syncProfileValues(
                                    context = this@MainActivity,
                                    profileIndex = profile,
                                    values = hashes,
                                )
                            }
                        }
                    },
                    onSkipWdttConnectHashes = ::skipConnectHashes,
                    onOpenWdttConnectFailureAction = { target ->
                        dismissWdttConnectFlow()
                        launchRemoteContinuation(target)
                    },
                    onDismissWdttConnectFlow = ::dismissWdttConnectFlow,
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
        val restoredAsConsumed =
            savedInstanceState?.getBoolean(STATE_EXTERNAL_INTENT_CONSUMED) == true
        if (!shouldHandleIncomingIntent(intent?.action, restoredAsConsumed)) {
            externalIntentConsumed = true
            replaceConsumedIncomingIntent()
        } else {
            handleIncomingIntent(intent)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        externalIntentConsumed = false
        handleIncomingIntent(intent)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putBoolean(STATE_EXTERNAL_INTENT_CONSUMED, externalIntentConsumed)
        super.onSaveInstanceState(outState)
    }

    internal fun launchRemoteContinuation(target: RemoteLaunchTarget) {
        RemoteContinuationLauncher.launch(this, target, remoteAuthTabLauncher)
    }

    private fun handleIncomingIntent(intent: Intent?) {
        when (intent?.action) {
            Intent.ACTION_VIEW -> {
                val data = intent.data
                val mimeType = intent.type
                externalIntentConsumed = true
                replaceConsumedIncomingIntent()
                if (data == null) return
                if (RemoteDocumentGateway.extractLink(data) != null) {
                    handleRemoteDocument(data)
                } else if (
                    data.scheme.equals("wdtt", ignoreCase = true) &&
                    data.host.equals("return", ignoreCase = true)
                ) {
                    val documentUri = RemoteContinuationLauncher.callbackDocumentUri(data)
                    if (documentUri != null) {
                        handleRemoteDocument(documentUri)
                    } else {
                        connectActionJob?.cancel()
                        connectActionJob = null
                        wdttConnectFlow = null
                    }
                } else if (data.scheme.equals("wdtt", ignoreCase = true)) {
                    handleIncomingTransferText(data.toString())
                } else {
                    handleIncomingUri(data, mimeType)
                }
            }
            Intent.ACTION_SEND -> {
                val mimeType = intent.type
                val streamUri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(Intent.EXTRA_STREAM) as? Uri
                } ?: intent.clipData?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.uri
                val streamFirst = mimeType?.let { type ->
                    type.startsWith("image/") || WdttDocument.isAcceptedMimeType(type)
                } == true
                val sharedText = intent.getStringExtra(Intent.EXTRA_TEXT)
                    ?: intent.clipData
                        ?.takeIf { it.itemCount > 0 }
                        ?.getItemAt(0)
                        ?.text
                        ?.toString()
                externalIntentConsumed = true
                replaceConsumedIncomingIntent()
                if (streamFirst && streamUri != null) {
                    handleIncomingUri(streamUri, mimeType)
                    return
                }
                if (!sharedText.isNullOrBlank()) {
                    handleIncomingTransferText(sharedText)
                    return
                }
                if (streamUri != null) handleIncomingUri(streamUri, mimeType)
            }
        }
    }

    private fun replaceConsumedIncomingIntent() {
        setIntent(
            Intent(this, MainActivity::class.java).apply {
                action = Intent.ACTION_MAIN
                addCategory(Intent.CATEGORY_LAUNCHER)
            }
        )
    }

    private fun vkHashDeviceName(): String {
        val manufacturer = Build.MANUFACTURER.orEmpty().trim()
        val model = Build.MODEL.orEmpty().trim()
        val name = listOf(manufacturer, model)
            .filter { it.isNotBlank() }
            .distinctBy { it.lowercase() }
            .joinToString(" ")
        return name.ifBlank { "Android-устройство" }
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
        RemoteDocumentGateway.extractLink(value.trim())?.let { link ->
            receiveRemoteDocument(link)
            return
        }
        val link = WdttTransferCodec.extractWdttLink(value)
        when {
            ClientTransferCodec.isClientTransfer(value) -> {
                ClientTransferInbox.offer(value)
                wdttDeepLinkMessage = "Распознан перенос клиента. В режиме «Я — админ» откройте «Деплой» → «Клиенты и сервер»: перед импортом приложение покажет проверку данных и целевого сервера."
            }
            link != null -> handleIncomingWdttLink(link)
            WdttTransferCodec.isAdminTransfer(value) -> pendingAdminTransfer = value.trim()
            WdttTransferCodec.isEncryptedServerBackup(value) ||
                WdttTransferCodec.documentFormat(value) == "wdtt-server-backup" -> {
                wdttDeepLinkMessage = "Распознана резервная копия сервера. Она применяется к выбранному серверу во вкладке «Деплой» → «Перенос сервера» → «Импорт»."
            }
            WdttTransferCodec.documentFormat(value) == "wdtt-plus-admin-settings" -> {
                wdttDeepLinkMessage = "Распознаны незашифрованные настройки администратора. В целях безопасности импортируется только защищённый файл, созданный в разделе «Получение/Передача»."
            }
            else -> handleIncomingVkShare(value)
        }
    }

    private fun handleRemoteDocument(uri: Uri) {
        val link = RemoteDocumentGateway.extractLink(uri)
        if (link == null) {
            wdttDeepLinkMessage = "Ссылка подключения повреждена или устарела."
            return
        }
        receiveRemoteDocument(link)
    }

    private fun receiveRemoteDocument(
        link: RemoteDocumentLink,
        localDocument: String? = null,
        attachmentProfile: Int? = null,
    ) {
        if (!remoteDocumentRequests.add(link.url)) return
        lifecycleScope.launch {
            try {
                var requestedAttachmentProfile = attachmentProfile
                wdttConnectFlow = WdttConnectFlow.Progress("Проверяем ссылку и получаем доступ...")
                suspend fun request(
                    document: String?,
                    profileAttachment: Boolean = false,
                ): RemoteDocumentDelivery =
                    RemoteDocumentGateway.receive(
                        link = link,
                        device = settingsStore.getOrCreateConnectDeviceId(),
                        label = vkHashDeviceName(),
                        client = BuildConfig.VERSION_NAME,
                        system = Build.VERSION.RELEASE.orEmpty(),
                        localBindings = settingsStore.remoteDocumentBindings(),
                        localDocument = document,
                        profileAttachment = profileAttachment,
                    )
                val delivery = try {
                    request(
                        localDocument,
                        profileAttachment = attachmentProfile != null,
                    )
                } catch (error: RemoteDocumentFailure) {
                    if (!error.profileAttachmentRequired || localDocument != null) throw error
                    val candidates = settingsStore.remoteAttachmentCandidates()
                    val selection = resolveRemoteAttachmentCandidates(
                        candidates = candidates,
                    )
                    when {
                        candidates.isEmpty() -> {
                            wdttConnectFlow = WdttConnectFlow.Failed(
                                "Все локальные профили уже заняты действующими удалёнными " +
                                    "разрешениями или готовыми профилями. Освободите обычный " +
                                    "профиль и откройте ссылку снова."
                            )
                            return@launch
                        }
                        else -> {
                            wdttConnectFlow = WdttConnectFlow.SelectAttachmentProfile(
                                link = link,
                                candidates = selection.choices,
                                selectedProfile = selection.choices.first().profileIndex,
                            )
                            return@launch
                        }
                    }
                }
                if (delivery.kind == RemoteDocumentKind.ATTACHMENT) {
                    val profile = requestedAttachmentProfile
                        ?: settingsStore.profileForRemoteBinding(delivery.binding)
                    if (
                        profile == null ||
                        !settingsStore.applyRemoteCapabilityAttachment(profile, delivery)
                    ) {
                        wdttConnectFlow = WdttConnectFlow.Failed(
                            "Не удалось сохранить разрешение в выбранном профиле."
                        )
                        return@launch
                    }
                    val confirmedStatus = when (
                        val confirmation = AccessLifecycleCoordinator.refreshProfile(
                            this@MainActivity,
                            profile,
                            force = true,
                        )
                    ) {
                        is AccessLifecycleRefreshResult.Success -> confirmation.status
                        is AccessLifecycleRefreshResult.Cached -> confirmation.status
                        else -> {
                            wdttConnectFlow = WdttConnectFlow.Failed(
                                "Разрешение сохранено в выбранном профиле, но сервер пока " +
                                    "не подтвердил привязку. Проверьте интернет и обновите " +
                                    "карточку профиля."
                            )
                            return@launch
                        }
                    }
                    val confirmedContinuation =
                        if (confirmedStatus?.continuationAvailable == false) {
                            RemoteContinuation(
                                available = false,
                                message = delivery.continuation.message,
                            )
                        } else {
                            delivery.continuation
                        }
                    wdttConnectFlow = WdttConnectFlow.SelectHashes(
                        profile = profile,
                        continuation = confirmedContinuation,
                        access = delivery.access,
                    )
                    return@launch
                }
                wdttConnectFlow = WdttConnectFlow.Progress("Доступ получен. Подготавливаем VPN-профиль...")
                var boundProfile: Int? = null
                for (binding in listOf(delivery.binding, delivery.access.binding)) {
                    if (binding.isBlank()) continue
                    boundProfile = settingsStore.profileForRemoteBinding(binding)
                    if (boundProfile != null) break
                }
                if (
                    boundProfile == null &&
                    delivery.kind == RemoteDocumentKind.BASE &&
                    requestedAttachmentProfile != null
                ) {
                    boundProfile = requestedAttachmentProfile
                }
                if (boundProfile == null && delivery.kind == RemoteDocumentKind.BASE) {
                    boundProfile = settingsStore.profileForConnectionDocument(delivery.document)
                }
                if (
                    delivery.kind == RemoteDocumentKind.UPDATE &&
                    boundProfile == null &&
                    delivery.binding.isNotBlank()
                ) {
                    wdttConnectFlow = WdttConnectFlow.Failed(
                        "Профиль не найден на этом устройстве. Если он был подключён "
                            + "на другом телефоне, сначала отвяжите прежнее устройство "
                            + "в боте. Затем получите там новую ссылку подключения "
                            + "и откройте её на этом телефоне."
                    )
                    return@launch
                }
                handleIncomingWdttLink(
                    delivery.document,
                    fromRemoteDocument = true,
                    delivery = delivery,
                    preferredProfile = boundProfile,
                    existingRemoteProfile = boundProfile != null,
                )
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: RemoteDocumentFailure) {
                wdttConnectFlow = WdttConnectFlow.Failed(
                    message = error.message
                        ?: "Не удалось активировать доступ. Получите новую ссылку подключения.",
                    action = error.action,
                )
            } catch (error: Exception) {
                wdttConnectFlow = WdttConnectFlow.Failed(
                    error.message ?: "Не удалось активировать доступ. Получите новую ссылку подключения."
                )
            } finally {
                remoteDocumentRequests.remove(link.url)
            }
        }
    }

    private fun handleIncomingWdttLink(
        link: String,
        fromRemoteDocument: Boolean = false,
        delivery: RemoteDocumentDelivery? = null,
        preferredProfile: Int? = null,
        existingRemoteProfile: Boolean = false,
    ) {
        lifecycleScope.launch {
            val store = SettingsStore(this@MainActivity)
            runCatching {
                store.createWdttDeepLinkApplyPlan(
                    link,
                    allowOmittedConnection = delivery?.kind == RemoteDocumentKind.UPDATE,
                )
            }.onSuccess { basePlan ->
                val plan = basePlan?.let {
                    if (preferredProfile == null) it else it.copy(
                        targetProfile = preferredProfile.coerceIn(0, 2),
                        requiresConfirmation = false
                    )
                }
                if (plan == null) {
                    if (fromRemoteDocument) {
                        wdttConnectFlow = WdttConnectFlow.Failed(
                            "Не удалось подготовить профиль из полученных данных. Получите новую ссылку."
                        )
                    } else {
                        wdttDeepLinkMessage = WdttDeepLink.validate(link).userMessage()
                    }
                } else if (delivery?.kind == RemoteDocumentKind.UPDATE) {
                    applyWdttDeepLinkPlan(
                        plan = plan,
                        fromRemoteDocument = true,
                        delivery = delivery,
                        isBoundUpdate = true,
                        existingRemoteProfile = true,
                    )
                } else if (
                    fromRemoteDocument &&
                    delivery != null &&
                    delivery.requiresInitialContinuationWarning(
                        existingProfileHasVkHashes = existingRemoteProfile &&
                            preferredProfile?.let { profile ->
                                store.tunnelProfileSnapshot(profile).vkHashes.isNotBlank()
                            } == true,
                    )
                ) {
                    wdttConnectFlow = WdttConnectFlow.ConfirmLimitedSetup(plan, delivery)
                } else if (plan.requiresConfirmation) {
                    if (fromRemoteDocument && delivery != null) {
                        wdttConnectFlow = WdttConnectFlow.SelectProfile(plan, delivery)
                    } else {
                        pendingWdttDeepLinkPlan = plan
                    }
                } else {
                    applyWdttDeepLinkPlan(
                        plan,
                        fromRemoteDocument,
                        delivery,
                        isBoundUpdate = false,
                        existingRemoteProfile = existingRemoteProfile,
                    )
                }
            }.onFailure { error ->
                if (fromRemoteDocument) {
                    wdttConnectFlow = WdttConnectFlow.Failed(
                        error.message ?: "Не удалось применить доступ."
                    )
                } else {
                    wdttDeepLinkMessage = error.message ?: "Не удалось применить wdtt:// ссылку."
                }
            }
        }
    }

    private fun applyWdttDeepLinkPlan(
        plan: WdttDeepLinkApplyPlan,
        fromRemoteDocument: Boolean = false,
        delivery: RemoteDocumentDelivery? = null,
        isBoundUpdate: Boolean = false,
        existingRemoteProfile: Boolean = false,
    ) {
        lifecycleScope.launch {
            if (fromRemoteDocument) {
                wdttConnectFlow = WdttConnectFlow.Progress("Сохраняем настройки в выбранный VPN-профиль...")
            }
            val store = SettingsStore(this@MainActivity)
            runCatching {
                if (fromRemoteDocument && delivery != null) {
                    store.applyRemoteDocumentDelivery(
                        plan = plan,
                        delivery = delivery,
                        isBoundUpdate = isBoundUpdate,
                        existingProfileRedelivery = existingRemoteProfile,
                    )
                } else {
                    store.applyWdttDeepLink(
                        plan,
                        resetRemoteContinuation = !isBoundUpdate,
                        profileMaxWorkers = delivery?.profileMaxWorkers,
                        remoteManaged = if (isBoundUpdate) null else fromRemoteDocument,
                        preserveVkHashes =
                            isBoundUpdate &&
                                delivery?.shouldPreserveLocalVkHashes() == true,
                    )
                }
            }.onSuccess { result ->
                val savedProfile = result?.targetProfile ?: plan.targetProfile
                if (fromRemoteDocument && result != null) {
                    requestTunnelProfileRuntimeUpdate(savedProfile)
                }
                val message = if (result == null) {
                    WdttDeepLink.validate(plan.link, allowMissingHashes = true).userMessage()
                } else {
                    val profileLabel = vpnProfileDisplayName(result.targetProfile, store.profileNames.first())
                    val action = if (result.overwritten) "перезаписана" else "добавлена"
                    val mode = if (result.storedAsLink) "сохранена в режиме ссылки" else "разобрана, поля подключения заполнены"
                    buildString {
                        append("Ссылка wdtt:// $action в профиль $profileLabel: $mode.")
                        if (
                            WdttDeepLink.parse(plan.link, allowMissingHashes = true)
                                ?.hashes
                                .isNullOrBlank()
                        ) {
                            append(" Добавьте свой VK-хеш перед запуском VPN.")
                        }
                    }
                }
                if (fromRemoteDocument) {
                    val profile = result?.targetProfile ?: plan.targetProfile
                    if (delivery?.access?.available == true || isBoundUpdate) {
                        lifecycleScope.launch {
                            AccessLifecycleCoordinator.refreshProfile(
                                this@MainActivity,
                                profile,
                                force = isBoundUpdate || delivery?.access?.initialStatus == null,
                            )
                        }
                    }
                    if (shouldRestoreUiAfterBoundUpdate(isBoundUpdate)) {
                        wdttConnectFlow = null
                    } else if (
                        existingRemoteProfile &&
                        store.tunnelProfileSnapshot(profile).vkHashes.isNotBlank()
                    ) {
                        val profileLabel = vpnProfileDisplayName(profile, store.profileNames.first())
                        wdttConnectFlow = WdttConnectFlow.Complete(
                            "Удалённый профиль $profileLabel уже подключён и обновлён."
                        )
                    } else {
                        val continuation = delivery?.continuation ?: RemoteContinuation(
                            available = false,
                            message = "Автоматическое заполнение для этого доступа сейчас недоступно."
                        )
                        wdttConnectFlow = WdttConnectFlow.SelectHashes(
                            profile = profile,
                            continuation = continuation,
                            access = delivery?.access ?: RemoteAccessCapability.Unavailable,
                        )
                    }
                } else {
                    wdttDeepLinkMessage = message
                }
            }.onFailure { error ->
                if (fromRemoteDocument) {
                    wdttConnectFlow = WdttConnectFlow.Failed(
                        error.message ?: "Не удалось сохранить профиль."
                    )
                } else {
                    wdttDeepLinkMessage = error.message ?: "Не удалось применить wdtt:// ссылку."
                }
            }
        }
    }

    private fun startConnectAction(profile: Int, continuation: RemoteContinuation) {
        // The dialog can deliver two taps before Compose has rendered the
        // ExternalAction state.  Do not cancel an already running preparation
        // and start a second browser/login flow: VK treats those parallel
        // attempts as repeated authentication requests and may answer with
        // its flood-control error [9].  A fresh attempt is available through
        // the explicit Back/Retry path after the current job finishes.
        if (connectActionJob?.isActive == true) return
        val access = (wdttConnectFlow as? WdttConnectFlow.SelectHashes)
            ?.access
            ?: RemoteAccessCapability.Unavailable
        wdttConnectFlow = WdttConnectFlow.ExternalAction(
            profile = profile,
            continuation = continuation,
            access = access,
            message = "Подготавливаем безопасный переход в VK..."
        )
        connectActionJob = lifecycleScope.launch {
            val runningJob = coroutineContext[Job]
            if (!continuation.available) {
                wdttConnectFlow = WdttConnectFlow.Failed(
                    continuation.message.ifBlank {
                        "Автоматическое получение сейчас недоступно. Заполните VK-хеши вручную."
                    }
                )
                return@launch
            }
            var tunnelStoppedForVk = false
            try {
                if (
                    TunnelManager.running.value ||
                    TunnelManager.transition.value != TunnelTransition.IDLE
                ) {
                    wdttConnectFlow = WdttConnectFlow.ExternalAction(
                        profile = profile,
                        continuation = continuation,
                        access = access,
                        message = "Останавливаем VPN и ждём стабильного подключения перед входом в VK..."
                    )
                }
                val stopResult = TunnelStopCoordinator.stopAndAwait(this@MainActivity)
                if (!stopResult.succeeded) {
                    throw IllegalStateException(
                        if (stopResult == TunnelStopResult.TIMED_OUT) {
                            "VPN не остановился за 20 секунд. Вернитесь в приложение и повторите попытку."
                        } else {
                            "Не удалось запросить остановку VPN. Остановите туннель и повторите попытку."
                        }
                    )
                }
                if (stopResult == TunnelStopResult.STOPPED) {
                    tunnelStoppedForVk = true
                    delay(TunnelStopCoordinator.DIRECT_NETWORK_SETTLE_MS)
                }
                wdttConnectFlow = WdttConnectFlow.ExternalAction(
                    profile = profile,
                    continuation = continuation,
                    access = access,
                    message = "Открываем защищённое продолжение..."
                )
                val target = RemoteContinuationLauncher.begin(
                    capability = continuation,
                    device = settingsStore.getOrCreateConnectDeviceId(),
                    localDocument = settingsStore.remoteActionProfileDocument(profile),
                )
                launchRemoteContinuation(target)
                wdttConnectFlow = WdttConnectFlow.Complete(
                    if (tunnelStoppedForVk) {
                        "Страница открыта. Завершите действие там; результат вернётся в нужный профиль автоматически. VPN оставлен выключенным."
                    } else {
                        "Страница открыта. Завершите действие там; результат вернётся в нужный профиль автоматически."
                    }
                )
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                wdttConnectFlow = WdttConnectFlow.Failed(
                    error.message ?: "Не удалось автоматически получить VK-хеши."
                )
            } finally {
                if (connectActionJob === runningJob) {
                    connectActionJob = null
                }
            }
        }
    }

    private fun cancelConnectAction() {
        val flow = wdttConnectFlow as? WdttConnectFlow.ExternalAction ?: return
        connectActionJob?.cancel()
        connectActionJob = null
        wdttConnectFlow = WdttConnectFlow.SelectHashes(
            profile = flow.profile,
            continuation = flow.continuation,
            access = flow.access,
        )
    }

    private fun skipConnectHashes() {
        if (wdttConnectFlow !is WdttConnectFlow.SelectHashes) return
        wdttConnectFlow = WdttConnectFlow.Complete(
            "Доступ добавлен. VK-хеши можно заполнить позже в настройках профиля."
        )
    }

    private fun dismissWdttConnectFlow() {
        connectActionJob?.cancel()
        connectActionJob = null
        wdttConnectFlow = null
    }

    private fun saveConnectManualHashes(profile: Int, rawHashes: String) {
        lifecycleScope.launch {
            val hashes = rawHashes
                .split(Regex("[\\s,]+"))
                .map(VkJoinLink::extractHash)
                .filter(VkJoinLink::isValidHash)
                .distinct()
            if (hashes.isEmpty()) {
                wdttConnectFlow = WdttConnectFlow.Failed(
                    "Вставьте от 1 до 4 VK-хешей или ссылок VK Звонков."
                )
                return@launch
            }
            runCatching {
                settingsStore.saveVkHashesForProfile(profile, hashes)
            }.onSuccess {
                runCatching {
                    AccessLifecycleCoordinator.syncProfileValues(
                        context = this@MainActivity,
                        profileIndex = profile,
                        values = hashes,
                    )
                }
                wdttConnectFlow = WdttConnectFlow.Complete(
                    "VK-хеши сохранены в новом VPN-профиле."
                )
            }.onFailure { error ->
                wdttConnectFlow = WdttConnectFlow.Failed(
                    error.message ?: "Не удалось сохранить VK-хеши."
                )
            }
        }
    }

    private fun restoreConnectHashes(profile: Int, capability: RemoteAccessCapability) {
        connectActionJob?.cancel()
        wdttConnectFlow = WdttConnectFlow.Progress(
            capability.exchange.message.ifBlank {
                "Возвращаем сохранённые VK-хеши в этот профиль..."
            }
        )
        connectActionJob = lifecycleScope.launch {
            val runningJob = coroutineContext[Job]
            try {
                AccessLifecycleCoordinator.restoreProfileValues(
                    context = this@MainActivity,
                    profileIndex = profile,
                    expectedCapability = capability,
                )
                wdttConnectFlow = WdttConnectFlow.Complete(
                    "Сохранённые VK-хеши возвращены в профиль."
                )
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                wdttConnectFlow = WdttConnectFlow.Failed(
                    error.message ?: "Не удалось вернуть сохранённые VK-хеши."
                )
            } finally {
                if (connectActionJob === runningJob) {
                    connectActionJob = null
                }
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
        if (!VkJoinLink.isValidHash(hash)) {
            sharedVkHashError = "В переданной ссылке не найден VK-хеш звонка."
            return
        }
        lifecycleScope.launch {
            runCatching {
                SettingsStore(this@MainActivity).insertVkHashFromShare(hash)
            }.onSuccess { result ->
                sharedVkHashResult = result
                sharedVkHashError = null
                lifecycleScope.launch {
                    runCatching {
                        AccessLifecycleCoordinator.syncProfileValues(
                            context = this@MainActivity,
                            profileIndex = result.profile,
                            values = result.hashes,
                        )
                    }
                }
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
                        body = "Хочу подключаться бесплатно по ссылке WDTT или вручную, управлять VPN, исключениями и смотреть логи.",
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

internal fun isMainTabVisible(
    tabId: Int,
    isAdminInterface: Boolean,
    linkMode: Boolean,
    remoteManagedProfile: Boolean,
): Boolean {
    if (tabId != 1) return true
    return isAdminInterface && !linkMode && !remoteManagedProfile
}

internal fun effectiveInterfaceRole(
    storedRole: String,
    remoteManagedProfile: Boolean,
): String = if (remoteManagedProfile) "user" else storedRole

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MainScreen(
    settingsStore: SettingsStore,
    onUiReadyForFirstDraw: () -> Unit = {},
    sharedVkHashResult: VkHashInsertResult? = null,
    sharedVkHashError: String? = null,
    onSharedVkHashMessageShown: () -> Unit = {},
    wdttDeepLinkMessage: String? = null,
    onWdttDeepLinkMessageShown: () -> Unit = {},
    pendingWdttDeepLinkPlan: WdttDeepLinkApplyPlan? = null,
    wdttConnectFlow: WdttConnectFlow? = null,
    pendingAdminTransfer: String? = null,
    onIncomingTransferContent: (String) -> Unit = {},
    onAdminTransferDismissed: () -> Unit = {},
    onAdminTransferFinished: (String) -> Unit = {},
    onSelectWdttDeepLinkOverwriteProfile: (Int) -> Unit = {},
    onConfirmWdttDeepLinkOverwrite: (WdttDeepLinkApplyPlan) -> Unit = {},
    onCancelWdttDeepLinkOverwrite: () -> Unit = {},
    onSelectWdttAttachmentProfile: (Int) -> Unit = {},
    onConfirmWdttAttachmentProfile: () -> Unit = {},
    onSelectWdttConnectProfile: (Int) -> Unit = {},
    onConfirmWdttConnectProfile: (WdttDeepLinkApplyPlan) -> Unit = {},
    onContinueLimitedWdttSetup: (WdttDeepLinkApplyPlan, RemoteDocumentDelivery) -> Unit = { _, _ -> },
    onStartWdttConnectAction: (Int, RemoteContinuation) -> Unit = { _, _ -> },
    onCancelWdttConnectAction: () -> Unit = {},
    onSaveWdttConnectManualHashes: (Int, String) -> Unit = { _, _ -> },
    onRestoreWdttConnectHashes: (Int, RemoteAccessCapability) -> Unit = { _, _ -> },
    onVkHashesSaved: (Int, List<String>) -> Unit = { _, _ -> },
    onSkipWdttConnectHashes: () -> Unit = {},
    onOpenWdttConnectFailureAction: (RemoteLaunchTarget) -> Unit = {},
    onDismissWdttConnectFlow: () -> Unit = {},
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
    val startupSettings by
        settingsStore.activeTunnelProfileContentUiSnapshot.collectAsStateWithLifecycle()
    if (!settingsReady || startupSettings == null) {
        Box(modifier = Modifier.fillMaxSize()) {
            AppBackdrop(modifier = Modifier.matchParentSize())
        }
        return
    }
    val storedInterfaceRole = startupSettings!!.interfaceRole
    val permissionOnboardingComplete = startupSettings!!.permissionOnboardingComplete
    val activeProfile = startupSettings!!.profileIndex
    val profileNames = startupSettings!!.profileNames
    val wdttLinkMode = startupSettings!!.linkMode
    val remoteManagedProfile = startupSettings!!.remoteManaged
    val interfaceRole = effectiveInterfaceRole(
        storedRole = storedInterfaceRole,
        remoteManagedProfile = remoteManagedProfile,
    )
    SideEffect(onUiReadyForFirstDraw)
    val migrationDeployHost by settingsStore.deployIp.collectAsStateWithLifecycle(initialValue = "")
    val migrationSshPassword by settingsStore.deployPassword.collectAsStateWithLifecycle(initialValue = "")
    val migrationSshPrivateKey by settingsStore.deploySshPrivateKey.collectAsStateWithLifecycle(initialValue = "")
    val migrationSshAuthMode by settingsStore.deploySshAuthMode.collectAsStateWithLifecycle(initialValue = "password")
    val migrationMainPassword by settingsStore.deployMainPassword.collectAsStateWithLifecycle(initialValue = "")
    val serverMigrationState by settingsStore.serverMigrationState.collectAsStateWithLifecycle(initialValue = null)
    val deviceCompatibilityCheckComplete by settingsStore.deviceCompatibilityCheckComplete.collectAsStateWithLifecycle(
        initialValue = true
    )
    val isAdminInterface = interfaceRole == "admin"
    LaunchedEffect(remoteManagedProfile) {
        settingsStore.synchronizeInterfaceRoleForProfile(remoteManagedProfile)
    }
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
    var projectSupportDialogRequest by remember { mutableIntStateOf(0) }
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

    val activeNavItems = remember(
        wdttLinkMode,
        isAdminInterface,
        remoteManagedProfile,
    ) {
        navItems.filter { item ->
            isMainTabVisible(
                tabId = item.id,
                isAdminInterface = isAdminInterface,
                linkMode = wdttLinkMode,
                remoteManagedProfile = remoteManagedProfile,
            )
        }
    }
    val actionsExpanded = rememberSaveable { mutableStateOf(false) }
    val projectExpanded = rememberSaveable { mutableStateOf(false) }
    val tabStateHolder = rememberSaveableStateHolder()
    var deployTabInitialized by rememberSaveable { mutableStateOf(false) }



    LaunchedEffect(wdttLinkMode, interfaceRole, remoteManagedProfile) {
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
        if (selectedTab != 4) projectSupportDialogRequest = 0
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
                val deployAvailable =
                    activeNavItems.any { it.id == 1 } &&
                        !wdttLinkMode &&
                        !remoteManagedProfile
                val deployVisible = selectedTab == 1 && deployAvailable
                val keepDeployTab = deployVisible || deployTabInitialized
                LaunchedEffect(deployVisible) {
                    if (deployVisible) deployTabInitialized = true
                }
                val deployAlpha by animateFloatAsState(
                    targetValue = if (deployVisible) 1f else 0f,
                    animationSpec = tween(durationMillis = if (deployVisible) 300 else 225),
                    label = "deploy_tab_fade"
                )
                if (keepDeployTab) {
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
                            0 -> SettingsTab(
                                settingsStore = settingsStore,
                                scrollPosition = tunnelScrollPosition,
                                onVkHashesSaved = onVkHashesSaved,
                                onOpenProjectSupport = {
                                    selectedTab = 4
                                    projectSupportDialogRequest += 1
                                },
                            )
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
                                scrollPosition = infoScrollPosition,
                                projectSupportDialogRequest = projectSupportDialogRequest,
                                onProjectSupportDialogRequestConsumed = {
                                    projectSupportDialogRequest = 0
                                },
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
            settingsStore = settingsStore,
            activeProfile = activeProfile,
            profileNames = profileNames,
            onActiveProfileChange = { profile ->
                scope.launch { settingsStore.saveActiveProfile(profile) }
            },
            onProfileNameChange = { profile, name ->
                scope.launch { settingsStore.saveProfileName(profile, name) }
            },
            interfaceRole = interfaceRole,
            adminModeAllowed = !remoteManagedProfile,
            onInterfaceRoleChange = { role ->
                if (!remoteManagedProfile || role == "user") {
                    scope.launch { settingsStore.saveInterfaceRole(role) }
                }
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
    val serverMigrationPromptVisible =
        isAdminInterface &&
        !remoteManagedProfile &&
        activeProfileManagesServer &&
        migrationNotice?.noticeRequired == true &&
        pendingUpdateCandidate == null &&
        startupDeviceReport == null
    if (serverMigrationPromptVisible) {
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

    wdttConnectFlow?.let { flow ->
        WdttConnectActivationDialog(
            flow = flow,
            profileNames = profileNames,
            onSelectAttachmentProfile = onSelectWdttAttachmentProfile,
            onConfirmAttachmentProfile = onConfirmWdttAttachmentProfile,
            onSelectProfile = onSelectWdttConnectProfile,
            onConfirmProfile = onConfirmWdttConnectProfile,
            onContinueLimitedSetup = onContinueLimitedWdttSetup,
            onStartExternalAction = onStartWdttConnectAction,
            onCancelExternalAction = onCancelWdttConnectAction,
            onSaveManualHashes = onSaveWdttConnectManualHashes,
            onRestoreSavedHashes = onRestoreWdttConnectHashes,
            onSkipHashes = onSkipWdttConnectHashes,
            onOpenFailureAction = onOpenWdttConnectFailureAction,
            onDismiss = onDismissWdttConnectFlow,
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
                                enabled = profile !in plan.blockedProfiles,
                                onClick = { onSelectWdttDeepLinkOverwriteProfile(profile) },
                                label = { Text(vpnProfileDisplayName(profile, profileNames)) }
                            )
                        }
                    }
                    if (plan.blockedProfiles.size == 3) {
                        Text("Все профили защищены действующим удалённым доступом. Сначала освободите один из них.")
                    } else {
                        Text("Будет полностью заменено подключение в профиле $profileLabel.")
                    }
                }
            },
            confirmButton = {
                TextButton(
                    enabled = plan.targetProfile !in plan.blockedProfiles,
                    onClick = { onConfirmWdttDeepLinkOverwrite(plan) },
                ) {
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
private fun WdttConnectActivationDialog(
    flow: WdttConnectFlow,
    profileNames: List<String>,
    onSelectAttachmentProfile: (Int) -> Unit,
    onConfirmAttachmentProfile: () -> Unit,
    onSelectProfile: (Int) -> Unit,
    onConfirmProfile: (WdttDeepLinkApplyPlan) -> Unit,
    onContinueLimitedSetup: (WdttDeepLinkApplyPlan, RemoteDocumentDelivery) -> Unit,
    onStartExternalAction: (Int, RemoteContinuation) -> Unit,
    onCancelExternalAction: () -> Unit,
    onSaveManualHashes: (Int, String) -> Unit,
    onRestoreSavedHashes: (Int, RemoteAccessCapability) -> Unit,
    onSkipHashes: () -> Unit,
    onOpenFailureAction: (RemoteLaunchTarget) -> Unit,
    onDismiss: () -> Unit,
) {
    var manualHashes by rememberSaveable { mutableStateOf("") }
    var selectedHashMethod by rememberSaveable { mutableStateOf<String?>(null) }
    var helpMethod by rememberSaveable { mutableStateOf<String?>(null) }
    var unavailableAutoMessage by rememberSaveable { mutableStateOf<String?>(null) }
    val canDismiss = flow is WdttConnectFlow.SelectAttachmentProfile ||
        flow is WdttConnectFlow.Complete ||
        flow is WdttConnectFlow.Failed
    AlertDialog(
        onDismissRequest = {
            when {
                flow is WdttConnectFlow.ExternalAction -> onCancelExternalAction()
                canDismiss -> onDismiss()
            }
        },
        title = { Text("Подключение WDTT Plus") },
        text = {
            AnimatedContent(
                targetState = flow,
                transitionSpec = {
                    (fadeIn(tween(120)) togetherWith fadeOut(tween(80))).using(
                        SizeTransform(
                            clip = false,
                            sizeAnimationSpec = { _, _ -> snap() },
                        )
                    )
                },
                contentKey = { it::class },
                label = "wdtt_connect_activation"
            ) { state ->
                when (state) {
                    is WdttConnectFlow.Progress -> {
                        Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                            CircularProgressIndicator()
                            Text(state.message)
                        }
                    }
                    is WdttConnectFlow.ExternalAction -> {
                        Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                            CircularProgressIndicator()
                            Text(state.message)
                        }
                    }
                    is WdttConnectFlow.SelectAttachmentProfile -> {
                        val selectedCandidate = state.candidates.first {
                            it.profileIndex == state.selectedProfile
                        }
                        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            Text(
                                "Найдено несколько изменённых обычных профилей. " +
                                    "Выберите, к какому из них привязать разрешение. " +
                                    "Готовые профили здесь недоступны."
                            )
                            state.candidates.forEach { candidate ->
                                FilterChip(
                                    selected = state.selectedProfile == candidate.profileIndex,
                                    onClick = {
                                        onSelectAttachmentProfile(candidate.profileIndex)
                                    },
                                    label = {
                                        Text("${candidate.displayName} · ${candidate.sourceLabel}")
                                    },
                                )
                            }
                            Text(
                                if (selectedCandidate.sourceLabel.contains("Деплой")) {
                                    "Если подключение в «Деплое» заполнено полностью, при запуске " +
                                        "будут использованы только адрес, порты и главный пароль. " +
                                        "SSH-логин, SSH-пароль и ключи не передаются."
                                } else {
                                    "Можно выбрать даже частично заполненный профиль и закончить " +
                                        "его настройку позже. Подключение не заменяется."
                                },
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    }
                    is WdttConnectFlow.SelectProfile -> {
                        val incomingName = WdttDeepLink.parse(
                            state.plan.link,
                            allowMissingHashes = true
                        )?.profileName.orEmpty()
                        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            Text("Свободных профилей нет. Выберите профиль для замены.")
                            if (incomingName.isNotBlank()) {
                                Text("Новый доступ: «$incomingName».")
                            }
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                repeat(3) { profile ->
                                    FilterChip(
                                        selected = state.plan.targetProfile == profile,
                                        enabled = profile !in state.plan.blockedProfiles,
                                        onClick = { onSelectProfile(profile) },
                                        label = { Text(vpnProfileDisplayName(profile, profileNames)) }
                                    )
                                }
                            }
                            Text(
                                if (state.plan.blockedProfiles.size == 3) {
                                    "Все профили защищены действующим готовым доступом. " +
                                        "Ни один из них нельзя перезаписать."
                                } else {
                                    "Подключение в выбранном профиле будет полностью заменено. " +
                                        "Действующие готовые профили недоступны для выбора."
                                },
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    }
                    is WdttConnectFlow.ConfirmLimitedSetup -> {
                        val reason = state.delivery.continuation.message.ifBlank {
                            "Автоматическое получение VK-хешей сейчас недоступно."
                        }
                        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            Text("Перед продолжением обратите внимание:")
                            Text(reason)
                            Text(
                                "Это ограничение относится только к автоматическому получению " +
                                    "VK-хешей. Сам профиль можно добавить и заполнить вручную.",
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    }
                    is WdttConnectFlow.SelectHashes -> {
                        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            Text("Выберите способ заполнения VK-хешей для профиля.")
                            HashMethodRow(
                                title = "Получить автоматически",
                                body = if (state.continuation.available) {
                                    state.continuation.message.ifBlank {
                                        "Войти в VK при необходимости и создать ссылки"
                                    }
                                } else {
                                    "Недоступно — нажмите, чтобы узнать, что делать"
                                },
                                onHelp = { helpMethod = "auto" },
                                onClick = {
                                    if (state.continuation.available) {
                                        onStartExternalAction(state.profile, state.continuation)
                                    } else {
                                        unavailableAutoMessage = state.continuation.message.ifBlank {
                                            "Автоматическое получение сейчас недоступно."
                                        }
                                    }
                                }
                            )
                            HashMethodRow(
                                title = "Заполнить вручную",
                                body = "Вставить 1-4 хеша или ссылки VK Звонков",
                                onHelp = { helpMethod = "manual" },
                                onClick = { selectedHashMethod = "manual" }
                            )
                            if (state.access.exchange.actionAvailable) {
                                HashMethodRow(
                                    title = state.access.exchange.label.ifBlank {
                                        "Вернуть хеши"
                                    },
                                    body = state.access.exchange.message.ifBlank {
                                        "Восстановить сохранённые хеши этого профиля"
                                    },
                                    onHelp = { helpMethod = "restore" },
                                    onClick = {
                                        onRestoreSavedHashes(state.profile, state.access)
                                    }
                                )
                            }
                            if (selectedHashMethod == "manual") {
                                OutlinedTextField(
                                    value = manualHashes,
                                    onValueChange = { manualHashes = it },
                                    modifier = Modifier.fillMaxWidth(),
                                    label = { Text("VK-хеши или ссылки") },
                                    minLines = 2,
                                    maxLines = 4
                                )
                            }
                        }
                    }
                    is WdttConnectFlow.Complete -> Text(state.message)
                    is WdttConnectFlow.Failed -> Text(state.message)
                }
            }
        },
        confirmButton = {
            when (flow) {
                is WdttConnectFlow.SelectAttachmentProfile -> {
                    TextButton(onClick = onConfirmAttachmentProfile) {
                        Text("Продолжить")
                    }
                }
                is WdttConnectFlow.SelectProfile -> {
                    TextButton(
                        enabled = flow.plan.targetProfile !in flow.plan.blockedProfiles,
                        onClick = { onConfirmProfile(flow.plan) },
                    ) {
                        Text("Сохранить")
                    }
                }
                is WdttConnectFlow.ConfirmLimitedSetup -> {
                    TextButton(
                        onClick = {
                            onContinueLimitedSetup(flow.plan, flow.delivery)
                        }
                    ) {
                        Text("Продолжить")
                    }
                }
                is WdttConnectFlow.SelectHashes -> {
                    if (selectedHashMethod == "manual") {
                        TextButton(
                            enabled = manualHashes.isNotBlank(),
                            onClick = { onSaveManualHashes(flow.profile, manualHashes) }
                        ) {
                            Text("Сохранить вручную")
                        }
                    }
                }
                is WdttConnectFlow.Complete -> {
                    TextButton(onClick = onDismiss) {
                        Text("Готово")
                    }
                }
                is WdttConnectFlow.Failed -> {
                    val action = flow.action
                    TextButton(
                        onClick = {
                            if (action == null) onDismiss() else onOpenFailureAction(action.target)
                        }
                    ) {
                        Text(action?.label ?: "Готово")
                    }
                }
                is WdttConnectFlow.ExternalAction -> Unit
                is WdttConnectFlow.Progress -> Unit
            }
        },
        dismissButton = {
            when (flow) {
                is WdttConnectFlow.SelectAttachmentProfile -> {
                    TextButton(onClick = onDismiss) {
                        Text("Отмена")
                    }
                }
                is WdttConnectFlow.SelectProfile -> {
                    TextButton(onClick = onDismiss) {
                        Text("Позже")
                    }
                }
                is WdttConnectFlow.ConfirmLimitedSetup -> {
                    TextButton(onClick = onDismiss) {
                        Text("Отмена")
                    }
                }
                is WdttConnectFlow.ExternalAction -> {
                    TextButton(onClick = onCancelExternalAction) {
                        Text("Назад")
                    }
                }
                is WdttConnectFlow.SelectHashes -> {
                    TextButton(onClick = onSkipHashes) {
                        Text("Пропустить")
                    }
                }
                is WdttConnectFlow.Failed -> {
                    if (flow.action != null) {
                        TextButton(onClick = onDismiss) {
                            Text("Закрыть")
                        }
                    }
                }
                else -> Unit
            }
        }
    )

    helpMethod?.let { method ->
        AlertDialog(
            onDismissRequest = { helpMethod = null },
            title = {
                Text(
                    when (method) {
                        "auto" -> "Автоматически"
                        "restore" -> "Вернуть хеши"
                        else -> "Вручную"
                    }
                )
            },
            text = {
                Text(
                    when (method) {
                        "auto" -> {
                            "WDTT Plus откроет официальное мини-приложение VK. Если вы ещё не " +
                                "вошли, VK сначала покажет свою форму входа, а затем вернёт вас к " +
                                "созданию ссылок. Пароль VK не передаётся WDTT Plus."
                        }
                        "restore" -> {
                            "WDTT Plus безопасно вернёт хеши, ранее сохранённые именно для " +
                                "этого профиля. Значения других профилей не используются."
                        }
                        else -> {
                            "Создайте или скопируйте до четырёх ссылок-приглашений VK Звонков, " +
                                "либо вставьте готовые хеши. Разделяйте значения пробелом, запятой " +
                                "или новой строкой."
                        }
                    }
                )
            },
            confirmButton = {
                TextButton(onClick = { helpMethod = null }) { Text("Понятно") }
            }
        )
    }

    unavailableAutoMessage?.let { message ->
        AlertDialog(
            onDismissRequest = { unavailableAutoMessage = null },
            title = { Text("Автоматическое получение недоступно") },
            text = {
                Text(
                    "$message\n\nСейчас можно заполнить VK-хеши вручную или пропустить этот шаг."
                )
            },
            confirmButton = {
                TextButton(onClick = { unavailableAutoMessage = null }) {
                    Text("Понятно")
                }
            }
        )
    }
}

@Composable
private fun HashMethodRow(
    title: String,
    body: String,
    onHelp: () -> Unit,
    onClick: () -> Unit,
) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(10.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(title, fontWeight = FontWeight.SemiBold)
                Text(body, style = MaterialTheme.typography.bodySmall)
            }
            IconButton(onClick = onHelp) {
                Icon(Icons.Filled.Info, contentDescription = "Как это работает")
            }
        }
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
