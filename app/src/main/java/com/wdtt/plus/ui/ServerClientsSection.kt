package com.wdtt.plus.ui

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.net.Uri
import android.os.Build
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.foundation.Image
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.requiredHeight
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.InsertDriveFile
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.CameraAlt
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ChevronLeft
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.PauseCircle
import androidx.compose.material.icons.filled.QrCode2
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.SaveAlt
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Smartphone
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.wdtt.plus.ClientPasswordRules
import com.wdtt.plus.ClientTransferCodec
import com.wdtt.plus.ClientTransferInbox
import com.wdtt.plus.ClientTransferPayload
import com.wdtt.plus.QrCaptureActivity
import com.wdtt.plus.ServerAdminActionResult
import com.wdtt.plus.ServerAdminClient
import com.wdtt.plus.ServerAdminProfileInfo
import com.wdtt.plus.ServerAdminState
import com.wdtt.plus.ServerAdminTarget
import com.wdtt.plus.SshCredentials
import com.wdtt.plus.ServerClientCreateRequest
import com.wdtt.plus.ServerClientInfo
import com.wdtt.plus.ServerTrafficPeriod
import com.wdtt.plus.TransferFiles
import com.wdtt.plus.WDTTColors
import com.wdtt.plus.connectionLink
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private enum class ClientWizardStep {
    Days,
    Label,
    Hash,
    Ports,
    Password,
    Confirm
}

private enum class ClientDetailsStep { Overview, Device, History, Edit }

private enum class ServerToolsStep { Overview, Owner, Network, Maintenance }

private enum class ClientActionCategory { Connection, Client, Access }

private enum class ClientStatusFilter { All, Active, Disabled }

private enum class ClientBindingFilter { All, Bound, Unbound }

private enum class ClientExpiryFilter { All, Valid, Expired, Unlimited }

private enum class ClientVkHashFilter { All, Present, Missing }

private enum class ClientsServerRefreshState { Unknown, Ready, Error }

internal fun serverClientsAccessIssue(
    host: String,
    hostValid: Boolean,
    sshPassword: String,
    sshPort: Int,
    mainPassword: String,
    sshPrivateKey: String = "",
    allowPasswordAuthentication: Boolean = true
): String? {
    if (host.isBlank()) return "Укажите IP-адрес или домен сервера в верхнем блоке «Деплой»."
    if (!hostValid) return "Проверьте IP-адрес или домен сервера в верхнем блоке «Деплой»."
    val credentials = SshCredentials(
        password = sshPassword,
        privateKey = sshPrivateKey,
        allowPasswordAuthentication = allowPasswordAuthentication
    )
    if (!credentials.hasAuthentication) {
        return sshAuthenticationIssueForMode(
            mode = if (allowPasswordAuthentication) "password" else "key",
            password = sshPassword,
            privateKey = sshPrivateKey,
            passwordLabel = "SSH-пароль",
            privateKeyLabel = "приватный SSH-ключ"
        ) ?: "Укажите SSH-пароль или приватный SSH-ключ в верхнем блоке «Деплой»."
    }
    if (sshPort !in 1..65535) return "Укажите корректный SSH-порт от 1 до 65535."
    if (mainPassword.isBlank()) return "Откройте «Секреты» и укажите главный пароль администратора."
    return null
}

internal fun shouldAutoRefreshServerClients(
    expanded: Boolean,
    targetReady: Boolean,
    enabled: Boolean,
    busy: Boolean,
    automaticRefreshAttempted: Boolean,
    lastRefreshAt: Long
): Boolean = expanded &&
    targetReady &&
    enabled &&
    !busy &&
    !automaticRefreshAttempted &&
    lastRefreshAt == 0L

private data class PendingClientAction(
    val title: String,
    val message: String,
    val confirmLabel: String,
    val danger: Boolean,
    val onConfirm: () -> Unit = {},
    val run: suspend () -> ServerAdminActionResult
)

@Composable
private fun ClientsServerStateCard(
    state: ServerAdminState?,
    refreshBusy: Boolean,
    lastRefreshAt: Long,
    lastRefreshAttemptAt: Long,
    lastRefreshError: String,
    accessIssue: String?,
    enabled: Boolean,
    onRefresh: () -> Unit
) {
    val visualState = when {
        lastRefreshError.isNotBlank() -> ClientsServerRefreshState.Error
        lastRefreshAt > 0L && state != null -> ClientsServerRefreshState.Ready
        else -> ClientsServerRefreshState.Unknown
    }
    val indicatorColor = when (visualState) {
        ClientsServerRefreshState.Unknown -> MaterialTheme.colorScheme.outline
        ClientsServerRefreshState.Ready -> WDTTColors.connected
        ClientsServerRefreshState.Error -> MaterialTheme.colorScheme.error
    }
    val title = when {
        refreshBusy -> "Обновляю клиентов и состояние сервера..."
        accessIssue != null -> "Обновление пока недоступно"
        lastRefreshError.isNotBlank() -> "Не удалось обновить данные"
        lastRefreshAt > 0L && state != null -> "Клиенты и сервер обновлены"
        else -> "Клиенты и сервер ещё не проверены"
    }
    val details = when {
        refreshBusy -> "Проверяю SSH-доступ, главный пароль администратора и читаю актуальный список."
        accessIssue != null -> accessIssue
        lastRefreshError.isNotBlank() -> buildString {
            if (lastRefreshAttemptAt > 0L) {
                append("Последняя попытка: ${formatRefreshDateTime(lastRefreshAttemptAt)}. ")
            }
            append(lastRefreshError)
        }
        lastRefreshAt > 0L && state != null ->
            "Обновлено: ${formatRefreshDateTime(lastRefreshAt)}.\nКлиентов: ${state.passwordCount}, устройств: ${state.deviceCount}."
        else -> "При первом раскрытии за текущий запуск список обновится автоматически. Правильность главного пароля проверит сервер."
    }

    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.40f),
        border = BorderStroke(1.dp, indicatorColor.copy(alpha = 0.42f))
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
                if (refreshBusy) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(14.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.primary
                    )
                } else {
                    Box(
                        modifier = Modifier
                            .size(12.dp)
                            .background(indicatorColor, CircleShape)
                    )
                }
                Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(
                        title,
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        details,
                        style = MaterialTheme.typography.bodySmall,
                        color = if (lastRefreshError.isNotBlank()) {
                            MaterialTheme.colorScheme.error
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        }
                    )
                }
            }
            TextButton(
                onClick = onRefresh,
                enabled = enabled && accessIssue == null && !refreshBusy,
                modifier = Modifier.align(Alignment.End)
            ) {
                if (refreshBusy) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.width(6.dp))
                }
                Text(if (refreshBusy) "Обновляю..." else "Обновить")
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ServerClientsSection(
    host: String,
    user: String,
    sshPassword: String,
    sshPrivateKey: String,
    sshKeyPassphrase: String,
    allowPasswordAuthentication: Boolean,
    sshPort: Int,
    mainPassword: String,
    defaultPorts: String,
    adminProfile: ServerAdminProfileInfo,
    sourceProfileName: String,
    enabled: Boolean,
    hostValid: Boolean,
    expanded: Boolean = false,
    modifier: Modifier = Modifier,
    onExpandedChange: (Boolean) -> Unit = {},
    onExpanded: () -> Unit = {}
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val clientsViewModel: ServerClientsViewModel = viewModel()
    var state by clientsViewModel.serverState
    var busy by remember { mutableStateOf(false) }
    var refreshBusy by remember { mutableStateOf(false) }
    var status by rememberSaveable { mutableStateOf("") }
    var showCreateWizard by rememberSaveable { mutableStateOf(false) }
    var showImportMethods by rememberSaveable { mutableStateOf(false) }
    var pendingImport by remember { mutableStateOf<ClientTransferPayload?>(null) }
    var exportClient by remember { mutableStateOf<ServerClientInfo?>(null) }
    var passwordClient by remember { mutableStateOf<ServerClientInfo?>(null) }
    var changedPasswordClient by remember { mutableStateOf<ServerClientInfo?>(null) }
    var pendingAction by remember { mutableStateOf<PendingClientAction?>(null) }
    var expiryClient by remember { mutableStateOf<ServerClientInfo?>(null) }
    var qrData by remember { mutableStateOf<Pair<String, Bitmap>?>(null) }
    var detailsClient by remember { mutableStateOf<ServerClientInfo?>(null) }
    var showServerTools by rememberSaveable { mutableStateOf(false) }
    var createdClient by remember { mutableStateOf<ServerClientInfo?>(null) }
    var importedClient by remember { mutableStateOf<ServerClientInfo?>(null) }
    var filtersExpanded by rememberSaveable { mutableStateOf(false) }
    var statusFilter by rememberSaveable { mutableStateOf(ClientStatusFilter.All) }
    var bindingFilter by rememberSaveable { mutableStateOf(ClientBindingFilter.All) }
    var expiryFilter by rememberSaveable { mutableStateOf(ClientExpiryFilter.All) }
    var vkHashFilter by rememberSaveable { mutableStateOf(ClientVkHashFilter.All) }
    var clientSearchFocused by remember { mutableStateOf(false) }
    var clientSearch by clientsViewModel.clientSearch
    var selectedClientIndex by clientsViewModel.selectedClientIndex
    var lastRefreshAt by clientsViewModel.lastRefreshAt
    var lastRefreshAttemptAt by clientsViewModel.lastRefreshAttemptAt
    var lastRefreshError by clientsViewModel.lastRefreshError
    var automaticRefreshAttempted by clientsViewModel.automaticRefreshAttempted
    val inboxTransfer by ClientTransferInbox.pending.collectAsStateWithLifecycle()
    val arrowRotation by animateFloatAsState(
        targetValue = if (expanded) 180f else 0f,
        label = "server_clients_arrow_rotation"
    )

    val accessIssue = serverClientsAccessIssue(
        host = host,
        hostValid = hostValid,
        sshPassword = sshPassword,
        sshPrivateKey = sshPrivateKey,
        allowPasswordAuthentication = allowPasswordAuthentication,
        sshPort = sshPort,
        mainPassword = mainPassword
    )
    val targetReady = accessIssue == null
    val targetKey = remember(host, user, sshPassword, sshPrivateKey, sshKeyPassphrase, allowPasswordAuthentication, sshPort, mainPassword) {
        listOf(
            host.trim(),
            user.ifBlank { "root" },
            sshPort.toString(),
            sshPassword.hashCode().toString(),
            sshPrivateKey.hashCode().toString(),
            sshKeyPassphrase.hashCode().toString(),
            allowPasswordAuthentication.toString(),
            mainPassword.hashCode().toString()
        ).joinToString("\u0000")
    }
    LaunchedEffect(targetKey) {
        if (clientsViewModel.targetKey != targetKey) {
            clientsViewModel.targetKey = targetKey
            val cached = ServerClientsProcessCache.get(targetKey)
            state = cached?.state
            status = ""
            lastRefreshAt = cached?.lastRefreshAt ?: 0L
            lastRefreshAttemptAt = cached?.lastRefreshAttemptAt ?: 0L
            lastRefreshError = cached?.lastRefreshError.orEmpty()
            automaticRefreshAttempted = cached?.attempted == true
            detailsClient = null
            showServerTools = false
            clientSearch = ""
            selectedClientIndex = 0
        }
    }

    LaunchedEffect(status, busy) {
        if (status.isBlank() || busy) return@LaunchedEffect
        delay(if (status.startsWith("Ошибка")) 8_000L else 4_500L)
        if (!busy) status = ""
    }

    val canUse = enabled && targetReady && !busy
    val effectiveUser = user.ifBlank { "root" }
    val target = ServerAdminTarget(
        host = host.trim(),
        user = effectiveUser,
        sshPassword = sshPassword,
        sshPrivateKey = sshPrivateKey,
        sshKeyPassphrase = sshKeyPassphrase,
        allowPasswordAuthentication = allowPasswordAuthentication,
        sshPort = sshPort,
        mainPassword = mainPassword
    )

    fun acceptClientTransfer(raw: String) {
        runCatching { ClientTransferCodec.decode(raw) }
            .onSuccess {
                pendingImport = it
                showImportMethods = false
            }
            .onFailure { status = "Ошибка: ${it.message ?: "данные клиента не распознаны"}" }
    }

    val importCameraLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        result.contents?.takeIf { it.isNotBlank() }?.let(::acceptClientTransfer)
    }
    val importGalleryLauncher = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) scope.launch {
            runCatching { withContext(Dispatchers.IO) { TransferFiles.decodeQrImage(context, uri) } }
                .onSuccess(::acceptClientTransfer)
                .onFailure { status = "Ошибка: ${it.message ?: "QR-код не прочитан"}" }
        }
    }
    val importFileLauncher = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) scope.launch {
            runCatching { withContext(Dispatchers.IO) { TransferFiles.readText(context, uri) } }
                .onSuccess(::acceptClientTransfer)
                .onFailure { status = "Ошибка: ${it.message ?: "файл клиента не прочитан"}" }
        }
    }

    LaunchedEffect(inboxTransfer) {
        inboxTransfer?.let { raw ->
            acceptClientTransfer(raw)
            ClientTransferInbox.clear(raw)
        }
    }

    fun applyFreshServerState(freshState: ServerAdminState) {
        val refreshedAt = System.currentTimeMillis()
        state = freshState
        lastRefreshAt = refreshedAt
        lastRefreshAttemptAt = refreshedAt
        lastRefreshError = ""
        automaticRefreshAttempted = true
        ServerClientsProcessCache.put(
            targetKey,
            ServerClientsProcessSnapshot(
                state = freshState,
                lastRefreshAt = refreshedAt,
                lastRefreshAttemptAt = refreshedAt,
                lastRefreshError = "",
                attempted = true
            )
        )
    }

    fun recordRefreshFailure(error: Throwable) {
        lastRefreshAttemptAt = System.currentTimeMillis()
        lastRefreshError = error.message ?: "не удалось прочитать клиентов и состояние сервера"
        automaticRefreshAttempted = true
        ServerClientsProcessCache.put(
            targetKey,
            ServerClientsProcessSnapshot(
                state = state,
                lastRefreshAt = lastRefreshAt,
                lastRefreshAttemptAt = lastRefreshAttemptAt,
                lastRefreshError = lastRefreshError,
                attempted = true
            )
        )
    }

    fun refreshClients() {
        if (!targetReady || !enabled || busy) return
        val requestedTargetKey = targetKey
        busy = true
        refreshBusy = true
        lastRefreshError = ""
        automaticRefreshAttempted = true
        ServerClientsProcessCache.put(
            targetKey,
            ServerClientsProcessSnapshot(
                state = state,
                lastRefreshAt = lastRefreshAt,
                lastRefreshAttemptAt = lastRefreshAttemptAt,
                lastRefreshError = "",
                attempted = true
            )
        )
        scope.launch {
            try {
                runCatching { ServerAdminClient.list(target) }
                    .onSuccess {
                        if (clientsViewModel.targetKey == requestedTargetKey) {
                            applyFreshServerState(it)
                        }
                    }
                    .onFailure {
                        if (clientsViewModel.targetKey == requestedTargetKey) {
                            recordRefreshFailure(it)
                        }
                    }
            } finally {
                refreshBusy = false
                busy = false
            }
        }
    }

    LaunchedEffect(expanded, targetKey, targetReady, enabled, busy, automaticRefreshAttempted, lastRefreshAt) {
        if (shouldAutoRefreshServerClients(
                expanded = expanded,
                targetReady = targetReady,
                enabled = enabled,
                busy = busy,
                automaticRefreshAttempted = automaticRefreshAttempted,
                lastRefreshAt = lastRefreshAt
            )
        ) {
            refreshClients()
        }
    }

    fun runAction(action: PendingClientAction) {
        pendingAction = null
        action.onConfirm()
        busy = true
        status = action.title
        scope.launch {
            runCatching { action.run() }
                .onSuccess { result ->
                    status = buildString {
                        append(result.message)
                        if (result.restarted) append(". Сервис перезапущен.")
                    }
                    runCatching { ServerAdminClient.list(target) }
                        .onSuccess(::applyFreshServerState)
                        .onFailure(::recordRefreshFailure)
                }
                .onFailure { status = "Ошибка: ${it.message ?: "операция не выполнена"}" }
            busy = false
        }
    }

    fun runDirect(title: String, action: suspend () -> ServerAdminActionResult) {
        busy = true
        status = title
        scope.launch {
            runCatching { action() }
                .onSuccess { result ->
                    status = result.message + if (result.restarted) ". Сервис перезапущен." else ""
                    runCatching { ServerAdminClient.list(target) }
                        .onSuccess(::applyFreshServerState)
                        .onFailure(::recordRefreshFailure)
                }
                .onFailure { status = "Ошибка: ${it.message ?: "операция не выполнена"}" }
            busy = false
        }
    }

    AppSectionCard(
        modifier = modifier,
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(0.dp)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(24.dp))
                .clickable {
                    val willExpand = !expanded
                    onExpandedChange(willExpand)
                    if (willExpand) onExpanded()
                }
                .padding(vertical = 2.dp)
        ) {
            Surface(shape = RoundedCornerShape(18.dp), color = MaterialTheme.colorScheme.primaryContainer) {
                Box(modifier = Modifier.size(40.dp), contentAlignment = Alignment.Center) {
                    Icon(
                        imageVector = Icons.Default.Smartphone,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }
            Column(modifier = Modifier.weight(1f)) {
                Text("Клиенты и сервер", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            }
            Icon(
                imageVector = Icons.Default.ExpandMore,
                contentDescription = if (expanded) "Свернуть" else "Раскрыть",
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
                    "Создание доступов, управление подключениями и серверные инструменты без Telegram-бота.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                ClientsServerStateCard(
                    state = state,
                    refreshBusy = refreshBusy,
                    lastRefreshAt = lastRefreshAt,
                    lastRefreshAttemptAt = lastRefreshAttemptAt,
                    lastRefreshError = lastRefreshError,
                    accessIssue = accessIssue,
                    enabled = enabled && !busy,
                    onRefresh = { refreshClients() }
                )

                ClientPanel {
                    Text(
                        "Действия для сервера",
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.align(Alignment.CenterHorizontally)
                    )
                    FlowRow(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(onClick = { showCreateWizard = true }, enabled = canUse) {
                            Icon(Icons.Default.Add, null, Modifier.size(18.dp))
                            Text(" Создать")
                        }
                        OutlinedButton(onClick = { showImportMethods = true }, enabled = canUse && state != null) {
                            Text("Импорт")
                        }
                        OutlinedButton(onClick = { showServerTools = true }, enabled = canUse && state != null) {
                            Text("Сервер")
                        }
                    }
                }

                if (status.isNotBlank()) {
                    ClientStatusBanner(status = status, busy = busy)
                }

                state?.let { current ->
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                val activeFilterCount = activeClientFilterCount(statusFilter, bindingFilter, expiryFilter, vkHashFilter)
                ClientPanel {
                    Text(
                        "Лимит: ${current.passwordCount}/${current.maxPasswords}\nАдрес сервера для ссылок: ${if (current.publicHost.isBlank()) "определён автоматически: ${current.effectivePublicHost.ifBlank { host }}" else "задан вручную: ${current.publicHost}"}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.Top
                    ) {
                        Surface(
                            shape = RoundedCornerShape(18.dp),
                            color = MaterialTheme.colorScheme.surface,
                            border = BorderStroke(
                                1.dp,
                                if (clientSearchFocused) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline
                            ),
                            modifier = Modifier
                                .weight(1f)
                                .requiredHeight(56.dp)
                        ) {
                            BasicTextField(
                                value = clientSearch,
                                onValueChange = { clientSearch = it.take(80); selectedClientIndex = 0 },
                                singleLine = true,
                                textStyle = MaterialTheme.typography.bodyLarge.copy(color = MaterialTheme.colorScheme.onSurface),
                                cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                                modifier = Modifier
                                    .fillMaxSize()
                                    .onFocusChanged { clientSearchFocused = it.isFocused },
                                decorationBox = { innerTextField ->
                                    Box(
                                        modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp),
                                        contentAlignment = Alignment.CenterStart
                                    ) {
                                        if (clientSearch.isBlank()) {
                                            Text(
                                                "Поиск по клиентам",
                                                style = MaterialTheme.typography.bodyLarge,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                        }
                                        innerTextField()
                                    }
                                }
                            )
                        }
                        Surface(
                            onClick = { filtersExpanded = true },
                            shape = RoundedCornerShape(18.dp),
                            color = MaterialTheme.colorScheme.surface,
                            contentColor = MaterialTheme.colorScheme.primary,
                            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
                            modifier = Modifier
                                .width(if (activeFilterCount > 0) 72.dp else 56.dp)
                                .requiredHeight(56.dp)
                        ) {
                            Row(
                                modifier = Modifier.fillMaxSize(),
                                horizontalArrangement = Arrangement.Center,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(Icons.Default.FilterList, contentDescription = "Фильтры", modifier = Modifier.size(20.dp))
                                if (activeFilterCount > 0) Text(" $activeFilterCount")
                            }
                        }
                    }
                }
                val filteredClients = remember(current.clients, clientSearch, statusFilter, bindingFilter, expiryFilter, vkHashFilter) {
                    current.clients
                        .filterByQuery(clientSearch)
                        .filterByClientFilters(statusFilter, bindingFilter, expiryFilter, vkHashFilter)
                }
                LaunchedEffect(filteredClients.size) {
                    selectedClientIndex = selectedClientIndex.coerceIn(0, (filteredClients.size - 1).coerceAtLeast(0))
                }
                if (filteredClients.isEmpty()) {
                    Text(
                        when {
                            current.clients.isEmpty() -> "Клиенты не загружены."
                            clientSearch.isBlank() && activeFilterCount > 0 -> "По фильтрам ничего не найдено."
                            else -> "Ничего не найдено."
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                } else {
                    val publicHost = current.publicHost.ifBlank { current.effectivePublicHost }
                    val selectedClient = filteredClients[selectedClientIndex.coerceIn(0, filteredClients.lastIndex)]
                    ClientPanel(contentPadding = PaddingValues(vertical = 12.dp)) {
                        ClientsPager(
                            clients = filteredClients,
                            selectedIndex = selectedClientIndex,
                            onSelectedIndexChange = { selectedClientIndex = it },
                            fallbackHost = host,
                            publicHost = publicHost
                        )
                        SwipeHint(
                            selectedIndex = selectedClientIndex,
                            count = filteredClients.size,
                            modifier = Modifier.align(Alignment.CenterHorizontally)
                        )
                    }
                    ClientPanel {
                            Text(
                                "Действия для ${selectedClient.displayName()}",
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.align(Alignment.CenterHorizontally)
                            )
                            ServerClientActions(
                                client = selectedClient,
                                fallbackHost = host,
                                publicHost = publicHost,
                                sourceProfileName = sourceProfileName,
                                busy = busy,
                                onShareLink = { link -> shareText(context, link) },
                                onFile = { link ->
                                    scope.launch {
                                        runCatching {
                                            withContext(Dispatchers.IO) {
                                                TransferFiles.writeTransferText(context, "WDTT-Plus-${selectedClient.safeFileName()}.wdtt", link)
                                            }
                                        }.onSuccess {
                                            shareUri(context, it, "application/vnd.wdtt.plus.transfer", "Передать подключение WDTT Plus")
                                        }.onFailure {
                                            Toast.makeText(context, it.message ?: "Не удалось создать файл.", Toast.LENGTH_LONG).show()
                                        }
                                    }
                                },
                                onQr = { link ->
                                    scope.launch {
                                        runCatching {
                                            withContext(Dispatchers.Default) { TransferFiles.createQrBitmap(context, link) }
                                        }.onSuccess { qrData = selectedClient.displayName() to it }
                                            .onFailure { Toast.makeText(context, it.message ?: "Не удалось создать QR.", Toast.LENGTH_LONG).show() }
                                    }
                                },
                                onExtend = { expiryClient = selectedClient },
                                onExport = { exportClient = selectedClient },
                                onDetails = {
                                    busy = true
                                    status = "Читаю данные клиента..."
                                    scope.launch {
                                        runCatching { ServerAdminClient.details(target, selectedClient.password) }
                                            .onSuccess {
                                                detailsClient = it
                                                status = "Данные клиента загружены."
                                            }
                                            .onFailure { status = "Ошибка: ${it.message ?: "не удалось прочитать клиента"}" }
                                        busy = false
                                    }
                                },
                                onUnbind = {
                                    pendingAction = PendingClientAction(
                                        title = "Отвязываю устройство...",
                                        message = "Отвязать устройство от «${selectedClient.displayName()}»? Его текущее подключение завершится сразу, остальные клиенты продолжат работать.",
                                        confirmLabel = "Отвязать",
                                        danger = false,
                                        run = { ServerAdminClient.unbind(target, selectedClient.password) }
                                    )
                                },
                                onChangePassword = { passwordClient = selectedClient },
                                onToggle = {
                                    pendingAction = if (selectedClient.status == "deactivated") {
                                        PendingClientAction(
                                            title = "Включаю клиента...",
                                            message = "Включить доступ «${selectedClient.displayName()}»?",
                                            confirmLabel = "Включить",
                                            danger = false,
                                            run = { ServerAdminClient.activate(target, selectedClient.password) }
                                        )
                                    } else {
                                        PendingClientAction(
                                            title = "Отключаю клиента...",
                                            message = "Отключить доступ «${selectedClient.displayName()}»? Текущее соединение завершится, но привязка устройства сохранится.",
                                            confirmLabel = "Откл.",
                                            danger = true,
                                            run = { ServerAdminClient.deactivate(target, selectedClient.password) }
                                        )
                                    }
                                },
                                onDelete = {
                                    pendingAction = PendingClientAction(
                                        title = "Удаляю клиента...",
                                        message = "Удалить «${selectedClient.displayName()}» без восстановления? Устройство тоже будет отвязано.",
                                        confirmLabel = "Удалить",
                                        danger = true,
                                        run = { ServerAdminClient.delete(target, selectedClient.password) }
                                    )
                                }
                            )
                    }
                    }
                }
            }
        }
    }
    }

    if (filtersExpanded) {
        ClientFiltersDialog(
            statusFilter = statusFilter,
            onStatusFilterChange = { statusFilter = it; selectedClientIndex = 0 },
            bindingFilter = bindingFilter,
            onBindingFilterChange = { bindingFilter = it; selectedClientIndex = 0 },
            expiryFilter = expiryFilter,
            onExpiryFilterChange = { expiryFilter = it; selectedClientIndex = 0 },
            vkHashFilter = vkHashFilter,
            onVkHashFilterChange = { vkHashFilter = it; selectedClientIndex = 0 },
            onClear = {
                statusFilter = ClientStatusFilter.All
                bindingFilter = ClientBindingFilter.All
                expiryFilter = ClientExpiryFilter.All
                vkHashFilter = ClientVkHashFilter.All
                selectedClientIndex = 0
            },
            onDismiss = { filtersExpanded = false }
        )
    }

    if (showCreateWizard) {
        CreateClientWizardDialog(
            defaultPorts = state?.defaultPorts ?: defaultPorts.ifBlank { "56000,56001,9000" },
            existingPasswords = state?.clients?.map { it.password }.orEmpty().toSet(),
            mainPassword = mainPassword,
            busy = busy,
            onDismiss = { if (!busy) showCreateWizard = false },
            onCreate = { request ->
                showCreateWizard = false
                busy = true
                status = "Создаю клиента..."
                scope.launch {
                    runCatching { ServerAdminClient.create(target, request) }
                        .onSuccess { result ->
                            status = buildString {
                                append(result.message)
                                if (result.restarted) append(". Сервис перезапущен.")
                            }
                            createdClient = result.createdClient
                            runCatching { ServerAdminClient.list(target) }
                                .onSuccess(::applyFreshServerState)
                                .onFailure(::recordRefreshFailure)
                        }
                        .onFailure { status = "Ошибка: ${it.message ?: "клиент не создан"}" }
                    busy = false
                }
            }
        )
    }

    if (showImportMethods) {
        ClientImportMethodsDialog(
            onDismiss = { showImportMethods = false },
            onCamera = {
                importCameraLauncher.launch(
                    ScanOptions()
                        .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                        .setPrompt("Наведите камеру на QR переноса клиента")
                        .setBeepEnabled(false)
                        .setCaptureActivity(QrCaptureActivity::class.java)
                        .setOrientationLocked(false)
                )
            },
            onGallery = { importGalleryLauncher.launch("image/*") },
            onFile = { importFileLauncher.launch("*/*") },
            onPaste = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val value = clipboard.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(context)?.toString()
                if (value.isNullOrBlank()) status = "Ошибка: в буфере обмена нет данных клиента"
                else acceptClientTransfer(value)
            }
        )
    }

    pendingImport?.let { payload ->
        val current = state
        ClientImportConfirmDialog(
            payload = payload,
            targetHost = current?.let { it.publicHost.ifBlank { it.effectivePublicHost.ifBlank { host } } }.orEmpty(),
            targetPorts = current?.defaultPorts ?: defaultPorts,
            passwordConflict = current?.clients?.any { it.password == payload.password } == true,
            mainPasswordConflict = payload.password == mainPassword,
            limitReached = current != null && current.passwordCount >= current.maxPasswords && current.expiredCount == 0,
            onDismiss = { pendingImport = null },
            onConfirm = {
                pendingImport = null
                busy = true
                status = "Импорт: отправляю данные клиента на сервер..."
                scope.launch {
                    try {
                        val result = ServerAdminClient.importClient(
                            target,
                            payload,
                            current?.defaultPorts ?: defaultPorts.ifBlank { "56000,56001,9000" }
                        )
                        status = "Импорт: клиент записан, проверяю список на сервере..."
                        val refreshed = runCatching { ServerAdminClient.list(target) }
                            .onFailure(::recordRefreshFailure)
                            .getOrThrow()
                        val imported = refreshed.clients.firstOrNull { it.password == payload.password }
                            ?: result.createdClient?.takeIf { created -> created.password == payload.password }
                            ?: throw IllegalStateException("сервер принял импорт, но клиент не найден в свежем списке. Нажмите «Обновить» и проверьте, не достигнут ли лимит клиентов.")
                        applyFreshServerState(refreshed)
                        clientSearch = ""
                        statusFilter = ClientStatusFilter.All
                        bindingFilter = ClientBindingFilter.All
                        expiryFilter = ClientExpiryFilter.All
                        vkHashFilter = ClientVkHashFilter.All
                        selectedClientIndex = refreshed.clients.indexOfFirst { it.password == payload.password }
                            .coerceAtLeast(0)
                        importedClient = imported
                        status = "Клиент импортирован и найден в списке без перезапуска сервера."
                    } catch (error: Throwable) {
                        status = "Ошибка: ${error.message ?: "клиент не импортирован"}"
                    }
                    busy = false
                }
            }
        )
    }

    exportClient?.let { client ->
        val transferResult = remember(client) { runCatching { ClientTransferCodec.encode(ClientTransferCodec.fromClient(client)) } }
        val transfer = transferResult.getOrNull()
        if (transfer == null) {
            AlertDialog(
                onDismissRequest = { exportClient = null },
                title = { DialogTitle("Экспорт невозможен", { exportClient = null }) },
                text = {
                    Text(
                        transferResult.exceptionOrNull()?.message ?: "Проверьте пароль и VK-хеши клиента.",
                        color = MaterialTheme.colorScheme.error
                    )
                },
                confirmButton = { Button(onClick = { exportClient = null }) { Text("Хорошо") } }
            )
        } else {
            ClientTransferExportDialog(
                client = client,
                onDismiss = { exportClient = null },
                onCopy = { copyText(context, "Перенос клиента WDTT Plus", transfer) },
                onShare = { shareText(context, transfer, "Передать клиента WDTT Plus") },
                onQr = {
                    scope.launch {
                        runCatching { withContext(Dispatchers.Default) { TransferFiles.createQrBitmap(context, transfer) } }
                            .onSuccess { qrData = "Перенос: ${client.displayName()}" to it }
                            .onFailure { status = "Ошибка: ${it.message ?: "QR-код не создан"}" }
                    }
                },
                onFile = {
                    scope.launch {
                        runCatching {
                            withContext(Dispatchers.IO) {
                                TransferFiles.writeTransferText(context, "WDTT-Plus-${client.safeFileName()}.wdtt-client", transfer)
                            }
                        }.onSuccess {
                            shareUri(context, it, "application/vnd.wdtt.plus.client", "Передать клиента WDTT Plus")
                        }.onFailure { status = "Ошибка: ${it.message ?: "файл клиента не создан"}" }
                    }
                }
            )
        }
    }

    passwordClient?.let { client ->
        ChangeClientPasswordDialog(
            client = client,
            existingPasswords = state?.clients?.map { it.password }.orEmpty().toSet(),
            mainPassword = mainPassword,
            onDismiss = { passwordClient = null },
            onConfirm = { newPassword ->
                passwordClient = null
                busy = true
                status = "Изменяю пароль клиента..."
                scope.launch {
                    runCatching { ServerAdminClient.setPassword(target, client.password, newPassword) }
                        .onSuccess { result ->
                            status = result.message
                            changedPasswordClient = result.createdClient
                            runCatching { ServerAdminClient.list(target) }
                                .onSuccess(::applyFreshServerState)
                                .onFailure(::recordRefreshFailure)
                        }
                        .onFailure { status = "Ошибка: ${it.message ?: "пароль не изменён"}" }
                    busy = false
                }
            }
        )
    }

    pendingAction?.let { action ->
        ConfirmClientActionDialog(
            action = action,
            onDismiss = { pendingAction = null },
            onConfirm = { runAction(action) }
        )
    }

    expiryClient?.let { client ->
        ExtendClientDialog(
            client = client,
            onDismiss = { expiryClient = null },
            onSelect = { days ->
                pendingAction = PendingClientAction(
                    title = "Обновляю срок...",
                    message = "Продлить «${client.displayName()}» ${formatExtensionPeriod(days)}?",
                    confirmLabel = "Продлить",
                    danger = false,
                    onConfirm = { expiryClient = null },
                    run = { ServerAdminClient.setExpiry(target, client.password, days) }
                )
            }
        )
    }

    createdClient?.let { client ->
        val link = client.connectionLink(
            host,
            state?.publicHost?.ifBlank { state?.effectivePublicHost.orEmpty() }.orEmpty(),
            sourceProfileName
        )
        AccessResultDialog(
            title = "Клиент создан",
            password = client.password,
            link = link,
            noLinkText = "VK-хеш не задан. Пароль уже работает; ссылку, QR и файл можно создать после добавления хеша в «Подробнее».",
            onDismiss = { createdClient = null },
            onCopyPassword = { copyText(context, "Пароль WDTT", client.password) },
            onCopyLink = { link?.let { copyText(context, "Ссылка WDTT", it) } },
            onShare = { link?.let { shareText(context, it) } },
            onQr = {
                link?.let { value ->
                    scope.launch {
                        runCatching { withContext(Dispatchers.Default) { TransferFiles.createQrBitmap(context, value) } }
                            .onSuccess { qrData = client.displayName() to it }
                            .onFailure { Toast.makeText(context, it.message ?: "Не удалось создать QR.", Toast.LENGTH_LONG).show() }
                    }
                }
            },
            onFile = {
                link?.let { value ->
                    scope.launch {
                        runCatching {
                            withContext(Dispatchers.IO) { TransferFiles.writeTransferText(context, "WDTT-Plus-${client.safeFileName()}.wdtt", value) }
                        }.onSuccess { shareUri(context, it, "application/vnd.wdtt.plus.transfer", "Передать подключение WDTT Plus") }
                            .onFailure { Toast.makeText(context, it.message ?: "Не удалось создать файл.", Toast.LENGTH_LONG).show() }
                    }
                }
            }
        )
    }

    importedClient?.let { client ->
        val link = client.connectionLink(
            host,
            state?.publicHost?.ifBlank { state?.effectivePublicHost.orEmpty() }.orEmpty(),
            sourceProfileName
        )
        AccessResultDialog(
            title = "Импорт готов",
            statusText = "Клиент импортирован и найден в списке.",
            password = client.password,
            link = link,
            noLinkText = "VK-хеш не задан. Клиент добавлен; хеш можно указать в «Подробнее».",
            onDismiss = { importedClient = null },
            onCopyPassword = { copyText(context, "Пароль импортированного клиента", client.password) },
            onCopyLink = { link?.let { copyText(context, "Ссылка WDTT", it) } },
            onShare = { link?.let { shareText(context, it) } },
            onQr = {
                link?.let { value ->
                    scope.launch {
                        runCatching { withContext(Dispatchers.Default) { TransferFiles.createQrBitmap(context, value) } }
                            .onSuccess { qrData = client.displayName() to it }
                            .onFailure { status = "Ошибка: ${it.message ?: "QR-код не создан"}" }
                    }
                }
            },
            onFile = {
                link?.let { value ->
                    scope.launch {
                        runCatching {
                            withContext(Dispatchers.IO) { TransferFiles.writeTransferText(context, "WDTT-Plus-${client.safeFileName()}.wdtt", value) }
                        }.onSuccess { shareUri(context, it, "application/vnd.wdtt.plus.transfer", "Передать подключение WDTT Plus") }
                            .onFailure { status = "Ошибка: ${it.message ?: "файл не создан"}" }
                    }
                }
            }
        )
    }

    changedPasswordClient?.let { client ->
        val link = client.connectionLink(
            host,
            state?.publicHost?.ifBlank { state?.effectivePublicHost.orEmpty() }.orEmpty(),
            sourceProfileName
        )
        AccessResultDialog(
            title = "Пароль изменён",
            password = client.password,
            link = link,
            noLinkText = "VK-хеш не задан. Новый пароль уже работает; добавьте хеш в «Подробнее», чтобы сформировать ссылку.",
            onDismiss = { changedPasswordClient = null },
            onCopyPassword = { copyText(context, "Новый пароль WDTT", client.password) },
            onCopyLink = { link?.let { copyText(context, "Новая ссылка WDTT", it) } },
            onShare = { link?.let { shareText(context, it) } },
            onQr = {
                link?.let { value ->
                    scope.launch {
                        runCatching { withContext(Dispatchers.Default) { TransferFiles.createQrBitmap(context, value) } }
                            .onSuccess { qrData = client.displayName() to it }
                            .onFailure { status = "Ошибка: ${it.message ?: "QR-код не создан"}" }
                    }
                }
            },
            onFile = {
                link?.let { value ->
                    scope.launch {
                        runCatching {
                            withContext(Dispatchers.IO) { TransferFiles.writeTransferText(context, "WDTT-Plus-${client.safeFileName()}.wdtt", value) }
                        }.onSuccess { shareUri(context, it, "application/vnd.wdtt.plus.transfer", "Передать новое подключение WDTT Plus") }
                            .onFailure { status = "Ошибка: ${it.message ?: "файл не создан"}" }
                    }
                }
            }
        )
    }

    detailsClient?.let { client ->
        ClientDetailsDialog(
            client = client,
            defaultPorts = state?.defaultPorts ?: defaultPorts.ifBlank { "56000,56001,9000" },
            fallbackHost = host,
            publicHost = state?.publicHost?.ifBlank { state?.effectivePublicHost.orEmpty() }.orEmpty(),
            sourceProfileName = sourceProfileName,
            busy = busy,
            onDismiss = { detailsClient = null },
            onSave = { label, hash, ports ->
                detailsClient = null
                runDirect("Обновляю клиента...") {
                    ServerAdminClient.updateClient(target, client.password, label, hash, ports)
                }
            }
        )
    }

    if (showServerTools) {
        state?.let { current ->
            ServerToolsDialog(
                state = current,
                localAdminProfile = adminProfile,
                busy = busy,
                onDismiss = { showServerTools = false },
                onSaveNetwork = { dns, limit, ports, publicHost ->
                    showServerTools = false
                    runDirect("Обновляю настройки сервера...") {
                        ServerAdminClient.updateSettings(target, dns, limit, ports, publicHost)
                    }
                },
                onRefreshIp = {
                    runDirect("Определяю публичный IP сервера...") { ServerAdminClient.refreshPublicHost(target) }
                },
                onCleanupExpired = {
                    pendingAction = PendingClientAction(
                        "Удаляю истёкшие доступы...",
                        "Удалить ${current.expiredCount} истёкших доступов?",
                        "Удалить", true
                    ) { ServerAdminClient.cleanupExpired(target) }
                },
                onCleanupOrphans = {
                    pendingAction = PendingClientAction(
                        "Удаляю забытые устройства...",
                        "Удалить ${current.orphanDeviceCount} ${current.orphanDeviceCount.pluralRu("запись", "записи", "записей")} устройств, не связанных с клиентами?",
                        "Удалить", true
                    ) { ServerAdminClient.cleanupOrphans(target) }
                },
                onResetTraffic = {
                    pendingAction = PendingClientAction(
                        "Сбрасываю статистику...",
                        "Обнулить счётчики трафика? Доступы и устройства сохранятся.",
                        "Сбросить", true
                    ) { ServerAdminClient.resetTraffic(target) }
                },
                onRestart = {
                    pendingAction = PendingClientAction(
                        "Перезапускаю WDTT...",
                        "Перезапустить wdtt.service? Все клиенты кратко отключатся.",
                        "Перезапуск", true
                    ) { ServerAdminClient.restart(target) }
                }
            )
        }
    }

    qrData?.let { (title, bitmap) ->
        ClientQrDialog(
            title = title,
            bitmap = bitmap,
            onDismiss = { qrData = null },
            onShare = {
                scope.launch {
                    val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
                    val fileName = "WDTT-Plus-QR-${title.safeQrFileName()}-$stamp.png"
                    runCatching {
                        withContext(Dispatchers.IO) { TransferFiles.writeQrPng(context, fileName, bitmap) }
                    }.onSuccess { shareUri(context, it, "image/png", "Передать QR-код WDTT Plus") }
                        .onFailure { Toast.makeText(context, it.message ?: "Не удалось поделиться QR.", Toast.LENGTH_LONG).show() }
                }
            },
            onSave = {
                scope.launch {
                    val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
                    runCatching {
                        withContext(Dispatchers.IO) { TransferFiles.saveQrToGallery(context, "WDTT-Plus-client-$stamp.png", bitmap) }
                    }.onSuccess {
                        Toast.makeText(context, "QR-код сохранён.", Toast.LENGTH_SHORT).show()
                    }.onFailure {
                        Toast.makeText(context, it.message ?: "Не удалось сохранить QR.", Toast.LENGTH_LONG).show()
                    }
                }
            }
        )
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ClientsPager(
    clients: List<ServerClientInfo>,
    selectedIndex: Int,
    onSelectedIndexChange: (Int) -> Unit,
    fallbackHost: String,
    publicHost: String
) {
    val pagerState = rememberPagerState(
        initialPage = selectedIndex.coerceIn(0, clients.lastIndex),
        pageCount = { clients.size }
    )
    LaunchedEffect(selectedIndex, clients.size) {
        val target = selectedIndex.coerceIn(0, clients.lastIndex)
        if (pagerState.currentPage != target) pagerState.scrollToPage(target)
    }
    LaunchedEffect(pagerState, clients.size) {
        snapshotFlow { pagerState.currentPage }.collect { page ->
            if (page in clients.indices) onSelectedIndexChange(page)
        }
    }
    HorizontalPager(
        state = pagerState,
        key = { index -> clients[index].password },
        beyondViewportPageCount = 1,
        contentPadding = PaddingValues(horizontal = 18.dp),
        pageSpacing = 12.dp,
        modifier = Modifier.fillMaxWidth()
    ) { page ->
        ServerClientCard(
            client = clients[page],
            fallbackHost = fallbackHost,
            publicHost = publicHost,
            modifier = Modifier.fillMaxWidth()
        )
    }
}

@Composable
private fun ServerClientCard(
    client: ServerClientInfo,
    fallbackHost: String,
    publicHost: String,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface.copy(alpha = 0.55f)),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.16f)),
        shape = RoundedCornerShape(18.dp)
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(client.displayName(), fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(
                        client.maskedPassword(),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                StatusChip(client.status)
            }
            Text(
                buildString {
                    append("Срок: ${formatExpiry(client.expiresAt)}")
                    append(" · Трафик: ${formatBytes(client.downBytes + client.upBytes)}")
                    if (client.deviceId.isNotBlank()) append(" · Устройство: ${client.deviceName.ifBlank { client.deviceId.take(8) }}")
                    else append(" · Не привязан")
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            if (client.vkHash.isBlank()) {
                Text(
                    "VK-хеш не задан: быструю ссылку/QR создать нельзя, пока не обновить хеш.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }
        }
    }
}

@Composable
private fun ClientFiltersDialog(
    statusFilter: ClientStatusFilter,
    onStatusFilterChange: (ClientStatusFilter) -> Unit,
    bindingFilter: ClientBindingFilter,
    onBindingFilterChange: (ClientBindingFilter) -> Unit,
    expiryFilter: ClientExpiryFilter,
    onExpiryFilterChange: (ClientExpiryFilter) -> Unit,
    vkHashFilter: ClientVkHashFilter,
    onVkHashFilterChange: (ClientVkHashFilter) -> Unit,
    onClear: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { DialogTitle("Фильтры клиентов", onDismiss) },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
            ) {
                ClientFiltersPanel(
                    statusFilter = statusFilter,
                    onStatusFilterChange = onStatusFilterChange,
                    bindingFilter = bindingFilter,
                    onBindingFilterChange = onBindingFilterChange,
                    expiryFilter = expiryFilter,
                    onExpiryFilterChange = onExpiryFilterChange,
                    vkHashFilter = vkHashFilter,
                    onVkHashFilterChange = onVkHashFilterChange,
                    onClear = onClear
                )
            }
        },
        confirmButton = {}
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ClientFiltersPanel(
    statusFilter: ClientStatusFilter,
    onStatusFilterChange: (ClientStatusFilter) -> Unit,
    bindingFilter: ClientBindingFilter,
    onBindingFilterChange: (ClientBindingFilter) -> Unit,
    expiryFilter: ClientExpiryFilter,
    onExpiryFilterChange: (ClientExpiryFilter) -> Unit,
    vkHashFilter: ClientVkHashFilter,
    onVkHashFilterChange: (ClientVkHashFilter) -> Unit,
    onClear: () -> Unit
) {
    val activeCount = activeClientFilterCount(statusFilter, bindingFilter, expiryFilter, vkHashFilter)
    Surface(
        modifier = Modifier.fillMaxWidth().padding(top = 10.dp),
        shape = RoundedCornerShape(18.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.24f),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.16f))
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            FilterGroupTitle("Статус")
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                ClientFilterChip("Все", statusFilter == ClientStatusFilter.All) { onStatusFilterChange(ClientStatusFilter.All) }
                ClientFilterChip("Активные", statusFilter == ClientStatusFilter.Active) { onStatusFilterChange(ClientStatusFilter.Active) }
                ClientFilterChip("Отключённые", statusFilter == ClientStatusFilter.Disabled) { onStatusFilterChange(ClientStatusFilter.Disabled) }
            }

            FilterGroupTitle("Устройство")
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                ClientFilterChip("Все", bindingFilter == ClientBindingFilter.All) { onBindingFilterChange(ClientBindingFilter.All) }
                ClientFilterChip("Привязанные", bindingFilter == ClientBindingFilter.Bound) { onBindingFilterChange(ClientBindingFilter.Bound) }
                ClientFilterChip("Без устройства", bindingFilter == ClientBindingFilter.Unbound) { onBindingFilterChange(ClientBindingFilter.Unbound) }
            }

            FilterGroupTitle("Срок")
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                ClientFilterChip("Все", expiryFilter == ClientExpiryFilter.All) { onExpiryFilterChange(ClientExpiryFilter.All) }
                ClientFilterChip("Действующие", expiryFilter == ClientExpiryFilter.Valid) { onExpiryFilterChange(ClientExpiryFilter.Valid) }
                ClientFilterChip("Истёкшие", expiryFilter == ClientExpiryFilter.Expired) { onExpiryFilterChange(ClientExpiryFilter.Expired) }
                ClientFilterChip("Бессрочные", expiryFilter == ClientExpiryFilter.Unlimited) { onExpiryFilterChange(ClientExpiryFilter.Unlimited) }
            }

            FilterGroupTitle("VK-хеш")
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                ClientFilterChip("Все", vkHashFilter == ClientVkHashFilter.All) { onVkHashFilterChange(ClientVkHashFilter.All) }
                ClientFilterChip("С хешем", vkHashFilter == ClientVkHashFilter.Present) { onVkHashFilterChange(ClientVkHashFilter.Present) }
                ClientFilterChip("Без хеша", vkHashFilter == ClientVkHashFilter.Missing) { onVkHashFilterChange(ClientVkHashFilter.Missing) }
            }

            if (activeCount > 0) {
                TextButton(onClick = onClear, modifier = Modifier.align(Alignment.End)) {
                    Text("Сбросить фильтры")
                }
            }
        }
    }
}

@Composable
private fun FilterGroupTitle(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.labelMedium,
        fontWeight = FontWeight.SemiBold,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
}

@Composable
private fun ClientFilterChip(
    text: String,
    selected: Boolean,
    onClick: () -> Unit
) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = { Text(text) }
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ServerClientActions(
    client: ServerClientInfo,
    fallbackHost: String,
    publicHost: String,
    sourceProfileName: String,
    busy: Boolean,
    onShareLink: (String) -> Unit,
    onFile: (String) -> Unit,
    onQr: (String) -> Unit,
    onExtend: () -> Unit,
    onExport: () -> Unit,
    onDetails: () -> Unit,
    onUnbind: () -> Unit,
    onChangePassword: () -> Unit,
    onToggle: () -> Unit,
    onDelete: () -> Unit
) {
    val link = remember(client, fallbackHost, publicHost, sourceProfileName) {
        client.connectionLink(fallbackHost, publicHost, sourceProfileName)
    }
    var category by remember(client.password) { mutableStateOf<ClientActionCategory?>(null) }
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        ClientActionCategoryBlock(
            title = "Подключение",
            expanded = category == ClientActionCategory.Connection,
            enabled = !busy,
            onClick = {
                category = ClientActionCategory.Connection.takeUnless { category == it }
            }
        ) {
            OutlinedButton(onClick = { link?.let(onShareLink) }, enabled = !busy && link != null) {
                Icon(Icons.Default.Link, null, Modifier.size(16.dp))
                Text(" Ссылка")
            }
            OutlinedButton(onClick = { link?.let(onQr) }, enabled = !busy && link != null) {
                Icon(Icons.Default.QrCode2, null, Modifier.size(16.dp))
                Text(" QR-код")
            }
            OutlinedButton(onClick = { link?.let(onFile) }, enabled = !busy && link != null) {
                Icon(Icons.AutoMirrored.Filled.InsertDriveFile, null, Modifier.size(16.dp))
                Text(" Файл")
            }
        }

        ClientActionCategoryBlock(
            title = "Клиент",
            expanded = category == ClientActionCategory.Client,
            enabled = !busy,
            onClick = {
                category = ClientActionCategory.Client.takeUnless { category == it }
            }
        ) {
            OutlinedButton(onClick = onExtend, enabled = !busy) { Text("Продлить") }
            OutlinedButton(onClick = onDetails, enabled = !busy) { Text("Подробнее") }
            OutlinedButton(onClick = onExport, enabled = !busy) { Text("Экспорт") }
        }

        ClientActionCategoryBlock(
            title = "Доступ",
            expanded = category == ClientActionCategory.Access,
            enabled = !busy,
            onClick = {
                category = ClientActionCategory.Access.takeUnless { category == it }
            }
        ) {
            OutlinedButton(onClick = onChangePassword, enabled = !busy) {
                Icon(Icons.Default.Key, null, Modifier.size(16.dp))
                Text(" Сменить пароль")
            }
            OutlinedButton(onClick = onUnbind, enabled = !busy && client.isBound) {
                Icon(Icons.Default.Smartphone, null, Modifier.size(16.dp))
                Text(" Отвязать")
            }
            OutlinedButton(onClick = onToggle, enabled = !busy) {
                Icon(
                    if (client.status == "deactivated") Icons.Default.LockOpen else Icons.Default.PauseCircle,
                    null,
                    Modifier.size(16.dp)
                )
                Text(if (client.status == "deactivated") " Включить" else " Отключить")
            }
            OutlinedButton(
                onClick = onDelete,
                enabled = !busy,
                colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)
            ) {
                Icon(Icons.Default.Delete, null, Modifier.size(16.dp))
                Text(" Удалить")
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ClientActionCategoryBlock(
    title: String,
    expanded: Boolean,
    enabled: Boolean,
    onClick: () -> Unit,
    content: @Composable () -> Unit
) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .animateContentSize(animationSpec = tween(durationMillis = 220)),
        shape = RoundedCornerShape(12.dp),
        color = if (expanded) MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.18f) else Color.Transparent,
        border = BorderStroke(
            1.dp,
            MaterialTheme.colorScheme.outline.copy(alpha = if (expanded) 0.34f else 0.18f)
        )
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Box(modifier = Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                OutlinedButton(
                    onClick = onClick,
                    enabled = enabled,
                    colors = ButtonDefaults.outlinedButtonColors()
                ) {
                    Text(title)
                    Spacer(Modifier.width(4.dp))
                    Icon(
                        if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                        contentDescription = if (expanded) "Свернуть" else "Раскрыть",
                        modifier = Modifier.size(18.dp)
                    )
                }
            }
            if (expanded) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.14f))
                    FlowRow(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        content()
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AccessResultDialog(
    title: String,
    statusText: String? = null,
    password: String,
    link: String?,
    noLinkText: String,
    onDismiss: () -> Unit,
    onCopyPassword: () -> Unit,
    onCopyLink: () -> Unit,
    onShare: () -> Unit,
    onQr: () -> Unit,
    onFile: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { DialogTitle(title, onDismiss) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                statusText?.let {
                    Text(
                        it,
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
                Card(
                    shape = RoundedCornerShape(18.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f))
                ) {
                    Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("Пароль", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Text(password, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                        OutlinedButton(onClick = onCopyPassword, modifier = Modifier.fillMaxWidth()) { Text("Копировать пароль") }
                    }
                }
                if (link == null) {
                    Text(noLinkText, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    Text("Ссылка содержит пароль и VK-хеш. Не публикуйте её.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    FlowRow(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(onClick = onCopyLink) { Text("Копировать") }
                        OutlinedButton(onClick = onShare) { Text("Поделиться") }
                        OutlinedButton(onClick = onQr) { Text("QR") }
                        OutlinedButton(onClick = onFile) { Text("Файл") }
                    }
                }
            }
        },
        confirmButton = {}
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ClientDetailsDialog(
    client: ServerClientInfo,
    defaultPorts: String,
    fallbackHost: String,
    publicHost: String,
    sourceProfileName: String,
    busy: Boolean,
    onDismiss: () -> Unit,
    onSave: (String, String, String) -> Unit
) {
    val context = LocalContext.current
    var step by rememberSaveable(client.password) { mutableStateOf(ClientDetailsStep.Overview) }
    var label by rememberSaveable(client.password) { mutableStateOf(client.label) }
    var hash by rememberSaveable(client.password) { mutableStateOf(client.vkHash) }
    var ports by rememberSaveable(client.password) { mutableStateOf(client.ports) }
    val portsValid = ports.isPortsSpec()
    val link = remember(client, fallbackHost, publicHost, sourceProfileName) {
        client.connectionLink(fallbackHost, publicHost, sourceProfileName)
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { DialogTitle(client.displayName(), onDismiss, enabled = !busy) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    when (step) {
                        ClientDetailsStep.Overview -> "Доступ и трафик"
                        ClientDetailsStep.Device -> "Устройство"
                        ClientDetailsStep.History -> "История привязок"
                        ClientDetailsStep.Edit -> "Редактирование"
                    },
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )
                Card(
                    modifier = Modifier.fillMaxWidth().heightIn(max = 430.dp),
                    shape = RoundedCornerShape(18.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f))
                ) {
                    Column(
                        modifier = Modifier.padding(14.dp).verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(9.dp)
                    ) {
                        when (step) {
                            ClientDetailsStep.Overview -> {
                                    InfoLine("Пароль", client.maskedPassword().removePrefix("Пароль: "))
                                    FlowRow(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
                                        verticalArrangement = Arrangement.spacedBy(8.dp)
                                    ) {
                                        OutlinedButton(onClick = { copyText(context, "Пароль WDTT", client.password) }) { Text("Копировать пароль") }
                                        OutlinedButton(onClick = { link?.let { copyText(context, "Ссылка WDTT", it) } }, enabled = link != null) { Text("Копировать ссылку") }
                                    }
                                    InfoLine("Статус", when (client.status) { "active" -> "активен"; "deactivated" -> "отключён"; "expired" -> "истёк"; else -> client.status })
                                    InfoLine("Срок", formatExpiry(client.expiresAt))
                                    InfoLine("Порты", client.ports)
                                    InfoLine("VK-хеш", client.vkHash.ifBlank { "не задан" })
                                    HorizontalDivider()
                                    TrafficPeriodBlock(client.traffic)
                                }
                                ClientDetailsStep.Device -> {
                                    val device = client.device
                                    if (device == null) {
                                        Text("Устройство ещё не привязано.")
                                    } else {
                                        InfoLine("Название", device.name.ifBlank { device.deviceId })
                                        InfoLine("ID", device.deviceId)
                                        InfoLine("WG IP", device.ip)
                                        InfoLine("Модель", listOf(device.manufacturer, device.model).filter { it.isNotBlank() }.joinToString(" ").ifBlank { "неизвестно" })
                                        InfoLine("Android", buildString {
                                            append(device.androidVersion.ifBlank { "неизвестно" })
                                            if (device.sdk > 0) append(" · SDK ${device.sdk}")
                                        })
                                        InfoLine("Приложение", device.appVersion.ifBlank { "неизвестно" })
                                        InfoLine("ABI", device.abi.ifBlank { "неизвестно" })
                                        InfoLine("Регион", listOf(device.country, device.locale).filter { it.isNotBlank() }.joinToString(" · ").ifBlank { "неизвестно" })
                                        InfoLine("Внешний IP", device.remoteIp.ifBlank { "неизвестно" })
                                        InfoLine("Последняя связь", formatDateTime(device.lastSeenAt))
                                    }
                                }
                                ClientDetailsStep.History -> {
                                    if (client.bindHistory.isEmpty()) {
                                        Text("История пока пуста.")
                                    } else {
                                        client.bindHistory.takeLast(15).asReversed().forEachIndexed { index, event ->
                                            if (index > 0) HorizontalDivider()
                                            Text(
                                                when (event.status) {
                                                    "active" -> "Подключено"
                                                    "unbound" -> "Отвязано"
                                                    "denied_mismatch" -> "Отклонено другое устройство"
                                                    else -> event.status
                                                },
                                                fontWeight = FontWeight.Bold
                                            )
                                            InfoLine("Когда", formatDateTime(event.eventAt.takeIf { it > 0 } ?: event.boundAt))
                                            InfoLine("Устройство", event.deviceName.ifBlank { event.deviceId })
                                            if (event.deviceIp.isNotBlank()) InfoLine("WG IP", event.deviceIp)
                                            if (event.remoteIp.isNotBlank()) InfoLine("Внешний IP", event.remoteIp)
                                            if (event.country.isNotBlank()) InfoLine("Регион", event.country)
                                            if (event.note.isNotBlank()) Text(event.note, style = MaterialTheme.typography.bodySmall)
                                        }
                                    }
                                }
                                ClientDetailsStep.Edit -> {
                                    OutlinedTextField(
                                        value = label,
                                        onValueChange = { label = it.take(40) },
                                        label = { Text("Название") },
                                        singleLine = true,
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                    OutlinedTextField(
                                        value = hash,
                                        onValueChange = { hash = it },
                                        label = { Text("VK-хеш или ссылка") },
                                        minLines = 2,
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                    OutlinedTextField(
                                        value = ports,
                                        onValueChange = { ports = it.filter { ch -> ch.isDigit() || ch == ',' }.take(32) },
                                        label = { Text("DTLS,WG,TUN") },
                                        singleLine = true,
                                        isError = !portsValid,
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                    OutlinedButton(onClick = { ports = defaultPorts }, modifier = Modifier.fillMaxWidth()) {
                                        Text("Стандартные порты")
                                    }
                                    if (!portsValid) Text("Формат: 56000,56001,9000", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                                }
                            }
                    }
                }
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        SelectButton("Обзор", step == ClientDetailsStep.Overview, modifier = Modifier.weight(1f)) {
                            step = ClientDetailsStep.Overview
                        }
                        SelectButton("Устройство", step == ClientDetailsStep.Device, modifier = Modifier.weight(1f)) {
                            step = ClientDetailsStep.Device
                        }
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        SelectButton("История", step == ClientDetailsStep.History, modifier = Modifier.weight(1f)) {
                            step = ClientDetailsStep.History
                        }
                        SelectButton("Изменить", step == ClientDetailsStep.Edit, modifier = Modifier.weight(1f)) {
                            step = ClientDetailsStep.Edit
                        }
                    }
                }
            }
        },
        confirmButton = {
            if (step == ClientDetailsStep.Edit) {
                Button(onClick = { onSave(label, hash, ports) }, enabled = !busy && portsValid) { Text("Сохранить") }
            }
        }
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ServerToolsDialog(
    state: ServerAdminState,
    localAdminProfile: ServerAdminProfileInfo,
    busy: Boolean,
    onDismiss: () -> Unit,
    onSaveNetwork: (String, Int, String, String) -> Unit,
    onRefreshIp: () -> Unit,
    onCleanupExpired: () -> Unit,
    onCleanupOrphans: () -> Unit,
    onResetTraffic: () -> Unit,
    onRestart: () -> Unit
) {
    var step by rememberSaveable { mutableStateOf(ServerToolsStep.Overview) }
    var dns by rememberSaveable(state.dns) { mutableStateOf(state.dns) }
    var limitText by rememberSaveable(state.maxPasswords) { mutableStateOf(state.maxPasswords.toString()) }
    var ports by rememberSaveable(state.defaultPorts) { mutableStateOf(state.defaultPorts) }
    var publicHost by rememberSaveable(state.publicHost) { mutableStateOf(state.publicHost) }
    val limit = limitText.toIntOrNull()
    val networkValid = dns.isNotBlank() && limit != null && limit in 1..500 && ports.isPortsSpec()

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { DialogTitle("Управление сервером", onDismiss, enabled = !busy) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Card(
                    modifier = Modifier.fillMaxWidth().heightIn(max = 440.dp),
                    shape = RoundedCornerShape(18.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f))
                ) {
                    Column(
                        modifier = Modifier.padding(14.dp).verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        when (step) {
	                                ServerToolsStep.Overview -> {
	                                    Text("Состояние", fontWeight = FontWeight.Bold)
	                                    InfoLine("Клиенты", "${state.passwordCount}/${state.maxPasswords}")
                                    InfoLine("Устройства", state.deviceCount.toString())
                                    InfoLine("Истёкшие", state.expiredCount.toString())
                                    InfoLine("Забытые устройства", state.orphanDeviceCount.toString())
                                    InfoLine(
                                        "Адрес сервера для ссылок",
                                        if (state.publicHost.isBlank()) "Определён автоматически: ${state.effectivePublicHost.ifBlank { "ещё не определён" }}"
                                        else "Задан вручную: ${state.publicHost}"
                                    )
                                    HorizontalDivider()
                                    Text("Весь трафик", fontWeight = FontWeight.Bold)
                                    TrafficPeriodBlock(state.traffic)
                                    HorizontalDivider()
	                                    Text("Главный пароль", fontWeight = FontWeight.Bold)
	                                    TrafficPeriodBlock(state.adminTraffic)
	                                }
	                                ServerToolsStep.Owner -> {
	                                    Text("Профиль владельца", fontWeight = FontWeight.Bold)
	                                    Text(
	                                        "Поля владельца хранятся отдельно от клиентов. Главный пароль не появляется в списке клиентов, не занимает лимит и не удаляется вместе с клиентскими доступами.",
	                                        style = MaterialTheme.typography.bodySmall,
	                                        color = MaterialTheme.colorScheme.onSurfaceVariant
	                                    )
	                                    HorizontalDivider()
	                                    Text("Сохранено на сервере", fontWeight = FontWeight.Bold)
	                                    InfoLine("Состояние", if (state.adminProfile.hasSavedFields) "сохранён ${formatDateTime(state.adminProfile.updatedAt)}" else "ещё не сохранён")
	                                    InfoLine("VK-хеши", secretPresenceLabel(state.adminProfile.vkHashes))
	                                    InfoLine("Резервный VK-хеш", secretPresenceLabel(state.adminProfile.secondaryVkHash))
	                                    InfoLine("Порты", state.adminProfile.ports)
	                                    InfoLine("Потоки", state.adminProfile.workersPerHash.toString())
	                                    InfoLine("Протокол", state.adminProfile.protocol)
	                                    InfoLine("SNI", state.adminProfile.sni.ifBlank { "не задан" })
	                                    InfoLine("No DNS", if (state.adminProfile.noDns) "включено" else "выключено")
	                                    HorizontalDivider()
	                                    Text("Будет записано при установке", fontWeight = FontWeight.Bold)
	                                    InfoLine("VK-хеши", secretPresenceLabel(localAdminProfile.vkHashes))
	                                    InfoLine("Резервный VK-хеш", secretPresenceLabel(localAdminProfile.secondaryVkHash))
	                                    InfoLine("Порты", localAdminProfile.ports)
	                                    InfoLine("Потоки", localAdminProfile.workersPerHash.toString())
	                                    InfoLine("Протокол", localAdminProfile.protocol)
	                                    InfoLine("SNI", localAdminProfile.sni.ifBlank { "не задан" })
	                                    InfoLine("No DNS", if (localAdminProfile.noDns) "включено" else "выключено")
	                                    Text(
	                                        "Это обзор без редактирования и отдельного сохранения. Чтобы изменить профиль владельца, заполните поля во вкладках «Туннель» и «Деплой», затем нажмите «Установить» и подтвердите установку с сохранением данных или с нуля.",
	                                        style = MaterialTheme.typography.bodySmall,
	                                        color = MaterialTheme.colorScheme.onSurfaceVariant
	                                    )
	                                }
	                                ServerToolsStep.Network -> {
	                                    Text("Настройки ссылок и клиентов", fontWeight = FontWeight.Bold)
                                    OutlinedTextField(
                                        value = dns,
                                        onValueChange = { dns = it.take(260) },
                                        label = { Text("DNS") },
                                        supportingText = { Text("Применится к новым конфигам клиентов") },
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                    OutlinedTextField(
                                        value = limitText,
                                        onValueChange = { limitText = it.filter(Char::isDigit).take(3) },
                                        label = { Text("Лимит клиентов") },
                                        singleLine = true,
                                        isError = limit == null || limit !in 1..500,
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                    OutlinedTextField(
                                        value = ports,
                                        onValueChange = { ports = it.filter { ch -> ch.isDigit() || ch == ',' }.take(32) },
                                        label = { Text("Порты новых ссылок") },
                                        supportingText = { Text("Реальные порты службы не меняются") },
                                        singleLine = true,
                                        isError = !ports.isPortsSpec(),
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                    OutlinedTextField(
                                        value = publicHost,
                                        onValueChange = { publicHost = it.trim().take(253) },
                                        label = { Text("Адрес сервера для ссылок") },
                                        supportingText = { Text("Укажите домен или IP. Пустое поле означает автоматическое определение публичного IP") },
                                        singleLine = true,
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                    if (publicHost.isNotBlank() || state.publicHost.isBlank()) {
                                        FlowRow(
                                            modifier = Modifier.fillMaxWidth(),
                                            horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
                                            verticalArrangement = Arrangement.spacedBy(8.dp)
                                        ) {
                                            if (publicHost.isNotBlank()) {
                                                OutlinedButton(onClick = { publicHost = "" }, enabled = !busy) {
                                                    Text("Определять автоматически")
                                                }
                                            } else {
                                                OutlinedButton(onClick = onRefreshIp, enabled = !busy) {
                                                    Icon(Icons.Default.Refresh, null, Modifier.size(18.dp))
                                                    Text(" Проверить текущий IP")
                                                }
                                            }
                                        }
                                    }
                                    if (publicHost.isBlank() && state.publicHost.isNotBlank()) {
                                        Text(
                                            "Нажмите «Сохранить», чтобы включить автоматическое определение.",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                }
                                ServerToolsStep.Maintenance -> {
                                    Text("Обслуживание", fontWeight = FontWeight.Bold)
                                    if (state.expiredCount > 0) {
                                        Text("Истёкшие доступы", fontWeight = FontWeight.Bold)
                                        state.clients.filter { it.status == "expired" }.take(12).forEach { client ->
                                            Text("• ${client.title} · ${client.maskedPassword().removePrefix("Пароль: ")}", style = MaterialTheme.typography.bodySmall)
                                        }
                                        if (state.expiredCount > 12) Text("…и ещё ${state.expiredCount - 12}", style = MaterialTheme.typography.bodySmall)
                                    }
                                    OutlinedButton(onClick = onCleanupExpired, enabled = !busy && state.expiredCount > 0, modifier = Modifier.fillMaxWidth()) { Text("Истёкшие · ${state.expiredCount}") }
                                    if (state.orphanDeviceCount > 0) {
                                        Text("Забытые устройства", fontWeight = FontWeight.Bold)
                                        state.orphanDevices.take(12).forEach { device ->
                                            Text("• ${device.name.ifBlank { device.deviceId }} · ${device.ip.ifBlank { "без IP" }}", style = MaterialTheme.typography.bodySmall)
                                        }
                                        if (state.orphanDeviceCount > 12) Text("…и ещё ${state.orphanDeviceCount - 12}", style = MaterialTheme.typography.bodySmall)
                                    }
                                    OutlinedButton(onClick = onCleanupOrphans, enabled = !busy && state.orphanDeviceCount > 0, modifier = Modifier.fillMaxWidth()) { Text("Забытые устройства · ${state.orphanDeviceCount}") }
                                    OutlinedButton(onClick = onResetTraffic, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text("Сбросить трафик") }
                                    OutlinedButton(
                                        onClick = onRestart,
                                        enabled = !busy,
                                        modifier = Modifier.fillMaxWidth(),
                                        colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)
                                    ) { Text("Перезапустить WDTT") }
                                    Text("Перезапуск нужен только после обновления бинарника или системных параметров. Управление клиентами работает без него.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                            }
                    }
                }
                FlowRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp, Alignment.CenterHorizontally),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
	                    ServerToolsStep.entries.forEach { page ->
	                        SelectButton(
	                            text = when (page) {
	                                ServerToolsStep.Overview -> "Обзор"
	                                ServerToolsStep.Owner -> "Владелец"
	                                ServerToolsStep.Network -> "Настройки"
	                                ServerToolsStep.Maintenance -> "Сервис"
	                            },
	                            selected = step == page,
	                            onClick = { step = page }
	                        )
                    }
                }
            }
        },
	        confirmButton = {
	            when (step) {
	                ServerToolsStep.Network -> {
	                    Button(onClick = { onSaveNetwork(dns, limit ?: 0, ports, publicHost) }, enabled = !busy && networkValid) { Text("Сохранить") }
	                }
	                else -> Unit
	            }
	        }
	    )
}

@Composable
private fun InfoLine(label: String, value: String) {
    Column(verticalArrangement = Arrangement.spacedBy(1.dp)) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun TrafficPeriodBlock(traffic: ServerTrafficPeriod) {
    InfoLine("Сегодня", formatTrafficPair(traffic.today.down, traffic.today.up))
    InfoLine("7 дней", formatTrafficPair(traffic.week.down, traffic.week.up))
    InfoLine("30 дней", formatTrafficPair(traffic.month.down, traffic.month.up))
    InfoLine("Всего", formatTrafficPair(traffic.all.down, traffic.all.up))
}

@Composable
private fun StatusChip(status: String) {
    val context = LocalContext.current
    val label = when (status) {
        "active" -> "Активен"
        "expired" -> "Истёк"
        "deactivated" -> "Откл."
        else -> status.ifBlank { "?" }
    }
    Surface(
        onClick = { Toast.makeText(context, "Статус: $label", Toast.LENGTH_SHORT).show() },
        shape = CircleShape,
        color = when (status) {
            "active" -> MaterialTheme.colorScheme.primaryContainer
            "deactivated" -> MaterialTheme.colorScheme.tertiaryContainer
            "expired" -> MaterialTheme.colorScheme.errorContainer
            else -> MaterialTheme.colorScheme.surfaceVariant
        },
        contentColor = when (status) {
            "active" -> MaterialTheme.colorScheme.onPrimaryContainer
            "deactivated" -> MaterialTheme.colorScheme.onTertiaryContainer
            "expired" -> MaterialTheme.colorScheme.onErrorContainer
            else -> MaterialTheme.colorScheme.onSurfaceVariant
        },
        modifier = Modifier.size(30.dp)
    ) {
        Box(contentAlignment = Alignment.Center) {
            Icon(
                imageVector = when (status) {
                    "active" -> Icons.Default.CheckCircle
                    "deactivated" -> Icons.Default.PauseCircle
                    "expired" -> Icons.Default.Close
                    else -> Icons.Default.CheckCircle
                },
                contentDescription = "Статус: $label",
                modifier = Modifier.size(17.dp)
            )
        }
    }
}

@Composable
private fun ClientStatusBanner(status: String, busy: Boolean) {
    val isError = status.startsWith("Ошибка")
    val containerColor = when {
        isError -> MaterialTheme.colorScheme.errorContainer
        busy -> MaterialTheme.colorScheme.secondaryContainer
        else -> MaterialTheme.colorScheme.primaryContainer
    }
    val contentColor = when {
        isError -> MaterialTheme.colorScheme.onErrorContainer
        busy -> MaterialTheme.colorScheme.onSecondaryContainer
        else -> MaterialTheme.colorScheme.onPrimaryContainer
    }
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        color = containerColor,
        contentColor = contentColor,
        tonalElevation = 1.dp,
        shadowElevation = 0.dp
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (busy) {
                CircularProgressIndicator(
                    modifier = Modifier.size(16.dp),
                    color = contentColor,
                    strokeWidth = 2.dp
                )
            }
            Text(
                status,
                style = MaterialTheme.typography.bodySmall,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.weight(1f)
            )
        }
    }
}

@Composable
private fun ClientPanel(
    modifier: Modifier = Modifier,
    contentPadding: PaddingValues = PaddingValues(12.dp),
    content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit
) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(22.dp),
        color = MaterialTheme.colorScheme.surface.copy(alpha = 0.48f),
        contentColor = MaterialTheme.colorScheme.onSurface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.14f)),
        tonalElevation = 0.dp,
        shadowElevation = 0.dp
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(contentPadding),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            content = content
        )
    }
}

@Composable
private fun SwipeHint(
    selectedIndex: Int,
    count: Int,
    modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier,
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Icon(
            Icons.Default.ChevronLeft,
            contentDescription = null,
            modifier = Modifier.size(18.dp),
            tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = if (selectedIndex > 0) 0.9f else 0.28f)
        )
        Row(horizontalArrangement = Arrangement.spacedBy(5.dp), verticalAlignment = Alignment.CenterVertically) {
            repeat(count.coerceAtMost(7)) { dot ->
                val active = when {
                    count <= 7 -> dot == selectedIndex
                    selectedIndex <= 3 -> dot == selectedIndex
                    selectedIndex >= count - 4 -> dot == 7 - (count - selectedIndex)
                    else -> dot == 3
                }
                Box(
                    modifier = Modifier
                        .size(if (active) 8.dp else 6.dp)
                        .background(
                            color = if (active) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline.copy(alpha = 0.42f),
                            shape = CircleShape
                        )
                )
            }
        }
        Text(
            "${selectedIndex + 1}/$count",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Icon(
            Icons.Default.ChevronRight,
            contentDescription = null,
            modifier = Modifier.size(18.dp),
            tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = if (selectedIndex < count - 1) 0.9f else 0.28f)
        )
    }
}

@Composable
private fun DialogTitle(
    title: String,
    onDismiss: () -> Unit,
    enabled: Boolean = true
) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
        Text(
            title,
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f)
        )
        IconButton(onClick = onDismiss, enabled = enabled, modifier = Modifier.size(32.dp)) {
            Icon(Icons.Default.Close, contentDescription = "Закрыть", modifier = Modifier.size(20.dp))
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ClientImportMethodsDialog(
    onDismiss: () -> Unit,
    onCamera: () -> Unit,
    onGallery: () -> Unit,
    onFile: () -> Unit,
    onPaste: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { DialogTitle("Импорт клиента", onDismiss) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Выберите данные переноса клиента. Обычная ссылка подключения сюда не импортируется.")
                FlowRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(onClick = onCamera) {
                        Icon(Icons.Default.CameraAlt, null, Modifier.size(18.dp))
                        Text(" Камера")
                    }
                    OutlinedButton(onClick = onGallery) {
                        Icon(Icons.Default.Image, null, Modifier.size(18.dp))
                        Text(" Галерея")
                    }
                    OutlinedButton(onClick = onFile) {
                        Icon(Icons.Default.FileOpen, null, Modifier.size(18.dp))
                        Text(" Файл")
                    }
                    OutlinedButton(onClick = onPaste) { Text("Вставить") }
                }
                Text(
                    "Файл, изображение или код содержит пароль клиента. После чтения приложение покажет проверку перед записью на сервер.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }
        },
        confirmButton = {}
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ClientTransferExportDialog(
    client: ServerClientInfo,
    onDismiss: () -> Unit,
    onCopy: () -> Unit,
    onShare: () -> Unit,
    onQr: () -> Unit,
    onFile: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { DialogTitle("Экспорт клиента", onDismiss) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Клиент: ${client.displayName()}", fontWeight = FontWeight.Bold)
                Text("Переносятся пароль, название, VK-хеши, срок и состояние доступа.")
                Text(
                    "Не переносятся устройство, WireGuard-ключи, адрес, порты, трафик и история. На новом сервере используются его настройки, а устройство привяжется при первом подключении.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                FlowRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(onClick = onQr) {
                        Icon(Icons.Default.QrCode2, null, Modifier.size(18.dp))
                        Text(" QR")
                    }
                    OutlinedButton(onClick = onFile) {
                        Icon(Icons.AutoMirrored.Filled.InsertDriveFile, null, Modifier.size(18.dp))
                        Text(" Файл")
                    }
                    OutlinedButton(onClick = onShare) {
                        Icon(Icons.Default.Share, null, Modifier.size(18.dp))
                        Text(" Поделиться")
                    }
                    OutlinedButton(onClick = onCopy) { Text("Копировать") }
                }
                Text(
                    "Передача содержит рабочий пароль клиента. Отправляйте её только себе или доверенному администратору.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }
        },
        confirmButton = {}
    )
}

@Composable
private fun ClientImportConfirmDialog(
    payload: ClientTransferPayload,
    targetHost: String,
    targetPorts: String,
    passwordConflict: Boolean,
    mainPasswordConflict: Boolean,
    limitReached: Boolean,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit
) {
    val expired = payload.expiresAt > 0 && payload.expiresAt <= System.currentTimeMillis() / 1000L
    val errors = buildList {
        if (passwordConflict) add("На новом сервере уже есть клиент с таким паролем.")
        if (mainPasswordConflict) add("Пароль клиента совпадает с главным паролем нового сервера.")
        if (expired) add("Срок этого клиента уже истёк.")
        if (limitReached) add("На новом сервере достигнут лимит клиентов.")
        if (targetHost.isBlank()) add("Не определён адрес нового сервера.")
        if (!targetPorts.isPortsSpec()) add("На новом сервере указаны некорректные порты.")
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { DialogTitle("Проверка импорта", onDismiss) },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                InfoLine("Клиент", payload.label.ifBlank { "Без имени" })
                InfoLine("Пароль", "${payload.password.take(3)}••••${payload.password.takeLast(3)}")
                InfoLine("Срок", formatExpiry(payload.expiresAt))
                InfoLine("Состояние", if (payload.deactivated) "Отключён" else "Активен")
                InfoLine("VK-хеши", if (payload.vkHash.isBlank()) "не заданы" else "заданы")
                HorizontalDivider()
                InfoLine("Новый сервер", targetHost.ifBlank { "не определён" })
                InfoLine("Порты нового сервера", targetPorts.ifBlank { "не заданы" })
                Text(
                    "Клиент будет скопирован без устройства, ключей, статистики и истории. Старый сервер не изменится. Импорт применяется наживую без перезапуска.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                errors.forEach { Text("• $it", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            }
        },
        confirmButton = { Button(onClick = onConfirm, enabled = errors.isEmpty()) { Text("Импортировать") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена") } }
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ChangeClientPasswordDialog(
    client: ServerClientInfo,
    existingPasswords: Set<String>,
    mainPassword: String,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit
) {
    var automatic by rememberSaveable(client.password) { mutableStateOf(true) }
    var generated by remember(client.password) { mutableStateOf(ClientPasswordRules.generate()) }
    var manual by rememberSaveable(client.password) { mutableStateOf("") }
    val value = if (automatic) generated else manual.trim()
    val error = when {
        ClientPasswordRules.validate(value) != null -> ClientPasswordRules.validate(value)
        value == client.password -> "Новый пароль совпадает с текущим."
        value == mainPassword -> "Пароль клиента не должен совпадать с главным паролем."
        value in existingPasswords -> "Клиент с таким паролем уже существует."
        else -> null
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { DialogTitle("Сменить пароль", onDismiss) },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text("Клиент: ${client.displayName()}", fontWeight = FontWeight.Bold)
                InfoLine("Текущий пароль", client.maskedPassword().removePrefix("Пароль: "))
                val deviceLabel = listOf(
                    client.deviceName,
                    client.device?.name.orEmpty(),
                    client.device?.model.orEmpty(),
                    client.deviceId
                ).firstOrNull { it.isNotBlank() }
                InfoLine("Устройство", deviceLabel ?: "не привязано")
                FlowRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    SelectButton("Автоматически", automatic) { automatic = true }
                    SelectButton("Вручную", !automatic) { automatic = false }
                }
                if (automatic) {
                    OutlinedTextField(value = generated, onValueChange = {}, readOnly = true, label = { Text("Новый пароль") }, modifier = Modifier.fillMaxWidth())
                    error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                    OutlinedButton(onClick = { generated = ClientPasswordRules.generate() }) { Text("Другой пароль") }
                } else {
                    OutlinedTextField(
                        value = manual,
                        onValueChange = { manual = it.trim().take(32) },
                        label = { Text("Новый пароль, 16 символов") },
                        supportingText = { error?.let { Text(it) } },
                        isError = error != null,
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
                Text(
                    "Старые ссылки перестанут работать, активное соединение этого клиента завершится. Название, срок, VK-хеши и привязка устройства сохранятся; остальные клиенты не затрагиваются.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
                Text("Изменение применяется наживую без перезапуска сервера.", style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = { Button(onClick = { onConfirm(value) }, enabled = error == null) { Text("Изменить") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена") } }
    )
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
private fun CreateClientWizardDialog(
    defaultPorts: String,
    existingPasswords: Set<String>,
    mainPassword: String,
    busy: Boolean,
    onDismiss: () -> Unit,
    onCreate: (ServerClientCreateRequest) -> Unit
) {
    var step by rememberSaveable { mutableStateOf(ClientWizardStep.Days) }
    var days by rememberSaveable { mutableStateOf(30) }
    var label by rememberSaveable { mutableStateOf("") }
    var vkHash by rememberSaveable { mutableStateOf("") }
    var useDefaultPorts by rememberSaveable { mutableStateOf(true) }
    var customPorts by rememberSaveable { mutableStateOf(defaultPorts) }
    var useAutoPassword by rememberSaveable { mutableStateOf(true) }
    var customPassword by rememberSaveable { mutableStateOf("") }
    val effectivePorts = if (useDefaultPorts) defaultPorts else customPorts
    val portsValid = effectivePorts.isPortsSpec()
    val passwordError = if (useAutoPassword || customPassword.isEmpty()) null else when {
        ClientPasswordRules.validate(customPassword) != null -> ClientPasswordRules.validate(customPassword)
        customPassword == mainPassword -> "Пароль клиента не должен совпадать с главным паролем."
        customPassword in existingPasswords -> "Клиент с таким паролем уже существует."
        else -> null
    }
    val passwordValid = useAutoPassword || (customPassword.isNotEmpty() && passwordError == null)

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { DialogTitle("Новый клиент", onDismiss, enabled = !busy) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    "Шаг ${step.ordinal + 1} из ${ClientWizardStep.entries.size}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(18.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f))
                ) {
                    Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        when (step) {
                                ClientWizardStep.Days -> {
                                    Text("Срок доступа", fontWeight = FontWeight.Bold)
                                    FlowRow(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
                                        verticalArrangement = Arrangement.spacedBy(8.dp)
                                    ) {
                                        listOf(7, 30, 90, 365).forEach { value ->
                                            SelectButton(
                                                text = "${value}д",
                                                selected = days == value,
                                                onClick = { days = value }
                                            )
                                        }
                                        SelectButton(text = "∞", selected = days == 0, onClick = { days = 0 })
                                    }
                                    OutlinedTextField(
                                        value = if (days == 0) "" else days.toString(),
                                        onValueChange = { input ->
                                            val parsed = input.filter { it.isDigit() }.take(3).toIntOrNull()
                                            if (parsed != null) days = parsed.coerceIn(1, 365)
                                        },
                                        label = { Text("Свои дни") },
                                        singleLine = true,
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                }
                                ClientWizardStep.Label -> {
                                    Text("Название", fontWeight = FontWeight.Bold)
                                    Text("Короткая метка для списка: друг, дом, ноутбук. Можно оставить пустой.", style = MaterialTheme.typography.bodySmall)
                                    OutlinedTextField(
                                        value = label,
                                        onValueChange = { label = it.take(40) },
                                        label = { Text("Название") },
                                        singleLine = true,
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                }
                                ClientWizardStep.Hash -> {
                                    Text("VK-хеш", fontWeight = FontWeight.Bold)
                                    Text("Нужен для быстрой ссылки, QR и файла. Можно вставить сам хеш или ссылку приглашения.", style = MaterialTheme.typography.bodySmall)
                                    OutlinedTextField(
                                        value = vkHash,
                                        onValueChange = { vkHash = it },
                                        label = { Text("Хеш или ссылка") },
                                        minLines = 2,
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                }
                                ClientWizardStep.Ports -> {
                                    Text("Порты ссылки", fontWeight = FontWeight.Bold)
                                    FlowRow(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
                                        verticalArrangement = Arrangement.spacedBy(8.dp)
                                    ) {
                                        SelectButton("Стандарт", useDefaultPorts) { useDefaultPorts = true }
                                        SelectButton("Свои", !useDefaultPorts) { useDefaultPorts = false }
                                    }
                                    OutlinedTextField(
                                        value = customPorts,
                                        onValueChange = { customPorts = it.filter { ch -> ch.isDigit() || ch == ',' }.take(32) },
                                        label = { Text("DTLS,WG,TUN") },
                                        singleLine = true,
                                        enabled = !useDefaultPorts,
                                        isError = !portsValid,
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                    if (!portsValid) Text("Формат: 56000,56001,9000", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                                }
                                ClientWizardStep.Password -> {
                                    Text("Пароль клиента", fontWeight = FontWeight.Bold)
                                    Text(
                                        "Автоматический пароль безопаснее. Ручной режим нужен, например, для переноса существующего клиента с другого сервера.",
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                    FlowRow(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
                                        verticalArrangement = Arrangement.spacedBy(8.dp)
                                    ) {
                                        SelectButton("Автоматически", useAutoPassword) { useAutoPassword = true }
                                        SelectButton("Вручную", !useAutoPassword) { useAutoPassword = false }
                                    }
                                    if (!useAutoPassword) {
                                        OutlinedTextField(
                                            value = customPassword,
                                            onValueChange = { customPassword = it.trim().take(32) },
                                            label = { Text("16 символов") },
                                            supportingText = {
                                                Text(passwordError ?: "Допустимы безопасные латинские буквы и цифры.")
                                            },
                                            isError = customPassword.isNotEmpty() && passwordError != null,
                                            singleLine = true,
                                            modifier = Modifier.fillMaxWidth()
                                        )
                                        OutlinedButton(onClick = { customPassword = ClientPasswordRules.generate() }) {
                                            Text("Сгенерировать")
                                        }
                                    }
                                }
                                ClientWizardStep.Confirm -> {
                                    Text("Проверка", fontWeight = FontWeight.Bold)
                                    Text("Срок: ${if (days == 0) "бессрочно" else "$days дн."}")
                                    Text("Название: ${label.ifBlank { "без имени" }}")
                                    Text("VK-хеш: ${if (vkHash.isBlank()) "не задан" else "задан"}")
                                    Text("Порты: $effectivePorts")
                                    Text("Пароль: ${if (useAutoPassword) "будет создан автоматически" else customPassword}")
                                    Text(
                                        "Новый доступ начнёт работать сразу, текущие подключения не прервутся.",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                    }
                }
            }
        },
        confirmButton = {
            Button(
                enabled = !busy &&
                    (step != ClientWizardStep.Ports || portsValid) &&
                    (step != ClientWizardStep.Password || passwordValid),
                onClick = {
                    if (step == ClientWizardStep.Confirm) {
                        onCreate(
                            ServerClientCreateRequest(
                                days = days.coerceIn(0, 365),
                                label = label,
                                vkHash = vkHash,
                                ports = effectivePorts,
                                password = customPassword.takeUnless { useAutoPassword }
                            )
                        )
                    } else {
                        step = ClientWizardStep.entries[step.ordinal + 1]
                    }
                }
            ) {
                Text(if (step == ClientWizardStep.Confirm) "Создать" else "Далее")
            }
        },
        dismissButton = {
            Row {
                if (step != ClientWizardStep.Days) {
                    TextButton(onClick = { step = ClientWizardStep.entries[step.ordinal - 1] }, enabled = !busy) {
                        Text("Назад")
                    }
                }
            }
        }
    )
}

@Composable
private fun SelectButton(
    text: String,
    selected: Boolean,
    enabled: Boolean = true,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    if (selected) {
        Button(onClick = onClick, enabled = enabled, modifier = modifier, contentPadding = PaddingValues(horizontal = 14.dp)) { Text(text) }
    } else {
        OutlinedButton(onClick = onClick, enabled = enabled, modifier = modifier, contentPadding = PaddingValues(horizontal = 14.dp)) { Text(text) }
    }
}

@Composable
private fun ConfirmClientActionDialog(
    action: PendingClientAction,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { DialogTitle(action.confirmLabel, onDismiss) },
        text = { Text(action.message) },
        confirmButton = {
            Button(
                onClick = onConfirm,
                colors = if (action.danger) {
                    ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error, contentColor = MaterialTheme.colorScheme.onError)
                } else {
                    ButtonDefaults.buttonColors()
                }
            ) { Text(action.confirmLabel) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Нет") } }
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ExtendClientDialog(
    client: ServerClientInfo,
    onDismiss: () -> Unit,
    onSelect: (Int) -> Unit
) {
    var customDays by rememberSaveable { mutableStateOf("") }
    val parsedDays = customDays.toIntOrNull()?.takeIf { it in 1..365 }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { DialogTitle("Продлить", onDismiss) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("Новый срок для «${client.displayName()}» от текущего момента.")
                FlowRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    listOf(7, 30, 90, 365).forEach { days ->
                        OutlinedButton(onClick = { onSelect(days) }) { Text("${days}д") }
                    }
                    OutlinedButton(onClick = { onSelect(0) }) { Text("∞") }
                }
                OutlinedTextField(
                    value = customDays,
                    onValueChange = { customDays = it.filter(Char::isDigit).take(3) },
                    label = { Text("Свой срок, 1–365 дней") },
                    singleLine = true,
                    isError = customDays.isNotEmpty() && parsedDays == null,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = { Button(onClick = { parsedDays?.let(onSelect) }, enabled = parsedDays != null) { Text("Применить") } }
    )
}

@Composable
private fun ClientQrDialog(
    title: String,
    bitmap: Bitmap,
    onDismiss: () -> Unit,
    onShare: () -> Unit,
    onSave: () -> Unit
) {
    val context = LocalContext.current
    val permissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) onSave()
        else Toast.makeText(context, "Без разрешения Android 9 не может сохранить QR-код.", Toast.LENGTH_LONG).show()
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(title, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                    IconButton(onClick = onDismiss, modifier = Modifier.size(32.dp)) {
                        Icon(Icons.Default.Close, contentDescription = "Закрыть", modifier = Modifier.size(20.dp))
                    }
                }
                Box(modifier = Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                    Image(bitmap = bitmap.asImageBitmap(), contentDescription = "QR-код WDTT Plus", modifier = Modifier.fillMaxWidth())
                }
                Text("QR содержит пароль и VK-хеш. Не публикуйте изображение.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        modifier = Modifier.weight(1f).heightIn(min = 48.dp),
                        contentPadding = PaddingValues(horizontal = 8.dp),
                        onClick = {
                            if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.P &&
                                ContextCompat.checkSelfPermission(context, Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED
                            ) {
                                permissionLauncher.launch(Manifest.permission.WRITE_EXTERNAL_STORAGE)
                            } else {
                                onSave()
                            }
                        }
                    ) {
                        Icon(Icons.Default.SaveAlt, null, Modifier.size(18.dp))
                        Text(" Сохранить", maxLines = 1)
                    }
                    Button(
                        onClick = onShare,
                        modifier = Modifier.weight(1f).heightIn(min = 48.dp),
                        contentPadding = PaddingValues(horizontal = 8.dp)
                    ) {
                        Icon(Icons.Default.Share, null, Modifier.size(18.dp))
                        Text(" Поделиться", maxLines = 1)
                    }
                }
            }
        },
        confirmButton = {}
    )
}

private fun ServerClientInfo.maskedPassword(): String =
    if (password.length <= 8) "Пароль: ••••" else "Пароль: ${password.take(3)}••••${password.takeLast(3)}"

private fun ServerClientInfo.displayName(): String =
    label.ifBlank { "Без имени" }

private fun ServerClientInfo.safeFileName(): String =
    listOf(
        label,
        deviceName,
        device?.name.orEmpty(),
        listOf(device?.manufacturer.orEmpty(), device?.model.orEmpty()).filter { it.isNotBlank() }.joinToString(" ")
    ).firstOrNull { it.isNotBlank() }.orEmpty().toSafeFilePart("client")

private fun String.safeQrFileName(): String =
    toSafeFilePart("qr")

private fun String.toSafeFilePart(fallback: String): String =
    replace(Regex("[^\\p{L}\\p{N}._-]+"), "-")
        .replace(Regex("-+"), "-")
        .trim('_', '.', '-')
        .take(48)
        .trim('_', '.', '-')
        .ifBlank { fallback }

private fun formatExtensionPeriod(days: Int): String =
    if (days <= 0) {
        "бессрочно"
    } else {
        "на $days ${days.pluralRu("день", "дня", "дней")}"
    }

private fun Int.pluralRu(one: String, few: String, many: String): String {
    val mod100 = this % 100
    val mod10 = this % 10
    return when {
        mod100 in 11..14 -> many
        mod10 == 1 -> one
        mod10 in 2..4 -> few
        else -> many
    }
}

private data class ClientSearchResult(
    val client: ServerClientInfo,
    val score: Int,
    val index: Int
)

private fun List<ServerClientInfo>.filterByQuery(query: String): List<ServerClientInfo> {
    val normalized = query.searchNormalize()
    val compact = query.searchCompact()
    if (normalized.isBlank()) return this
    return mapIndexedNotNull { index, client ->
        client.searchScore(normalized, compact)?.let { score ->
            ClientSearchResult(client = client, score = score, index = index)
        }
    }.sortedWith(
        compareByDescending<ClientSearchResult> { it.score }
            .thenBy { it.index }
    ).map { it.client }
}

private fun List<ServerClientInfo>.filterByClientFilters(
    statusFilter: ClientStatusFilter,
    bindingFilter: ClientBindingFilter,
    expiryFilter: ClientExpiryFilter,
    vkHashFilter: ClientVkHashFilter
): List<ServerClientInfo> {
    val now = System.currentTimeMillis() / 1000L
    return filter { client ->
        client.matchesStatusFilter(statusFilter) &&
            client.matchesBindingFilter(bindingFilter) &&
            client.matchesExpiryFilter(expiryFilter, now) &&
            client.matchesVkHashFilter(vkHashFilter)
    }
}

private fun activeClientFilterCount(
    statusFilter: ClientStatusFilter,
    bindingFilter: ClientBindingFilter,
    expiryFilter: ClientExpiryFilter,
    vkHashFilter: ClientVkHashFilter
): Int =
    listOf(
        statusFilter != ClientStatusFilter.All,
        bindingFilter != ClientBindingFilter.All,
        expiryFilter != ClientExpiryFilter.All,
        vkHashFilter != ClientVkHashFilter.All
    ).count { it }

private fun ServerClientInfo.matchesStatusFilter(filter: ClientStatusFilter): Boolean =
    when (filter) {
        ClientStatusFilter.All -> true
        ClientStatusFilter.Active -> isActive
        ClientStatusFilter.Disabled -> !isActive
    }

private fun ServerClientInfo.matchesBindingFilter(filter: ClientBindingFilter): Boolean =
    when (filter) {
        ClientBindingFilter.All -> true
        ClientBindingFilter.Bound -> isBound
        ClientBindingFilter.Unbound -> !isBound
    }

private fun ServerClientInfo.matchesExpiryFilter(filter: ClientExpiryFilter, now: Long): Boolean =
    when (filter) {
        ClientExpiryFilter.All -> true
        ClientExpiryFilter.Valid -> expiresAt <= 0 || expiresAt >= now
        ClientExpiryFilter.Expired -> expiresAt > 0 && expiresAt < now
        ClientExpiryFilter.Unlimited -> expiresAt <= 0
    }

private fun ServerClientInfo.matchesVkHashFilter(filter: ClientVkHashFilter): Boolean =
    when (filter) {
        ClientVkHashFilter.All -> true
        ClientVkHashFilter.Present -> vkHash.isNotBlank()
        ClientVkHashFilter.Missing -> vkHash.isBlank()
    }

private fun ServerClientInfo.searchScore(query: String, compactQuery: String): Int? {
    val device = device
    val fields = buildList {
        addSearchField(label, weight = 1_000)
        addSearchField(title, weight = 980)
        addSearchField(displayName(), weight = 940)
        addSearchField(deviceName, weight = 820)
        addSearchField(device?.name.orEmpty(), weight = 800)
        addSearchField(device?.model.orEmpty(), weight = 760)
        addSearchField(device?.brand.orEmpty(), weight = 740)
        addSearchField(device?.manufacturer.orEmpty(), weight = 720)
        addSearchField(password, weight = 620, minQueryLength = 2)
        addSearchField(vkHash, weight = 560, minQueryLength = 3)
        addSearchField(ports, weight = 520, minQueryLength = 2)
        addSearchField(device?.appVersion.orEmpty(), weight = 420, minQueryLength = 2)
        addSearchField(device?.androidVersion.orEmpty(), weight = 380, minQueryLength = 2)
        addSearchField(device?.locale.orEmpty(), weight = 340, minQueryLength = 2)
        addSearchField(device?.country.orEmpty(), weight = 320, minQueryLength = 2)
        addSearchField(deviceId, weight = 90, minQueryLength = 4)
        addSearchField(deviceIp, weight = 80, minQueryLength = 4)
        addSearchField(device?.timeZone.orEmpty(), weight = 70, minQueryLength = 4)
        addSearchField(device?.remoteIp.orEmpty(), weight = 60, minQueryLength = 4)
    }
    return fields.maxOfOrNull { it.matchScore(query, compactQuery) ?: 0 }?.takeIf { it > 0 }
}

private data class ClientSearchField(
    val value: String,
    val weight: Int,
    val minQueryLength: Int
)

private fun MutableList<ClientSearchField>.addSearchField(
    value: String,
    weight: Int,
    minQueryLength: Int = 1
) {
    if (value.isNotBlank()) add(ClientSearchField(value, weight, minQueryLength))
}

private fun ClientSearchField.matchScore(query: String, compactQuery: String): Int? {
    if (query.length < minQueryLength) return null
    val normalized = value.searchNormalize()
    if (normalized.isBlank()) return null
    val compact = value.searchCompact()
    return when {
        normalized == query -> weight + 500
        normalized.startsWith(query) -> weight + 420
        normalized.wordStartsWith(query) -> weight + 360
        normalized.contains(query) -> weight + 220
        compactQuery.isNotBlank() && compact == compactQuery -> weight + 180
        compactQuery.isNotBlank() && compact.startsWith(compactQuery) -> weight + 130
        compactQuery.isNotBlank() && compact.contains(compactQuery) -> weight + 80
        else -> null
    }
}

private fun String.wordStartsWith(query: String): Boolean =
    split(Regex("[\\s_.,;:()\\[\\]{}<>/\\\\|+\\-]+")).any { it.startsWith(query) }

private fun String.searchNormalize(): String =
    trim().lowercase(Locale.getDefault()).replace('ё', 'е')

private fun String.searchCompact(): String =
    searchNormalize().filter { it.isLetterOrDigit() }

private fun formatExpiry(ts: Long): String {
    if (ts <= 0) return "бессрочно"
    val now = System.currentTimeMillis() / 1000L
    val date = SimpleDateFormat("dd.MM.yyyy", Locale.getDefault()).format(Date(ts * 1000L))
    if (ts < now) return "истёк $date"
    val days = ((ts - now) / 86_400L).coerceAtLeast(0)
    return "$date · ${days}д"
}

private fun formatBytes(value: Long): String {
    val mb = value / 1024.0 / 1024.0
    return if (mb < 1024) String.format(Locale.US, "%.1f МБ", mb) else String.format(Locale.US, "%.2f ГБ", mb / 1024.0)
}

private fun formatTrafficPair(down: Long, up: Long): String =
    "↓ ${formatBytes(down)} · ↑ ${formatBytes(up)}"

private fun formatDateTime(ts: Long): String {
    if (ts <= 0) return "неизвестно"
    return SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(Date(ts * 1000L))
}

private fun formatRefreshDateTime(timestampMillis: Long): String {
    if (timestampMillis <= 0L) return "неизвестно"
    return SimpleDateFormat("dd.MM.yyyy HH:mm", Locale("ru", "RU")).format(Date(timestampMillis))
}

private fun secretPresenceLabel(value: String): String {
    val count = value.split(',', ' ', '\n', '\t')
        .map { it.trim() }
        .count { it.isNotBlank() }
    return if (count == 0) "не заданы" else "заданы ($count)"
}

private fun String.isPortsSpec(): Boolean {
    val parts = split(",").map { it.trim().toIntOrNull() }
    return parts.size == 3 && parts.all { it != null && it in 1..65535 }
}

private fun shareText(context: Context, text: String, title: String = "Передать подключение WDTT Plus") {
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, text)
    }
    context.startActivity(Intent.createChooser(intent, title))
}

private fun copyText(context: Context, label: String, text: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    clipboard.setPrimaryClip(ClipData.newPlainText(label, text))
    Toast.makeText(context, "Скопировано.", Toast.LENGTH_SHORT).show()
}

private fun shareUri(context: Context, uri: Uri, mimeType: String, title: String) {
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = mimeType
        putExtra(Intent.EXTRA_STREAM, uri)
        clipData = ClipData.newUri(context.contentResolver, title, uri)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    context.startActivity(Intent.createChooser(intent, title))
}
