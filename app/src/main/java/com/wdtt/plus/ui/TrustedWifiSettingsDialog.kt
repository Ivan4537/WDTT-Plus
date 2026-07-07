package com.wdtt.plus.ui

import android.Manifest
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.LocationOn
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.core.net.toUri
import com.wdtt.plus.ConnectedWifiState
import com.wdtt.plus.SettingsStore
import com.wdtt.plus.TrustedWifiAccessProblem
import com.wdtt.plus.TrustedWifiManager
import com.wdtt.plus.TunnelManager
import com.wdtt.plus.TunnelService
import com.wdtt.plus.readConnectedWifiState
import com.wdtt.plus.isWdttAlwaysOnVpn
import com.wdtt.plus.sanitizeTrustedWifiSsid
import com.wdtt.plus.trustedWifiAccessProblem
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private enum class TrustedWifiUiAction {
    Enable,
    AddCurrent
}

private const val BACKGROUND_LOCATION_PERMISSION = "android.permission.ACCESS_BACKGROUND_LOCATION"

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TrustedWifiSettingsDialog(
    settingsStore: SettingsStore,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val configuration = LocalConfiguration.current
    val enabledState by remember(settingsStore) {
        settingsStore.trustedWifiEnabled.map { value: Boolean -> value as Boolean? }
    }.collectAsStateWithLifecycle(initialValue = null)
    val trustedSsidsState by remember(settingsStore) {
        settingsStore.trustedWifiSsids.map { value: List<String> -> value as List<String>? }
    }.collectAsStateWithLifecycle(initialValue = null)
    val enabled = enabledState == true
    val trustedSsids = trustedSsidsState.orEmpty()
    val settingsReady = enabledState != null && trustedSsidsState != null
    val runtimeState by TrustedWifiManager.state.collectAsStateWithLifecycle()
    var currentWifi by remember { mutableStateOf(ConnectedWifiState(connected = false)) }
    var pendingAction by remember { mutableStateOf<TrustedWifiUiAction?>(null) }
    var showForegroundExplanation by rememberSaveable { mutableStateOf(false) }
    var showBackgroundExplanation by rememberSaveable { mutableStateOf(false) }
    var showLocationExplanation by rememberSaveable { mutableStateOf(false) }
    var showManualInput by rememberSaveable { mutableStateOf(false) }
    var manualInput by rememberSaveable { mutableStateOf("") }

    fun recheckService() {
        if (!TunnelManager.running.value && !TrustedWifiManager.state.value.waiting) return
        runCatching {
            context.startService(Intent(context, TunnelService::class.java).apply {
                action = "TRUSTED_WIFI_RECHECK"
            })
        }
    }

    val performAction: (TrustedWifiUiAction) -> Unit = { action ->
        scope.launch {
            when (action) {
                TrustedWifiUiAction.Enable -> settingsStore.saveTrustedWifiEnabled(true)
                TrustedWifiUiAction.AddCurrent -> {
                    val wifi = withContext(Dispatchers.Default) { readConnectedWifiState(context) }
                    currentWifi = wifi
                    if (wifi.ssidAvailable) {
                        val added = settingsStore.addTrustedWifiSsid(wifi.ssid)
                        val message = if (added) {
                            "Сеть «${wifi.ssid}» добавлена"
                        } else {
                            "Сеть «${wifi.ssid}» уже есть в списке"
                        }
                        Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(context, "Не удалось определить имя текущей Wi-Fi сети", Toast.LENGTH_LONG).show()
                    }
                }
            }
            pendingAction = null
            recheckService()
        }
    }

    fun continuePendingAction() {
        val action = pendingAction ?: return
        when (trustedWifiAccessProblem(context)) {
            TrustedWifiAccessProblem.ForegroundPermission -> showForegroundExplanation = true
            TrustedWifiAccessProblem.BackgroundPermission -> showBackgroundExplanation = true
            TrustedWifiAccessProblem.LocationDisabled -> showLocationExplanation = true
            null -> performAction(action)
        }
    }

    val foregroundPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { grants ->
        if (grants[Manifest.permission.ACCESS_FINE_LOCATION] == true) continuePendingAction()
        else {
            pendingAction = null
            Toast.makeText(context, "Без доступа к имени Wi-Fi функция не включена", Toast.LENGTH_LONG).show()
        }
    }
    val backgroundPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) continuePendingAction()
        else {
            pendingAction = null
            Toast.makeText(context, "Для работы при закрытом приложении нужен постоянный доступ", Toast.LENGTH_LONG).show()
        }
    }
    val appSettingsLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) {
        continuePendingAction()
    }
    val locationSettingsLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) {
        continuePendingAction()
    }

    fun requestAction(action: TrustedWifiUiAction) {
        pendingAction = action
        continuePendingAction()
    }

    LaunchedEffect(Unit) {
        currentWifi = withContext(Dispatchers.Default) { readConnectedWifiState(context) }
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) {
            Surface(
                modifier = Modifier
                    .fillMaxWidth(0.92f)
                    .fillMaxHeight(0.9f)
                    .heightIn(max = (configuration.screenHeightDp.dp - 32.dp).coerceAtLeast(360.dp)),
                shape = RoundedCornerShape(30.dp),
                color = MaterialTheme.colorScheme.surface,
                tonalElevation = 8.dp,
                shadowElevation = 8.dp
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState())
                        .padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(14.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Surface(
                            shape = RoundedCornerShape(16.dp),
                            color = MaterialTheme.colorScheme.primaryContainer
                        ) {
                            Box(modifier = Modifier.size(48.dp), contentAlignment = Alignment.Center) {
                                Icon(Icons.Default.Wifi, contentDescription = null, modifier = Modifier.size(25.dp))
                            }
                        }
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                "Доверенные сети Wi-Fi",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold
                            )
                            Text(
                                "Общая настройка для всех VPN-профилей",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        IconButton(onClick = onDismiss) {
                            Icon(Icons.Default.Close, contentDescription = "Закрыть")
                        }
                    }

                    if (!settingsReady) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(180.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            CircularProgressIndicator()
                        }
                    } else {
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(18.dp),
                            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f)
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth().padding(14.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                    Text("Автоматическое ожидание", fontWeight = FontWeight.SemiBold)
                                    Text(
                                        "VPN выключается в выбранных сетях и восстанавливается после выхода из них.",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                                Switch(
                                    checked = enabled,
                                    onCheckedChange = { checked ->
                                        if (checked) requestAction(TrustedWifiUiAction.Enable)
                                        else scope.launch {
                                            settingsStore.saveTrustedWifiEnabled(false)
                                            recheckService()
                                        }
                                    }
                                )
                            }
                        }

                        val currentStatus = when {
                            runtimeState.waiting -> "Ожидание в сети «${runtimeState.ssid.ifBlank { "Wi-Fi" }}»"
                            currentWifi.ssidAvailable && currentWifi.ssid in trustedSsids -> "Сейчас подключена доверенная сеть «${currentWifi.ssid}»"
                            currentWifi.ssidAvailable -> "Текущая сеть: ${currentWifi.ssid}"
                            !currentWifi.connected -> "Wi-Fi сейчас не подключён"
                            else -> "Имя текущей Wi-Fi сети недоступно"
                        }
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(16.dp),
                            color = if (runtimeState.waiting) {
                                MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.7f)
                            } else {
                                MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f)
                            },
                            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.2f))
                        ) {
                            Text(
                                currentStatus,
                                modifier = Modifier.padding(14.dp),
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.Medium
                            )
                        }

                        Text(
                            "Сети без VPN",
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.Bold
                        )
                        if (trustedSsids.isEmpty()) {
                            Text(
                                "Список пуст. Добавьте текущую сеть или введите её точное имя вручную.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        } else {
                            trustedSsids.forEach { ssid ->
                                Surface(
                                    modifier = Modifier.fillMaxWidth(),
                                    shape = RoundedCornerShape(14.dp),
                                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.42f)
                                ) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth().padding(start = 14.dp, end = 4.dp, top = 5.dp, bottom = 5.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Icon(Icons.Default.Wifi, contentDescription = null, modifier = Modifier.size(19.dp))
                                        Text(ssid, modifier = Modifier.weight(1f).padding(horizontal = 10.dp))
                                        IconButton(onClick = {
                                            scope.launch {
                                                settingsStore.removeTrustedWifiSsid(ssid)
                                                recheckService()
                                            }
                                        }) {
                                            Icon(Icons.Default.DeleteOutline, contentDescription = "Удалить сеть")
                                        }
                                    }
                                }
                            }
                        }

                        Button(
                            onClick = { requestAction(TrustedWifiUiAction.AddCurrent) },
                            modifier = Modifier.fillMaxWidth().heightIn(min = 50.dp),
                            shape = RoundedCornerShape(16.dp)
                        ) {
                            Icon(Icons.Default.Add, contentDescription = null)
                            Text(" Добавить текущую сеть")
                        }
                        OutlinedButton(
                            onClick = { showManualInput = true },
                            modifier = Modifier.fillMaxWidth().heightIn(min = 50.dp),
                            shape = RoundedCornerShape(16.dp)
                        ) {
                            Text("Добавить вручную")
                        }

                        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.55f))
                        Text(
                            "Во время ожидания интернет работает напрямую, а WDTT Plus сохраняет тихое уведомление, чтобы заметить выход из Wi-Fi. Ручное отключение отменяет автоматическое восстановление.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            lineHeight = MaterialTheme.typography.bodyMedium.lineHeight
                        )
                        Text(
                            "Android считает имя Wi-Fi данными о местоположении. WDTT Plus не получает координаты и использует разрешение только для точного имени подключённой сети.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        if (isWdttAlwaysOnVpn(context)) {
                            Text(
                                "Системный режим «Всегда включённый VPN» сейчас активен. Android не позволит использовать прямой интернет в доверенной сети, пока этот режим не будет отключён.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                    }
                }
            }
        }
    }

    if (showManualInput) {
        AlertDialog(
            onDismissRequest = { showManualInput = false },
            title = {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("Добавить сеть")
                    IconButton(onClick = { showManualInput = false }) {
                        Icon(Icons.Default.Close, contentDescription = "Закрыть")
                    }
                }
            },
            text = {
                OutlinedTextField(
                    value = manualInput,
                    onValueChange = { manualInput = sanitizeTrustedWifiSsid(it) },
                    label = { Text("Точное имя сети (SSID)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            },
            confirmButton = {
                Button(
                    enabled = sanitizeTrustedWifiSsid(manualInput).isNotBlank(),
                    onClick = {
                        scope.launch {
                            val clean = sanitizeTrustedWifiSsid(manualInput)
                            val added = settingsStore.addTrustedWifiSsid(clean)
                            if (added) {
                                Toast.makeText(context, "Сеть «$clean» добавлена", Toast.LENGTH_SHORT).show()
                                manualInput = ""
                                showManualInput = false
                                recheckService()
                            } else {
                                Toast.makeText(context, "Сеть «$clean» уже есть в списке", Toast.LENGTH_SHORT).show()
                            }
                        }
                    }
                ) { Text("Добавить") }
            }
        )
    }

    if (showForegroundExplanation) {
        PermissionExplanationDialog(
            title = "Доступ к имени Wi-Fi",
            text = "Android относит имя подключённой Wi-Fi сети к данным о местоположении. WDTT Plus не читает координаты: доступ нужен только для сравнения SSID со списком доверенных сетей.",
            button = "Продолжить",
            onDismiss = {
                showForegroundExplanation = false
                pendingAction = null
            },
            onConfirm = {
                showForegroundExplanation = false
                foregroundPermissionLauncher.launch(
                    arrayOf(
                        Manifest.permission.ACCESS_COARSE_LOCATION,
                        Manifest.permission.ACCESS_FINE_LOCATION
                    )
                )
            }
        )
    }
    if (showBackgroundExplanation) {
        PermissionExplanationDialog(
            title = "Работа при закрытом приложении",
            text = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                "Чтобы VPN восстановился после выхода из доверенной сети при выключенном экране, разрешите доступ к местоположению «Всегда» на системной странице приложения. Координаты не используются."
            } else {
                "Чтобы отслеживать выход из доверенной сети при выключенном экране, Android требует отдельное разрешение на фоновый доступ. Координаты не используются."
            },
            button = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) "Открыть настройки" else "Разрешить",
            onDismiss = {
                showBackgroundExplanation = false
                pendingAction = null
            },
            onConfirm = {
                showBackgroundExplanation = false
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    appSettingsLauncher.launch(
                        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                            data = "package:${context.packageName}".toUri()
                        }
                    )
                } else {
                    backgroundPermissionLauncher.launch(BACKGROUND_LOCATION_PERMISSION)
                }
            }
        )
    }
    if (showLocationExplanation) {
        PermissionExplanationDialog(
            title = "Включите определение местоположения",
            text = "Android не раскрывает имя Wi-Fi, когда системное определение местоположения выключено. WDTT Plus нужны только названия сетей, координаты не считываются.",
            button = "Открыть настройки",
            onDismiss = {
                showLocationExplanation = false
                pendingAction = null
            },
            onConfirm = {
                showLocationExplanation = false
                locationSettingsLauncher.launch(Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS))
            }
        )
    }
}

@Composable
private fun PermissionExplanationDialog(
    title: String,
    text: String,
    button: String,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = { Icon(Icons.Default.LocationOn, contentDescription = null) },
        title = { Text(title, textAlign = TextAlign.Center) },
        text = { Text(text) },
        confirmButton = { Button(onClick = onConfirm) { Text(button) } },
        dismissButton = { OutlinedButton(onClick = onDismiss) { Text("Не сейчас") } }
    )
}
