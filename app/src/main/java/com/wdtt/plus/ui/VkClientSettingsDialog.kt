package com.wdtt.plus.ui

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.HelpOutline
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
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
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.wdtt.plus.BUILT_IN_VK_CLIENT_IDS
import com.wdtt.plus.SettingsStore
import com.wdtt.plus.TunnelManager
import com.wdtt.plus.isValidVkClientId
import com.wdtt.plus.normalizeVkClientId
import com.wdtt.plus.normalizeVkClientSecret
import java.security.MessageDigest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import kotlin.math.ceil
import kotlin.math.max

private const val VK_CLIENT_ID_PROBE_VERSION = 3
internal const val VK_CLIENT_ID_PROBE_COOLDOWN_MS = 10_000L
private const val VK_CLIENT_ID_PROBE_CHECKED_AT = "_checked_at"
private const val VK_ID_CABINET_URL = "https://id.vk.ru/about/business/go/"

internal enum class VkClientIdProbeStatus {
    LegacyCompatible,
    LegacyRejected,
    CheckFailed
}

internal data class VkClientIdProbeCache(
    val results: Map<String, VkClientIdProbeStatus>,
    val checkedAt: Long
)

internal fun vkClientIdProbeCooldownRemainingMillis(now: Long, lastStartedAt: Long): Long {
    if (lastStartedAt <= 0L) return 0L
    val elapsed = (now - lastStartedAt).coerceAtLeast(0L)
    return (VK_CLIENT_ID_PROBE_COOLDOWN_MS - elapsed).coerceAtLeast(0L)
}

internal fun vkClientIdAvailabilityMessage(
    ids: List<String>,
    results: Map<String, VkClientIdProbeStatus>
): String {
    val cleanIds = ids.map(String::trim).filter(String::isNotEmpty).distinct()
    val available = cleanIds.filter { results[it] == VkClientIdProbeStatus.LegacyCompatible }
    val rejected = cleanIds.filter { results[it] == VkClientIdProbeStatus.LegacyRejected }
    val failed = cleanIds.filter { results[it] == VkClientIdProbeStatus.CheckFailed }
    return when {
        cleanIds.size == 1 && available.isNotEmpty() ->
            "Client ID ${cleanIds.first()} принимается резервным способом"
        cleanIds.size == 1 && rejected.isNotEmpty() ->
            "Client ID ${cleanIds.first()} не принимается резервным способом"
        cleanIds.size == 1 ->
            "Не удалось проверить Client ID ${cleanIds.first()}: сеть или временная ошибка VK"
        rejected.isEmpty() && failed.isEmpty() -> "Все встроенные Client ID доступны для резервного способа"
        else -> buildList {
            if (available.isNotEmpty()) add("Доступны: ${available.joinToString(", ")}")
            if (rejected.isNotEmpty()) add("Не принимаются: ${rejected.joinToString(", ")}")
            if (failed.isNotEmpty()) add("Не удалось проверить: ${failed.joinToString(", ")}")
        }.joinToString(". ", postfix = ".")
    }
}

internal fun vkClientIdsForAutomaticProbe(
    customCredentialsEnabled: Boolean,
    customClientId: String,
    customClientSecret: String
): List<String> = if (customCredentialsEnabled) {
    customClientId.trim().takeIf(::isValidVkClientId)
        ?.takeIf { customClientSecret.trim().isNotEmpty() }
        ?.let(::listOf)
        .orEmpty()
} else {
    BUILT_IN_VK_CLIENT_IDS
}

private object VkClientIdProbeRateLimiter {
    private var lastStartedAt = 0L

    @Synchronized
    fun acquire(now: Long, persistedCheckedAt: Long): Long {
        val effectiveLastStartedAt = max(lastStartedAt, persistedCheckedAt)
        val remaining = vkClientIdProbeCooldownRemainingMillis(now, effectiveLastStartedAt)
        if (remaining == 0L) lastStartedAt = now
        return remaining
    }
}

@Composable
fun VkClientSettingsDialog(
    settingsStore: SettingsStore,
    activeClientIds: String,
    onClientIdsChange: (String) -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val configuration = LocalConfiguration.current
    val enabledState by remember(settingsStore) {
        settingsStore.customVkCredentialsEnabled.map { it as Boolean? }
    }.collectAsStateWithLifecycle(initialValue = null)
    val savedClientIdState by remember(settingsStore) {
        settingsStore.customVkClientId.map { it as String? }
    }.collectAsStateWithLifecycle(initialValue = null)
    val savedClientSecretState by remember(settingsStore) {
        settingsStore.customVkClientSecret.map { it as String? }
    }.collectAsStateWithLifecycle(initialValue = null)
    val checkResultsJsonState by remember(settingsStore) {
        settingsStore.clientIdCheckResults.map { it as String? }
    }.collectAsStateWithLifecycle(initialValue = null)
    val tunnelRunning by TunnelManager.running.collectAsStateWithLifecycle()

    val enabled = enabledState == true
    val savedClientId = savedClientIdState.orEmpty()
    val savedClientSecret = savedClientSecretState.orEmpty()
    val settingsReady = enabledState != null && savedClientIdState != null &&
        savedClientSecretState != null && checkResultsJsonState != null
    val probeCache = remember(checkResultsJsonState) {
        parseVkClientIdCheckResults(checkResultsJsonState.orEmpty())
    }
    val checkResults = probeCache.results
    val builtInSelection = remember(activeClientIds) {
        activeClientIds.split(',').map { it.trim() }.filter { it.isNotEmpty() }
    }

    var clientIdInput by rememberSaveable { mutableStateOf("") }
    var clientSecretInput by rememberSaveable { mutableStateOf("") }
    var inputsInitialized by rememberSaveable { mutableStateOf(false) }
    var secretFocused by remember { mutableStateOf(false) }
    var checkingIds by remember { mutableStateOf<Set<String>>(emptySet()) }
    var showHelp by rememberSaveable { mutableStateOf(false) }

    LaunchedEffect(settingsReady) {
        if (settingsReady && !inputsInitialized) {
            clientIdInput = savedClientId
            clientSecretInput = savedClientSecret
            inputsInitialized = true
        }
    }

    val normalizedClientId = normalizeVkClientId(clientIdInput)
    val normalizedClientSecret = normalizeVkClientSecret(clientSecretInput)
    val customInputComplete = isValidVkClientId(normalizedClientId) && normalizedClientSecret.isNotBlank()
    val hasUnsavedChanges = inputsInitialized && (
        normalizedClientId != savedClientId || normalizedClientSecret != savedClientSecret
    )

    fun checkIds(ids: List<String>, manual: Boolean) {
        val cleanIds = ids.map(String::trim).filter(::isValidVkClientId).distinct()
        if (cleanIds.isEmpty()) return
        if (checkingIds.isNotEmpty()) {
            if (manual) Toast.makeText(context, "Проверка уже выполняется", Toast.LENGTH_SHORT).show()
            return
        }
        val startedAt = System.currentTimeMillis()
        val cooldownRemaining = VkClientIdProbeRateLimiter.acquire(startedAt, probeCache.checkedAt)
        if (cooldownRemaining > 0L) {
            if (manual) {
                val seconds = ceil(cooldownRemaining / 1_000.0).toInt().coerceAtLeast(1)
                Toast.makeText(
                    context,
                    "Повторная проверка будет доступна через $seconds с",
                    Toast.LENGTH_SHORT
                ).show()
            }
            return
        }
        checkingIds = cleanIds.toSet()
        scope.launch {
            try {
                val checkedNow = withContext(Dispatchers.IO) {
                    buildMap {
                        cleanIds.forEach { id ->
                            put(id, checkVkClientId(id))
                        }
                    }
                }
                val freshResults = checkResults.toMutableMap().apply { putAll(checkedNow) }
                settingsStore.saveClientIdCheckResults(
                    encodeVkClientIdCheckResults(freshResults, startedAt)
                )
                Toast.makeText(
                    context,
                    vkClientIdAvailabilityMessage(cleanIds, checkedNow),
                    Toast.LENGTH_LONG
                ).show()
            } finally {
                checkingIds = emptySet()
            }
        }
    }

    LaunchedEffect(settingsReady, enabled, savedClientId, savedClientSecret) {
        if (settingsReady) {
            checkIds(
                vkClientIdsForAutomaticProbe(enabled, savedClientId, savedClientSecret),
                manual = false
            )
        }
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
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
                                Icon(Icons.Default.VpnKey, contentDescription = null, modifier = Modifier.size(25.dp))
                            }
                        }
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                "Клиенты VK",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold
                            )
                            Text(
                                "Настройка для текущего профиля подключения",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        IconButton(
                            onClick = onDismiss,
                            modifier = Modifier.remoteIconButtonFocus(),
                        ) {
                            Icon(Icons.Default.Close, contentDescription = "Закрыть")
                        }
                    }

                    if (!settingsReady) {
                        Box(
                            modifier = Modifier.fillMaxWidth().height(180.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            CircularProgressIndicator()
                        }
                    } else {
                        if (tunnelRunning) {
                            Surface(
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(18.dp),
                                color = MaterialTheme.colorScheme.errorContainer
                            ) {
                                Text(
                                    "VPN сейчас работает. Чтобы изменить резервные Client ID, сначала выключите VPN. Проверка доступности остаётся доступной.",
                                    modifier = Modifier.padding(14.dp),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onErrorContainer,
                                    fontWeight = FontWeight.SemiBold
                                )
                            }
                        }

                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(18.dp),
                            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f)
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .remoteToggleableRow(
                                        value = enabled,
                                        enabled = !tunnelRunning,
                                    ) { checked ->
                                        scope.launch {
                                            settingsStore.saveCustomVkCredentialsEnabled(checked)
                                        }
                                    }
                                    .padding(14.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                Column(
                                    modifier = Modifier.weight(1f),
                                    verticalArrangement = Arrangement.spacedBy(4.dp)
                                ) {
                                    Text("Собственные резервные реквизиты", fontWeight = FontWeight.SemiBold)
                                    Text(
                                        if (enabled) {
                                            "После быстрого VKCalls сначала пробуется ваш Client ID."
                                        } else {
                                            "После быстрого VKCalls используются встроенные Client ID."
                                        },
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                                Switch(
                                    checked = enabled,
                                    enabled = !tunnelRunning,
                                    onCheckedChange = null,
                                )
                            }
                        }

                        if (enabled) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text("Резервные реквизиты приложения VK", fontWeight = FontWeight.Bold)
                                    Text(
                                        "Оба поля обязательны",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                                IconButton(
                                    onClick = { showHelp = true },
                                    modifier = Modifier.remoteHelpFocus(),
                                ) {
                                    Icon(
                                        Icons.AutoMirrored.Filled.HelpOutline,
                                        contentDescription = "Как получить Client ID и secret"
                                    )
                                }
                            }

                            OutlinedTextField(
                                value = clientIdInput,
                                onValueChange = { clientIdInput = normalizeVkClientId(it) },
                                modifier = Modifier.fillMaxWidth(),
                                label = { Text("Client ID") },
                                supportingText = { Text("ID приложения из кабинета VK ID") },
                                enabled = !tunnelRunning,
                                singleLine = true,
                                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                                    keyboardType = KeyboardType.Number
                                )
                            )

                            OutlinedTextField(
                                value = clientSecretInput,
                                onValueChange = { clientSecretInput = it.take(512) },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .onFocusChanged { secretFocused = it.isFocused },
                                label = { Text("Client secret") },
                                supportingText = {
                                    Text("Защищённый ключ скрывается после выхода из поля")
                                },
                                enabled = !tunnelRunning,
                                singleLine = true,
                                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                                    keyboardType = KeyboardType.Password
                                ),
                                visualTransformation = if (secretFocused) {
                                    VisualTransformation.None
                                } else {
                                    PasswordVisualTransformation()
                                }
                            )

                            Surface(
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(14.dp),
                                color = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.45f)
                            ) {
                                Text(
                                    "Защищённый ключ сохраняется в зашифрованном виде через Android Keystore и не добавляется в журналы.",
                                    modifier = Modifier.padding(13.dp),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSecondaryContainer
                                )
                            }

                            if (hasUnsavedChanges) {
                                Text(
                                    "Есть несохранённые изменения",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.tertiary,
                                    fontWeight = FontWeight.SemiBold
                                )
                            }

                            Button(
                                onClick = {
                                    scope.launch {
                                        settingsStore.saveCustomVkCredentials(
                                            normalizedClientId,
                                            normalizedClientSecret
                                        )
                                        clientIdInput = normalizedClientId
                                        clientSecretInput = normalizedClientSecret
                                        Toast.makeText(context, "Реквизиты сохранены", Toast.LENGTH_SHORT).show()
                                    }
                                },
                                enabled = !tunnelRunning && customInputComplete && hasUnsavedChanges,
                                modifier = Modifier.fillMaxWidth().heightIn(min = 50.dp),
                                shape = RoundedCornerShape(16.dp)
                            ) {
                                Text("Сохранить")
                            }

                            val customProbeResult = checkResults[normalizedClientId]
                            OutlinedButton(
                                onClick = { checkIds(listOf(normalizedClientId), manual = true) },
                                enabled = isValidVkClientId(normalizedClientId) && checkingIds.isEmpty(),
                                modifier = Modifier.fillMaxWidth().heightIn(min = 50.dp),
                                shape = RoundedCornerShape(16.dp)
                            ) {
                                Text(if (normalizedClientId in checkingIds) "Проверка…" else "Проверить Client ID")
                            }

                            if (customProbeResult != null && normalizedClientId !in checkingIds) {
                                val statusColor = when (customProbeResult) {
                                    VkClientIdProbeStatus.LegacyCompatible -> MaterialTheme.colorScheme.primaryContainer
                                    VkClientIdProbeStatus.LegacyRejected -> MaterialTheme.colorScheme.errorContainer
                                    VkClientIdProbeStatus.CheckFailed -> MaterialTheme.colorScheme.tertiaryContainer
                                }
                                val statusContentColor = when (customProbeResult) {
                                    VkClientIdProbeStatus.LegacyCompatible -> MaterialTheme.colorScheme.onPrimaryContainer
                                    VkClientIdProbeStatus.LegacyRejected -> MaterialTheme.colorScheme.onErrorContainer
                                    VkClientIdProbeStatus.CheckFailed -> MaterialTheme.colorScheme.onTertiaryContainer
                                }
                                Surface(
                                    modifier = Modifier.fillMaxWidth(),
                                    shape = RoundedCornerShape(14.dp),
                                    color = statusColor
                                ) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth().padding(13.dp),
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                                    ) {
                                        Icon(
                                            imageVector = when (customProbeResult) {
                                                VkClientIdProbeStatus.LegacyCompatible -> Icons.Default.CheckCircle
                                                VkClientIdProbeStatus.LegacyRejected -> Icons.Default.Cancel
                                                VkClientIdProbeStatus.CheckFailed -> Icons.Default.WarningAmber
                                            },
                                            contentDescription = null,
                                            tint = statusContentColor
                                        )
                                        Text(
                                            text = when (customProbeResult) {
                                                VkClientIdProbeStatus.LegacyCompatible ->
                                                    "Client ID принимается резервным способом"
                                                VkClientIdProbeStatus.LegacyRejected ->
                                                    "Client ID не принимается резервным способом"
                                                VkClientIdProbeStatus.CheckFailed ->
                                                    "Проверку выполнить не удалось: сеть или временная ошибка VK"
                                            },
                                            style = MaterialTheme.typography.bodySmall,
                                            color = statusContentColor,
                                            fontWeight = FontWeight.SemiBold
                                        )
                                    }
                                }
                            }

                            Text(
                                "Сохранённый собственный Client ID проверяется автоматически при входе. Это второй вариант после VKCalls. Такая проверка подтверждает только приём ID старым способом VK; получение TURN-данных окончательно проверяется при подключении.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }

                        Text("Встроенный резерв", fontWeight = FontWeight.Bold)
                        Text(
                            if (enabled) {
                                "Используется, если VKCalls и собственные реквизиты не сработали. Встроенный ID можно проверить нажатием на строку."
                            } else {
                                "Используется, если VKCalls не сработал. Проверка запускается автоматически при входе; нажмите на строку для повтора."
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )

                        BUILT_IN_VK_CLIENT_IDS.forEach { id ->
                                Surface(
                                    modifier = Modifier.fillMaxWidth(),
                                    shape = RoundedCornerShape(14.dp),
                                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.42f),
                                    onClick = { checkIds(listOf(id), manual = true) }
                                ) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Checkbox(
                                            checked = id in builtInSelection,
                                            enabled = !tunnelRunning,
                                            onCheckedChange = { checked ->
                                                val updated = if (checked) {
                                                    (builtInSelection + id).distinct()
                                                } else {
                                                    builtInSelection - id
                                                }
                                                if (updated.isNotEmpty()) {
                                                    onClientIdsChange(updated.joinToString(","))
                                                } else {
                                                    Toast.makeText(
                                                        context,
                                                        "Нельзя отключить все Client ID: без них программа перестанет работать",
                                                        Toast.LENGTH_LONG
                                                    ).show()
                                                }
                                            }
                                        )
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(id, fontWeight = FontWeight.SemiBold)
                                            Text(
                                                if (id in builtInSelection) "Выбран для резерва" else "Отключён",
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                        }
                                        Box(
                                            modifier = Modifier.size(36.dp),
                                            contentAlignment = Alignment.Center
                                        ) {
                                            when {
                                                id in checkingIds -> CircularProgressIndicator(
                                                    modifier = Modifier.size(22.dp),
                                                    strokeWidth = 2.5.dp
                                                )
                                                checkResults[id] == VkClientIdProbeStatus.LegacyCompatible -> Icon(
                                                    Icons.Default.CheckCircle,
                                                    contentDescription = "Client ID доступен для резервного способа",
                                                    tint = MaterialTheme.colorScheme.primary,
                                                    modifier = Modifier.size(24.dp)
                                                )
                                                checkResults[id] == VkClientIdProbeStatus.LegacyRejected -> Icon(
                                                    Icons.Default.Cancel,
                                                    contentDescription = "Client ID недоступен для резервного способа",
                                                    tint = MaterialTheme.colorScheme.error,
                                                    modifier = Modifier.size(24.dp)
                                                )
                                                checkResults[id] == VkClientIdProbeStatus.CheckFailed -> Icon(
                                                    Icons.Default.WarningAmber,
                                                    contentDescription = "Не удалось проверить Client ID",
                                                    tint = MaterialTheme.colorScheme.tertiary,
                                                    modifier = Modifier.size(24.dp)
                                                )
                                                else -> Text(
                                                    "—",
                                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                    fontWeight = FontWeight.Bold
                                                )
                                            }
                                        }
                                    }
                                }
                        }

                        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.55f))
                        Text(
                            if (enabled) {
                                "Порядок подключения: быстрый VKCalls без капчи → собственные реквизиты → встроенный резерв. Если резервный способ запросит капчу, приложение попробует решить её автоматически."
                            } else {
                                "Порядок подключения: быстрый VKCalls без капчи → встроенный резерв. Если резервный способ запросит капчу, приложение попробует решить её автоматически."
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }
    }

    if (showHelp) {
        VkClientCredentialsHelpDialog(onDismiss = { showHelp = false })
    }
}

@Composable
private fun VkClientCredentialsHelpDialog(onDismiss: () -> Unit) {
    val context = LocalContext.current
    val television = isTelevisionDevice()
    val clipboard = LocalClipboardManager.current
    val configuration = LocalConfiguration.current
    val packageName = context.packageName
    val signingSha1 = remember(context) { appSigningSha1(context) }

    fun copy(value: String, message: String) {
        clipboard.setText(AnnotatedString(value))
        Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Surface(
                modifier = (if (television) {
                    Modifier.televisionDialogWidth(television, fraction = 0.82f, maxWidth = 1_000.dp)
                } else {
                    Modifier.fillMaxWidth(0.92f)
                })
                    .fillMaxHeight(0.9f)
                    .heightIn(max = (configuration.screenHeightDp.dp - 32.dp).coerceAtLeast(360.dp)),
                shape = RoundedCornerShape(30.dp),
                color = MaterialTheme.colorScheme.surface,
                tonalElevation = 10.dp,
                shadowElevation = 10.dp
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
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                "Резервные реквизиты VK",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold
                            )
                            Text(
                                "Резервный провайдер через кабинет VK ID",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        IconButton(
                            onClick = onDismiss,
                            modifier = Modifier.remoteIconButtonFocus(),
                        ) {
                            Icon(Icons.Default.Close, contentDescription = "Закрыть")
                        }
                    }

                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                        color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.65f)
                    ) {
                        Text(
                            "Собственные реквизиты относятся только к резервному legacy-провайдеру. Для основного быстрого VKCalls они не нужны. Понадобятся ID приложения и Защищённый ключ из одного приложения VK; сервисный ключ доступа не подходит.",
                            modifier = Modifier.padding(14.dp),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onPrimaryContainer
                        )
                    }

                    HelpStep(
                        number = 1,
                        title = "Откройте кабинет VK ID",
                        text = "Войдите в аккаунт владельца приложения, откройте раздел «Мои приложения» и нажмите «Добавить приложение»."
                    )
                    Button(
                        onClick = {
                            runCatching {
                                context.startActivity(Intent(Intent.ACTION_VIEW, android.net.Uri.parse(VK_ID_CABINET_URL)))
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(14.dp)
                    ) {
                        Text("Открыть кабинет VK ID")
                    }

                    HelpStep(
                        number = 2,
                        title = "Создайте Android-приложение",
                        text = "Укажите понятное название, выберите платформу Android, затем заполните имя пакета и SHA-1 подписи установленного APK."
                    )
                    CopyValueCard(
                        label = "Название пакета",
                        value = packageName,
                        onCopy = { copy(packageName, "Название пакета скопировано") }
                    )
                    CopyValueCard(
                        label = "SHA-1 подписи этого APK",
                        value = signingSha1.ifBlank { "Не удалось определить" },
                        onCopy = signingSha1.takeIf(String::isNotBlank)?.let { sha1 ->
                            { copy(sha1, "SHA-1 скопирован") }
                        }
                    )

                    HelpStep(
                        number = 3,
                        title = "Скопируйте реквизиты",
                        text = "После создания откройте карточку приложения → «Приложение» → «Информация о приложении». Поле «ID приложения» вставьте как Client ID, а поле «Защищённый ключ» — как Client secret."
                    )

                    HelpStep(
                        number = 4,
                        title = "Сохраните и проверьте",
                        text = "Вернитесь в WDTT Plus, заполните оба поля, нажмите «Сохранить», затем «Проверить Client ID». Для полного доступа к ключам VK может попросить подтвердить профиль бизнеса."
                    )

                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                        color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.55f),
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.error.copy(alpha = 0.25f))
                    ) {
                        Column(
                            modifier = Modifier.padding(14.dp),
                            verticalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Text("Важно", fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onErrorContainer)
                            Text(
                                "Не публикуйте Защищённый ключ, не отправляйте его в чат и не добавляйте в GitHub. Новое приложение VK ID может не иметь прав старой TURN-цепочки: статус проверки показывает распознавание legacy OAuth, а окончательный результат виден только при реальном подключении. При неудаче приложение продолжит через встроенный резерв.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onErrorContainer
                            )
                        }
                    }

                    Button(
                        onClick = onDismiss,
                        modifier = Modifier.fillMaxWidth().heightIn(min = 50.dp),
                        shape = RoundedCornerShape(16.dp)
                    ) {
                        Text("Понятно")
                    }
                }
            }
        }
    }
}

@Composable
private fun HelpStep(number: Int, title: String, text: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.Top
    ) {
        Surface(shape = CircleShape, color = MaterialTheme.colorScheme.secondaryContainer) {
            Box(modifier = Modifier.size(30.dp), contentAlignment = Alignment.Center) {
                Text(number.toString(), fontWeight = FontWeight.Bold)
            }
        }
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(title, fontWeight = FontWeight.Bold)
            Text(
                text,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                lineHeight = 18.sp
            )
        }
    }
}

@Composable
private fun CopyValueCard(label: String, value: String, onCopy: (() -> Unit)?) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(start = 14.dp, end = 4.dp, top = 8.dp, bottom = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(value, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
            }
            IconButton(onClick = { onCopy?.invoke() }, enabled = onCopy != null) {
                Icon(Icons.Default.ContentCopy, contentDescription = "Копировать")
            }
        }
    }
}

internal fun parseVkClientIdCheckResults(raw: String): VkClientIdProbeCache = runCatching {
    val json = JSONObject(raw)
    if (json.optInt("_probe_version") != VK_CLIENT_ID_PROBE_VERSION) {
        return@runCatching VkClientIdProbeCache(emptyMap(), 0L)
    }
    val results = buildMap {
        val keys = json.keys()
        while (keys.hasNext()) {
            val key = keys.next()
            if (key != "_probe_version" && key != VK_CLIENT_ID_PROBE_CHECKED_AT) {
                runCatching { VkClientIdProbeStatus.valueOf(json.optString(key)) }
                    .getOrNull()
                    ?.let { put(key, it) }
            }
        }
    }
    VkClientIdProbeCache(
        results = results,
        checkedAt = json.optLong(VK_CLIENT_ID_PROBE_CHECKED_AT, 0L).coerceAtLeast(0L)
    )
}.getOrDefault(VkClientIdProbeCache(emptyMap(), 0L))

private fun encodeVkClientIdCheckResults(
    results: Map<String, VkClientIdProbeStatus>,
    checkedAt: Long
): String =
    JSONObject().apply {
        put("_probe_version", VK_CLIENT_ID_PROBE_VERSION)
        put(VK_CLIENT_ID_PROBE_CHECKED_AT, checkedAt.coerceAtLeast(0L))
        results.forEach { (id, result) -> put(id, result.name) }
    }.toString()

internal val vkLegacyOAuthProbeEndpoints = listOf(
    "https://oauth.vk.ru/authorize",
    "https://oauth.vk.com/authorize"
)

private fun checkVkClientId(appId: String): VkClientIdProbeStatus {
    val cleanAppId = appId.trim()
    if (!isValidVkClientId(cleanAppId)) return VkClientIdProbeStatus.LegacyRejected
    var legacyRejected = false
    for (endpoint in vkLegacyOAuthProbeEndpoints) {
        var connection: java.net.HttpURLConnection? = null
        try {
            val url = java.net.URL(
                "$endpoint?client_id=$cleanAppId&display=mobile&response_type=token"
            )
            connection = url.openConnection() as java.net.HttpURLConnection
            connection.requestMethod = "GET"
            connection.connectTimeout = 5_000
            connection.readTimeout = 5_000
            val responseCode = connection.responseCode
            if (isVkLegacyClientIdProbeSuccessful(responseCode, connection.contentType.orEmpty())) {
                return VkClientIdProbeStatus.LegacyCompatible
            }
            if (isVkLegacyClientIdProbeRejected(responseCode)) {
                legacyRejected = true
            }
        } catch (_: Exception) {
            // Try the compatibility domain below.
        } finally {
            connection?.disconnect()
        }
    }
    return if (legacyRejected) {
        VkClientIdProbeStatus.LegacyRejected
    } else {
        VkClientIdProbeStatus.CheckFailed
    }
}

internal fun isVkLegacyClientIdProbeSuccessful(statusCode: Int, contentType: String): Boolean =
    statusCode in 200..299 && contentType.startsWith("text/html", ignoreCase = true)

internal fun isVkLegacyClientIdProbeRejected(statusCode: Int): Boolean =
    statusCode in 400..499 && statusCode != 408 && statusCode != 429

@Suppress("DEPRECATION")
private fun appSigningSha1(context: Context): String = runCatching {
    val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
    } else {
        context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
    }
    val signature = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        val signingInfo = packageInfo.signingInfo ?: return@runCatching ""
        if (signingInfo.hasMultipleSigners()) {
            signingInfo.apkContentsSigners.firstOrNull()
        } else {
            signingInfo.signingCertificateHistory.firstOrNull()
        }
    } else {
        packageInfo.signatures?.firstOrNull()
    } ?: return@runCatching ""
    MessageDigest.getInstance("SHA-1")
        .digest(signature.toByteArray())
        .joinToString(":") { byte -> "%02X".format(byte) }
}.getOrDefault("")
