package com.wdtt.plus.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.HelpOutline
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.SettingsEthernet
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.wdtt.plus.DEFAULT_RT_TURN_SNI
import com.wdtt.plus.SshProfileAccessStatus

@Composable
internal fun RtNetworkSettingsDialog(
    rtNetwork: Boolean,
    connectionPath: String,
    onConnectionModeChange: (Boolean) -> Unit,
    turnSni: String,
    turnSniValid: Boolean,
    rtMasque: Boolean,
    rtMasqueServerBootstrap: Boolean,
    serverAccess: SshProfileAccessStatus,
    tunnelRunning: Boolean,
    onTurnSniChange: (String) -> Unit,
    onRtMasqueChange: (Boolean) -> Unit,
    onServerBootstrapChange: (Boolean) -> Unit,
    onShowRtHelp: () -> Unit,
    onShowMasqueHelp: () -> Unit,
    onShowServerHelp: () -> Unit,
    onDismiss: () -> Unit,
) {
    val controlsEnabled = !tunnelRunning
    var advancedExpanded by rememberSaveable { mutableStateOf(false) }
    SettingsDialogLayout(title = "Подключение", onDismiss = onDismiss, onHelp = onShowRtHelp, animateSize = true) {
        if (tunnelRunning) {
            Text(
                "Остановите соединение, чтобы изменить режим.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Column(Modifier.selectableGroup(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            listOf("UDP" to false, "TCP/TLS" to true).forEach { (title, mode) ->
                val selected = rtNetwork == mode
                val shape = RoundedCornerShape(16.dp)
                Surface(
                    shape = shape,
                    color = if (selected) MaterialTheme.colorScheme.secondaryContainer
                        else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth()
                            .remoteFocusOutline(shape, enabled = controlsEnabled)
                            .selectable(
                                selected = selected,
                                enabled = controlsEnabled,
                                role = Role.RadioButton,
                                onClick = { onConnectionModeChange(mode) },
                            ).padding(horizontal = 12.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        RadioButton(selected = selected, enabled = controlsEnabled, onClick = null)
                        Column(Modifier.weight(1f)) {
                            Text(title, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                            Text(
                                if (mode) "Без внешнего UDP" else "UDP, при недоступности — TCP/TLS",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }
        if (connectionPath.isNotEmpty()) {
            Text("Последний рабочий способ: $connectionPath", style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        run {
            val extras = buildList {
                if (rtMasque) add("MASQUE")
                if (rtMasque && rtMasqueServerBootstrap) add("Регистрация по SSH")
                if (!turnSniValid) add("Проверьте SNI")
                else if (turnSni.isNotBlank() && turnSni != DEFAULT_RT_TURN_SNI) add("Свой SNI")
            }.joinToString(" · ").ifBlank { "Для сетей с ограничениями" }
            Surface(
                shape = RoundedCornerShape(16.dp),
                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
                modifier = Modifier.fillMaxWidth().remoteFocusOutline(RoundedCornerShape(16.dp))
                    .clickable { advancedExpanded = !advancedExpanded },
            ) {
                Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Дополнительно", style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                        Text(extras, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Icon(if (advancedExpanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                        contentDescription = if (advancedExpanded) "Свернуть настройки" else "Раскрыть настройки")
                }
            }
        }
        if (advancedExpanded) {
            OutlinedTextField(
                value = turnSni,
                onValueChange = onTurnSniChange,
                label = { Text("Внешний SNI") },
                placeholder = { Text(DEFAULT_RT_TURN_SNI) },
                isError = !turnSniValid,
                enabled = controlsEnabled,
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                supportingText = {
                    Text(if (turnSniValid) "Для TURN/TLS и MASQUE"
                        else "Укажите домен латиницей, например $DEFAULT_RT_TURN_SNI")
                },
            )
            ConnectionOptionRow(
                title = "MASQUE", subtitle = "Резерв через Cloudflare",
                checked = rtMasque, enabled = controlsEnabled,
                onCheckedChange = onRtMasqueChange, onHelp = onShowMasqueHelp,
            )
            if (rtMasque) {
                ConnectionOptionRow(
                    title = "Регистрация по SSH",
                    subtitle = if (serverAccess.available) "Если WARP не регистрируется напрямую"
                        else "Недоступно: ${serverAccess.unavailableReason}",
                    checked = rtMasqueServerBootstrap,
                    enabled = controlsEnabled && serverAccess.available,
                    isError = !serverAccess.available,
                    onCheckedChange = onServerBootstrapChange, onHelp = onShowServerHelp,
                )
            }
        }
    }
}

@Composable
private fun ConnectionOptionRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    enabled: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    onHelp: (() -> Unit)? = null,
    isError: Boolean = false,
) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(title, modifier = Modifier.weight(1f, fill = false),
                    style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                if (onHelp != null) {
                    HintIconButton(hint = "Справка: $title", onClick = onHelp, modifier = Modifier.size(28.dp).remoteHelpFocus()) {
                        Icon(Icons.AutoMirrored.Filled.HelpOutline, contentDescription = "Справка: $title",
                            modifier = Modifier.size(20.dp))
                    }
                }
            }
            Text(subtitle, style = MaterialTheme.typography.bodySmall,
                color = if (isError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(checked = checked, enabled = enabled, onCheckedChange = onCheckedChange,
            modifier = Modifier.remoteSwitchFocus(enabled = enabled))
    }
}

@Composable
internal fun ConnectionSettingsCard(mode: String, onClick: () -> Unit) {
    AppSectionCard(
        modifier = Modifier.fillMaxWidth().remoteFocusOutline(RoundedCornerShape(16.dp)).clickable(onClick = onClick),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 14.dp),
    ) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Icon(Icons.Default.SettingsEthernet, contentDescription = null,
                tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(22.dp))
            Column(Modifier.weight(1f)) {
                Text("Подключение", style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                Text(mode, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Icon(Icons.Default.ChevronRight, contentDescription = "Открыть настройку подключения",
                tint = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
