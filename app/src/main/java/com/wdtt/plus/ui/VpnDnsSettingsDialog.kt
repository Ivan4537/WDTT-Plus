package com.wdtt.plus.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.AlertDialogDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.wdtt.plus.VPN_DNS_CUSTOM_ID
import com.wdtt.plus.VPN_DNS_PROFILE_ID
import com.wdtt.plus.VpnDnsCategory
import com.wdtt.plus.VpnDnsPreset
import com.wdtt.plus.VpnDnsSettingsSnapshot
import com.wdtt.plus.normalizeCustomVpnDnsServers
import com.wdtt.plus.vpnDnsPresets

@Composable
internal fun VpnDnsSettingsCard(
    settings: VpnDnsSettingsSnapshot,
    onClick: () -> Unit,
) {
    val subtitle = when (settings.selectionId) {
        VPN_DNS_PROFILE_ID -> "DNS из WireGuard-профиля"
        VPN_DNS_CUSTOM_ID -> settings.customServers.joinToString(", ").ifBlank { "Не настроен" }
        else -> settings.configuredServers.joinToString(", ")
    }
    AppSectionCard(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 14.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = Icons.Default.Dns,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(22.dp),
            )
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "DNS внутри VPN",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    text = "${settings.title} · $subtitle",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Spacer(Modifier.width(8.dp))
            Icon(
                imageVector = Icons.Default.ChevronRight,
                contentDescription = "Открыть настройку DNS",
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
internal fun VpnDnsSettingsDialog(
    initialSettings: VpnDnsSettingsSnapshot,
    onApply: (selectionId: String, customServers: String) -> Unit,
    onDismiss: () -> Unit,
) {
    var selectionId by remember(initialSettings.profileIndex, initialSettings.selectionId) {
        mutableStateOf(initialSettings.selectionId)
    }
    var customInput by remember(initialSettings.profileIndex, initialSettings.customServers) {
        mutableStateOf(initialSettings.customServers.joinToString(", "))
    }
    var validationError by remember(initialSettings.profileIndex) { mutableStateOf<String?>(null) }
    val selectedPreset = vpnDnsPresets.firstOrNull { it.id == selectionId }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        Surface(
            modifier = Modifier
                .fillMaxWidth(0.92f)
                .heightIn(max = 720.dp),
            shape = RoundedCornerShape(20.dp),
            color = AlertDialogDefaults.containerColor,
            tonalElevation = 6.dp,
        ) {
            Column(modifier = Modifier.padding(horizontal = 20.dp, vertical = 16.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = "DNS внутри VPN",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.weight(1f),
                    )
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Default.Close, contentDescription = "Закрыть")
                    }
                }

                Column(
                    modifier = Modifier
                        .weight(1f, fill = false)
                        .verticalScroll(rememberScrollState()),
                ) {
                    Text(
                        text = "Текущий профиль",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(top = 4.dp, bottom = 4.dp),
                    )
                    VpnDnsOptionRow(
                        title = "Как в профиле",
                        subtitle = "Использовать DNS, полученный вместе с WireGuard-конфигурацией",
                        selected = selectionId == VPN_DNS_PROFILE_ID,
                        onClick = {
                            selectionId = VPN_DNS_PROFILE_ID
                            validationError = null
                        },
                    )

                    VpnDnsPresetSection(
                        title = "Обычные DNS",
                        presets = vpnDnsPresets.filter { it.category == VpnDnsCategory.STANDARD },
                        selectionId = selectionId,
                        onSelect = {
                            selectionId = it
                            validationError = null
                        },
                    )
                    VpnDnsPresetSection(
                        title = "Smart DNS",
                        presets = vpnDnsPresets.filter { it.category == VpnDnsCategory.SMART },
                        selectionId = selectionId,
                        onSelect = {
                            selectionId = it
                            validationError = null
                        },
                    )

                    Text(
                        text = "Свой DNS",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(top = 14.dp, bottom = 4.dp),
                    )
                    VpnDnsOptionRow(
                        title = "Ввести вручную",
                        subtitle = customInput.ifBlank { "Один или два IPv4-адреса" },
                        selected = selectionId == VPN_DNS_CUSTOM_ID,
                        onClick = {
                            selectionId = VPN_DNS_CUSTOM_ID
                            validationError = null
                        },
                    )
                    if (selectionId == VPN_DNS_CUSTOM_ID) {
                        OutlinedTextField(
                            value = customInput,
                            onValueChange = { value ->
                                customInput = value.filter { character ->
                                    character.isDigit() || character in ".,; \n\t"
                                }
                                validationError = null
                            },
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 8.dp),
                            label = { Text("IPv4-адреса DNS") },
                            placeholder = { Text("1.1.1.1, 1.0.0.1") },
                            supportingText = {
                                Text(validationError ?: "Разделите адреса запятой или пробелом")
                            },
                            isError = validationError != null,
                            minLines = 1,
                            maxLines = 2,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                            shape = RoundedCornerShape(12.dp),
                        )
                    }

                    if (selectedPreset?.category == VpnDnsCategory.SMART) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 12.dp),
                            verticalAlignment = Alignment.Top,
                        ) {
                            Icon(
                                Icons.Default.WarningAmber,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.tertiary,
                                modifier = Modifier.size(20.dp),
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(
                                text = "Сторонний Smart DNS может направлять соединения с отдельными сервисами через собственные шлюзы.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                    Text(
                        text = "Настройка действует на системный DNS приложений внутри VPN. Встроенный в приложение или браузер защищённый DNS может использовать собственный адрес.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 12.dp, bottom = 4.dp),
                    )
                }

                Button(
                    onClick = {
                        if (selectionId == VPN_DNS_CUSTOM_ID) {
                            val result = runCatching { normalizeCustomVpnDnsServers(customInput) }
                            validationError = result.exceptionOrNull()?.message
                            if (result.isFailure) return@Button
                            customInput = result.getOrThrow().joinToString(", ")
                        }
                        onApply(selectionId, customInput)
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 14.dp),
                    shape = RoundedCornerShape(14.dp),
                ) {
                    Text("Применить")
                }
            }
        }
    }
}

@Composable
private fun VpnDnsPresetSection(
    title: String,
    presets: List<VpnDnsPreset>,
    selectionId: String,
    onSelect: (String) -> Unit,
) {
    Text(
        text = title,
        style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(top = 14.dp, bottom = 4.dp),
    )
    presets.forEach { preset ->
        VpnDnsOptionRow(
            title = preset.title,
            subtitle = "${preset.servers.joinToString(", ")} · ${preset.description}",
            selected = selectionId == preset.id,
            onClick = { onSelect(preset.id) },
        )
    }
}

@Composable
private fun VpnDnsOptionRow(
    title: String,
    subtitle: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        color = if (selected) {
            MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.55f)
        } else {
            MaterialTheme.colorScheme.surface
        },
        shape = RoundedCornerShape(8.dp),
        border = if (selected) {
            BorderStroke(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.65f))
        } else {
            null
        },
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            RadioButton(selected = selected, onClick = onClick)
            Spacer(Modifier.width(6.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(text = title, style = MaterialTheme.typography.bodyMedium)
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.35f))
}
