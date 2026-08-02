package com.wdtt.plus.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.HelpOutline
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.wdtt.plus.DEFAULT_RT_TURN_SNI
import com.wdtt.plus.SshProfileAccessStatus

@Composable
internal fun RtNetworkSettingsDialog(
    rtNetwork: Boolean,
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
    val configuration = LocalConfiguration.current
    val dialogMaxHeight = (configuration.screenHeightDp.dp - 32.dp).coerceAtLeast(360.dp)
    val dialogMinHeight = 520.dp.coerceAtMost(dialogMaxHeight)
    val controlsEnabled = rtNetwork && !tunnelRunning
    val serverSupportingText = when {
        !rtNetwork -> "Сначала включите «Сеть РТ»"
        !rtMasque -> "Сначала включите MASQUE"
        !serverAccess.available -> "Недоступно: ${serverAccess.unavailableReason}"
        tunnelRunning -> "Остановите VPN, чтобы изменить настройку"
        else -> "Только первая регистрация WARP · SSH из «Деплой»"
    }
    val serverTextIsError = rtNetwork && rtMasque && !serverAccess.available

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center,
        ) {
            Surface(
                modifier = Modifier
                    .fillMaxWidth(0.92f)
                    .heightIn(min = dialogMinHeight, max = dialogMaxHeight),
                shape = RoundedCornerShape(30.dp),
                color = MaterialTheme.colorScheme.surface,
                tonalElevation = 8.dp,
                shadowElevation = 8.dp,
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState())
                        .padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(14.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        Surface(
                            shape = RoundedCornerShape(16.dp),
                            color = MaterialTheme.colorScheme.primaryContainer,
                        ) {
                            Box(
                                modifier = Modifier.size(48.dp),
                                contentAlignment = Alignment.Center,
                            ) {
                                Icon(
                                    Icons.Default.Cloud,
                                    contentDescription = null,
                                    modifier = Modifier.size(25.dp),
                                )
                            }
                        }
                        Text(
                            "Сеть РТ",
                            modifier = Modifier.weight(1f),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                        )
                        IconButton(onClick = onShowRtHelp) {
                            Icon(
                                Icons.AutoMirrored.Filled.HelpOutline,
                                contentDescription = "Инструкция по режиму Сеть РТ",
                            )
                        }
                        IconButton(onClick = onDismiss) {
                            Icon(Icons.Default.Close, contentDescription = "Закрыть")
                        }
                    }

                    if (!rtNetwork || tunnelRunning) {
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(16.dp),
                            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f),
                            border = BorderStroke(
                                1.dp,
                                MaterialTheme.colorScheme.outline.copy(alpha = 0.2f),
                            ),
                        ) {
                            Text(
                                if (!rtNetwork) {
                                    "Включите «Сеть РТ» в основном окне, чтобы изменить эти параметры."
                                } else {
                                    "Остановите VPN, чтобы изменить параметры режима."
                                },
                                modifier = Modifier.padding(14.dp),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }

                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        OutlinedTextField(
                            value = turnSni,
                            onValueChange = onTurnSniChange,
                            label = { Text("SNI белого списка") },
                            placeholder = { Text(DEFAULT_RT_TURN_SNI) },
                            isError = !turnSniValid,
                            enabled = controlsEnabled,
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(16.dp),
                        )
                        Text(
                            text = if (turnSniValid) {
                                "Только для TURN/TLS и MASQUE; в TURN/TCP и UDP SNI нет"
                            } else {
                                "Укажите домен латиницей, например $DEFAULT_RT_TURN_SNI"
                            },
                            modifier = Modifier.fillMaxWidth(),
                            style = MaterialTheme.typography.bodySmall,
                            color = if (turnSniValid) {
                                MaterialTheme.colorScheme.onSurfaceVariant
                            } else {
                                MaterialTheme.colorScheme.error
                            },
                        )
                    }

                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text("MASQUE", fontWeight = FontWeight.SemiBold)
                                IconButton(
                                    onClick = onShowMasqueHelp,
                                    modifier = Modifier.size(32.dp),
                                ) {
                                    Icon(
                                        Icons.AutoMirrored.Filled.HelpOutline,
                                        contentDescription = "Инструкция по MASQUE",
                                        modifier = Modifier.size(19.dp),
                                    )
                                }
                            }
                            Text(
                                "Резерв после TURN/TLS и TCP: HTTP/2, затем HTTP/3",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        Switch(
                            checked = rtMasque,
                            enabled = controlsEnabled,
                            onCheckedChange = onRtMasqueChange,
                        )
                    }

                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text("Через сервер", fontWeight = FontWeight.SemiBold)
                                IconButton(
                                    onClick = onShowServerHelp,
                                    modifier = Modifier.size(32.dp),
                                ) {
                                    Icon(
                                        Icons.AutoMirrored.Filled.HelpOutline,
                                        contentDescription = "Инструкция по регистрации через сервер",
                                        modifier = Modifier.size(19.dp),
                                    )
                                }
                            }
                            Text(
                                serverSupportingText,
                                style = MaterialTheme.typography.bodySmall,
                                color = if (serverTextIsError) {
                                    MaterialTheme.colorScheme.error
                                } else {
                                    MaterialTheme.colorScheme.onSurfaceVariant
                                },
                            )
                        }
                        Switch(
                            checked = rtMasqueServerBootstrap,
                            enabled = controlsEnabled && rtMasque && serverAccess.available,
                            onCheckedChange = onServerBootstrapChange,
                        )
                    }

                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f),
                        border = BorderStroke(
                            1.dp,
                            MaterialTheme.colorScheme.outline.copy(alpha = 0.2f),
                        ),
                    ) {
                        Column(
                            modifier = Modifier.padding(14.dp),
                            verticalArrangement = Arrangement.spacedBy(6.dp),
                        ) {
                            Text(
                                "Когда включать",
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.SemiBold,
                            )
                            Text(
                                "Сеть РТ — если в мобильной сети Ростелекома открываются разрешённые сайты, но WDTT Plus не подключается.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Text(
                                "MASQUE — если одной «Сети РТ» недостаточно: это дополнительный резерв после TURN/TLS и TCP.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Text(
                                "Через сервер — только если первая регистрация WARP для MASQUE не проходит напрямую; нужен настроенный иностранный SSH-сервер в «Деплой».",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }
    }
}
