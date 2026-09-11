package com.wdtt.plus.ui

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.wdtt.plus.ScreenOffMode
import com.wdtt.plus.DeviceCompatibility
import com.wdtt.plus.ProcessExitCategory
import com.wdtt.plus.classifyProcessExit
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner

internal fun isBatteryOptimizationDisabled(context: Context): Boolean {
    val powerManager = context.getSystemService(Context.POWER_SERVICE) as PowerManager
    return powerManager.isIgnoringBatteryOptimizations(context.packageName)
}

@Composable
internal fun ScreenOffModeDialog(
    initialMode: ScreenOffMode,
    onApply: (ScreenOffMode) -> Unit,
    onConfigureBatterySaving: (ScreenOffMode) -> Unit,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    var selectedName by rememberSaveable(initialMode) { mutableStateOf(initialMode.name) }
    val selected = ScreenOffMode.valueOf(selectedName)
    var batteryUnrestricted by remember { mutableStateOf(isBatteryOptimizationDisabled(context)) }
    var recentSystemStop by remember {
        mutableStateOf(
            DeviceCompatibility.recentProcessExitHistory(context)
                ?.latestUnexpected
                ?.let(::classifyProcessExit) == ProcessExitCategory.SystemPolicy
        )
    }
    DisposableEffect(lifecycleOwner, context) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                batteryUnrestricted = isBatteryOptimizationDisabled(context)
                recentSystemStop = DeviceCompatibility.recentProcessExitHistory(context)
                    ?.latestUnexpected
                    ?.let(::classifyProcessExit) == ProcessExitCategory.SystemPolicy
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }
    val options = listOf(
        ScreenOffMode.BALANCED to (
            "Сбалансированно" to
                "Обычная фоновая работа и современное автоматическое восстановление. Режим по умолчанию."
            ),
        ScreenOffMode.HOLD_CONNECTION to (
            "Удерживать соединение" to
                "Старается сохранять активное соединение при выключенном экране, в том числе при работе через Wi‑Fi. " +
                    "Может заметно увеличить расход батареи."
            ),
        ScreenOffMode.SAVE_BATTERY to (
            "Экономить батарею" to
                "Намеренно приостанавливает VPN по сохранённому сценарию и возобновляет его автоматически."
            ),
    )

    AlertDialog(
        onDismissRequest = onDismiss,
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                options.forEach { (mode, presentation) ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { selectedName = mode.name }
                            .padding(vertical = 6.dp),
                        verticalAlignment = Alignment.Top,
                    ) {
                        RadioButton(
                            selected = selected == mode,
                            onClick = { selectedName = mode.name },
                        )
                        Column(modifier = Modifier.padding(start = 8.dp)) {
                            Text(presentation.first, fontWeight = FontWeight.SemiBold)
                            Text(
                                presentation.second,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
                if (selected == ScreenOffMode.HOLD_CONNECTION) {
                    Text(
                        if (recentSystemStop) {
                            "Android недавно принудительно завершил WDTT Plus. Проверьте в настройках приложения разрешение фоновой работы; на некоторых телефонах оно действует отдельно от обычной оптимизации батареи."
                        } else if (batteryUnrestricted) {
                            "WDTT Plus исключён из стандартной оптимизации батареи Android. Ограничения производителя телефона могут действовать отдельно."
                        } else {
                            "Android может всё равно ограничить приложение. Разрешите работу без ограничения батареи."
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = if (batteryUnrestricted) {
                            MaterialTheme.colorScheme.primary
                        } else {
                            MaterialTheme.colorScheme.error
                        },
                    )
                    OutlinedButton(
                        onClick = {
                            if (!batteryUnrestricted) {
                                val intent = Intent(
                                    Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                                    Uri.parse("package:${context.packageName}"),
                                ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                runCatching { context.startActivity(intent) }.onFailure {
                                    context.startActivity(
                                        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                                            .setData(Uri.parse("package:${context.packageName}"))
                                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                                    )
                                }
                                batteryUnrestricted = isBatteryOptimizationDisabled(context)
                            } else {
                                context.startActivity(
                                    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                                        .setData(Uri.parse("package:${context.packageName}"))
                                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                                )
                            }
                        },
                    ) {
                        Text(if (batteryUnrestricted) "Настройки приложения" else "Разрешить фоновую работу")
                    }
                }
                if (selected == ScreenOffMode.SAVE_BATTERY) {
                    TextButton(onClick = { onConfigureBatterySaving(selected) }) {
                        Text("Настроить таймер экономии")
                    }
                }
            }
        },
        title = {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = "Работа при выключенном экране",
                    modifier = Modifier.weight(1f),
                )
                IconButton(
                    onClick = onDismiss,
                    modifier = Modifier.remoteIconButtonFocus(),
                ) {
                    Icon(Icons.Default.Close, contentDescription = "Закрыть")
                }
            }
        },
        confirmButton = {
            Button(onClick = { onApply(selected) }) { Text("Сохранить") }
        },
    )
}
