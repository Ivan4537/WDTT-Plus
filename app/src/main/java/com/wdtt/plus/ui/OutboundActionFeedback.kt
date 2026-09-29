package com.wdtt.plus.ui

import android.content.ClipData
import android.content.ClipboardManager
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

internal data class OutboundActionFeedback(
    val summary: String,
    val category: RemoteLogCategory,
    val diagnostics: String,
)

internal fun outboundResultSummary(output: String): String {
    val lines = output.lineSequence().map { it.trim() }.filter { line ->
        Regex("^[А-Яа-яЁё]").containsMatchIn(line) &&
            classifyRemoteCommandLine(line).category != RemoteLogCategory.Technical
    }.toList()
    return lines.take(10).joinToString("\n").ifBlank { "Действие выполнено. Технические подробности доступны ниже." }
}

internal fun outboundErrorSummary(friendly: String): String {
    val text = friendly.substringBefore("Последние строки сервера:").trim()
    return if (Regex("^[А-Яа-яЁё]").containsMatchIn(text)) text
    else "Действие не выполнено. Откройте подробности для диагностики."
}

@Composable
internal fun OutboundActionMessage(feedback: OutboundActionFeedback, modifier: Modifier = Modifier) {
    var expanded by remember(feedback) { mutableStateOf(false) }
    val context = LocalContext.current
    val error = feedback.category == RemoteLogCategory.Error
    val warning = feedback.category == RemoteLogCategory.Warning
    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.medium,
        color = when {
            error -> MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.55f)
            warning -> MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.55f)
            else -> MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f)
        },
    ) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                when { error -> "Не выполнено"; warning -> "Требует внимания"; else -> "Результат" },
                fontWeight = FontWeight.SemiBold,
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(feedback.summary, style = MaterialTheme.typography.bodySmall)
            if (feedback.diagnostics.isNotBlank()) {
                TextButton(onClick = { expanded = !expanded }) {
                    Text(if (expanded) "Скрыть подробности" else "Подробности")
                }
                if (expanded) {
                    Text("Диагностический вывод. Секретные значения скрыты.", style = MaterialTheme.typography.labelSmall)
                    TextButton(onClick = {
                        context.getSystemService(ClipboardManager::class.java)?.setPrimaryClip(
                            ClipData.newPlainText("Диагностика выходного IP", feedback.summary + "\n\n" + feedback.diagnostics)
                        )
                    }) { Text("Копировать лог") }
                    SelectionContainer {
                        Text(
                            feedback.diagnostics,
                            modifier = Modifier.fillMaxWidth().heightIn(max = 280.dp).verticalScroll(rememberScrollState()),
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                        )
                    }
                }
            }
        }
    }
}
