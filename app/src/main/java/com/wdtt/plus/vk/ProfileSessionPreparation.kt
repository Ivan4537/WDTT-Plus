package com.wdtt.plus.vk

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

@Composable
internal fun ProfileSessionPreparation(status: String, failed: Boolean, close: () -> Unit) {
    Box(Modifier.fillMaxSize().background(Color.Black.copy(alpha = .58f)).systemBarsPadding(),
        contentAlignment = Alignment.Center) {
        Surface(Modifier.fillMaxWidth().padding(12.dp), shape = RoundedCornerShape(24.dp)) {
            Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("ВК-хеши", Modifier.weight(1f), style = MaterialTheme.typography.titleLarge)
                    IconButton(onClick = close) { Icon(Icons.Default.Close, "Закрыть") }
                }
                Text(status, color = if (failed) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
                if (!failed) LinearProgressIndicator(Modifier.fillMaxWidth())
            }
        }
    }
}
