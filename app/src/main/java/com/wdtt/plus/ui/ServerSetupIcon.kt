package com.wdtt.plus.ui

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalFoundationApi::class)
@Composable
internal fun ServerSetupIcon(
    icon: ImageVector,
    label: String,
    description: String,
    needsAttention: Boolean,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    val showHint = rememberIconHint("$label — $description")
    val colors = MaterialTheme.colorScheme
    val color = if (needsAttention) colors.error else colors.primary
    Box(
        modifier = Modifier.size(40.dp).clip(CircleShape)
            .graphicsLayer { alpha = if (enabled) 1f else 0.42f }
            .remoteIconButtonFocus(enabled = enabled)
            .combinedClickable(
                interactionSource = remember { MutableInteractionSource() },
                indication = null,
                enabled = enabled,
                role = Role.Button,
                onClick = onClick,
                onLongClick = showHint,
            )
            .semantics { stateDescription = if (needsAttention) "Нужно заполнить обязательные поля" else "Настроено" },
        contentAlignment = Alignment.Center,
    ) {
        Icon(icon, contentDescription = "$label: $description", modifier = Modifier.size(20.dp), tint = color)
    }
}
