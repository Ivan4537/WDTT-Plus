package com.wdtt.plus.ui

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp

/** Shared check/cancel control without a rectangular pressed background. */
@OptIn(ExperimentalFoundationApi::class)
@Composable
internal fun CheckActionIcon(
    checking: Boolean,
    enabled: Boolean = true,
    idleIcon: ImageVector,
    description: String,
    cancelDescription: String,
    onClick: () -> Unit,
    onLongClick: (() -> Unit)? = null,
) {
    val showHint = rememberIconHint(description)
    Box(
        modifier = Modifier.size(40.dp).clip(CircleShape)
            .remoteIconButtonFocus(enabled = enabled)
            .combinedClickable(
                interactionSource = remember { MutableInteractionSource() },
                indication = null,
                enabled = enabled,
                role = Role.Button,
                onClick = onClick,
                onLongClick = if (checking) null else onLongClick ?: showHint,
            ),
        contentAlignment = Alignment.Center,
    ) {
        val color = MaterialTheme.colorScheme.primary.copy(alpha = if (enabled) 1f else 0.42f)
        if (checking) {
            CircularProgressIndicator(Modifier.size(28.dp), color = color, strokeWidth = 2.dp)
        }
        Icon(
            if (checking) Icons.Default.Close else idleIcon,
            contentDescription = if (checking) cancelDescription else description,
            modifier = Modifier.size(if (checking) 15.dp else 21.dp),
            tint = color,
        )
    }
}
