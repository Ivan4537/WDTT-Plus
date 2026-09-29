package com.wdtt.plus.ui

import androidx.compose.foundation.layout.*
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.tween
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.HelpOutline
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties

/** Bound the native window before its content is measured. A full-height
 * WRAP_CONTENT Dialog can otherwise extend under Android's navigation bar.
 * Read insets in the caller, not inside the dialog where they may be zero. */
@Composable
internal fun BoundedAppDialog(
    onDismissRequest: () -> Unit,
    properties: DialogProperties = DialogProperties(usePlatformDefaultWidth = false),
    content: @Composable () -> Unit,
) {
    val availableHeight = availableDialogHeight()
    Dialog(onDismissRequest = onDismissRequest, properties = properties) {
        Box(Modifier.heightIn(max = availableHeight)) {
            content()
        }
    }
}

@Composable
private fun availableDialogHeight(): Dp {
    val configuration = LocalConfiguration.current
    val density = LocalDensity.current
    val safeInsets = WindowInsets.safeDrawing
    return with(density) {
        (configuration.screenHeightDp.dp - safeInsets.getTop(this).toDp() -
            safeInsets.getBottom(this).toDp() - 24.dp).coerceAtLeast(1.dp)
    }
}

/** Keep standard alert actions outside the scrollable information area. */
@Composable
internal fun BoundedAlertDialog(
    onDismissRequest: () -> Unit,
    confirmButton: @Composable () -> Unit,
    modifier: Modifier = Modifier,
    dismissButton: (@Composable () -> Unit)? = null,
    icon: (@Composable () -> Unit)? = null,
    title: (@Composable () -> Unit)? = null,
    text: (@Composable () -> Unit)? = null,
    shape: Shape = AlertDialogDefaults.shape,
    containerColor: Color = AlertDialogDefaults.containerColor,
    iconContentColor: Color = AlertDialogDefaults.iconContentColor,
    titleContentColor: Color = AlertDialogDefaults.titleContentColor,
    textContentColor: Color = AlertDialogDefaults.textContentColor,
    tonalElevation: Dp = AlertDialogDefaults.TonalElevation,
    properties: DialogProperties = DialogProperties(),
    scrollableText: Boolean = true,
) {
    val availableHeight = availableDialogHeight()
    val scrollState = rememberScrollState()
    val television = isTelevisionDevice()
    AlertDialog(
        onDismissRequest = onDismissRequest,
        confirmButton = confirmButton,
        modifier = modifier.heightIn(max = availableHeight),
        dismissButton = dismissButton,
        icon = icon,
        title = title,
        text = text?.let { body ->
            {
                if (scrollableText) {
                    Box(Modifier.verticalScroll(scrollState)
                        .tvDpadScrollable(scrollState, television)) { body() }
                } else {
                    body()
                }
            }
        },
        shape = shape,
        containerColor = containerColor,
        iconContentColor = iconContentColor,
        titleContentColor = titleContentColor,
        textContentColor = textContentColor,
        tonalElevation = tonalElevation,
        properties = properties,
    )
}

/** Uses the dialog's actual viewport, including system bars and the keyboard. */
@Composable
internal fun SettingsDialogLayout(
    title: String,
    onDismiss: () -> Unit,
    onHelp: (() -> Unit)? = null,
    animateSize: Boolean = false,
    secure: Boolean = false,
    footer: (@Composable () -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    val television = isTelevisionDevice()
    val scrollState = rememberScrollState()
    BoundedAppDialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(
            usePlatformDefaultWidth = false,
            decorFitsSystemWindows = true,
            securePolicy = if (secure) androidx.compose.ui.window.SecureFlagPolicy.SecureOn else androidx.compose.ui.window.SecureFlagPolicy.Inherit,
        ),
    ) {
        BoxWithConstraints(
            modifier = Modifier.fillMaxSize().padding(12.dp),
            contentAlignment = Alignment.Center,
        ) {
            Surface(
                modifier = Modifier.widthIn(max = if (television) 920.dp else 560.dp)
                    .fillMaxWidth(if (television) 0.78f else 1f)
                    // Center the animated bounds so expansion lifts the top edge
                    // smoothly while revealing the additional content below.
                    .then(if (animateSize) Modifier.animateContentSize(tween(250), alignment = Alignment.TopCenter) else Modifier)
                    .heightIn(max = maxHeight),
                shape = RoundedCornerShape(24.dp),
                color = MaterialTheme.colorScheme.surface,
                contentColor = MaterialTheme.colorScheme.onSurface,
                tonalElevation = 8.dp,
            ) {
                Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Row(Modifier.weight(1f), verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                title,
                                modifier = Modifier.weight(1f, fill = false),
                                style = MaterialTheme.typography.titleLarge,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.primary,
                            )
                            if (onHelp != null) {
                                HintIconButton(hint = "Справка: $title", onClick = onHelp, modifier = Modifier.remoteHelpFocus()) {
                                    Icon(Icons.AutoMirrored.Filled.HelpOutline, contentDescription = "Справка: $title")
                                }
                            }
                        }
                        IconButton(onClick = onDismiss, modifier = Modifier.remoteIconButtonFocus()) {
                            Icon(Icons.Default.Close, contentDescription = "Закрыть")
                        }
                    }
                    Column(
                        modifier = Modifier.weight(1f, fill = false).fillMaxWidth()
                            .verticalScroll(scrollState).tvDpadScrollable(scrollState, television),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                        content = content,
                    )
                    if (footer != null) {
                        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                        footer()
                    }
                }
            }
        }
    }
}
