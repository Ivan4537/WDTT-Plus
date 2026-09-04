package com.wdtt.plus.ui

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.border
import androidx.compose.foundation.focusable
import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.composed
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.draw.clip
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.semantics.Role
import androidx.compose.material3.MaterialTheme
import com.wdtt.plus.isTelevisionDevice

@Composable
internal fun isTelevisionDevice(): Boolean {
    val configuration = LocalConfiguration.current
    val context = LocalContext.current
    return remember(configuration.uiMode, context) {
        isTelevisionDevice(context)
    }
}

/**
 * Makes keyboard/D-pad focus unmistakable on custom clickable surfaces.
 * Material controls already expose their own focus target; this modifier only
 * observes it, so one remote press never has to pass through a duplicate target.
 */
internal fun Modifier.remoteFocusOutline(
    shape: Shape = RoundedCornerShape(16.dp),
    enabled: Boolean = true,
    focusedScale: Float = 1f,
): Modifier = composed {
    if (!enabled) return@composed this

    var focused by remember { mutableStateOf(false) }
    val scale by animateFloatAsState(
        targetValue = if (focused) focusedScale.coerceAtLeast(1f) else 1f,
        label = "remote_focus_scale",
    )
    val borderColor = if (focused) {
        MaterialTheme.colorScheme.primary
    } else {
        androidx.compose.ui.graphics.Color.Transparent
    }

    this
        .onFocusChanged { focused = it.isFocused }
        .then(
            if (focusedScale > 1f) {
                Modifier.graphicsLayer {
                    scaleX = scale
                    scaleY = scale
                }
            } else {
                Modifier
            }
        )
        .border(width = 2.dp, color = borderColor, shape = shape)
        .clip(shape)
}

internal fun Modifier.remoteSwitchFocus(enabled: Boolean = true): Modifier =
    remoteFocusOutline(
        shape = RoundedCornerShape(percent = 50),
        enabled = enabled,
        focusedScale = 1.06f,
    )

internal fun Modifier.remoteToggleableRow(
    value: Boolean,
    enabled: Boolean = true,
    shape: Shape = RoundedCornerShape(14.dp),
    onValueChange: (Boolean) -> Unit,
): Modifier = this
    .remoteFocusOutline(shape = shape, enabled = enabled)
    .toggleable(
        value = value,
        enabled = enabled,
        role = Role.Switch,
        onValueChange = onValueChange,
    )

internal fun Modifier.remoteCompactFocus(
    shape: Shape = CircleShape,
    enabled: Boolean = true,
): Modifier = remoteFocusOutline(shape, enabled, focusedScale = 1.08f)

/** A stable circular focus ring for small icon buttons. */
internal fun Modifier.remoteIconButtonFocus(enabled: Boolean = true): Modifier =
    remoteFocusOutline(shape = CircleShape, enabled = enabled)

internal fun Modifier.remoteHelpFocus(enabled: Boolean = true): Modifier =
    remoteIconButtonFocus(enabled)

/** Keeps informational dialogs comfortably wide on TV without changing phone sizing. */
internal fun Modifier.televisionDialogWidth(
    television: Boolean,
    fraction: Float = 0.78f,
    maxWidth: Dp = 920.dp,
): Modifier = if (television) {
    fillMaxWidth(fraction.coerceIn(0.5f, 0.96f)).widthIn(max = maxWidth)
} else {
    this
}

/** A readable, non-clickable list row that can carry D-pad focus and auto-scroll. */
internal fun Modifier.remoteReadableItem(
    shape: Shape = RoundedCornerShape(8.dp),
): Modifier = this
    .remoteFocusOutline(shape)
    .focusable()

internal fun tvDpadScrollDeltaPx(
    forward: Boolean,
    canScrollBackward: Boolean,
    canScrollForward: Boolean,
    viewportSizePx: Int,
    minimumStepPx: Float,
): Float {
    val canScroll = if (forward) canScrollForward else canScrollBackward
    if (!canScroll) return 0f
    val step = maxOf(minimumStepPx, viewportSizePx.coerceAtLeast(0) * 0.16f)
    return if (forward) step else -step
}

/**
 * Gives a read-only scroll viewport its own visible TV focus target. While the
 * viewport itself is focused, every D-pad press moves the text by a small,
 * deterministic step. At either edge the event is released, allowing normal
 * focus navigation to the close/action buttons. Child controls keep their
 * ordinary D-pad behavior because only direct viewport focus is handled.
 */
internal fun Modifier.tvDpadScrollable(
    scrollState: ScrollState,
    television: Boolean,
    requestInitialFocus: Boolean = true,
    shape: Shape = RoundedCornerShape(12.dp),
): Modifier = composed {
    if (!television) return@composed this

    val focusRequester = remember { FocusRequester() }
    val minimumStepPx = with(LocalDensity.current) { 56.dp.toPx() }
    var directlyFocused by remember { mutableStateOf(false) }

    LaunchedEffect(requestInitialFocus) {
        if (requestInitialFocus) focusRequester.requestFocus()
    }

    this
        .focusRequester(focusRequester)
        .onPreviewKeyEvent { event ->
            if (!directlyFocused || event.type != KeyEventType.KeyDown) {
                return@onPreviewKeyEvent false
            }
            val forward = when (event.key) {
                Key.DirectionDown -> true
                Key.DirectionUp -> false
                else -> return@onPreviewKeyEvent false
            }
            val delta = tvDpadScrollDeltaPx(
                forward = forward,
                canScrollBackward = scrollState.canScrollBackward,
                canScrollForward = scrollState.canScrollForward,
                viewportSizePx = scrollState.viewportSize,
                minimumStepPx = minimumStepPx,
            )
            if (delta == 0f) {
                false
            } else {
                scrollState.dispatchRawDelta(delta)
                true
            }
        }
        .remoteFocusOutline(shape = shape)
        .onFocusChanged { directlyFocused = it.isFocused }
        .focusable()
}
