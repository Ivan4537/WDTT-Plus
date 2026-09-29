package com.wdtt.plus.ui

import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.ime
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonColors
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.composed
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.semantics.onLongClick
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntRect
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Popup
import androidx.compose.ui.window.PopupPositionProvider
import androidx.compose.ui.window.PopupProperties
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow

private data class IconHint(val owner: Any, val message: String, val occurrence: Any = Any())
private val currentIconHint = MutableStateFlow<IconHint?>(null)

/** One notice at a time, rendered in the pressed icon's window, including dialogs. */
@Composable
internal fun rememberIconHint(message: String): () -> Unit {
    val owner = remember { Any() }
    val hint by currentIconHint.collectAsState()
    val haptic = LocalHapticFeedback.current
    val density = LocalDensity.current
    val bottomInset = maxOf(WindowInsets.safeDrawing.getBottom(density), WindowInsets.ime.getBottom(density))
    val gap = with(density) { 104.dp.roundToPx() }
    val sideGap = with(density) { 16.dp.roundToPx() }
    val maxWidth = (LocalConfiguration.current.screenWidthDp.dp - 32.dp).coerceAtLeast(1.dp)
    val position = remember(bottomInset, gap, sideGap) {
        object : PopupPositionProvider {
            override fun calculatePosition(anchorBounds: IntRect, windowSize: IntSize,
                layoutDirection: LayoutDirection, popupContentSize: IntSize): IntOffset = IntOffset(
                ((windowSize.width - popupContentSize.width) / 2).coerceAtLeast(sideGap),
                (windowSize.height - bottomInset - gap - popupContentSize.height).coerceAtLeast(sideGap),
            )
        }
    }
    if (hint?.owner === owner) {
        Popup(popupPositionProvider = position,
            properties = PopupProperties(focusable = false, dismissOnBackPress = false, dismissOnClickOutside = false)) {
            WdttInlineNotice(hint!!.message, modifier = Modifier.widthIn(max = maxWidth))
        }
        LaunchedEffect(hint) {
            val shown = hint
            delay(2_500)
            currentIconHint.compareAndSet(shown, null)
        }
    }
    DisposableEffect(owner) {
        onDispose { currentIconHint.value?.takeIf { it.owner === owner }?.let { currentIconHint.compareAndSet(it, null) } }
    }
    return {
        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
        currentIconHint.value = IconHint(owner, message)
    }
}

/** Observe the hold before the button handles release; consume only a completed hold. */
internal fun Modifier.iconHoldHint(message: String): Modifier = composed {
    val showHint by rememberUpdatedState(rememberIconHint(message))
    semantics {
        onLongClick(label = message) { showHint(); true }
    }.pointerInput(Unit) {
        awaitEachGesture {
            val down = awaitFirstDown(requireUnconsumed = false, pass = PointerEventPass.Initial)
            val cancelled = withTimeoutOrNull(viewConfiguration.longPressTimeoutMillis) {
                var ended = false
                while (!ended) {
                    val event = awaitPointerEvent(PointerEventPass.Initial)
                    val change = event.changes.firstOrNull { it.id == down.id }
                    ended = change == null || !change.pressed || change.isConsumed ||
                        (change.position - down.position).getDistance() > viewConfiguration.touchSlop ||
                        event.changes.any { it.id != down.id && it.pressed }
                }
                true
            }
            if (cancelled == null) {
                showHint()
                do {
                    val event = awaitPointerEvent(PointerEventPass.Initial)
                    event.changes.forEach { it.consume() }
                } while (event.changes.any { it.pressed })
            }
        }
    }
}

@Composable
internal fun HintIconButton(
    hint: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    colors: IconButtonColors = IconButtonDefaults.iconButtonColors(),
    interactionSource: MutableInteractionSource? = null,
    content: @Composable () -> Unit,
) {
    IconButton(onClick = onClick, modifier = modifier.iconHoldHint(hint), enabled = enabled,
        colors = colors, interactionSource = interactionSource, content = content)
}

@Composable
internal fun HintFilledTonalIconButton(
    hint: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    colors: IconButtonColors = IconButtonDefaults.filledTonalIconButtonColors(),
    interactionSource: MutableInteractionSource? = null,
    content: @Composable () -> Unit,
) {
    FilledTonalIconButton(onClick = onClick, modifier = modifier.iconHoldHint(hint),
        enabled = enabled, colors = colors, interactionSource = interactionSource, content = content)
}
