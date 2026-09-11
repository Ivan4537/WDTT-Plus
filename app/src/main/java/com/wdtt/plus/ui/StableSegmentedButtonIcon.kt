package com.wdtt.plus.ui

import androidx.compose.runtime.Composable

/**
 * Выбранный сегмент уже однозначно обозначен заливкой. Пустой icon slot не
 * отнимает ширину у подписи и сохраняет единый API существующих кнопок.
 */
@Composable
@Suppress("UNUSED_PARAMETER")
internal fun StableSegmentedButtonIcon(selected: Boolean) = Unit
