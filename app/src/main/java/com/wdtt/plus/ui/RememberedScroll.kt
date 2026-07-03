package com.wdtt.plus.ui

import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableIntState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeoutOrNull

@Composable
fun rememberRememberedScrollState(savedPosition: MutableIntState): ScrollState {
    val scrollState = rememberScrollState(initial = savedPosition.intValue)
    var restored by remember { mutableStateOf(false) }

    LaunchedEffect(scrollState) {
        val target = savedPosition.intValue
        if (target > 0) {
            withTimeoutOrNull(900) {
                snapshotFlow { scrollState.maxValue }
                    .filter { maxValue -> maxValue >= target }
                    .first()
            }
            scrollState.scrollTo(target.coerceIn(0, scrollState.maxValue))
        }
        restored = true
    }

    LaunchedEffect(scrollState, restored) {
        if (!restored) return@LaunchedEffect
        snapshotFlow { scrollState.value }.collect { position ->
            savedPosition.intValue = position
        }
    }

    return scrollState
}

@Composable
fun rememberRememberedLazyListState(
    savedFirstVisibleItemIndex: MutableIntState,
    savedFirstVisibleItemScrollOffset: MutableIntState
): LazyListState {
    val listState = rememberLazyListState(
        initialFirstVisibleItemIndex = savedFirstVisibleItemIndex.intValue,
        initialFirstVisibleItemScrollOffset = savedFirstVisibleItemScrollOffset.intValue
    )
    var restored by remember { mutableStateOf(false) }

    LaunchedEffect(listState) {
        val targetIndex = savedFirstVisibleItemIndex.intValue
        val targetOffset = savedFirstVisibleItemScrollOffset.intValue
        if (targetIndex > 0 || targetOffset > 0) {
            snapshotFlow { listState.layoutInfo.totalItemsCount }
                .filter { itemCount -> itemCount > 0 }
                .first()
            val itemCount = listState.layoutInfo.totalItemsCount
            listState.scrollToItem(targetIndex.coerceAtMost(itemCount - 1), targetOffset)
        }
        restored = true
    }

    LaunchedEffect(listState, restored) {
        if (!restored) return@LaunchedEffect
        snapshotFlow {
            listState.firstVisibleItemIndex to listState.firstVisibleItemScrollOffset
        }.collect { (index, offset) ->
            savedFirstVisibleItemIndex.intValue = index
            savedFirstVisibleItemScrollOffset.intValue = offset
        }
    }

    return listState
}
