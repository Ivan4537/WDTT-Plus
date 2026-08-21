package com.wdtt.plus.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.semantics.progressBarRangeInfo
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.setProgress
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.wdtt.plus.MAX_SLEEP_PAUSE_DELAY_MINUTES
import com.wdtt.plus.SleepBatteryMode
import com.wdtt.plus.normalizeSleepPauseDelayMinutes
import com.wdtt.plus.sleepDelayDescription
import kotlin.math.PI
import kotlin.math.atan2
import kotlin.math.cos
import kotlin.math.roundToInt
import kotlin.math.sin

internal fun adjustSleepTimerHours(totalMinutes: Int, hoursDelta: Int): Int =
    normalizeSleepPauseDelayMinutes(totalMinutes + hoursDelta * 60)

internal fun replaceSleepTimerMinuteComponent(totalMinutes: Int, minute: Int): Int {
    val normalized = normalizeSleepPauseDelayMinutes(totalMinutes)
    val hours = (normalized / 60).coerceAtMost(23)
    return normalizeSleepPauseDelayMinutes(hours * 60 + minute.coerceIn(0, 59))
}

internal fun updateSleepTimerFromDialDrag(
    totalMinutes: Int,
    previousMinute: Int,
    nextMinute: Int,
): Int {
    val previous = previousMinute.coerceIn(0, 59)
    val next = nextMinute.coerceIn(0, 59)
    var minuteDelta = next - previous
    if (minuteDelta > 30) {
        minuteDelta -= 60
    } else if (minuteDelta < -30) {
        minuteDelta += 60
    }
    return normalizeSleepPauseDelayMinutes(totalMinutes + minuteDelta)
}

internal fun formatSleepTimerDuration(totalMinutes: Int): String =
    sleepDelayDescription(totalMinutes)

@Composable
internal fun SleepTimerDialog(
    initialMode: SleepBatteryMode,
    initialPauseDelayMinutes: Int,
    initialResumeDelayMinutes: Int,
    onApply: (SleepBatteryMode, Int, Int) -> Unit,
    onDismiss: () -> Unit,
) {
    var selectedModeName by rememberSaveable(initialMode) { mutableStateOf(initialMode.name) }
    var pauseDelayMinutes by rememberSaveable(initialPauseDelayMinutes) {
        mutableIntStateOf(normalizeSleepPauseDelayMinutes(initialPauseDelayMinutes))
    }
    var resumeDelayMinutes by rememberSaveable(initialResumeDelayMinutes) {
        mutableIntStateOf(normalizeSleepPauseDelayMinutes(initialResumeDelayMinutes))
    }
    val selectedMode = SleepBatteryMode.valueOf(selectedModeName)
    val totalMinutes = when (selectedMode) {
        SleepBatteryMode.DELAYED_PAUSE -> pauseDelayMinutes
        SleepBatteryMode.TIMED_PAUSE -> resumeDelayMinutes
    }
    val onTotalMinutesChange: (Int) -> Unit = { minutes ->
        when (selectedMode) {
            SleepBatteryMode.DELAYED_PAUSE -> pauseDelayMinutes = minutes
            SleepBatteryMode.TIMED_PAUSE -> resumeDelayMinutes = minutes
        }
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        Surface(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp),
            shape = RoundedCornerShape(28.dp),
            tonalElevation = 8.dp,
            shadowElevation = 12.dp,
        ) {
            Column(
                modifier = Modifier
                    .padding(horizontal = 22.dp, vertical = 20.dp)
                    .verticalScroll(rememberScrollState()),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Box(
                    modifier = Modifier.fillMaxWidth(),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = "Таймер сна",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                    )
                    IconButton(
                        onClick = onDismiss,
                        modifier = Modifier.align(Alignment.CenterEnd),
                    ) {
                        Icon(
                            imageVector = Icons.Default.Close,
                            contentDescription = "Закрыть таймер сна",
                        )
                    }
                }
                Spacer(Modifier.height(4.dp))
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 80.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = when (selectedMode) {
                            SleepBatteryMode.DELAYED_PAUSE -> if (totalMinutes == 0) {
                                "VPN отключится сразу после выключения экрана. Интернет будет работать напрямую до включения экрана"
                            } else {
                                "VPN отключится через выбранное время. После отключения интернет будет работать напрямую до включения экрана"
                            }
                            SleepBatteryMode.TIMED_PAUSE -> if (totalMinutes == 0) {
                                "При значении 0 мин VPN останется активным после выключения экрана"
                            } else {
                                "VPN отключится сразу и включится примерно через выбранное время. Во время паузы интернет работает напрямую"
                            }
                        },
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                    )
                }
                Spacer(Modifier.height(12.dp))

                SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                    SleepBatteryMode.entries.forEachIndexed { index, mode ->
                        SegmentedButton(
                            selected = selectedMode == mode,
                            onClick = { selectedModeName = mode.name },
                            shape = SegmentedButtonDefaults.itemShape(
                                index = index,
                                count = SleepBatteryMode.entries.size,
                            ),
                            icon = {
                                StableSegmentedButtonIcon(selected = selectedMode == mode)
                            },
                            label = {
                                Text(
                                    text = when (mode) {
                                        SleepBatteryMode.DELAYED_PAUSE -> "Отключить позже"
                                        SleepBatteryMode.TIMED_PAUSE -> "Включить позже"
                                    },
                                    modifier = Modifier.width(IntrinsicSize.Min),
                                    maxLines = 2,
                                    textAlign = TextAlign.Center,
                                )
                            },
                        )
                    }
                }
                Spacer(Modifier.height(16.dp))

                SleepTimerDial(
                    totalMinutes = totalMinutes,
                    mode = selectedMode,
                    onTotalMinutesChange = onTotalMinutesChange,
                )

                Spacer(Modifier.height(14.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    OutlinedButton(
                        onClick = { onTotalMinutesChange(adjustSleepTimerHours(totalMinutes, -1)) },
                        enabled = totalMinutes > 0,
                        shape = RoundedCornerShape(14.dp),
                    ) {
                        Text("−1 ч", fontWeight = FontWeight.SemiBold)
                    }
                    Spacer(Modifier.width(12.dp))
                    OutlinedButton(
                        onClick = { onTotalMinutesChange(adjustSleepTimerHours(totalMinutes, 1)) },
                        enabled = totalMinutes < MAX_SLEEP_PAUSE_DELAY_MINUTES,
                        shape = RoundedCornerShape(14.dp),
                    ) {
                        Text("+1 ч", fontWeight = FontWeight.SemiBold)
                    }
                }

                Spacer(Modifier.height(18.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Button(onClick = { onApply(selectedMode, pauseDelayMinutes, resumeDelayMinutes) }) {
                        Text("Применить")
                    }
                }
            }
        }
    }
}

@Composable
private fun SleepTimerDial(
    totalMinutes: Int,
    mode: SleepBatteryMode,
    onTotalMinutesChange: (Int) -> Unit,
) {
    val minute = totalMinutes % 60
    val currentTotalMinutes by rememberUpdatedState(totalMinutes)
    val currentOnTotalMinutesChange by rememberUpdatedState(onTotalMinutesChange)
    val primary = MaterialTheme.colorScheme.primary
    val primaryContainer = MaterialTheme.colorScheme.primaryContainer
    val knobBorder = MaterialTheme.colorScheme.onPrimary
    val outline = MaterialTheme.colorScheme.outlineVariant
    val labelColor = MaterialTheme.colorScheme.onSurfaceVariant

    fun positionToMinute(position: Offset, size: Int): Int {
        val center = size / 2f
        val angle = atan2(position.y - center, position.x - center) + PI / 2.0
        val normalizedAngle = (angle + PI * 2.0) % (PI * 2.0)
        return ((normalizedAngle / (PI * 2.0) * 60.0).roundToInt() % 60).coerceIn(0, 59)
    }

    Box(
        modifier = Modifier
            .size(238.dp)
            .semantics {
                contentDescription = when (mode) {
                    SleepBatteryMode.DELAYED_PAUSE -> "Круговой таймер до отключения VPN"
                    SleepBatteryMode.TIMED_PAUSE -> "Круговой таймер до включения VPN"
                }
                stateDescription = formatSleepTimerDuration(totalMinutes)
                progressBarRangeInfo = ProgressBarRangeInfo(
                    current = totalMinutes.toFloat(),
                    range = 0f..MAX_SLEEP_PAUSE_DELAY_MINUTES.toFloat(),
                    steps = MAX_SLEEP_PAUSE_DELAY_MINUTES - 1,
                )
                setProgress { target ->
                    currentOnTotalMinutesChange(normalizeSleepPauseDelayMinutes(target.roundToInt()))
                    true
                }
            },
        contentAlignment = Alignment.Center,
    ) {
        Canvas(
            modifier = Modifier
                .matchParentSize()
                .pointerInput(Unit) {
                    detectTapGestures { position ->
                        currentOnTotalMinutesChange(
                            replaceSleepTimerMinuteComponent(
                                currentTotalMinutes,
                                positionToMinute(position, size.width),
                            )
                        )
                    }
                }
                .pointerInput(Unit) {
                    var previousMinute = currentTotalMinutes % 60
                    var dragTotal = currentTotalMinutes
                    detectDragGestures(
                        onDragStart = { position ->
                            dragTotal = currentTotalMinutes
                            previousMinute = positionToMinute(position, size.width)
                        },
                    ) { change, _ ->
                        val nextMinute = positionToMinute(change.position, size.width)
                        val nextTotal = updateSleepTimerFromDialDrag(
                            totalMinutes = dragTotal,
                            previousMinute = previousMinute,
                            nextMinute = nextMinute,
                        )
                        previousMinute = nextMinute
                        dragTotal = nextTotal
                        currentOnTotalMinutesChange(nextTotal)
                    }
                }
        ) {
            val center = Offset(size.width / 2f, size.height / 2f)
            val radius = size.minDimension / 2f - 18.dp.toPx()
            val minuteAngle = minute / 60f * 360f - 90f
            val angleRadians = minuteAngle / 180f * PI
            val knob = Offset(
                x = center.x + cos(angleRadians).toFloat() * radius,
                y = center.y + sin(angleRadians).toFloat() * radius,
            )

            drawCircle(
                color = primaryContainer.copy(alpha = 0.36f),
                radius = radius + 11.dp.toPx(),
                center = center,
            )
            drawCircle(
                color = outline,
                radius = radius,
                center = center,
                style = Stroke(width = 7.dp.toPx()),
            )
            repeat(60) { index ->
                val tickAngle = (index / 60f * 360f - 90f) / 180f * PI
                val major = index % 5 == 0
                val outer = radius - 7.dp.toPx()
                val inner = outer - if (major) 9.dp.toPx() else 4.dp.toPx()
                drawLine(
                    color = if (major) labelColor.copy(alpha = 0.75f) else labelColor.copy(alpha = 0.3f),
                    start = Offset(
                        center.x + cos(tickAngle).toFloat() * inner,
                        center.y + sin(tickAngle).toFloat() * inner,
                    ),
                    end = Offset(
                        center.x + cos(tickAngle).toFloat() * outer,
                        center.y + sin(tickAngle).toFloat() * outer,
                    ),
                    strokeWidth = if (major) 2.dp.toPx() else 1.dp.toPx(),
                    cap = StrokeCap.Round,
                )
            }
            if (minute > 0) {
                drawArc(
                    color = primary,
                    startAngle = -90f,
                    sweepAngle = minute / 60f * 360f,
                    useCenter = false,
                    topLeft = Offset(center.x - radius, center.y - radius),
                    size = androidx.compose.ui.geometry.Size(radius * 2f, radius * 2f),
                    style = Stroke(width = 7.dp.toPx(), cap = StrokeCap.Round),
                )
            }
            drawLine(
                color = primary.copy(alpha = 0.7f),
                start = center,
                end = knob,
                strokeWidth = 4.dp.toPx(),
                cap = StrokeCap.Round,
            )
            drawCircle(color = knobBorder, radius = 15.dp.toPx(), center = knob)
            drawCircle(color = primary, radius = 12.dp.toPx(), center = knob)
            drawCircle(
                color = Color.White.copy(alpha = 0.85f),
                radius = 3.dp.toPx(),
                center = knob + Offset(x = -4.dp.toPx(), y = -4.dp.toPx()),
            )
        }

        Text("0", modifier = Modifier.align(Alignment.TopCenter).padding(top = 3.dp), color = labelColor, fontSize = 11.sp)
        Text("15", modifier = Modifier.align(Alignment.CenterEnd).padding(end = 1.dp), color = labelColor, fontSize = 11.sp)
        Text("30", modifier = Modifier.align(Alignment.BottomCenter).padding(bottom = 3.dp), color = labelColor, fontSize = 11.sp)
        Text("45", modifier = Modifier.align(Alignment.CenterStart).padding(start = 1.dp), color = labelColor, fontSize = 11.sp)

        Surface(
            modifier = Modifier.size(122.dp),
            shape = CircleShape,
            color = MaterialTheme.colorScheme.surface,
            tonalElevation = 3.dp,
            shadowElevation = 2.dp,
        ) {
            Column(
                modifier = Modifier.padding(8.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                Text(
                    text = formatSleepTimerDuration(totalMinutes),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    textAlign = TextAlign.Center,
                )
                Text(
                    text = when (mode) {
                        SleepBatteryMode.DELAYED_PAUSE -> "до отключения"
                        SleepBatteryMode.TIMED_PAUSE ->
                            if (totalMinutes == 0) "VPN активен" else "до включения"
                    },
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
            }
        }
    }
}
