package com.wdtt.plus.ui

import org.junit.Assert.assertEquals
import org.junit.Test

class TvSteppedSliderTest {
    @Test
    fun dpadChangesSliderByOneStep() {
        assertEquals(27f, steppedSliderValue(18f, 9f..45f, 9f, 1), 0f)
        assertEquals(9f, steppedSliderValue(18f, 9f..45f, 9f, -1), 0f)
    }

    @Test
    fun dpadSliderStopsAtBounds() {
        assertEquals(9f, steppedSliderValue(9f, 9f..45f, 9f, -1), 0f)
        assertEquals(45f, steppedSliderValue(45f, 9f..45f, 9f, 1), 0f)
    }
}
