package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Test

class TunnelSessionTrafficTest {
    @Test
    fun trafficSurvivesAnIntentionalTransportRestart() {
        val accumulator = TunnelSessionTrafficAccumulator()

        assertEquals(
            "Активных: 9 | ↓12.50 МБ / ↑3.25 МБ",
            accumulator.accumulate("Активных: 9 | ↓12.50 МБ / ↑3.25 МБ"),
        )

        accumulator.noteTransportRestart()

        assertEquals(
            "Активных: 9 | ↓13.00 МБ / ↑3.35 МБ",
            accumulator.accumulate("Активных: 9 | ↓0.50 МБ / ↑0.10 МБ"),
        )
    }

    @Test
    fun unexpectedCounterResetIsAccumulatedWithoutLosingSessionTotals() {
        val accumulator = TunnelSessionTrafficAccumulator()
        accumulator.accumulate("Активных: 9 | ↓4,00 МБ / ↑2,00 МБ")

        assertEquals(
            "Активных: 9 | ↓4.25 МБ / ↑2.50 МБ",
            accumulator.accumulate("Активных: 9 | ↓0,25 МБ / ↑0,50 МБ"),
        )
    }

    @Test
    fun newSessionStartsFromFreshCounters() {
        val accumulator = TunnelSessionTrafficAccumulator()
        accumulator.accumulate("Активных: 9 | ↓8.00 МБ / ↑1.00 МБ")
        accumulator.noteTransportRestart()
        accumulator.accumulate("Активных: 9 | ↓1.00 МБ / ↑0.50 МБ")

        accumulator.reset()

        assertEquals(
            "Активных: 9 | ↓0.25 МБ / ↑0.10 МБ",
            accumulator.accumulate("Активных: 9 | ↓0.25 МБ / ↑0.10 МБ"),
        )
    }
}
