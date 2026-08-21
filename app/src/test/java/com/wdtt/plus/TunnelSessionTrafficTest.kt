package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Test

class TunnelSessionTrafficTest {
    @Test
    fun notificationUsesGigabytesAfterOneGigabyte() {
        assertEquals(
            "Активных: 18 | ↓1.50 ГБ / ↑1.00 ГБ",
            formatTunnelTrafficForNotification(
                "Активных: 18 | ↓1536.00 МБ / ↑1024.00 МБ",
            ),
        )
    }

    @Test
    fun notificationKeepsSmallerDirectionInMegabytes() {
        assertEquals(
            "Активных: 18 | ↓1.25 ГБ / ↑512.25 МБ",
            formatTunnelTrafficForNotification(
                "Активных: 18 | ↓1280,00 МБ / ↑512.25 МБ",
            ),
        )
    }

    @Test
    fun notificationKeepsTrafficBelowOneGigabyteInMegabytes() {
        assertEquals(
            "Активных: 9 | ↓1023.99 МБ / ↑10.00 МБ",
            formatTunnelTrafficForNotification(
                "Активных: 9 | ↓1023.99 МБ / ↑10.00 МБ",
            ),
        )
    }

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

    @Test
    fun restoredServiceContinuesTheSameTrafficSession() {
        val beforeProcessRestart = TunnelSessionTrafficAccumulator()
        beforeProcessRestart.accumulate("Активных: 9 | ↓12.50 МБ / ↑3.25 МБ")

        val afterProcessRestart = TunnelSessionTrafficAccumulator()
        afterProcessRestart.restore(beforeProcessRestart.snapshot())

        assertEquals(
            "Активных: 9 | ↓13.00 МБ / ↑3.35 МБ",
            afterProcessRestart.accumulate("Активных: 9 | ↓0.50 МБ / ↑0.10 МБ"),
        )
    }

    @Test
    fun invalidPersistedTrafficSnapshotIsIgnored() {
        val accumulator = TunnelSessionTrafficAccumulator()
        accumulator.restore(
            TunnelSessionTrafficSnapshot(
                downloadOffsetMb = Double.NaN,
                uploadOffsetMb = 1.0,
                lastRawDownloadMb = 2.0,
                lastRawUploadMb = 3.0,
            ),
        )

        assertEquals(
            "Активных: 9 | ↓0.25 МБ / ↑0.10 МБ",
            accumulator.accumulate("Активных: 9 | ↓0.25 МБ / ↑0.10 МБ"),
        )
    }
}
