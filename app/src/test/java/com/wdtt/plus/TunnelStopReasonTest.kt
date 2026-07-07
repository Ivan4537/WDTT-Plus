package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class TunnelStopReasonTest {
    @Test
    fun stoppedSession_preservesTrafficAndAddsReason() {
        val result = buildStoppedSessionStats(
            "Активных: 4 | ↓12.34 МБ / ↑5.67 МБ",
            TunnelStopReason.NetworkRecoveryFailed
        )

        assertEquals(
            "VPN отключён · Причина: связь не восстановилась после ошибки сети · " +
                "Активных: 0 · ↓12.34 МБ / ↑5.67 МБ",
            result
        )
    }

    @Test
    fun stoppedSession_withoutReceivedStatsDoesNotInventTraffic() {
        val result = buildStoppedSessionStats("Ожидание данных...", TunnelStopReason.User)

        assertEquals("VPN отключён · Причина: отключено пользователем · Активных: 0", result)
        assertFalse(result.contains("↓"))
    }

    @Test
    fun trustedWifiSessionUsesWaitingText() {
        val result = buildStoppedSessionStats(
            "Активных: 2 | ↓1.00 МБ / ↑0.50 МБ",
            TunnelStopReason.TrustedWifi
        )

        assertEquals(
            "VPN в ожидании · Причина: подключена доверенная сеть Wi-Fi · " +
                "Активных: 0 · ↓1.00 МБ / ↑0.50 МБ",
            result
        )
    }
}
