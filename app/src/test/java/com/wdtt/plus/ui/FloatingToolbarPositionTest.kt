package com.wdtt.plus.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FloatingToolbarPositionTest {
    @Test
    fun defaultBottomPositionStaysAboveNavigation() {
        assertEquals(
            1_600f,
            floatingToolbarMaxOffset(
                parentHeightPx = 2_000f,
                safeBottomPx = 100f,
                toolbarHeightPx = 100f,
                navigationReservePx = 192f,
                bottomGapPx = 8f,
                minOffsetY = 80f,
            ),
        )
    }

    @Test
    fun shortScreenClampsPositionToSafeTop() {
        assertEquals(
            80f,
            floatingToolbarMaxOffset(
                parentHeightPx = 300f,
                safeBottomPx = 80f,
                toolbarHeightPx = 100f,
                navigationReservePx = 192f,
                bottomGapPx = 8f,
                minOffsetY = 80f,
            ),
        )
    }

    @Test
    fun proxySettingsLabelUsesAvailableCardWidth() {
        assertFalse(proxySettingsButtonShowsLabel(289))
        assertTrue(proxySettingsButtonShowsLabel(290))
    }

    @Test
    fun proxyAccessInstructionsExplainBothScopes() {
        val device = proxyAccessInstructions("device", "socks5", "127.0.0.1", 1080, false)
        assertTrue(device.any { it.contains("этом телефоне") })
        assertTrue(device.any { it.contains("127.0.0.1") })
        assertTrue(device.any { it.contains("com.wdtt.plus") })
        assertTrue(device.any { it.contains("TCP и UDP") && it.contains("UDP ASSOCIATE") })

        val lan = proxyAccessInstructions("lan", "http", "192.168.1.10", 8080, true)
        assertTrue(lan.any { it.contains("второе устройство") })
        assertTrue(lan.any { it.contains("192.168.1.10") && it.contains("127.0.0.1") })
        assertTrue(lan.any { it.contains("логин и пароль") })
        assertTrue(lan.any { it.contains("только TCP") && it.contains("SOCKS5 с UDP") })

        val bothAuto = proxyAccessInstructions("both", "auto", "192.168.1.10", 1080, true)
        assertTrue(bothAuto.any { it.contains("одновременно") })
        assertTrue(bothAuto.any { it.contains("127.0.0.1:1080") && it.contains("192.168.1.10:1080") })
        assertTrue(bothAuto.any { it.contains("SOCKS5 и HTTP CONNECT") && it.contains("UDP") })
        assertTrue(bothAuto.any { it.contains("автоматически") })
    }

    @Test
    fun copiedProxySettingsContainConnectionValues() {
        assertEquals(
            "SOCKS5\nАдрес: 192.168.1.10\nПорт: 1080\nЛогин: wdtt\nПароль: secret",
            proxySettingsClipboardText(false, "192.168.1.10", 1080, true, "wdtt", "secret"),
        )
    }

    @Test
    fun runningProxySummaryShowsEveryReadyAddress() {
        assertEquals(
            "АВТО ПРОКСИ · готов: 127.0.0.1:1080 · 192.168.1.34:1080",
            proxyTunnelAddressSummary(
                mode = "auto",
                fallbackAddress = "127.0.0.1:1080",
                readyAddresses = listOf("127.0.0.1:1080", "192.168.1.34:1080"),
                running = true,
            ),
        )
    }

    @Test
    fun stoppedProxySummaryShowsConfiguredAddressesWithoutReadyClaim() {
        assertEquals(
            "АВТО ПРОКСИ · 127.0.0.1:1080 · 192.168.1.34:1080",
            proxyTunnelAddressSummary(
                mode = "auto",
                fallbackAddress = "127.0.0.1:1080",
                readyAddresses = listOf("127.0.0.1:1080", "192.168.1.34:1080"),
                running = false,
            ),
        )
    }
}
