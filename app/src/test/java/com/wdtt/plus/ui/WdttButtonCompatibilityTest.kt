package com.wdtt.plus.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class WdttButtonCompatibilityTest {
    @Test
    fun `contrast workaround is limited to Xiaomi device families`() {
        assertTrue(needsMiuiFilledButtonContrastWorkaround("Xiaomi", "Xiaomi"))
        assertTrue(needsMiuiFilledButtonContrastWorkaround("Xiaomi", "Redmi"))
        assertTrue(needsMiuiFilledButtonContrastWorkaround("unknown", "POCO"))

        assertFalse(needsMiuiFilledButtonContrastWorkaround("Samsung", "samsung"))
        assertFalse(needsMiuiFilledButtonContrastWorkaround("Google", "google"))
        assertFalse(needsMiuiFilledButtonContrastWorkaround("OnePlus", "OnePlus"))
        assertFalse(needsMiuiFilledButtonContrastWorkaround("", ""))
    }
}
