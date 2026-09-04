package com.wdtt.plus

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnSlotHandoverPolicyTest {
    @Test
    fun `safe establish refusal yields instead of retrying or taking the slot`() {
        assertTrue(
            shouldYieldVpnSlotAfterSafeEstablishFailure(
                SafeGoBackend.VpnSlotUnavailableException(),
            ),
        )
        assertTrue(
            shouldYieldVpnSlotAfterSafeEstablishFailure(
                IllegalStateException("start failed", SafeGoBackend.VpnSlotUnavailableException()),
            ),
        )
    }

    @Test
    fun `ordinary tunnel failure keeps the established recovery path available`() {
        assertFalse(
            shouldYieldVpnSlotAfterSafeEstablishFailure(
                IllegalStateException("DNS unavailable"),
            ),
        )
    }
}
