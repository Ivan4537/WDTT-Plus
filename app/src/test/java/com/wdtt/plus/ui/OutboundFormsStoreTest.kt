package com.wdtt.plus.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OutboundFormsStoreTest {
    @Test
    fun keys_areScopedToVpnProfile() {
        assertEquals(
            "profile_0_external_proxy_host",
            OutboundFormsStore.key(0, "external_proxy_host")
        )
        assertEquals(
            "profile_2_external_proxy_host",
            OutboundFormsStore.key(2, "external_proxy_host")
        )
        assertEquals(
            "profile_2_external_proxy_host",
            OutboundFormsStore.key(99, "external_proxy_host")
        )
    }

    @Test
    fun secretKeys_haveSeparateEncryptedStorageName() {
        assertEquals(
            "profile_1_imported_wg_config_encrypted",
            OutboundFormsStore.encryptedKey(1, "imported_wg_config")
        )
        assertTrue(OutboundFormsStore.isSecretPlainKey("profile_1_wg_exit_password"))
        assertTrue(OutboundFormsStore.isSecretPlainKey("local_proxy_password"))
        assertFalse(OutboundFormsStore.isSecretPlainKey("profile_1_external_proxy_host"))
        assertFalse(OutboundFormsStore.isSecretPlainKey("profile_1_tun_interface"))
    }
}
