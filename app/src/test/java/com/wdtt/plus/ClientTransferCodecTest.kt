package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ClientTransferCodecTest {
    @Test
    fun clientTransfer_roundTripsOnlyPortableFields() {
        val source = ClientTransferPayload(
            password = "ABCDEFGHJKLMNPQR",
            label = "Телефон папы",
            vkHash = "abcdefghijklmnop,qrstuvwxyzABCDEF",
            expiresAt = 1_900_000_000,
            deactivated = true,
            createdAt = 12345
        )

        val encoded = ClientTransferCodec.encode(source)

        assertEquals(source, ClientTransferCodec.decode(encoded))
        assertTrue(ClientTransferCodec.isClientTransfer(encoded))
        assertFalse(encoded.contains("device_id"))
        assertFalse(encoded.contains("down_bytes"))
        assertFalse(encoded.contains("ports"))
        assertFalse(encoded.contains("host"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun clientTransfer_rejectsUnsafePassword() {
        ClientTransferCodec.decode(
            """{"format":"wdtt-plus-client","version":1,"password":"bad password","expires_at":0}"""
        )
    }

    @Test
    fun clientPasswordRules_matchServerAlphabet() {
        assertEquals(null, ClientPasswordRules.validate("ABCDEFGHJKLMNPQR"))
        assertTrue(ClientPasswordRules.validate("ABCDEFGHJKLMNPQ0") != null)
        assertTrue(ClientPasswordRules.validate("short") != null)
    }

    @Test(expected = IllegalArgumentException::class)
    fun clientTransfer_rejectsUnknownVersion() {
        ClientTransferCodec.decode(
            """{"format":"wdtt-plus-client","version":99,"password":"ABCDEFGHJKLMNPQR","expires_at":0}"""
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun clientTransfer_rejectsBrokenHash() {
        ClientTransferCodec.decode(
            """{"format":"wdtt-plus-client","version":1,"password":"ABCDEFGHJKLMNPQR","vk_hash":"bad/path","expires_at":0}"""
        )
    }
}
