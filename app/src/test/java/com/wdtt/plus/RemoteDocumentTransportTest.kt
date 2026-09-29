package com.wdtt.plus

import java.io.IOException
import java.util.concurrent.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Test

class RemoteDocumentTransportTest {
    @Test
    fun `direct response stays authoritative and does not use tunnel`() = runBlocking {
        var tunnelCalled = false

        val result = requestRemoteDocumentWithTunnelFallback(
            directRequest = { RemoteDocumentHttpResponse(409, "direct") },
            tunnelRequest = {
                tunnelCalled = true
                OpaqueHttpsRelayResult.Success(200, "relay", "")
            },
        )

        assertEquals(409, result.status)
        assertEquals("direct", result.body)
        assertFalse(tunnelCalled)
    }

    @Test
    fun `transport failure retries once through active tunnel`() = runBlocking {
        val result = requestRemoteDocumentWithTunnelFallback(
            directRequest = { throw IOException("direct route unavailable") },
            tunnelRequest = {
                OpaqueHttpsRelayResult.Success(200, "relay", "")
            },
        )

        assertEquals(200, result.status)
        assertEquals("relay", result.body)
    }

    @Test
    fun `preferred tunnel avoids blocked physical request`() = runBlocking {
        var directCalled = false

        val result = requestRemoteDocumentWithTunnelFallback(
            directRequest = {
                directCalled = true
                throw IOException("physical network is allowlisted")
            },
            tunnelRequest = {
                OpaqueHttpsRelayResult.Success(200, "relay", "")
            },
            preferTunnel = true,
        )

        assertEquals(200, result.status)
        assertEquals("relay", result.body)
        assertFalse(directCalled)
    }

    @Test
    fun `preferred unavailable tunnel falls back to physical request`() = runBlocking {
        val result = requestRemoteDocumentWithTunnelFallback(
            directRequest = { RemoteDocumentHttpResponse(200, "direct") },
            tunnelRequest = {
                OpaqueHttpsRelayResult.Unavailable("tunnel unavailable")
            },
            preferTunnel = true,
        )

        assertEquals(200, result.status)
        assertEquals("direct", result.body)
    }

    @Test
    fun `unavailable tunnel preserves original transport failure`() {
        val directError = IOException("direct route unavailable")

        val thrown = assertThrows(IOException::class.java) {
            runBlocking {
                requestRemoteDocumentWithTunnelFallback(
                    directRequest = { throw directError },
                    tunnelRequest = {
                        OpaqueHttpsRelayResult.Unavailable("tunnel unavailable")
                    },
                )
            }
        }

        assertSame(directError, thrown)
    }

    @Test
    fun `cancelled request never starts tunnel fallback`() {
        var tunnelCalled = false

        assertThrows(CancellationException::class.java) {
            runBlocking {
                requestRemoteDocumentWithTunnelFallback(
                    directRequest = { throw CancellationException("cancelled") },
                    tunnelRequest = {
                        tunnelCalled = true
                        OpaqueHttpsRelayResult.Success(200, "relay", "")
                    },
                )
            }
        }

        assertFalse(tunnelCalled)
    }
}
