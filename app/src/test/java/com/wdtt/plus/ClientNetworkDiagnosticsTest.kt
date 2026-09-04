package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ClientNetworkDiagnosticsTest {
    @Test
    fun vkDiagnosticsTreatModernVkCallsHostsAsPrimaryAndLegacyHostsAsReserve() {
        assertTrue("api.vk.me" in primaryVkDiagnosticHosts)
        assertTrue("calls.okcdn.ru" in primaryVkDiagnosticHosts)
        assertTrue("vk.ru" in reserveVkDiagnosticHosts)
        assertTrue("login.vk.ru" in reserveVkDiagnosticHosts)
        assertTrue("api.vk.ru" in reserveVkDiagnosticHosts)
        assertTrue("id.vk.ru" in reserveVkDiagnosticHosts)
        assertTrue("static.vk.ru" in reserveVkDiagnosticHosts)
        assertTrue("vk.com" in reserveVkDiagnosticHosts)
        assertTrue(primaryVkDiagnosticHosts.intersect(reserveVkDiagnosticHosts).isEmpty())
        assertEquals("api.vk.me", clientDnsProbeHost)
    }

    @Test
    fun clientDnsPath_usesSystemFallbackWithoutReportingFailure() {
        val result = assessClientDnsPath(emptySet(), systemPrimaryApiWorks = true)

        assertEquals("прямой DNS недоступен, используется системный DNS", result.status)
        assertEquals(DeviceCheckSeverity.Info, result.severity)
        assertEquals(null, result.action)
    }

    @Test
    fun clientDnsPath_acceptsSecondaryUdpRoute() {
        val result = assessClientDnsPath(setOf("77.88.8.1 UDP"), systemPrimaryApiWorks = false)

        assertEquals("резервный UDP DNS доступен", result.status)
        assertEquals(DeviceCheckSeverity.Info, result.severity)
        assertEquals(null, result.action)
    }

    @Test
    fun clientDnsPath_prefersSecondaryUdpOverPrimaryTcp() {
        val result = assessClientDnsPath(
            setOf("77.88.8.8 TCP", "77.88.8.1 UDP"),
            systemPrimaryApiWorks = true
        )

        assertEquals("резервный UDP DNS доступен", result.status)
        assertEquals(DeviceCheckSeverity.Info, result.severity)
    }

    @Test
    fun clientDnsPath_acceptsTcpFallback() {
        val result = assessClientDnsPath(setOf("77.88.8.8 TCP"), systemPrimaryApiWorks = false)

        assertEquals("UDP DNS недоступен, TCP отвечает", result.status)
        assertEquals(DeviceCheckSeverity.Info, result.severity)
        assertEquals(null, result.action)
    }

    @Test
    fun clientDnsPath_keepsPrimaryDirectRouteAheadOfSystemDns() {
        val result = assessClientDnsPath(setOf("77.88.8.8 UDP"), systemPrimaryApiWorks = true)

        assertEquals("основной UDP DNS доступен", result.status)
        assertEquals(DeviceCheckSeverity.Ok, result.severity)
        assertEquals(null, result.action)
    }

    @Test
    fun clientDnsPath_reportsFailureOnlyWhenEveryRouteIsUnavailable() {
        val result = assessClientDnsPath(emptySet(), systemPrimaryApiWorks = false)

        assertEquals("DNS до VK недоступен", result.status)
        assertEquals(DeviceCheckSeverity.Error, result.severity)
        assertEquals(DeviceCheckAction.NetworkSettings, result.action)
    }

    @Test
    fun privateDnsWarningAppearsOnlyWhenPrivateDnsAndNetworkProblemMeet() {
        assertNull(
            buildPrivateDnsProblemItem(
                state = AndroidPrivateDnsState(active = false),
                dnsProblem = true,
                httpsProblem = true,
            )
        )
        assertNull(
            buildPrivateDnsProblemItem(
                state = AndroidPrivateDnsState(active = true, serverName = "dns.example"),
                dnsProblem = false,
                httpsProblem = false,
            )
        )

        val item = buildPrivateDnsProblemItem(
            state = AndroidPrivateDnsState(active = true, serverName = "dns.google"),
            dnsProblem = true,
            httpsProblem = false,
        )

        assertEquals("Android Private DNS", item?.title)
        assertEquals("включён (dns.google)", item?.status)
        assertEquals(DeviceCheckSeverity.Warning, item?.severity)
        assertEquals(DeviceCheckAction.NetworkSettings, item?.action)
        assertTrue(item?.recommendation?.contains("Частный DNS") == true)
    }

    @Test
    fun privateDnsRecommendationTailIsConditional() {
        assertEquals("", privateDnsRecommendationTail(AndroidPrivateDnsState(active = false)))
        assertEquals(
            ", а также Android Private DNS",
            privateDnsRecommendationTail(AndroidPrivateDnsState(active = true, serverName = "dns.google")),
        )
    }

    @Test
    fun dnsQuery_containsExpectedHeaderNameAndARecordType() {
        val query = buildDnsQuery(clientDnsProbeHost, 0x1234)

        assertEquals(0x12, query[0].toInt() and 0xff)
        assertEquals(0x34, query[1].toInt() and 0xff)
        assertEquals(1, unsignedShort(query, 4))
        assertTrue(query.copyOfRange(12, query.size).containsSubsequence(byteArrayOf(3, 'a'.code.toByte(), 'p'.code.toByte(), 'i'.code.toByte())))
        assertEquals(1, unsignedShort(query, query.size - 4))
        assertEquals(1, unsignedShort(query, query.size - 2))
    }

    @Test
    fun dnsResponse_parsesAnswerCountAndFlags() {
        val response = byteArrayOf(
            0x12, 0x34,
            0x83.toByte(), 0x80.toByte(),
            0x00, 0x01,
            0x00, 0x02,
            0x00, 0x00,
            0x00, 0x00
        )

        val status = parseDnsResponse(response, 0x1234)

        assertEquals(0, status.responseCode)
        assertEquals(2, status.answerCount)
        assertTrue(status.truncated)
    }

    @Test(expected = IllegalArgumentException::class)
    fun dnsResponse_rejectsDifferentTransaction() {
        parseDnsResponse(
            byteArrayOf(
                0x55, 0x66,
                0x81.toByte(), 0x80.toByte(),
                0x00, 0x01,
                0x00, 0x01,
                0x00, 0x00,
                0x00, 0x00
            ),
            0x1234
        )
    }

    private fun unsignedShort(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    private fun ByteArray.containsSubsequence(expected: ByteArray): Boolean {
        if (expected.isEmpty() || expected.size > size) return false
        return indices.any { start ->
            start + expected.size <= size && expected.indices.all { index -> this[start + index] == expected[index] }
        }
    }
}
