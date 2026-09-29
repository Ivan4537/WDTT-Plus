package com.wdtt.plus

import org.junit.Assert.*
import org.junit.Test

class ConnectionDiagnosticsTest {
    @Test fun modesHaveUnambiguousDatagramPolicy() {
        assertEquals("UDP", connectionModeDiagnostic(false).status)
        assertEquals("TCP/TLS", connectionModeDiagnostic(true).status)
        assertTrue(connectionModeDiagnostic(true).details.contains("HTTP/3 запрещены"))
        assertTrue(connectionModeDiagnostic(false).details.contains("пауза", ignoreCase = true))
        assertTrue(connectionModeDiagnostic(false).details.contains("рабочих UDP-каналов нет"))
        for (mode in listOf(false, true)) assertTrue(connectionModeDiagnostic(mode).details.contains("восстанавливаются"))
    }
    @Test fun eventParserRejectsUnknownAndStaleValues() {
        assertNull(connectionEventLog("READY 3 tcp", 4))
        assertNull(connectionEventLog("READY 4 arbitrary-secret", 4))
        assertNull(connectionEventLog("READY 4 tcp trailing-secret", 4))
        assertNull(connectionEventLog("UDP_BACKOFF 3", 4))
        assertEquals("Сервер ответил · TCP ✓", connectionEventLog("READY 4 tcp", 4)?.message)
    }
    @Test fun connectionEventsAreNotConfusedWithProxyAutoMode() {
        for (event in listOf("TRY tls-front", "READY 0 tls-front", "PAUSED limit", "UDP_BACKOFF 0")) {
            val result = connectionEventLog(event, 0)!!
            assertFalse(result.message.contains("Авто"))
        }
        assertTrue(connectionEventLog("UDP_BACKOFF 0", 0)!!.warning)
    }
    @Test fun confirmedTransportsRemainSeparateInAggregatedLogs() {
        val udp = connectionEventLog("READY 4 udp", 4)!!
        val tcp = connectionEventLog("READY 4 tcp", 4)!!
        assertNotEquals(udp.key, tcp.key)
        assertTrue(udp.message.contains("UDP ✓"))
        assertTrue(tcp.message.contains("TCP ✓"))
        assertTrue(connectionEventLog("UDP_PARTIAL 4", 4)!!.message.contains("Остальные UDP-каналы работают"))
        assertNull(connectionEventLog("UDP_PARTIAL 3", 4))
    }
    @Test fun failuresShowStageAndDurationWithoutRawErrorText() {
        val failure = connectionEventLog("FAILED 4 udp dtls timeout 8002", 4)!!
        assertTrue(failure.warning)
        assertTrue(failure.message.contains("защищённое соединение с сервером"))
        assertTrue(failure.message.contains("8 с"))
        for (event in listOf(
            "FAILED 3 udp dtls timeout 8002", "FAILED 4 udp dtls timeout -1",
            "FAILED 4 udp secret timeout 8002", "FAILED 4 udp dtls secret 8002",
            "FAILED 4 udp dtls timeout 8002 extra", "FAILED 4 unknown dtls timeout 8002",
        )) assertNull(connectionEventLog(event, 4))
    }
}
