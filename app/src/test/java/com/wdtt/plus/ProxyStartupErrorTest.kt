package com.wdtt.plus

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ProxyStartupErrorTest {
    @Test
    fun `native process replacement is serialized with confirmed old process exit`() {
        val source = sequenceOf(
            File("app/src/main/java/com/wdtt/plus/TunnelManager.kt"),
            File("src/main/java/com/wdtt/plus/TunnelManager.kt"),
        ).first(File::isFile).readText()

        assertTrue("private val processLifecycleLock = Any()" in source)
        assertTrue("process = startNativeProcess(pb)" in source)
        assertTrue("process?.let(::stopNativeProcessLocked)" in source)
        assertTrue("check(process?.let(::stopNativeProcessLocked) != false)" in source)
        assertTrue("builder.start().also { process = it }" in source)
        assertTrue(
            "proxy ready state must be cleared while an old process is stopping",
            "if (tunnelModeUsesLocalProxy(activeMode.value))" in source &&
                "proxyReadyAddresses.value = emptyList()" in source,
        )
    }

    @Test
    fun `port in use becomes a dedicated connection issue`() {
        val presentation = proxyErrorPresentation("port_in_use|127.0.0.1:1080")

        assertEquals(ConnectionIssueKind.PROXY_PORT_IN_USE, presentation.issue.kind)
        assertEquals("Порт прокси уже занят", presentation.issue.title)
        assertTrue(presentation.issue.action.contains("127.0.0.1:1080 уже занят"))
        assertTrue(presentation.issue.action.contains("Выберите другой порт"))
        assertEquals("[ПРОКСИ] Порт занят: 127.0.0.1:1080", presentation.logMessage)
    }

    @Test
    fun `proxy error state never retains planned ready addresses`() {
        val presentation = proxyErrorPresentation("port_in_use|192.168.1.113:1080")

        assertNull(presentation.readyAddress)
        assertTrue(presentation.readyAddresses.isEmpty())
    }

    @Test
    fun `generic structured startup error remains readable`() {
        val presentation = proxyErrorPresentation("startup|ошибка userspace WireGuard")

        assertEquals(ConnectionIssueKind.GENERAL, presentation.issue.kind)
        assertEquals("Прокси не запустился", presentation.issue.title)
        assertTrue(presentation.issue.action.contains("ошибка userspace WireGuard"))
    }
}
