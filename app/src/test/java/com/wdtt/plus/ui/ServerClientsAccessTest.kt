package com.wdtt.plus.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ServerClientsAccessTest {
    @Test
    fun accessRequiresDeployHostSshAndAdminPassword() {
        assertEquals(
            "Укажите IP-адрес или домен сервера в верхнем блоке «Деплой».",
            serverClientsAccessIssue("", false, "", 22, "")
        )
        assertEquals(
            "Проверьте IP-адрес или домен сервера в верхнем блоке «Деплой».",
            serverClientsAccessIssue("https://bad host", false, "ssh", 22, "owner")
        )
        assertEquals(
            "Укажите SSH-пароль сервера в верхнем блоке «Деплой».",
            serverClientsAccessIssue("vpn.example.org", true, "", 22, "owner")
        )
        assertEquals(
            "Укажите корректный SSH-порт от 1 до 65535.",
            serverClientsAccessIssue("vpn.example.org", true, "ssh", 0, "owner")
        )
        assertEquals(
            "Откройте «Секреты» и укажите главный пароль администратора.",
            serverClientsAccessIssue("vpn.example.org", true, "ssh", 22, "")
        )
        assertNull(serverClientsAccessIssue("vpn.example.org", true, "ssh", 22, "owner"))
    }

    @Test
    fun clientAutoRefreshRunsOnlyOnceForReadyTarget() {
        assertTrue(shouldAutoRefreshServerClients(true, true, true, false, false, 0L))
        assertFalse(shouldAutoRefreshServerClients(false, true, true, false, false, 0L))
        assertFalse(shouldAutoRefreshServerClients(true, false, true, false, false, 0L))
        assertFalse(shouldAutoRefreshServerClients(true, true, true, true, false, 0L))
        assertFalse(shouldAutoRefreshServerClients(true, true, true, false, true, 0L))
        assertFalse(shouldAutoRefreshServerClients(true, true, true, false, false, 1L))
    }

    @Test
    fun outboundAutoRefreshRunsOncePerSshTarget() {
        assertTrue(shouldAutoRefreshOutboundState(true, false, false, true, true, "new", ""))
        assertFalse(shouldAutoRefreshOutboundState(true, false, false, true, true, "same", "same"))
        assertFalse(shouldAutoRefreshOutboundState(false, false, false, true, true, "new", ""))
        assertFalse(shouldAutoRefreshOutboundState(true, true, false, true, true, "new", ""))
        assertFalse(shouldAutoRefreshOutboundState(true, false, true, true, true, "new", ""))
        assertFalse(shouldAutoRefreshOutboundState(true, false, false, false, true, "new", ""))
        assertFalse(shouldAutoRefreshOutboundState(true, false, false, true, false, "new", ""))
    }
}
