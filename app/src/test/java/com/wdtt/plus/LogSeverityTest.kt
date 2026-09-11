package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class LogSeverityTest {
    @Test
    fun wrapHandshakeRetryMessage_doesNotBlameThePassword() {
        assertEquals(
            "[WRAP] Отдельные каналы не ответили, выполняется повтор",
            WRAP_HANDSHAKE_RETRY_MESSAGE
        )
        assertFalse(WRAP_HANDSHAKE_RETRY_MESSAGE.contains("парол", ignoreCase = true))
    }

    @Test
    fun wrapHandshakeTerminalMessage_doesNotPresentTimeoutAsBadPassword() {
        val message = wrapHandshakeTerminalMessage(rtNetwork = false)

        assertEquals(
            "\uD83D\uDD0C Сервер не ответил на WRAP. Возможны проблемы с сервером или маршрутом, блокировка UDP/TURN, " +
                "неверный пароль либо несовместимость WRAP. Воркеры остановлены.",
            message,
        )
        assertFalse(message.startsWith("🔒 Неверный пароль"))
    }

    @Test
    fun repeatedTurnWorkerFailures_useOneRecoverableWarningKey() {
        val first = classifyRecoverableWorkerRetry(
            "[ВОРКЕР #1] Ошибка (попытка 1): TURN Allocate: all retransmissions failed for first",
            activeWorkerCount = 3
        )
        val second = classifyRecoverableWorkerRetry(
            "[ВОРКЕР #5] Ошибка (попытка 1): TURN Allocate: all retransmissions failed for second",
            activeWorkerCount = 3
        )

        assertEquals("worker_turn_allocate_retry", first?.first)
        assertEquals(first?.first, second?.first)
        assertEquals(
            "[TURN] Отдельные каналы не получили ответ на Allocate; выполняются повторы; активных=3",
            first?.second
        )
    }

    @Test
    fun fatalWorkerFailure_isNotDowngradedToWarning() {
        val result = classifyRecoverableWorkerRetry(
            "[ВОРКЕР #1] Ошибка (попытка 1): FATAL_AUTH неверный пароль"
        )

        assertNull(result)
    }

    @Test
    fun vkCallsStreamPreflightLogs_arePresentedAsUserStatus() {
        for (streamId in listOf(100, 200, 300, 400)) {
            val start = classifyVkCallsLog("[STREAM $streamId] [VKCalls] preflight 1/2")
            assertEquals("vkcalls_start", start?.key)
            assertEquals("[VKCalls] Пробуем основной бескапчевый провайдер...", start?.message)
            assertEquals(false, start?.warning)
        }

        val retry = classifyVkCallsLog(
            "[STREAM 300] [VKCalls] первая анонимная сессия не принята; повторяем один раз с новой идентичностью"
        )
        val fallback = classifyVkCallsLog(
            "[STREAM 400] [VKCalls] preflight не сработал после безопасного повтора: timeout; продолжаем резервную legacy-цепочку",
            isError = true,
        )

        assertEquals("vkcalls_retry", retry?.key)
        assertEquals("[VKCalls] Повторяем проверку с новой анонимной сессией...", retry?.message)
        assertEquals(false, retry?.warning)
        assertEquals("vkcalls_network_fallback", fallback?.key)
        assertEquals("[VKCalls] Основной провайдер не ответил по сети — используем резерв", fallback?.message)
        assertEquals(false, fallback?.warning)
    }

    @Test
    fun vkCallsFallbackLogs_keepTheActualFailureCategory() {
        val captcha = classifyVkCallsLog(
            "[VKCalls] основной провайдер запросил CAPTCHA; продолжаем одной legacy-цепочкой",
            isError = true,
        )
        val limit = classifyVkCallsLog(
            "[VKCalls] VK временно ограничил анонимный вход; продолжаем резервную legacy-цепочку",
            isError = true,
        )
        val response = classifyVkCallsLog(
            "[VKCalls] preflight не сработал после безопасного повтора: messages.getCallPreview parse secret: expected non-empty string",
            isError = true,
        )
        val rejected = classifyVkCallsLog(
            "[VKCalls] preflight не сработал: VK API error 5: anonymous session rejected; продолжаем резервную legacy-цепочку",
            isError = true,
        )

        assertEquals("vkcalls_captcha_fallback", captcha?.key)
        assertEquals("[VKCalls] Основной провайдер запросил CAPTCHA — используем автоматический резерв", captcha?.message)
        assertEquals("vkcalls_limit_fallback", limit?.key)
        assertEquals("[VKCalls] VK временно ограничил анонимные запросы — используем резерв", limit?.message)
        assertEquals("vkcalls_response_fallback", response?.key)
        assertEquals("[VKCalls] Ответ основного провайдера изменился — используем резерв", response?.message)
        assertEquals("vkcalls_rejected_fallback", rejected?.key)
        assertEquals("[VKCalls] Основной провайдер не принял анонимную сессию — используем резерв", rejected?.message)
        assertEquals(false, captcha?.warning)
        assertEquals(false, limit?.warning)
        assertEquals(false, response?.warning)
        assertEquals(false, rejected?.warning)
    }

    @Test
    fun warningDoesNotCountAsUnreadError() {
        val warning = LogEntry("warning", "Повторяем", severity = LogSeverity.Warning)

        assertFalse(warning.isError)
    }

    @Test
    fun serverExpiredDenialIsRecognizedBeforeLocalizedProtocolMessage() {
        assertTrue(isExpiredAccessAuthFailure("FATAL_AUTH: DENIED:expired"))
        assertTrue(isExpiredAccessAuthFailure("FATAL_AUTH: срок действия пароля истёк"))
        assertFalse(isExpiredAccessAuthFailure("FATAL_AUTH: неверный пароль подключения"))
    }
}
