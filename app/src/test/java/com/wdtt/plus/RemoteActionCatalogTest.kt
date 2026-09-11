package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RemoteActionCatalogTest {
    @Test
    fun parse_acceptsOnlyKnownPlacementsAndExactTargets() {
        val catalog = RemoteActionCatalogGateway.parse(
            """
            {
              "version": 1,
              "actions": {
                "tunnel": {
                  "title": "Дополнительное действие",
                  "message": "Продолжить во внешнем сервисе",
                  "label": "Открыть",
                  "confirmation_title": "Подтверждение",
                  "confirmation_message": "Первый абзац.\n\nВторой абзац.",
                  "confirmation_label": "Продолжить",
                  "progress_label": "Открываю…",
                  "preparing_message": "Подготавливаю...",
                  "stopping_message": "Останавливаю...",
                  "opening_message": "Открываю...",
                  "success_message": "Открыто.",
                  "cancelled_message": "Отменено.",
                  "failure_message": "Не удалось.",
                  "compact_message": "Короткий текст.",
                  "compact_label": "Короткая кнопка",
                  "compact_link_text": "Короткий",
                  "compact_button_visible": false,
                  "cancel_label": "Остановить",
                  "form": {
                    "token": "opaque.form.token_1234567890",
                    "submit_url": "https://example.org/actions/execute",
                    "title": "Введите значение",
                    "message": "Выберите готовое значение или укажите своё.",
                    "choices": [
                      {"label": "Первое", "value": "opaque-choice-1"},
                      {"label": "Второе", "value": "opaque-choice-2"}
                    ],
                    "input_label": "Значение",
                    "input_suffix": "",
                    "initial_value": "7",
                    "minimum": 2,
                    "maximum": 19,
                    "max_characters": 2,
                    "supporting_text": "Допустимый диапазон",
                    "invalid_text": "Проверьте значение",
                    "submit_label": "Продолжить — {value}",
                    "busy_label": "Подготавливаем…",
                    "failure_message": "Не удалось продолжить.",
                    "fallback_label": "Открыть страницу"
                  },
                  "url": "https://example.org/start?opaque=1",
                  "fallback": "https://example.org/fallback",
                  "handler": "org.example.client",
                  "alternate_handlers": [
                    "org.example.client.web",
                    "org.example.client.x"
                  ]
                },
                "unknown": {
                  "title": "Неизвестное место",
                  "message": "Не должно попасть в каталог",
                  "label": "Открыть",
                  "url": "https://example.org/ignored"
                }
              }
            }
            """.trimIndent()
        )

        val action = catalog.at("tunnel")!!
        assertEquals("Дополнительное действие", action.title)
        assertEquals("https://example.org/start?opaque=1", action.target.primaryUrl)
        assertEquals("https://example.org/fallback", action.target.fallbackUrl)
        assertEquals("org.example.client", action.target.preferredHandler)
        assertEquals(
            listOf("org.example.client.web", "org.example.client.x"),
            action.target.alternateHandlers,
        )
        assertEquals(
            listOf(
                "org.example.client",
                "org.example.client.web",
                "org.example.client.x",
            ),
            action.target.handlerPackages(),
        )
        assertEquals("Подтверждение", action.confirmationTitle)
        assertEquals("Первый абзац.\n\nВторой абзац.", action.confirmationMessage)
        assertEquals("Продолжить", action.confirmationLabel)
        assertEquals("Открываю…", action.progressLabel)
        assertEquals("Подготавливаю...", action.preparingMessage)
        assertEquals("Останавливаю...", action.stoppingMessage)
        assertEquals("Открываю...", action.openingMessage)
        assertEquals("Открыто.", action.successMessage)
        assertEquals("Отменено.", action.cancelledMessage)
        assertEquals("Не удалось.", action.failureMessage)
        assertEquals("Короткий текст.", action.compactMessage)
        assertEquals("Короткая кнопка", action.compactLabel)
        assertEquals("Короткий", action.compactLinkText)
        assertEquals(false, action.compactButtonVisible)
        assertEquals("Остановить", action.cancelLabel)
        assertEquals("Введите значение", action.form?.title)
        assertEquals("opaque-choice-2", action.form?.choices?.get(1)?.value)
        assertEquals(2L, action.form?.minimum)
        assertEquals(19L, action.form?.maximum)
        assertNull(catalog.at("unknown"))
    }

    @Test
    fun parse_rejectsUnsafeOrMalformedActions() {
        val catalog = RemoteActionCatalogGateway.parse(
            """
            {
              "version": 1,
              "actions": {
                "tunnel": {
                  "title": "Опасная ссылка",
                  "message": "Неподдерживаемая схема",
                  "label": "Открыть",
                  "url": "custom://private-contract"
                },
                "profile": {
                  "title": "Неверный обработчик",
                  "message": "Имя пакета не прошло проверку",
                  "label": "Открыть",
                  "url": "https://example.org/start",
                  "handler": "not a package"
                },
                "about": {
                  "title": "Неверные резервные обработчики",
                  "message": "Имя пакета не прошло проверку",
                  "label": "Открыть",
                  "url": "https://example.org/start",
                  "alternate_handlers": ["also not a package"]
                }
              }
            }
            """.trimIndent()
        )

        assertTrue(catalog.actions.isEmpty())
    }

    @Test
    fun parse_rejectsUnknownProtocolVersion() {
        val catalog = RemoteActionCatalogGateway.parse(
            """{"version":2,"actions":{}}"""
        )

        assertTrue(catalog.actions.isEmpty())
    }

    @Test
    fun parseValidCatalog_distinguishesConfirmedEmptyCatalogFromBrokenResponse() {
        val confirmedEmpty = RemoteActionCatalogGateway.parseValidCatalog(
            """{"version":1,"actions":{}}"""
        )

        assertTrue(confirmedEmpty != null)
        assertTrue(confirmedEmpty!!.actions.isEmpty())
        assertNull(RemoteActionCatalogGateway.parseValidCatalog("service unavailable"))
        assertNull(
            RemoteActionCatalogGateway.parseValidCatalog(
                """{"version":2,"actions":{}}"""
            )
        )
        assertNull(
            RemoteActionCatalogGateway.parseValidCatalog(
                """
                {
                  "version": 1,
                  "actions": {
                    "tunnel": {
                      "title": "Небезопасное действие",
                      "message": "Не должно заменять исправный кэш",
                      "label": "Открыть",
                      "url": "custom://unsafe"
                    }
                  }
                }
                """.trimIndent()
            )
        )
    }

    @Test
    fun parseExecutionTarget_acceptsOnlyExactHttpsTargets() {
        val target = RemoteActionCatalogGateway.parseExecutionTarget(
            """
            {
              "version": 1,
              "url": "https://actions.example.org/opaque",
              "fallback": "https://example.org/fallback",
              "handler": ""
            }
            """.trimIndent()
        )

        assertEquals("https://actions.example.org/opaque", target.primaryUrl)
        assertEquals("https://example.org/fallback", target.fallbackUrl)
    }
}
