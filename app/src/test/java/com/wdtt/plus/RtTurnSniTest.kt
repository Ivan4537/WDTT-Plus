package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RtTurnSniTest {
    @Test
    fun allRtNetworkSettingsAreRegisteredAsProfilePreferences() {
        val profilePreferenceNames = SettingsStore.resettableProfilePreferenceNames()

        assertTrue(
            profilePreferenceNames.containsAll(
                setOf(
                    "rt_network",
                    "rt_masque",
                    "rt_masque_server_bootstrap",
                    "rt_turn_sni",
                )
            )
        )
    }

    @Test
    fun masqueRequiresBothSwitches() {
        assertFalse(shouldUseRtMasque(rtNetwork = false, rtMasque = false))
        assertFalse(shouldUseRtMasque(rtNetwork = false, rtMasque = true))
        assertFalse(shouldUseRtMasque(rtNetwork = true, rtMasque = false))
        assertTrue(shouldUseRtMasque(rtNetwork = true, rtMasque = true))
        assertFalse(
            shouldUseRtMasqueServerBootstrap(
                rtNetwork = false,
                rtMasque = true,
                serverBootstrap = true,
            )
        )
        assertFalse(
            shouldUseRtMasqueServerBootstrap(
                rtNetwork = true,
                rtMasque = false,
                serverBootstrap = true,
            )
        )
        assertTrue(
            shouldUseRtMasqueServerBootstrap(
                rtNetwork = true,
                rtMasque = true,
                serverBootstrap = true,
            )
        )
    }

    @Test
    fun masqueLogsExposeProtocolFallbackAndRegistrationRecovery() {
        val h2 = classifyMasqueLog(
            "[СЕССИЯ #1] [MASQUE] turns:443 через HTTP/2 не сработал: timeout"
        )
        assertEquals("masque_h2_failed", h2?.key)
        assertTrue(h2?.warning == true)
        assertTrue(h2?.message?.contains("таймаут") == true)

        val selected = classifyMasqueLog(
            "[СЕССИЯ #1] Relay: 1.2.3.4:5 через TURN TURNS внутри MASQUE HTTP/3 ✓"
        )
        assertEquals("masque_selected", selected?.key)
        assertTrue(selected?.startsDtls == true)

        val invalid = classifyMasqueLog(
            "[MASQUE] фоновая подготовка WARP пока не выполнена: сохранённая конфигурация WARP повреждена"
        )
        assertEquals("masque_registration_invalid", invalid?.key)
        assertTrue(invalid?.message?.contains("Сбросить регистрацию WARP") == true)

        assertNull(classifyMasqueLog("[TURN] обычный режим"))
    }

    @Test
    fun enrollmentLogKeepsSafeCloudflareFailureReason() {
        val rateLimit = classifyMasqueLog(
            "[MASQUE] фоновая подготовка WARP пока не выполнена: регистрация WARP: WARP API HTTP 429: code=1042"
        )
        assertEquals("masque_enrollment_pending", rateLimit?.key)
        assertTrue(rateLimit?.message?.contains("HTTP 429") == true)
        assertTrue(rateLimit?.message?.contains("этап 1/4") == true)
        assertTrue(rateLimit?.message?.contains("код API 1042") == true)

        val serverFailure = classifyMasqueLog(
            "[MASQUE] фоновая подготовка WARP пока не выполнена: этап 2/4, включение MASQUE: WARP API HTTP 500"
        )
        assertTrue(serverFailure?.message?.contains("временная ошибка Cloudflare") == true)
        assertTrue(serverFailure?.message?.contains("этап 2/4") == true)

        val unexpectedBody = classifyMasqueLog(
            "[MASQUE] фоновая подготовка WARP пока не выполнена: этап 1/4, создание устройства WARP: " +
                "WARP API вернул ответ не в формате JSON: HTTP 200, Content-Type=text/html, размер=1240 байт"
        )
        assertTrue(unexpectedBody?.message?.contains("не в формате JSON") == true)
        assertTrue(unexpectedBody?.message?.contains("Content-Type=text/html") == true)

        val unknownFailure = classifyMasqueLog(
            "[MASQUE] фоновая подготовка WARP пока не выполнена: этап 1/4, создание ключа устройства WARP: " +
                "ошибка генератора случайных чисел"
        )
        assertTrue(unknownFailure?.message?.contains("ошибка генератора случайных чисел") == true)

        val tlsTimeout = classifyMasqueLog(
            "[MASQUE] фоновая подготовка WARP пока не выполнена: этап 1/4, создание устройства WARP: " +
                "WARP API: тайм-аут TLS-рукопожатия (8 с) после успешного TCP/443"
        )
        assertTrue(tlsTimeout?.message?.contains("TLS-рукопожатие") == true)
        assertTrue(tlsTimeout?.message?.contains("после успешного TCP/443") == true)

        val responseTimeout = classifyMasqueLog(
            "[MASQUE] фоновая подготовка WARP пока не выполнена: этап 1/4, создание устройства WARP: " +
                "WARP API: HTTP-запрос отправлен, но Cloudflare не прислал ответ за 12 с"
        )
        assertTrue(responseTimeout?.message?.contains("уже отправленный HTTPS-запрос") == true)

        val accountCreated = classifyMasqueLog(
            "[MASQUE] этап 1/4 завершён: устройство WARP создано в Cloudflare; этап 2/4 — включаем для него MASQUE"
        )
        assertEquals("masque_account_created", accountCreated?.key)
        assertTrue(accountCreated?.message?.contains("устройство WARP создано") == true)

        val saved = classifyMasqueLog(
            "[MASQUE] этап 4/4 завершён: регистрация WARP сохранена в приватном хранилище приложения ✓"
        )
        assertEquals("masque_enrollment_saved", saved?.key)
        assertTrue(saved?.message?.contains("приватном хранилище") == true)
    }

    @Test
    fun cloudflareApiPhasesRemainSeparateInTheVisibleLog() {
        assertEquals(
            "masque_api_dns",
            classifyMasqueLog("[MASQUE] API Cloudflare: системный DNS Android разрешил адрес ✓")?.key,
        )
        assertEquals(
            "masque_api_tcp",
            classifyMasqueLog("[MASQUE] API Cloudflare: TCP/443 через системную сеть Android установлен ✓")?.key,
        )
        assertEquals(
            "masque_api_tls",
            classifyMasqueLog("[MASQUE] API Cloudflare: TLS-рукопожатие завершено, согласован HTTP/2 ✓")?.key,
        )
        assertEquals(
            "masque_api_request",
            classifyMasqueLog("[MASQUE] API Cloudflare: HTTP-запрос отправлен, ожидаем ответ...")?.key,
        )
        assertEquals(
            "masque_api_response",
            classifyMasqueLog("[MASQUE] API Cloudflare: получен первый байт HTTP-ответа ✓")?.key,
        )
        assertEquals(
            "masque_api_retry",
            classifyMasqueLog(
                "[MASQUE] API Cloudflare: TLS timeout; данные устройства ещё не отправлялись — " +
                "выполняем одну безопасную повторную попытку"
            )?.key,
        )
        assertEquals(
            "masque_api_tls_fallback",
            classifyMasqueLog(
                "[MASQUE] API Cloudflare: обычный TLS не прошёл до отправки данных — " +
                    "повторяем через TLS 1.2/HTTP 1.1 с разделённым ClientHello"
            )?.key,
        )
        assertEquals(
            "masque_api_server_retry",
            classifyMasqueLog(
                "[MASQUE] API Cloudflare: прямые HTTPS-пути недоступны до отправки данных — " +
                    "пробуем защищённый выход через сервер профиля"
            )?.key,
        )
        assertEquals(
            "masque_api_server_connected",
            classifyMasqueLog(
                "[MASQUE] API Cloudflare: защищённый выход через сервер профиля доступен ✓"
            )?.key,
        )
        assertEquals(
            "masque_api_tls_fallback_ok",
            classifyMasqueLog(
                "[MASQUE] API Cloudflare: TLS-рукопожатие завершено, согласован HTTP/1.1 ✓"
            )?.key,
        )
    }

    @Test
    fun normalizesValidDomain() {
        assertEquals("ya.ru", normalizeRtTurnSni(" Ya.RU "))
        assertEquals("telemost.yandex.ru", normalizeRtTurnSni("telemost.yandex.ru"))
    }

    @Test
    fun rejectsValuesThatCannotBeTlsSni() {
        listOf("", "ya", "127.0.0.1", "я.рф", "-ya.ru", "ya..ru").forEach { value ->
            assertNull(value, normalizeRtTurnSni(value))
        }
    }

    @Test
    fun rtTurnSniDoesNotReplaceExistingServerSni() {
        val params = buildTunnelParams(
            TunnelProfileSnapshot(
                profileIndex = 0,
                remoteManaged = false,
                linkMode = false,
                link = "",
                peer = "vpn.example",
                vkHashes = "hash",
                secondaryVkHash = "",
                connectionPassword = "password",
                workersPerHash = 18,
                profileMaxWorkers = 0,
                manualPortsEnabled = false,
                serverDtlsPort = 56000,
                listenPort = 9000,
                sni = "server.example",
                protocol = "udp",
                vkCallsPreflight = true,
                rtNetwork = true,
                rtMasque = true,
                rtMasqueServerBootstrap = true,
                rtMasqueServerAccessReady = true,
                rtTurnSni = "ya.ru",
                captchaMode = "auto",
                captchaSolveMethod = "auto",
                fingerprint = "firefox",
                clientIds = DEFAULT_VK_CLIENT_IDS,
                customVkCredentialsEnabled = false,
                customVkClientId = "",
                customVkClientSecret = "",
            )
        )

        assertNotNull(params)
        assertEquals("server.example", params?.sni)
        assertEquals("ya.ru", params?.rtTurnSni)
        assertEquals(true, params?.rtMasque)
        assertEquals(true, params?.rtMasqueServerBootstrap)
    }

    @Test
    fun serverBootstrapIsNotStartedWithoutDeploySshAccess() {
        val params = buildTunnelParams(
            TunnelProfileSnapshot(
                profileIndex = 0,
                remoteManaged = false,
                linkMode = false,
                link = "",
                peer = "vpn.example",
                vkHashes = "hash",
                secondaryVkHash = "",
                connectionPassword = "password",
                workersPerHash = 18,
                profileMaxWorkers = 0,
                manualPortsEnabled = false,
                serverDtlsPort = 56000,
                listenPort = 9000,
                sni = "",
                protocol = "udp",
                vkCallsPreflight = true,
                rtNetwork = true,
                rtMasque = true,
                rtMasqueServerBootstrap = true,
                rtMasqueServerAccessReady = false,
                rtTurnSni = "ya.ru",
                captchaMode = "auto",
                captchaSolveMethod = "auto",
                fingerprint = "firefox",
                clientIds = DEFAULT_VK_CLIENT_IDS,
                customVkCredentialsEnabled = false,
                customVkClientId = "",
                customVkClientSecret = "",
            )
        )

        assertNotNull(params)
        assertEquals(false, params?.rtMasqueServerBootstrap)
    }
}
