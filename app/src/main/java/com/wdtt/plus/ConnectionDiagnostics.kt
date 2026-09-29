package com.wdtt.plus

internal fun connectionModeTitle(streamOnly: Boolean): String = if (streamOnly) "TCP/TLS" else "UDP"

internal fun connectionPathTitle(path: String): String? = when (path) {
    "udp" -> "UDP"
    "tcp" -> "TCP"
    "tls" -> "TLS"
    "tls-front" -> "TLS · внешний SNI"
    "h2" -> "MASQUE · HTTP/2"
    "h3" -> "MASQUE · HTTP/3"
    else -> null
}

internal data class ConnectionEventLog(val key: String, val message: String, val warning: Boolean = false)

internal fun connectionEventLog(event: String, networkEpoch: Long): ConnectionEventLog? {
    val parts = event.trim().split(' ')
    return when (parts.firstOrNull()) {
        "TRY" -> {
            if (parts.size != 2) return null
            val path = connectionPathTitle(parts[1]) ?: return null
            ConnectionEventLog("try_${parts[1]}", "Пробуем подключиться через $path")
        }
        "READY" -> {
            if (parts.size != 3 || parts[1].toLongOrNull() != networkEpoch) return null
            val path = connectionPathTitle(parts[2]) ?: return null
            ConnectionEventLog("ready_${parts[2]}", "Сервер ответил · $path ✓")
        }
        "FAILED" -> {
            if (parts.size != 6 || parts[1].toLongOrNull() != networkEpoch) return null
            val path = connectionPathTitle(parts[2]) ?: return null
            val stage = when (parts[3]) {
                "turn" -> "подключение к ретранслятору"
                "dtls" -> "защищённое соединение с сервером"
                "registration" -> "регистрация на сервере"
                "protocol" -> "согласование передачи данных"
                "confirmation" -> "проверка ответа сервера"
                "active" -> "работа канала"
                else -> return null
            }
            val reason = when (parts[4]) {
                "timeout" -> "истекло время ожидания"
                "network" -> "сетевая ошибка"
                "closed" -> "канал закрыт"
                "limit" -> "достигнут лимит подключений"
                "capacity" -> "ретранслятор занят"
                "auth" -> "доступ не подтверждён"
                "protocol" -> "несовместимые параметры передачи"
                "interrupted" -> "попытка прервана"
                else -> return null
            }
            val elapsed = parts[5].toLongOrNull()?.takeIf { it >= 0 } ?: return null
            ConnectionEventLog("failed_${parts[2]}_${parts[3]}_${parts[4]}",
                "$path: $stage — $reason (${elapsed / 1000} с).", warning = true)
        }
        "UDP_PARTIAL" -> {
            if (parts.size != 2 || parts[1].toLongOrNull() != networkEpoch) return null
            ConnectionEventLog("udp_partial", "Один UDP-канал не ответил. Остальные UDP-каналы работают; восстанавливаем недостающие.", warning = true)
        }
        "UDP_BACKOFF" -> {
            if (parts.size != 2 || parts[1].toLongOrNull() != networkEpoch) return null
            ConnectionEventLog("udp_backoff", "Рабочих UDP-каналов нет. Пробуем TCP/TLS; новые проверки внешнего UDP отложены на 5 минут.", warning = true)
        }
        "PAUSED" -> ConnectionEventLog("paused", "Лимит попыток исчерпан. Смените сеть или подключитесь заново.", warning = true)
        else -> null
    }
}

internal fun connectionModeDiagnostic(streamOnly: Boolean): DeviceCheckItem = DeviceCheckItem(
    title = "Подключение",
    status = connectionModeTitle(streamOnly),
    details = (if (streamOnly) "Используются TLS и TCP. Внешние UDP и HTTP/3 запрещены; UDP внутри VPN остаётся доступен. "
        else "Сначала проверяется UDP, при недоступности — TCP/TLS. Пауза для новых проверок UDP действует, когда рабочих UDP-каналов нет. Отказ отдельного канала не отключает остальные. Рабочий резерв не заменяется фоновыми проверками. ") +
        "В обоих режимах проверяется ответ сервера и восстанавливаются потерянные каналы. После серии неудач попытки приостанавливаются.",
    recommendation = "Приложение не определяет блокировку SIM. Если интернет пропал полностью, проверьте доступ без VPN.",
    severity = DeviceCheckSeverity.Info,
)
