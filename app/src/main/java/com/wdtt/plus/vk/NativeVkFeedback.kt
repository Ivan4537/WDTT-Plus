package com.wdtt.plus.vk

/** Never forward exception text, provider bodies, OAuth URLs or credentials to logs. */
internal object NativeVkFeedback {
    fun diagnostic(stage: String, error: Throwable): String {
        val kind = when (error) {
            is VkHttpFailure -> "HTTP_${error.status}"
            is java.net.SocketTimeoutException -> "TIMEOUT"
            is java.io.IOException -> "NETWORK"
            else -> "FAILED"
        }
        val code = Regex("\\b(?:NET_[A-Z_]{2,32}|HTTP_[0-9]{3}|(?:IDENTITY|CHECK_TOKEN)_(?:VK_(?:[0-9]{1,7}(?:_IP_MISMATCH)?|UNKNOWN)|HTTP_[0-9]{3}|NETWORK|TIMEOUT|JSON|SHAPE|EXPIRED)|TOKEN_LENGTH|SERVICE_CONFIG)\\b")
            .find(error.message.orEmpty())?.value
        val vk = Regex("VK API: ошибка ([0-9]{1,7})\\.").find(error.message.orEmpty())?.groupValues?.get(1)
        val errno = generateSequence(error) { it.cause }.take(8)
            .filterIsInstance<android.system.ErrnoException>().firstOrNull()?.errno
        val exceptionClass = error.javaClass.simpleName.uppercase().takeIf { it.matches(Regex("[A-Z]{1,48}")) }
        return listOf(stage.takeIf { it.matches(Regex("[A-Z_]{1,32}")) } ?: "OPERATION",
            code ?: vk?.let { "VK_$it" } ?: kind, exceptionClass,
            errno?.let { "ERRNO_$it" }).filterNotNull().joinToString(" / ")
    }

    fun validDiagnostic(value: String) = value.length <= 160 &&
        value.matches(Regex("[A-Z0-9_ /]{1,160}"))

    fun presentation(value: String): String {
        val parts = value.split('/').map(String::trim)
        if (parts.firstOrNull()?.startsWith("CAPTCHA_") == true) return when (parts.first()) {
            "CAPTCHA_AUTOMATIC" -> "ВК запросил проверку. Выполняется одна автоматическая попытка."
            "CAPTCHA_MANUAL" -> "Пройдите проверку ВК вручную в открытом окне."
            "CAPTCHA_IDLE" -> "Проверка ВК закрыта. Продолжаю действие."
            else -> "Не удалось пройти проверку ВК автоматически. Решите её вручную."
        }
        val stage = when (parts.firstOrNull()) {
            "PREPARE", "BROKER", "BROKER_BIND", "BROKER_LOST" -> "Не удалось подготовить получение ВК-хешей."
            "NETWORK", "NETWORK_LOST", "DIRECT_FALLBACK", "WEB_FALLBACK" -> "Не удалось подготовить соединение с ВК."
            "LOGIN", "WEB_TLS", "WEB_PAGE", "WEB_RENDER", "WEB_EXTERNAL" -> "Не удалось открыть страницу входа ВК."
            "VK_ID_CALLBACK", "OAUTH_CALLBACK", "IDENTITY" -> "Не удалось завершить вход в ВК."
            "PERMIT" -> "Не удалось безопасно начать получение ВК-хешей."
            "CALL" -> "ВК не создал ссылку звонка. Автоматический повтор отключён."
            "CAPTCHA" -> "Проверка ВК не завершена. Повторный запрос не отправлен."
            "UPLOAD", "FINISH" -> "Не удалось сохранить полученные ВК-хеши. Повтор не создаст новые ссылки."
            "RESTORE" -> "Не удалось восстановить сохранённое состояние получения."
            "LOGOUT" -> "Не удалось полностью завершить выход из ВК."
            else -> "Не удалось завершить получение ВК-хешей."
        }
        val detail = when {
            parts.any { it == "TIMEOUT" } -> "Время ожидания истекло."
            parts.any { it == "NETWORK" } -> "Проверьте подключение к интернету."
            else -> "Подробности сохранены без личных данных."
        }
        return "$stage $detail"
    }
}
