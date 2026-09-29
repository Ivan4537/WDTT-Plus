package com.wdtt.plus.vk

import java.net.URI

/** Presentation/one-click budget only: never grants permission to replay an API request. */
internal class VkCaptchaPolicy {
    enum class State { IDLE, AUTOMATIC, MANUAL, ERROR }
    data class Frame(val generation: Int, val state: String, val seenAt: Long)
    private val frames = linkedMapOf<String, Frame>()
    private val attempted = mutableSetOf<String>()
    private val manual = mutableSetOf<String>()
    private var clicks = 0
    var state = State.IDLE
        private set
    val active get() = state != State.IDLE
    fun update(frame: String, generation: Int, state: String, now: Long, foreground: Boolean): String? {
        if (!frame.matches(Regex("[a-z0-9]{1,64}")) || generation !in 0..128 ||
            state !in setOf("clear", "checkbox", "automatic", "waiting", "manual", "error")) return null
        if (frames[frame]?.generation?.let { it > generation } == true) return null
        if (state == "clear") frames.remove(frame)
        else if (frames.size < 16 || frame in frames) frames[frame] = Frame(generation, state, now)
        val key = "$frame:$generation"
        if (state == "manual" || state == "error") manual.add(key)
        val action = if (state == "checkbox" && foreground && frame in frames && key !in attempted && key !in manual) {
            if (clicks < 4) { attempted.add(key); clicks++; "click" }
            else { manual.add(key); "manual" }
        } else null
        refresh(now)
        return action
    }
    fun userInteraction(now: Long) {
        frames.forEach { (id, frame) -> manual.add("$id:${frame.generation}") }
        refresh(now)
    }
    fun refresh(now: Long) {
        frames.entries.removeAll { now - it.value.seenAt > 3500 }
        state = when {
            frames.isEmpty() -> State.IDLE
            frames.values.any { it.state == "error" } -> State.ERROR
            frames.any { (id, frame) -> frame.state == "manual" || "$id:${frame.generation}" in manual } -> State.MANUAL
            frames.values.any { it.state == "checkbox" || it.state == "automatic" } -> State.AUTOMATIC
            else -> State.MANUAL
        }
    }
    companion object {
        val origins = setOf("https://vk.ru", "https://m.vk.ru", "https://www.vk.ru", "https://id.vk.ru",
            "https://login.vk.ru", "https://oauth.vk.ru", "https://api.vk.ru",
            "https://vk.com", "https://m.vk.com", "https://www.vk.com", "https://id.vk.com",
            "https://login.vk.com", "https://oauth.vk.com", "https://api.vk.com")
        fun trustedOrigin(raw: String): Boolean = runCatching {
            val uri = URI(raw)
            uri.rawUserInfo == null && uri.port in setOf(-1, 443) && "${uri.scheme}://${uri.host}" in origins
        }.getOrDefault(false)
        fun captchaPage(raw: String): Boolean = trustedOrigin(raw) && runCatching {
            val path = URI(raw).path.orEmpty().lowercase()
            "captcha" in path || "not_robot" in path
        }.getOrDefault(false)
        fun message(state: State): String = when (state) {
            State.AUTOMATIC -> "ВК запросил проверку. Пробую пройти её автоматически…"
            State.MANUAL -> "Пройдите проверку ВК в этом окне. Затем действие продолжится."
            State.ERROR -> "Проверка ВК не пройдена. Решите её на странице ВК."
            State.IDLE -> "Проверка завершена. Продолжаю…"
        }
    }
}
