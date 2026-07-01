package com.wdtt.plus

object VkJoinLink {
    fun extractHash(input: String): String {
        var s = input.trim().trim('<', '>', '"', '\'')
        if (s.isBlank()) return ""

        val lower = s.lowercase()
        val marker = "/call/join/"
        val markerIndex = lower.indexOf(marker)
        s = when {
            markerIndex >= 0 -> s.substring(markerIndex + marker.length)
            lower.startsWith("http://") || lower.startsWith("https://") -> return ""
            else -> s
        }

        val stopIndex = s.indexOfFirst { it == '?' || it == '#' || it == '/' || it.isWhitespace() }
        if (stopIndex >= 0) {
            s = s.substring(0, stopIndex)
        }
        return s.trim().trimEnd('/')
    }
}

