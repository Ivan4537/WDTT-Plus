package com.wdtt.plus

object VkJoinLink {
    private val hashPattern = Regex("^[A-Za-z0-9_-]{1,512}$")

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

    fun isValidHash(value: String): Boolean = hashPattern.matches(value.trim())

    fun isValidInput(input: String): Boolean {
        val clean = input.trim().trim('<', '>', '"', '\'')
        if (clean.isBlank()) return false
        val isLink = clean.startsWith("http://", ignoreCase = true) ||
            clean.startsWith("https://", ignoreCase = true)
        return if (isLink) {
            clean.contains("/call/join/", ignoreCase = true) &&
                isValidHash(extractHash(clean))
        } else {
            isValidHash(clean)
        }
    }

    fun normalizeHashes(input: String): String? {
        if (input.isBlank()) return ""
        val values = input.split(Regex("[,\\s]+"))
            .filter { it.isNotBlank() }
        if (values.isEmpty() || values.any { !isValidInput(it) }) return null
        return values.map(::extractHash).distinct().joinToString(",")
    }

    /** True only when the profile already contains four distinct valid call hashes. */
    fun hasCompleteHashSet(input: String): Boolean =
        normalizeHashes(input)
            ?.split(',')
            ?.filter(String::isNotBlank)
            ?.size == 4

    fun extractValidHash(input: String): String =
        extractHash(input).takeIf { isValidInput(input) }.orEmpty()
}
