package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VkJoinLinkTest {
    @Test
    fun extractsHashFromCurrentVkRuLink() {
        assertEquals(
            "current_hash_1234567890",
            VkJoinLink.extractHash(
                "https://vk.ru/call/join/current_hash_1234567890?from=share#fragment"
            )
        )
    }

    @Test
    fun keepsVkComLinksAsCompatibilityInput() {
        assertEquals(
            "legacy_hash_1234567890",
            VkJoinLink.extractHash(
                "https://vk.com/call/join/legacy_hash_1234567890?from=share"
            )
        )
    }

    @Test
    fun keepsRawHashInputSupported() {
        assertEquals(
            "raw_hash_1234567890",
            VkJoinLink.extractHash("raw_hash_1234567890")
        )
    }

    @Test
    fun acceptsOnlyOpaqueAsciiHashValues() {
        assertTrue(VkJoinLink.isValidHash("3XariaxnHDP9eTiWVFukTMO6ZjCw7c0QQS_J3gYiiaM"))
        assertTrue(VkJoinLink.isValidHash("short"))
        assertFalse(VkJoinLink.isValidHash("пользовательский"))
        assertFalse(VkJoinLink.isValidHash("переподключаются"))
        assertEquals("", VkJoinLink.extractValidHash("https://vk.ru/call/join/пользовательский"))
    }

    @Test
    fun validatesCharactersWithoutGuessingVkHashLength() {
        assertTrue(VkJoinLink.isValidInput("a"))
        assertTrue(VkJoinLink.isValidInput("https://vk.ru/call/join/a?from=share"))
        assertFalse(VkJoinLink.isValidInput("хеш"))
        assertFalse(VkJoinLink.isValidInput("bad/path"))
        assertFalse(VkJoinLink.isValidInput("https://vk.ru/not-a-call/a"))
        assertEquals("a,b_C-2", VkJoinLink.normalizeHashes("a, b_C-2"))
    }

    @Test
    fun completeHashSetRequiresFourDistinctValidValues() {
        assertTrue(VkJoinLink.hasCompleteHashSet("one,two,three,four"))
        assertFalse(VkJoinLink.hasCompleteHashSet("one,two,three"))
        assertFalse(VkJoinLink.hasCompleteHashSet("one,two,three,three"))
        assertFalse(VkJoinLink.hasCompleteHashSet("one,two,three,нельзя"))
    }
}
