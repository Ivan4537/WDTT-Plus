package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Test

class RemoteProfileUpdatePresentationTest {
    @Test
    fun newlyAppliedUpdateHasExplicitConfirmation() {
        val confirmation = boundProfileUpdateConfirmation(
            profileLabel = "Чехия",
            alreadyApplied = false,
        )

        assertEquals("Профиль обновлён", confirmation.title)
        assertEquals(
            "Новые настройки профиля Чехия сохранены. Можно подключаться.",
            confirmation.message,
        )
    }

    @Test
    fun repeatedLinkConfirmsThatCurrentRevisionIsAlreadyStored() {
        val confirmation = boundProfileUpdateConfirmation(
            profileLabel = "Чехия",
            alreadyApplied = true,
        )

        assertEquals("Профиль уже обновлён", confirmation.title)
        assertEquals(
            "Актуальные настройки профиля Чехия уже сохранены на этом устройстве.",
            confirmation.message,
        )
    }
}
