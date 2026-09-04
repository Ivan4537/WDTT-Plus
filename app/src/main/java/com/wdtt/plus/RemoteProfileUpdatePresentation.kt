package com.wdtt.plus

internal data class BoundProfileUpdateConfirmation(
    val title: String,
    val message: String,
)

internal fun boundProfileUpdateConfirmation(
    profileLabel: String,
    alreadyApplied: Boolean,
): BoundProfileUpdateConfirmation =
    if (alreadyApplied) {
        BoundProfileUpdateConfirmation(
            title = "Профиль уже обновлён",
            message = "Актуальные настройки профиля $profileLabel уже сохранены на этом устройстве.",
        )
    } else {
        BoundProfileUpdateConfirmation(
            title = "Профиль обновлён",
            message = "Новые настройки профиля $profileLabel сохранены. Можно подключаться.",
        )
    }
