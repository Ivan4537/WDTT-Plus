package com.wdtt.plus.vk

internal data class NativeVkAccountActions(
    val showLogin: Boolean,
    val showAcquire: Boolean,
    val showReplace: Boolean,
    val showLogout: Boolean,
) {
    companion object {
        fun forState(
            loginPageOpen: Boolean,
            authorized: Boolean,
            hasToken: Boolean,
            acquireFallbackAvailable: Boolean,
            replacementConfirmationNeeded: Boolean,
            logoutPending: Boolean = false,
        ) =
            if (logoutPending) NativeVkAccountActions(false, false, false, true) else NativeVkAccountActions(
                showLogin = !loginPageOpen && !authorized && !hasToken && !replacementConfirmationNeeded,
                showAcquire = !loginPageOpen && (authorized || hasToken) && acquireFallbackAvailable &&
                    !replacementConfirmationNeeded,
                showReplace = !loginPageOpen && replacementConfirmationNeeded,
                showLogout = authorized || hasToken,
            )

        fun replacementConfirmationNeeded(
            hasCompleteLocalValues: Boolean,
            replacementConfirmed: Boolean,
            hasRecoveredOperation: Boolean,
        ): Boolean = hasCompleteLocalValues &&
            !replacementConfirmed &&
            !hasRecoveredOperation

        fun acquireFallbackAvailable(
            busy: Boolean,
            hasError: Boolean,
            journalPhases: List<String>,
        ): Boolean {
            if (busy) return false
            if (journalPhases.any { it !in setOf("received", "uploaded") }) return false
            return hasError || journalPhases.isNotEmpty()
        }
    }
}
