package com.wdtt.plus

enum class AccessLifecycleSeverity {
    NORMAL,
    WARNING,
    ERROR;

    companion object {
        fun parse(value: String, allowConnect: Boolean): AccessLifecycleSeverity =
            when (value.trim().lowercase()) {
                "normal", "info" -> NORMAL
                "warning", "warn" -> WARNING
                "error", "danger" -> ERROR
                else -> if (allowConnect) NORMAL else ERROR
            }
    }
}

/**
 * Opaque provider-neutral capability attached to a remotely managed profile.
 *
 * Android does not interpret the provider policy behind this capability. It
 * submits the protected key to the exact HTTPS service URL, then applies only
 * the generic connection decision and optional document/action returned by it.
 */
data class RemoteAccessCapability(
    val available: Boolean,
    val key: String = "",
    val url: String = "",
    val binding: String = "",
    val initialStatus: AccessLifecycleStatus? = null,
    val cachedAction: CachedRemoteAction = CachedRemoteAction.Unavailable,
    val exchange: RemoteProfileExchange = RemoteProfileExchange.Unavailable,
) {
    companion object {
        val Unavailable = RemoteAccessCapability(available = false)
    }
}

/**
 * Provider-neutral exchange attached to one remotely managed profile.
 *
 * Tokens are opaque and device-bound. Android can submit the profile's normal
 * auxiliary values or invoke the remotely presented action, but it does not
 * know why the provider stores them or how the returned update is produced.
 */
data class RemoteProfileExchange(
    val submitAvailable: Boolean,
    val submitToken: String = "",
    val actionAvailable: Boolean = false,
    val actionToken: String = "",
    val label: String = "",
    val message: String = "",
) {
    companion object {
        val Unavailable = RemoteProfileExchange(submitAvailable = false)
    }
}

/**
 * A provider-neutral action cached with a remotely managed profile.
 *
 * Android treats [payload] as an opaque clipboard value and opens [target]
 * exactly as supplied. Presentation is also remote-provided, so the APK does
 * not know which external channel fulfills the action.
 */
data class CachedRemoteAction(
    val available: Boolean,
    val payload: String = "",
    val target: RemoteLaunchTarget = RemoteLaunchTarget(primaryUrl = ""),
    val title: String = "",
    val message: String = "",
    val label: String = "",
    val clipboardLabel: String = "",
    val copiedMessage: String = "",
    val failedMessage: String = "",
    val helpTitle: String = "",
    val helpIntro: String = "",
    val helpSteps: String = "",
) {
    companion object {
        val Unavailable = CachedRemoteAction(available = false)
    }
}

data class AccessProfileUpdate(
    val revision: Long,
    val link: RemoteDocumentLink,
)

data class AccessLifecycleStatus(
    val allowConnect: Boolean,
    val actionAvailable: Boolean,
    val actionLabel: String = "",
    val actionMessage: String = "",
    val title: String = "",
    val message: String = "",
    val detailLabel: String = "",
    val detailValue: String = "",
    val actionIcon: String = "",
    val continuationAvailable: Boolean? = null,
    val continuationExpiresAtSeconds: Long? = null,
    val dismissible: Boolean? = null,
    val dismissedMessage: String = "",
    val severity: AccessLifecycleSeverity = AccessLifecycleSeverity.NORMAL,
    val checkedAtMillis: Long = System.currentTimeMillis(),
    val profileRevision: Long = 0,
    val profileUpdate: AccessProfileUpdate? = null,
    val cachedAction: CachedRemoteAction = CachedRemoteAction.Unavailable,
    val exchange: RemoteProfileExchange? = null,
)

data class StoredAccessLifecycle(
    val managed: Boolean,
    val capability: RemoteAccessCapability,
    val status: AccessLifecycleStatus?,
    val appliedProfileRevision: Long,
    val lastAttemptAtMillis: Long,
)

data class AccessLifecycleUiState(
    val managed: Boolean,
    val allowConnect: Boolean,
    val actionAvailable: Boolean,
    val actionLabel: String,
    val actionMessage: String,
    val title: String,
    val message: String,
    val detailLabel: String = "",
    val detailValue: String = "",
    val actionIcon: String = "",
    val continuationAvailable: Boolean? = null,
    val continuationExpiresAtSeconds: Long? = null,
    val dismissible: Boolean? = null,
    val dismissedMessage: String = "",
    val severity: AccessLifecycleSeverity,
    val checkedAtMillis: Long,
) {
    companion object {
        val Unmanaged = AccessLifecycleUiState(
            managed = false,
            allowConnect = true,
            actionAvailable = false,
            actionLabel = "",
            actionMessage = "",
            title = "",
            message = "",
            detailLabel = "",
            detailValue = "",
            actionIcon = "",
            continuationAvailable = null,
            continuationExpiresAtSeconds = null,
            dismissible = null,
            dismissedMessage = "",
            severity = AccessLifecycleSeverity.NORMAL,
            checkedAtMillis = 0,
        )
    }
}

internal fun accessLifecycleDismissalSignature(
    lifecycle: AccessLifecycleUiState,
): String {
    if (!lifecycle.managed) return ""
    return listOf(
        lifecycle.allowConnect,
        lifecycle.actionAvailable,
        lifecycle.title,
        lifecycle.message,
        lifecycle.detailLabel,
        lifecycle.detailValue,
        lifecycle.continuationAvailable,
        lifecycle.continuationExpiresAtSeconds,
        lifecycle.dismissible,
        lifecycle.dismissedMessage,
    ).joinToString("|")
}

internal fun accessLifecycleCanDismiss(lifecycle: AccessLifecycleUiState): Boolean =
    lifecycle.dismissible ?: (
        lifecycle.allowConnect && lifecycle.severity == AccessLifecycleSeverity.WARNING
        )

internal fun boundContinuationAvailable(
    hasCredential: Boolean,
    hasEndpoint: Boolean,
    remoteAvailability: Boolean?,
    expiresAtSeconds: Long? = null,
    nowSeconds: Long = System.currentTimeMillis() / 1_000L,
): Boolean = hasCredential &&
    hasEndpoint &&
    remoteAvailability != false &&
    (expiresAtSeconds == null || expiresAtSeconds == 0L || expiresAtSeconds > nowSeconds)

internal fun StoredAccessLifecycle.toUiState(): AccessLifecycleUiState {
    val current = status
    return AccessLifecycleUiState(
        managed = managed,
        allowConnect = current?.allowConnect ?: true,
        actionAvailable = current?.actionAvailable == true,
        actionLabel = current?.actionLabel.orEmpty(),
        actionMessage = current?.actionMessage.orEmpty(),
        title = current?.title.orEmpty(),
        message = current?.message.orEmpty(),
        detailLabel = current?.detailLabel.orEmpty(),
        detailValue = current?.detailValue.orEmpty(),
        actionIcon = current?.actionIcon.orEmpty(),
        continuationAvailable = current?.continuationAvailable,
        continuationExpiresAtSeconds = current?.continuationExpiresAtSeconds,
        dismissible = current?.dismissible,
        dismissedMessage = current?.dismissedMessage.orEmpty(),
        severity = current?.severity ?: AccessLifecycleSeverity.NORMAL,
        checkedAtMillis = current?.checkedAtMillis ?: 0,
    )
}

internal sealed interface AccessStartDecision {
    data object Allowed : AccessStartDecision
    data class Denied(val status: AccessLifecycleStatus) : AccessStartDecision
}

internal fun accessStartDecision(
    lifecycle: StoredAccessLifecycle,
): AccessStartDecision {
    val status = lifecycle.status
    val pendingProfileUpdate = status?.profileUpdate
        ?.revision
        ?.let { it > lifecycle.appliedProfileRevision } == true
    return if (
        !lifecycle.capability.available ||
        status == null ||
        (status.allowConnect && !pendingProfileUpdate)
    ) {
        AccessStartDecision.Allowed
    } else {
        AccessStartDecision.Denied(
            if (pendingProfileUpdate) {
                status.copy(
                    allowConnect = false,
                    title = "Нужно обновить профиль",
                    message = "Не удалось применить новые параметры. Повторите подключение.",
                    severity = AccessLifecycleSeverity.WARNING,
                )
            } else {
                status
            }
        )
    }
}

internal fun AccessLifecycleUiState.fallbackTitle(): String =
    if (allowConnect) "Профиль доступен" else "Профиль временно недоступен"
