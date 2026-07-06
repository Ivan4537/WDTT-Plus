package com.wdtt.plus

/** Версии приложения, для которых выпускалась новая обязательная серверная часть. */
internal val SERVER_MIGRATION_LEVELS = intArrayOf(2, 3, 5, 6, 7)

data class ServerMigrationState(
    val pendingLevel: Int,
    val acknowledgedLevel: Int,
    val completedLevel: Int
) {
    val noticeRequired: Boolean
        get() = pendingLevel > acknowledgedLevel

    val profileUpdateRequired: Boolean
        get() = pendingLevel > completedLevel
}

internal data class ServerMigrationInitialization(
    val lastSeenAppVersionCode: Int,
    val pendingLevel: Int,
    val acknowledgedLevel: Int
)

internal fun latestServerMigrationLevel(appVersionCode: Int): Int =
    SERVER_MIGRATION_LEVELS.lastOrNull { it <= appVersionCode } ?: 0

internal fun crossedServerMigrationLevel(previousVersionCode: Int, currentVersionCode: Int): Int =
    SERVER_MIGRATION_LEVELS.lastOrNull {
        it > previousVersionCode && it <= currentVersionCode
    } ?: 0

internal fun hasManagedServerCredentials(
    host: String,
    sshAuthMode: String,
    sshPassword: String,
    mainPassword: String,
    sshPrivateKey: String = ""
): Boolean = host.isNotBlank() &&
    sshCredentialsForMode(sshAuthMode, sshPassword, sshPrivateKey, "").hasAuthentication &&
    mainPassword.isNotBlank()

/**
 * Обновляет накопительное состояние предупреждений. При первом запуске новой схемы старые
 * отметки v2/v3/v5 используются как исходный уровень, поэтому прочитанные окна не повторяются.
 */
internal fun resolveServerMigrationInitialization(
    currentVersionCode: Int,
    isUpdatedInstall: Boolean,
    storedLastSeenAppVersionCode: Int?,
    storedPendingLevel: Int,
    storedAcknowledgedLevel: Int?,
    legacyAcknowledgedLevel: Int
): ServerMigrationInitialization {
    val acknowledgedLevel = maxOf(storedAcknowledgedLevel ?: 0, legacyAcknowledgedLevel)
    var pendingLevel = storedPendingLevel

    if (storedLastSeenAppVersionCode != null) {
        pendingLevel = maxOf(
            pendingLevel,
            crossedServerMigrationLevel(storedLastSeenAppVersionCode, currentVersionCode)
        )
    } else if (isUpdatedInstall) {
        val currentRequiredLevel = latestServerMigrationLevel(currentVersionCode)
        if (currentRequiredLevel > acknowledgedLevel) {
            pendingLevel = maxOf(pendingLevel, currentRequiredLevel)
        }
    }

    return ServerMigrationInitialization(
        lastSeenAppVersionCode = maxOf(storedLastSeenAppVersionCode ?: 0, currentVersionCode),
        pendingLevel = pendingLevel,
        acknowledgedLevel = acknowledgedLevel
    )
}
