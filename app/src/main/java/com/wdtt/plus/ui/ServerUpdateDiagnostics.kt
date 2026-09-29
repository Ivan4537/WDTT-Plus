package com.wdtt.plus.ui

import java.util.Locale

/** Only public, bounded inspection results belong in a support report. */
internal data class ServerUpdateDiagnosticSnapshot(
    val rollbackState: ServerUpdateRollbackState,
    val serviceExists: Boolean,
    val binaryExists: Boolean,
    val configDirExists: Boolean,
    val accessDbExists: Boolean,
    val wgKeysExist: Boolean,
    val serviceActive: Boolean,
    val inspectionSucceeded: Boolean,
)

private val knownRollbackDiagnostics = setOf(
    "absent", "checksum_mismatch", "committed", "invalid_format",
    "legacy_state_not_prepared", "missing_binary", "missing_checksums",
    "missing_config", "missing_format", "missing_or_unsafe_state",
    "missing_service", "preparation_not_finished", "state_not_prepared",
    "unknown_backup_entry", "unknown_preparation", "unreadable_backup",
    "unreadable_checksums", "unreadable_config_tree", "unsafe_backup_path",
    "unsafe_backup_permissions", "unsafe_config_tree", "unsafe_marker",
    "unsafe_preparation", "unexpected_binary", "unexpected_config",
    "unexpected_service", "service_state_without_service",
)

private fun safeRollbackDiagnostic(value: String): String {
    val code = value.trim().lowercase(Locale.ROOT).replace(' ', '_')
    return code.takeIf(knownRollbackDiagnostics::contains) ?: "other"
}

internal fun buildServerUpdateDiagnosticReport(
    snapshot: ServerUpdateDiagnosticSnapshot,
    generatedAt: String,
    appVersion: String,
): String {
    val (state, detail) = when (val rollback = snapshot.rollbackState) {
        ServerUpdateRollbackState.None -> "none" to "absent"
        ServerUpdateRollbackState.PreparationIncomplete -> "preparation_incomplete" to "preparation_not_finished"
        ServerUpdateRollbackState.Committed -> "committed_valid" to "committed"
        is ServerUpdateRollbackState.PreparedValid -> "prepared_valid" to "verified"
        is ServerUpdateRollbackState.PreparedCorrupted ->
            "prepared_corrupted" to safeRollbackDiagnostic(rollback.diagnostic)
        is ServerUpdateRollbackState.UnknownState ->
            "unknown_state" to safeRollbackDiagnostic(rollback.diagnostic)
    }
    fun flag(value: Boolean) = if (value) "yes" else "no"
    return buildString {
        appendLine("WDTT Plus — диагностика обновления сервера")
        appendLine("Создано: $generatedAt")
        appendLine("Версия приложения: $appVersion")
        appendLine("Данные: только результат последней проверки, без адреса сервера и секретов")
        appendLine("Проверка SSH завершена: ${flag(snapshot.inspectionSucceeded)}")
        appendLine("Состояние страховочной копии: $state")
        appendLine("Код проверки копии: $detail")
        appendLine("Служба активна: ${flag(snapshot.serviceActive)}")
        appendLine("Unit-файл обнаружен: ${flag(snapshot.serviceExists)}")
        appendLine("Бинарник обнаружен: ${flag(snapshot.binaryExists)}")
        appendLine("Каталог конфигурации обнаружен: ${flag(snapshot.configDirExists)}")
        appendLine("База доступа обнаружена: ${flag(snapshot.accessDbExists)}")
        appendLine("Ключи WireGuard обнаружены: ${flag(snapshot.wgKeysExist)}")
        if (snapshot.rollbackState is ServerUpdateRollbackState.PreparedValid) {
            val markers = snapshot.rollbackState.markers
            appendLine("Копия конфигурации: ${flag(markers.hadConfig)}")
            appendLine("Копия бинарника: ${flag(markers.hadBinary)}")
            appendLine("Копия unit-файла: ${flag(markers.hadService)}")
            appendLine("Служба была активна до обновления: ${flag(markers.wasActive)}")
            appendLine("Служба была включена до обновления: ${flag(markers.wasEnabled)}")
        }
    }
}
