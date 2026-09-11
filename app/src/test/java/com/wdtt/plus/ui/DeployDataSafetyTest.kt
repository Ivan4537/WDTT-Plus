package com.wdtt.plus.ui

import java.io.File
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DeployDataSafetyTest {
    @Test
    fun `single owner profile difference is shown without a whole-profile warning`() {
        assertEquals(
            listOf("Потоки на хеш: сервер — 36, приложение — 27"),
            ownerProfileOverwriteLines(
                listOf("Потоки на хеш: сервер — 36, приложение — 27"),
            ),
        )
        assertEquals(
            listOf(
                "Поля профиля владельца («Туннель» и порты):",
                "  Потоки на хеш: сервер — 36, приложение — 27",
                "  Протокол: сервер — tcp, приложение — udp",
            ),
            ownerProfileOverwriteLines(
                listOf(
                    "Потоки на хеш: сервер — 36, приложение — 27",
                    "Протокол: сервер — tcp, приложение — udp",
                ),
            ),
        )
    }

    @Test
    fun `deploy ssh never binds the app socket to its own android vpn network`() {
        val sourceRoot = sequenceOf(
            File("app/src/main/java/com/wdtt/plus"),
            File("src/main/java/com/wdtt/plus")
        ).first(File::isDirectory)
        val deploySources = sourceRoot.walkTopDown()
            .filter { it.isFile && it.extension in setOf("kt", "java") }
            .joinToString("\n") { it.readText() }

        assertFalse("own-VPN Network socket binding reintroduces EPERM", "network.socketFactory" in deploySources)
        assertFalse("removed SSH VPN socket factory was restored", "WdttVpnSocketFactory" in deploySources)
        assertFalse("removed SSH VPN network selector was restored", "WdttVpnSshFallback" in deploySources)
        assertTrue(
            "safe Deploy operations must use the typed in-tunnel relay",
            "executeDeploySafeRequest" in deploySources && "DEPLOY_SAFE|" in deploySources,
        )
    }

    @Test
    fun `deploy script keeps all config and never accepts secret process arguments`() {
        val script = sequenceOf(
            File("app/src/main/assets/deploy.sh"),
            File("src/main/assets/deploy.sh")
        ).first(File::isFile).readText()

        assertTrue("legacy free-form process arguments remain", "WDTT_ARGS" !in script)
        assertTrue("preserve mode must keep the whole config tree", "всё содержимое /etc/wdtt сохранено" in script)
        assertTrue("existing database reset guard is missing", "Найдена существующая база WDTT" in script)
        assertTrue("deploy mode must be explicit", "WDTT_INSTALL_MODE" in script)
        assertTrue("fresh install must reject new traces", "после проверки появились следы WDTT" in script)
        assertTrue("staged server version is not checked before replacement", "staged_version" in script)
        assertTrue("failed service start does not fail deployment", "Сервис wdtt не прошёл проверку запуска" in script)
    }

    @Test
    fun `destructive reset opens a separate hold dialog and prepares rollback`() {
        val source = sequenceOf(
            File("app/src/main/java/com/wdtt/plus/ui/DeployTab.kt"),
            File("src/main/java/com/wdtt/plus/ui/DeployTab.kt")
        ).first(File::isFile).readText()

        assertTrue("reset must open a separate confirmation dialog", "ServerResetConfirmDialog(" in source)
        assertTrue("reset must use the shared hold guard", "actionLabel = \"Начать с нуля\"" in source)
        assertFalse("legacy reset phrase must not clutter the main dialog", "Для сброса введите СБРОСИТЬ" in source)
        assertTrue(
            "managed Android reset must prepare rollback",
            "DeploymentOwnership.IncompleteAndroidDeploy" in source &&
                "prepareServerUpdateRollback(ssh)" in source
        )
    }

    @Test
    fun `server removal offers independently guarded preserve and full modes`() {
        val source = sequenceOf(
            File("app/src/main/java/com/wdtt/plus/ui/DeployTab.kt"),
            File("src/main/java/com/wdtt/plus/ui/DeployTab.kt")
        ).first(File::isFile).readText()

        assertTrue("Удалить сервер, сохранить данные" in source)
        assertTrue("Удалить полностью" in source)
        assertTrue("server-uninstall-preserve" in source)
        assertTrue("server-uninstall-all" in source)
        assertTrue("WDTT_UNINSTALL_DATA" in source)
        assertTrue("WDTT_ROOT_ACCESS" in source)
    }

    @Test
    fun `fresh and preserving deploy modes cannot be confused`() {
        assertDeploymentMayBeUpdated(DeploymentOwnership.NoInstall, DeployMode.FreshInstall)
        assertDeploymentMayBeUpdated(DeploymentOwnership.AndroidDeploy, DeployMode.PreserveData)
        assertDeploymentMayBeUpdated(DeploymentOwnership.LegacyAndroidDeploy, DeployMode.PreserveData)
        assertDeploymentMayBeUpdated(DeploymentOwnership.IncompleteAndroidDeploy, DeployMode.ResetAll)

        assertFails { assertDeploymentMayBeUpdated(DeploymentOwnership.NoInstall, DeployMode.PreserveData) }
        assertFails { assertDeploymentMayBeUpdated(DeploymentOwnership.AndroidDeploy, DeployMode.FreshInstall) }
        assertFails { assertDeploymentMayBeUpdated(DeploymentOwnership.UnknownExisting, DeployMode.FreshInstall) }
        assertFails { assertDeploymentMayBeUpdated(DeploymentOwnership.StandaloneInstaller, DeployMode.PreserveData) }
        assertFails { assertDeploymentMayBeUpdated(DeploymentOwnership.LegacyAndroidDeploy, DeployMode.ResetAll) }
        assertFails { assertDeploymentMayBeUpdated(DeploymentOwnership.IncompleteAndroidDeploy, DeployMode.PreserveData) }
    }

    private fun assertFails(block: () -> Unit) {
        var failed = false
        try {
            block()
        } catch (_: IllegalStateException) {
            failed = true
        }
        assertTrue("unsafe deployment mode was accepted", failed)
    }

    @Test
    fun `dangerous server hold confirms once only after three uninterrupted seconds`() {
        val start = advanceDangerousServerHold(
            current = DangerousServerHoldState(),
            pressed = true,
            safetyReady = true,
            nowElapsedMs = 1_000L
        )
        val early = advanceDangerousServerHold(start.state, true, true, 3_999L)
        val complete = advanceDangerousServerHold(early.state, true, true, 4_000L)
        val repeated = advanceDangerousServerHold(complete.state, true, true, 5_000L)

        assertEquals(DANGEROUS_SERVER_HOLD_MS, start.remainingMs)
        assertFalse(start.confirmed)
        assertEquals(1L, early.remainingMs)
        assertFalse(early.confirmed)
        assertEquals(0L, complete.remainingMs)
        assertTrue(complete.confirmed)
        assertFalse("one continuous press must not execute twice", repeated.confirmed)
    }

    @Test
    fun `dangerous server hold resets on release or lost safety condition`() {
        val started = advanceDangerousServerHold(
            current = DangerousServerHoldState(),
            pressed = true,
            safetyReady = true,
            nowElapsedMs = 10_000L
        )
        val released = advanceDangerousServerHold(started.state, false, true, 12_500L)
        val restarted = advanceDangerousServerHold(released.state, true, true, 20_000L)
        val connectionLost = advanceDangerousServerHold(restarted.state, true, false, 22_900L)
        val afterReconnect = advanceDangerousServerHold(connectionLost.state, true, true, 23_000L)

        assertEquals(DangerousServerHoldState(), released.state)
        assertEquals(DANGEROUS_SERVER_HOLD_MS, released.remainingMs)
        assertFalse(released.confirmed)
        assertEquals(DangerousServerHoldState(), connectionLost.state)
        assertEquals(DANGEROUS_SERVER_HOLD_MS, connectionLost.remainingMs)
        assertEquals(DANGEROUS_SERVER_HOLD_MS, afterReconnect.remainingMs)
        assertFalse(afterReconnect.confirmed)
    }

    @Test
    fun `backup settings expose a dirty state until saved values match`() {
        assertFalse(
            hasUnsavedServerBackupSettings(
                savedEnabled = true,
                savedIntervalHours = 24,
                savedRetentionCount = 14,
                enabledInput = true,
                intervalInput = "24",
                retentionInput = "14"
            )
        )
        assertTrue(
            hasUnsavedServerBackupSettings(
                savedEnabled = true,
                savedIntervalHours = 24,
                savedRetentionCount = 14,
                enabledInput = false,
                intervalInput = "24",
                retentionInput = "14"
            )
        )
        assertTrue(serverBackupSettingsAreValid("6", "90"))
        assertFalse(serverBackupSettingsAreValid("5", "14"))
        assertFalse(serverBackupSettingsAreValid("24", ""))
    }

    @Test
    fun `restore scroll aligns title to viewport and every restore creates a new request`() {
        assertEquals(
            510,
            restoreSectionScrollTarget(
                currentScroll = 100,
                titleTopInWindow = 500f,
                viewportTopInWindow = 80f,
                revealOffsetPx = 10f,
                maxScroll = 2_000
            )
        )

        val source = sequenceOf(
            File("app/src/main/java/com/wdtt/plus/ui/DeployTab.kt"),
            File("src/main/java/com/wdtt/plus/ui/DeployTab.kt")
        ).first(File::isFile).readText()
        assertTrue("each successful restore must retrigger scrolling", "restoreScrollRequestId += 1" in source)
        assertTrue("scrolling must use the restore title coordinates", "titleModifier = Modifier.onGloballyPositioned" in source)
        val backupCardSource = source
            .substringAfter("private fun ServerBackupManagementCard(")
            .substringBefore("private fun ServerBackupPanel(")
        assertTrue(
            "backup settings status height must animate to zero",
            "targetValue = if (hasUnsavedSettings) 58.dp else 0.dp" in backupCardSource &&
                ".height(unsavedSettingsAreaHeight)" in backupCardSource
        )
        assertFalse(
            "backup settings status must not use its old permanently reserved height",
            ".fillMaxWidth()\n                    .height(48.dp)" in backupCardSource
        )
    }

    @Test
    fun `backup history keeps information in pager and actions in a separate selected panel`() {
        val source = sequenceOf(
            File("app/src/main/java/com/wdtt/plus/ui/DeployTab.kt"),
            File("src/main/java/com/wdtt/plus/ui/DeployTab.kt")
        ).first(File::isFile).readText()
        val historySource = source
            .substringAfter("private fun ServerBackupsPager(")
            .substringBefore("private fun ServerBackupSwipeHint(")
        val cardSource = historySource
            .substringAfter("private fun ServerBackupCard(")
            .substringBefore("private fun ColumnScope.ServerBackupActions(")
        val actionsSource = historySource.substringAfter("private fun ColumnScope.ServerBackupActions(")

        assertFalse("scrolling backup cards must not contain action buttons", "onRestore" in cardSource)
        assertTrue("selected backup actions must be rendered separately", "onRestore(backup)" in actionsSource)
        assertTrue("backup card must show verified content metadata", "contentMetadataAvailable" in cardSource)
        assertTrue("selected backup must follow the pager selection", "val selectedBackup = backups[selectedBackupIndex]" in source)
    }

    @Test
    fun `portable backup device count matches client view and excludes owner or orphan records`() {
        val database = JSONObject()
            .put(
                "admin_profile",
                JSONObject().put("device_ids", org.json.JSONArray().put("owner-phone"))
            )
            .put(
                "devices",
                JSONObject()
                    .put("client-phone", JSONObject())
                    .put("owner-phone", JSONObject())
                    .put("orphan", JSONObject())
            )
            .put(
                "passwords",
                JSONObject().put(
                    "ABCDEFGHJKLMNPQR",
                    JSONObject()
                        .put("device_id", "client-phone")
                        .put(
                            "bind_history",
                            org.json.JSONArray()
                                .put(JSONObject().put("device_id", "client-phone").put("bound_at", 10).put("status", "active"))
                                .put(JSONObject().put("device_id", "old-client-phone").put("bound_at", 5).put("status", "unbound"))
                                .put(JSONObject().put("device_id", "rejected-phone").put("status", "denied_mismatch"))
                        )
                )
            )

        assertEquals(2, clientDeviceCountForBackup(database))
    }

    @Test
    fun `backup history uses the established client carousel layout`() {
        val source = sequenceOf(
            File("app/src/main/java/com/wdtt/plus/ui/DeployTab.kt"),
            File("src/main/java/com/wdtt/plus/ui/DeployTab.kt")
        ).first(File::isFile).readText()

        assertTrue("backup carousel is missing", "private fun ServerBackupsPager(" in source)
        assertTrue("backup cards must use HorizontalPager", "HorizontalPager(" in source)
        assertTrue("neighboring backup cards must remain visible", "contentPadding = PaddingValues(horizontal = 18.dp)" in source)
        assertTrue("backup carousel arrows and dots are missing", "private fun ServerBackupSwipeHint(" in source)
        assertTrue("unsaved policy state is not visible", "Изменения не сохранены" in source)
        assertTrue("restore result must scroll to its next step", "migrationImportTopInWindow" in source)
        assertFalse("duplicate backup heading must be removed", "Резервные копии сервера" in source)
    }

    @Test
    fun `backup cards use correct russian count forms`() {
        assertEquals("1 клиент", backupClientCountLabel(1))
        assertEquals("2 клиента", backupClientCountLabel(2))
        assertEquals("5 клиентов", backupClientCountLabel(5))
        assertEquals("11 клиентов", backupClientCountLabel(11))
        assertEquals("21 клиент", backupClientCountLabel(21))
        assertEquals("1 устройство", backupDeviceCountLabel(1))
        assertEquals("3 устройства", backupDeviceCountLabel(3))
        assertEquals("14 устройств", backupDeviceCountLabel(14))
        assertEquals("22 устройства", backupDeviceCountLabel(22))
    }

    @Test
    fun `server backup management keeps secrets off argv and uses guarded destructive actions`() {
        val adminSource = sequenceOf(
            File("app/src/main/java/com/wdtt/plus/ServerAdminClient.kt"),
            File("src/main/java/com/wdtt/plus/ServerAdminClient.kt")
        ).first(File::isFile).readText()
        val deploySource = sequenceOf(
            File("app/src/main/java/com/wdtt/plus/ui/DeployTab.kt"),
            File("src/main/java/com/wdtt/plus/ui/DeployTab.kt")
        ).first(File::isFile).readText()

        assertTrue("admin requests must use the protected stdin contract", "--request-stdin" in adminSource)
        assertTrue("Android must accept the current server snapshot format", "require(version in 1..3)" in adminSource)
        assertTrue("SSH admin output must have a hard resource limit", "MAX_COMMAND_OUTPUT_CHARS" in adminSource)
        assertTrue(
            "main password must not be interpolated into the admin command",
            "--main-password ${'$'}{shellQuote(target.mainPassword)}" !in adminSource
        )
        assertTrue("destructive restore must use the shared hold guard", "actionLabel = if (isDeploy) \"Продолжить\" else \"Заменить\"" in deploySource)
        assertTrue("backup deletion must use the shared hold guard", "guardKey = backup.id" in deploySource)
        assertFalse("legacy restore phrase must be removed", "Для замены введите ВОССТАНОВИТЬ" in deploySource)
        assertFalse("legacy delete phrase must be removed", "Введите УДАЛИТЬ" in deploySource)
        assertTrue("server must receive the delete confirmation too", "\"--confirm\", \"УДАЛИТЬ\"" in adminSource)
        assertTrue("backup download must use Android document storage", "ActivityResultContracts.CreateDocument" in deploySource)
        assertTrue("backup upload must use Android document selection", "ActivityResultContracts.GetContent" in deploySource)
        assertTrue("restore must create a persistent safety copy", "createPersistentSafetyBackup(request, \"pre_restore\")" in deploySource)
        assertTrue("deploy must create a persistent safety copy", "reason = \"pre_deploy\"" in deploySource)
        assertTrue("restore must wait for the live admin socket", "[ -S /run/wdtt/admin.sock ] && break" in deploySource)
        assertTrue("current full backups must restore an absent outbound profile", "backup.formatVersion >= 3" in deploySource)
        assertTrue("stale outbound profiles must be removed during exact restore", "rm -f /etc/wdtt/outbound-profile.env" in deploySource)
        assertTrue("full backups must restore automatic backup settings", "backup.backupPolicyJson" in deploySource)
        assertTrue("backup policy restore must use an atomic replacement", ".backup-policy.json.import" in deploySource)
        assertTrue("backup dialogs must use a close icon", "DialogTitleWithClose(" in deploySource)
        assertFalse("backup export dialog must not keep a bottom cancel button", "TextButton(onClick = onDismiss, enabled = !busy) { Text(\"Отмена\") }" in deploySource)
    }

    @Test
    fun `prepared deploy database preserves clients and unknown compatible fields`() {
        val current = JSONObject()
            .put("main_password", "old-owner")
            .put("admin_id", "old-admin")
            .put("bot_token", "old-token")
            .put("dns", "1.1.1.1")
            .put("max_passwords", 50)
            .put("default_ports", "56000,56001,9000")
            .put("future_compatible_field", "keep-me")
            .put(
                "passwords",
                JSONObject().put(
                    "ABCDEFGHJKLMNPQR",
                    JSONObject()
                        .put("device_id", "")
                        .put("expires_at", 0)
                        .put("down_bytes", 10)
                        .put("up_bytes", 20)
                )
            )
            .put("devices", JSONObject())

        val prepared = JSONObject(
            prepareDeployDatabaseJson(
                currentJson = current.toString(),
                mainPassword = "new-owner",
                adminId = "",
                botToken = "",
                dns = "9.9.9.9",
                ports = "56100,56101,9100"
            )
        )

        assertEquals("new-owner", prepared.getString("main_password"))
        assertEquals("old-admin", prepared.getString("admin_id"))
        assertEquals("old-token", prepared.getString("bot_token"))
        assertEquals("9.9.9.9", prepared.getString("dns"))
        assertEquals("56100,56101,9100", prepared.getString("default_ports"))
        assertEquals("keep-me", prepared.getString("future_compatible_field"))
        assertTrue(prepared.getJSONObject("passwords").has("ABCDEFGHJKLMNPQR"))
    }

    @Test
    fun `deploy DNS is normalized and legacy default upgrade is not a conflict`() {
        assertEquals("1.1.1.1,1.0.0.1", normalizedDeployDns(" 1.1.1.1 ", "1.0.0.1"))
        assertTrue(isLegacyDefaultDnsUpgrade("1.1.1.1", "1.1.1.1,1.0.0.1"))
        assertFalse(isLegacyDefaultDnsUpgrade("8.8.8.8", "1.1.1.1,1.0.0.1"))

        val invalid = runCatching { normalizedDeployDns("1.1.1.1; reboot", "") }
        assertTrue("invalid DNS characters must be rejected", invalid.isFailure)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `new deploy refuses empty owner password`() {
        prepareDeployDatabaseJson(
            currentJson = null,
            mainPassword = "",
            adminId = "",
            botToken = "",
            dns = "1.1.1.1",
            ports = "56000,56001,9000"
        )
    }
}
