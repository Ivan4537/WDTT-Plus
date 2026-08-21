package com.wdtt.plus.ui

import com.wdtt.plus.ServerAdminProfileInfo
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class ServerMigrationTest {
    @Test
    fun backupValidation_acceptsCurrentOwnerAndClientFields() {
        validatePasswordsDbStructure(database("client-a", "Телефон"))
    }

    @Test
    fun backupValidation_acceptsTrafficImportHistory() {
        val db = database("client-a", "Телефон")

        validatePasswordsDbStructure(db)
    }

    @Test(expected = IllegalArgumentException::class)
    fun backupValidation_rejectsMalformedTrafficImportHistory() {
        val db = database("client-a", "Телефон")
        db.getJSONObject("passwords").getJSONObject("client-a")
            .put("traffic_imports", JSONArray())

        validatePasswordsDbStructure(db)
    }

    @Test
    fun preserveValidation_recoversEmptyMainPasswordFromCurrentSecrets() {
        val db = database("client-a", "Телефон").put("main_password", "")

        val needsRecovery = validatePasswordsDbForPreserving(db, "new-owner-password")

        assertTrue(needsRecovery)
        assertTrue(db.optString("main_password").isEmpty())
        assertTrue(db.getJSONObject("passwords").has("client-a"))
    }

    @Test
    fun preserveValidation_recoversMissingMainPasswordFromCurrentSecrets() {
        val db = database("client-a", "Телефон").apply { remove("main_password") }

        assertTrue(validatePasswordsDbForPreserving(db, "new-owner-password"))
        assertTrue(!db.has("main_password"))
    }

    @Test
    fun preserveValidation_keepsValidMainPassword() {
        val db = database("client-a", "Телефон")

        assertTrue(!validatePasswordsDbForPreserving(db, "new-owner-password"))
        assertTrue(db.optString("main_password") == "owner-password")
    }

    @Test(expected = IllegalArgumentException::class)
    fun preserveValidation_rejectsRecoveryWithoutCurrentMainPassword() {
        val db = database("client-a", "Телефон").put("main_password", "")

        validatePasswordsDbForPreserving(db, "")
    }

    @Test(expected = IllegalArgumentException::class)
    fun preserveValidation_stillRejectsMalformedClientDataDuringRecovery() {
        val db = database("client-a", "Телефон").put("main_password", "")
        db.getJSONObject("passwords").getJSONObject("client-a").put("expires_at", -1L)

        validatePasswordsDbForPreserving(db, "new-owner-password")
    }

    @Test
    fun preserveUpdate_acceptsLiveTrafficAndHistoryGrowth() {
        val before = database("client-a", "Телефон")
            .put("admin_down_bytes", 5_000L)
            .put("admin_up_bytes", 2_000L)
            .put(
                "admin_traffic",
                JSONArray().put(trafficBucket("2026-07-30", 5_000L, 2_000L))
            )
        before.getJSONObject("passwords").getJSONObject("client-a")
            .getJSONArray("bind_history")
            .put(bindEvent(1))

        val after = JSONObject(before.toString())
        after.put("admin_down_bytes", 5_200L)
            .put("admin_up_bytes", 2_100L)
        after.getJSONArray("admin_traffic")
            .getJSONObject(0)
            .put("down_bytes", 5_200L)
            .put("up_bytes", 2_100L)
        val afterEntry = after.getJSONObject("passwords").getJSONObject("client-a")
        afterEntry.put("down_bytes", 1_500L)
            .put("up_bytes", 2_500L)
        afterEntry.getJSONArray("traffic")
            .getJSONObject(0)
            .put("down_bytes", 1_500L)
            .put("up_bytes", 2_500L)
        afterEntry.getJSONArray("traffic")
            .put(trafficBucket("2026-07-30", 25L, 10L))
        afterEntry.getJSONArray("bind_history").put(bindEvent(2))

        validatePreservedServerState(before.toString(), after.toString())
    }

    @Test(expected = IllegalArgumentException::class)
    fun preserveUpdate_rejectsTrafficCounterRegression() {
        val before = database("client-a", "Телефон")
        val after = JSONObject(before.toString())
        after.getJSONObject("passwords").getJSONObject("client-a")
            .put("down_bytes", 1_023L)

        validatePreservedServerState(before.toString(), after.toString())
    }

    @Test(expected = IllegalArgumentException::class)
    fun preserveUpdate_rejectsTrafficHistoryRegression() {
        val before = database("client-a", "Телефон")
        val after = JSONObject(before.toString())
        val entry = after.getJSONObject("passwords").getJSONObject("client-a")
        entry.put("down_bytes", 2_048L)
        entry.getJSONArray("traffic").getJSONObject(0)
            .put("down_bytes", 1_023L)

        validatePreservedServerState(before.toString(), after.toString())
    }

    @Test
    fun preserveUpdate_acceptsAppendAfterCappedBindHistory() {
        val before = database("client-a", "Телефон")
        val beforeHistory = before.getJSONObject("passwords")
            .getJSONObject("client-a")
            .getJSONArray("bind_history")
        repeat(50) { beforeHistory.put(bindEvent(it)) }

        val after = JSONObject(before.toString())
        val afterHistory = JSONArray()
        for (index in 1 until 50) {
            afterHistory.put(bindEvent(index))
        }
        afterHistory.put(bindEvent(50))
        after.getJSONObject("passwords").getJSONObject("client-a")
            .put("bind_history", afterHistory)

        validatePreservedServerState(before.toString(), after.toString())
    }

    @Test
    fun preserveUpdate_acceptsFirstDeviceBindingDuringRestart() {
        val before = database("client-a", "Телефон")
        val after = JSONObject(before.toString())
        bindDevice(
            after,
            "client-a",
            "device-a",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        )
        after.getJSONObject("passwords").getJSONObject("client-a")
            .getJSONArray("bind_history")
            .put(
                JSONObject()
                    .put("device_id", "device-a")
                    .put("event_at", 1_700_000_100L)
                    .put("bound_at", 1_700_000_100L)
                    .put("status", "active")
            )

        validatePreservedServerState(before.toString(), after.toString())
    }

    @Test(expected = IllegalArgumentException::class)
    fun preserveUpdate_rejectsRemovalOfExistingDeviceBinding() {
        val before = database("client-a", "Телефон")
        bindDevice(
            before,
            "client-a",
            "device-a",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        )
        val after = JSONObject(before.toString())
        after.getJSONObject("passwords").getJSONObject("client-a")
            .put("device_id", "")

        validatePreservedServerState(before.toString(), after.toString())
    }

    @Test(expected = IllegalArgumentException::class)
    fun backupValidation_rejectsInvalidOwnerProfile() {
        val db = database("client-a", "Телефон")
        db.getJSONObject("admin_profile").put("workers_per_hash", 500)

        validatePasswordsDbStructure(db)
    }

    @Test
    fun replaceImport_preservesClientDataAndHistory() {
        val source = database("client-a", "Телефон")
        val after = JSONObject(source.toString())
        after.getJSONObject("passwords").getJSONObject("client-a").put("ports", "56010,56011,9010")

        validateImportedServerState(source.toString(), null, after.toString(), replace = true)
    }

    @Test
    fun replaceImport_acceptsTrafficAndDeviceRefreshAfterServiceStart() {
        val source = database("client-a", "Телефон")
            .put("admin_down_bytes", 100L)
            .put("admin_up_bytes", 200L)
            .put(
                "admin_traffic",
                JSONArray().put(trafficBucket("2026-07-30", 100L, 200L))
            )
        bindDevice(
            source,
            "client-a",
            "device-a",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        )
        source.getJSONObject("devices").getJSONObject("device-a")
            .put("last_seen_at", 100L)
            .put("name", "Старое имя")
            .put("sdk", 34)

        val after = JSONObject(source.toString())
            .put("admin_down_bytes", 125L)
            .put("admin_up_bytes", 240L)
        after.getJSONArray("admin_traffic").getJSONObject(0)
            .put("down_bytes", 125L)
            .put("up_bytes", 240L)
        val afterEntry = after.getJSONObject("passwords").getJSONObject("client-a")
        afterEntry.put("down_bytes", 1_500L)
            .put("up_bytes", 2_500L)
        afterEntry.getJSONArray("traffic").getJSONObject(0)
            .put("down_bytes", 1_500L)
            .put("up_bytes", 2_500L)
        after.getJSONObject("devices").getJSONObject("device-a")
            .put("last_seen_at", 101L)
            .put("name", "Обновлённое имя")
            .put("sdk", 35)
            .put("remote_ip", "203.0.113.10")

        validateImportedServerState(source.toString(), null, after.toString(), replace = true)
    }

    @Test(expected = IllegalArgumentException::class)
    fun replaceImport_detectsChangedTrafficImportHistory() {
        val source = database("client-a", "Телефон")
        val after = JSONObject(source.toString())
        after.getJSONObject("passwords")
            .getJSONObject("client-a")
            .getJSONObject("traffic_imports")
            .getJSONObject("move-1")
            .put("down_bytes", 999L)

        validateImportedServerState(source.toString(), null, after.toString(), replace = true)
    }

    @Test
    fun mergeImport_preservesTargetAndAddsMissingClient() {
        val before = database("target-client", "Существующий")
        val source = database("source-client", "Перенесённый")
        val after = JSONObject(before.toString())
        after.getJSONObject("passwords").put(
            "source-client",
            JSONObject(source.getJSONObject("passwords").getJSONObject("source-client").toString())
        )

        validateImportedServerState(source.toString(), before.toString(), after.toString(), replace = false)
        assertTrue(after.getJSONObject("passwords").has("target-client"))
        assertTrue(after.getJSONObject("passwords").has("source-client"))
    }

    @Test(expected = IllegalStateException::class)
    fun importValidation_detectsMissingTransferredClient() {
        val source = database("client-a", "Телефон")
        val after = database("another-client", "Другой")

        validateImportedServerState(source.toString(), null, after.toString(), replace = true)
    }

    @Test(expected = IllegalArgumentException::class)
    fun mergeRejectsDeviceIdWithDifferentKeys() {
        val source = database("source-client", "Перенесённый")
        val target = database("target-client", "Существующий")
        bindDevice(source, "source-client", "same-device", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        bindDevice(target, "target-client", "same-device", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")

        mergeServerDatabaseEntries(source, target, "56000,56001,9000")
    }

    @Test
    fun mergeCopiesOnlyDeviceOfAddedClient() {
        val source = database("source-client", "Перенесённый")
        val target = database("target-client", "Существующий")
        bindDevice(source, "source-client", "used-device", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        bindDevice(target, "target-client", "target-device", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
        source.getJSONObject("devices").put(
            "orphan-device",
            device("orphan-device", "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=")
        )

        mergeServerDatabaseEntries(source, target, "56000,56001,9000")

        assertTrue(target.getJSONObject("devices").has("used-device"))
        assertTrue(!target.getJSONObject("devices").has("orphan-device"))
        assertTrue(target.getJSONObject("devices").getJSONObject("used-device").getString("ip") == "10.66.66.3")
    }

    @Test
    fun replaceAdaptsOwnerAndClientPortsToTarget() {
        val source = database("client-a", "Телефон")

        val prepared = JSONObject(
            prepareServerDatabaseForTarget(
                sourceJson = source.toString(),
                currentDbJson = null,
                merge = false,
                portsSpec = "56100,56101,9100",
                dnsValue = "9.9.9.9",
                publicHost = "new.example.org"
            )
        )

        assertEquals(
            "56100,56101,9100",
            prepared.getJSONObject("passwords").getJSONObject("client-a").getString("ports")
        )
        assertEquals("56100,56101,9100", prepared.getJSONObject("admin_profile").getString("ports"))
        assertEquals(9100, prepared.getJSONObject("admin_profile").getInt("listen_port"))
        assertEquals("new.example.org", prepared.getString("public_ip"))
    }

    @Test
    fun mergeIntoEmptyServerKeepsWholeSourceDatabase() {
        val source = database("client-a", "Телефон")
            .put("admin_down_bytes", 12_345L)
            .put("admin_up_bytes", 54_321L)

        val prepared = JSONObject(
            prepareServerDatabaseForTarget(
                sourceJson = source.toString(),
                currentDbJson = null,
                merge = true,
                portsSpec = "56100,56101,9100",
                dnsValue = "9.9.9.9",
                publicHost = "new.example.org"
            )
        )

        assertEquals(12_345L, prepared.getLong("admin_down_bytes"))
        assertEquals(54_321L, prepared.getLong("admin_up_bytes"))
        assertTrue(prepared.getJSONObject("admin_profile").has("workers_per_hash"))
        assertTrue(prepared.getJSONObject("passwords").has("client-a"))
    }

    @Test
    fun exportUsesCurrentOwnerProfileWhenTunnelPointsToSourceServer() {
        val source = database("client-a", "Телефон")
        source.getJSONObject("admin_profile")
            .put("vk_hashes", "old-owner-hash")
            .put("device_ids", JSONArray().put("owner-phone"))

        val prepared = prepareServerDatabaseForBackup(
            sourceJson = source.toString(),
            localOwnerProfile = ServerAdminProfileInfo(
                vkHashes = "new-owner-hash-1,new-owner-hash-2",
                secondaryVkHash = "new-reserve-hash",
                profileName = "Новый сервер",
                workersPerHash = 24,
                protocol = "tcp",
                listenPort = 9100,
                sni = "example.org",
                noDns = true,
                vpnDnsSelectionId = "custom",
                vpnDnsCustomServers = listOf("10.0.0.53"),
                vpnDnsStored = true,
                ports = "56100,56101,9100"
            ),
            localPeer = "OLD.EXAMPLE.ORG.",
            sourceHost = "old.example.org"
        )

        val profile = JSONObject(prepared.json).getJSONObject("admin_profile")
        assertTrue(prepared.ownerProfileFromApp)
        assertEquals("new-owner-hash-1,new-owner-hash-2", profile.getString("vk_hashes"))
        assertEquals("new-reserve-hash", profile.getString("secondary_vk_hash"))
        assertEquals("56100,56101,9100", profile.getString("ports"))
        assertEquals("owner-phone", profile.getJSONArray("device_ids").getString(0))
        assertEquals("custom", profile.getString("vpn_dns_selection"))
        assertEquals("10.0.0.53", profile.getString("vpn_dns_custom"))
    }

    @Test
    fun exportDoesNotMixOwnerProfileFromAnotherServer() {
        val source = database("client-a", "Телефон")
        source.getJSONObject("admin_profile").put("vk_hashes", "server-owner-hash")

        val prepared = prepareServerDatabaseForBackup(
            sourceJson = source.toString(),
            localOwnerProfile = ServerAdminProfileInfo(vkHashes = "other-server-hash"),
            localPeer = "other.example.org",
            sourceHost = "old.example.org"
        )

        assertFalse(prepared.ownerProfileFromApp)
        assertEquals(
            "server-owner-hash",
            JSONObject(prepared.json).getJSONObject("admin_profile").getString("vk_hashes")
        )
    }

    @Test
    fun versionTwoBackupRoundTripVerifiesIntegrity() {
        val source = database("client-a", "Телефон")
        val keys = List(4) { "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" }.joinToString("\n")
        val encoded = backupToJson(
            parseBackup(
                passwordsJson = source.toString(),
                wgKeysDat = keys,
                createdAt = "27.07.2026 12:00",
                sourceHost = "old.example.org"
            )
        )

        val decoded = parseBackupFile(encoded)

        assertEquals(2, decoded.formatVersion)
        assertTrue(decoded.integrityVerified)
        assertTrue(decoded.hasWgKeys)
        assertEquals(source.toString(), decoded.passwordsJson)
    }

    @Test
    fun versionTwoBackupKeepsOwnerProfileSourceMarker() {
        val backup = parseBackup(
            passwordsJson = database("client-a", "Телефон").toString(),
            wgKeysDat = null,
            createdAt = "05.08.2026 23:00",
            sourceHost = "old.example.org",
            ownerProfileFromApp = true
        )

        val decoded = parseBackupFile(backupToJson(backup))

        assertTrue(decoded.ownerProfileFromApp)
    }

    @Test(expected = IllegalArgumentException::class)
    fun backupRejectsAdditionalWireGuardKeyLines() {
        val keys = List(5) { "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" }.joinToString("\n")

        parseBackup(
            passwordsJson = database("client-a", "Телефон").toString(),
            wgKeysDat = keys,
            createdAt = "05.08.2026 23:00",
            sourceHost = "old.example.org"
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun versionTwoBackupRejectsChangedDatabase() {
        val source = database("client-a", "Телефон")
        val encoded = JSONObject(
            backupToJson(
                parseBackup(
                    passwordsJson = source.toString(),
                    wgKeysDat = null,
                    createdAt = "27.07.2026 12:00",
                    sourceHost = "old.example.org"
                )
            )
        )
        val changed = JSONObject(source.toString()).put("dns", "8.8.8.8").toString()
        encoded.put(
            "passwords_json_b64",
            Base64.getEncoder().encodeToString(changed.toByteArray())
        )

        parseBackupFile(encoded.toString())
    }

    @Test
    fun versionOneBackupRemainsCompatible() {
        val source = database("client-a", "Телефон")
        val legacy = JSONObject()
            .put("format", "wdtt-server-backup")
            .put("version", 1)
            .put("created_at", "05.07.2026 10:00")
            .put("source_host", "old.example.org")
            .put(
                "passwords_json_b64",
                Base64.getEncoder().encodeToString(source.toString().toByteArray())
            )

        val decoded = parseBackupFile(legacy.toString())

        assertEquals(1, decoded.formatVersion)
        assertFalse(decoded.integrityVerified)
        assertEquals(source.toString(), decoded.passwordsJson)
    }

    private fun database(password: String, label: String): JSONObject {
        val entry = JSONObject()
            .put("device_id", "")
            .put("expires_at", 2_000_000_000L)
            .put("down_bytes", 1024L)
            .put("up_bytes", 2048L)
            .put("label", label)
            .put("vk_hash", "1234567890abcdef")
            .put("ports", "56000,56001,9000")
            .put("traffic", JSONArray().put(
                JSONObject()
                    .put("date", "2026-07-05")
                    .put("down_bytes", 1024L)
                    .put("up_bytes", 2048L)
            ))
            .put("traffic_imports", JSONObject().put(
                "move-1",
                JSONObject()
                    .put("down_bytes", 100L)
                    .put("up_bytes", 200L)
                    .put("applied_at", 1_700_000_000L)
            ))
            .put("bind_history", JSONArray())
        return JSONObject()
            .put("main_password", "owner-password")
            .put("admin_id", "123456")
            .put("bot_token", "123456:token")
            .put("dns", "1.1.1.1,1.0.0.1")
            .put("public_ip", "vpn.example.org")
            .put("default_ports", "56000,56001,9000")
            .put("max_passwords", 50)
            .put("passwords", JSONObject().put(password, entry))
            .put("devices", JSONObject())
            .put("admin_profile", JSONObject()
                .put("workers_per_hash", 16)
                .put("protocol", "udp")
                .put("listen_port", 9000)
                .put("ports", "56000,56001,9000")
            )
    }

    private fun bindDevice(db: JSONObject, password: String, deviceId: String, privateKey: String) {
        db.getJSONObject("passwords").getJSONObject(password).put("device_id", deviceId)
        db.getJSONObject("devices").put(deviceId, device(deviceId, privateKey))
    }

    private fun device(deviceId: String, privateKey: String): JSONObject = JSONObject()
        .put("device_id", deviceId)
        .put("ip", "10.66.66.2")
        .put("priv_key", privateKey)
        .put("pub_key", "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=")

    private fun trafficBucket(date: String, downBytes: Long, upBytes: Long): JSONObject =
        JSONObject()
            .put("date", date)
            .put("down_bytes", downBytes)
            .put("up_bytes", upBytes)

    private fun bindEvent(index: Int): JSONObject =
        JSONObject()
            .put("device_id", "device-$index")
            .put("event_at", 1_700_000_000L + index)
            .put("status", "denied_mismatch")
}
