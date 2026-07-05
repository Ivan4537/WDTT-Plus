package com.wdtt.plus.ui

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertTrue
import org.junit.Test

class ServerMigrationTest {
    @Test
    fun backupValidation_acceptsCurrentOwnerAndClientFields() {
        validatePasswordsDbStructure(database("client-a", "Телефон"))
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

    private fun database(password: String, label: String): JSONObject {
        val entry = JSONObject()
            .put("device_id", "")
            .put("expires_at", 0L)
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
}
