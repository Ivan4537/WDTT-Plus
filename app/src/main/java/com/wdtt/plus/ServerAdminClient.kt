package com.wdtt.plus

import com.jcraft.jsch.ChannelExec
import com.jcraft.jsch.Session
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

data class ServerAdminTarget(
    val host: String,
    val user: String,
    val sshPassword: String,
    val sshPort: Int,
    val mainPassword: String,
    val sshPrivateKey: String = "",
    val sshKeyPassphrase: String = "",
    val allowPasswordAuthentication: Boolean
)

data class ServerAdminProfileInfo(
    val vkHashes: String = "",
    val secondaryVkHash: String = "",
    val profileName: String = "",
    val workersPerHash: Int = 16,
    val protocol: String = "udp",
    val listenPort: Int = 9000,
    val sni: String = "",
    val noDns: Boolean = false,
    val ports: String = "56000,56001,9000",
    val deviceIds: List<String> = emptyList(),
    val updatedAt: Long = 0
) {
    val hasSavedFields: Boolean
        get() = updatedAt > 0L || vkHashes.isNotBlank() || secondaryVkHash.isNotBlank() || vpnProfileRestorableName(profileName).isNotBlank()
}

data class ServerAdminState(
    val publicHost: String,
    val effectivePublicHost: String,
    val dns: String,
    val defaultPorts: String,
    val maxPasswords: Int,
    val passwordCount: Int,
    val deviceCount: Int,
    val expiredCount: Int,
    val orphanDeviceCount: Int,
    val orphanDevices: List<ServerDeviceInfo>,
    val traffic: ServerTrafficPeriod,
    val adminTraffic: ServerTrafficPeriod,
    val adminProfile: ServerAdminProfileInfo,
    val clients: List<ServerClientInfo>
) {
    val linkHost: String
        get() = publicHost.ifBlank { "" }
}

data class ServerTrafficValue(val down: Long = 0, val up: Long = 0)

data class ServerTrafficPeriod(
    val today: ServerTrafficValue = ServerTrafficValue(),
    val week: ServerTrafficValue = ServerTrafficValue(),
    val month: ServerTrafficValue = ServerTrafficValue(),
    val all: ServerTrafficValue = ServerTrafficValue()
)

data class ServerDeviceInfo(
    val deviceId: String,
    val ip: String,
    val name: String,
    val manufacturer: String,
    val brand: String,
    val model: String,
    val androidVersion: String,
    val sdk: Int,
    val abi: String,
    val appVersion: String,
    val locale: String,
    val country: String,
    val timeZone: String,
    val remoteIp: String,
    val lastSeenAt: Long
)

data class ServerBindEvent(
    val deviceId: String,
    val deviceName: String,
    val deviceIp: String,
    val remoteIp: String,
    val country: String,
    val boundAt: Long,
    val unboundAt: Long,
    val eventAt: Long,
    val status: String,
    val note: String
)

data class ServerClientInfo(
    val password: String,
    val label: String,
    val vkHash: String,
    val ports: String,
    val status: String,
    val expiresAt: Long,
    val downBytes: Long,
    val upBytes: Long,
    val deviceId: String,
    val deviceName: String,
    val deviceIp: String,
    val deviceLastSeen: Long,
    val bindEventsCount: Int,
    val traffic: ServerTrafficPeriod,
    val device: ServerDeviceInfo?,
    val bindHistory: List<ServerBindEvent>
) {
    val title: String
        get() = label.ifBlank { "Без имени" }

    val isActive: Boolean
        get() = status == "active"

    val isBound: Boolean
        get() = deviceId.isNotBlank()
}

data class ServerClientCreateRequest(
    val days: Int,
    val label: String,
    val vkHash: String,
    val ports: String,
    val password: String? = null,
    val expiresAt: Long? = null,
    val deactivated: Boolean = false
)

data class ServerAdminActionResult(
    val message: String,
    val restartRequired: Boolean,
    val restarted: Boolean,
    val createdClient: ServerClientInfo?
)

object ServerAdminClient {
    private const val ADMIN_TIMEOUT = 45_000L
    private const val RESTART_TIMEOUT = 70_000L

    suspend fun list(target: ServerAdminTarget): ServerAdminState = withContext(Dispatchers.IO) {
        withSession(target) { ssh ->
            parseState(callAdmin(ssh, target, listOf("list")))
        }
    }

    suspend fun details(target: ServerAdminTarget, password: String): ServerClientInfo = withContext(Dispatchers.IO) {
        withSession(target) { ssh ->
            val json = callAdmin(ssh, target, listOf("details", "--password", password))
            json.optJSONObject("password")?.let(::parseClient)
                ?: throw IllegalStateException("сервер не вернул данные клиента")
        }
    }

    suspend fun create(target: ServerAdminTarget, request: ServerClientCreateRequest): ServerAdminActionResult =
        withContext(Dispatchers.IO) {
            withSession(target) { ssh ->
                val args = mutableListOf(
                    "create",
                    "--days", request.days.coerceIn(0, 365).toString()
                )
                if (request.label.isNotBlank()) args += listOf("--label", request.label.trim())
                if (request.vkHash.isNotBlank()) args += listOf("--vk-hash", request.vkHash.trim())
                if (request.ports.isNotBlank()) args += listOf("--ports", request.ports.trim())
                request.password?.takeIf { it.isNotBlank() }?.let { args += listOf("--client-password", it) }
                request.expiresAt?.let { args += listOf("--expires-at", it.coerceAtLeast(0).toString()) }
                if (request.deactivated) args += "--deactivated"
                actionFromResponse(callAdmin(ssh, target, args))
            }
        }

    suspend fun importClient(
        target: ServerAdminTarget,
        payload: ClientTransferPayload,
        targetPorts: String
    ): ServerAdminActionResult = create(
        target,
        ServerClientCreateRequest(
            days = 0,
            label = payload.label,
            vkHash = payload.vkHash,
            ports = targetPorts,
            password = payload.password,
            expiresAt = payload.expiresAt,
            deactivated = payload.deactivated
        )
    )

    suspend fun delete(target: ServerAdminTarget, password: String): ServerAdminActionResult =
        runPasswordAction(target, "delete", password)

    suspend fun unbind(target: ServerAdminTarget, password: String): ServerAdminActionResult =
        runPasswordAction(target, "unbind", password)

    suspend fun deactivate(target: ServerAdminTarget, password: String): ServerAdminActionResult =
        runPasswordAction(target, "deactivate", password)

    suspend fun activate(target: ServerAdminTarget, password: String): ServerAdminActionResult =
        runPasswordAction(target, "activate", password)

    suspend fun setExpiry(target: ServerAdminTarget, password: String, days: Int): ServerAdminActionResult =
        withContext(Dispatchers.IO) {
            withSession(target) { ssh ->
                actionFromResponse(
                    callAdmin(ssh, target, listOf("set-expiry", "--password", password, "--days", days.coerceIn(0, 365).toString()))
                )
            }
        }

    suspend fun setLabel(target: ServerAdminTarget, password: String, label: String): ServerAdminActionResult =
        withContext(Dispatchers.IO) {
            withSession(target) { ssh ->
                actionFromResponse(
                    callAdmin(ssh, target, listOf("set-label", "--password", password, "--label", label))
                )
            }
        }

    suspend fun setHash(target: ServerAdminTarget, password: String, hash: String): ServerAdminActionResult =
        withContext(Dispatchers.IO) {
            withSession(target) { ssh ->
                actionFromResponse(
                    callAdmin(ssh, target, listOf("set-hash", "--password", password, "--vk-hash", hash))
                )
            }
        }

    suspend fun setPorts(target: ServerAdminTarget, password: String, ports: String): ServerAdminActionResult =
        runArgsAction(target, listOf("set-ports", "--password", password, "--ports", ports))

    suspend fun setPassword(target: ServerAdminTarget, password: String, newPassword: String): ServerAdminActionResult =
        runArgsAction(target, listOf("set-password", "--password", password, "--new-password", newPassword))

    suspend fun updateClient(target: ServerAdminTarget, password: String, label: String, hash: String, ports: String): ServerAdminActionResult =
        withContext(Dispatchers.IO) {
            withSession(target) { ssh ->
                val requestedLabel = label.trim()
                val updated = actionFromResponse(callAdmin(ssh, target, listOf(
                    "update-client", "--password", password,
                    "--label", requestedLabel, "--vk-hash", hash, "--ports", ports
                )))
                val relabeled = actionFromResponse(
                    callAdmin(ssh, target, listOf("set-label", "--password", password, "--label", requestedLabel))
                )
                val savedClient = relabeled.createdClient ?: updated.createdClient
                if (requestedLabel.isNotBlank() && savedClient?.label.isNullOrBlank()) {
                    throw IllegalStateException("Название не сохранилось на сервере. Попробуйте обновить сервер WDTT Plus и повторить.")
                }
                relabeled.copy(
                    message = updated.message,
                    restartRequired = updated.restartRequired || relabeled.restartRequired,
                    restarted = updated.restarted || relabeled.restarted,
                    createdClient = savedClient
                )
            }
        }

    suspend fun setDns(target: ServerAdminTarget, value: String): ServerAdminActionResult =
        runArgsAction(target, listOf("set-dns", "--value", value))

    suspend fun setLimit(target: ServerAdminTarget, value: Int): ServerAdminActionResult =
        runArgsAction(target, listOf("set-limit", "--value", value.coerceIn(1, 500).toString()))

    suspend fun setDefaultPorts(target: ServerAdminTarget, value: String): ServerAdminActionResult =
        runArgsAction(target, listOf("set-default-ports", "--value", value))

    suspend fun setPublicHost(target: ServerAdminTarget, value: String): ServerAdminActionResult =
        runArgsAction(target, listOf("set-public-ip", "--value", value.ifBlank { "auto" }))

    suspend fun updateSettings(
        target: ServerAdminTarget,
        dns: String,
        limit: Int,
        defaultPorts: String,
        publicHost: String
    ): ServerAdminActionResult = runArgsAction(target, listOf(
        "update-settings", "--dns", dns,
        "--limit", limit.coerceIn(1, 500).toString(),
        "--ports", defaultPorts,
        "--public-ip", publicHost.ifBlank { "auto" }
    ))

    suspend fun updateAdminProfileFromTunnel(
        target: ServerAdminTarget,
        profile: ServerAdminProfileInfo
    ): ServerAdminActionResult = runArgsAction(target, buildAdminProfilePatchArgs(profile))

    suspend fun refreshPublicHost(target: ServerAdminTarget): ServerAdminActionResult =
        runArgsAction(target, listOf("refresh-public-ip"))

    suspend fun cleanupExpired(target: ServerAdminTarget): ServerAdminActionResult =
        runArgsAction(target, listOf("cleanup-expired"))

    suspend fun cleanupOrphans(target: ServerAdminTarget): ServerAdminActionResult =
        runArgsAction(target, listOf("cleanup-orphans"))

    suspend fun resetTraffic(target: ServerAdminTarget): ServerAdminActionResult =
        runArgsAction(target, listOf("reset-traffic"))

    suspend fun restart(target: ServerAdminTarget): ServerAdminActionResult =
        withContext(Dispatchers.IO) {
            withSession(target) { ssh ->
                ssh.exec(rootCommand("systemctl restart wdtt"), RESTART_TIMEOUT)
                ServerAdminActionResult(
                    message = "Готово",
                    restartRequired = false,
                    restarted = true,
                    createdClient = null
                )
            }
        }

    private suspend fun runPasswordAction(target: ServerAdminTarget, command: String, password: String): ServerAdminActionResult =
        withContext(Dispatchers.IO) {
            withSession(target) { ssh ->
                actionFromResponse(callAdmin(ssh, target, listOf(command, "--password", password)))
            }
        }

    private suspend fun runArgsAction(target: ServerAdminTarget, args: List<String>): ServerAdminActionResult =
        withContext(Dispatchers.IO) {
            withSession(target) { ssh -> actionFromResponse(callAdmin(ssh, target, args)) }
        }

    private fun <T> withSession(target: ServerAdminTarget, block: (AdminSshClient) -> T): T {
        var session: Session? = null
        try {
            session = createSession(target)
            return block(AdminSshClient(session, target.sshPassword))
        } finally {
            try { session?.disconnect() } catch (_: Exception) {}
        }
    }

    private fun callAdmin(ssh: AdminSshClient, target: ServerAdminTarget, args: List<String>): JSONObject {
        val command = buildString {
            append("/usr/local/bin/wdtt-server admin")
            append(" --config-dir /etc/wdtt")
            append(" --main-password ")
            append(shellQuote(target.mainPassword))
            args.forEach {
                append(' ')
                append(shellQuote(it))
            }
        }
        val output = ssh.exec(rootCommand(command), ADMIN_TIMEOUT)
        val json = extractJson(output)
        if (!json.optBoolean("ok", false)) {
            throw IllegalStateException(friendlyAdminError(json.optString("message", output)))
        }
        return json
    }

    private fun actionFromResponse(json: JSONObject): ServerAdminActionResult {
        val restartRequired = json.optBoolean("restart_required", false)
        if (restartRequired) {
            throw IllegalStateException(
                "Сервер вернул старый режим сохранения через перезапуск. " +
                    "Переустановите сервер из этой версии WDTT Plus, чтобы изменения применялись на живую."
            )
        }
        val createdClient = json.optJSONObject("password")?.let(::parseClient)
        return ServerAdminActionResult(
            message = json.optString("message", "Готово"),
            restartRequired = restartRequired,
            restarted = false,
            createdClient = createdClient
        )
    }

    private fun parseState(json: JSONObject): ServerAdminState {
        val server = json.optJSONObject("server") ?: JSONObject()
        val clientsJson = json.optJSONArray("passwords")
        val clients = buildList {
            if (clientsJson != null) {
                for (i in 0 until clientsJson.length()) {
                    val item = clientsJson.optJSONObject(i) ?: continue
                    add(parseClient(item))
                }
            }
        }
        val defaultPorts = server.optString("default_ports", "56000,56001,9000")
        return ServerAdminState(
            publicHost = server.optString("public_ip", ""),
            effectivePublicHost = server.optString("effective_public_ip", ""),
            dns = server.optString("dns", ""),
            defaultPorts = defaultPorts,
            maxPasswords = server.optInt("max_passwords", 50),
            passwordCount = server.optInt("password_count", clients.size),
            deviceCount = server.optInt("device_count", 0),
            expiredCount = server.optInt("expired_count", 0),
            orphanDeviceCount = server.optInt("orphan_device_count", 0),
            orphanDevices = buildList {
                val devices = server.optJSONArray("orphan_devices") ?: return@buildList
                for (i in 0 until devices.length()) {
                    devices.optJSONObject(i)?.let { add(parseDevice(it)) }
                }
            },
            traffic = parseTrafficPeriod(server.optJSONObject("traffic")),
            adminTraffic = parseTrafficPeriod(server.optJSONObject("admin_traffic")),
            adminProfile = parseAdminProfile(server.optJSONObject("admin_profile"), defaultPorts),
            clients = clients
        )
    }

    private fun parseAdminProfile(json: JSONObject?, defaultPorts: String): ServerAdminProfileInfo {
        val ports = json?.optString("ports", defaultPorts).orEmpty().ifBlank { defaultPorts }
        val listenPort = json?.optInt("listen_port", 0)
            ?.takeIf { it in 1..65535 }
            ?: ports.thirdPortOrDefault(9000)
        val deviceIds = buildList {
            val raw = json?.optJSONArray("device_ids") ?: return@buildList
            for (i in 0 until raw.length()) {
                raw.optString(i).trim().takeIf { it.isNotBlank() }?.let(::add)
            }
        }
        return ServerAdminProfileInfo(
            vkHashes = json?.optString("vk_hashes", "").orEmpty().trim(),
            secondaryVkHash = json?.optString("secondary_vk_hash", "").orEmpty().trim(),
            profileName = vpnProfileRestorableName(json?.optString("profile_name", "").orEmpty()),
            workersPerHash = (json?.optInt("workers_per_hash", 16) ?: 16).coerceIn(1, 128),
            protocol = json?.optString("protocol", "udp").orEmpty().lowercase().takeIf { it == "udp" || it == "tcp" } ?: "udp",
            listenPort = listenPort,
            sni = json?.optString("sni", "").orEmpty().trim(),
            noDns = json?.optBoolean("no_dns", false) ?: false,
            ports = ports,
            deviceIds = deviceIds,
            updatedAt = json?.optLong("updated_at", 0L) ?: 0L
        )
    }

    private fun parseClient(json: JSONObject): ServerClientInfo =
        ServerClientInfo(
            password = json.optString("password"),
            label = json.optString("label", "").trim(),
            vkHash = json.optString("vk_hash"),
            ports = json.optString("ports", "56000,56001,9000"),
            status = json.optString("status", "active"),
            expiresAt = json.optLong("expires_at", 0),
            downBytes = json.optLong("down_bytes", 0),
            upBytes = json.optLong("up_bytes", 0),
            deviceId = json.optString("device_id"),
            deviceName = json.optString("device_name"),
            deviceIp = json.optString("device_ip"),
            deviceLastSeen = json.optLong("device_last_seen", 0),
            bindEventsCount = json.optInt("bind_events_count", 0),
            traffic = parseTrafficPeriod(json.optJSONObject("traffic")),
            device = json.optJSONObject("device")?.let(::parseDevice),
            bindHistory = buildList {
                val history = json.optJSONArray("bind_history") ?: return@buildList
                for (i in 0 until history.length()) {
                    history.optJSONObject(i)?.let { add(parseBindEvent(it)) }
                }
            }
        )

    private fun parseTrafficPeriod(json: JSONObject?): ServerTrafficPeriod = ServerTrafficPeriod(
        today = parseTrafficValue(json?.optJSONObject("today")),
        week = parseTrafficValue(json?.optJSONObject("week")),
        month = parseTrafficValue(json?.optJSONObject("month")),
        all = parseTrafficValue(json?.optJSONObject("all"))
    )

    private fun parseTrafficValue(json: JSONObject?): ServerTrafficValue = ServerTrafficValue(
        down = json?.optLong("down", 0) ?: 0,
        up = json?.optLong("up", 0) ?: 0
    )

    private fun parseDevice(json: JSONObject): ServerDeviceInfo = ServerDeviceInfo(
        deviceId = json.optString("device_id"), ip = json.optString("ip"), name = json.optString("name"),
        manufacturer = json.optString("manufacturer"), brand = json.optString("brand"), model = json.optString("model"),
        androidVersion = json.optString("android_version"), sdk = json.optInt("sdk", 0), abi = json.optString("abi"),
        appVersion = json.optString("app_version"), locale = json.optString("locale"), country = json.optString("country"),
        timeZone = json.optString("time_zone"), remoteIp = json.optString("remote_ip"), lastSeenAt = json.optLong("last_seen_at", 0)
    )

    private fun parseBindEvent(json: JSONObject): ServerBindEvent = ServerBindEvent(
        deviceId = json.optString("device_id"), deviceName = json.optString("device_name"),
        deviceIp = json.optString("device_ip"), remoteIp = json.optString("remote_ip"), country = json.optString("country"),
        boundAt = json.optLong("bound_at", 0), unboundAt = json.optLong("unbound_at", 0), eventAt = json.optLong("event_at", 0),
        status = json.optString("status"), note = json.optString("note")
    )

    private fun createSession(target: ServerAdminTarget): Session {
        return createSshSession(
            host = target.host,
            user = target.user,
            credentials = SshCredentials(
                password = target.sshPassword,
                privateKey = target.sshPrivateKey,
                privateKeyPassphrase = target.sshKeyPassphrase,
                allowPasswordAuthentication = target.allowPasswordAuthentication
            ),
            port = target.sshPort
        )
    }

    private fun shellQuote(value: String): String =
        "'" + value.replace("'", "'\"'\"'") + "'"

    private fun rootCommand(command: String): String {
        val quoted = shellQuote(command)
        return "if command -v sudo >/dev/null 2>&1; then sudo -S bash -c $quoted; " +
            "elif [ \"\$(id -u)\" = \"0\" ]; then bash -c $quoted; " +
            "else echo 'error: root privileges required and sudo not found'; exit 1; fi"
    }

    private fun extractJson(output: String): JSONObject {
        val candidate = output
            .lineSequence()
            .map { it.trim() }
            .filter { it.startsWith("{") && it.endsWith("}") }
            .lastOrNull()
            ?: throw IllegalStateException(friendlyAdminError(output.ifBlank { "сервер не вернул JSON" }))
        return JSONObject(candidate)
    }

    private fun friendlyAdminError(raw: String): String {
        val text = raw.trim()
        val lower = text.lowercase()
        return when {
            "no_passwords_json" in lower ->
                "на сервере не найдена база WDTT Plus. Сначала выполните деплой."
            "admin_socket_unavailable" in lower ->
                "сервер ещё не поддерживает управление без перезапуска. Переустановите сервер из этой версии WDTT Plus."
            "неизвестная admin-команда" in lower || "flag provided but not defined" in lower ->
                "сервер ещё не поддерживает перенос или смену пароля клиента. Выполните установку сервера с сохранением данных из этой версии WDTT Plus."
            "главный пароль" in lower ->
                "главный пароль администратора не совпадает с сервером."
            "no such file" in lower || "not found" in lower && "wdtt-server" in lower ->
                "на сервере старый wdtt-server без admin-команд. Переустановите сервер из этой версии WDTT Plus."
            "permission denied" in lower || "authentication failed" in lower || "auth fail" in lower ->
                "не удалось войти по SSH. Проверьте логин, SSH-пароль или приватный ключ, пароль ключа и порт."
            "root privileges required" in lower || "sudo not found" in lower ->
                "для управления нужны root-права или sudo на сервере."
            "connection refused" in lower ->
                "сервер отклонил SSH-подключение. Проверьте SSH-порт."
            "timeout" in lower || "timed out" in lower ->
                "сервер не ответил вовремя."
            text.isBlank() -> "операция не выполнена"
            else -> text.take(220)
        }
    }
}

internal fun hasMeaningfulAdminProfileFields(profile: ServerAdminProfileInfo): Boolean =
    buildAdminProfilePatchArgs(profile).size > 1

internal fun buildAdminProfilePatchArgs(profile: ServerAdminProfileInfo): List<String> = buildList {
    add("update-admin-profile")
    profile.vkHashes.trim().takeIf { it.isNotBlank() }?.let {
        add("--vk-hashes")
        add(it)
    }
    profile.secondaryVkHash.trim().takeIf { it.isNotBlank() }?.let {
        add("--secondary-vk-hash")
        add(it)
    }
    vpnProfileRestorableName(profile.profileName).takeIf { it.isNotBlank() }?.let {
        add("--profile-name")
        add(it)
    }
    profile.workersPerHash.coerceIn(1, 128).takeIf { it != 16 }?.let {
        add("--workers")
        add(it.toString())
    }
    profile.protocol.trim().lowercase().takeIf { it == "tcp" }?.let {
        add("--protocol")
        add(it)
    }
    profile.listenPort.coerceIn(1, 65535).takeIf { it != 9000 }?.let {
        add("--listen-port")
        add(it.toString())
    }
    profile.sni.trim().takeIf { it.isNotBlank() }?.let {
        add("--sni")
        add(it)
    }
    profile.ports.trim().takeIf { it.isNotBlank() && it != "56000,56001,9000" }?.let {
        add("--ports")
        add(it)
    }
    if (profile.noDns) add("--no-dns")
}

private class AdminSshClient(private val session: Session, private val sudoPassword: String) {
    fun exec(command: String, timeout: Long): String {
        if (!session.isConnected) throw IllegalStateException("SSH-сессия разорвана")
        var channel: ChannelExec? = null
        val result = StringBuilder()
        try {
            channel = session.openChannel("exec") as ChannelExec
            channel.setCommand(command)
            val outStream = channel.outputStream
            val input = channel.inputStream
            val err = channel.errStream
            channel.connect(15_000)
            if (command.contains("sudo -S")) {
                outStream.write("$sudoPassword\n".toByteArray())
                outStream.flush()
            }
            val reader = input.bufferedReader()
            val errReader = err.bufferedReader()
            val started = System.currentTimeMillis()
            while (!channel.isClosed || reader.ready() || errReader.ready()) {
                if (System.currentTimeMillis() - started > timeout) {
                    try { channel.disconnect() } catch (_: Exception) {}
                    throw IllegalStateException("timeout")
                }
                if (reader.ready()) {
                    reader.readLine()?.let { result.appendLine(cleanShellLine(it)) }
                }
                if (errReader.ready()) {
                    errReader.readLine()
                        ?.takeIf { !it.contains("password for", ignoreCase = true) }
                        ?.let { result.appendLine(cleanShellLine(it)) }
                }
                if (!reader.ready() && !errReader.ready()) Thread.sleep(80)
            }
            val output = result.toString().trim()
            if (channel.exitStatus != 0) {
                if (output.startsWith("{") && output.endsWith("}")) return output
                throw IllegalStateException(output.ifBlank { "команда завершилась с кодом ${channel.exitStatus}" })
            }
            if (output.startsWith("error:", ignoreCase = true)) {
                throw IllegalStateException(output)
            }
            return output
        } finally {
            try { channel?.disconnect() } catch (_: Exception) {}
        }
    }

    private fun cleanShellLine(line: String): String =
        line.replace(Regex("\u001B\\[[;\\d]*m"), "")
}

private fun String.thirdPortOrDefault(default: Int): Int =
    split(",").map { it.trim().toIntOrNull() }.getOrNull(2)?.takeIf { it in 1..65535 } ?: default

fun ServerClientInfo.connectionLink(fallbackHost: String, publicHost: String, profileName: String = ""): String? {
    return buildServerConnectionLink(password, vkHash, ports, fallbackHost, publicHost, profileName)
}

fun buildServerConnectionLink(
    password: String,
    hashes: String,
    ports: String,
    fallbackHost: String,
    publicHost: String,
    profileName: String = ""
): String? {
    if (hashes.isBlank() || password.isBlank()) return null
    val parts = ports.split(",").map { it.trim().toIntOrNull() }
    if (parts.size != 3) return null
    val dtls = parts[0]?.takeIf { it in 1..65535 } ?: return null
    val wg = parts[1]?.takeIf { it in 1..65535 } ?: return null
    val local = parts[2]?.takeIf { it in 1..65535 } ?: return null
    val host = publicHost.ifBlank { fallbackHost }.trim()
    if (host.isBlank()) return null
    return WdttTransferCodec.buildConnectionLink(
        WdttLinkParts(
            host = host,
            dtlsPort = dtls,
            wgPort = wg,
            localPort = local,
            password = password,
            hashes = hashes,
            profileName = profileName
        )
    )
}
