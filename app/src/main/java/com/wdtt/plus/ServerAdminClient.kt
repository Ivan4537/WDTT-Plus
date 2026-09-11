package com.wdtt.plus

import com.jcraft.jsch.ChannelExec
import com.jcraft.jsch.Session
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.util.Base64

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
    val workersPerHash: Int = 18,
    val protocol: String = "udp",
    val listenPort: Int = 9000,
    val sni: String = "",
    val noDns: Boolean = false,
    val vpnDnsSelectionId: String = VPN_DNS_PROFILE_ID,
    val vpnDnsCustomServers: List<String> = emptyList(),
    val vpnDnsStored: Boolean = false,
    val ports: String = "56000,56001,9000",
    val deviceIds: List<String> = emptyList(),
    val updatedAt: Long = 0
) {
    val hasSavedFields: Boolean
        get() = updatedAt > 0L || vkHashes.isNotBlank() || secondaryVkHash.isNotBlank() || vpnProfileRestorableName(profileName).isNotBlank()

    val vpnDnsDisplayLabel: String
        get() {
            if (!vpnDnsStored) return "не сохранён"
            val settings = VpnDnsSettingsSnapshot(
                profileIndex = 0,
                selectionId = vpnDnsSelectionId,
                customServers = vpnDnsCustomServers,
            )
            return if (settings.configuredServers.isEmpty()) {
                settings.title
            } else {
                "${settings.title} (${settings.configuredServers.joinToString(", ")})"
            }
        }
}

data class ServerAdminState(
    val publicHost: String,
    val effectivePublicHost: String,
    val dns: String,
    val defaultPorts: String,
    val maxPasswords: Int,
    val passwordCount: Int,
    val deviceCount: Int,
    val ownerDeviceCount: Int,
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

data class ServerBackupPolicyInfo(
    val enabled: Boolean,
    val intervalHours: Int,
    val retentionCount: Int
)

data class ServerStoredBackupInfo(
    val id: String,
    val createdAt: Long,
    val reason: String,
    val serverVersion: String,
    val passwordCount: Int,
    val deviceCount: Int,
    val sizeBytes: Long,
    val sha256: String,
    val valid: Boolean,
    val error: String,
    val contentMetadataAvailable: Boolean,
    val hasWireGuardKeys: Boolean,
    val hasBackupPolicy: Boolean,
    val outboundProfileMode: String
)

data class ServerBackupManagerInfo(
    val policy: ServerBackupPolicyInfo,
    val lastAttemptAt: Long,
    val lastSuccessAt: Long,
    val lastBackupId: String,
    val lastError: String,
    val nextRunAt: Long,
    val totalBytes: Long,
    val validCount: Int,
    val brokenCount: Int,
    val backups: List<ServerStoredBackupInfo>
)

data class ServerStoredBackupFile(
    val path: String,
    val mode: Int,
    val size: Long,
    val sha256: String,
    val data: ByteArray
)

data class ServerStoredBackupDocument(
    val id: String,
    val createdAt: Long,
    val reason: String,
    val serverVersion: String,
    val passwordCount: Int,
    val deviceCount: Int,
    val files: List<ServerStoredBackupFile>
)

object ServerAdminClient {
    private const val SAFE_DIRECT_CONNECT_TIMEOUT_MS = 4_000
    private const val ADMIN_TIMEOUT = 45_000L
    private const val RESTART_TIMEOUT = 70_000L
    private const val BACKUP_TIMEOUT = 120_000L
    private const val MAX_BACKUP_DOCUMENT_BYTES = 8 * 1024 * 1024

    suspend fun list(target: ServerAdminTarget): ServerAdminState = withContext(Dispatchers.IO) {
        parseState(callSafeAdmin(target, listOf("list")))
    }

    suspend fun details(target: ServerAdminTarget, password: String): ServerClientInfo = withContext(Dispatchers.IO) {
        val json = callSafeAdmin(target, listOf("details", "--password", password))
        json.optJSONObject("password")?.let(::parseClient)
            ?: throw IllegalStateException("сервер не вернул данные клиента")
    }

    internal suspend fun safeInspectThroughTunnel(
        target: ServerAdminTarget,
        operationArgs: List<String>,
        timeout: Long = ADMIN_TIMEOUT,
    ): String {
        require(operationArgs.isNotEmpty()) { "Не указан вид безопасной проверки" }
        val availability = TunnelManager.deploySafeRelayAvailability(target.host)
        if (!availability.available) {
            throw IllegalStateException(availability.unavailableMessage())
        }
        val args = listOf("safe-inspect") + operationArgs
        return when (val relay = TunnelManager.executeDeploySafeRequest(
            targetHost = target.host,
            requestJson = adminRequestJson(target, args),
            timeoutMs = timeout.coerceAtLeast(15_000L),
        )) {
            is DeploySafeRelayResult.Success -> parseAdminRelayResponse(relay.payload)
                .optString("safe_output", "")
                .takeIf(String::isNotBlank)
                ?: throw IllegalStateException("сервер не вернул результат безопасной проверки")
            is DeploySafeRelayResult.Unavailable -> throw IllegalStateException(relay.reason)
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
    ): ServerAdminActionResult {
        return try {
            runArgsAction(target, buildAdminProfilePatchArgs(profile))
        } catch (error: IllegalStateException) {
            val legacyArgs = buildAdminProfilePatchArgs(profile, includeVpnDns = false)
            val dnsArgsWereAdded = legacyArgs != buildAdminProfilePatchArgs(profile)
            val oldServer = error.message.orEmpty().contains("сервер ещё не поддерживает", ignoreCase = true)
            if (!dnsArgsWereAdded || !oldServer) throw error
            runArgsAction(target, legacyArgs).copy(
                message = "Профиль обновлён, но DNS внутри VPN не сохранён: обновите серверную часть.",
            )
        }
    }

    suspend fun refreshPublicHost(target: ServerAdminTarget): ServerAdminActionResult =
        runArgsAction(target, listOf("refresh-public-ip"))

    suspend fun cleanupExpired(target: ServerAdminTarget): ServerAdminActionResult =
        runArgsAction(target, listOf("cleanup-expired"))

    suspend fun cleanupOrphans(target: ServerAdminTarget): ServerAdminActionResult =
        runArgsAction(target, listOf("cleanup-orphans"))

    suspend fun resetTraffic(target: ServerAdminTarget): ServerAdminActionResult =
        runArgsAction(target, listOf("reset-traffic"))

    suspend fun backupStatus(target: ServerAdminTarget): ServerBackupManagerInfo = withContext(Dispatchers.IO) {
        parseBackupStatus(callSafeAdmin(target, listOf("backup-status"), BACKUP_TIMEOUT))
    }

    suspend fun configureBackups(
        target: ServerAdminTarget,
        enabled: Boolean,
        intervalHours: Int,
        retentionCount: Int
    ): ServerBackupManagerInfo = withContext(Dispatchers.IO) {
        require(intervalHours in 6..168) { "Интервал должен быть от 6 до 168 часов" }
        require(retentionCount in 2..90) { "Количество копий должно быть от 2 до 90" }
        withSession(target) { ssh ->
            parseBackupStatus(
                callAdmin(
                    ssh,
                    target,
                    listOf(
                        "backup-configure",
                        "--enabled", enabled.toString(),
                        "--interval-hours", intervalHours.toString(),
                        "--retention", retentionCount.toString()
                    ),
                    BACKUP_TIMEOUT
                )
            )
        }
    }

    suspend fun createBackup(
        target: ServerAdminTarget,
        reason: String = "manual"
    ): ServerBackupManagerInfo = withContext(Dispatchers.IO) {
        require(reason in setOf("manual", "pre_deploy", "pre_restore")) { "Некорректная причина резервной копии" }
        if (reason == "manual") {
            parseBackupStatus(callSafeAdmin(target, listOf("backup-create", "--reason", reason), BACKUP_TIMEOUT))
        } else {
            withSession(target) { ssh ->
                parseBackupStatus(callAdmin(ssh, target, listOf("backup-create", "--reason", reason), BACKUP_TIMEOUT))
            }
        }
    }

    suspend fun verifyBackup(target: ServerAdminTarget, id: String): ServerStoredBackupInfo = withContext(Dispatchers.IO) {
        requireBackupId(id)
        parseBackupInfo(
            callSafeAdmin(target, listOf("backup-verify", "--id", id), BACKUP_TIMEOUT)
                .getJSONObject("backup")
        )
    }

    suspend fun exportBackup(target: ServerAdminTarget, id: String): ServerStoredBackupDocument = withContext(Dispatchers.IO) {
        requireBackupId(id)
        parseBackupDocument(
            callSafeAdmin(target, listOf("backup-export", "--id", id), BACKUP_TIMEOUT)
                .getJSONObject("backup_document")
        )
    }

    suspend fun deleteBackup(target: ServerAdminTarget, id: String): ServerBackupManagerInfo = withContext(Dispatchers.IO) {
        requireBackupId(id)
        withSession(target) { ssh ->
            parseBackupStatus(
                callAdmin(
                    ssh,
                    target,
                    listOf("backup-delete", "--id", id, "--confirm", "УДАЛИТЬ"),
                    BACKUP_TIMEOUT
                )
            )
        }
    }

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

    private fun <T> withSession(
        target: ServerAdminTarget,
        safeReadOnly: Boolean = false,
        block: (AdminSshClient) -> T,
    ): T {
        var session: Session? = null
        try {
            session = createSession(target, safeReadOnly)
            return block(AdminSshClient(session, target.sshPassword))
        } finally {
            try { session?.disconnect() } catch (_: Exception) {}
        }
    }

    private fun callAdmin(
        ssh: AdminSshClient,
        target: ServerAdminTarget,
        args: List<String>,
        timeout: Long = ADMIN_TIMEOUT
    ): JSONObject {
        val request = JSONObject()
            .put("main_password", target.mainPassword)
            .put("args", JSONArray(args))
            .toString()
        val output = ssh.execRootWithStdin(
            command = "/usr/local/bin/wdtt-server admin --config-dir /etc/wdtt --request-stdin",
            stdinPayload = "$request\n",
            timeout = timeout
        )
        val json = extractJson(output)
        if (!json.optBoolean("ok", false)) {
            throw IllegalStateException(friendlyAdminError(json.optString("message", output)))
        }
        return json
    }

    private fun adminRequestJson(target: ServerAdminTarget, args: List<String>): String =
        JSONObject()
            .put("main_password", target.mainPassword)
            .put("args", JSONArray(args))
            .toString()

    private suspend fun callSafeAdmin(
        target: ServerAdminTarget,
        args: List<String>,
        timeout: Long = ADMIN_TIMEOUT,
    ): JSONObject {
        val availability = TunnelManager.deploySafeRelayAvailability(target.host)
        if (!availability.transportAvailable) {
            return withSession(target, safeReadOnly = true) { ssh -> callAdmin(ssh, target, args, timeout) }
        }

        var directFailure: Exception? = null
        var session: Session? = null
        try {
            session = createSession(
                target = target,
                safeReadOnly = true,
                connectTimeoutMs = SAFE_DIRECT_CONNECT_TIMEOUT_MS,
            )
        } catch (error: Exception) {
            if (!isConnectivityFailure(error)) throw error
            directFailure = error
        }
        val connectedSession = session
        if (connectedSession != null) {
            try {
                // После установленного SSH-соединения не повторяем команду другим
                // путём: ответ мог потеряться уже после выполнения на сервере.
                return callAdmin(AdminSshClient(connectedSession, target.sshPassword), target, args, timeout)
            } finally {
                runCatching { connectedSession.disconnect() }
            }
        }

        if (!availability.available) {
            throw IllegalStateException(availability.unavailableMessage(), directFailure)
        }

        TunnelManager.noteDeployNetworkRoute(
            key = "deploy_safe_relay",
            message = "Прямое подключение не ответило; безопасная операция выполняется через активный WDTT.",
            warning = false,
        )
        return when (val relay = TunnelManager.executeDeploySafeRequest(
            targetHost = target.host,
            requestJson = adminRequestJson(target, args),
            timeoutMs = timeout.coerceAtLeast(15_000L),
        )) {
            is DeploySafeRelayResult.Success -> parseAdminRelayResponse(relay.payload)
            is DeploySafeRelayResult.Unavailable -> {
                if (relay.reason.indicatesOldDeployRelay()) {
                    TunnelManager.noteDeployNetworkRoute(
                        key = "deploy_safe_relay_legacy",
                        message = "Сервер ещё не поддерживает безопасный канал Деплоя; используется совместимое прямое SSH-подключение.",
                        warning = true,
                    )
                    return withSession(target, safeReadOnly = true) { ssh -> callAdmin(ssh, target, args, timeout) }
                }
                val directText = directFailure?.message.orEmpty().substringBefore(" WDTT Plus")
                throw IllegalStateException(
                    buildString {
                        append("Безопасная операция не выполнена через активный WDTT: ")
                        append(relay.reason.ifBlank { "сервер не ответил" })
                        if (directText.isNotBlank()) append(". Прямая попытка: $directText")
                    },
                    directFailure,
                )
            }
        }
    }

    private fun parseAdminRelayResponse(payload: String): JSONObject {
        val json = runCatching { JSONObject(payload) }
            .getOrElse { throw IllegalStateException("сервер вернул повреждённый ответ безопасной операции", it) }
        if (!json.optBoolean("ok", false)) {
            throw IllegalStateException(friendlyAdminError(json.optString("message", "операция отклонена сервером")))
        }
        return json
    }

    private fun isConnectivityFailure(error: Throwable): Boolean =
        isSshConnectivityFailure(
            generateSequence(error) { it.cause }
                .mapNotNull { it.message?.takeIf(String::isNotBlank) }
                .joinToString(": "),
        )

    private fun String.indicatesOldDeployRelay(): Boolean {
        val value = lowercase()
        return "ещё не поддерживает" in value || "не поддерживает проверку через туннель" in value
    }

    private fun requireBackupId(id: String) {
        require(Regex("^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$").matches(id)) {
            "Некорректный идентификатор резервной копии"
        }
    }

    private fun parseBackupStatus(response: JSONObject): ServerBackupManagerInfo {
        val status = response.optJSONObject("backup_status")
            ?: throw IllegalStateException("сервер не вернул состояние резервного копирования")
        val policy = status.optJSONObject("policy") ?: JSONObject()
        val state = status.optJSONObject("state") ?: JSONObject()
        val backups = buildList {
            val array = status.optJSONArray("backups") ?: return@buildList
            for (index in 0 until array.length()) {
                array.optJSONObject(index)?.let { add(parseBackupInfo(it)) }
            }
        }
        return ServerBackupManagerInfo(
            policy = ServerBackupPolicyInfo(
                enabled = policy.optBoolean("enabled", false),
                intervalHours = policy.optInt("interval_hours", 24).coerceIn(6, 168),
                retentionCount = policy.optInt("retention_count", 14).coerceIn(2, 90)
            ),
            lastAttemptAt = state.optLong("last_attempt_at", 0L),
            lastSuccessAt = state.optLong("last_success_at", 0L),
            lastBackupId = state.optString("last_backup_id", ""),
            lastError = state.optString("last_error", "").take(240),
            nextRunAt = status.optLong("next_run_at", 0L),
            totalBytes = status.optLong("total_bytes", 0L).coerceAtLeast(0L),
            validCount = status.optInt("valid_count", 0).coerceAtLeast(0),
            brokenCount = status.optInt("broken_count", 0).coerceAtLeast(0),
            backups = backups
        )
    }

    private fun parseBackupInfo(json: JSONObject): ServerStoredBackupInfo = ServerStoredBackupInfo(
        id = json.optString("id", ""),
        createdAt = json.optLong("created_at", 0L),
        reason = json.optString("reason", "").take(40),
        serverVersion = json.optString("server_version", "").take(32),
        passwordCount = json.optInt("password_count", 0).coerceIn(0, 500),
        deviceCount = json.optInt("device_count", 0).coerceIn(0, 2048),
        sizeBytes = json.optLong("size_bytes", 0L).coerceAtLeast(0L),
        sha256 = json.optString("sha256", "").lowercase(),
        valid = json.optBoolean("valid", false),
        error = json.optString("error", "").take(240),
        contentMetadataAvailable = json.optBoolean("content_metadata", false),
        hasWireGuardKeys = json.optBoolean("has_wireguard_keys", false),
        hasBackupPolicy = json.optBoolean("has_backup_policy", false),
        outboundProfileMode = json.optString("outbound_profile_mode", "").takeIf {
            it in setOf("direct", "external_proxy", "tun_interface", "warp_free", "imported_wg", "wireguard_vps", "configured")
        }.orEmpty()
    )

    internal fun parseBackupDocument(json: JSONObject): ServerStoredBackupDocument {
        require(json.optString("format") == "wdtt-server-snapshot") { "неподдерживаемый формат серверной копии" }
        val version = json.optInt("version", 0)
        require(version in 1..3) { "неподдерживаемая версия серверной копии" }
        val id = json.optString("id")
        requireBackupId(id)
        var total = 0L
        val seen = mutableSetOf<String>()
        val files = buildList {
            val array = json.optJSONArray("files") ?: throw IllegalArgumentException("в серверной копии нет файлов")
            require(array.length() in 2..4) { "некорректное число файлов в серверной копии" }
            for (index in 0 until array.length()) {
                val item = array.getJSONObject(index)
                val path = item.getString("path")
                require(path in setOf("passwords.json", "wg-keys.dat", "outbound-profile.env", "backup-policy.json") && seen.add(path)) {
                    "недопустимый файл в серверной копии"
                }
                val size = item.getLong("size")
                val limit = when (path) {
                    "passwords.json" -> 5_000_000L
                    "wg-keys.dat" -> 4096L
                    "outbound-profile.env" -> 2L * 1024 * 1024
                    else -> 64L * 1024
                }
                require(item.optInt("mode", 0) == 384) { "небезопасные права файла $path" }
                require(size in 1..limit) { "некорректный размер файла $path" }
                val encoded = item.getString("data_b64")
                require(encoded.length <= (limit * 4 / 3 + 8).toInt()) { "файл $path слишком большой" }
                val data = Base64.getDecoder().decode(encoded)
                require(data.size.toLong() == size) { "размер файла $path не совпал" }
                val expected = item.getString("sha256").lowercase()
                require(Regex("^[0-9a-f]{64}$").matches(expected)) { "нет контрольной суммы файла $path" }
                require(java.security.MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) } == expected) {
                    "контрольная сумма файла $path не совпала"
                }
                total += size
                require(total <= MAX_BACKUP_DOCUMENT_BYTES) { "серверная копия слишком большая" }
                add(
                    ServerStoredBackupFile(
                        path = path,
                        mode = item.optInt("mode", 0),
                        size = size,
                        sha256 = expected,
                        data = data
                    )
                )
            }
        }
        require(files.any { it.path == "passwords.json" } && files.any { it.path == "wg-keys.dat" }) {
            "в серверной копии нет базы или WireGuard-ключей"
        }
        require(version < 3 || files.any { it.path == "backup-policy.json" }) {
            "в серверной копии нет настроек резервного копирования"
        }
        return ServerStoredBackupDocument(
            id = id,
            createdAt = json.optLong("created_at", 0L),
            reason = json.optString("reason", ""),
            serverVersion = json.optString("server_version", ""),
            passwordCount = json.optInt("password_count", 0),
            deviceCount = json.optInt("device_count", 0),
            files = files
        )
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
            ownerDeviceCount = server.optInt(
                "owner_device_count",
                server.optJSONObject("admin_profile")
                    ?.optJSONArray("device_ids")
                    ?.length()
                    ?: 0
            ),
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
            workersPerHash = (json?.optInt("workers_per_hash", 18) ?: 18).coerceIn(1, 128),
            protocol = json?.optString("protocol", "udp").orEmpty().lowercase().takeIf { it == "udp" || it == "tcp" } ?: "udp",
            listenPort = listenPort,
            sni = json?.optString("sni", "").orEmpty().trim(),
            noDns = json?.optBoolean("no_dns", false) ?: false,
            vpnDnsSelectionId = normalizeVpnDnsSelectionId(
                json?.optString("vpn_dns_selection", VPN_DNS_PROFILE_ID)
            ),
            vpnDnsCustomServers = decodeStoredCustomVpnDnsServers(
                json?.optString("vpn_dns_custom", "").orEmpty()
            ),
            vpnDnsStored = json?.has("vpn_dns_selection") == true,
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

    private fun createSession(
        target: ServerAdminTarget,
        safeReadOnly: Boolean = false,
        connectTimeoutMs: Int = 20_000,
    ): Session {
        return createSshSession(
            host = target.host,
            user = target.user,
            credentials = SshCredentials(
                password = target.sshPassword,
                privateKey = target.sshPrivateKey,
                privateKeyPassphrase = target.sshKeyPassphrase,
                allowPasswordAuthentication = target.allowPasswordAuthentication
            ),
            port = target.sshPort,
            routePolicy = if (safeReadOnly) {
                SshRoutePolicy.SAFE_READ_ONLY_DIRECT
            } else {
                SshRoutePolicy.SERVER_MUTATION_DIRECT_ONLY
            },
            connectTimeoutMs = connectTimeoutMs,
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
                "Сервер отклонил SSH-подключение. Проверьте SSH-порт."
            "timeout" in lower || "timed out" in lower ->
                "Сервер не ответил вовремя."
            text.isBlank() -> "операция не выполнена"
            else -> text.take(220)
        }.let(::capitalizeUserSentence)
    }
}

internal fun hasMeaningfulAdminProfileFields(profile: ServerAdminProfileInfo): Boolean =
    buildAdminProfilePatchArgs(profile).size > 1

internal fun buildAdminProfilePatchArgs(
    profile: ServerAdminProfileInfo,
    includeVpnDns: Boolean = true,
): List<String> = buildList {
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
    profile.workersPerHash.coerceIn(1, 128).takeIf { it != 18 }?.let {
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
    if (includeVpnDns && profile.vpnDnsStored) {
        add("--vpn-dns-selection")
        add(normalizeVpnDnsSelectionId(profile.vpnDnsSelectionId))
        add("--vpn-dns-custom")
        add(profile.vpnDnsCustomServers.joinToString(","))
    }
}

private class AdminSshClient(private val session: Session, private val sudoPassword: String) {
    companion object {
        private const val MAX_COMMAND_OUTPUT_CHARS = 16_000_000
    }

    fun execRootWithStdin(command: String, stdinPayload: String, timeout: Long): String {
        val isRoot = session.userName == "root"
        if (!isRoot) {
            exec("sudo -S -p '' -v", 20_000L, sudoPassword + "\n")
        }
        val quoted = "'" + command.replace("'", "'\"'\"'") + "'"
        val rootCommand = if (isRoot) {
            "bash -c $quoted"
        } else {
            "sudo -n bash -c $quoted"
        }
        return exec(rootCommand, timeout, stdinPayload)
    }

    fun exec(command: String, timeout: Long): String = exec(command, timeout, null)

    private fun exec(command: String, timeout: Long, stdinPayload: String?): String {
        if (!session.isConnected) throw IllegalStateException("SSH-сессия разорвана")
        var channel: ChannelExec? = null
        val stdout = StringBuilder()
        val stderr = StringBuilder()
        try {
            channel = session.openChannel("exec") as ChannelExec
            channel.setCommand(command)
            val outStream = channel.outputStream
            val input = channel.inputStream
            val err = channel.errStream
            channel.connect(15_000)
            if (stdinPayload != null) {
                outStream.write(stdinPayload.toByteArray(Charsets.UTF_8))
                outStream.flush()
            } else if (command.contains("sudo -S")) {
                outStream.write("$sudoPassword\n".toByteArray(Charsets.UTF_8))
                outStream.flush()
            }
            val reader = input.bufferedReader()
            val errReader = err.bufferedReader()
            val stdoutBuffer = CharArray(8 * 1024)
            val stderrBuffer = CharArray(4 * 1024)
            val started = System.currentTimeMillis()
            while (!channel.isClosed || reader.ready() || errReader.ready()) {
                if (System.currentTimeMillis() - started > timeout) {
                    try { channel.disconnect() } catch (_: Exception) {}
                    throw IllegalStateException("timeout")
                }
                if (reader.ready()) {
                    val read = reader.read(stdoutBuffer)
                    if (read > 0) {
                        require(stdout.length + stderr.length + read <= MAX_COMMAND_OUTPUT_CHARS) {
                            "ответ сервера превышает безопасный размер"
                        }
                        stdout.append(stdoutBuffer, 0, read)
                    }
                }
                if (errReader.ready()) {
                    val read = errReader.read(stderrBuffer)
                    if (read > 0) {
                        require(stdout.length + stderr.length + read <= MAX_COMMAND_OUTPUT_CHARS) {
                            "ответ сервера превышает безопасный размер"
                        }
                        stderr.append(stderrBuffer, 0, read)
                    }
                }
                if (!reader.ready() && !errReader.ready()) Thread.sleep(80)
            }
            val cleanStdout = cleanShellOutput(stdout.toString()).trim()
            val cleanStderr = cleanShellOutput(stderr.toString())
                .lineSequence()
                .filterNot { it.contains("password for", ignoreCase = true) }
                .joinToString("\n")
                .trim()
            val output = listOf(cleanStdout, cleanStderr)
                .filter(String::isNotBlank)
                .joinToString("\n")
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

    private fun cleanShellOutput(value: String): String =
        value.replace(Regex("\u001B\\[[;\\d]*m"), "")
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
    if (password.isBlank()) return null
    val normalizedHashes = VkJoinLink.normalizeHashes(hashes) ?: return null
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
            hashes = normalizedHashes,
            profileName = profileName
        )
    )
}
