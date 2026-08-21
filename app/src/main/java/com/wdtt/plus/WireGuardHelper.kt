package com.wdtt.plus

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import com.wireguard.config.Interface
import com.wireguard.config.Peer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.net.InetAddress
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

class WireGuardHelper(context: Context) {
    private val appContext = context.applicationContext
    private val backend = (appContext as WdttApplication).getBackend(context)

    private companion object {
        val wgMutex = Mutex()
        var sharedTunnel: WgTunnel? = null
        var sharedConfigFingerprint: String? = null
    }

    class WgTunnel(
        private val onExternalDown: (() -> Unit)? = null
    ) : Tunnel {
        @Volatile
        var suppressDownCallback: Boolean = false

        override fun getName() = "WDTT Plus"
        override fun onStateChange(newState: Tunnel.State) {
            if (newState != Tunnel.State.DOWN) return
            val isCurrentTunnel = sharedTunnel === this
            if (isCurrentTunnel) {
                sharedTunnel = null
                sharedConfigFingerprint = null
            }
            if (isCurrentTunnel && !suppressDownCallback) {
                onExternalDown?.invoke()
            }
        }
    }

    suspend fun startTunnel(configString: String) = wgMutex.withLock {
        startTunnelLocked(configString)
    }

    private suspend fun startTunnelLocked(configString: String) = withContext(Dispatchers.IO) {
        try {
            if (VpnService.prepare(appContext) != null) {
                throw IllegalStateException("VPN-разрешение не выдано")
            }

            val parsedConfig = Config.parse(ByteArrayInputStream(configString.toByteArray(Charsets.UTF_8)))

            val builder = Interface.Builder()
                .parseAddresses(parsedConfig.`interface`.addresses.joinToString(", ") { it.toString() })
            if (parsedConfig.`interface`.listenPort.isPresent) {
                builder.parseListenPort(parsedConfig.`interface`.listenPort.get().toString())
            }
            if (parsedConfig.`interface`.mtu.isPresent) {
                val serverMtu = parsedConfig.`interface`.mtu.get()
                // Используем серверное значение, но не менее 1280 для мобильных сетей
                builder.parseMtu(serverMtu.coerceAtLeast(1280).toString())
            } else {
                builder.parseMtu("1280")
            }
            builder.parsePrivateKey(parsedConfig.`interface`.keyPair.privateKey.toBase64())

            // 1. Пакеты, которые всегда исключаются (наше приложение, ВК)
            // 2. Получаю настройки пользователя
            val settingsStore = SettingsStore(appContext)
            val runningProfile = TunnelManager.activeTunnelProfile.value
            val routingSettings = if (runningProfile != null) {
                settingsStore.vpnRoutingSettingsForProfile(runningProfile)
            } else {
                settingsStore.vpnRoutingSettings.first()
            }
            val dnsSettings = if (runningProfile != null) {
                settingsStore.vpnDnsSettingsForProfile(runningProfile)
            } else {
                settingsStore.vpnDnsSettings.first()
            }
            val profileLabel = vpnProfileDisplayName(
                dnsSettings.profileIndex,
                settingsStore.profileNames.first(),
            )
            val profileDnsServers = parsedConfig.`interface`.dnsServers
                .mapNotNull { it.hostAddress }
            val effectiveDns = resolveEffectiveVpnDns(
                settings = dnsSettings,
                profileServers = profileDnsServers,
            )
            if (effectiveDns.servers.isNotEmpty()) {
                builder.parseDnsServers(effectiveDns.servers.joinToString(", "))
            }
            TunnelManager.noteVpnDnsEvent(
                key = "applied_${dnsSettings.profileIndex}_${effectiveDns.selectionId}",
                message = vpnDnsAppliedLogMessage(profileLabel, effectiveDns),
                warning = effectiveDns.fellBackToProfile,
            )
            val selectedPackages = routingSettings.appPackages
                .split(",")
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .toSet()
            val isWhitelist = routingSettings.isWhitelist
            val addressRules = routingSettings.addressRules
            val resolvedDomains = resolveAddressRuleDomains(addressRules)
            val addressRouting = runCatching {
                resolveVpnAddressRouting(
                    isWhitelist = isWhitelist,
                    rules = addressRules,
                    domainResolver = { domain -> resolvedDomains[domain].orEmpty() },
                )
            }.getOrElse { error ->
                Log.e("WG", "Address routing fallback: ${error.readableMessage()}")
                TunnelManager.noteAddressRoutingWarning(
                    key = "fallback",
                    message = if (isWhitelist) {
                        "Правила адресов не применены: ${error.message ?: "ошибка списка"}. " +
                            "БС адресов временно закрыт до исправления списка."
                    } else {
                        "Правила адресов не применены: ${error.message ?: "ошибка списка"}. " +
                            "VPN продолжает работать без адресных исключений."
                    },
                )
                VpnAddressRoutingResult(
                    allowedIps = if (isWhitelist) emptyList() else listOf("0.0.0.0/0"),
                )
            }
            val effectiveAllowedIps = effectiveWireGuardAllowedIps(
                isWhitelist = isWhitelist,
                addressRulesConfigured = addressRules.isNotEmpty(),
                addressRouting = addressRouting,
                vpnDnsIpv4 = effectiveDns.servers.filter(::isIpv4Literal),
            )
            val installedPackages = appContext.packageManager
                .getInstalledApplications(0)
                .map { it.packageName }
                .toSet()
            val routing = resolveVpnAppRouting(
                isWhitelist = isWhitelist,
                selectedPackages = selectedPackages,
                installedPackages = installedPackages,
                ownPackageName = appContext.packageName,
                addressWhitelistConfigured = isWhitelist && addressRules.isNotEmpty(),
            )
            if (routing.included.isNotEmpty()) {
                builder.includeApplications(routing.included)
            } else if (routing.excluded.isNotEmpty()) {
                builder.excludeApplications(routing.excluded)
            }
            val routedAllowedIps = applyVpnAppRoutingToAllowedIps(
                routing = routing,
                allowedIps = effectiveAllowedIps,
            )

            val newInterface = builder.build()

            val peerBuilder = Peer.Builder()
            val firstPeer = parsedConfig.peers.firstOrNull()
                ?: throw IllegalStateException("WireGuard config has no peer")
            firstPeer.let { peer ->
                peerBuilder.parsePublicKey(peer.publicKey.toBase64())
                if (peer.preSharedKey.isPresent) peerBuilder.parsePreSharedKey(peer.preSharedKey.get().toBase64())
                if (peer.endpoint.isPresent) peerBuilder.parseEndpoint(peer.endpoint.get().toString())
                if (peer.persistentKeepalive.isPresent) peerBuilder.parsePersistentKeepalive(peer.persistentKeepalive.get().toString())
            }
            // Android строит маршруты назначения из AllowedIPs. Пустой БС адресов
            // оставляет peer без маршрутов: VPN поднят, но пользовательский трафик в него
            // не попадёт. Для ЧС здесь уже рассчитано дополнение выбранных IPv4/CIDR.
            if (routedAllowedIps.isNotEmpty()) {
                peerBuilder.parseAllowedIPs(routedAllowedIps.joinToString(", "))
            }
            if (addressRouting.unresolvedDomains.isNotEmpty()) {
                val previewDomains = addressRouting.unresolvedDomains.take(3)
                val preview = previewDomains.joinToString(", ")
                val remaining = addressRouting.unresolvedDomains.size - previewDomains.size
                Log.w(
                    "WG",
                    "Address routing: unresolved domains=" +
                        addressRouting.unresolvedDomains.joinToString(", "),
                )
                TunnelManager.noteAddressRoutingWarning(
                    key = "unresolved_domains",
                    message = buildString {
                        append("Не удалось определить IPv4: ")
                        append(preview)
                        if (remaining > 0) append(" и ещё $remaining")
                        append(". Эти домены не применены; переподключите VPN после восстановления DNS.")
                    },
                )
            }
            
            val finalConfig = Config.Builder()
                .setInterface(newInterface)
                .addPeer(peerBuilder.build())
                .build()

            sharedTunnel?.let { existingTunnel ->
                val existingUp = runCatching {
                    backend.getState(existingTunnel) == Tunnel.State.UP
                }.getOrDefault(false)
                if (
                    shouldReuseRunningWireGuard(
                        tunnelUp = existingUp,
                        currentConfigFingerprint = sharedConfigFingerprint,
                        updatedConfig = finalConfig,
                    )
                ) {
                    Log.d("WG", "WireGuard config unchanged; keeping the current VPN interface")
                    return@withContext
                }
            }

            ensureGoBackendServiceStarted()

            // GoBackend умеет сам восстановить предыдущую конфигурацию, если новая не
            // поднимется. Не выключаем рабочий tunnel заранее, иначе этот rollback теряется.
            val previousTunnel = sharedTunnel
            val previousFingerprint = sharedConfigFingerprint
            previousTunnel?.suppressDownCallback = true
            val nextTunnel = WgTunnel {
                notifyWireGuardInterfaceDropped()
            }
            try {
                setTunnelUpWithRetry(nextTunnel, finalConfig)
            } catch (error: Exception) {
                previousTunnel?.suppressDownCallback = false
                val previousRestored = previousTunnel != null && runCatching {
                    backend.getState(previousTunnel) == Tunnel.State.UP
                }.getOrDefault(false)
                if (previousRestored) {
                    sharedTunnel = previousTunnel
                    sharedConfigFingerprint = previousFingerprint
                }
                throw error
            }
            sharedTunnel = nextTunnel
            sharedConfigFingerprint = wireGuardConfigFingerprint(finalConfig)
            Log.d("WG", "WireGuard tunnel started successfully")
        } catch (e: Exception) {
            val detailed = "WireGuard start failed: ${e.readableMessage()}; ${configString.describeWireGuardConfig()}"
            Log.e("WG", detailed)
            e.printStackTrace()
            throw IllegalStateException(detailed, e)
        }
    }

    suspend fun reloadTunnel() = wgMutex.withLock {
        withContext(Dispatchers.IO) {
            if (sharedTunnel == null) return@withContext
            try {
                val configFlow = TunnelManager.config.first() ?: return@withContext
                startTunnelLocked(configFlow)
                Log.d("WG", "WireGuard tunnel reloaded for updated profile settings")
            } catch (e: Exception) {
                Log.e("WG", "Failed to reload WireGuard: ${e.readableMessage()}")
                TunnelManager.noteVpnInterfaceReloadWarning(
                    message = "Новые настройки маршрутизации или DNS не применились: ${e.readableMessage()}. " +
                        "Рабочая конфигурация сохранена, если Android смог её восстановить.",
                )
            }
        }
    }

    private suspend fun resolveAddressRuleDomains(
        rules: List<VpnAddressRule>,
    ): Map<String, List<String>> {
        val domains = rules.asSequence()
            .filter { it.type == VpnAddressType.DOMAIN }
            .map(VpnAddressRule::value)
            .distinct()
            .toList()
        if (domains.isEmpty()) return emptyMap()

        val resolved = ConcurrentHashMap<String, List<String>>()
        val concurrency = Semaphore(16)
        withTimeoutOrNull(5_000L) {
            coroutineScope {
                domains.map { domain ->
                    async(Dispatchers.IO) {
                        concurrency.withPermit {
                            val addresses = runCatching {
                                runInterruptible {
                                    InetAddress.getAllByName(domain)
                                        .mapNotNull(InetAddress::getHostAddress)
                                }
                            }.getOrDefault(emptyList())
                            resolved[domain] = addresses
                        }
                    }
                }.forEach { it.await() }
            }
        }
        return resolved
    }

    suspend fun isTunnelUp(): Boolean = wgMutex.withLock {
        val current = sharedTunnel ?: return false
        return try {
            backend.getState(current) == Tunnel.State.UP
        } catch (e: Exception) {
            false
        }
    }

    suspend fun stopTunnel() = wgMutex.withLock {
        withContext(Dispatchers.IO) {
            try {
                sharedTunnel?.let {
                    it.suppressDownCallback = true
                    backend.setState(it, Tunnel.State.DOWN, null)
                    sharedTunnel = null
                    sharedConfigFingerprint = null
                    Log.d("WG", "WireGuard tunnel stopped")
                }
            } catch (e: Exception) {
                Log.e("WG", "Failed to stop WireGuard: ${e.readableMessage()}")
            }
        }
    }

    private fun notifyWireGuardInterfaceDropped() {
        val slotTransferred = isVpnSlotTransferred()
        TunnelManager.onWireGuardInterfaceDropped(slotTransferred)
        if (slotTransferred) {
            requestVpnSlotHandoverStop()
            return
        }

        // При смене VPN Android может уничтожить старый VpnService чуть раньше,
        // чем обновит владельца разрешения. Несколько коротких проверок закрывают
        // эту гонку, не добавляя постоянного polling: ветка выполняется только
        // после внешнего DOWN-сигнала от WireGuard.
        TunnelManager.scope.launch {
            repeat(20) {
                delay(250L)
                if (isVpnSlotTransferred()) {
                    TunnelManager.onWireGuardInterfaceDropped(vpnSlotTransferred = true)
                    requestVpnSlotHandoverStop()
                    return@launch
                }
            }
        }
    }

    /**
     * Не полагаемся только на StateFlow: callback WireGuard приходит в момент,
     * когда Android уже передаёт единственный VPN-слот. Доставляем сигнал в
     * работающую foreground-службу сразу, чтобы она закрыла нативный клиент и
     * не смогла запустить WireGuard повторно в этой сессии.
     */
    private fun requestVpnSlotHandoverStop() {
        runCatching {
            appContext.startService(
                Intent(appContext, TunnelService::class.java).apply {
                    action = ACTION_VPN_SLOT_REVOKED
                }
            )
        }.onFailure {
            Log.w("WG", "Не удалось немедленно передать остановку VPN-службе: ${it.readableMessage()}")
        }
    }

    private fun isVpnSlotTransferred(): Boolean =
        runCatching { VpnService.prepare(appContext) != null }.getOrDefault(false)

    private suspend fun ensureGoBackendServiceStarted() {
        withContext(Dispatchers.Main) {
            runCatching {
                val intent = Intent(appContext, GoBackend.VpnService::class.java)
                appContext.startService(intent)
            }.onFailure {
                Log.w("WG", "GoBackend service warmup failed: ${it.readableMessage()}")
            }
        }
        delay(300)
    }

    private suspend fun setTunnelUpWithRetry(nextTunnel: WgTunnel, finalConfig: Config) {
        var lastError: Exception? = null
        repeat(3) { attempt ->
            try {
                backend.setState(nextTunnel, Tunnel.State.UP, finalConfig)
                return
            } catch (e: Exception) {
                lastError = e
                Log.w("WG", "WireGuard UP attempt ${attempt + 1}/3 failed: ${e.readableMessage()}")
                runCatching { backend.setState(nextTunnel, Tunnel.State.DOWN, null) }
                ensureGoBackendServiceStarted()
                delay(250L * (attempt + 1))
            }
        }
        throw lastError ?: IllegalStateException("WireGuard UP failed")
    }

    private fun Throwable.readableMessage(): String {
        val text = message ?: localizedMessage
        return if (text.isNullOrBlank()) this::class.java.simpleName else "${this::class.java.simpleName}: $text"
    }

    private fun String.describeWireGuardConfig(): String {
        val lines = lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toList()
        val hasInterface = lines.any { it.equals("[Interface]", ignoreCase = true) }
        val hasPeer = lines.any { it.equals("[Peer]", ignoreCase = true) }
        val hasPrivateKey = lines.any { it.startsWith("PrivateKey", ignoreCase = true) }
        val hasPublicKey = lines.any { it.startsWith("PublicKey", ignoreCase = true) }
        val hasAddress = lines.any { it.startsWith("Address", ignoreCase = true) }
        val endpoint = lines.firstOrNull { it.startsWith("Endpoint", ignoreCase = true) }
            ?.substringAfter("=", "")
            ?.trim()
            ?.take(80)
            ?: "none"
        return "config lines=${lines.size}, interface=$hasInterface, peer=$hasPeer, privateKey=$hasPrivateKey, publicKey=$hasPublicKey, address=$hasAddress, endpoint=$endpoint"
    }
}

internal fun shouldReuseRunningWireGuard(
    tunnelUp: Boolean,
    currentConfigFingerprint: String?,
    updatedConfig: Config,
): Boolean =
    tunnelUp &&
        currentConfigFingerprint != null &&
        currentConfigFingerprint == wireGuardConfigFingerprint(updatedConfig)

internal fun wireGuardConfigFingerprint(config: Config): String =
    MessageDigest.getInstance("SHA-256")
        .digest(config.toWgQuickString().toByteArray(Charsets.UTF_8))
        .joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }
