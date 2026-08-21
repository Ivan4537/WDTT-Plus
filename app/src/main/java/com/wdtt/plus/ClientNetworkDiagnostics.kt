package com.wdtt.plus

import android.content.Context
import android.net.ConnectivityManager
import android.net.DnsResolver
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.CancellationSignal
import android.os.SystemClock
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URL
import java.net.UnknownHostException
import java.util.concurrent.Executor
import javax.net.ssl.HttpsURLConnection
import kotlin.coroutines.resume

data class ClientNetworkDiagnosticsReport(
    val summaryLines: List<String>,
    val items: List<DeviceCheckItem>
)

private data class DiagnosticNetwork(
    val network: Network,
    val capabilities: NetworkCapabilities,
    val linkProperties: LinkProperties?,
    val activeNetworkIsVpn: Boolean,
    val mobileOperator: String
)

private data class NetworkProbeResult(
    val label: String,
    val success: Boolean,
    val result: String,
    val elapsedMs: Long
) {
    fun display(): String = "$label: $result (${elapsedMs} мс)"
}

internal data class DnsResponseStatus(
    val responseCode: Int,
    val answerCount: Int,
    val truncated: Boolean
)

internal data class ClientDnsPathAssessment(
    val status: String,
    val recommendation: String,
    val severity: DeviceCheckSeverity,
    val action: DeviceCheckAction?
)

private const val NETWORK_PROBE_TIMEOUT_MS = 4_500L
private const val SOCKET_TIMEOUT_MS = 3_500
private val directExecutor = Executor { command -> command.run() }
private val clientDnsServers = listOf("77.88.8.8", "77.88.8.1")
private val clientDnsRouteOrder = listOf(
    "77.88.8.8 UDP",
    "77.88.8.1 UDP",
    "77.88.8.8 TCP",
    "77.88.8.1 TCP"
)
internal const val clientDnsProbeHost = "api.vk.me"
internal val primaryVkDiagnosticHosts = linkedSetOf(
    "api.vk.me",
    "calls.okcdn.ru"
)
internal val reserveVkDiagnosticHosts = linkedSetOf(
    "vk.ru",
    "login.vk.ru",
    "api.vk.ru",
    "id.vk.ru",
    "static.vk.ru",
    "vk.com",
    "id.vk.com",
    "static.vk.com"
)
private val vkDnsHosts = (primaryVkDiagnosticHosts + reserveVkDiagnosticHosts).toList()
private val vkHttpsTargets = listOf(
    "api.vk.me" to "https://api.vk.me/method/users.get?v=5.276",
    "calls.okcdn.ru" to "https://calls.okcdn.ru/fb.do",
    "vk.ru" to "https://vk.ru/",
    "login.vk.ru" to "https://login.vk.ru/",
    "api.vk.ru" to "https://api.vk.ru/method/users.get?v=5.275",
    "id.vk.ru" to "https://id.vk.ru/",
    "static.vk.ru" to "https://static.vk.ru/",
    "vk.com" to "https://vk.com/",
    "id.vk.com" to "https://id.vk.com/",
    "static.vk.com" to "https://static.vk.com/"
)

suspend fun collectClientNetworkDiagnostics(context: Context): ClientNetworkDiagnosticsReport =
    collectClientNetworkDiagnostics(context, retryOnNetworkChange = true)

internal suspend fun collectVpnDnsRuntimeDiagnostic(
    context: Context,
    settings: VpnDnsSettingsSnapshot,
    tunnelRunning: Boolean,
    runningProfile: Int?,
): DeviceCheckItem? = withContext(Dispatchers.IO) {
    if (
        !tunnelRunning ||
        runningProfile != settings.profileIndex ||
        settings.selectionId == VPN_DNS_PROFILE_ID ||
        settings.configuredServers.isEmpty()
    ) {
        return@withContext null
    }

    val connectivityManager = context.getSystemService(ConnectivityManager::class.java)
        ?: return@withContext null
    val network = runCatching { connectivityManager.activeNetwork }.getOrNull()
    val capabilities = network?.let {
        runCatching { connectivityManager.getNetworkCapabilities(it) }.getOrNull()
    }
    if (network == null || capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) != true) {
        return@withContext DeviceCheckItem(
            title = "Доступность выбранного DNS внутри VPN",
            status = "VPN-сеть Android не найдена",
            details = "Туннель отмечен как запущенный, но Android не вернул активную VPN-сеть для безопасной проверки выбранного DNS.",
            recommendation = "Подождите несколько секунд и повторите проверку. Если интернет не работает, переподключите VPN.",
            severity = DeviceCheckSeverity.Warning,
        )
    }

    val servers = settings.configuredServers.distinct()
    val results = coroutineScope {
        servers.flatMap { server ->
            listOf(
                async(Dispatchers.IO) {
                    timedProbe("$server UDP") {
                        directDnsQuery(network, server, useTcp = false, host = "example.com")
                    }
                },
                async(Dispatchers.IO) {
                    timedProbe("$server TCP") {
                        directDnsQuery(network, server, useTcp = true, host = "example.com")
                    }
                },
            )
        }.awaitAll()
    }
    val networkAfterProbe = runCatching { connectivityManager.activeNetwork }.getOrNull()
    if (networkAfterProbe != network) {
        return@withContext DeviceCheckItem(
            title = "Доступность выбранного DNS внутри VPN",
            status = "сеть изменилась во время проверки",
            details = "Результаты для прежней VPN-сети отброшены.",
            recommendation = "Дождитесь устойчивого подключения и повторите проверку устройства.",
            severity = DeviceCheckSeverity.Info,
        )
    }

    val respondingServers = servers.count { server ->
        results.any { result -> result.success && result.label.startsWith("$server ") }
    }
    DeviceCheckItem(
        title = "Доступность выбранного DNS внутри VPN",
        status = "$respondingServers из ${servers.size} серверов отвечают",
        details = results.joinToString(". ") { it.display() } +
            ". Проверка выполнена через активную VPN-сеть; достаточно ответа по UDP или TCP.",
        recommendation = if (respondingServers == servers.size) {
            ""
        } else {
            "Выберите другой вариант в «Туннель → DNS внутри VPN» либо верните «Как в профиле» и повторите проверку."
        },
        severity = if (respondingServers == servers.size) {
            DeviceCheckSeverity.Ok
        } else {
            DeviceCheckSeverity.Warning
        },
    )
}

private suspend fun collectClientNetworkDiagnostics(
    context: Context,
    retryOnNetworkChange: Boolean
): ClientNetworkDiagnosticsReport =
    withContext(Dispatchers.IO) {
        val connectivityManager = context.getSystemService(ConnectivityManager::class.java)
        val diagnosticNetwork = connectivityManager?.let { selectDiagnosticNetwork(context, it) }
        if (diagnosticNetwork == null) {
            return@withContext ClientNetworkDiagnosticsReport(
                summaryLines = listOf("Активная физическая сеть для проверки DNS/VK не найдена"),
                items = listOf(
                    DeviceCheckItem(
                        title = "Сетевой путь телефона",
                        status = "физическая сеть не найдена",
                        details = "Не удалось выбрать сеть без VPN для безопасной проверки DNS и узлов VK/OK.",
                        recommendation = "Отключите режим полёта, включите Wi‑Fi или мобильную сеть и повторите диагностику.",
                        severity = DeviceCheckSeverity.Warning,
                        action = DeviceCheckAction.NetworkSettings
                    )
                )
            )
        }

        val networkItem = buildNetworkPathItem(diagnosticNetwork)
        val (dnsResults, clientDnsResults, httpsResults) = coroutineScope {
            val systemDns = async { probeSystemDns(diagnosticNetwork.network) }
            val clientDns = async { probeClientDns(diagnosticNetwork.network) }
            val vkHttps = async { probeVkHttps(diagnosticNetwork.network) }
            Triple(systemDns.await(), clientDns.await(), vkHttps.await())
        }

        val networkAfterProbes = selectDiagnosticNetwork(context, connectivityManager)
        if (networkAfterProbes?.network != diagnosticNetwork.network) {
            if (retryOnNetworkChange && networkAfterProbes != null) {
                val retried = collectClientNetworkDiagnostics(
                    context,
                    retryOnNetworkChange = false
                )
                return@withContext retried.copy(
                    summaryLines = listOf(
                        "Сеть изменилась во время диагностики; проверки автоматически повторены на новой сети"
                    ) + retried.summaryLines,
                    items = listOf(networkChangeItem(retried = true)) + retried.items
                )
            }
            return@withContext ClientNetworkDiagnosticsReport(
                summaryLines = listOf(
                    "Сеть изменилась во время диагностики; результаты устаревшей сети отброшены"
                ),
                items = listOf(networkChangeItem(retried = false))
            )
        }

        val primaryDnsResults = dnsResults.filter { it.label in primaryVkDiagnosticHosts }
        val reserveDnsResults = dnsResults.filter { it.label in reserveVkDiagnosticHosts }
        val primaryDnsOk = primaryDnsResults.count { it.success }
        val clientUdp = clientDnsResults.filter { it.label.endsWith("UDP") }
        val clientTcp = clientDnsResults.filter { it.label.endsWith("TCP") }
        val clientUdpOk = clientUdp.count { it.success }
        val clientTcpOk = clientTcp.count { it.success }
        val primaryHttpsResults = httpsResults.filter { it.label in primaryVkDiagnosticHosts }
        val reserveHttpsResults = httpsResults.filter { it.label in reserveVkDiagnosticHosts }
        val primaryHttpsOk = primaryHttpsResults.count { it.success }

        val systemPrimaryApiWorks = dnsResults.firstOrNull { it.label == clientDnsProbeHost }?.success == true
        val successfulClientDnsRoutes = clientDnsResults
            .filter { it.success }
            .mapTo(linkedSetOf()) { it.label }
        val clientDnsAssessment = assessClientDnsPath(successfulClientDnsRoutes, systemPrimaryApiWorks)

        val dnsItem = DeviceCheckItem(
            title = "DNS основного VKCalls на телефоне",
            status = "$primaryDnsOk из ${primaryDnsResults.size} основных узлов разрешаются",
            details = primaryDnsResults.joinToString(". ") { it.display() } + ". " +
                "Резервные legacy- и совместимые узлы: " +
                reserveDnsResults.joinToString(". ") { it.display() } + ".",
            recommendation = if (primaryDnsOk == primaryDnsResults.size) "" else
                "Быстрый VKCalls может быть недоступен. Проверьте системный или Private DNS и сеть оператора; приложение также попробует legacy-резерв.",
            severity = if (primaryDnsOk == primaryDnsResults.size) DeviceCheckSeverity.Ok else DeviceCheckSeverity.Warning,
            action = if (primaryDnsOk == primaryDnsResults.size) null else DeviceCheckAction.NetworkSettings
        )

        val clientDnsItem = DeviceCheckItem(
            title = "DNS-путь нативного клиента",
            status = clientDnsAssessment.status,
            details = clientDnsResults.joinToString(". ") { it.display() } +
                ". Нативный клиент проверяет эти прямые DNS-пути, а при их недоступности автоматически использует системный DNS Android.",
            recommendation = clientDnsAssessment.recommendation,
            severity = clientDnsAssessment.severity,
            action = clientDnsAssessment.action
        )

        val httpsItem = DeviceCheckItem(
            title = "Основной VKCalls HTTPS с телефона",
            status = "$primaryHttpsOk из ${primaryHttpsResults.size} основных узлов отвечают",
            details = primaryHttpsResults.joinToString(". ") { it.display() } + ". " +
                "Резервные legacy- и совместимые узлы: " +
                reserveHttpsResults.joinToString(". ") { it.display() } +
                ". Любой HTTP-код означает, что DNS, TCP и TLS до узла отработали; авторизация и VK-хеш не используются.",
            recommendation = if (primaryHttpsOk == primaryHttpsResults.size) "" else
                "Для быстрого VKCalls сеть должна пропускать api.vk.me и calls.okcdn.ru. При их недоступности приложение попробует legacy-резерв.",
            severity = if (primaryHttpsOk == primaryHttpsResults.size) DeviceCheckSeverity.Ok else DeviceCheckSeverity.Warning,
            action = if (primaryHttpsOk == primaryHttpsResults.size) null else DeviceCheckAction.NetworkSettings
        )

        val recentNetworkEvents = buildRecentNetworkEventsItem()
        ClientNetworkDiagnosticsReport(
            summaryLines = listOf(
                "Физическая сеть диагностики: ${networkPathSummary(diagnosticNetwork)}",
                "DNS основного VKCalls: $primaryDnsOk/${primaryDnsResults.size}",
                "DNS клиента: ${clientDnsAssessment.status}; UDP $clientUdpOk/${clientUdp.size}, TCP $clientTcpOk/${clientTcp.size}",
                "HTTPS основного VKCalls: $primaryHttpsOk/${primaryHttpsResults.size}"
            ),
            items = buildList {
                add(networkItem)
                add(dnsItem)
                add(clientDnsItem)
                add(httpsItem)
                recentNetworkEvents?.let(::add)
            }
        )
    }

internal fun assessClientDnsPath(
    successfulDirectRoutes: Set<String>,
    systemPrimaryApiWorks: Boolean
): ClientDnsPathAssessment {
    val selectedDirectRoute = clientDnsRouteOrder.firstOrNull(successfulDirectRoutes::contains)
    return when {
        selectedDirectRoute == "77.88.8.8 UDP" -> ClientDnsPathAssessment(
            status = "основной UDP DNS доступен",
            recommendation = "",
            severity = DeviceCheckSeverity.Ok,
            action = null
        )
        selectedDirectRoute == "77.88.8.1 UDP" -> ClientDnsPathAssessment(
            status = "резервный UDP DNS доступен",
            recommendation = "Основной прямой DNS ограничен, но нативный клиент автоматически выберет рабочий резервный адрес.",
            severity = DeviceCheckSeverity.Info,
            action = null
        )
        selectedDirectRoute?.endsWith(" TCP") == true -> ClientDnsPathAssessment(
            status = "UDP DNS недоступен, TCP отвечает",
            recommendation = "Оператор ограничивает прямой UDP DNS, но нативный клиент автоматически использует рабочий TCP-путь.",
            severity = DeviceCheckSeverity.Info,
            action = null
        )
        systemPrimaryApiWorks -> ClientDnsPathAssessment(
            status = "прямой DNS недоступен, используется системный DNS",
            recommendation = "Это штатный автоматический fallback: менять DNS вручную не требуется.",
            severity = DeviceCheckSeverity.Info,
            action = null
        )
        else -> ClientDnsPathAssessment(
            status = "DNS до VK недоступен",
            recommendation = "Не ответили ни прямые DNS-пути клиента, ни системный DNS Android. Проверьте Private DNS или повторите проверку в другой сети.",
            severity = DeviceCheckSeverity.Error,
            action = DeviceCheckAction.NetworkSettings
        )
    }
}

private fun selectDiagnosticNetwork(context: Context, connectivityManager: ConnectivityManager): DiagnosticNetwork? {
    val activeNetwork = runCatching { connectivityManager.activeNetwork }.getOrNull()
    val activeCapabilities = activeNetwork?.let {
        runCatching { connectivityManager.getNetworkCapabilities(it) }.getOrNull()
    }
    val activeNetworkIsVpn = activeCapabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true

    val candidates = runCatching { connectivityManager.allNetworks.toList() }.getOrDefault(emptyList())
        .mapNotNull { network ->
            val capabilities = runCatching { connectivityManager.getNetworkCapabilities(network) }.getOrNull()
                ?: return@mapNotNull null
            if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) ||
                !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            ) {
                return@mapNotNull null
            }
            Triple(network, capabilities, runCatching { connectivityManager.getLinkProperties(network) }.getOrNull())
        }

    val selected = candidates.maxByOrNull { (network, capabilities, _) ->
        var score = 0
        if (network == activeNetwork) score += 100
        if (capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) score += 50
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) score += 10
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) score += 5
        score
    } ?: return null

    return DiagnosticNetwork(
        network = selected.first,
        capabilities = selected.second,
        linkProperties = selected.third,
        activeNetworkIsVpn = activeNetworkIsVpn,
        mobileOperator = mobileOperatorSummary(context, selected.second)
    )
}

private fun mobileOperatorSummary(context: Context, capabilities: NetworkCapabilities): String {
    if (!capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) return "не применяется"
    return runCatching {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            return@runCatching "не определён для выбранной сети на этой версии Android"
        }
        val dataSubscriptionId = SubscriptionManager.getDefaultDataSubscriptionId()
        if (dataSubscriptionId < 0) {
            return@runCatching "не определён для выбранной data-SIM"
        }
        val baseManager = context.getSystemService(TelephonyManager::class.java)
        val manager = baseManager?.createForSubscriptionId(dataSubscriptionId)
            ?: return@runCatching "телефонная служба недоступна"
        val names = listOf(manager.networkOperatorName, manager.simOperatorName)
            .map(String::trim)
            .filter(String::isNotBlank)
            .distinct()
        buildString {
            append(names.joinToString(" / ").ifBlank { "не определён" })
            append(", roaming=")
            append(manager.isNetworkRoaming)
            append(", основная data-SIM")
        }
    }.getOrDefault("недоступен")
}

private fun networkChangeItem(retried: Boolean): DeviceCheckItem = DeviceCheckItem(
    title = "Смена сети во время диагностики",
    status = if (retried) "проверки повторены" else "результаты отброшены",
    details = if (retried) {
        "Android сменил физическую сеть или мобильную data-SIM во время проверки. " +
            "Результаты старой сети не использованы; пункты ниже относятся к новой сети."
    } else {
        "Android сменил физическую сеть или мобильную data-SIM, поэтому ошибки старого " +
            "сетевого дескриптора (например ENONET/ENETUNREACH) не считаются отказом DNS или устройства."
    },
    recommendation = if (retried) "" else
        "Дождитесь устойчивого подключения к нужной сети и повторите проверку устройства.",
    severity = if (retried) DeviceCheckSeverity.Info else DeviceCheckSeverity.Warning,
    action = if (retried) null else DeviceCheckAction.NetworkSettings
)

private fun buildNetworkPathItem(network: DiagnosticNetwork): DeviceCheckItem {
    val capabilities = network.capabilities
    val validated = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
    val details = networkPathSummary(network)
    return DeviceCheckItem(
        title = "Сетевой путь телефона",
        status = if (validated) "физическая сеть подтверждена" else "интернет не подтверждён Android",
        details = details,
        recommendation = if (validated) "" else
            "Проверьте ограничения оператора, captive portal или доступность интернета без VPN.",
        severity = if (validated) DeviceCheckSeverity.Ok else DeviceCheckSeverity.Warning,
        action = if (validated) null else DeviceCheckAction.NetworkSettings
    )
}

private fun networkPathSummary(network: DiagnosticNetwork): String {
    val capabilities = network.capabilities
    val properties = network.linkProperties
    val transports = buildList {
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) add("мобильная")
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) add("Wi‑Fi")
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) add("Ethernet")
    }.joinToString().ifBlank { "не определена" }
    val hasIpv4 = properties?.linkAddresses?.any { it.address is Inet4Address } == true
    val hasIpv6 = properties?.linkAddresses?.any { it.address is Inet6Address } == true
    val dnsServers = properties?.dnsServers
        ?.joinToString { it.hostAddress.orEmpty() }
        ?.ifBlank { "не указаны" }
        ?: "недоступны"
    val privateDns = if (properties?.isPrivateDnsActive == true) {
        properties.privateDnsServerName?.takeIf(String::isNotBlank)?.let { "включён ($it)" } ?: "включён"
    } else {
        "выключен"
    }
    val nat64 = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        properties?.nat64Prefix?.toString() ?: "нет"
    } else {
        "не поддерживается Android"
    }
    val mtu = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        properties?.mtu?.toString() ?: "недоступно"
    } else {
        "не поддерживается Android"
    }
    return "Сеть: $transports; validated=${capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)}; " +
        "metered=${!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)}; " +
        "активный VPN=${network.activeNetworkIsVpn}; оператор=${network.mobileOperator}; " +
        "IPv4=$hasIpv4; IPv6=$hasIpv6; NAT64=$nat64; " +
        "MTU=$mtu; системные DNS: $dnsServers; Private DNS: $privateDns. " +
        "Локальные IP-адреса телефона в отчёт не включаются."
}

private suspend fun probeSystemDns(network: Network): List<NetworkProbeResult> = coroutineScope {
    vkDnsHosts.map { host ->
        async(Dispatchers.IO) {
            timedProbe(host) {
                val addresses = resolveWithSystemDns(network, host)
                val ipv4 = addresses.count { it is Inet4Address }
                val ipv6 = addresses.count { it is Inet6Address }
                if (addresses.isEmpty()) error("пустой DNS-ответ")
                "OK, IPv4=$ipv4, IPv6=$ipv6"
            }
        }
    }.awaitAll()
}

private suspend fun resolveWithSystemDns(network: Network, host: String): List<InetAddress> =
    withTimeout(NETWORK_PROBE_TIMEOUT_MS) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            suspendCancellableCoroutine { continuation ->
                val cancellationSignal = CancellationSignal()
                continuation.invokeOnCancellation { cancellationSignal.cancel() }
                DnsResolver.getInstance().query(
                    network,
                    host,
                    DnsResolver.FLAG_EMPTY,
                    directExecutor,
                    cancellationSignal,
                    object : DnsResolver.Callback<List<InetAddress>> {
                        override fun onAnswer(answer: List<InetAddress>, rcode: Int) {
                            if (!continuation.isActive) return
                            if (rcode == 0 && answer.isNotEmpty()) continuation.resume(answer)
                            else continuation.resumeWith(Result.failure(UnknownHostException("DNS rcode=$rcode")))
                        }

                        override fun onError(error: DnsResolver.DnsException) {
                            if (continuation.isActive) continuation.resumeWith(Result.failure(error))
                        }
                    }
                )
            }
        } else {
            runInterruptible(Dispatchers.IO) { network.getAllByName(host).toList() }
        }
    }

private suspend fun probeClientDns(network: Network): List<NetworkProbeResult> = coroutineScope {
    clientDnsServers.flatMap { server ->
        listOf(
            async(Dispatchers.IO) {
                timedProbe("$server UDP") { directDnsQuery(network, server, useTcp = false) }
            },
            async(Dispatchers.IO) {
                timedProbe("$server TCP") { directDnsQuery(network, server, useTcp = true) }
            }
        )
    }.awaitAll()
}

private fun directDnsQuery(
    network: Network,
    server: String,
    useTcp: Boolean,
    host: String = clientDnsProbeHost,
): String {
    val queryId = (SystemClock.elapsedRealtimeNanos() and 0xffff).toInt()
    val query = buildDnsQuery(host, queryId)
    val response = if (useTcp) {
        Socket().use { socket ->
            network.bindSocket(socket)
            socket.connect(InetSocketAddress(server, 53), SOCKET_TIMEOUT_MS)
            socket.soTimeout = SOCKET_TIMEOUT_MS
            DataOutputStream(socket.getOutputStream()).use { output ->
                output.writeShort(query.size)
                output.write(query)
                output.flush()
                val input = DataInputStream(socket.getInputStream())
                val responseLength = input.readUnsignedShort()
                require(responseLength in 12..65_535) { "некорректная длина DNS-ответа" }
                ByteArray(responseLength).also(input::readFully)
            }
        }
    } else {
        DatagramSocket(null).use { socket ->
            network.bindSocket(socket)
            socket.soTimeout = SOCKET_TIMEOUT_MS
            socket.connect(InetSocketAddress(server, 53))
            socket.send(DatagramPacket(query, query.size))
            val buffer = ByteArray(2_048)
            val packet = DatagramPacket(buffer, buffer.size)
            socket.receive(packet)
            packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
        }
    }
    val status = parseDnsResponse(response, queryId)
    require(status.responseCode == 0) { "DNS rcode=${status.responseCode}" }
    require(status.answerCount > 0) { "DNS-ответ без записей" }
    return "OK, ответов=${status.answerCount}${if (status.truncated) ", truncated" else ""}"
}

internal fun buildDnsQuery(host: String, queryId: Int): ByteArray {
    val labels = host.trim('.').split('.')
    require(labels.isNotEmpty() && labels.all { it.isNotBlank() && it.toByteArray(Charsets.US_ASCII).size <= 63 }) {
        "некорректное DNS-имя"
    }
    val bytes = ArrayList<Byte>(host.length + 18)
    fun addShort(value: Int) {
        bytes += ((value ushr 8) and 0xff).toByte()
        bytes += (value and 0xff).toByte()
    }
    addShort(queryId)
    addShort(0x0100)
    addShort(1)
    addShort(0)
    addShort(0)
    addShort(0)
    labels.forEach { label ->
        val encoded = label.toByteArray(Charsets.US_ASCII)
        bytes += encoded.size.toByte()
        encoded.forEach { bytes += it }
    }
    bytes += 0.toByte()
    addShort(1)
    addShort(1)
    return bytes.toByteArray()
}

internal fun parseDnsResponse(response: ByteArray, expectedId: Int): DnsResponseStatus {
    require(response.size >= 12) { "короткий DNS-ответ" }
    fun unsignedShort(offset: Int): Int =
        ((response[offset].toInt() and 0xff) shl 8) or (response[offset + 1].toInt() and 0xff)
    require(unsignedShort(0) == (expectedId and 0xffff)) { "чужой DNS-ответ" }
    val flags = unsignedShort(2)
    require(flags and 0x8000 != 0) { "DNS-пакет не является ответом" }
    return DnsResponseStatus(
        responseCode = flags and 0x000f,
        answerCount = unsignedShort(6),
        truncated = flags and 0x0200 != 0
    )
}

private suspend fun probeVkHttps(network: Network): List<NetworkProbeResult> = coroutineScope {
    vkHttpsTargets.map { (label, url) ->
        async(Dispatchers.IO) {
            timedProbe(label) { httpsProbe(network, url) }
        }
    }.awaitAll()
}

private fun httpsProbe(network: Network, target: String): String {
    val connection = network.openConnection(URL(target)) as HttpsURLConnection
    return try {
        connection.connectTimeout = SOCKET_TIMEOUT_MS
        connection.readTimeout = SOCKET_TIMEOUT_MS
        connection.instanceFollowRedirects = false
        connection.requestMethod = "GET"
        connection.setRequestProperty("User-Agent", "WDTT-Plus-Diagnostics/${BuildConfig.VERSION_NAME}")
        connection.setRequestProperty("Range", "bytes=0-0")
        val responseCode = connection.responseCode
        require(responseCode in 100..599) { "нет HTTP-ответа" }
        "HTTP $responseCode"
    } finally {
        connection.disconnect()
    }
}

private suspend inline fun timedProbe(label: String, crossinline block: suspend () -> String): NetworkProbeResult {
    val started = SystemClock.elapsedRealtime()
    return try {
        val result = block()
        NetworkProbeResult(label, true, result, SystemClock.elapsedRealtime() - started)
    } catch (error: CancellationException) {
        if (error !is TimeoutCancellationException) throw error
        NetworkProbeResult(label, false, "тайм-аут", SystemClock.elapsedRealtime() - started)
    } catch (_: SocketTimeoutException) {
        NetworkProbeResult(label, false, "тайм-аут", SystemClock.elapsedRealtime() - started)
    } catch (_: UnknownHostException) {
        NetworkProbeResult(label, false, "DNS не разрешён", SystemClock.elapsedRealtime() - started)
    } catch (error: Throwable) {
        val reason = error.message
            ?.replace(Regex("[\\r\\n]+"), " ")
            ?.take(120)
            ?.takeIf(String::isNotBlank)
            ?: error.javaClass.simpleName
        NetworkProbeResult(label, false, reason, SystemClock.elapsedRealtime() - started)
    }
}

private fun buildRecentNetworkEventsItem(): DeviceCheckItem? {
    val entries = TunnelManager.logs.value
        .filter { entry ->
            entry.severity != LogSeverity.Info ||
                entry.key.startsWith("err_") ||
                entry.key.startsWith("vkcalls_") ||
                entry.key.startsWith("vk_provider_") ||
                entry.key.startsWith("vk_credentials_") ||
                entry.key.startsWith("vk_legacy_") ||
                entry.key.startsWith("turn_") ||
                entry.key.startsWith("rt_") ||
                entry.key.startsWith("masque_") ||
                entry.key.startsWith("worker_turn_")
        }
        .take(12)
    if (entries.isEmpty()) return null
    val details = entries.joinToString(" | ") { entry ->
        val message = entry.message
            .replace(Regex("(https?://[^?\\s]+)\\?[^\\s]+"), "\$1?<параметры скрыты>")
            .replace(Regex("(?i)(token|password|credential|secret)=([^&\\s]+)"), "\$1=<скрыто>")
            .take(220)
        "${entry.key}: $message${if (entry.count > 1) " ×${entry.count}" else ""}"
    }
    return DeviceCheckItem(
        title = "Последние сетевые события туннеля",
        status = "собрано ${entries.size}",
        details = details,
        severity = DeviceCheckSeverity.Info
    )
}
