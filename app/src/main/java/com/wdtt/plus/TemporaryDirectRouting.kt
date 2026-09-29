package com.wdtt.plus

import android.content.Context
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.net.IDN
import java.util.UUID

/**
 * Process-local, non-persistent destination-routing lease for optional build
 * extensions.  The public client does not assign provider or commercial
 * meaning to the exact domains supplied by an installed local extension.
 */
internal object TemporaryDirectRouteRegistry {
    private val lock = Any()
    private val leases = linkedMapOf<String, Set<String>>()
    private var resolvedDomains: Set<String> = emptySet()

    fun currentDomains(): Set<String> = synchronized(lock) {
        leases.values.flatten().toSet()
    }

    fun add(domains: Set<String>): String = synchronized(lock) {
        resolvedDomains = emptySet()
        UUID.randomUUID().toString().also { token -> leases[token] = domains }
    }

    fun remove(token: String): Boolean = synchronized(lock) {
        val removed = leases.remove(token) != null
        if (removed) resolvedDomains = emptySet()
        removed
    }

    fun recordResolvedDomains(domains: Set<String>) = synchronized(lock) {
        resolvedDomains = domains.intersect(leases.values.flatten().toSet())
    }

    fun allResolved(domains: Set<String>): Boolean = synchronized(lock) {
        domains.isNotEmpty() && resolvedDomains.containsAll(domains)
    }
}

internal class TemporaryDirectRouteLease private constructor(
    private val context: Context,
    private val token: String?,
) {
    private var released = false

    suspend fun release() {
        if (released) return
        released = true
        val currentToken = token ?: return
        withContext(NonCancellable) {
            operationMutex.withLock {
                if (!TemporaryDirectRouteRegistry.remove(currentToken)) return@withLock
                if (TunnelManager.running.value && TunnelManager.activeMode.value == TUNNEL_MODE_VPN) {
                    WireGuardHelper(context).reloadTunnel()
                    delay(ROUTE_SETTLE_MS)
                }
            }
        }
    }

    companion object {
        private val operationMutex = Mutex()
        private const val ROUTE_SETTLE_MS = 350L
        private const val MAX_DOMAINS = 16

        suspend fun acquire(context: Context, domains: Collection<String>): TemporaryDirectRouteLease =
            operationMutex.withLock {
                val appContext = context.applicationContext
                val normalized = normalizeTemporaryDirectDomains(domains)
                if (
                    normalized.isEmpty() ||
                    !TunnelManager.running.value ||
                    TunnelManager.activeMode.value != TUNNEL_MODE_VPN ||
                    !WireGuardHelper(appContext).isTunnelUp()
                ) {
                    return@withLock TemporaryDirectRouteLease(appContext, null)
                }

                val token = TemporaryDirectRouteRegistry.add(normalized)
                val helper = WireGuardHelper(appContext)
                if (!helper.reloadTunnel() || !TemporaryDirectRouteRegistry.allResolved(normalized)) {
                    TemporaryDirectRouteRegistry.remove(token)
                    helper.reloadTunnel()
                    throw IllegalStateException(
                        "Не удалось подготовить прямое соединение с внешним сервисом. VPN восстановлен без временных маршрутов."
                    )
                }
                delay(ROUTE_SETTLE_MS)
                TemporaryDirectRouteLease(appContext, token)
            }

        private fun normalizeTemporaryDirectDomains(domains: Collection<String>): Set<String> {
            require(domains.size <= MAX_DOMAINS) { "Получено слишком много адресов продолжения." }
            return domains.asSequence()
                .map(String::trim)
                .filter(String::isNotEmpty)
                .map { value ->
                    val ascii = IDN.toASCII(value.trimEnd('.'), IDN.USE_STD3_ASCII_RULES)
                        .lowercase()
                    require(
                        ascii.length in 3..253 &&
                            '.' in ascii &&
                            ascii.split('.').all { label ->
                                label.length in 1..63 &&
                                    label.first().isLetterOrDigit() &&
                                    label.last().isLetterOrDigit() &&
                                    label.all { it.isLetterOrDigit() || it == '-' }
                            }
                    ) { "Адрес прямого продолжения повреждён." }
                    ascii
                }
                .toSet()
        }
    }
}
