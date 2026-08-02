package com.wdtt.plus

import android.content.Context
import android.os.Build
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.TimeZone

sealed interface AccessLifecycleRefreshResult {
    data object Unmanaged : AccessLifecycleRefreshResult
    data class Success(val status: AccessLifecycleStatus) : AccessLifecycleRefreshResult
    data class Cached(val status: AccessLifecycleStatus?) : AccessLifecycleRefreshResult
    data class Throttled(
        val status: AccessLifecycleStatus?,
        val retryAfterMillis: Long,
    ) : AccessLifecycleRefreshResult
    data class Failed(val message: String, val cached: AccessLifecycleStatus?) :
        AccessLifecycleRefreshResult
}

object AccessLifecycleCoordinator {
    private const val STATUS_CACHE_TTL_MS = 10 * 60 * 1000L
    private const val MIN_ATTEMPT_INTERVAL_MS = 10_000L
    private val profileLocks = Array(3) { Mutex() }
    private val _refreshingProfiles = MutableStateFlow<Set<Int>>(emptySet())
    val refreshingProfiles: StateFlow<Set<Int>> = _refreshingProfiles.asStateFlow()
    private val pendingExternalRefresh = mutableSetOf<Int>()

    suspend fun refreshProfile(
        context: Context,
        profileIndex: Int,
        force: Boolean = false,
    ): AccessLifecycleRefreshResult = withContext(Dispatchers.IO) {
        refreshProfileOnWorker(context, profileIndex, force)
    }

    private suspend fun refreshProfileOnWorker(
        context: Context,
        profileIndex: Int,
        force: Boolean = false,
    ): AccessLifecycleRefreshResult {
        val appContext = context.applicationContext
        val profile = profileIndex.coerceIn(0, 2)
        val store = SettingsStore(appContext)
        val before = store.accessLifecycleForProfile(profile)
        if (!before.capability.available) return AccessLifecycleRefreshResult.Unmanaged
        val now = System.currentTimeMillis()
        if (
            !force &&
            before.status != null &&
            now - before.status.checkedAtMillis in 0 until STATUS_CACHE_TTL_MS
        ) {
            return AccessLifecycleRefreshResult.Cached(before.status)
        }
        val attemptAge = now - before.lastAttemptAtMillis
        if (attemptAge in 0 until MIN_ATTEMPT_INTERVAL_MS) {
            return AccessLifecycleRefreshResult.Throttled(
                status = before.status,
                retryAfterMillis = MIN_ATTEMPT_INTERVAL_MS - attemptAge,
            )
        }
        return profileLocks[profile].withLock {
            val current = store.accessLifecycleForProfile(profile)
            val currentNow = System.currentTimeMillis()
            if (!current.capability.available) return@withLock AccessLifecycleRefreshResult.Unmanaged
            if (current.status?.continuationAvailable != false) {
                syncPendingProfileValues(store, profile, current.capability)
            }
            if (
                !force &&
                current.status != null &&
                currentNow - current.status.checkedAtMillis in 0 until STATUS_CACHE_TTL_MS
            ) {
                return@withLock AccessLifecycleRefreshResult.Cached(current.status)
            }
            val currentAttemptAge = currentNow - current.lastAttemptAtMillis
            if (currentAttemptAge in 0 until MIN_ATTEMPT_INTERVAL_MS) {
                return@withLock AccessLifecycleRefreshResult.Throttled(
                    status = current.status,
                    retryAfterMillis = MIN_ATTEMPT_INTERVAL_MS - currentAttemptAge,
                )
            }
            store.saveAccessLifecycleAttempt(profile, currentNow)
            setRefreshing(profile, true)
            try {
                val received = AccessLifecycleGateway.fetch(
                    capability = current.capability,
                    device = store.getOrCreateConnectDeviceId(),
                    client = BuildConfig.VERSION_NAME,
                    system = Build.VERSION.RELEASE.orEmpty(),
                    timezone = TimeZone.getDefault().id,
                    profileRevision = current.appliedProfileRevision,
                )
                val effectiveCapability = current.capability.copy(
                    exchange = received.exchange ?: current.capability.exchange,
                )
                if (effectiveCapability != current.capability) {
                    store.saveRemoteAccessCapability(effectiveCapability, profile)
                }
                val effectiveCurrent = current.copy(capability = effectiveCapability)
                // Статус доступа самодостаточен: сохраняем его даже если отдельное
                // обновление параметров профиля временно не удалось скачать или применить.
                if (
                    !store.saveAccessLifecycleStatus(
                        profile,
                        received,
                        expectedCapability = effectiveCapability,
                    )
                ) {
                    return@withLock AccessLifecycleRefreshResult.Unmanaged
                }
                if (received.continuationAvailable != false) {
                    try {
                        syncPendingProfileValues(store, profile, effectiveCapability)
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (error: Exception) {
                        TunnelManager.noteAccessLifecycleEvent(
                            key = "profile_${profile}_values_sync_failed",
                            message = error.message
                                ?: "Не удалось обновить сохранённые данные профиля",
                            warning = true,
                        )
                    }
                }
                val profileUpdated = applyProfileUpdateIfNeeded(
                    appContext = appContext,
                    store = store,
                    profile = profile,
                    current = effectiveCurrent,
                    status = received,
                )
                // Новая capability может очистить прежний статус при ротации ключа.
                if (profileUpdated) {
                    store.saveAccessLifecycleStatus(
                        profile,
                        received,
                        expectedCapability = effectiveCapability,
                    )
                }
                // Состояние управляемого доступа показывается своей профильной карточкой.
                // Общая ошибка подключения не должна дублировать её и переноситься на
                // другой, в том числе ручной, профиль.
                TunnelManager.clearConnectionIssue(ConnectionIssueKind.ACCESS)
                if (
                    current.status?.allowConnect != received.allowConnect ||
                    current.status?.title != received.title
                ) {
                    TunnelManager.noteAccessLifecycleEvent(
                        key = "profile_${profile}_decision",
                        message = received.title.ifBlank { "Состояние профиля обновлено" },
                        warning = received.severity != AccessLifecycleSeverity.NORMAL,
                    )
                }
                updateExternalSurfaces(appContext)
                AccessLifecycleRefreshResult.Success(received)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: AccessLifecycleRequestException) {
                if (!error.kind.authoritative) {
                    return@withLock accessRefreshFailure(profile, current, error)
                }
                val denied = authoritativeAccessDenialStatus(
                    failure = error,
                    cached = current.status,
                )
                if (
                    !store.saveAccessLifecycleStatus(
                        profile,
                        denied,
                        expectedCapability = current.capability,
                    )
                ) {
                    return@withLock AccessLifecycleRefreshResult.Unmanaged
                }
                TunnelManager.clearConnectionIssue(ConnectionIssueKind.ACCESS)
                if (
                    current.status?.allowConnect != denied.allowConnect ||
                    current.status?.title != denied.title
                ) {
                    TunnelManager.noteAccessLifecycleEvent(
                        key = "profile_${profile}_${error.code}",
                        message = denied.title,
                        warning = true,
                    )
                }
                updateExternalSurfaces(appContext)
                AccessLifecycleRefreshResult.Success(denied)
            } catch (error: Exception) {
                accessRefreshFailure(profile, current, error)
            } finally {
                setRefreshing(profile, false)
            }
        }
    }

    private fun accessRefreshFailure(
        profile: Int,
        current: StoredAccessLifecycle,
        error: Exception,
    ): AccessLifecycleRefreshResult.Failed {
        TunnelManager.noteAccessLifecycleEvent(
            key = "profile_${profile}_check_failed",
            message = error.message ?: "Не удалось обновить сведения о доступе",
            warning = true,
        )
        return AccessLifecycleRefreshResult.Failed(
            message = error.message ?: "Не удалось проверить профиль.",
            cached = current.status,
        )
    }

    internal suspend fun prepareStart(
        context: Context,
        profileIndex: Int,
    ): AccessStartDecision {
        val profile = profileIndex.coerceIn(0, 2)
        val store = SettingsStore(context.applicationContext)
        val current = store.accessLifecycleForProfile(profile)
        if (!current.capability.available) return AccessStartDecision.Allowed
        val now = System.currentTimeMillis()
        val cachedDecision = accessStartDecision(current)
        val fresh = current.status?.checkedAtMillis?.let {
            now - it in 0 until STATUS_CACHE_TTL_MS
        } == true
        if (fresh && cachedDecision == AccessStartDecision.Allowed) {
            return AccessStartDecision.Allowed
        }

        return when (val refreshed = refreshProfile(context, profile, force = true)) {
            is AccessLifecycleRefreshResult.Success ->
                if (refreshed.status.allowConnect) {
                    AccessStartDecision.Allowed
                } else {
                    AccessStartDecision.Denied(refreshed.status)
                }
            is AccessLifecycleRefreshResult.Cached -> {
                accessStartDecision(store.accessLifecycleForProfile(profile))
            }
            is AccessLifecycleRefreshResult.Throttled -> {
                accessStartDecision(store.accessLifecycleForProfile(profile))
            }
            is AccessLifecycleRefreshResult.Failed ->
                accessStartDecision(store.accessLifecycleForProfile(profile))
            AccessLifecycleRefreshResult.Unmanaged -> AccessStartDecision.Allowed
        }
    }

    suspend fun beginAction(
        context: Context,
        profileIndex: Int,
    ): RemoteLaunchTarget {
        val profile = profileIndex.coerceIn(0, 2)
        val store = SettingsStore(context.applicationContext)
        val current = store.accessLifecycleForProfile(profile)
        require(current.capability.available && current.status?.actionAvailable == true) {
            current.status?.actionMessage?.ifBlank {
                "Действие сейчас недоступно."
            } ?: "Действие сейчас недоступно."
        }
        val target = AccessLifecycleGateway.begin(
            capability = current.capability,
            device = store.getOrCreateConnectDeviceId(),
            client = BuildConfig.VERSION_NAME,
            system = Build.VERSION.RELEASE.orEmpty(),
            timezone = TimeZone.getDefault().id,
            profileRevision = current.appliedProfileRevision,
        )
        store.markAccessLifecycleActionLaunched(profile)
        synchronized(pendingExternalRefresh) {
            pendingExternalRefresh += profile
        }
        return target
    }

    suspend fun noteServerDenied(context: Context, profileIndex: Int) {
        val appContext = context.applicationContext
        val profile = profileIndex.coerceIn(0, 2)
        val store = SettingsStore(appContext)
        store.markAccessLifecycleDenied(profile)
        updateExternalSurfaces(appContext)
        refreshProfile(appContext, profile, force = true)
    }

    suspend fun refreshAllIfStale(context: Context) {
        val store = SettingsStore(context.applicationContext)
        store.accessLifecycleProfiles().forEach { profile ->
            refreshProfile(context, profile, force = false)
        }
    }

    suspend fun refreshAllOnForeground(
        context: Context,
        alreadyScheduledProfiles: Set<Int> = emptySet(),
    ) {
        val store = SettingsStore(context.applicationContext)
        accessProfilesForForegroundRefresh(
            managedProfiles = store.accessLifecycleProfiles(),
            alreadyScheduledProfiles = alreadyScheduledProfiles,
        ).forEach { profile ->
            refreshAfterAttemptWindow(context, profile)
        }
    }

    suspend fun refreshAfterSuccessfulConnect(context: Context, profileIndex: Int) {
        refreshAfterAttemptWindow(context, profileIndex)
    }

    suspend fun refreshAfterExternalAction(
        context: Context,
        profileIndex: Int,
    ): AccessLifecycleRefreshResult =
        refreshAfterAttemptWindow(context, profileIndex)

    private suspend fun refreshAfterAttemptWindow(
        context: Context,
        profileIndex: Int,
    ): AccessLifecycleRefreshResult {
        val first = refreshProfile(
            context.applicationContext,
            profileIndex,
            force = true,
        )
        if (first !is AccessLifecycleRefreshResult.Throttled) return first
        delay(first.retryAfterMillis)
        return refreshProfile(
            context.applicationContext,
            profileIndex,
            force = true,
        )
    }

    fun takePendingExternalRefreshProfiles(): Set<Int> = synchronized(pendingExternalRefresh) {
        pendingExternalRefresh.toSet().also { pendingExternalRefresh.clear() }
    }

    suspend fun syncProfileValues(
        context: Context,
        profileIndex: Int,
        values: List<String>,
    ): Boolean {
        val profile = profileIndex.coerceIn(0, 2)
        val cleaned = values
            .map(VkJoinLink::extractHash)
            .filter(VkJoinLink::isValidHash)
            .distinct()
            .take(4)
        val store = SettingsStore(context.applicationContext)
        val current = store.accessLifecycleForProfile(profile)
        val exchange = current.capability.exchange
        if (
            !current.capability.available ||
            !exchange.submitAvailable ||
            exchange.submitToken.isBlank()
        ) {
            return false
        }
        store.markProfileValuesSyncPending(profile)
        val updatedExchange = AccessLifecycleGateway.submitProfileValues(
            capability = current.capability,
            token = exchange.submitToken,
            device = store.getOrCreateConnectDeviceId(),
            client = BuildConfig.VERSION_NAME,
            system = Build.VERSION.RELEASE.orEmpty(),
            timezone = TimeZone.getDefault().id,
            values = cleaned,
        )
        store.saveRemoteAccessCapability(
            current.capability.copy(exchange = updatedExchange),
            profile,
        )
        store.clearProfileValuesSyncPending(profile)
        return true
    }

    suspend fun restoreProfileValues(
        context: Context,
        profileIndex: Int,
        expectedCapability: RemoteAccessCapability,
    ): WdttDeepLinkApplyResult {
        val appContext = context.applicationContext
        val profile = profileIndex.coerceIn(0, 2)
        val store = SettingsStore(appContext)
        return profileLocks[profile].withLock {
            val current = store.accessLifecycleForProfile(profile)
            require(
                current.capability.available &&
                    expectedCapability.available &&
                    current.capability.key == expectedCapability.key &&
                    current.capability.url == expectedCapability.url &&
                    current.capability.binding == expectedCapability.binding
            ) {
                "Сохранённые данные относятся к другому профилю."
            }
            val exchange = current.capability.exchange
            require(
                exchange.actionAvailable && exchange.actionToken.isNotBlank()
            ) {
                "Действие для этого профиля больше недоступно."
            }
            val link = AccessLifecycleGateway.invokeProfileAction(
                capability = current.capability,
                token = exchange.actionToken,
                device = store.getOrCreateConnectDeviceId(),
                client = BuildConfig.VERSION_NAME,
                system = Build.VERSION.RELEASE.orEmpty(),
                timezone = TimeZone.getDefault().id,
                profileRevision = current.appliedProfileRevision,
            )
            val delivery = RemoteDocumentGateway.receive(
                link = link,
                device = store.getOrCreateConnectDeviceId(),
                label = androidDeviceLabel(),
                client = BuildConfig.VERSION_NAME,
                system = Build.VERSION.RELEASE.orEmpty(),
                localBindings = store.remoteDocumentBindings(),
            )
            require(delivery.kind == RemoteDocumentKind.UPDATE) {
                "WDTT Plus вернул неподходящее обновление профиля."
            }
            require(
                current.capability.binding.isNotBlank() &&
                    delivery.binding == current.capability.binding
            ) {
                "Обновление относится к другому профилю."
            }
            val applied = store.applyRemoteDocumentDelivery(
                plan = WdttDeepLinkApplyPlan(
                    link = delivery.document,
                    targetProfile = profile,
                    requiresConfirmation = false,
                    storeAsLink = false,
                ),
                delivery = delivery,
                isBoundUpdate = true,
            ) ?: throw IllegalStateException("Не удалось применить обновление профиля.")
            store.clearProfileValuesSyncPending(profile)
            requestTunnelProfileRuntimeUpdate(profile)
            applied
        }
    }

    private suspend fun syncPendingProfileValues(
        store: SettingsStore,
        profile: Int,
        capability: RemoteAccessCapability,
    ) {
        if (!store.profileValuesSyncPending(profile)) return
        val exchange = capability.exchange
        if (!exchange.submitAvailable || exchange.submitToken.isBlank()) return
        val values = store.tunnelProfileSnapshot(profile).vkHashes
            .split(",")
            .map(VkJoinLink::extractHash)
            .filter(VkJoinLink::isValidHash)
            .distinct()
            .take(4)
        runCatching {
            val updatedExchange = AccessLifecycleGateway.submitProfileValues(
                capability = capability,
                token = exchange.submitToken,
                device = store.getOrCreateConnectDeviceId(),
                client = BuildConfig.VERSION_NAME,
                system = Build.VERSION.RELEASE.orEmpty(),
                timezone = TimeZone.getDefault().id,
                values = values,
            )
            store.saveRemoteAccessCapability(
                capability.copy(exchange = updatedExchange),
                profile,
            )
        }.onSuccess {
            store.clearProfileValuesSyncPending(profile)
        }
    }

    private suspend fun applyProfileUpdateIfNeeded(
        appContext: Context,
        store: SettingsStore,
        profile: Int,
        current: StoredAccessLifecycle,
        status: AccessLifecycleStatus,
    ): Boolean {
        val update = status.profileUpdate ?: return false
        if (update.revision <= current.appliedProfileRevision) return false
        val delivery = RemoteDocumentGateway.receive(
            link = update.link,
            device = store.getOrCreateConnectDeviceId(),
            label = androidDeviceLabel(),
            client = BuildConfig.VERSION_NAME,
            system = Build.VERSION.RELEASE.orEmpty(),
            localBindings = store.remoteDocumentBindings(),
        )
        require(delivery.kind == RemoteDocumentKind.UPDATE) {
            "WDTT Plus вернул неподходящее обновление профиля."
        }
        val binding = store.remoteAccessBindingForProfile(profile)
        require(binding.isNotBlank() && delivery.binding == binding) {
            "Обновление относится к другому профилю."
        }
        val applied = store.applyRemoteDocumentDelivery(
            plan = WdttDeepLinkApplyPlan(
                link = delivery.document,
                targetProfile = profile,
                requiresConfirmation = false,
                storeAsLink = false,
            ),
            delivery = delivery,
            isBoundUpdate = true,
        )
        require(applied != null) { "Не удалось применить обновление профиля." }
        store.saveAppliedAccessProfileRevision(profile, update.revision)
        requestTunnelProfileRuntimeUpdate(profile)
        TunnelManager.noteAccessLifecycleEvent(
            key = "profile_${profile}_updated",
            message = "Параметры профиля обновлены",
            warning = false,
        )
        return true
    }

    private fun androidDeviceLabel(): String {
        val values = listOf(Build.MANUFACTURER, Build.MODEL)
            .map(String::trim)
            .filter(String::isNotBlank)
            .distinctBy(String::lowercase)
        return values.joinToString(" ").ifBlank { "Android-устройство" }
    }

    private fun setRefreshing(profile: Int, refreshing: Boolean) {
        _refreshingProfiles.value = _refreshingProfiles.value.toMutableSet().apply {
            if (refreshing) add(profile) else remove(profile)
        }
    }

    private fun updateExternalSurfaces(context: Context) {
        VpnWidgetProvider.updateAllWidgets(context)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            android.service.quicksettings.TileService.requestListeningState(
                context,
                android.content.ComponentName(context, QuickToggleTileService::class.java),
            )
        }
    }
}

internal fun accessProfilesForForegroundRefresh(
    managedProfiles: Collection<Int>,
    alreadyScheduledProfiles: Set<Int>,
): List<Int> = managedProfiles
    .filter { it in 0..2 && it !in alreadyScheduledProfiles }
    .distinct()
    .sorted()

internal fun authoritativeAccessDenialStatus(
    failure: AccessLifecycleRequestException,
    cached: AccessLifecycleStatus?,
    checkedAtMillis: Long = System.currentTimeMillis(),
): AccessLifecycleStatus {
    require(failure.kind.authoritative)
    val (title, fallbackMessage) = when (failure.kind) {
        AccessLifecycleFailureKind.REJECTED ->
            "Профиль недоступен" to
                "Поставщик отклонил использование этого профиля."
        AccessLifecycleFailureKind.UNBOUND ->
            "Профиль отвязан" to
                "Запросите новую ссылку на профиль у поставщика."
        AccessLifecycleFailureKind.UNAVAILABLE ->
            "Профиль больше недоступен" to
                "Проверьте профиль и привязку устройства у поставщика."
        AccessLifecycleFailureKind.TEMPORARY -> error("temporary failure is not authoritative")
    }
    return AccessLifecycleStatus(
        allowConnect = false,
        actionAvailable = false,
        title = title,
        message = failure.message?.takeIf { it.isNotBlank() } ?: fallbackMessage,
        severity = AccessLifecycleSeverity.ERROR,
        checkedAtMillis = checkedAtMillis,
        profileRevision = cached?.profileRevision ?: 0,
    )
}
