package com.wdtt.plus

import android.app.Application
import android.content.Context
import android.util.Log
import com.wireguard.android.backend.Tunnel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

internal fun shouldClearPhantomVpn(activeTunnelProfile: Int?): Boolean =
    activeTunnelProfile == null

class WdttApplication : Application() {
    @Volatile
    private var backendInstance: SafeGoBackend? = null

    val backend: SafeGoBackend
        get() = getBackend(this)

    override fun onCreate() {
        super.onCreate()
        DeployManager.init(this)

        val settingsStore = SettingsStore(this)

        // Очищаем только действительно бесхозный фантомный VPN. Если сохранён активный
        // профиль, Android одновременно восстанавливает TunnelService: безусловный DOWN
        // здесь мог опередить или оборвать штатное восстановление и затем вызвать новый UP.
        CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
            runCatching {
                val activeTunnelProfile = settingsStore.activeTunnelProfile.first()
                if (!shouldClearPhantomVpn(activeTunnelProfile)) {
                    Log.d("WdttApp", "Ожидается восстановление активного VPN; очистка фантома пропущена")
                    return@runCatching
                }
                val backend = getBackend(this@WdttApplication)
                val tunnel = WireGuardHelper.WgTunnel()
                backend.setState(tunnel, Tunnel.State.DOWN, null)
                Log.d("WdttApp", "Успешно очищен фантомный VPN при холодном старте")
            }.onFailure {
                Log.w("WdttApp", "Не удалось очистить фантомный VPN: ${it.message}")
            }
        }
        CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
            RemoteActionCatalogGateway.fetch(force = true)
        }
        CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
            AccessLifecycleCoordinator.refreshAllIfStale(this@WdttApplication)
        }

        // Реактивно обновляем виджеты при изменении туннеля, активного профиля или его названия.
        CoroutineScope(SupervisorJob() + Dispatchers.Main).launch {
            try {
                combine(
                    TunnelManager.running,
                    TrustedWifiManager.state,
                    settingsStore.activeProfile,
                    settingsStore.profileNames,
                    settingsStore.activeAccessLifecycle
                ) { _, _, _, _, _ -> Unit }.collect {
                    VpnWidgetProvider.updateAllWidgets(this@WdttApplication)
                }
            } catch (e: Exception) {
                Log.e("WdttApp", "Не удалось обновить виджеты: ${e.message}")
            }
        }

        // Реактивно отслеживаем флаг логирования
        CoroutineScope(SupervisorJob() + Dispatchers.Main).launch {
            try {
                settingsStore.loggingEnabled.collect { enabled ->
                    TunnelManager.isLoggingEnabled = enabled
                }
            } catch (e: Exception) {
                Log.e("WdttApp", "Не удалось отслеживать флаг логирования: ${e.message}")
            }
        }
    }

    fun getBackend(context: Context): SafeGoBackend {
        return backendInstance ?: synchronized(this) {
            backendInstance ?: SafeGoBackend(context.applicationContext).also { backend ->
                backend.setRevocationListener {
                    TunnelManager.onWireGuardInterfaceDropped(vpnSlotTransferred = true)
                    runCatching {
                        startService(
                            android.content.Intent(this@WdttApplication, TunnelService::class.java).apply {
                                action = ACTION_VPN_SLOT_REVOKED
                            },
                        )
                    }.onFailure { error ->
                        Log.w("WdttApp", "Не удалось передать отзыв VPN foreground-службе", error)
                    }
                }
                backendInstance = backend
                backend
            }
        }
    }
}
