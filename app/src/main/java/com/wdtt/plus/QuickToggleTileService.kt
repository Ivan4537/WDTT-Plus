package com.wdtt.plus

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Log
import android.widget.Toast
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch

class QuickToggleTileService : TileService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var stateJob: Job? = null

    override fun onStartListening() {
        super.onStartListening()
        // Реактивно подписываемся на статус активности туннеля.
        // Плитка будет строго отражать РЕАЛЬНОЕ состояние туннеля на 100% без рассинхронизаций.
        stateJob?.cancel()
        stateJob = scope.launch {
            try {
                val settingsStore = SettingsStore(this@QuickToggleTileService)
                combine(
                    TunnelManager.running,
                    TrustedWifiManager.state,
                    settingsStore.activeProfile,
                    TunnelManager.activeTunnelProfile,
                    settingsStore.profileNames,
                ) { running, trustedWifi, selectedProfile, activeTunnelProfile, profileNames ->
                    TileUiState(
                        running,
                        trustedWifi,
                        selectedProfile,
                        activeTunnelProfile,
                        profileNames,
                        AccessLifecycleUiState.Unmanaged,
                    )
                }.combine(settingsStore.activeAccessLifecycle) { state, accessLifecycle ->
                    state.copy(accessLifecycle = accessLifecycle)
                }.collect { uiState ->
                    updateTile(uiState)
                }
            } catch (e: Exception) {
                Log.e("QuickToggleTile", "Error collecting running state", e)
            }
        }
    }

    override fun onStopListening() {
        stateJob?.cancel()
        super.onStopListening()
    }

    override fun onClick() {
        super.onClick()
        runCatching {
            val running = TunnelManager.running.value
            val trustedWifiWaiting = TrustedWifiManager.state.value.waiting
            val action = if (running || trustedWifiWaiting) {
                TunnelToggleAction.STOP
            } else {
                tunnelToggleAction(
                    running = false,
                    trustedWifiWaiting = false,
                    vpnPermissionRequired = VpnService.prepare(this) != null,
                )
            }
            when (action) {
                TunnelToggleAction.STOP -> {
                    // Состояние плитки изменится после фактической остановки службы.
                    startService(
                        Intent(this, TunnelService::class.java).apply { this.action = "STOP" }
                    )
                }
                TunnelToggleAction.REQUEST_VPN_PERMISSION -> {
                    Toast.makeText(
                        this,
                        "Откройте WDTT Plus и выдайте VPN-разрешение",
                        Toast.LENGTH_LONG
                    ).show()
                    openMainActivity()
                }
                TunnelToggleAction.START -> scope.launch {
                    try {
                        val intent = buildTunnelStartIntentFromSettings(this@QuickToggleTileService)
                        if (intent == null) {
                            Toast.makeText(
                                this@QuickToggleTileService,
                                "Заполните настройки подключения в WDTT Plus",
                                Toast.LENGTH_LONG
                            ).show()
                            openMainActivity()
                            return@launch
                        }

                        if (Build.VERSION.SDK_INT >= 26) {
                            startForegroundService(intent)
                        } else {
                            startService(intent)
                        }
                    } catch (e: Exception) {
                        Log.e("QuickToggleTile", "Failed to start tunnel via QS tile", e)
                        Toast.makeText(
                            this@QuickToggleTileService,
                            "Ошибка запуска: ${e.localizedMessage}",
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                }
            }
        }.onFailure { e ->
            Log.e("QuickToggleTile", "Crash prevented in onClick", e)
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun updateTile(uiState: TileUiState) {
        runCatching {
            val running = uiState.running
            val waiting = uiState.trustedWifi.waiting
            val profileNames = uiState.profileNames
            val profile = displayedTunnelProfile(
                selectedProfile = uiState.selectedProfile,
                activeTunnelProfile = uiState.activeTunnelProfile,
                running = running,
                trustedWifiWaiting = waiting,
            )
            val profileLabel = vpnProfileDisplayName(profile, profileNames)
            val defaultProfileLabel = vpnProfileDefaultName(profile)
            val profileIsDefault = profileLabel == defaultProfileLabel
            val accessBlocked =
                uiState.accessLifecycle.managed &&
                    !uiState.accessLifecycle.allowConnect &&
                    !running &&
                    !waiting
            qsTile?.apply {
                label = when {
                    waiting -> "Ожидание"
                    !running -> "WDTT Plus"
                    profileIsDefault -> "WDTT Plus $profileLabel"
                    else -> profileLabel
                }
                icon = Icon.createWithResource(this@QuickToggleTileService, R.drawable.ic_tile_logo)
                state = if (running && !waiting) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
                if (Build.VERSION.SDK_INT >= 29) {
                    subtitle = when {
                        waiting -> uiState.trustedWifi.ssid.ifBlank { "Wi-Fi" }
                        running -> ""
                        accessBlocked -> uiState.accessLifecycle.title
                            .ifBlank { uiState.accessLifecycle.fallbackTitle() }
                        else -> "Отключено"
                    }
                }
                updateTile()
            }
        }.onFailure { e ->
            Log.e("QuickToggleTile", "Failed to update QS tile state", e)
        }
    }

    private data class TileUiState(
        val running: Boolean,
        val trustedWifi: TrustedWifiRuntimeState,
        val selectedProfile: Int,
        val activeTunnelProfile: Int?,
        val profileNames: List<String>,
        val accessLifecycle: AccessLifecycleUiState,
    )

    @SuppressLint("StartActivityAndCollapseDeprecated")
    private fun openMainActivity() {
        runCatching {
            val intent = Intent(this, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            if (Build.VERSION.SDK_INT >= 34) {
                val pendingIntent = PendingIntent.getActivity(
                    this,
                    100,
                    intent,
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                )
                startActivityAndCollapse(pendingIntent)
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(intent)
            }
        }.onFailure { e ->
            Log.e("QuickToggleTile", "Failed to open MainActivity", e)
        }
    }

}
