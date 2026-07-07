package com.wdtt.plus

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
                    settingsStore.profileNames
                ) { running, trustedWifi, activeProfile, profileNames ->
                    TileUiState(running, trustedWifi, activeProfile, profileNames)
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
            if (TunnelManager.running.value || TrustedWifiManager.state.value.waiting) {
                // Если запущен — останавливаем. Состояние плитки изменится автоматически,
                // когда TunnelManager остановит процессы и обновит статус running в false.
                val stopIntent = Intent(this, TunnelService::class.java).apply { action = "STOP" }
                startService(stopIntent)
                return
            }

            // Проверяем наличие выданного разрешения VPN перед стартом
            if (VpnService.prepare(this) != null) {
                Toast.makeText(this, "Откройте WDTT Plus и выдайте VPN-разрешение", Toast.LENGTH_LONG).show()
                openMainActivity()
                return
            }

            // Запускаем старт туннеля в фоне
            scope.launch {
                try {
                    val intent = buildTunnelStartIntentFromSettings(this@QuickToggleTileService)
                    if (intent == null) {
                        Toast.makeText(this@QuickToggleTileService, "Заполните настройки подключения в WDTT Plus", Toast.LENGTH_LONG).show()
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
                    Toast.makeText(this@QuickToggleTileService, "Ошибка запуска: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
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
            val activeProfile = uiState.activeProfile
            val profileNames = uiState.profileNames
            val profile = activeProfile.coerceIn(0, 2)
            val profileLabel = vpnProfileDisplayName(profile, profileNames)
            val defaultProfileLabel = vpnProfileDefaultName(profile)
            val profileIsDefault = profileLabel == defaultProfileLabel
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
        val activeProfile: Int,
        val profileNames: List<String>
    )

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
