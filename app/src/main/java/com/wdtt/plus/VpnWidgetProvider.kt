package com.wdtt.plus

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.util.Log
import android.widget.RemoteViews
import android.widget.Toast
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

class VpnWidgetProvider : AppWidgetProvider() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    companion object {
        const val ACTION_WIDGET_TOGGLE = "com.wdtt.plus.ACTION_WIDGET_TOGGLE"

        fun updateAllWidgets(context: Context) {
            runCatching {
                val appWidgetManager = AppWidgetManager.getInstance(context)
                val thisWidget = ComponentName(context, VpnWidgetProvider::class.java)
                val appWidgetIds = appWidgetManager.getAppWidgetIds(thisWidget)
                if (appWidgetIds.isNotEmpty()) {
                    val intent = Intent(context, VpnWidgetProvider::class.java).apply {
                        action = AppWidgetManager.ACTION_APPWIDGET_UPDATE
                        putExtra(AppWidgetManager.EXTRA_APPWIDGET_IDS, appWidgetIds)
                    }
                    context.sendBroadcast(intent)
                }
            }
            VpnCompactWidgetProvider.updateAllWidgets(context)
        }
    }

    override fun onUpdate(context: Context, appWidgetManager: AppWidgetManager, appWidgetIds: IntArray) {
        val running = TunnelManager.running.value
        val trustedWifi = TrustedWifiManager.state.value
        scope.launch {
            val settingsStore = SettingsStore(context)
            val selectedProfile = settingsStore.activeProfile.first().coerceIn(0, 2)
            val activeTunnelProfile = TunnelManager.activeTunnelProfile.value
                ?: settingsStore.activeTunnelProfile.first()
            val displayedProfile = displayedTunnelProfile(
                selectedProfile = selectedProfile,
                activeTunnelProfile = activeTunnelProfile,
                running = running,
                trustedWifiWaiting = trustedWifi.waiting,
            )
            val profileNames = settingsStore.profileNames.first()
            val accessLifecycle =
                settingsStore.accessLifecycleForProfile(displayedProfile).toUiState()
            for (appWidgetId in appWidgetIds) {
                updateWidgetState(
                    context = context,
                    appWidgetManager = appWidgetManager,
                    appWidgetId = appWidgetId,
                    running = running,
                    trustedWifi = trustedWifi,
                    activeProfile = displayedProfile,
                    profileNames = profileNames,
                    accessLifecycle = accessLifecycle,
                )
            }
        }
    }

    override fun onReceive(context: Context, intent: Intent) {
        super.onReceive(context, intent)
        if (intent.action == ACTION_WIDGET_TOGGLE) {
            runCatching {
                val running = TunnelManager.running.value
                val trustedWifiWaiting = TrustedWifiManager.state.value.waiting
                val action = if (running || trustedWifiWaiting) {
                    TunnelToggleAction.STOP
                } else {
                    tunnelToggleAction(
                        running = false,
                        trustedWifiWaiting = false,
                        vpnPermissionRequired = VpnService.prepare(context) != null,
                    )
                }
                when (action) {
                    TunnelToggleAction.STOP -> {
                        context.startService(
                            Intent(context, TunnelService::class.java).apply { this.action = "STOP" }
                        )
                        updateAllWidgets(context)
                    }
                    TunnelToggleAction.REQUEST_VPN_PERMISSION -> {
                        Toast.makeText(
                            context,
                            "Откройте WDTT Plus и выдайте VPN-разрешение",
                            Toast.LENGTH_LONG
                        ).show()
                        openMainActivity(context)
                    }
                    TunnelToggleAction.START -> scope.launch {
                        try {
                            val startIntent = buildTunnelStartIntentFromSettings(context)
                            if (startIntent == null) {
                                Toast.makeText(
                                    context,
                                    "Заполните настройки подключения в WDTT Plus",
                                    Toast.LENGTH_LONG
                                ).show()
                                openMainActivity(context)
                                return@launch
                            }

                            if (Build.VERSION.SDK_INT >= 26) {
                                context.startForegroundService(startIntent)
                            } else {
                                context.startService(startIntent)
                            }
                        } catch (e: Exception) {
                            Log.e("VpnWidget", "Failed to start tunnel from widget", e)
                            Toast.makeText(
                                context,
                                "Ошибка запуска: ${e.localizedMessage}",
                                Toast.LENGTH_SHORT
                            ).show()
                        }
                    }
                }
            }.onFailure { e ->
                Log.e("VpnWidget", "Error handling widget click", e)
            }
        }
    }

    private fun updateWidgetState(
        context: Context,
        appWidgetManager: AppWidgetManager,
        appWidgetId: Int,
        running: Boolean,
        trustedWifi: TrustedWifiRuntimeState,
        activeProfile: Int,
        profileNames: List<String>,
        accessLifecycle: AccessLifecycleUiState,
    ) {
        val views = RemoteViews(context.packageName, R.layout.vpn_widget)

        // Обновляем текст статуса и неоновую иконку кнопки
        if (trustedWifi.waiting) {
            val networkName = trustedWifi.ssid.ifBlank { "Wi-Fi" }
            views.setTextViewText(R.id.widget_status, "Ожидание: $networkName")
            views.setTextColor(R.id.widget_status, 0xFFFFB74D.toInt())
            views.setInt(R.id.widget_toggle_btn, "setBackgroundResource", R.drawable.bg_widget_button_inactive)
        } else if (running) {
            val profileName = vpnProfileDisplayName(activeProfile, profileNames)
            val status = "Подключено к $profileName"
            views.setTextViewText(R.id.widget_status, status)
            views.setTextColor(R.id.widget_status, 0xFF00E5FF.toInt()) // Неоновый голубой
            views.setInt(R.id.widget_toggle_btn, "setBackgroundResource", R.drawable.bg_widget_button_active)
        } else {
            val accessBlocked = accessLifecycle.managed && !accessLifecycle.allowConnect
            views.setTextViewText(
                R.id.widget_status,
                accessLifecycle.title.takeIf { accessBlocked && it.isNotBlank() }
                    ?: accessLifecycle.fallbackTitle().takeIf { accessBlocked }
                    ?: "Отключено"
            )
            views.setTextColor(
                R.id.widget_status,
                if (
                    accessLifecycle.severity == AccessLifecycleSeverity.ERROR &&
                    accessBlocked
                ) {
                    0xFFFF6B6B.toInt()
                } else {
                    0xFF888888.toInt()
                }
            )
            views.setInt(R.id.widget_toggle_btn, "setBackgroundResource", R.drawable.bg_widget_button_inactive)
        }

        // Клик по всей карточке открывает приложение
        val openIntent = Intent(context, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        val openPendingIntent = PendingIntent.getActivity(
            context,
            appWidgetId,
            openIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        views.setOnClickPendingIntent(R.id.widget_container, openPendingIntent)

        // Клик по кнопке запускает/останавливает VPN
        val toggleIntent = Intent(context, VpnWidgetProvider::class.java).apply {
            action = ACTION_WIDGET_TOGGLE
        }
        val togglePendingIntent = PendingIntent.getBroadcast(
            context,
            appWidgetId + 1000,
            toggleIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        views.setOnClickPendingIntent(R.id.widget_toggle_btn, togglePendingIntent)

        appWidgetManager.updateAppWidget(appWidgetId, views)
    }

    private fun openMainActivity(context: Context) {
        val intent = Intent(context, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        runCatching {
            val pendingIntent = PendingIntent.getActivity(
                context,
                200,
                intent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
            pendingIntent.send()
        }.onFailure {
            context.startActivity(intent)
        }
    }

}
