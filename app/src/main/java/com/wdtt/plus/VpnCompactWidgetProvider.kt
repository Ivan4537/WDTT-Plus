package com.wdtt.plus

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.widget.RemoteViews
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

class VpnCompactWidgetProvider : AppWidgetProvider() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    companion object {
        fun updateAllWidgets(context: Context) {
            runCatching {
                val manager = AppWidgetManager.getInstance(context)
                val component = ComponentName(context, VpnCompactWidgetProvider::class.java)
                val ids = manager.getAppWidgetIds(component)
                if (ids.isNotEmpty()) {
                    context.sendBroadcast(
                        Intent(context, VpnCompactWidgetProvider::class.java).apply {
                            action = AppWidgetManager.ACTION_APPWIDGET_UPDATE
                            putExtra(AppWidgetManager.EXTRA_APPWIDGET_IDS, ids)
                        }
                    )
                }
            }
        }
    }

    override fun onUpdate(
        context: Context,
        appWidgetManager: AppWidgetManager,
        appWidgetIds: IntArray
    ) {
        val running = TunnelManager.running.value
        val waiting = TrustedWifiManager.state.value.waiting
        scope.launch {
            val settingsStore = SettingsStore(context)
            val activeProfile = settingsStore.activeProfile.first().coerceIn(0, 2)
            val profileNames = settingsStore.profileNames.first()
            val profileName = vpnProfileDisplayName(activeProfile, profileNames)

            appWidgetIds.forEach { appWidgetId ->
                val views = RemoteViews(context.packageName, R.layout.vpn_widget_compact)
                views.setInt(
                    R.id.compact_widget_toggle,
                    "setBackgroundResource",
                    if (running && !waiting) R.drawable.bg_widget_button_active else R.drawable.bg_widget_button_inactive
                )
                views.setTextViewText(
                    R.id.compact_widget_profile,
                    if (waiting) "Ожидание" else profileName
                )

                val toggleIntent = Intent(context, VpnWidgetProvider::class.java).apply {
                    action = VpnWidgetProvider.ACTION_WIDGET_TOGGLE
                }
                val togglePendingIntent = PendingIntent.getBroadcast(
                    context,
                    appWidgetId + 20_000,
                    toggleIntent,
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                )
                views.setOnClickPendingIntent(R.id.compact_widget_container, togglePendingIntent)
                views.setOnClickPendingIntent(R.id.compact_widget_toggle, togglePendingIntent)

                appWidgetManager.updateAppWidget(appWidgetId, views)
            }
        }
    }
}
