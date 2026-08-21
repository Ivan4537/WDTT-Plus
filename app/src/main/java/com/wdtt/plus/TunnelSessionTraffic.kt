package com.wdtt.plus

import android.content.Context
import java.util.Locale

private val tunnelTrafficPairRegex = Regex(
    "↓\\s*([0-9]+(?:[.,][0-9]+)?)\\s*МБ\\s*/\\s*↑\\s*([0-9]+(?:[.,][0-9]+)?)\\s*МБ"
)
private val tunnelTrafficValueMbRegex = Regex(
    "([↓↑])\\s*([0-9]+(?:[.,][0-9]+)?)\\s*МБ"
)

internal fun formatTunnelTrafficForNotification(message: String): String =
    tunnelTrafficValueMbRegex.replace(message) { match ->
        val megabytes = match.groupValues[2].replace(',', '.').toDoubleOrNull()
            ?: return@replace match.value
        if (megabytes < MEBIBYTES_PER_GIBIBYTE) {
            match.value
        } else {
            val gibibytes = megabytes / MEBIBYTES_PER_GIBIBYTE
            "${match.groupValues[1]}${String.format(Locale.US, "%.2f", gibibytes)} ГБ"
        }
    }

internal data class TunnelSessionTrafficSnapshot(
    val downloadOffsetMb: Double,
    val uploadOffsetMb: Double,
    val lastRawDownloadMb: Double?,
    val lastRawUploadMb: Double?,
)

internal class TunnelSessionTrafficAccumulator {
    private var downloadOffsetMb = 0.0
    private var uploadOffsetMb = 0.0
    private var lastRawDownloadMb: Double? = null
    private var lastRawUploadMb: Double? = null

    @Synchronized
    fun reset() {
        downloadOffsetMb = 0.0
        uploadOffsetMb = 0.0
        lastRawDownloadMb = null
        lastRawUploadMb = null
    }

    @Synchronized
    fun restore(snapshot: TunnelSessionTrafficSnapshot?) {
        reset()
        if (snapshot == null || !snapshot.isValid()) return
        downloadOffsetMb = snapshot.downloadOffsetMb
        uploadOffsetMb = snapshot.uploadOffsetMb
        lastRawDownloadMb = snapshot.lastRawDownloadMb
        lastRawUploadMb = snapshot.lastRawUploadMb
    }

    @Synchronized
    fun snapshot(): TunnelSessionTrafficSnapshot = TunnelSessionTrafficSnapshot(
        downloadOffsetMb = downloadOffsetMb,
        uploadOffsetMb = uploadOffsetMb,
        lastRawDownloadMb = lastRawDownloadMb,
        lastRawUploadMb = lastRawUploadMb,
    )

    @Synchronized
    fun noteTransportRestart() {
        downloadOffsetMb += lastRawDownloadMb ?: 0.0
        uploadOffsetMb += lastRawUploadMb ?: 0.0
        lastRawDownloadMb = null
        lastRawUploadMb = null
    }

    @Synchronized
    fun accumulate(message: String): String {
        val match = tunnelTrafficPairRegex.find(message) ?: return message
        val rawDownload = match.groupValues[1].toTrafficDouble() ?: return message
        val rawUpload = match.groupValues[2].toTrafficDouble() ?: return message

        val previousDownload = lastRawDownloadMb
        val previousUpload = lastRawUploadMb
        if (previousDownload != null && rawDownload + TRAFFIC_RESET_TOLERANCE_MB < previousDownload) {
            downloadOffsetMb += previousDownload
        }
        if (previousUpload != null && rawUpload + TRAFFIC_RESET_TOLERANCE_MB < previousUpload) {
            uploadOffsetMb += previousUpload
        }

        lastRawDownloadMb = rawDownload
        lastRawUploadMb = rawUpload

        val replacement = "↓${formatTrafficMb(downloadOffsetMb + rawDownload)} МБ / " +
            "↑${formatTrafficMb(uploadOffsetMb + rawUpload)} МБ"
        return message.replaceRange(match.range, replacement)
    }

    private fun String.toTrafficDouble(): Double? =
        replace(',', '.').toDoubleOrNull()

    private fun formatTrafficMb(value: Double): String =
        String.format(Locale.US, "%.2f", value)

    private companion object {
        const val TRAFFIC_RESET_TOLERANCE_MB = 0.005
    }
}

private fun TunnelSessionTrafficSnapshot.isValid(): Boolean =
    downloadOffsetMb.isFinite() && downloadOffsetMb >= 0.0 &&
        uploadOffsetMb.isFinite() && uploadOffsetMb >= 0.0 &&
        lastRawDownloadMb.isValidTrafficValue() &&
        lastRawUploadMb.isValidTrafficValue()

private fun Double?.isValidTrafficValue(): Boolean =
    this == null || (isFinite() && this >= 0.0)

private const val MEBIBYTES_PER_GIBIBYTE = 1024.0

internal class TunnelSessionTrafficStore(context: Context) {
    private val appContext = context.applicationContext
    private val preferences = appContext.getSharedPreferences(
        PREFERENCES_NAME,
        Context.MODE_PRIVATE,
    )
    private val currentBootCount = runCatching {
        android.provider.Settings.Global.getInt(
            appContext.contentResolver,
            android.provider.Settings.Global.BOOT_COUNT,
        )
    }.getOrDefault(UNKNOWN_BOOT_COUNT)

    fun load(): TunnelSessionTrafficSnapshot? {
        if (preferences.getInt(KEY_VERSION, 0) != SNAPSHOT_VERSION) return null
        val savedBootCount = preferences.getInt(KEY_BOOT_COUNT, UNKNOWN_BOOT_COUNT)
        if (
            currentBootCount != UNKNOWN_BOOT_COUNT &&
            savedBootCount != UNKNOWN_BOOT_COUNT &&
            currentBootCount != savedBootCount
        ) return null
        return TunnelSessionTrafficSnapshot(
            downloadOffsetMb = preferences.getString(KEY_DOWNLOAD_OFFSET, null)?.toDoubleOrNull()
                ?: return null,
            uploadOffsetMb = preferences.getString(KEY_UPLOAD_OFFSET, null)?.toDoubleOrNull()
                ?: return null,
            lastRawDownloadMb = preferences.getString(KEY_LAST_RAW_DOWNLOAD, null)?.toDoubleOrNull(),
            lastRawUploadMb = preferences.getString(KEY_LAST_RAW_UPLOAD, null)?.toDoubleOrNull(),
        ).takeIf(TunnelSessionTrafficSnapshot::isValid)
    }

    fun save(snapshot: TunnelSessionTrafficSnapshot) {
        if (!snapshot.isValid()) return
        preferences.edit()
            .putInt(KEY_VERSION, SNAPSHOT_VERSION)
            .putInt(KEY_BOOT_COUNT, currentBootCount)
            .putString(KEY_DOWNLOAD_OFFSET, snapshot.downloadOffsetMb.toString())
            .putString(KEY_UPLOAD_OFFSET, snapshot.uploadOffsetMb.toString())
            .putNullableDouble(KEY_LAST_RAW_DOWNLOAD, snapshot.lastRawDownloadMb)
            .putNullableDouble(KEY_LAST_RAW_UPLOAD, snapshot.lastRawUploadMb)
            .apply()
    }

    fun clear() {
        preferences.edit().clear().apply()
    }

    private fun android.content.SharedPreferences.Editor.putNullableDouble(
        key: String,
        value: Double?,
    ): android.content.SharedPreferences.Editor = if (value == null) {
        remove(key)
    } else {
        putString(key, value.toString())
    }

    private companion object {
        const val PREFERENCES_NAME = "wdtt_tunnel_session_traffic"
        const val SNAPSHOT_VERSION = 1
        const val UNKNOWN_BOOT_COUNT = -1
        const val KEY_VERSION = "version"
        const val KEY_BOOT_COUNT = "boot_count"
        const val KEY_DOWNLOAD_OFFSET = "download_offset_mb"
        const val KEY_UPLOAD_OFFSET = "upload_offset_mb"
        const val KEY_LAST_RAW_DOWNLOAD = "last_raw_download_mb"
        const val KEY_LAST_RAW_UPLOAD = "last_raw_upload_mb"
    }
}
