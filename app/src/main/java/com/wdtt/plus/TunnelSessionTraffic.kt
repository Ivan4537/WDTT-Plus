package com.wdtt.plus

import java.util.Locale

private val tunnelTrafficPairRegex = Regex(
    "↓\\s*([0-9]+(?:[.,][0-9]+)?)\\s*МБ\\s*/\\s*↑\\s*([0-9]+(?:[.,][0-9]+)?)\\s*МБ"
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
