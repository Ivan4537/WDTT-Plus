package com.wdtt.plus

import android.os.Bundle
import android.view.View
import com.journeyapps.barcodescanner.CaptureActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.google.zxing.client.android.R as ZxingR

class QrCaptureActivity : CaptureActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val statusView = findViewById<View>(ZxingR.id.zxing_status_view) ?: return
        val originalLeft = statusView.paddingLeft
        val originalTop = statusView.paddingTop
        val originalRight = statusView.paddingRight
        val originalBottom = statusView.paddingBottom
        val extraBottom = (24 * resources.displayMetrics.density).toInt()
        ViewCompat.setOnApplyWindowInsetsListener(statusView) { view, insets ->
            val systemBottom = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            ).bottom
            view.setPadding(
                originalLeft,
                originalTop,
                originalRight,
                originalBottom + systemBottom + extraBottom
            )
            insets
        }
        ViewCompat.requestApplyInsets(statusView)
    }
}
