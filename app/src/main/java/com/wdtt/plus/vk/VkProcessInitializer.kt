package com.wdtt.plus.vk

import android.app.Application
import android.webkit.WebView
import androidx.annotation.Keep
import androidx.compose.runtime.Composable
import com.wdtt.plus.LocalBuildExtension

@Keep
object VkProcessInitializer : LocalBuildExtension {
    override fun initializeAuxiliaryProcess(application: Application): Boolean {
        val process = Application.getProcessName()
        val profile = (0..2).firstOrNull {
            process == application.packageName + ProfileWebSessionScope.processSuffix(it)
        }
        if (profile == null) return false
        // Before any WebView/CookieManager access. Other app WebViews cannot read this jar.
        WebView.setDataDirectorySuffix(ProfileWebSessionScope.webDataSuffix(profile))
        WebView.setWebContentsDebuggingEnabled(false)
        // No main-process VPN initialization, workers, backend requests or widget state here.
        return true
    }

    @Composable
    override fun Content() = Unit
}
