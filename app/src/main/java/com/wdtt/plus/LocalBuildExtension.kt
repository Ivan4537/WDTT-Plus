package com.wdtt.plus

import android.app.Application
import androidx.compose.runtime.Composable

/** Provider process initialization. No remote discovery. */
interface LocalBuildExtension {
    fun initializeAuxiliaryProcess(application: Application): Boolean

    @Composable
    fun Content()
}

object LocalBuildExtensions {
    private val extension: LocalBuildExtension? by lazy {
        try {
            Class.forName("com.wdtt.plus.vk.VkProcessInitializer")
                .getField("INSTANCE").get(null) as LocalBuildExtension
        } catch (_: ClassNotFoundException) {
            null
        }
    }

    fun initializeAuxiliaryProcess(application: Application): Boolean =
        extension?.initializeAuxiliaryProcess(application) == true

    @Composable
    fun Content() {
        extension?.Content()
    }
}
