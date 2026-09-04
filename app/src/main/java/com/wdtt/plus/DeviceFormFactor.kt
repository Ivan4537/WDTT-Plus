package com.wdtt.plus

import android.content.Context
import android.content.pm.PackageManager
import android.content.res.Configuration

internal fun isTelevisionUiMode(uiMode: Int): Boolean =
    uiMode and Configuration.UI_MODE_TYPE_MASK == Configuration.UI_MODE_TYPE_TELEVISION

internal fun shouldUseTelevisionControls(
    uiMode: Int,
    hasLeanbackFeature: Boolean,
): Boolean = isTelevisionUiMode(uiMode) || hasLeanbackFeature

internal fun isTelevisionDevice(context: Context): Boolean =
    shouldUseTelevisionControls(
        uiMode = context.resources.configuration.uiMode,
        hasLeanbackFeature =
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_LEANBACK) ||
                context.packageManager.hasSystemFeature(PackageManager.FEATURE_LEANBACK_ONLY),
    )

internal fun shouldShowPhonePermissionOnboarding(television: Boolean): Boolean = !television
