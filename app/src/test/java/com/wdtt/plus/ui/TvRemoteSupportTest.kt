package com.wdtt.plus.ui

import android.content.res.Configuration
import com.wdtt.plus.isTelevisionUiMode
import com.wdtt.plus.shouldShowPhonePermissionOnboarding
import com.wdtt.plus.shouldUseTelevisionControls
import java.io.File
import javax.imageio.ImageIO
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TvRemoteSupportTest {
    private fun projectFile(path: String): File = listOf(
        File(path),
        File("app/$path"),
    ).first(File::isFile)

    @Test
    fun televisionModeIsDetectedWithAdditionalUiModeFlags() {
        val televisionNightMode =
            Configuration.UI_MODE_TYPE_TELEVISION or Configuration.UI_MODE_NIGHT_YES

        assertTrue(isTelevisionUiMode(televisionNightMode))
    }

    @Test
    fun ordinaryAndroidModesRemainNonTelevision() {
        assertFalse(isTelevisionUiMode(Configuration.UI_MODE_TYPE_NORMAL))
        assertFalse(isTelevisionUiMode(Configuration.UI_MODE_TYPE_CAR))
        assertFalse(isTelevisionUiMode(Configuration.UI_MODE_TYPE_WATCH))
    }

    @Test
    fun leanbackFeatureCoversTvFirmwareWithoutTelevisionUiMode() {
        assertTrue(
            shouldUseTelevisionControls(
                uiMode = Configuration.UI_MODE_TYPE_NORMAL,
                hasLeanbackFeature = true,
            )
        )
    }

    @Test
    fun ordinaryAndroidDoesNotEnableTvControlsFromOrientationIndependentMode() {
        assertFalse(
            shouldUseTelevisionControls(
                uiMode = Configuration.UI_MODE_TYPE_NORMAL,
                hasLeanbackFeature = false,
            )
        )
    }

    @Test
    fun phonePermissionOnboardingIsSkippedOnlyForTelevision() {
        assertTrue(shouldShowPhonePermissionOnboarding(television = false))
        assertFalse(shouldShowPhonePermissionOnboarding(television = true))
    }

    @Test
    fun dpadScrollUsesSmallRepeatableViewportStep() {
        assertEquals(
            160f,
            tvDpadScrollDeltaPx(
                forward = true,
                canScrollBackward = false,
                canScrollForward = true,
                viewportSizePx = 1_000,
                minimumStepPx = 80f,
            ),
            0f,
        )
        assertEquals(
            -80f,
            tvDpadScrollDeltaPx(
                forward = false,
                canScrollBackward = true,
                canScrollForward = true,
                viewportSizePx = 200,
                minimumStepPx = 80f,
            ),
            0f,
        )
    }

    @Test
    fun dpadScrollReleasesFocusNavigationAtEdges() {
        assertEquals(
            0f,
            tvDpadScrollDeltaPx(
                forward = true,
                canScrollBackward = true,
                canScrollForward = false,
                viewportSizePx = 1_000,
                minimumStepPx = 80f,
            ),
            0f,
        )
        assertEquals(
            0f,
            tvDpadScrollDeltaPx(
                forward = false,
                canScrollBackward = false,
                canScrollForward = true,
                viewportSizePx = 1_000,
                minimumStepPx = 80f,
            ),
            0f,
        )
    }

    @Test
    fun televisionBannerProvidesEveryRequiredDensityAtSixteenByNine() {
        val expectedSizes = mapOf(
            "mdpi" to (160 to 90),
            "hdpi" to (240 to 135),
            "xhdpi" to (320 to 180),
            "xxhdpi" to (480 to 270),
            "xxxhdpi" to (640 to 360),
        )
        val manifest = projectFile("src/main/AndroidManifest.xml").readText()

        expectedSizes.forEach { (density, size) ->
            val banner = ImageIO.read(
                projectFile("src/main/res/drawable-$density/tv_banner.png")
            )
            assertEquals(size.first, banner.width)
            assertEquals(size.second, banner.height)
        }
        assertTrue(manifest.contains("android:banner=\"@drawable/tv_banner\""))
    }
}
