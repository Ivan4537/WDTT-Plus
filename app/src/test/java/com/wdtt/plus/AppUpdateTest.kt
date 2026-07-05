package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AppUpdateTest {
    private val universalSha = "0".repeat(64)
    private val arm64Sha = "1".repeat(64)
    private val staleSha = "2".repeat(64)

    @Test
    fun sameVersionFix_isNotReportedWhenInstalledShaMatchesAnyReleaseApk() {
        val release = releaseWithHashes(universalSha, arm64Sha)

        assertFalse(hasSameVersionApkFix(universalSha, release))
        assertFalse(hasSameVersionApkFix(arm64Sha, release))
    }

    @Test
    fun sameVersionFix_isReportedWhenInstalledShaIsAbsentFromReleaseApks() {
        val release = releaseWithHashes(universalSha, arm64Sha)

        assertTrue(hasSameVersionApkFix(staleSha, release))
    }

    @Test
    fun sameVersionFix_isNotReportedWithoutGithubApkDigests() {
        val release = AppReleaseInfo(
            versionTag = "v7",
            releaseUrl = "https://example.org/v7",
            source = RemoteVersionSource.Release,
            assets = listOf(
                AppReleaseAsset(
                    name = "WDTT-Plus-v7-arm64-v8a-release.apk",
                    downloadUrl = "https://example.org/app.apk",
                    sizeBytes = 1L,
                    digest = ""
                )
            )
        )

        assertFalse(hasSameVersionApkFix(staleSha, release))
    }

    @Test
    fun sameVersionFixPostponeKey_changesWhenReleaseApkHashesChange() {
        val first = sameVersionFixPostponeKey(releaseWithHashes(universalSha, arm64Sha))
        val second = sameVersionFixPostponeKey(releaseWithHashes(universalSha, staleSha))

        assertNotEquals(first, second)
    }

    @Test
    fun versionComparison_supportsSameIntegerTags() {
        assertTrue(isSameVersion("7", "v7"))
        assertTrue(isSameVersion("v7", "7"))
        assertFalse(isSameVersion("v7", "v8"))
        assertEquals(false, isNewerVersion("v7", "v7"))
    }

    @Test
    fun updateInterval_usesAtLeastThirtyMinutesAndSupportsNever() {
        assertEquals(null, updateIntervalMinutesToMillis(UPDATE_CHECK_NEVER))
        assertEquals(30L * 60L * 1000L, updateIntervalMinutesToMillis(1))
        assertEquals(30L * 60L * 1000L, updateIntervalMinutesToMillis(DEFAULT_UPDATE_CHECK_INTERVAL_MINUTES))
        assertEquals(45L * 60L * 1000L, updateIntervalMinutesToMillis(45))
        assertEquals(UPDATE_CHECK_NEVER, normalizeUpdateCheckIntervalMinutes(UPDATE_CHECK_NEVER))
        assertEquals(DEFAULT_UPDATE_CHECK_INTERVAL_MINUTES, normalizeUpdateCheckIntervalMinutes(1))
    }

    @Test
    fun foregroundUpdateCheck_isThrottledByFiveMinutes() {
        val now = 1_000_000L

        assertTrue(shouldRunForegroundUpdateCheck(lastCheckAt = 0L, now = now))
        assertFalse(
            shouldRunForegroundUpdateCheck(
                lastCheckAt = now - FOREGROUND_UPDATE_CHECK_MIN_INTERVAL_MS + 1L,
                now = now
            )
        )
        assertTrue(
            shouldRunForegroundUpdateCheck(
                lastCheckAt = now - FOREGROUND_UPDATE_CHECK_MIN_INTERVAL_MS,
                now = now
            )
        )
    }

    private fun releaseWithHashes(vararg hashes: String): AppReleaseInfo {
        return AppReleaseInfo(
            versionTag = "v7",
            releaseUrl = "https://example.org/v7",
            source = RemoteVersionSource.Release,
            assets = hashes.mapIndexed { index, hash ->
                AppReleaseAsset(
                    name = if (index == 0) {
                        "WDTT-Plus-v7-universal-release.apk"
                    } else {
                        "WDTT-Plus-v7-arm64-v8a-release.apk"
                    },
                    downloadUrl = "https://example.org/app-$index.apk",
                    sizeBytes = 1L,
                    digest = "sha256:$hash"
                )
            }
        )
    }
}
