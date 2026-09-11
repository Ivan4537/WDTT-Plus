package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AppUpdateTest {
    private val universalSha = "0".repeat(64)
    private val arm64Sha = "1".repeat(64)
    private val staleSha = "2".repeat(64)

    @Test
    fun slowDirectDownloadFallsBackOnlyWhenRelayIsReady() {
        assertFalse(shouldFallbackSlowDirectUpdateDownload(true, 100L, 7_999L))
        assertFalse(shouldFallbackSlowDirectUpdateDownload(false, 1L, 60_000L))
        assertTrue(shouldFallbackSlowDirectUpdateDownload(true, 128L * 1024L, 8_000L))
        assertFalse(shouldFallbackSlowDirectUpdateDownload(true, 1024L * 1024L, 8_000L))
    }

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

    @Test
    fun updateAssetRequiresOfficialUrlSizeAndDigest() {
        val safe = AppReleaseAsset(
            name = "WDTT-Plus-v12-universal-release.apk",
            downloadUrl = (
                "https://github.com/Ivan4537/WDTT-Plus/releases/download/" +
                    "v12/WDTT-Plus-v12-universal-release.apk"
                ),
            sizeBytes = 42L,
            digest = "sha256:${"a".repeat(64)}",
        )
        val release = AppReleaseInfo(
            versionTag = "v12",
            releaseUrl = "https://github.com/Ivan4537/WDTT-Plus/releases/tag/v12",
            source = RemoteVersionSource.Release,
            assets = listOf(safe),
        )

        assertEquals(safe, selectUpdateApkAsset(release))
        assertNull(
            selectUpdateApkAsset(
                release.copy(assets = listOf(safe.copy(digest = ""))),
            ),
        )
        assertFalse(
            isTrustedUpdateDownloadUrl(
                "https://github.com/other/project/releases/download/v12/app.apk",
                initialRequest = true,
            ),
        )
        assertTrue(
            isTrustedUpdateDownloadUrl(
                "https://release-assets.githubusercontent.com/opaque",
                initialRequest = false,
            ),
        )
    }

    @Test
    fun relayedMetadataPreservesOfficialReleaseAndApkVerificationData() {
        val digest = "sha256:${"a".repeat(64)}"
        val parsed = parseRelayedUpdateMetadata(
            """{
                "version_tag":"17",
                "release_url":"https://github.com/Ivan4537/WDTT-Plus/releases/tag/v17",
                "source":"release",
                "assets":[{
                    "name":"WDTT-Plus-v17-arm64-v8a-release.apk",
                    "download_url":"https://github.com/Ivan4537/WDTT-Plus/releases/download/v17/WDTT-Plus-v17-arm64-v8a-release.apk",
                    "size":12345,
                    "digest":"$digest"
                }]
            }""".trimIndent(),
        )

        requireNotNull(parsed)
        assertEquals("v17", parsed.versionTag)
        assertEquals(RemoteVersionSource.Release, parsed.source)
        assertEquals(digest, parsed.assets.single().digest)
    }

    @Test
    fun relayedMetadataRejectsUntrustedReleaseOrAssetUrls() {
        assertNull(
            parseRelayedUpdateMetadata(
                """{
                    "version_tag":"v17",
                    "release_url":"https://example.com/Ivan4537/WDTT-Plus/releases/tag/v17",
                    "source":"release"
                }""".trimIndent(),
            ),
        )

        val parsed = parseRelayedUpdateMetadata(
            """{
                "version_tag":"v17",
                "release_url":"https://github.com/Ivan4537/WDTT-Plus/releases/tag/v17",
                "source":"release",
                "assets":[{
                    "name":"evil.apk",
                    "download_url":"https://example.com/evil.apk",
                    "size":123,
                    "digest":"sha256:${"b".repeat(64)}"
                }]
            }""".trimIndent(),
        )
        requireNotNull(parsed)
        assertTrue(parsed.assets.isEmpty())
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
