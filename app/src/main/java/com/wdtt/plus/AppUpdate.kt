package com.wdtt.plus

import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.Locale

const val UPDATE_CHECK_NEVER = -1
const val DEFAULT_UPDATE_CHECK_INTERVAL_MINUTES = 30
const val FOREGROUND_UPDATE_CHECK_MIN_INTERVAL_MS = 5L * 60L * 1000L
const val UPDATE_DIALOG_ACTION_POSTPONED = "postponed"
const val UPDATE_DIALOG_ACTION_UPDATE = "update"

private const val UPDATE_LOG_TAG = "WDTT"
private const val GITHUB_RELEASES_URL = "https://api.github.com/repos/Ivan4537/WDTT-Plus/releases?per_page=30"
private const val GITHUB_LATEST_RELEASE_URL = "https://api.github.com/repos/Ivan4537/WDTT-Plus/releases/latest"
private const val GITHUB_LATEST_RELEASE_WEB_URL = "https://github.com/Ivan4537/WDTT-Plus/releases/latest"
private const val GITHUB_RELEASE_TAG_URL_PREFIX = "https://github.com/Ivan4537/WDTT-Plus/releases/tag/"
private const val GITHUB_TAGS_URL = "https://api.github.com/repos/Ivan4537/WDTT-Plus/tags?per_page=100"
private const val GITHUB_TAG_TREE_URL_PREFIX = "https://github.com/Ivan4537/WDTT-Plus/tree/"
private const val UPDATE_CHECK_TOTAL_TIMEOUT_MS = 25_000L
private const val UPDATE_CHECK_REQUEST_TIMEOUT_MS = 6_000L
private const val UPDATE_CHECK_MIN_REQUEST_TIMEOUT_MS = 1_000L
private const val UPDATE_APK_HASH_TIMEOUT_MS = 4_000L
private const val GITHUB_API_RATE_LIMIT_FALLBACK_MS = 30L * 60L * 1000L
private val SIMPLE_VERSION_TAG_REGEX = Regex("^v?(\\d+)$", RegexOption.IGNORE_CASE)

@Volatile
private var githubApiCooldownUntilMs = 0L

@Volatile
private var installedApkSha256Cache: InstalledApkSha256Cache? = null

fun updateIntervalMinutesToMillis(minutes: Int): Long? = when {
    minutes == UPDATE_CHECK_NEVER -> null
    minutes <= 0 -> null
    else -> minutes.coerceAtLeast(DEFAULT_UPDATE_CHECK_INTERVAL_MINUTES) * 60L * 1000L
}

fun shouldRunForegroundUpdateCheck(lastCheckAt: Long, now: Long): Boolean {
    return lastCheckAt <= 0L || now - lastCheckAt >= FOREGROUND_UPDATE_CHECK_MIN_INTERVAL_MS
}

data class AppReleaseInfo(
    val versionTag: String,
    val releaseUrl: String,
    val source: RemoteVersionSource,
    val assets: List<AppReleaseAsset> = emptyList()
)

data class AppReleaseAsset(
    val name: String,
    val downloadUrl: String,
    val sizeBytes: Long,
    val digest: String = ""
) {
    val sha256: String?
        get() = digest
            .removePrefix("sha256:")
            .trim()
            .lowercase(Locale.US)
            .takeIf { it.matches(Regex("^[0-9a-f]{64}$")) }
}

data class AppUpdateDownloadProgress(
    val fileName: String,
    val downloadedBytes: Long,
    val totalBytes: Long
) {
    val fraction: Float?
        get() = totalBytes.takeIf { it > 0L }?.let { (downloadedBytes.toFloat() / it).coerceIn(0f, 1f) }

    val percent: Int?
        get() = fraction?.let { (it * 100).toInt().coerceIn(0, 100) }
}

enum class RemoteVersionSource {
    Release,
    Tag
}

enum class AppUpdateKind {
    NewVersion,
    SameVersionFix
}

data class AppUpdateCandidate(
    val release: AppReleaseInfo,
    val kind: AppUpdateKind,
    val sameVersionFixKey: String? = null
) {
    val postponeKey: String
        get() = when (kind) {
            AppUpdateKind.NewVersion -> release.versionTag
            AppUpdateKind.SameVersionFix -> sameVersionFixKey ?: "${release.versionTag}:fix"
        }
}

private data class InstalledApkSha256Cache(
    val path: String,
    val length: Long,
    val lastModified: Long,
    val sha256: String
)

private class UpdateCheckBudget(
    timeoutMs: Long = UPDATE_CHECK_TOTAL_TIMEOUT_MS
) {
    private val deadlineAt = System.currentTimeMillis() + timeoutMs

    val expired: Boolean
        get() = System.currentTimeMillis() >= deadlineAt

    fun timeoutForHttpPhase(): Int? {
        val remaining = deadlineAt - System.currentTimeMillis()
        if (remaining < UPDATE_CHECK_MIN_REQUEST_TIMEOUT_MS * 2L) return null
        return minOf(
            UPDATE_CHECK_REQUEST_TIMEOUT_MS,
            (remaining / 2L).coerceAtLeast(UPDATE_CHECK_MIN_REQUEST_TIMEOUT_MS)
        ).toInt()
    }

    fun requireTimeLeft(operation: String) {
        if (expired) throw IOException("$operation не уложилась в лимит времени")
    }
}

suspend fun fetchLatestReleaseInfo(localVersion: String? = null): AppReleaseInfo? = withContext(Dispatchers.IO) {
    val budget = UpdateCheckBudget()
    val webRelease = fetchReleaseFromLatestWebRedirect(budget)
    val apiRelease = fetchReleaseFromLatestEndpoint(budget) ?: fetchLatestStableReleaseFromList(budget)
    val latestRelease = when {
        webRelease == null -> apiRelease
        apiRelease == null -> fetchReleaseByTag(webRelease.versionTag, budget) ?: webRelease
        isNewerVersion(apiRelease.versionTag, webRelease.versionTag) -> fetchReleaseByTag(webRelease.versionTag, budget) ?: webRelease
        else -> apiRelease
    }
    val latestTag = fetchLatestTagFromList(budget)

    when {
        latestRelease == null -> latestTag
        latestTag == null -> latestRelease
        isNewerVersion(latestRelease.versionTag, latestTag.versionTag) -> latestTag
        else -> latestRelease
    }
}

suspend fun resolveAppUpdateCandidate(
    context: Context,
    localVersion: String,
    release: AppReleaseInfo?
): AppUpdateCandidate? = withContext(Dispatchers.IO) {
    if (release == null) return@withContext null
    if (isNewerVersion(localVersion, release.versionTag)) {
        return@withContext AppUpdateCandidate(
            release = release,
            kind = AppUpdateKind.NewVersion
        )
    }

    if (!isSameVersion(localVersion, release.versionTag) || release.source != RemoteVersionSource.Release) {
        return@withContext null
    }

    val installedSha256 = installedApkSha256(context, UpdateCheckBudget(UPDATE_APK_HASH_TIMEOUT_MS))
        ?: return@withContext null
    if (!hasSameVersionApkFix(installedSha256, release)) return@withContext null
    AppUpdateCandidate(
        release = release,
        kind = AppUpdateKind.SameVersionFix,
        sameVersionFixKey = sameVersionFixPostponeKey(release)
    )
}

fun selectUpdateApkAsset(release: AppReleaseInfo): AppReleaseAsset? {
    val apkAssets = release.assets
        .filter { it.name.endsWith(".apk", ignoreCase = true) && it.downloadUrl.isNotBlank() }
    if (apkAssets.isEmpty()) return null

    Build.SUPPORTED_ABIS.orEmpty().forEach { abi ->
        apkAssets.firstOrNull { it.name.contains(abi, ignoreCase = true) }?.let { return it }
    }

    return apkAssets.firstOrNull { it.name.contains("universal", ignoreCase = true) }
        ?: apkAssets.firstOrNull()
}

suspend fun downloadUpdateApk(
    context: Context,
    asset: AppReleaseAsset,
    onProgress: suspend (AppUpdateDownloadProgress) -> Unit = {}
): File = withContext(Dispatchers.IO) {
    val appContext = context.applicationContext
    val updatesDir = File(appContext.cacheDir, "updates").apply { mkdirs() }
    updatesDir.listFiles()?.forEach { file ->
        if (file.isFile && file.extension.equals("apk", ignoreCase = true)) file.delete()
    }

    val outputFile = File(updatesDir, asset.name.safeUpdateAssetName())
    var conn: HttpURLConnection? = null

    suspend fun emit(downloaded: Long, total: Long) {
        withContext(Dispatchers.Main) {
            onProgress(AppUpdateDownloadProgress(asset.name, downloaded, total))
        }
    }

    try {
        conn = URL(asset.downloadUrl).openConnection() as HttpURLConnection
        applyNoCacheHeaders(conn)
        conn.instanceFollowRedirects = true
        conn.requestMethod = "GET"
        conn.setRequestProperty("Accept", "application/vnd.android.package-archive,application/octet-stream,*/*")
        conn.setRequestProperty("User-Agent", "WDTTAndroid/${BuildConfig.VERSION_NAME}")
        conn.connectTimeout = 15_000
        conn.readTimeout = 30_000

        val responseCode = conn.responseCode
        if (responseCode !in 200..299) {
            throw IOException("GitHub вернул HTTP $responseCode при скачивании APK")
        }

        val total = asset.sizeBytes.takeIf { it > 0L }
            ?: conn.contentLengthLong.takeIf { it > 0L }
            ?: 0L
        var downloaded = 0L
        var lastEmitAt = 0L
        emit(0L, total)

        conn.inputStream.use { input ->
            outputFile.outputStream().use { output ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    output.write(buffer, 0, read)
                    downloaded += read
                    val now = System.currentTimeMillis()
                    if (now - lastEmitAt >= 250L || downloaded == total) {
                        lastEmitAt = now
                        emit(downloaded, total)
                    }
                }
            }
        }

        if (asset.sizeBytes > 0L && outputFile.length() != asset.sizeBytes) {
            outputFile.delete()
            throw IOException("Размер APK не совпал с GitHub asset")
        }

        asset.sha256?.let { expected ->
            val actual = outputFile.sha256Hex()
            if (!actual.equals(expected, ignoreCase = true)) {
                outputFile.delete()
                throw SecurityException("SHA-256 скачанного APK не совпал с GitHub digest")
            }
        }

        emit(outputFile.length(), total.takeIf { it > 0L } ?: outputFile.length())
        outputFile
    } catch (e: Exception) {
        outputFile.delete()
        throw e
    } finally {
        conn?.disconnect()
    }
}

fun canRequestApkInstall(context: Context): Boolean {
    return Build.VERSION.SDK_INT < Build.VERSION_CODES.O ||
        context.packageManager.canRequestPackageInstalls()
}

fun installUpdateApk(context: Context, apkFile: File) {
    val appContext = context.applicationContext
    val uri = FileProvider.getUriForFile(appContext, "${appContext.packageName}.files", apkFile)
    val intent = Intent(Intent.ACTION_VIEW).apply {
        setDataAndType(uri, "application/vnd.android.package-archive")
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    appContext.startActivity(intent)
}

fun isNewerVersion(local: String, remote: String): Boolean {
    val localParts = versionParts(local)
    val remoteParts = versionParts(remote)
    if (remoteParts.isEmpty()) return false

    val maxLen = maxOf(localParts.size, remoteParts.size)
    for (i in 0 until maxLen) {
        val localPart = localParts.getOrElse(i) { 0 }
        val remotePart = remoteParts.getOrElse(i) { 0 }
        if (remotePart > localPart) return true
        if (remotePart < localPart) return false
    }
    return false
}

fun isSameVersion(left: String, right: String): Boolean {
    val leftNumber = versionNumber(left) ?: return false
    val rightNumber = versionNumber(right) ?: return false
    return leftNumber == rightNumber
}

internal fun releaseApkSha256Set(release: AppReleaseInfo): Set<String> {
    return release.assets
        .asSequence()
        .filter { it.name.endsWith(".apk", ignoreCase = true) }
        .mapNotNull { it.sha256 }
        .map { it.lowercase(Locale.US) }
        .toSet()
}

internal fun hasSameVersionApkFix(installedSha256: String?, release: AppReleaseInfo): Boolean {
    val installed = installedSha256
        ?.trim()
        ?.lowercase(Locale.US)
        ?.takeIf { it.matches(Regex("^[0-9a-f]{64}$")) }
        ?: return false
    val officialApkHashes = releaseApkSha256Set(release)
    return officialApkHashes.isNotEmpty() && installed !in officialApkHashes
}

internal fun sameVersionFixPostponeKey(release: AppReleaseInfo): String? {
    val officialApkHashes = releaseApkSha256Set(release)
        .takeIf { it.isNotEmpty() }
        ?: return null
    val fingerprint = officialApkHashes
        .sorted()
        .joinToString("\n")
        .sha256Hex()
        .take(16)
    return "${release.versionTag}:fix:$fingerprint"
}

private fun fetchLatestStableReleaseFromList(budget: UpdateCheckBudget): AppReleaseInfo? {
    val response = fetchGitHubApi(GITHUB_RELEASES_URL, budget) ?: return null
    val releases = try {
        JSONArray(response)
    } catch (e: Exception) {
        Log.w(UPDATE_LOG_TAG, "[WARN] Update check: failed to parse releases list", e)
        return null
    }

    var bestRelease: AppReleaseInfo? = null
    for (i in 0 until releases.length()) {
        val json = releases.optJSONObject(i) ?: continue
        if (json.optBoolean("draft") || json.optBoolean("prerelease")) continue
        val release = json.toAppReleaseInfo() ?: continue
        if (bestRelease == null || isNewerVersion(bestRelease.versionTag, release.versionTag)) {
            bestRelease = release
        }
    }
    return bestRelease
}

private fun fetchLatestTagFromList(budget: UpdateCheckBudget): AppReleaseInfo? {
    val response = fetchGitHubApi(GITHUB_TAGS_URL, budget) ?: return null
    val tags = try {
        JSONArray(response)
    } catch (e: Exception) {
        Log.w(UPDATE_LOG_TAG, "[WARN] Update check: failed to parse tags list", e)
        return null
    }

    var bestTag: AppReleaseInfo? = null
    for (i in 0 until tags.length()) {
        val json = tags.optJSONObject(i) ?: continue
        val tagName = normalizeVersionTag(json.optString("name"))
        if (tagName.isBlank()) continue
        val tag = AppReleaseInfo(
            versionTag = tagName,
            releaseUrl = "$GITHUB_TAG_TREE_URL_PREFIX$tagName",
            source = RemoteVersionSource.Tag
        )
        if (bestTag == null || isNewerVersion(bestTag.versionTag, tag.versionTag)) {
            bestTag = tag
        }
    }
    return bestTag
}

private fun fetchReleaseFromLatestEndpoint(budget: UpdateCheckBudget): AppReleaseInfo? {
    val response = fetchGitHubApi(GITHUB_LATEST_RELEASE_URL, budget) ?: return null
    val json = try {
        JSONObject(response)
    } catch (e: Exception) {
        Log.w(UPDATE_LOG_TAG, "[WARN] Update check: failed to parse latest release", e)
        return null
    }
    return json.toAppReleaseInfo()
}

private fun fetchReleaseByTag(tag: String, budget: UpdateCheckBudget): AppReleaseInfo? {
    val normalizedTag = normalizeVersionTag(tag)
    if (normalizedTag.isBlank()) return null
    val response = fetchGitHubApi("https://api.github.com/repos/Ivan4537/WDTT-Plus/releases/tags/$normalizedTag", budget)
        ?: return null
    val json = try {
        JSONObject(response)
    } catch (e: Exception) {
        Log.w(UPDATE_LOG_TAG, "[WARN] Update check: failed to parse release by tag", e)
        return null
    }
    return json.toAppReleaseInfo()
}

private fun fetchReleaseFromLatestWebRedirect(budget: UpdateCheckBudget): AppReleaseInfo? {
    var conn: HttpURLConnection? = null
    return try {
        val requestTimeout = budget.timeoutForHttpPhase() ?: return null
        conn = URL(GITHUB_LATEST_RELEASE_WEB_URL).openConnection() as HttpURLConnection
        applyNoCacheHeaders(conn)
        conn.instanceFollowRedirects = false
        conn.requestMethod = "GET"
        conn.setRequestProperty("Accept", "text/html,*/*")
        conn.setRequestProperty("User-Agent", "WDTTAndroid/${BuildConfig.VERSION_NAME}")
        conn.connectTimeout = requestTimeout
        conn.readTimeout = requestTimeout

        val responseCode = conn.responseCode
        val location = conn.getHeaderField("Location")
        if (!location.isNullOrBlank()) {
            val releaseUrl = URL(URL(GITHUB_LATEST_RELEASE_WEB_URL), location).toString()
            val versionTag = extractTagFromReleaseUrl(releaseUrl)
            if (!versionTag.isNullOrBlank()) {
                return AppReleaseInfo(versionTag, releaseUrl, RemoteVersionSource.Release)
            }
        }

        if (responseCode in 200..299) {
            val response = conn.inputStream.bufferedReader().use { it.readText() }
            val versionTag = Regex("/releases/tag/([^\"?#<]+)").find(response)?.groupValues?.getOrNull(1)
            if (!versionTag.isNullOrBlank()) {
                return AppReleaseInfo(versionTag, "$GITHUB_RELEASE_TAG_URL_PREFIX$versionTag", RemoteVersionSource.Release)
            }
        }

        Log.w(UPDATE_LOG_TAG, "[WARN] Update check: GitHub web fallback returned $responseCode")
        null
    } catch (e: Exception) {
        Log.w(UPDATE_LOG_TAG, "[WARN] Update check: GitHub web fallback failed", e)
        null
    } finally {
        conn?.disconnect()
    }
}

private fun fetchGitHubApi(url: String, budget: UpdateCheckBudget): String? {
    val now = System.currentTimeMillis()
    if (now < githubApiCooldownUntilMs || budget.expired) return null
    return fetchHttpText(
        url = url,
        sourceLabel = "GitHub API",
        accept = "application/vnd.github+json",
        budget = budget,
        isGitHubApi = true
    )
}

private fun fetchHttpText(
    url: String,
    sourceLabel: String,
    accept: String,
    budget: UpdateCheckBudget,
    isGitHubApi: Boolean = false
): String? {
    var conn: HttpURLConnection? = null
    return try {
        val requestTimeout = budget.timeoutForHttpPhase() ?: return null
        conn = URL(url).openConnection() as HttpURLConnection
        applyNoCacheHeaders(conn)
        conn.requestMethod = "GET"
        conn.setRequestProperty("Accept", accept)
        if (isGitHubApi) {
            conn.setRequestProperty("X-GitHub-Api-Version", "2022-11-28")
        }
        conn.setRequestProperty("User-Agent", "WDTTAndroid/${BuildConfig.VERSION_NAME}")
        conn.connectTimeout = requestTimeout
        conn.readTimeout = requestTimeout

        val responseCode = conn.responseCode
        val stream = if (responseCode in 200..299) conn.inputStream else conn.errorStream
        val response = stream?.bufferedReader()?.use { it.readText() }.orEmpty()

        if (responseCode in 200..299) {
            if (isGitHubApi) githubApiCooldownUntilMs = 0L
            response
        } else {
            if (isGitHubApi) noteGitHubApiCooldown(conn, responseCode, response)
            Log.w(
                UPDATE_LOG_TAG,
                "[WARN] Update check: $sourceLabel returned $responseCode ${response.take(300)}"
            )
            null
        }
    } catch (e: Exception) {
        Log.w(UPDATE_LOG_TAG, "[WARN] Update check: $sourceLabel request failed", e)
        null
    } finally {
        conn?.disconnect()
    }
}

private fun applyNoCacheHeaders(conn: HttpURLConnection) {
    conn.useCaches = false
    conn.setRequestProperty("Cache-Control", "no-cache, no-store, max-age=0")
    conn.setRequestProperty("Pragma", "no-cache")
    conn.setRequestProperty("Expires", "0")
}

private fun noteGitHubApiCooldown(conn: HttpURLConnection, responseCode: Int, response: String) {
    if (responseCode != HttpURLConnection.HTTP_FORBIDDEN && responseCode != 429) return
    val now = System.currentTimeMillis()
    val retryAfterUntil = conn.getHeaderField("Retry-After")?.trim()?.toLongOrNull()?.takeIf { it > 0L }?.let { now + it * 1000L }
    val rateLimitResetUntil = conn.getHeaderField("X-RateLimit-Reset")?.trim()?.toLongOrNull()?.takeIf { it > 0L }?.let { it * 1000L }
    val fallbackUntil = now + if (response.contains("rate limit", ignoreCase = true)) GITHUB_API_RATE_LIMIT_FALLBACK_MS else 5L * 60L * 1000L
    val cooldownUntil = listOfNotNull(retryAfterUntil, rateLimitResetUntil).filter { it > now }.minOrNull() ?: fallbackUntil
    if (cooldownUntil > githubApiCooldownUntilMs) {
        githubApiCooldownUntilMs = cooldownUntil
        Log.w(
            UPDATE_LOG_TAG,
            "[WARN] Update check: GitHub API cooldown ${(cooldownUntil - now) / 1000}s after HTTP $responseCode"
        )
    }
}

private fun JSONObject.toAppReleaseInfo(): AppReleaseInfo? {
    val versionTag = normalizeVersionTag(optString("tag_name"))
    val releaseUrl = optString("html_url").trim()
    if (versionTag.isBlank() || releaseUrl.isBlank()) return null
    return AppReleaseInfo(
        versionTag = versionTag,
        releaseUrl = releaseUrl,
        source = RemoteVersionSource.Release,
        assets = optJSONArray("assets").toReleaseAssets()
    )
}

private fun JSONArray?.toReleaseAssets(): List<AppReleaseAsset> {
    if (this == null) return emptyList()
    return buildList {
        for (i in 0 until length()) {
            val json = optJSONObject(i) ?: continue
            val name = json.optString("name").trim()
            val downloadUrl = json.optString("browser_download_url").trim()
            if (name.isBlank() || downloadUrl.isBlank()) continue
            add(
                AppReleaseAsset(
                    name = name,
                    downloadUrl = downloadUrl,
                    sizeBytes = json.optLong("size", 0L),
                    digest = json.optString("digest").trim()
                )
            )
        }
    }
}

private fun versionParts(version: String): List<Int> {
    return listOfNotNull(versionNumber(version))
}

private fun normalizeVersionTag(version: String): String {
    val number = versionNumber(version) ?: return ""
    return "v$number"
}

private fun versionNumber(version: String): Int? {
    val match = SIMPLE_VERSION_TAG_REGEX.matchEntire(version.trim()) ?: return null
    return match.groupValues.getOrNull(1)?.toIntOrNull()
}

private fun extractTagFromReleaseUrl(releaseUrl: String): String? {
    val marker = "/releases/tag/"
    val index = releaseUrl.indexOf(marker)
    if (index < 0) return null
    return releaseUrl.substring(index + marker.length)
        .substringBefore("?")
        .substringBefore("#")
        .substringBefore("/")
        .takeIf { it.isNotBlank() }
        ?.let(::normalizeVersionTag)
}

private fun String.safeUpdateAssetName(): String {
    val cleaned = replace(Regex("[^A-Za-z0-9._-]+"), "-")
        .trim('-', '.', '_')
        .takeIf { it.isNotBlank() }
        ?: "WDTT-Plus-update.apk"
    return if (cleaned.endsWith(".apk", ignoreCase = true)) cleaned else "$cleaned.apk"
}

private fun installedApkSha256(context: Context, budget: UpdateCheckBudget): String? {
    val appContext = context.applicationContext
    val path = appContext.applicationInfo.sourceDir?.takeIf { it.isNotBlank() } ?: return null
    val apkFile = File(path)
    if (!apkFile.isFile) return null

    val cached = installedApkSha256Cache
    if (
        cached != null &&
        cached.path == apkFile.absolutePath &&
        cached.length == apkFile.length() &&
        cached.lastModified == apkFile.lastModified()
    ) {
        return cached.sha256
    }

    return runCatching {
        apkFile.sha256Hex(budget)
    }.onSuccess { sha ->
        installedApkSha256Cache = InstalledApkSha256Cache(
            path = apkFile.absolutePath,
            length = apkFile.length(),
            lastModified = apkFile.lastModified(),
            sha256 = sha
        )
    }.onFailure { error ->
        Log.w(UPDATE_LOG_TAG, "[WARN] Update check: failed to hash installed APK", error)
    }.getOrNull()
}

private fun File.sha256Hex(budget: UpdateCheckBudget? = null): String {
    val digest = MessageDigest.getInstance("SHA-256")
    inputStream().use { input ->
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            budget?.requireTimeLeft("SHA-256 установленного APK")
            val read = input.read(buffer)
            if (read < 0) break
            digest.update(buffer, 0, read)
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}

private fun String.sha256Hex(): String {
    val digest = MessageDigest.getInstance("SHA-256")
    return digest.digest(toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
}
