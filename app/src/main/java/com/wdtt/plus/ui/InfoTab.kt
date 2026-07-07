package com.wdtt.plus.ui

import androidx.compose.runtime.MutableState

import android.app.ActivityManager
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.PowerManager
import android.os.StatFs
import android.provider.Settings
import android.system.Os
import android.system.OsConstants
import android.webkit.WebView
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.GenericShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.automirrored.filled.HelpOutline
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Favorite
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Update
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableIntState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInParent
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.wdtt.plus.BuildConfig
import com.wdtt.plus.DeviceCheckAction
import com.wdtt.plus.DeviceCompatibility
import com.wdtt.plus.R
import com.wdtt.plus.SettingsStore
import com.wdtt.plus.TunnelManager
import com.wdtt.plus.TrustedWifiManager
import com.wdtt.plus.trustedWifiAccessProblem
import com.wdtt.plus.UPDATE_DIALOG_ACTION_POSTPONED
import com.wdtt.plus.UPDATE_DIALOG_ACTION_UPDATE
import com.wdtt.plus.WDTTColors
import com.wdtt.plus.AppReleaseInfo
import com.wdtt.plus.AppUpdateCandidate
import com.wdtt.plus.AppUpdateDownloadProgress
import com.wdtt.plus.canRequestApkInstall
import com.wdtt.plus.downloadUpdateApk
import com.wdtt.plus.fetchLatestReleaseInfo
import com.wdtt.plus.installUpdateApk
import com.wdtt.plus.isNewerVersion
import com.wdtt.plus.resolveAppUpdateCandidate
import com.wdtt.plus.selectUpdateApkAsset
import com.wdtt.plus.deviceCheckActionIntent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.sin

private const val ReleasesUrl = "https://github.com/Ivan4537/WDTT-Plus/releases"
private const val IssuesUrl = "https://github.com/Ivan4537/WDTT-Plus/issues/new/choose"
private const val DeveloperProfileUrl = "https://github.com/Ivan4537"
private const val RepositoryUrl = "https://github.com/Ivan4537/WDTT-Plus"
private const val ChangelogUrl = "$RepositoryUrl/blob/main/CHANGELOG.md"
private const val DonateUrl = "https://yoomoney.ru/to/410012216336438"
private const val OriginalDonateUrl = "https://yoomoney.ru/to/4100119505530465/"
private val DonateActionButtonColor = Color(0xFF00AEA5)

private val browserPackages = listOf(
    "com.android.chrome",
    "com.google.android.googlequicksearchbox",
    "org.mozilla.firefox",
    "com.yandex.browser",
    "ru.yandex.searchplugin",
    "com.yandex.browser.lite",
    "com.opera.browser",
    "com.opera.mini.native",
    "com.microsoft.emmx",
    "com.brave.browser",
    "com.duckduckgo.mobile.android",
    "com.sec.android.app.sbrowser",
    "com.vivaldi.browser",
    "com.kiwibrowser.browser",
)

private val Android16BlobShape: Shape = GenericShape { size, _ ->
    val centerX = size.width / 2f
    val centerY = size.height / 2f
    val outerRadius = min(size.width, size.height) / 2f
    val innerRadius = outerRadius * 0.92f
    val points = 14

    for (i in 0 until points * 2) {
        val angle = (-PI / 2.0) + (i * PI / points)
        val radius = if (i % 2 == 0) outerRadius else innerRadius
        val x = centerX + (radius * cos(angle)).toFloat()
        val y = centerY + (radius * sin(angle)).toFloat()
        if (i == 0) moveTo(x, y) else lineTo(x, y)
    }
    close()
}

private fun openUrlInBrowser(context: Context, url: String) {
    try {
        val pm = context.packageManager
        val uri = Uri.parse(url)
        for (pkg in browserPackages) {
            val intent = Intent(Intent.ACTION_VIEW, uri).apply {
                addCategory(Intent.CATEGORY_BROWSABLE)
                setPackage(pkg)
            }
            if (intent.resolveActivity(pm) != null) {
                context.startActivity(intent)
                return
            }
        }
        val intent = Intent(Intent.ACTION_VIEW, uri).apply { addCategory(Intent.CATEGORY_BROWSABLE) }
        if (intent.resolveActivity(pm) != null) context.startActivity(intent)
    } catch (_: Exception) {
    }
}

private fun openDeviceCheckAction(context: Context, action: DeviceCheckAction) {
    runCatching {
        val intent = deviceCheckActionIntent(context, action)
        if (intent.resolveActivity(context.packageManager) != null) {
            context.startActivity(intent)
        } else {
            context.startActivity(
                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                    data = Uri.parse("package:${context.packageName}")
                }
            )
        }
    }.onFailure {
        Toast.makeText(context, "Не удалось открыть настройки Android", Toast.LENGTH_SHORT).show()
    }
}

@Composable
fun InfoTab(
    actionsExpandedState: MutableState<Boolean> = rememberSaveable { mutableStateOf(true) },
    projectExpandedState: MutableState<Boolean> = rememberSaveable { mutableStateOf(true) },
    scrollPosition: MutableIntState = rememberSaveable { mutableIntStateOf(0) }
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val settingsStore = remember { SettingsStore(context) }
    val infoScrollState = rememberRememberedScrollState(scrollPosition)
    val topRevealOffsetPx = with(LocalDensity.current) { 10.dp.toPx() }
    var actionsSectionY by remember { mutableStateOf(0f) }
    var projectSectionY by remember { mutableStateOf(0f) }
    val currentVersion = remember { "v${BuildConfig.VERSION_NAME.removePrefix("v")}" }
    val releaseDate = remember { BuildConfig.MOD_RELEASE_DATE }
	var isCheckingUpdates by remember { mutableStateOf(false) }
	var pendingManualUpdateCandidate by remember { mutableStateOf<AppUpdateCandidate?>(null) }
    var updateDownloadProgress by remember { mutableStateOf<AppUpdateDownloadProgress?>(null) }
    var updateDownloadStatus by rememberSaveable { mutableStateOf("") }
    var updateDownloadBusy by remember { mutableStateOf(false) }
    var pendingUpdateApkPath by rememberSaveable { mutableStateOf<String?>(null) }
	var showHelpDialog by remember { mutableStateOf(false) }
	var showSupportDialog by remember { mutableStateOf(false) }
    var isCheckingDevice by remember { mutableStateOf(false) }
    var deviceCheckReport by remember { mutableStateOf<com.wdtt.plus.DeviceCompatibilityReport?>(null) }
	var actionsExpanded by actionsExpandedState
	var projectExpanded by projectExpandedState
    val updateLatestVersion by settingsStore.updateLatestVersion.collectAsStateWithLifecycle(initialValue = "")
    val updateLastError by settingsStore.updateLastError.collectAsStateWithLifecycle(initialValue = "")
    val updateStatus = remember(isCheckingUpdates, updateLatestVersion, updateLastError, currentVersion) {
        when {
            isCheckingUpdates -> "Проверяем GitHub releases..."
            updateLatestVersion.isNotBlank() && isNewerVersion(currentVersion, updateLatestVersion) ->
                "На GitHub доступна версия $updateLatestVersion"
            updateLatestVersion.isNotBlank() -> "Последняя версия: $updateLatestVersion"
            updateLastError.isNotBlank() -> "Последняя проверка завершилась ошибкой"
            else -> "Проверить GitHub вручную"
        }
    }
    val updateInstallPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) {
        val apkFile = pendingUpdateApkPath?.let(::File)
        if (apkFile != null && apkFile.exists() && canRequestApkInstall(context)) {
            runCatching {
                installUpdateApk(context, apkFile)
                pendingManualUpdateCandidate = null
                updateDownloadStatus = ""
                updateDownloadProgress = null
            }.onFailure { error ->
                updateDownloadStatus = error.message ?: "Не удалось открыть установку APK."
                Toast.makeText(context, updateDownloadStatus, Toast.LENGTH_LONG).show()
            }
        } else if (apkFile != null) {
            updateDownloadStatus = "Разрешение на установку из WDTT Plus не выдано."
            Toast.makeText(context, updateDownloadStatus, Toast.LENGTH_LONG).show()
        }
    }

    fun requestDownloadedUpdateInstall(apkFile: File) {
        pendingUpdateApkPath = apkFile.absolutePath
        if (!canRequestApkInstall(context)) {
            updateDownloadStatus = "Разрешите установку из WDTT Plus в настройках Android."
            updateInstallPermissionLauncher.launch(
                Intent(
                    Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                    Uri.parse("package:${context.packageName}")
                )
            )
            return
        }

        runCatching {
            installUpdateApk(context, apkFile)
            pendingManualUpdateCandidate = null
            updateDownloadStatus = ""
            updateDownloadProgress = null
        }.onFailure { error ->
            updateDownloadStatus = error.message ?: "Не удалось открыть установку APK."
            Toast.makeText(context, updateDownloadStatus, Toast.LENGTH_LONG).show()
        }
    }

    suspend fun buildDeviceCheckReportWithVersion(): com.wdtt.plus.DeviceCompatibilityReport {
        val latestCheckedAt = System.currentTimeMillis()
        val latestRelease = fetchLatestReleaseInfo(currentVersion)
        settingsStore.saveUpdateState(
            lastCheckAt = latestCheckedAt,
            latestVersion = latestRelease?.versionTag ?: "",
            error = if (latestRelease == null) "Не удалось проверить" else ""
        )
        val versionItem = DeviceCompatibility.appVersionItem(
            currentVersion = currentVersion,
            releaseDate = releaseDate,
            latestRelease = latestRelease
        )
        val workers = runCatching { settingsStore.workersPerHash.first() }.getOrNull()
        val diagnosticsSummary = withContext(Dispatchers.Default) {
            buildSupportReportSummary(context.applicationContext, settingsStore)
        }
        val report = withContext(Dispatchers.Default) {
            DeviceCompatibility.check(
                context = context.applicationContext,
                includeRuntimeChecks = true,
                workersPerHash = workers
            )
        }
        return report.copy(
            summaryLines = diagnosticsSummary,
            items = listOf(versionItem) +
                report.items.filterNot { it.title == DeviceCompatibility.APP_VERSION_ITEM_TITLE }
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .fillMaxWidth()
            .padding(start = 16.dp, end = 16.dp, top = 0.dp, bottom = 28.dp)
            .verticalScroll(infoScrollState),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "Информация",
                style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                color = MaterialTheme.colorScheme.onSurface
            )
        }

		InfoHeroCard(
			currentVersion = currentVersion,
            releaseDate = releaseDate,
			onSupportClick = { showSupportDialog = true }
		)

        ExpandableSectionCard(
            title = "Действия",
            itemCount = "4 пункта",
            expanded = actionsExpanded,
            modifier = Modifier.onGloballyPositioned { actionsSectionY = it.positionInParent().y },
            onToggle = {
                val willExpand = !actionsExpanded
                actionsExpanded = willExpand
                if (willExpand) {
                    scope.launch {
                        kotlinx.coroutines.delay(80)
                        infoScrollState.animateScrollTo((actionsSectionY - topRevealOffsetPx).toInt().coerceAtLeast(0))
                    }
                }
            },
            icon = {
                Icon(
                    imageVector = Icons.Default.Info,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(18.dp)
                )
            }
        ) {
            WideActionTile(
                title = "Поднять вопрос",
                subtitle = "Выбрать шаблон GitHub issue",
                onClick = { openUrlInBrowser(context, IssuesUrl) },
                icon = {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_github),
                        contentDescription = null,
                        modifier = Modifier.size(20.dp),
                        tint = MaterialTheme.colorScheme.onPrimaryContainer
                    )
                }
            )

            WideActionTile(
                title = "Проверить устройство",
                subtitle = if (isCheckingDevice) {
                    "Проверяем версию, Android, ABI, сеть и системные условия..."
                } else {
                    "Проверка совместимости и полный отчёт для диагностики"
                },
                onClick = {
                    if (isCheckingDevice) return@WideActionTile
                    isCheckingDevice = true
                    scope.launch {
                        runCatching {
                            buildDeviceCheckReportWithVersion()
                        }.onSuccess { report ->
                            deviceCheckReport = report
                        }.onFailure { error ->
                            Toast.makeText(
                                context,
                                error.message ?: "Не удалось проверить устройство",
                                Toast.LENGTH_LONG
                            ).show()
                        }
                        isCheckingDevice = false
                    }
                },
                icon = {
                    Icon(
                        imageVector = Icons.Default.Info,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp),
                        tint = MaterialTheme.colorScheme.onPrimaryContainer
                    )
                }
            )

            WideActionTile(
                title = "Справка",
                subtitle = "Коротко про VPN, исключения, капчу и запуск",
                onClick = { showHelpDialog = true },
                icon = {
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.HelpOutline,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp),
                        tint = MaterialTheme.colorScheme.onPrimaryContainer
                    )
                }
            )

            WideActionTile(
                title = "Проверить обновления",
                subtitle = updateStatus,
                onClick = {
                    if (isCheckingUpdates) return@WideActionTile
                    isCheckingUpdates = true
                    scope.launch {
                        val checkedAt = System.currentTimeMillis()
                        var release: AppReleaseInfo? = null
                        var updateCandidate: AppUpdateCandidate? = null
                        var errorMessage = ""
                        try {
                            runCatching {
                                release = fetchLatestReleaseInfo(currentVersion)
                                if (release == null) {
                                    errorMessage = "Не удалось проверить"
                                    return@runCatching
                                }
                                updateCandidate = resolveAppUpdateCandidate(context, currentVersion, release)
                            }.onFailure { error ->
                                errorMessage = error.message ?: "Не удалось проверить обновления"
                            }

                            settingsStore.saveUpdateState(
                                lastCheckAt = checkedAt,
                                latestVersion = release?.versionTag ?: "",
                                error = errorMessage
                            )

                            val currentRelease = release
                            if (currentRelease == null) {
                                val message = if (updateLatestVersion.isNotBlank()) {
                                    "Не удалось проверить. Последняя известная версия: $updateLatestVersion"
                                } else {
                                    "Не удалось проверить обновления"
                                }
                                Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
                                return@launch
                            }

                            val candidate = updateCandidate
                            if (candidate != null) {
                                settingsStore.saveUpdateDialogShown(candidate.postponeKey, checkedAt)
                                pendingManualUpdateCandidate = candidate
                            } else {
                                Toast.makeText(
                                    context,
                                    "У вас уже последняя версия: ${currentRelease.versionTag}",
                                    Toast.LENGTH_SHORT
                                ).show()
                            }
                        } finally {
                            isCheckingUpdates = false
                        }
                    }
                },
                icon = {
                    Icon(
                        imageVector = Icons.Default.Update,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp),
                        tint = MaterialTheme.colorScheme.onPrimaryContainer
                    )
                }
            )
        }

        pendingManualUpdateCandidate?.let { candidate ->
            val release = candidate.release
            val apkAsset = remember(release) { selectUpdateApkAsset(release) }
            AppUpdateDialog(
                release = release,
                updateKind = candidate.kind,
                apkAsset = apkAsset,
                isDownloading = updateDownloadBusy,
                downloadProgress = updateDownloadProgress,
                downloadStatus = updateDownloadStatus,
                onPostpone = {
                    pendingManualUpdateCandidate = null
                    updateDownloadStatus = ""
                    updateDownloadProgress = null
                    Toast.makeText(context, "Обновление отложено на 24 часа.", Toast.LENGTH_SHORT).show()
                    scope.launch {
                        val now = System.currentTimeMillis()
                        settingsStore.saveUpdatePostpone(
                            version = candidate.postponeKey,
                            until = now + 24L * 60L * 60L * 1000L
                        )
                        settingsStore.saveUpdateDialogAction(
                            version = candidate.postponeKey,
                            action = UPDATE_DIALOG_ACTION_POSTPONED,
                            actedAt = now
                        )
                    }
                },
                onUpdate = {
                    scope.launch {
                        settingsStore.saveUpdateDialogAction(
                            version = candidate.postponeKey,
                            action = UPDATE_DIALOG_ACTION_UPDATE,
                            actedAt = System.currentTimeMillis()
                        )
                        if (apkAsset == null) {
                            pendingManualUpdateCandidate = null
                            openUrlInBrowser(context, release.releaseUrl)
                            return@launch
                        }

                        updateDownloadBusy = true
                        updateDownloadStatus = "Подготовка скачивания..."
                        updateDownloadProgress = null
                        runCatching {
                            val apkFile = downloadUpdateApk(context, apkAsset) { progress ->
                                updateDownloadProgress = progress
                                updateDownloadStatus = if (progress.percent != null) {
                                    "Скачивание APK"
                                } else {
                                    "Скачивание APK..."
                                }
                            }
                            updateDownloadStatus = if (apkAsset.sha256 != null) {
                                "APK скачан и проверен. Открываю установку..."
                            } else {
                                "APK скачан. Открываю установку..."
                            }
                            requestDownloadedUpdateInstall(apkFile)
                        }.onFailure { error ->
                            updateDownloadStatus = error.message ?: "Не удалось скачать обновление."
                            Toast.makeText(context, updateDownloadStatus, Toast.LENGTH_LONG).show()
                        }
                        updateDownloadBusy = false
                    }
                },
                onOpenRelease = {
                    pendingManualUpdateCandidate = null
                    updateDownloadStatus = ""
                    updateDownloadProgress = null
                    openUrlInBrowser(context, release.releaseUrl)
                }
            )
        }

        ExpandableSectionCard(
            title = "О проекте",
            itemCount = "4 ссылки",
            expanded = projectExpanded,
            modifier = Modifier.onGloballyPositioned { projectSectionY = it.positionInParent().y },
            onToggle = {
                val willExpand = !projectExpanded
                projectExpanded = willExpand
                if (willExpand) {
                    scope.launch {
                        kotlinx.coroutines.delay(80)
                        infoScrollState.animateScrollTo((projectSectionY - topRevealOffsetPx).toInt().coerceAtLeast(0))
                    }
                }
            },
            icon = {
                Icon(
                    imageVector = Icons.Default.Code,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(18.dp)
                )
            }
        ) {
			ProjectLinkRow(
				title = "Разработка модификации",
				subtitle = "GitHub профиль Ivan4537",
				onClick = { openUrlInBrowser(context, DeveloperProfileUrl) },
				icon = {
					Icon(
						imageVector = Icons.Default.Person,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp)
                    )
                }
			)

			ProjectLinkRow(
				title = "Репозиторий WDTT Plus",
				subtitle = "Исходники и релизы приложения",
				onClick = { openUrlInBrowser(context, RepositoryUrl) },
				icon = {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_github),
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp)
                    )
                }
            )

            ProjectLinkRow(
                title = "Актуальные релизы",
                subtitle = "Страница загрузки APK",
                onClick = { openUrlInBrowser(context, ReleasesUrl) },
                icon = {
                    Icon(
                        imageVector = Icons.Default.Update,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp)
                    )
                }
            )

            ProjectLinkRow(
                title = "История изменений",
                subtitle = "Что менялось в версиях WDTT Plus",
                onClick = { openUrlInBrowser(context, ChangelogUrl) },
                icon = {
                    Icon(
                        imageVector = Icons.Default.Update,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp)
                    )
                }
            )
        }

        Spacer(modifier = Modifier.height(20.dp))
	}

	if (showHelpDialog) ImportantInfoDialog(onDismiss = { showHelpDialog = false })
    deviceCheckReport?.let { report ->
        DeviceCompatibilityDialog(
            report = report,
            title = "Проверка устройства",
            subtitle = "Расширенная проверка не запускает VPN, но показывает совместимость устройства, настройки Android и статус подключения.",
            note = "Кнопка «Скопировать отчёт» добавит в буфер версию приложения, Android, ABI, память, сеть, WebView, native-клиент и текущие настройки без секретных значений.",
            onDismiss = { deviceCheckReport = null },
            onCopy = {
                scope.launch {
                    val freshReport = runCatching {
                        buildDeviceCheckReportWithVersion()
                    }.getOrElse {
                        report
                    }
                    deviceCheckReport = freshReport
                    val clipboard = context.getSystemService(ClipboardManager::class.java)
                    clipboard?.setPrimaryClip(ClipData.newPlainText("WDTT Device Check", freshReport.toPlainText()))
                    Toast.makeText(context, "Отчёт проверки скопирован", Toast.LENGTH_SHORT).show()
                }
            },
            onAction = { action -> openDeviceCheckAction(context, action) }
        )
    }
	if (showSupportDialog) {
		SupportProjectDialog(
			onDismiss = { showSupportDialog = false },
			onDonateModClick = { openUrlInBrowser(context, DonateUrl) },
			onDonateOriginalClick = { openUrlInBrowser(context, OriginalDonateUrl) }
		)
	}
}

@Composable
private fun SupportProjectDialog(
	onDismiss: () -> Unit,
	onDonateModClick: () -> Unit,
	onDonateOriginalClick: () -> Unit
) {
	Dialog(
		onDismissRequest = onDismiss,
		properties = DialogProperties(usePlatformDefaultWidth = false)
	) {
		BoxWithConstraints(
			modifier = Modifier.fillMaxSize().padding(8.dp),
			contentAlignment = Alignment.Center
		) {
			Surface(
				shape = RoundedCornerShape(28.dp),
				color = MaterialTheme.colorScheme.surface,
				tonalElevation = 8.dp,
				shadowElevation = 18.dp,
				modifier = Modifier
					.fillMaxWidth()
					.padding(horizontal = 12.dp)
					.heightIn(max = maxHeight * 0.92f)
			) {
				Column(
					modifier = Modifier
						.fillMaxWidth()
						.padding(20.dp)
						.verticalScroll(rememberScrollState()),
					verticalArrangement = Arrangement.spacedBy(16.dp)
				) {
					Row(
						modifier = Modifier.fillMaxWidth(),
						horizontalArrangement = Arrangement.spacedBy(12.dp),
						verticalAlignment = Alignment.CenterVertically
					) {
						Surface(
							shape = RoundedCornerShape(18.dp),
							color = MaterialTheme.colorScheme.primaryContainer
						) {
							Box(modifier = Modifier.size(42.dp), contentAlignment = Alignment.Center) {
								Icon(
									imageVector = Icons.Default.Favorite,
									contentDescription = null,
									tint = MaterialTheme.colorScheme.primary,
									modifier = Modifier.size(20.dp)
								)
							}
						}
						Column(modifier = Modifier.weight(1f)) {
							Text(
								"Поддержать проект",
								style = MaterialTheme.typography.titleMedium,
								fontWeight = FontWeight.Bold,
								color = MaterialTheme.colorScheme.onSurface
							)
						}
						FilledTonalIconButton(onClick = onDismiss) {
							Icon(Icons.Default.Close, contentDescription = null)
						}
					}

					SupportDonateBlock(
						title = "WDTT Plus",
						body = "Поддержка этой версии помогает развивать доработки приложения, серверной части, Telegram-бота и удобство для пользователей.",
						buttonText = "ЮMoney",
						onClick = onDonateModClick,
						emphasized = true
					)

					SupportDonateBlock(
						title = "Автор оригинального приложения",
						body = "Оригинальная основа проекта создана amurcanov. Можно отдельно поддержать автора исходного приложения.",
						buttonText = "ЮMoney",
						onClick = onDonateOriginalClick,
						emphasized = false
					)
					Spacer(Modifier.height(4.dp))
				}
			}
		}
	}
}

@Composable
private fun SupportDonateBlock(
	title: String,
	body: String,
	buttonText: String,
	onClick: () -> Unit,
	emphasized: Boolean
) {
	val containerColor = if (emphasized) {
		DonateActionButtonColor.copy(alpha = 0.12f)
	} else {
		MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f)
	}
	val borderColor = if (emphasized) {
		DonateActionButtonColor.copy(alpha = 0.38f)
	} else {
		MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.45f)
	}

	Surface(
		shape = RoundedCornerShape(22.dp),
		color = containerColor,
		border = BorderStroke(1.dp, borderColor)
	) {
		Column(
			modifier = Modifier
				.fillMaxWidth()
				.padding(16.dp),
			verticalArrangement = Arrangement.spacedBy(12.dp)
		) {
			Text(
				title,
				style = MaterialTheme.typography.titleSmall,
				fontWeight = FontWeight.Bold,
				color = MaterialTheme.colorScheme.onSurface
			)
			Text(
				body,
				style = MaterialTheme.typography.bodySmall,
				color = MaterialTheme.colorScheme.onSurfaceVariant,
				lineHeight = 18.sp
			)
			Button(
				onClick = onClick,
				shape = RoundedCornerShape(18.dp),
				colors = ButtonDefaults.buttonColors(
					containerColor = if (emphasized) DonateActionButtonColor else MaterialTheme.colorScheme.primary,
					contentColor = Color.White
				),
				modifier = Modifier
					.fillMaxWidth()
					.heightIn(min = 46.dp)
			) {
				Text(buttonText, fontWeight = FontWeight.Bold)
			}
		}
	}
}

@Composable
private fun InfoHeroCard(
    currentVersion: String,
    releaseDate: String,
    onSupportClick: () -> Unit
) {
    val colors = MaterialTheme.colorScheme
    val isDark = colors.background.luminance() < 0.22f
    val heroBrush = remember(colors.primaryContainer, colors.secondaryContainer, colors.surfaceVariant) {
        Brush.linearGradient(
            listOf(
                colors.primaryContainer,
                colors.secondaryContainer,
                colors.surfaceVariant
            )
        )
    }
    val glassColor = if (isDark) colors.surface.copy(alpha = 0.46f) else Color.White.copy(alpha = 0.54f)
    val glassBorder = colors.outlineVariant.copy(alpha = if (isDark) 0.50f else 0.32f)

    Surface(
        shape = RoundedCornerShape(32.dp),
        color = Color.Transparent,
        contentColor = MaterialTheme.colorScheme.onSurface,
        shadowElevation = 10.dp,
        tonalElevation = 0.dp
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(32.dp))
                .background(heroBrush)
                .padding(22.dp)
        ) {
            Box(
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .offset(x = 30.dp, y = (-34).dp)
                    .size(138.dp)
                    .clip(Android16BlobShape)
                    .background(colors.primary.copy(alpha = 0.10f))
            )
            Box(
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .offset(x = 26.dp, y = 30.dp)
                    .size(112.dp)
                    .clip(Android16BlobShape)
                    .background(colors.secondary.copy(alpha = 0.12f))
            )

            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(18.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    HeroMetaPill(
                        text = "WDTT Plus",
                        containerColor = glassColor,
                        borderColor = glassBorder,
                        modifier = Modifier.weight(1f)
                    )
                    HeroVersionPill(
                        version = currentVersion,
                        releaseDate = releaseDate,
                        containerColor = colors.primary.copy(alpha = if (isDark) 0.18f else 0.10f),
                        borderColor = colors.primary.copy(alpha = if (isDark) 0.22f else 0.14f),
                        modifier = Modifier.weight(1f)
                    )
                }

                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = "WDTT Plus",
                        style = MaterialTheme.typography.headlineSmall.copy(
                            fontWeight = FontWeight.Black,
                            fontSize = 30.sp,
                            lineHeight = 34.sp
                        ),
                        color = colors.onSurface
                    )
				Text(
					text = "Android-клиент для TURN/VK туннеля с WireGuard, капчей, управлением сервером и удобными сценариями подключения.",
					style = MaterialTheme.typography.bodyMedium,
					color = colors.onSurfaceVariant,
					lineHeight = 21.sp
				)
			}

			Button(
				onClick = onSupportClick,
				shape = RoundedCornerShape(22.dp),
				colors = ButtonDefaults.buttonColors(
					containerColor = DonateActionButtonColor,
					contentColor = Color.White
				),
				modifier = Modifier
					.fillMaxWidth()
					.heightIn(min = 54.dp)
			) {
				Icon(Icons.Default.Favorite, contentDescription = null, modifier = Modifier.size(18.dp))
				Spacer(modifier = Modifier.width(8.dp))
				Text("Поддержать проект", fontWeight = FontWeight.Bold, fontSize = 15.sp)
			}
		}
	}
}
}

@Composable
private fun HeroMetaPill(
    text: String,
    containerColor: Color,
    borderColor: Color,
    modifier: Modifier = Modifier
) {
    Surface(
        shape = RoundedCornerShape(18.dp),
        color = containerColor,
        border = BorderStroke(1.dp, borderColor),
        modifier = modifier.height(52.dp)
    ) {
        Box(contentAlignment = Alignment.Center, modifier = Modifier.fillMaxSize()) {
            Text(
                text = text,
                modifier = Modifier.padding(horizontal = 12.dp),
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface,
                textAlign = TextAlign.Center
            )
        }
    }
}

@Composable
private fun HeroVersionPill(
    version: String,
    releaseDate: String,
    containerColor: Color,
    borderColor: Color,
    modifier: Modifier = Modifier
) {
    Surface(
        shape = RoundedCornerShape(18.dp),
        color = containerColor,
        border = BorderStroke(1.dp, borderColor),
        modifier = modifier.height(52.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 12.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = "Версия ${version.removePrefix("v")}",
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface,
                textAlign = TextAlign.Center
            )
            Text(
                text = "от $releaseDate",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )
        }
    }
}

@Composable
private fun ExpandableSectionCard(
    title: String,
    itemCount: String,
    expanded: Boolean,
    modifier: Modifier = Modifier,
    onToggle: () -> Unit,
    icon: @Composable () -> Unit,
    content: @Composable ColumnScope.() -> Unit
) {
    val arrowRotation by animateFloatAsState(
        targetValue = if (expanded) 180f else 0f,
        label = "section_arrow_rotation"
    )

    AppSectionCard(
        modifier = modifier,
        contentPadding = PaddingValues(horizontal = 18.dp, vertical = 18.dp),
        verticalArrangement = Arrangement.spacedBy(0.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(24.dp))
                .clickable(onClick = onToggle)
                .padding(vertical = 2.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Surface(shape = RoundedCornerShape(18.dp), color = MaterialTheme.colorScheme.primaryContainer) {
                Box(modifier = Modifier.size(40.dp), contentAlignment = Alignment.Center) { icon() }
            }

            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.Center) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }

            MetaChip(text = itemCount)

            Icon(
                imageVector = Icons.Default.KeyboardArrowDown,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier
                    .size(24.dp)
                    .rotate(arrowRotation)
            )
        }

        AnimatedVisibility(
            visible = expanded,
            enter = expandVertically() + fadeIn(),
            exit = shrinkVertically() + fadeOut()
        ) {
            Column(
                modifier = Modifier.padding(top = 12.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.30f))
                content()
            }
        }
    }
}

@Composable
private fun MetaChip(text: String) {
    Surface(
        shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surface.copy(alpha = 0.88f),
        contentColor = MaterialTheme.colorScheme.onSurface
    ) {
        Text(
            text = text,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 7.dp),
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun InfoActionTile(
    title: String,
    subtitle: String,
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
    icon: @Composable () -> Unit
) {
    Surface(
        shape = RoundedCornerShape(24.dp),
        color = MaterialTheme.colorScheme.surface.copy(alpha = 0.70f),
        contentColor = MaterialTheme.colorScheme.onSurface,
        modifier = modifier
            .clip(RoundedCornerShape(24.dp))
            .clickable(onClick = onClick)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 116.dp)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Surface(shape = RoundedCornerShape(16.dp), color = MaterialTheme.colorScheme.primaryContainer) {
                Box(modifier = Modifier.size(40.dp), contentAlignment = Alignment.Center) { icon() }
            }

            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    lineHeight = 18.sp
                )
            }
        }
    }
}

@Composable
private fun WideActionTile(
    title: String,
    subtitle: String,
    onClick: () -> Unit,
    icon: @Composable () -> Unit
) {
    Surface(
        shape = RoundedCornerShape(24.dp),
        color = MaterialTheme.colorScheme.surface.copy(alpha = 0.70f),
        contentColor = MaterialTheme.colorScheme.onSurface,
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(24.dp))
            .clickable(onClick = onClick)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 15.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Surface(shape = RoundedCornerShape(16.dp), color = MaterialTheme.colorScheme.primaryContainer) {
                Box(modifier = Modifier.size(40.dp), contentAlignment = Alignment.Center) { icon() }
            }

            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text(
                    title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    lineHeight = 18.sp
                )
            }

            Icon(
                imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(18.dp)
            )
        }
    }
}

@Composable
private fun ProjectLinkRow(
    title: String,
    subtitle: String,
    onClick: () -> Unit,
    icon: @Composable () -> Unit
) {
    Surface(
        shape = RoundedCornerShape(24.dp),
        color = MaterialTheme.colorScheme.surface.copy(alpha = 0.64f),
        contentColor = MaterialTheme.colorScheme.onSurface,
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(24.dp))
            .clickable(onClick = onClick)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 14.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Surface(shape = RoundedCornerShape(16.dp), color = MaterialTheme.colorScheme.primaryContainer) {
                Box(
                    modifier = Modifier.defaultMinSize(minWidth = 40.dp, minHeight = 40.dp),
                    contentAlignment = Alignment.Center
                ) {
                    icon()
                }
            }

            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    lineHeight = 18.sp
                )
            }

            Icon(
                imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(18.dp)
            )
        }
    }
}

private fun diagnosticText(block: () -> Any?): String =
    runCatching { block()?.toString()?.takeIf(String::isNotBlank) ?: "недоступно" }
        .getOrDefault("недоступно")

private fun formatMiB(bytes: Long): String = "${bytes.coerceAtLeast(0L) / (1024L * 1024L)} МБ"

private suspend fun buildSupportReportSummary(context: Context, settingsStore: SettingsStore): List<String> {
    val androidVersion = Build.VERSION.RELEASE ?: "?"
    val sdkInt = Build.VERSION.SDK_INT
    val primaryAbi = Build.SUPPORTED_ABIS.firstOrNull().orEmpty().ifBlank { "unknown" }
    val supportedAbis = Build.SUPPORTED_ABIS.joinToString().ifBlank { "unknown" }
    val manufacturer = Build.MANUFACTURER.orEmpty().ifBlank { "unknown" }
    val brand = Build.BRAND.orEmpty().ifBlank { "unknown" }
    val model = Build.MODEL.orEmpty().ifBlank { "unknown" }
    val device = Build.DEVICE.orEmpty().ifBlank { "unknown" }
    val product = Build.PRODUCT.orEmpty().ifBlank { "unknown" }
    val hardware = Build.HARDWARE.orEmpty().ifBlank { "unknown" }
    val board = Build.BOARD.orEmpty().ifBlank { "unknown" }
    val romDisplay = Build.DISPLAY.orEmpty().ifBlank { "unknown" }
    val buildId = Build.ID.orEmpty().ifBlank { "unknown" }
    val buildFingerprint = Build.FINGERPRINT.orEmpty().ifBlank { "unknown" }
    val buildType = Build.TYPE.orEmpty().ifBlank { "unknown" }
    val socManufacturer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        Build.SOC_MANUFACTURER.orEmpty().ifBlank { "unknown" }
    } else {
        "n/a"
    }
    val socModel = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        Build.SOC_MODEL.orEmpty().ifBlank { "unknown" }
    } else {
        "n/a"
    }

    val appInfo = runCatching { context.applicationInfo }.getOrNull()
    val packageInfo = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong())
            )
        } else {
            @Suppress("DEPRECATION")
            context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.GET_SIGNING_CERTIFICATES
            )
        }
    }.getOrNull()
    val signingCertificate = diagnosticText {
        val certificate = packageInfo?.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()
            ?: return@diagnosticText null
        MessageDigest.getInstance("SHA-256")
            .digest(certificate)
            .joinToString("") { "%02x".format(it) }
    }
    val installSource = diagnosticText {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            context.packageManager.getInstallSourceInfo(context.packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            context.packageManager.getInstallerPackageName(context.packageName)
        } ?: "ручная установка"
    }
    val dateFormat = SimpleDateFormat("dd.MM.yyyy HH:mm:ss", Locale.ROOT)
    val firstInstallTime = diagnosticText { packageInfo?.firstInstallTime?.let { dateFormat.format(Date(it)) } }
    val lastUpdateTime = diagnosticText { packageInfo?.lastUpdateTime?.let { dateFormat.format(Date(it)) } }
    val processBits = diagnosticText { if (android.os.Process.is64Bit()) "64-bit" else "32-bit" }
    val pageSize = diagnosticText { "${Os.sysconf(OsConstants._SC_PAGESIZE)} байт" }
    val securityPatch = Build.VERSION.SECURITY_PATCH.orEmpty().ifBlank { "unknown" }
    val kernel = diagnosticText { System.getProperty("os.version") }

    val activityManager = runCatching {
        context.getSystemService(ActivityManager::class.java)
    }.getOrNull()
    val memoryInfo = runCatching {
        ActivityManager.MemoryInfo().also { activityManager?.getMemoryInfo(it) }
    }.getOrNull()
    val memorySummary = if (memoryInfo != null && memoryInfo.totalMem > 0L) {
        "всего ${formatMiB(memoryInfo.totalMem)}, доступно ${formatMiB(memoryInfo.availMem)}, " +
            "lowMemory=${memoryInfo.lowMemory}"
    } else {
        "недоступно"
    }
    val memoryClass = diagnosticText {
        "обычный ${activityManager?.memoryClass} МБ, большой ${activityManager?.largeMemoryClass} МБ"
    }
    val lowRamDevice = diagnosticText { activityManager?.isLowRamDevice }

    val storageSummary = runCatching {
        val stat = StatFs(context.filesDir.absolutePath)
        "свободно ${formatMiB(stat.availableBytes)}, всего ${formatMiB(stat.totalBytes)}"
    }.getOrDefault("недоступно")

    val powerManager = runCatching { context.getSystemService(PowerManager::class.java) }.getOrNull()
    val powerSummary = diagnosticText {
        "экономия=${powerManager?.isPowerSaveMode}, " +
            "без ограничений батареи=${powerManager?.isIgnoringBatteryOptimizations(context.packageName)}"
    }

    val connectivityManager = runCatching {
        context.getSystemService(ConnectivityManager::class.java)
    }.getOrNull()
    val activeNetwork = runCatching { connectivityManager?.activeNetwork }.getOrNull()
    val networkCapabilities = runCatching {
        activeNetwork?.let { connectivityManager?.getNetworkCapabilities(it) }
    }.getOrNull()
    val networkTransports = buildList {
        if (networkCapabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true) add("Wi-Fi")
        if (networkCapabilities?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true) add("мобильная")
        if (networkCapabilities?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true) add("Ethernet")
        if (networkCapabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) add("VPN")
    }.joinToString().ifBlank { "не определён" }
    val networkSummary = if (networkCapabilities != null) {
        "$networkTransports, internet=${networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)}, " +
            "validated=${networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)}, " +
            "metered=${connectivityManager?.isActiveNetworkMetered}"
    } else {
        "недоступно"
    }
    val privateDns = diagnosticText {
        val properties = activeNetwork?.let { connectivityManager?.getLinkProperties(it) }
        properties?.isPrivateDnsActive
    }

    val webViewInfo = diagnosticText {
        WebView.getCurrentWebViewPackage()?.let { "${it.packageName} ${it.versionName}" }
    }
    val nativeClientInfo = runCatching {
        val nativeClient = File(appInfo?.nativeLibraryDir.orEmpty(), "libclient.so")
        if (nativeClient.isFile) {
            "найден, ${formatMiB(nativeClient.length())}, executable=${nativeClient.canExecute()}"
        } else {
            "не найден"
        }
    }.getOrDefault("недоступно")

    val notificationPermission = diagnosticText {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            "не требуется до Android 13"
        } else {
            context.checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) ==
                PackageManager.PERMISSION_GRANTED
        }
    }
    val updateInstallPermission = diagnosticText {
        context.packageManager.canRequestPackageInstalls()
    }
    val vpnPermission = diagnosticText { VpnService.prepare(context) == null }
    val displayMetrics = context.resources.displayMetrics
    val screenSummary = diagnosticText {
        "${displayMetrics.widthPixels}×${displayMetrics.heightPixels}, " +
            "density=${displayMetrics.densityDpi} dpi, fontScale=${context.resources.configuration.fontScale}"
    }

    val activeProfile = runCatching { settingsStore.activeProfile.first() + 1 }.getOrNull()
    val workers = runCatching { settingsStore.workersPerHash.first() }.getOrNull()
    val vkHashes = runCatching { settingsStore.vkHashes.first() }.getOrDefault("")
    val hashCount = vkHashes
        .split(Regex("[,\\s\\n]+"))
        .count { it.isNotBlank() }
        .coerceAtMost(4)
    val hasSecondaryHash = runCatching { settingsStore.secondaryVkHash.first().isNotBlank() }.getOrNull()
    val vkCallsEnabled = runCatching { settingsStore.vkCallsPreflight.first() }.getOrNull()
    val captchaMode = runCatching { settingsStore.captchaMode.first() }.getOrNull()
    val fingerprint = runCatching { settingsStore.selectedFingerprint.first() }.getOrNull()
    val linkMode = runCatching { settingsStore.wdttLinkMode.first() }.getOrNull()
    val interfaceRole = runCatching { settingsStore.interfaceRole.first() }.getOrNull()
    val themeMode = runCatching { settingsStore.themeMode.first() }.getOrNull()
    val dynamicColor = runCatching { settingsStore.isDynamicColor.first() }.getOrNull()
    val loggingEnabled = runCatching { settingsStore.loggingEnabled.first() }.getOrNull()
    val trustedWifiEnabled = runCatching { settingsStore.trustedWifiEnabled.first() }.getOrNull()
    val trustedWifiCount = runCatching { settingsStore.trustedWifiSsids.first().size }.getOrNull()
    val trustedWifiAccess = if (trustedWifiEnabled == true) {
        when (trustedWifiAccessProblem(context)) {
            com.wdtt.plus.TrustedWifiAccessProblem.ForegroundPermission -> "нет доступа к имени Wi-Fi"
            com.wdtt.plus.TrustedWifiAccessProblem.BackgroundPermission -> "нет фонового доступа"
            com.wdtt.plus.TrustedWifiAccessProblem.LocationDisabled -> "определение местоположения выключено"
            null -> "доступ выдан"
        }
    } else {
        "не требуется"
    }
    val tunnelIssue = TunnelManager.connectionIssue.value?.title.orEmpty().ifBlank { "нет" }

    return buildString {
        appendLine("Версия приложения: ${BuildConfig.VERSION_NAME}")
        appendLine("Дата релиза: ${BuildConfig.MOD_RELEASE_DATE}")
        appendLine("Версия пакета: code ${packageInfo?.longVersionCode ?: "?"}")
        appendLine("Источник установки: $installSource")
        appendLine("Первая установка: $firstInstallTime")
        appendLine("Последнее обновление: $lastUpdateTime")
        appendLine("SHA-256 сертификата: $signingCertificate")
        appendLine("Android: $androidVersion (SDK $sdkInt, patch $securityPatch)")
        appendLine("SDK приложения: min ${appInfo?.minSdkVersion ?: "?"}, target ${appInfo?.targetSdkVersion ?: "?"}")
        appendLine("Устройство: $manufacturer / $brand / $model")
        appendLine("Код устройства: $device")
        appendLine("Продукт: $product")
        appendLine("ABI: $primaryAbi")
        appendLine("Все ABI: $supportedAbis")
        appendLine("Процесс: $processBits")
        appendLine("Страница памяти: $pageSize")
        appendLine("SoC: $socManufacturer / $socModel")
        appendLine("Hardware: $hardware")
        appendLine("Board: $board")
        appendLine("ROM: $romDisplay")
        appendLine("Build ID: $buildId")
        appendLine("Build type: $buildType")
        appendLine("Fingerprint: $buildFingerprint")
        appendLine("Kernel: $kernel")
        appendLine("RAM: $memorySummary")
        appendLine("Memory class: $memoryClass")
        appendLine("Low-RAM устройство: $lowRamDevice")
        appendLine("Хранилище приложения: $storageSummary")
        appendLine("Питание: $powerSummary")
        appendLine("Сеть: $networkSummary")
        appendLine("Private DNS: $privateDns")
        appendLine("WebView: $webViewInfo")
        appendLine("Нативный клиент: $nativeClientInfo")
        appendLine("Экран: $screenSummary")
        appendLine("Разрешение уведомлений: $notificationPermission")
        appendLine("Установка обновлений APK: $updateInstallPermission")
        appendLine("VPN-разрешение: $vpnPermission")
        appendLine(
            "Доверенные Wi-Fi: включено=${trustedWifiEnabled ?: "недоступно"}, " +
                "сетей=${trustedWifiCount ?: "недоступно"}, ожидание=${TrustedWifiManager.state.value.waiting}, доступ=$trustedWifiAccess"
        )
        appendLine("Локаль: ${diagnosticText { Locale.getDefault().toLanguageTag() }}")
        appendLine("Часовой пояс: ${diagnosticText { TimeZone.getDefault().id }}")
        appendLine("Туннель: запущен=${TunnelManager.running.value}, активных=${TunnelManager.activeWorkers.value}")
        appendLine("Последняя проблема: $tunnelIssue")
        appendLine("Профиль: ${activeProfile ?: "недоступно"}")
        appendLine("Потоки: ${workers ?: "недоступно"}")
        appendLine("VK-хеши: заполнено $hashCount, запасной=${hasSecondaryHash ?: "недоступно"}")
        appendLine("VKCalls: ${vkCallsEnabled ?: "недоступно"}")
        appendLine("Captcha mode: ${captchaMode ?: "недоступно"}")
        appendLine("TLS fingerprint: ${fingerprint ?: "недоступно"}")
        appendLine("Режим ссылки: ${linkMode ?: "недоступно"}")
        appendLine("Роль интерфейса: ${interfaceRole?.ifBlank { "не выбрана" } ?: "недоступно"}")
        appendLine("Тема: ${themeMode ?: "недоступно"}, Dynamic Colors=${dynamicColor ?: "недоступно"}")
        appendLine("Логирование: ${loggingEnabled ?: "недоступно"}")
    }.trim().lines()
}
