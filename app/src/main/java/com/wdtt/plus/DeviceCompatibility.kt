package com.wdtt.plus

import android.Manifest
import android.app.ActivityManager
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
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

enum class DeviceCheckSeverity {
    Ok,
    Info,
    Warning,
    Error
}

enum class DeviceCheckAction {
    AppSettings,
    BatterySettings,
    NetworkSettings,
    VpnSettings,
    UnknownAppInstallSettings,
    WebViewSettings
}

data class DeviceCheckItem(
    val title: String,
    val status: String,
    val details: String,
    val recommendation: String = "",
    val severity: DeviceCheckSeverity = DeviceCheckSeverity.Ok,
    val firstLaunchRelevant: Boolean = false,
    val action: DeviceCheckAction? = null
)

data class DeviceCompatibilityReport(
    val checkedAt: Long,
    val items: List<DeviceCheckItem>,
    val summaryLines: List<String> = emptyList()
) {
    val problemItems: List<DeviceCheckItem>
        get() = items.filter { it.severity == DeviceCheckSeverity.Warning || it.severity == DeviceCheckSeverity.Error }

    val firstLaunchProblemItems: List<DeviceCheckItem>
        get() = items.filter {
            it.firstLaunchRelevant &&
                (it.severity == DeviceCheckSeverity.Warning || it.severity == DeviceCheckSeverity.Error)
        }

    val hasErrors: Boolean
        get() = items.any { it.severity == DeviceCheckSeverity.Error }

    val overallStatus: String
        get() = when {
            items.any { it.severity == DeviceCheckSeverity.Error } -> "есть критичные несовместимости"
            items.any { it.severity == DeviceCheckSeverity.Warning } -> "есть предупреждения"
            else -> "подходит"
        }

    fun firstLaunchReport(): DeviceCompatibilityReport =
        copy(items = firstLaunchProblemItems)

    fun toPlainText(): String {
        val formatter = SimpleDateFormat("dd.MM.yyyy HH:mm:ss", Locale.ROOT)
        return buildString {
            appendLine("Проверка устройства WDTT Plus")
            appendLine("Проверено: ${formatter.format(Date(checkedAt))}")
            appendLine("Итог: $overallStatus")
            if (summaryLines.isNotEmpty()) {
                appendLine()
                appendLine("Сводка")
                summaryLines.forEach { line -> appendLine(line) }
            }
            items.forEach { item ->
                appendLine()
                appendLine("[${item.severity.label()}] ${item.title}: ${item.status}")
                appendLine(item.details)
                if (item.recommendation.isNotBlank()) {
                    appendLine("Рекомендация: ${item.recommendation}")
                }
            }
        }.trim()
    }
}

object DeviceCompatibility {
    const val APP_VERSION_ITEM_TITLE = "Версия WDTT Plus"
    private const val MIN_RECOMMENDED_SDK = 29
    private const val LOW_STORAGE_WARNING_BYTES = 200L * 1024L * 1024L
    private val supportedNativeAbis = setOf("arm64-v8a", "armeabi-v7a", "x86_64")

    fun check(
        context: Context,
        includeRuntimeChecks: Boolean,
        workersPerHash: Int? = null
    ): DeviceCompatibilityReport {
        val appContext = context.applicationContext
        val items = buildList {
            add(androidVersionItem())
            add(abiItem())
            add(nativeClientItem(appContext))
            nativeRuntimeSafetyItem()?.let(::add)
            add(pageSizeItem())
            add(memoryClassItem(appContext, workersPerHash))
            add(webViewItem(includeRuntimeChecks))
            add(storageItem(appContext))

            if (includeRuntimeChecks) {
                add(networkItem(appContext))
                add(vpnPermissionItem(appContext))
                add(tunnelStateItem())
                add(notificationPermissionItem(appContext))
                add(batteryItem(appContext))
                add(updateInstallPermissionItem(appContext))
            }
        }
        return DeviceCompatibilityReport(
            checkedAt = System.currentTimeMillis(),
            items = items
        )
    }

    fun appVersionItem(
        currentVersion: String,
        releaseDate: String,
        latestRelease: AppReleaseInfo?
    ): DeviceCheckItem {
        val normalizedCurrent = currentVersion.ifBlank { "v${BuildConfig.VERSION_NAME}" }
        val currentWithDate = "$normalizedCurrent от $releaseDate"
        return when {
            latestRelease == null -> DeviceCheckItem(
                title = APP_VERSION_ITEM_TITLE,
                status = "$currentWithDate · актуальность не проверена",
                details = "Не удалось получить последнюю версию WDTT Plus с GitHub на момент проверки.",
                recommendation = "Проверьте интернет или нажмите «Проверить обновления» позже.",
                severity = DeviceCheckSeverity.Warning
            )
            isNewerVersion(normalizedCurrent, latestRelease.versionTag) -> DeviceCheckItem(
                title = APP_VERSION_ITEM_TITLE,
                status = "$currentWithDate · доступна ${latestRelease.versionTag}",
                details = "На GitHub уже есть более новая версия WDTT Plus. Часть исправлений может отсутствовать на этом телефоне.",
                recommendation = "Обновите приложение до ${latestRelease.versionTag}.",
                severity = DeviceCheckSeverity.Warning
            )
            else -> DeviceCheckItem(
                title = APP_VERSION_ITEM_TITLE,
                status = "$currentWithDate · актуальная",
                details = "На момент проверки последняя найденная версия: ${latestRelease.versionTag}.",
                severity = DeviceCheckSeverity.Ok
            )
        }
    }

    private fun androidVersionItem(): DeviceCheckItem {
        val version = Build.VERSION.RELEASE ?: "?"
        val sdk = Build.VERSION.SDK_INT
        return if (sdk < MIN_RECOMMENDED_SDK) {
            DeviceCheckItem(
                title = "Версия Android",
                status = "Android $version / SDK $sdk",
                details = "WDTT Plus ориентируется на Android 10+ / SDK 29+. На этой версии работа нативного клиента и сетевого стека не гарантируется.",
                recommendation = "Используйте устройство с Android 10 или новее.",
                severity = DeviceCheckSeverity.Error,
                firstLaunchRelevant = true
            )
        } else {
            DeviceCheckItem(
                title = "Версия Android",
                status = "Android $version / SDK $sdk",
                details = "Версия Android подходит под основной ориентир совместимости WDTT Plus.",
                severity = DeviceCheckSeverity.Ok,
                firstLaunchRelevant = true
            )
        }
    }

    private fun abiItem(): DeviceCheckItem {
        val allAbis = Build.SUPPORTED_ABIS.toList()
        val supported = allAbis.filter { it in supportedNativeAbis }
        val primary = allAbis.firstOrNull().orEmpty().ifBlank { "не определён" }
        return when {
            supported.isEmpty() -> DeviceCheckItem(
                title = "Архитектура CPU",
                status = "неподдерживаемая ABI",
                details = "Устройство сообщает ABI: ${allAbis.joinToString().ifBlank { "не определены" }}. WDTT Plus собирается для ${supportedNativeAbis.joinToString()}.",
                recommendation = "Попробуйте universal APK только если устройство действительно поддерживает одну из этих ABI; иначе приложение не сможет запустить нативный клиент.",
                severity = DeviceCheckSeverity.Error,
                firstLaunchRelevant = true
            )
            primary == "armeabi-v7a" -> DeviceCheckItem(
                title = "Архитектура CPU",
                status = "32-bit ARM / armeabi-v7a",
                details = "Эта ABI поддерживается, но на старых 32-битных устройствах запас по памяти и потокам обычно ниже, чем на arm64.",
                recommendation = "Если туннель нестабилен, уменьшите мощность до минимальных 9 потоков и скопируйте отчёт через «Проверить устройство».",
                severity = DeviceCheckSeverity.Info,
                firstLaunchRelevant = false
            )
            else -> DeviceCheckItem(
                title = "Архитектура CPU",
                status = primary,
                details = "Найдена поддерживаемая ABI: ${supported.joinToString()}.",
                severity = DeviceCheckSeverity.Ok,
                firstLaunchRelevant = true
            )
        }
    }

    private fun nativeRuntimeSafetyItem(): DeviceCheckItem? {
        val primary = Build.SUPPORTED_ABIS.firstOrNull().orEmpty()
        if (primary != "armeabi-v7a") return null
        return DeviceCheckItem(
            title = "32-bit нативный режим",
            status = "безопасные atomic-счётчики",
            details = "В этой сборке Android Go-клиент использует выровненные typed atomics для трафика, активных каналов и health-monitor. Это защищает старые ARMv7-устройства от остановки транспорта из-за 64-bit atomic-доступов.",
            severity = DeviceCheckSeverity.Ok,
            firstLaunchRelevant = true
        )
    }

    private fun nativeClientItem(context: Context): DeviceCheckItem {
        val nativeLibraryDir = context.applicationInfo.nativeLibraryDir.orEmpty()
        val nativeClient = File(nativeLibraryDir, "libclient.so")
        return when {
            !nativeClient.isFile -> DeviceCheckItem(
                title = "Нативный клиент",
                status = "libclient.so не найден",
                details = "Android-часть запустилась, но нативный Go-клиент, который поднимает TURN/DTLS транспорт, в установленном APK не найден.",
                recommendation = "Переустановите APK нужной ABI или universal APK из официального релиза WDTT Plus.",
                severity = DeviceCheckSeverity.Error,
                firstLaunchRelevant = true
            )
            nativeClient.length() <= 0L -> DeviceCheckItem(
                title = "Нативный клиент",
                status = "libclient.so пустой",
                details = "Файл нативного клиента найден, но его размер равен нулю.",
                recommendation = "Переустановите APK; текущая установка выглядит повреждённой.",
                severity = DeviceCheckSeverity.Error,
                firstLaunchRelevant = true
            )
            else -> DeviceCheckItem(
                title = "Нативный клиент",
                status = "найден",
                details = "libclient.so найден в установленном APK, размер: ${formatMiB(nativeClient.length())}.",
                severity = DeviceCheckSeverity.Ok,
                firstLaunchRelevant = true
            )
        }
    }

    private fun pageSizeItem(): DeviceCheckItem {
        val pageSize = runCatching { Os.sysconf(OsConstants._SC_PAGESIZE) }.getOrNull()
        return when {
            pageSize == null || pageSize <= 0L -> DeviceCheckItem(
                title = "Страница памяти",
                status = "не удалось определить",
                details = "Android не вернул размер страницы памяти.",
                recommendation = "Если VPN не стартует на новом устройстве, скопируйте отчёт через «Проверить устройство».",
                severity = DeviceCheckSeverity.Info,
                firstLaunchRelevant = false
            )
            pageSize > 4096L -> DeviceCheckItem(
                title = "Страница памяти",
                status = "$pageSize байт",
                details = "Устройство использует страницу памяти больше 4 KB. Для новых Android-устройств с 16 KB page size нужна отдельная проверка нативной библиотеки.",
                recommendation = "Запуск не блокируется. Если туннель не стартует, отправьте отчёт из «Проверить устройство» — это важный сценарий для будущей совместимости.",
                severity = DeviceCheckSeverity.Warning,
                firstLaunchRelevant = true
            )
            else -> DeviceCheckItem(
                title = "Страница памяти",
                status = "$pageSize байт",
                details = "Обычный размер страницы памяти для текущей нативной сборки.",
                severity = DeviceCheckSeverity.Ok,
                firstLaunchRelevant = true
            )
        }
    }

    private fun memoryClassItem(context: Context, workersPerHash: Int?): DeviceCheckItem {
        val activityManager = runCatching {
            context.getSystemService(ActivityManager::class.java)
        }.getOrNull()
        val lowRam = activityManager?.isLowRamDevice == true
        val memoryClass = activityManager?.memoryClass ?: 0
        val largeMemoryClass = activityManager?.largeMemoryClass ?: 0
        val workerWarning = workersPerHash != null && workersPerHash > 8 && lowRam
        return when {
            workerWarning -> DeviceCheckItem(
                title = "Память устройства",
                status = "low-RAM, мощность $workersPerHash",
                details = "Android помечает устройство как low-RAM. Большое число потоков может не успевать стабильно подняться.",
                recommendation = "Для таких устройств начните с минимальных 9 потоков. Это не ошибка подключения к профилю VPN.",
                severity = DeviceCheckSeverity.Warning,
                firstLaunchRelevant = true
            )
            lowRam -> DeviceCheckItem(
                title = "Память устройства",
                status = "low-RAM / Android Go возможен",
                details = "Устройство относится к классу с ограниченной памятью. Приложение может работать, но высокая мощность будет менее предсказуемой.",
                recommendation = "Если активные потоки не появляются, уменьшите мощность до минимальных 9 потоков и проверьте логи.",
                severity = DeviceCheckSeverity.Warning,
                firstLaunchRelevant = true
            )
            else -> DeviceCheckItem(
                title = "Память устройства",
                status = "обычный класс памяти",
                details = "memoryClass=$memoryClass МБ, largeMemoryClass=$largeMemoryClass МБ.",
                severity = DeviceCheckSeverity.Ok,
                firstLaunchRelevant = false
            )
        }
    }

    private fun webViewItem(includeRuntimeChecks: Boolean): DeviceCheckItem {
        if (!includeRuntimeChecks) {
            return DeviceCheckItem(
                title = "WebView",
                status = "не проверялся",
                details = "WebView не нужен для первичной архитектурной проверки.",
                severity = DeviceCheckSeverity.Info,
                firstLaunchRelevant = false
            )
        }
        val webView = runCatching { WebView.getCurrentWebViewPackage() }.getOrNull()
        return if (webView == null) {
            DeviceCheckItem(
                title = "WebView",
                status = "не найден",
                details = "Автоматическая и ручная captcha через WebView могут не работать.",
                recommendation = "Проверьте системный Android System WebView или браузер-провайдер WebView.",
                severity = DeviceCheckSeverity.Warning,
                firstLaunchRelevant = false,
                action = DeviceCheckAction.WebViewSettings
            )
        } else {
            DeviceCheckItem(
                title = "WebView",
                status = webView.packageName,
                details = "Версия: ${webView.versionName}. WebView доступен для captcha-сценариев.",
                severity = DeviceCheckSeverity.Ok,
                firstLaunchRelevant = false
            )
        }
    }

    private fun storageItem(context: Context): DeviceCheckItem {
        val availableBytes = runCatching { StatFs(context.filesDir.absolutePath).availableBytes }.getOrNull()
        return when {
            availableBytes == null -> DeviceCheckItem(
                title = "Память приложения",
                status = "не удалось проверить",
                details = "Свободное место в разделе приложения не определено.",
                severity = DeviceCheckSeverity.Info
            )
            availableBytes < LOW_STORAGE_WARNING_BYTES -> DeviceCheckItem(
                title = "Память приложения",
                status = "мало свободного места",
                details = "Свободно примерно ${formatMiB(availableBytes)}. Для скачивания обновлений, отчётов и временных файлов этого может быть мало.",
                recommendation = "Освободите место на устройстве.",
                severity = DeviceCheckSeverity.Warning,
                action = DeviceCheckAction.AppSettings
            )
            else -> DeviceCheckItem(
                title = "Память приложения",
                status = "достаточно",
                details = "Свободно примерно ${formatMiB(availableBytes)}.",
                severity = DeviceCheckSeverity.Ok
            )
        }
    }

    private fun networkItem(context: Context): DeviceCheckItem {
        val connectivityManager = runCatching {
            context.getSystemService(ConnectivityManager::class.java)
        }.getOrNull()
        val activeNetwork = runCatching { connectivityManager?.activeNetwork }.getOrNull()
        val capabilities = runCatching {
            activeNetwork?.let { connectivityManager?.getNetworkCapabilities(it) }
        }.getOrNull()
        if (capabilities == null) {
            return DeviceCheckItem(
                title = "Сеть Android",
                status = "активная сеть не найдена",
                details = "Приложение запустится, но для VKCalls, TURN и обновлений нужна сеть.",
                recommendation = "Подключитесь к Wi‑Fi или мобильной сети.",
                severity = DeviceCheckSeverity.Warning,
                action = DeviceCheckAction.NetworkSettings
            )
        }
        val transports = buildList {
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) add("Wi‑Fi")
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) add("мобильная")
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) add("Ethernet")
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) add("VPN")
        }.joinToString().ifBlank { "не определён" }
        val hasInternet = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        val validated = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        return if (!hasInternet || !validated) {
            DeviceCheckItem(
                title = "Сеть Android",
                status = "$transports, интернет не подтверждён",
                details = "Android видит сеть, но не подтверждает полноценный доступ в интернет.",
                recommendation = "Проверьте сеть, DNS, captive portal или ограничения оператора.",
                severity = DeviceCheckSeverity.Warning,
                action = DeviceCheckAction.NetworkSettings
            )
        } else {
            DeviceCheckItem(
                title = "Сеть Android",
                status = "$transports, интернет подтверждён",
                details = "Активная сеть выглядит пригодной для проверки VK/TURN.",
                severity = DeviceCheckSeverity.Ok
            )
        }
    }

    private fun vpnPermissionItem(context: Context): DeviceCheckItem {
        val granted = runCatching { VpnService.prepare(context) == null }.getOrDefault(false)
        return if (granted) {
            DeviceCheckItem(
                title = "VPN-разрешение",
                status = "выдано",
                details = "WDTT Plus уже может поднимать системный VPN-интерфейс.",
                severity = DeviceCheckSeverity.Ok,
                action = DeviceCheckAction.VpnSettings
            )
        } else {
            DeviceCheckItem(
                title = "VPN-разрешение",
                status = "будет запрошено при подключении",
                details = "Отсутствие VPN-разрешения сейчас не является ошибкой. Оно понадобится только при первом запуске туннеля.",
                recommendation = "Если подключение не стартует после нажатия «Подключить», подтвердите системный запрос VPN.",
                severity = DeviceCheckSeverity.Info,
                action = DeviceCheckAction.VpnSettings
            )
        }
    }

    private fun tunnelStateItem(): DeviceCheckItem {
        val running = TunnelManager.running.value
        val trustedWifi = TrustedWifiManager.state.value
        val activeWorkers = TunnelManager.activeWorkers.value
        val issue = TunnelManager.connectionIssue.value
        return if (trustedWifi.waiting) {
            DeviceCheckItem(
                title = "Текущее подключение VPN",
                status = "ожидание доверенной Wi-Fi сети",
                details = "VPN сейчас выключен автоматикой доверенных сетей и восстановится после выхода из Wi-Fi.",
                severity = DeviceCheckSeverity.Ok
            )
        } else if (running) {
            DeviceCheckItem(
                title = "Текущее подключение VPN",
                status = "активно",
                details = "VPN подключён. Активных каналов: $activeWorkers.",
                recommendation = issue?.let { "${it.title}: ${it.action}" }.orEmpty(),
                severity = if (activeWorkers > 0) DeviceCheckSeverity.Ok else DeviceCheckSeverity.Warning
            )
        } else {
            DeviceCheckItem(
                title = "Текущее подключение VPN",
                status = "не активно",
                details = "VPN сейчас не подключён. Это не мешает проверке устройства; пункт фиксирует текущее состояние туннеля.",
                recommendation = issue?.let { "${it.title}: ${it.action}" }.orEmpty(),
                severity = DeviceCheckSeverity.Info
            )
        }
    }

    private fun notificationPermissionItem(context: Context): DeviceCheckItem {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            return DeviceCheckItem(
                title = "Уведомления",
                status = "отдельное разрешение не требуется",
                details = "На этой версии Android уведомления не требуют отдельного runtime-разрешения.",
                severity = DeviceCheckSeverity.Ok
            )
        }
        val granted = context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        return if (granted) {
            DeviceCheckItem(
                title = "Уведомления",
                status = "разрешены",
                details = "Приложение сможет показывать статус VPN и важные события.",
                severity = DeviceCheckSeverity.Ok,
                action = DeviceCheckAction.AppSettings
            )
        } else {
            DeviceCheckItem(
                title = "Уведомления",
                status = "не разрешены",
                details = "Это не мешает архитектурной совместимости, но может скрывать статус VPN, ошибки и запросы captcha.",
                recommendation = "Разрешите уведомления WDTT Plus в настройках Android.",
                severity = DeviceCheckSeverity.Warning,
                action = DeviceCheckAction.AppSettings
            )
        }
    }

    private fun batteryItem(context: Context): DeviceCheckItem {
        val powerManager = runCatching { context.getSystemService(PowerManager::class.java) }.getOrNull()
        val ignored = runCatching {
            powerManager?.isIgnoringBatteryOptimizations(context.packageName)
        }.getOrNull()
        return when (ignored) {
            true -> DeviceCheckItem(
                title = "Фоновая работа",
                status = "без ограничений батареи",
                details = "Android не должен агрессивно останавливать VPN в фоне.",
                severity = DeviceCheckSeverity.Ok,
                action = DeviceCheckAction.BatterySettings
            )
            false -> DeviceCheckItem(
                title = "Фоновая работа",
                status = "ограничения батареи могут мешать",
                details = "Это не архитектурная ошибка, но на некоторых прошивках VPN может засыпать при выключенном экране.",
                recommendation = "Отключите ограничения батареи для WDTT Plus, если туннель сам останавливается.",
                severity = DeviceCheckSeverity.Warning,
                action = DeviceCheckAction.BatterySettings
            )
            null -> DeviceCheckItem(
                title = "Фоновая работа",
                status = "не удалось проверить",
                details = "Состояние ограничений батареи не определено.",
                severity = DeviceCheckSeverity.Info,
                action = DeviceCheckAction.AppSettings
            )
        }
    }

    private fun updateInstallPermissionItem(context: Context): DeviceCheckItem {
        val canInstall = runCatching { context.packageManager.canRequestPackageInstalls() }
            .getOrDefault(false)
        return if (canInstall) {
            DeviceCheckItem(
                title = "Установка обновлений",
                status = "разрешена",
                details = "WDTT Plus сможет скачать APK и передать его системному установщику Android.",
                severity = DeviceCheckSeverity.Ok,
                action = DeviceCheckAction.UnknownAppInstallSettings
            )
        } else {
            DeviceCheckItem(
                title = "Установка обновлений",
                status = "потребуется разрешение",
                details = "Это не мешает VPN. Разрешение понадобится только для установки APK, скачанного внутри приложения.",
                recommendation = "Когда будете обновляться из приложения, Android попросит разрешить установку из WDTT Plus.",
                severity = DeviceCheckSeverity.Info,
                action = DeviceCheckAction.UnknownAppInstallSettings
            )
        }
    }

    private fun formatMiB(bytes: Long): String =
        "${bytes.coerceAtLeast(0L) / (1024L * 1024L)} МБ"
}

fun DeviceCheckSeverity.label(): String = when (this) {
    DeviceCheckSeverity.Ok -> "OK"
    DeviceCheckSeverity.Info -> "INFO"
    DeviceCheckSeverity.Warning -> "WARN"
    DeviceCheckSeverity.Error -> "ERROR"
}

fun DeviceCheckAction.label(): String = when (this) {
    DeviceCheckAction.AppSettings -> "Настройки приложения"
    DeviceCheckAction.BatterySettings -> "Батарея"
    DeviceCheckAction.NetworkSettings -> "Настройки сети"
    DeviceCheckAction.VpnSettings -> "VPN"
    DeviceCheckAction.UnknownAppInstallSettings -> "Установка APK"
    DeviceCheckAction.WebViewSettings -> "WebView"
}

fun deviceCheckActionIntent(context: Context, action: DeviceCheckAction): Intent {
    return when (action) {
        DeviceCheckAction.AppSettings -> Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = Uri.parse("package:${context.packageName}")
        }
        DeviceCheckAction.BatterySettings -> Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = Uri.parse("package:${context.packageName}")
        }
        DeviceCheckAction.NetworkSettings -> Intent(Settings.ACTION_WIRELESS_SETTINGS)
        DeviceCheckAction.VpnSettings -> Intent(Settings.ACTION_VPN_SETTINGS)
        DeviceCheckAction.UnknownAppInstallSettings -> Intent(
            Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
            Uri.parse("package:${context.packageName}")
        )
        DeviceCheckAction.WebViewSettings -> Intent(Settings.ACTION_WEBVIEW_SETTINGS)
    }
}
