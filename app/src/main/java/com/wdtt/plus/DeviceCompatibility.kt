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
import org.json.JSONObject
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

internal enum class RtMasqueEnrollmentState {
    Missing,
    Ready,
    Invalid,
}

internal fun inspectRtMasqueEnrollment(file: File): RtMasqueEnrollmentState {
    if (!file.isFile) return RtMasqueEnrollmentState.Missing
    if (file.length() !in 1L..128L * 1024L) return RtMasqueEnrollmentState.Invalid
    return runCatching {
        val json = JSONObject(file.readText(Charsets.UTF_8))
        val requiredFields = listOf(
            "private_key",
            "endpoint_v4",
            "endpoint_pub_key",
            "ipv4",
        )
        if (
            json.optInt("version", -1) != 1 ||
            requiredFields.any { json.optString(it).isBlank() }
        ) {
            RtMasqueEnrollmentState.Invalid
        } else {
            RtMasqueEnrollmentState.Ready
        }
    }.getOrDefault(RtMasqueEnrollmentState.Invalid)
}

internal fun pageSizeCompatibilityItem(
    pageSize: Long?,
    processIs64Bit: Boolean,
): DeviceCheckItem = when {
    pageSize == null || pageSize <= 0L -> DeviceCheckItem(
        title = "Страница памяти",
        status = "не удалось определить",
        details = "Android не вернул размер страницы памяти.",
        recommendation = "Если VPN не стартует на новом устройстве, скопируйте отчёт через «Проверить устройство».",
        severity = DeviceCheckSeverity.Info,
        firstLaunchRelevant = false,
    )
    pageSize == 16L * 1024L && processIs64Bit -> DeviceCheckItem(
        title = "Страница памяти",
        status = "16 КиБ · поддерживается",
        details = "Устройство использует страницы памяти 16 КиБ. Все 64-битные нативные библиотеки release-сборки WDTT Plus проверяются на совместимое LOAD-выравнивание.",
        severity = DeviceCheckSeverity.Ok,
        firstLaunchRelevant = true,
    )
    pageSize > 4096L -> DeviceCheckItem(
        title = "Страница памяти",
        status = "$pageSize байт · требуется проверка",
        details = "Android использует нестандартный для этой ABI размер страницы памяти, который нельзя подтвердить как штатный 16-КиБ режим текущей 64-битной сборки.",
        recommendation = "Если туннель не стартует, установите подходящий APK и отправьте отчёт из «Проверить устройство».",
        severity = DeviceCheckSeverity.Warning,
        firstLaunchRelevant = true,
    )
    else -> DeviceCheckItem(
        title = "Страница памяти",
        status = "$pageSize байт",
        details = "Размер страницы памяти поддерживается текущей нативной сборкой.",
        severity = DeviceCheckSeverity.Ok,
        firstLaunchRelevant = true,
    )
}

internal fun tunnelHealthItem(
    running: Boolean,
    activeWorkers: Int,
    issue: ConnectionIssue?,
    confirmedNetworkFailure: Boolean,
): DeviceCheckItem = when {
    !running -> DeviceCheckItem(
        title = "Текущее подключение VPN",
        status = "не активно",
        details = "VPN сейчас не подключён. Это не мешает проверке устройства; пункт фиксирует текущее состояние туннеля.",
        recommendation = issue?.let { "${it.title}: ${it.action}" }.orEmpty(),
        severity = DeviceCheckSeverity.Info,
    )
    confirmedNetworkFailure -> DeviceCheckItem(
        title = "Текущее подключение VPN",
        status = "нет ответа на пользовательский трафик",
        details = "VPN-интерфейс включён, активных каналов: $activeWorkers, но приложение подтвердило отсутствие ответов на переданный трафик.",
        recommendation = issue?.let { "${it.title}: ${it.action}" }
            ?: "WDTT Plus автоматически проверит восстановление и при необходимости переподключит VPN.",
        severity = DeviceCheckSeverity.Warning,
    )
    issue != null -> DeviceCheckItem(
        title = "Текущее подключение VPN",
        status = "обнаружена проблема",
        details = "VPN-интерфейс включён, активных каналов: $activeWorkers. Приложение обнаружило состояние, требующее внимания.",
        recommendation = "${issue.title}: ${issue.action}",
        severity = DeviceCheckSeverity.Warning,
    )
    activeWorkers <= 0 -> DeviceCheckItem(
        title = "Текущее подключение VPN",
        status = "нет активных каналов",
        details = "VPN подключён, но сейчас нет активных транспортных каналов.",
        recommendation = "Подождите автоматического восстановления. Если каналы не появятся, переподключите VPN и приложите новый отчёт.",
        severity = DeviceCheckSeverity.Warning,
    )
    else -> DeviceCheckItem(
        title = "Текущее подключение VPN",
        status = "активно",
        details = "VPN подключён. Активных каналов: $activeWorkers.",
        severity = DeviceCheckSeverity.Ok,
    )
}

internal fun sleepBatteryModeItem(
    enabled: Boolean,
    mode: SleepBatteryMode,
    pauseDelayMinutes: Int,
    resumeDelayMinutes: Int,
    runtime: SleepBatteryRuntimeState,
    notificationsGranted: Boolean,
    batteryOptimizationsIgnored: Boolean?,
): DeviceCheckItem {
    if (!enabled) {
        return DeviceCheckItem(
            title = "Экономия батареи во сне",
            status = "выключена",
            details = "При выключенном экране WDTT Plus не будет намеренно останавливать VPN по сценарию сна.",
            severity = DeviceCheckSeverity.Info,
        )
    }

    val normalizedPause = normalizeSleepPauseDelayMinutes(pauseDelayMinutes)
    val normalizedResume = normalizeSleepPauseDelayMinutes(resumeDelayMinutes)
    val status = when (mode) {
        SleepBatteryMode.DELAYED_PAUSE -> if (normalizedPause == 0) {
            "отключение сразу после выключения экрана"
        } else {
            "отключение через ${sleepDelayDescription(normalizedPause)}"
        }
        SleepBatteryMode.TIMED_PAUSE -> if (normalizedResume == 0) {
            "таймер 0 мин, VPN остаётся активным"
        } else {
            "пауза примерно на ${sleepDelayDescription(normalizedResume)}"
        }
    }
    val runtimeText = when (runtime.phase) {
        SleepBatteryRuntimePhase.IDLE -> "сценарий сейчас не выполняется"
        SleepBatteryRuntimePhase.WAITING_TO_PAUSE -> "идёт отсчёт до отключения VPN"
        SleepBatteryRuntimePhase.PAUSED_UNTIL_SCREEN_ON -> "VPN отключён до включения экрана"
        SleepBatteryRuntimePhase.WAITING_TO_RESUME -> "VPN отключён, ожидается таймер включения"
        SleepBatteryRuntimePhase.RESUMED_UNTIL_SCREEN_ON -> "VPN уже включён таймером"
    }
    val timedResumeNeedsAttention =
        mode == SleepBatteryMode.TIMED_PAUSE && normalizedResume > 0
    val severity = when {
        !notificationsGranted -> DeviceCheckSeverity.Warning
        timedResumeNeedsAttention && batteryOptimizationsIgnored == false -> DeviceCheckSeverity.Warning
        else -> DeviceCheckSeverity.Ok
    }
    val recommendation = when {
        !notificationsGranted ->
            "Разрешите уведомления WDTT Plus, чтобы видеть отсчёт и быстрые действия сценария сна."
        timedResumeNeedsAttention && batteryOptimizationsIgnored == false ->
            "Снимите ограничения батареи с WDTT Plus, если Android задерживает включение VPN по таймеру."
        else -> ""
    }
    val timerNote = if (timedResumeNeedsAttention) {
        " Android может немного отложить таймер в глубоком сне; включение экрана всегда завершает сценарий сразу."
    } else {
        " Включение экрана завершает текущий сценарий."
    }
    return DeviceCheckItem(
        title = "Экономия батареи во сне",
        status = status,
        details = "Текущее состояние: $runtimeText.$timerNote Во время паузы интернет телефона идёт напрямую, без VPN.",
        recommendation = recommendation,
        severity = severity,
        action = when {
            !notificationsGranted -> DeviceCheckAction.AppSettings
            timedResumeNeedsAttention && batteryOptimizationsIgnored == false ->
                DeviceCheckAction.BatterySettings
            else -> null
        },
    )
}

internal fun trustedWifiModeItem(
    enabled: Boolean,
    savedNetworkCount: Int,
    waiting: Boolean,
    waitingSsid: String,
    accessProblem: TrustedWifiAccessProblem?,
): DeviceCheckItem {
    if (!enabled) {
        return DeviceCheckItem(
            title = "Доверенные Wi-Fi",
            status = "выключены",
            details = "VPN не будет автоматически останавливаться при подключении к сохранённым Wi-Fi сетям.",
            severity = DeviceCheckSeverity.Info,
        )
    }

    val accessRecommendation = when (accessProblem) {
        TrustedWifiAccessProblem.ForegroundPermission ->
            "Разрешите WDTT Plus доступ к местоположению или ближайшим устройствам, чтобы Android возвращал имя Wi-Fi."
        TrustedWifiAccessProblem.BackgroundPermission ->
            "Разрешите фоновый доступ к местоположению, чтобы доверенная сеть определялась при закрытом приложении."
        TrustedWifiAccessProblem.LocationDisabled ->
            "Включите определение местоположения Android, иначе система скрывает имя текущей Wi-Fi сети."
        null -> ""
    }
    val accessAction = when (accessProblem) {
        TrustedWifiAccessProblem.LocationDisabled -> DeviceCheckAction.NetworkSettings
        TrustedWifiAccessProblem.ForegroundPermission,
        TrustedWifiAccessProblem.BackgroundPermission -> DeviceCheckAction.AppSettings
        null -> null
    }
    val cleanCount = savedNetworkCount.coerceAtLeast(0)
    val status = when {
        cleanCount == 0 -> "включены, сети не сохранены"
        accessProblem != null -> "включены, нет доступа к имени Wi-Fi"
        waiting -> "VPN ожидает выхода из доверенной сети"
        else -> "включены, сетей: $cleanCount"
    }
    val details = when {
        cleanCount == 0 ->
            "Автоматика включена, но без сохранённых сетей она не сможет приостанавливать VPN."
        accessProblem != null ->
            "Сохранено сетей: $cleanCount. Android не позволяет приложению надёжно определить текущую Wi-Fi сеть в нужном режиме."
        waiting -> {
            val network = waitingSsid.trim().takeIf(String::isNotEmpty)?.let { " «$it»" }.orEmpty()
            "VPN намеренно выключен в доверенной сети$network и восстановится после подтверждённого перехода на другую сеть."
        }
        else ->
            "Сохранено сетей: $cleanCount. VPN будет останавливаться только в них и восстанавливаться после выхода из доверенной сети."
    }
    return DeviceCheckItem(
        title = "Доверенные Wi-Fi",
        status = status,
        details = details,
        recommendation = when {
            cleanCount == 0 -> "Добавьте хотя бы одну сеть или выключите эту автоматику."
            accessProblem != null -> accessRecommendation
            else -> ""
        },
        severity = if (cleanCount == 0 || accessProblem != null) {
            DeviceCheckSeverity.Warning
        } else {
            DeviceCheckSeverity.Ok
        },
        action = accessAction,
    )
}

internal fun vpnRoutingModeItem(
    snapshot: VpnRoutingSettingsSnapshot,
    installedPackages: Set<String>,
    ownPackageName: String,
): DeviceCheckItem {
    val selectedPackages = decodeStoredVpnPackages(snapshot.appPackages)
        .filterNot { isAlwaysBypassedVpnPackage(it, ownPackageName) }
    val installedSelected = selectedPackages.filter { it in installedPackages }
    val missingPackages = selectedPackages.filterNot { it in installedPackages }
    val addressCount = snapshot.addressRules.size
    val domainCount = snapshot.addressRules.count { it.type == VpnAddressType.DOMAIN }
    val mode = if (snapshot.isWhitelist) "БС" else "ЧС"
    val counts = "приложений: ${selectedPackages.size}, адресов: $addressCount" +
        if (domainCount > 0) ", доменов: $domainCount" else ""

    val warning = when {
        snapshot.isWhitelist && selectedPackages.isEmpty() && addressCount == 0 ->
            "Белый список пуст: при подключении профиль намеренно не пропускает трафик приложений через VPN."
        snapshot.isWhitelist && selectedPackages.isNotEmpty() && installedSelected.isEmpty() ->
            "Ни одно выбранное приложение сейчас не установлено: профиль не пропускает трафик приложений через VPN."
        missingPackages.isNotEmpty() ->
            "Часть выбранных приложений не установлена (${missingPackages.size}); их правила начнут действовать после установки."
        else -> null
    }
    val behavior = when {
        snapshot.isWhitelist && selectedPackages.isEmpty() && addressCount > 0 ->
            "Адресные правила применяются ко всем приложениям, кроме обязательных системных исключений WDTT Plus."
        snapshot.isWhitelist ->
            "Через VPN идут только выбранные установленные приложения и заданные адресные направления."
        selectedPackages.isEmpty() && addressCount == 0 ->
            "Пользовательских исключений нет; через VPN идёт весь поддерживаемый трафик, кроме обязательных исключений WDTT Plus."
        else ->
            "Выбранные приложения и адреса обходят VPN, остальной поддерживаемый трафик идёт через туннель."
    }
    return DeviceCheckItem(
        title = "Маршрутизация приложений и адресов",
        status = "профиль ${snapshot.profileIndex + 1}: $mode, $counts",
        details = listOfNotNull(behavior, warning).joinToString(" "),
        recommendation = if (warning != null) {
            "Проверьте активный профиль во вкладке «Исключения»; предупреждение не изменяет настройки автоматически."
        } else {
            ""
        },
        severity = if (warning != null) DeviceCheckSeverity.Warning else DeviceCheckSeverity.Ok,
    )
}

internal fun vpnDnsModeItem(
    settings: VpnDnsSettingsSnapshot,
    tunnelRunning: Boolean,
    runningProfile: Int?,
    profileName: String? = null,
): DeviceCheckItem {
    val appliesNow = tunnelRunning && runningProfile == settings.profileIndex
    val customInvalid = settings.selectionId == VPN_DNS_CUSTOM_ID &&
        settings.customServers.isEmpty()
    val serverText = settings.configuredServers.joinToString(", ")
    val status = when {
        customInvalid -> "свой DNS не заполнен"
        settings.selectionId == VPN_DNS_PROFILE_ID -> "как в WireGuard-профиле"
        else -> "${settings.title}: $serverText"
    }
    val details = buildString {
        val displayName = profileName?.takeIf { it.isNotBlank() } ?: "Профиль ${settings.profileIndex + 1}"
        append("Настройка относится к «")
        append(displayName)
        append("» и управляет DNS внутри системного VPN-интерфейса Android. ")
        when {
            customInvalid -> append("При подключении безопасно сохранится DNS из WireGuard-профиля.")
            settings.selectionId == VPN_DNS_PROFILE_ID ->
                append("Фактические адреса предоставляет сервер вместе с WireGuard-конфигурацией.")
            settings.isSmartDns ->
                append("Это сторонний Smart DNS; отдельные сервисы могут направляться через его шлюзы.")
            else -> append("Выбранные адреса передаются Android VPN-интерфейсу.")
        }
        if (appliesNow) {
            append(" Сейчас запущен этот профиль.")
        } else if (tunnelRunning) {
            append(" Сейчас запущен другой профиль; настройка применится при запуске этого профиля.")
        }
    }
    return DeviceCheckItem(
        title = "DNS внутри VPN",
        status = status,
        details = details,
        recommendation = when {
            customInvalid -> "Откройте «Туннель → DNS внутри VPN» и укажите один или два IPv4-адреса либо выберите готовый вариант."
            settings.isSmartDns -> "Учитывайте политику конфиденциальности стороннего сервиса и проверяйте нужные сайты после его выбора."
            else -> ""
        },
        severity = when {
            customInvalid -> DeviceCheckSeverity.Warning
            settings.isSmartDns -> DeviceCheckSeverity.Info
            else -> DeviceCheckSeverity.Ok
        },
    )
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
            add(nativeComponentsItem(appContext))
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

    private fun nativeComponentsItem(context: Context): DeviceCheckItem {
        val nativeLibraryDir = context.applicationInfo.nativeLibraryDir.orEmpty()
        val nativeClient = File(nativeLibraryDir, "libclient.so")
        val wireGuardBackend = File(nativeLibraryDir, "libwg-go.so")
        val missing = buildList {
            if (!nativeClient.isFile || nativeClient.length() <= 0L) add("libclient.so")
            if (!wireGuardBackend.isFile || wireGuardBackend.length() <= 0L) add("libwg-go.so")
        }
        return when {
            missing.isNotEmpty() -> DeviceCheckItem(
                title = "Нативные компоненты",
                status = "не найдены: ${missing.joinToString()}",
                details = "В установленном APK отсутствует или повреждён нативный клиент TURN/DTLS либо WireGuard backend системного VPN.",
                recommendation = "Переустановите APK нужной ABI или universal APK из официального релиза WDTT Plus.",
                severity = DeviceCheckSeverity.Error,
                firstLaunchRelevant = true
            )
            else -> DeviceCheckItem(
                title = "Нативные компоненты",
                status = "клиент и WireGuard найдены",
                details = "libclient.so: ${formatMiB(nativeClient.length())}; libwg-go.so: ${formatMiB(wireGuardBackend.length())}.",
                severity = DeviceCheckSeverity.Ok,
                firstLaunchRelevant = true
            )
        }
    }

    private fun pageSizeItem(): DeviceCheckItem {
        val pageSize = runCatching { Os.sysconf(OsConstants._SC_PAGESIZE) }.getOrNull()
        return pageSizeCompatibilityItem(pageSize, android.os.Process.is64Bit())
    }

    fun rtNetworkModeItem(context: Context, profile: TunnelProfileSnapshot): DeviceCheckItem {
        val enrollment = inspectRtMasqueEnrollment(
            File(context.filesDir, RT_MASQUE_CONFIG_FILE_NAME)
        )
        return when {
            !profile.rtNetwork -> DeviceCheckItem(
                title = "Режим Сеть РТ",
                status = "выключен",
                details = "Используется обычный порядок транспортов; настройки РТ этого профиля не влияют на подключение.",
                severity = DeviceCheckSeverity.Info,
            )
            !profile.rtMasque -> DeviceCheckItem(
                title = "Режим Сеть РТ",
                status = "TURN/TLS и TCP включены · MASQUE выключен",
                details = "Для активного профиля включён только основной механизм Сети РТ. Регистрация WARP не требуется.",
                severity = DeviceCheckSeverity.Ok,
            )
            profile.rtMasqueServerBootstrap && !profile.rtMasqueServerAccessReady -> DeviceCheckItem(
                title = "Режим Сеть РТ",
                status = "«Через сервер» настроен не полностью",
                details = "MASQUE включён, но в активном профиле нет полного SSH-доступа из раздела «Деплой».",
                recommendation = "Заполните адрес и пароль либо приватный SSH-ключ в «Деплой» или выключите «Через сервер».",
                severity = DeviceCheckSeverity.Warning,
            )
            enrollment == RtMasqueEnrollmentState.Invalid -> DeviceCheckItem(
                title = "Режим Сеть РТ",
                status = "регистрация WARP повреждена",
                details = "Локальный файл регистрации MASQUE не содержит корректной структуры версии 1. Секретные поля в отчёт не включены.",
                recommendation = "Остановите VPN и выполните «Сбросить регистрацию WARP» в инструкции MASQUE.",
                severity = DeviceCheckSeverity.Warning,
            )
            enrollment == RtMasqueEnrollmentState.Missing -> DeviceCheckItem(
                title = "Режим Сеть РТ",
                status = "MASQUE включён · регистрация ещё не создана",
                details = "При следующем запуске VPN приложение попробует зарегистрировать отдельное устройство WARP. Прямые TURN-пути продолжат работать во время подготовки.",
                recommendation = if (profile.rtMasqueServerBootstrap) {
                    "Если прямой TLS Cloudflare недоступен, приложение сможет использовать SSH-выход активного профиля."
                } else {
                    "Если регистрация не выполняется, проверьте журнал MASQUE; при необходимости настройте «Через сервер»."
                },
                severity = DeviceCheckSeverity.Info,
            )
            else -> DeviceCheckItem(
                title = "Режим Сеть РТ",
                status = "MASQUE готов",
                details = "Структура сохранённой регистрации WARP корректна; при запуске её дополнительно проверит нативный клиент.",
                severity = DeviceCheckSeverity.Ok,
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
                details = "Быстрый VKCalls может работать без WebView, но автоматическая и ручная капча резервного способа будут недоступны.",
                recommendation = "Обновите или включите Android System WebView либо браузер-провайдер WebView, чтобы резервное подключение могло пройти капчу.",
                severity = DeviceCheckSeverity.Warning,
                firstLaunchRelevant = false,
                action = DeviceCheckAction.WebViewSettings
            )
        } else {
            DeviceCheckItem(
                title = "WebView",
                status = webView.packageName,
                details = "Версия: ${webView.versionName}. WebView доступен для капчи резервного способа.",
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
                details = "Приложение запустится, но для быстрого VKCalls, TURN и обновлений нужна сеть.",
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
                details = "Android подтвердил общий доступ в интернет. Системный DNS, DNS-путь нативного клиента и служебные узлы VK/OK проверяются отдельными пунктами ниже.",
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
            tunnelHealthItem(
                running = true,
                activeWorkers = activeWorkers,
                issue = issue,
                confirmedNetworkFailure = TunnelManager.hasConfirmedNetworkFailureSince(0L),
            )
        } else {
            tunnelHealthItem(
                running = false,
                activeWorkers = activeWorkers,
                issue = issue,
                confirmedNetworkFailure = false,
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
