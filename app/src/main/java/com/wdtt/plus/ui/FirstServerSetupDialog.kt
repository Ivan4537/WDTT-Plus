package com.wdtt.plus.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.os.PersistableBundle
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.wdtt.plus.sshCredentialsForMode
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import java.security.SecureRandom

internal enum class ServerSetupKind { FRESH, EXISTING, PRESERVED, INCOMPLETE, RECOVERY, STANDALONE }

internal data class ServerSetupReview(
    val changes: List<String> = emptyList(),
    val notes: List<String> = emptyList(),
)

internal fun ServerSetupDraft.sameServerAccess(other: ServerSetupDraft): Boolean =
    host.trim() == other.host.trim() && user.trim() == other.user.trim() &&
        sshPassword == other.sshPassword && sshPort.ifBlank { "22" } == other.sshPort.ifBlank { "22" } &&
        authMode == other.authMode && privateKey == other.privateKey && keyPassphrase == other.keyPassphrase

internal fun classifyFirstServerSetup(hasAnyTrace: Boolean, ownership: DeploymentOwnership, hasRollback: Boolean): ServerSetupKind? = when {
    ownership == DeploymentOwnership.StandaloneInstaller -> ServerSetupKind.STANDALONE
    hasRollback -> ServerSetupKind.RECOVERY
    !hasAnyTrace && ownership in setOf(DeploymentOwnership.UnknownExisting, DeploymentOwnership.NoInstall) -> ServerSetupKind.FRESH
    !hasAnyTrace -> null
    ownership == DeploymentOwnership.AndroidDeploy || ownership == DeploymentOwnership.LegacyAndroidDeploy -> ServerSetupKind.EXISTING
    ownership == DeploymentOwnership.PreservedAndroidData -> ServerSetupKind.PRESERVED
    ownership == DeploymentOwnership.IncompleteAndroidDeploy -> ServerSetupKind.INCOMPLETE
    else -> null
}

internal fun offersServerUpdate(setupCompleted: Boolean, sshReady: Boolean, mainPassword: String): Boolean =
    setupCompleted || (sshReady && mainPassword.isNotBlank())

internal fun canOpenInitialServerTunnel(
    installedProfile: Int?, installedNavigationRevision: Int?, activeProfile: Int,
    navigationRevision: Int, visible: Boolean, navigationCancelled: Boolean,
): Boolean = installedProfile == activeProfile && installedNavigationRevision == navigationRevision &&
    visible && !navigationCancelled

internal fun generateServerAdminPassword(): String {
    val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    val random = SecureRandom()
    return buildString { repeat(24) { append(alphabet[random.nextInt(alphabet.length)]) } }
}

internal data class ServerSetupDraft(
    val host: String = "", val user: String = "root", val sshPassword: String = "",
    val sshPort: String = "22", val authMode: String = "password",
    val privateKey: String = "", val keyPassphrase: String = "",
    val mainPassword: String = "", val dns1: String = "1.1.1.1", val dns2: String = "1.0.0.1",
    val dtlsPort: String = "56000", val wgPort: String = "56001", val localPort: String = "9000",
    val adminId: String = "", val botToken: String = "",
) {
    fun accessIssue(): String? = primaryServerSshAccessIssue(
        host.trim(), host.trim().isValidPublicHost(), authMode, sshPassword, privateKey,
        sshPort.ifBlank { "22" }.toIntOrNull() ?: 0,
    )
    fun settingsIssue(): String? {
        if (!mainPassword.matches(Regex("^[a-zA-Z0-9_.!?:#/-]+$"))) return "Укажите пароль администратора: латинские буквы, цифры или _ . ! ? : # - /"
        val ports = listOf(dtlsPort, wgPort, localPort).map { it.toIntOrNull() ?: 0 }
        if (ports.any { it !in 1..65535 }) return "Порты должны быть числами от 1 до 65535."
        if (ports[0] == ports[1]) return "Порты WDTT и WireGuard должны отличаться."
        runCatching { normalizedDeployDns(dns1, dns2) }.exceptionOrNull()?.let { return it.message ?: "Проверьте DNS." }
        if ((adminId.isBlank()) != (botToken.isBlank())) return "Для Telegram-бота заполните оба поля или отключите настройку бота."
        if (adminId.isNotBlank() && adminId.toLongOrNull() == null) return "ID администратора должен быть числом."
        return null
    }
    fun request(): DeployRequest {
        require(accessIssue() == null && settingsIssue() == null)
        val credentials = sshCredentialsForMode(authMode, sshPassword, privateKey, keyPassphrase)
        return DeployRequest(host.trim(), user.ifBlank { "root" }, credentials.password,
            credentials.privateKey, credentials.privateKeyPassphrase, credentials.allowPasswordAuthentication,
            sshPort.ifBlank { "22" }.toInt(), mainPassword, adminId, botToken,
            dtlsPort.toInt(), wgPort.toInt(), localPort.toInt(), dns1.trim(), dns2.trim())
    }
}

internal fun copyServerSecret(context: android.content.Context, label: String, value: String) {
    val clip = ClipData.newPlainText(label, value)
    clip.description.extras = PersistableBundle().apply { putBoolean("android.content.extra.IS_SENSITIVE", true) }
    context.getSystemService(ClipboardManager::class.java)?.setPrimaryClip(clip)
}

@Composable
internal fun SetupSecretField(
    value: String, onChange: (String) -> Unit, label: String,
    enabled: Boolean = true, multiline: Boolean = false,
    onRegenerate: (() -> Unit)? = null, allowCopy: Boolean = false,
) {
    var focused by remember { mutableStateOf(false) }
    val context = LocalContext.current
    OutlinedTextField(
        value = value, onValueChange = onChange, label = { Text(label) }, enabled = enabled,
        singleLine = !multiline, maxLines = if (multiline) 5 else 1,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false),
        visualTransformation = if (focused) VisualTransformation.None else PasswordVisualTransformation(),
        modifier = Modifier.fillMaxWidth().onFocusChanged { focused = it.isFocused },
        shape = androidx.compose.foundation.shape.RoundedCornerShape(16.dp),
        trailingIcon = if (onRegenerate != null || allowCopy) ({
            Row {
                onRegenerate?.let { regenerate ->
                    HintIconButton(hint = "Сгенерировать новый пароль", onClick = regenerate, enabled = enabled, modifier = Modifier.remoteIconButtonFocus(enabled)) {
                        Icon(Icons.Default.Refresh, "Сгенерировать новый пароль")
                    }
                }
                if (allowCopy) HintIconButton(hint = "Скопировать $label",
                    onClick = { copyServerSecret(context, label, value) }, enabled = enabled && value.isNotBlank(),
                    modifier = Modifier.remoteIconButtonFocus(enabled && value.isNotBlank()),
                ) { Icon(Icons.Default.ContentCopy, "Скопировать $label") }
            }
        }) else null,
    )
}

@Composable
internal fun FirstServerSetupDialog(
    initial: ServerSetupDraft,
    onDismiss: () -> Unit,
    onProbe: suspend (ServerSetupDraft) -> ServerSetupKind,
    onReview: suspend (ServerSetupDraft, ServerSetupKind) -> ServerSetupReview,
    onInstall: suspend (ServerSetupDraft, ServerSetupKind) -> Unit,
) {
    // Secrets are kept out of the saved-state Bundle. Saved credentials use SettingsStore encryption.
    var draft by remember { mutableStateOf(initial) }
    var step by remember { mutableIntStateOf(0) }
    var kind by remember { mutableStateOf(ServerSetupKind.FRESH) }
    var verifiedAccess by remember { mutableStateOf<ServerSetupDraft?>(null) }
    var review by remember { mutableStateOf<ServerSetupReview?>(null) }
    var reviewedDraft by remember { mutableStateOf<ServerSetupDraft?>(null) }
    val fresh = kind == ServerSetupKind.FRESH
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf("") }
    var customDns by remember { mutableStateOf(initial.dns1 != "1.1.1.1" || initial.dns2 != "1.0.0.1") }
    var customPorts by remember { mutableStateOf(initial.dtlsPort != "56000" || initial.wgPort != "56001" || initial.localPort != "9000") }
    var useBot by remember { mutableStateOf(initial.adminId.isNotBlank() || initial.botToken.isNotBlank()) }
    val scope = rememberCoroutineScope()
    val shown = draft.copy(
        dns1 = if (customDns && kind != ServerSetupKind.STANDALONE) draft.dns1 else "1.1.1.1", dns2 = if (customDns && kind != ServerSetupKind.STANDALONE) draft.dns2 else "1.0.0.1",
        dtlsPort = if (customPorts && kind != ServerSetupKind.STANDALONE) draft.dtlsPort else "56000", wgPort = if (customPorts && kind != ServerSetupKind.STANDALONE) draft.wgPort else "56001",
        localPort = if (customPorts && kind != ServerSetupKind.STANDALONE) draft.localPort else "9000",
        adminId = if (useBot && kind != ServerSetupKind.STANDALONE) draft.adminId else "", botToken = if (useBot && kind != ServerSetupKind.STANDALONE) draft.botToken else "",
    )
    fun openStep(target: Int) {
        if (busy || target == step) return
        error = ""
        when (target) {
            0 -> step = 0
            1 -> {
                error = draft.accessIssue().orEmpty()
                if (error.isBlank() && verifiedAccess?.let { draft.sameServerAccess(it) } != true) {
                    error = "На шаге «Доступ» нажмите «Далее», чтобы проверить VPS."
                }
                if (error.isBlank()) step = 1
            }
            2 -> {
                error = draft.accessIssue() ?: shown.settingsIssue().orEmpty()
                if (error.isBlank() && verifiedAccess?.let { draft.sameServerAccess(it) } != true) {
                    error = "После изменения доступа проверьте VPS ещё раз."
                }
                if (error.isBlank() && (review == null || reviewedDraft != shown)) {
                    error = "На шаге «Настройки» нажмите «Далее», чтобы перейти к итогу."
                }
                if (error.isBlank()) step = 2
            }
        }
    }
    SettingsDialogLayout(
        title = "Настройка сервера", secure = true, onDismiss = { if (!busy) onDismiss() },
        footer = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (error.isNotBlank()) Text(error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    if (step > 0) OutlinedButton(onClick = { openStep(step - 1) }, enabled = !busy,
                        contentPadding = PaddingValues(horizontal = 12.dp)) { Text("Назад", maxLines = 1) }
                    Button(
                        enabled = !busy, modifier = Modifier.weight(1f).heightIn(min = 48.dp),
                        onClick = {
                            error = ""
                            when (step) {
                                0 -> {
                                    error = draft.accessIssue().orEmpty()
                                    if (error.isBlank()) {
                                        busy = true
                                        scope.launch {
                                            try {
                                                val detected = onProbe(draft)
                                                val sameAccess = verifiedAccess?.let { draft.sameServerAccess(it) } == true
                                                val nextPassword = when {
                                                    sameAccess && detected == kind -> draft.mainPassword
                                                    detected == ServerSetupKind.FRESH -> generateServerAdminPassword()
                                                    verifiedAccess == null -> initial.mainPassword
                                                    else -> ""
                                                }
                                                kind = detected
                                                verifiedAccess = draft
                                                review = null
                                                reviewedDraft = null
                                                draft = draft.copy(mainPassword = nextPassword)
                                                step = 1
                                            } catch (e: CancellationException) { throw e }
                                            catch (e: Exception) { error = friendlyDeployError(e, "проверка сервера") }
                                            finally { busy = false }
                                        }
                                    }
                                }
                                1 -> {
                                    error = draft.accessIssue() ?: shown.settingsIssue().orEmpty()
                                    if (error.isBlank() && verifiedAccess?.let { draft.sameServerAccess(it) } != true) {
                                        error = "После изменения доступа проверьте VPS ещё раз."
                                    }
                                    if (error.isBlank()) {
                                        busy = true
                                        scope.launch {
                                            try {
                                                val result = onReview(shown, kind)
                                                if (verifiedAccess?.let { draft.sameServerAccess(it) } != true) {
                                                    error = "После изменения доступа проверьте VPS ещё раз."
                                                } else {
                                                    review = result
                                                    reviewedDraft = shown
                                                    step = 2
                                                }
                                            } catch (e: CancellationException) { throw e }
                                            catch (e: Exception) { error = friendlyDeployError(e, "сравнение настроек") }
                                            finally { busy = false }
                                        }
                                    }
                                }
                                else -> {
                                    if (reviewedDraft != shown || review == null || verifiedAccess?.let { draft.sameServerAccess(it) } != true) {
                                        error = "Настройки изменились. Повторите проверку на предыдущем шаге."
                                        return@Button
                                    }
                                    busy = true
                                    scope.launch {
                                        try { onInstall(shown, kind) }
                                        catch (e: CancellationException) { throw e }
                                        catch (e: Exception) { error = friendlyDeployError(e, "подготовка установки") }
                                        finally { busy = false }
                                    }
                                }
                            }
                        },
                    ) {
                        if (busy) { CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary); Spacer(Modifier.width(8.dp)) }
                        Text(
                            if (busy) when (step) {
                                0 -> "Проверяю VPS…"
                                1 -> if (fresh) "Проверяю настройки…" else "Сравниваю настройки…"
                                else -> "Подготавливаю…"
                            } else when (step) {
                                0 -> "Далее"
                                1 -> "Далее"
                                else -> if (fresh) "Установить" else if (kind == ServerSetupKind.STANDALONE) "Продолжить" else "Продолжить"
                            }, maxLines = 1, overflow = TextOverflow.Ellipsis, textAlign = TextAlign.Center,
                        )
                    }
                }
            }
        },
    ) {
        SetupStepProgress(step = step, onSelect = ::openStep)
        when (step) {
            0 -> {
                Text("Доступ к вашему VPS", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                Text("Адрес и данные входа предоставляет VPS-провайдер. Проверка ничего не устанавливает и не меняет на сервере.", style = MaterialTheme.typography.bodySmall)
                SetupTextField(draft.host, { draft = draft.copy(host = it.filterNot(Char::isWhitespace)) }, "IP-адрес или домен", enabled = !busy)
                SetupTextField(draft.user, { draft = draft.copy(user = it.filterNot(Char::isWhitespace)) }, "Пользователь SSH · обычно root", enabled = !busy)
                SetupChoice("Вход на VPS", listOf("Пароль", "SSH-ключ"), if (draft.authMode == "key") 1 else 0, !busy) {
                    draft = draft.copy(authMode = if (it == 1) "key" else "password")
                }
                SetupSecretField(draft.sshPassword, { draft = draft.copy(sshPassword = it) },
                    if (draft.authMode == "key") "Пароль sudo · если требуется" else "Пароль входа на VPS", enabled = !busy)
                if (draft.authMode == "key") {
                    SetupSecretField(draft.privateKey, { draft = draft.copy(privateKey = it) }, "Приватный SSH-ключ", enabled = !busy, multiline = true)
                    SetupSecretField(draft.keyPassphrase, { draft = draft.copy(keyPassphrase = it) }, "Пароль SSH-ключа · необязательно", enabled = !busy)
                }
                SetupTextField(draft.sshPort, { draft = draft.copy(sshPort = it.filter(Char::isDigit).take(5)) }, "Порт SSH · по умолчанию 22", numeric = true, enabled = !busy)
            }
            1 -> {
                AppSectionCard {
                    Text(when (kind) {
                        ServerSetupKind.FRESH -> "WDTT на VPS не найден"
                        ServerSetupKind.EXISTING -> "WDTT уже установлен"
                        ServerSetupKind.PRESERVED -> "Найдены сохранённые данные WDTT"
                        ServerSetupKind.INCOMPLETE -> "Найдена незавершённая установка"
                        ServerSetupKind.RECOVERY -> "Найдена страховочная копия обновления"
                        ServerSetupKind.STANDALONE -> "Сервер установлен вручную"
                    }, fontWeight = FontWeight.Bold)
                    Text(if (fresh) "Доступ по SSH подтверждён. Пароль WDTT создан автоматически; при желании измените его."
                        else when (kind) {
                            ServerSetupKind.STANDALONE -> "Этот сервер обслуживается ручным установщиком. Здесь можно получить его настройки; установка и удаление из приложения запрещены. Нужен существующий пароль WDTT."
                            ServerSetupKind.PRESERVED -> "Клиенты и настройки сохранены. Укажите прежний пароль WDTT; на следующем шаге можно восстановить сервер с сохранением данных."
                            ServerSetupKind.INCOMPLETE -> "Повторная установка потребует отдельного подтверждения. Используйте ранее заданный пароль; если его ещё нет, создайте новый кнопкой генерации."
                            ServerSetupKind.RECOVERY -> "Сначала нужно проверить и разрешить прерванное обновление. Введите существующий пароль; приложение откроет безопасное восстановление."
                            else -> "Введите существующий пароль администратора WDTT. Перед обновлением приложение отдельно проверит установку и предложит сохранить данные."
                        }, style = MaterialTheme.typography.bodySmall)
                    SetupSecretField(draft.mainPassword, { draft = draft.copy(mainPassword = it.filterNot(Char::isWhitespace)) },
                        "Пароль администратора WDTT", onRegenerate = if (fresh || kind == ServerSetupKind.INCOMPLETE) ({ draft = draft.copy(mainPassword = generateServerAdminPassword()) }) else null, allowCopy = true)
                    Text("Это отдельный пароль WDTT, а не пароль VPS. Он даёт права администратора.", style = MaterialTheme.typography.bodySmall)
                }
                if (kind != ServerSetupKind.STANDALONE) {
                AppSectionCard {
                    SetupChoice("DNS сервера", listOf("По умолчанию", "Свой"), if (customDns) 1 else 0) { customDns = it == 1 }
                    Text("По умолчанию: 1.1.1.1 и 1.0.0.1", style = MaterialTheme.typography.bodySmall)
                    if (customDns) {
                        SetupTextField(draft.dns1, { draft = draft.copy(dns1 = it) }, "Основной DNS")
                        SetupTextField(draft.dns2, { draft = draft.copy(dns2 = it) }, "Резервный DNS · необязательно")
                    }
                }
                AppSectionCard {
                    SetupChoice("Порты", listOf("По умолчанию", "Свои"), if (customPorts) 1 else 0) { customPorts = it == 1 }
                    Text("WDTT: 56000 · WireGuard: 56001 · локальный: 9000", style = MaterialTheme.typography.bodySmall)
                    if (customPorts) {
                        SetupTextField(draft.dtlsPort, { draft = draft.copy(dtlsPort = it.filter(Char::isDigit).take(5)) }, "Порт WDTT", true)
                        SetupTextField(draft.wgPort, { draft = draft.copy(wgPort = it.filter(Char::isDigit).take(5)) }, "Порт WireGuard", true)
                        SetupTextField(draft.localPort, { draft = draft.copy(localPort = it.filter(Char::isDigit).take(5)) }, "Локальный порт в приложении", true)
                    }
                }
                AppSectionCard {
                    SetupChoice("Telegram-бот · необязательно", listOf(if (fresh) "Пропустить" else "Не менять", "Настроить"), if (useBot) 1 else 0) { useBot = it == 1 }
                    Text("Управление через приложение работает без бота.", style = MaterialTheme.typography.bodySmall)
                    if (useBot) {
                        SetupTextField(draft.adminId, { draft = draft.copy(adminId = it.trim()) }, "Telegram ID администратора", numeric = true)
                        SetupSecretField(draft.botToken, { draft = draft.copy(botToken = it.trim()) }, "Токен бота")
                    }
                }
                }
            }
            else -> {
                AppSectionCard {
                    Text(if (fresh) "Первая установка" else if (kind == ServerSetupKind.STANDALONE) "Подключение к готовому серверу" else "Проверка существующей установки", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    Text(shown.host, fontWeight = FontWeight.SemiBold)
                    Text("SSH: ${shown.user.ifBlank { "root" }} · порт ${shown.sshPort.ifBlank { "22" }}\nWDTT: ${shown.dtlsPort}\nWireGuard: ${shown.wgPort}\nDNS: ${shown.dns1}${if (shown.dns2.isBlank()) "" else ", ${shown.dns2}"}\nTelegram-бот: ${if (shown.adminId.isNotBlank()) "настроен" else if (fresh) "пропущен" else "без изменений"}")
                }
                if (!fresh && kind != ServerSetupKind.STANDALONE && kind != ServerSetupKind.RECOVERY) {
                    AppSectionCard {
                        Text("Изменения настроек", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                        val changes = review?.changes.orEmpty()
                        if (changes.isEmpty()) Text("Проверенные настройки совпадают. Серверная часть может обновиться.", style = MaterialTheme.typography.bodySmall)
                        else changes.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
                        review?.notes.orEmpty().forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
                    }
                }
                Text(if (fresh) "Приложение проверит совместимость, установит WDTT, настроит службу и необходимые правила сети. После установки покажет данные сервера и заполнит подключение в «Туннеле»."
                    else if (kind == ServerSetupKind.STANDALONE) "Будут сохранены только локальные поля подключения. Затем получите настройки готового сервера; на VPS ничего не изменяется." else "Следующий шаг проверит текущие данные. Обновление или удаление данных потребует отдельного подтверждения; автоматически ничего не будет заменено.", style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

@Composable
private fun SetupStepProgress(step: Int, onSelect: (Int) -> Unit) {
    LinearProgressIndicator(
        progress = { (step + 1) / 3f }, modifier = Modifier.fillMaxWidth().height(4.dp),
        color = MaterialTheme.colorScheme.primary,
        trackColor = MaterialTheme.colorScheme.surfaceVariant,
    )
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        listOf("Доступ", "Настройки", "Итог").forEachIndexed { index, name ->
            val selected = index == step
            val done = index < step
            Column(
                modifier = Modifier.weight(1f).clickable(
                    interactionSource = remember { MutableInteractionSource() }, indication = null,
                ) { onSelect(index) }.padding(vertical = 4.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Surface(
                    shape = CircleShape,
                    color = when {
                        selected -> MaterialTheme.colorScheme.primary
                        done -> MaterialTheme.colorScheme.primaryContainer
                        else -> MaterialTheme.colorScheme.surfaceVariant
                    },
                ) {
                    Box(Modifier.size(28.dp), contentAlignment = Alignment.Center) {
                        if (done) Icon(Icons.Default.Check, null, Modifier.size(17.dp), tint = MaterialTheme.colorScheme.onPrimaryContainer)
                        else Text("${index + 1}", style = MaterialTheme.typography.labelMedium,
                            color = if (selected) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                Text(name, maxLines = 1, overflow = TextOverflow.Ellipsis,
                    style = MaterialTheme.typography.labelSmall,
                    color = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun SetupTextField(value: String, onChange: (String) -> Unit, label: String, numeric: Boolean = false, enabled: Boolean = true) {
    OutlinedTextField(value, onChange, label = { Text(label) }, modifier = Modifier.fillMaxWidth(), singleLine = true,
        enabled = enabled, shape = androidx.compose.foundation.shape.RoundedCornerShape(16.dp),
        keyboardOptions = KeyboardOptions(keyboardType = if (numeric) KeyboardType.Number else KeyboardType.Text))
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SetupChoice(title: String, labels: List<String>, selected: Int, enabled: Boolean = true, onSelect: (Int) -> Unit) {
    Text(title, fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodyMedium)
    SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
        labels.forEachIndexed { index, label ->
            SegmentedButton(selected = selected == index, onClick = { onSelect(index) }, shape = SegmentedButtonDefaults.itemShape(index, labels.size),
                enabled = enabled, icon = { StableSegmentedButtonIcon(selected == index) }) { Text(label, style = MaterialTheme.typography.labelMedium) }
        }
    }
}

@Composable
internal fun FirstServerSetupResultDialog(draft: ServerSetupDraft, tunnelPrepared: Boolean, onFinish: () -> Unit) {
    val context = LocalContext.current
    val report = buildString {
        append("Сервер WDTT\nАдрес: ${draft.host}\nSSH: ${draft.user.ifBlank { "root" }} · ${draft.sshPort}\n")
        if (draft.sshPassword.isNotBlank()) append("Пароль SSH/sudo: ${draft.sshPassword}\n")
        if (draft.adminId.isNotBlank()) append("Telegram ID администратора: ${draft.adminId}\nТокен бота: ${draft.botToken}\n")
        append("Пароль администратора WDTT: ${draft.mainPassword}\nWDTT: ${draft.dtlsPort}\nWireGuard: ${draft.wgPort}\nЛокальный порт: ${draft.localPort}\nDNS: ${draft.dns1}, ${draft.dns2}")
    }
    SettingsDialogLayout(title = "Сервер установлен", secure = true, onDismiss = onFinish, footer = {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { copyServerSecret(context, "Данные вашего сервера", report) }, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Default.ContentCopy, null, Modifier.size(18.dp)); Spacer(Modifier.width(8.dp)); Text("Скопировать данные")
            }
        }
    }) {
        AppSectionCard {
            Text("Установка завершена", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text("SSH-доступ, пароль администратора и выбранные параметры уже сохранены в «Деплое».")
            Text(if (tunnelPrepared)
                "Адрес, пароль и порты заполнены в «Туннеле → Вручную». Добавьте ВК-хеши в настройках и подключитесь."
            else "Прежние настройки «Туннеля» сохранены. Для подключения к новому серверу используйте отдельный пустой профиль или измените подключение вручную.")
        }
        AppSectionCard {
            Text("Данные администратора", fontWeight = FontWeight.Bold)
            Text(report, style = MaterialTheme.typography.bodyMedium)
            if (draft.authMode == "key") Text("Для входа по SSH используйте свой ключ.", style = MaterialTheme.typography.bodySmall)
        }
        Text("Сохраните данные администратора: после закрытия они не будут показаны вместе. Не передавайте их клиентам.", style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
internal fun ServerWorkflowHelpDialog(onDismiss: () -> Unit) {
SettingsDialogLayout(title = "Установка и подключение", onDismiss = onDismiss) {
                Text("Установить", fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary)
                Text("На пустом профиле «Установка сервера» откроет мастер. Когда SSH-доступ и пароль WDTT уже заполнены, «Обновить сервер» сразу проверит VPS, покажет отличия и предложит обновление с сохранением данных или переустановку. «Изменить настройки» откроет мастер с текущими значениями. Если WDTT не найден, приложение предложит первую установку. После успешной первой установки SSH и параметры сохраняются автоматически. Пустой «Туннель» заполняется в режиме «Вручную»; остаётся добавить ВК-хеши. После закрытия данных сервера и отсчёта таймера приложение перейдёт на вкладку «Туннель», если вы не перешли в другой раздел или окно. Такой переход отменяет только переключение вкладки — пустое подключение всё равно заполняется. Обновление и переустановка не меняют подключение и не переключают вкладку. Прежнее подключение сохраняется. Новый пароль создаётся только для чистого VPS; удаление данных требует отдельного подтверждения.")
                Text("Подключить", fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary)
                Text("Считывает настройки уже работающего WDTT-сервера. Нужны SSH-доступ и существующий главный пароль администратора. Приложение покажет отличия и запросит подтверждение перед заменой локальных полей. На сервер ничего не записывается, доступы клиентов не меняются.")
                Text("Настройки выходного IP загружаются отдельно в блоке «Выходной IP и прокси». Диагностика сервера доступна по лупе; удаление — по значку корзины и только после отдельного подтверждения.")
            }
}
