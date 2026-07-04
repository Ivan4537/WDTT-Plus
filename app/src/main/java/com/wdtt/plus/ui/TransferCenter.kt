package com.wdtt.plus.ui

import android.Manifest
import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.net.Uri
import android.os.Build
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.InsertDriveFile
import androidx.compose.material.icons.filled.CameraAlt
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.QrCode2
import androidx.compose.material.icons.filled.SaveAlt
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.wdtt.plus.SettingsStore
import com.wdtt.plus.TransferFiles
import com.wdtt.plus.WdttTransferCodec
import com.wdtt.plus.QrCaptureActivity
import com.wdtt.plus.vpnProfileDisplayName
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private enum class AdminExportAction { Qr, File }

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun TransferCenterDialog(
    settingsStore: SettingsStore,
    activeProfile: Int,
    isAdmin: Boolean,
    onIncomingContent: (String) -> Unit,
    onDismiss: () -> Unit
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var qrData by remember { mutableStateOf<Pair<String, Bitmap>?>(null) }
    var adminAction by remember { mutableStateOf<AdminExportAction?>(null) }
    val profileNames by settingsStore.profileNames.collectAsStateWithLifecycle(initialValue = emptyList())
    val activeProfileLabel = vpnProfileDisplayName(activeProfile, profileNames)

    fun runCatchingUi(block: suspend () -> Unit) {
        busy = true
        error = null
        scope.launch {
            runCatching { block() }
                .onFailure { error = it.message ?: "Не удалось выполнить передачу." }
            busy = false
        }
    }

    val cameraLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        result.contents?.takeIf { it.isNotBlank() }?.let(onIncomingContent)
    }
    val galleryLauncher = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) runCatchingUi {
            val text = withContext(Dispatchers.IO) { TransferFiles.decodeQrImage(context, uri) }
            onIncomingContent(text)
        }
    }
    val fileLauncher = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) runCatchingUi {
            val text = withContext(Dispatchers.IO) { TransferFiles.readText(context, uri) }
            onIncomingContent(text)
        }
    }

    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        properties = DialogProperties(usePlatformDefaultWidth = false),
        modifier = Modifier.fillMaxWidth(0.94f),
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Box(modifier = Modifier.fillMaxWidth()) {
                    IconButton(
                        onClick = onDismiss,
                        enabled = !busy,
                        modifier = Modifier.align(androidx.compose.ui.Alignment.CenterEnd).size(32.dp)
                    ) {
                        Icon(Icons.Default.Close, contentDescription = "Закрыть", modifier = Modifier.size(20.dp))
                    }
                }
                Text("Получение VPN", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                FlowRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    TransferButton("Камера", Icons.Default.CameraAlt, busy) {
                        cameraLauncher.launch(
                            ScanOptions()
                                .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                                .setPrompt("Наведите камеру на QR-код WDTT Plus")
                                .setBeepEnabled(false)
                                .setCaptureActivity(QrCaptureActivity::class.java)
                                .setOrientationLocked(false)
                        )
                    }
                    TransferButton("Галерея", Icons.Default.Image, busy) { galleryLauncher.launch("image/*") }
                    TransferButton("Файл", Icons.Default.FileOpen, busy) { fileLauncher.launch("*/*") }
                }

                HorizontalDivider()
                Text("Передача $activeProfileLabel", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                Text(
                    "Ссылка содержит пароль подключения и VK-хеши. Передавайте её только тому, кому доверяете.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                FlowRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    TransferButton("QR", Icons.Default.QrCode2, busy) {
                        runCatchingUi {
                            val link = settingsStore.connectionLinkForProfile(activeProfile)
                            val bitmap = withContext(Dispatchers.Default) { TransferFiles.createQrBitmap(context, link) }
                            qrData = activeProfileLabel to bitmap
                        }
                    }
                    TransferButton("Ссылка", Icons.Default.Share, busy) {
                        runCatchingUi {
                            shareText(context, settingsStore.connectionLinkForProfile(activeProfile))
                        }
                    }
                    TransferButton("Файл", Icons.AutoMirrored.Filled.InsertDriveFile, busy) {
                        runCatchingUi {
                            val link = settingsStore.connectionLinkForProfile(activeProfile)
                            val uri = withContext(Dispatchers.IO) {
                                TransferFiles.writeTransferText(context, "WDTT-Plus-${activeProfileLabel.safeTransferFileName()}.wdtt", link)
                            }
                            shareUri(context, uri, "application/vnd.wdtt.plus.transfer", "Передать подключение WDTT Plus")
                        }
                    }
                }

                if (isAdmin) {
                    HorizontalDivider()
                    Text("Настройки администратора", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    Text(
                        "Все три VPN-профиля, параметры деплоя, пароли, токен бота, исключения и настройки выхода. Данные шифруются указанным паролем.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            onClick = { adminAction = AdminExportAction.Qr },
                            enabled = !busy,
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(Icons.Default.QrCode2, null, Modifier.size(18.dp))
                            Text(" QR")
                        }
                        OutlinedButton(
                            onClick = { adminAction = AdminExportAction.File },
                            enabled = !busy,
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(Icons.AutoMirrored.Filled.InsertDriveFile, null, Modifier.size(18.dp))
                            Text(" Файл")
                        }
                    }
                }

                error?.let {
                    Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
                if (busy) Text("Подготавливаю…", style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = {}
    )

    adminAction?.let { action ->
        AdminExportPasswordDialog(
            onDismiss = { adminAction = null },
            onConfirm = { password ->
                adminAction = null
                runCatchingUi {
                    val plain = settingsStore.exportAdminSettings()
                    val encrypted = try {
                        withContext(Dispatchers.Default) {
                            WdttTransferCodec.encryptAdminSettings(plain, password)
                        }
                    } finally {
                        password.fill('\u0000')
                    }
                    when (action) {
                        AdminExportAction.Qr -> {
                            val bitmap = withContext(Dispatchers.Default) { TransferFiles.createQrBitmap(context, encrypted) }
                            qrData = "Настройки администратора" to bitmap
                        }
                        AdminExportAction.File -> {
                            val stamp = SimpleDateFormat("yyyyMMdd-HHmm", Locale.US).format(Date())
                            val uri = withContext(Dispatchers.IO) {
                                TransferFiles.writeTransferText(context, "WDTT-Plus-admin-$stamp.wdtt-backup", encrypted)
                            }
                            shareUri(context, uri, "application/vnd.wdtt.plus.transfer", "Передать настройки WDTT Plus")
                        }
                    }
                }
            }
        )
    }

    qrData?.let { (title, bitmap) ->
        QrDisplayDialog(
            title = title,
            bitmap = bitmap,
            onDismiss = { qrData = null },
            onShare = {
                runCatchingUi {
                    val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
                    val fileName = "WDTT-Plus-QR-${title.safeQrFileName()}-$stamp.png"
                    val uri = withContext(Dispatchers.IO) {
                        TransferFiles.writeQrPng(context, fileName, bitmap)
                    }
                    shareUri(context, uri, "image/png", "Передать QR-код WDTT Plus")
                }
            },
            onSave = {
                scope.launch {
                    val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
                    runCatching {
                        withContext(Dispatchers.IO) {
                            TransferFiles.saveQrToGallery(context, "WDTT-Plus-QR-$stamp.png", bitmap)
                        }
                    }.onSuccess {
                        Toast.makeText(context, "QR-код сохранён в галерею.", Toast.LENGTH_SHORT).show()
                    }.onFailure {
                        Toast.makeText(context, it.message ?: "Не удалось сохранить QR-код.", Toast.LENGTH_LONG).show()
                    }
                }
            }
        )
    }
}

@Composable
fun AdminImportDialog(
    settingsStore: SettingsStore,
    encryptedDocument: String,
    onFinished: (String) -> Unit,
    onDismiss: () -> Unit
) {
    val scope = rememberCoroutineScope()
    val preview = remember(encryptedDocument) { runCatching { WdttTransferCodec.previewAdminTransfer(encryptedDocument) }.getOrNull() }
    var password by remember { mutableStateOf("") }
    var passwordFocused by remember { mutableStateOf(false) }
    var decrypted by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text(if (decrypted == null) "Защищённые настройки" else "Заменить настройки?") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                if (decrypted == null) {
                    Text("Источник: WDTT Plus ${preview?.sourceVersion ?: "?"}. Для расшифровки введите пароль, заданный при передаче.")
                    OutlinedTextField(
                        value = password,
                        onValueChange = { password = it; error = null },
                        label = { Text("Пароль файла") },
                        visualTransformation = if (passwordFocused) VisualTransformation.None else PasswordVisualTransformation(),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().onFocusChanged { passwordFocused = it.isFocused }
                    )
                } else {
                    Text("Будут заменены все три VPN-профиля и локальные настройки администратора. Текущие данные приложения восстановить автоматически не получится.")
                }
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = {
            Button(
                enabled = !busy && (decrypted != null || password.isNotEmpty()),
                onClick = {
                    busy = true
                    error = null
                    scope.launch {
                        if (decrypted == null) {
                            runCatching {
                                withContext(Dispatchers.Default) {
                                    val chars = password.toCharArray()
                                    try {
                                        WdttTransferCodec.decryptAdminSettings(encryptedDocument, chars)
                                    } finally {
                                        chars.fill('\u0000')
                                    }
                                }
                            }.onSuccess {
                                decrypted = it
                                password = ""
                            }.onFailure { error = it.message ?: "Не удалось расшифровать настройки." }
                            busy = false
                        } else {
                            runCatching { settingsStore.importAdminSettings(decrypted!!) }
                                .onSuccess { onFinished("Настройки администратора импортированы. Активирован режим администратора.") }
                                .onFailure { error = it.message ?: "Не удалось импортировать настройки." }
                            busy = false
                        }
                    }
                }
            ) { Text(if (decrypted == null) "Проверить" else "Заменить") }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !busy) { Text("Отмена") } }
    )
}

@Composable
private fun AdminExportPasswordDialog(onDismiss: () -> Unit, onConfirm: (CharArray) -> Unit) {
    var password by remember { mutableStateOf("") }
    var repeat by remember { mutableStateOf("") }
    var passwordFocused by remember { mutableStateOf(false) }
    var repeatFocused by remember { mutableStateOf(false) }
    val error = when {
        password.isNotEmpty() && password.length < 8 -> "Минимум 8 символов"
        repeat.isNotEmpty() && password != repeat -> "Пароли не совпадают"
        else -> null
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Защитить настройки") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Пароль не сохраняется. Передайте его получателю отдельно.")
                OutlinedTextField(
                    password,
                    { password = it },
                    label = { Text("Пароль") },
                    visualTransformation = if (passwordFocused) VisualTransformation.None else PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().onFocusChanged { passwordFocused = it.isFocused }
                )
                OutlinedTextField(
                    repeat,
                    { repeat = it },
                    label = { Text("Повторите пароль") },
                    visualTransformation = if (repeatFocused) VisualTransformation.None else PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().onFocusChanged { repeatFocused = it.isFocused }
                )
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = {
            Button(onClick = { onConfirm(password.toCharArray()); password = ""; repeat = "" }, enabled = password.length >= 8 && password == repeat) {
                Text("Продолжить")
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена") } }
    )
}

@Composable
private fun QrDisplayDialog(
    title: String,
    bitmap: Bitmap,
    onDismiss: () -> Unit,
    onShare: () -> Unit,
    onSave: () -> Unit
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val permissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) onSave()
        else Toast.makeText(context, "Без разрешения Android 9 не может сохранить QR-код в галерею.", Toast.LENGTH_LONG).show()
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = androidx.compose.ui.Alignment.CenterVertically
                ) {
                    Text(title, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                    IconButton(onClick = onDismiss, modifier = Modifier.size(32.dp)) {
                        Icon(Icons.Default.Close, contentDescription = "Закрыть", modifier = Modifier.size(20.dp))
                    }
                }
                Image(bitmap = bitmap.asImageBitmap(), contentDescription = "QR-код WDTT Plus", modifier = Modifier.fillMaxWidth())
                Text("QR содержит секретные данные. Не публикуйте изображение.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        modifier = Modifier.weight(1f).heightIn(min = 48.dp),
                        contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 8.dp),
                        onClick = {
                            if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.P &&
                                ContextCompat.checkSelfPermission(context, Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED
                            ) {
                                permissionLauncher.launch(Manifest.permission.WRITE_EXTERNAL_STORAGE)
                            } else {
                                onSave()
                            }
                        }
                    ) {
                        Icon(Icons.Default.SaveAlt, null, Modifier.size(18.dp))
                        Text(" Сохранить", maxLines = 1)
                    }
                    Button(
                        onClick = onShare,
                        modifier = Modifier.weight(1f).heightIn(min = 48.dp),
                        contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 8.dp)
                    ) {
                        Icon(Icons.Default.Share, null, Modifier.size(18.dp))
                        Text(" Поделиться", maxLines = 1)
                    }
                }
            }
        },
        confirmButton = {}
    )
}

@Composable
private fun TransferButton(label: String, icon: androidx.compose.ui.graphics.vector.ImageVector, busy: Boolean, onClick: () -> Unit) {
    OutlinedButton(onClick = onClick, enabled = !busy) {
        Icon(icon, null, Modifier.size(18.dp))
        Text(" $label")
    }
}

private fun shareText(context: Context, text: String) {
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, text)
    }
    context.startActivity(Intent.createChooser(intent, "Передать подключение WDTT Plus"))
}

private fun String.safeQrFileName(): String =
    replace(Regex("[^\\p{L}\\p{N}._-]+"), "-")
        .replace(Regex("-+"), "-")
        .trim('_', '.', '-')
        .take(48)
        .trim('_', '.', '-')
        .ifBlank { "qr" }

private fun String.safeTransferFileName(): String =
    replace(Regex("[^\\p{L}\\p{N}._-]+"), "-")
        .replace(Regex("-+"), "-")
        .trim('_', '.', '-')
        .take(48)
        .trim('_', '.', '-')
        .ifBlank { "VPN" }

private fun shareUri(context: Context, uri: Uri, mimeType: String, title: String) {
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = mimeType
        putExtra(Intent.EXTRA_STREAM, uri)
        clipData = ClipData.newUri(context.contentResolver, title, uri)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    context.startActivity(Intent.createChooser(intent, title))
}
