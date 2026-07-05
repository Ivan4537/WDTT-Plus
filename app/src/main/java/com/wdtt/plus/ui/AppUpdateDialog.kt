package com.wdtt.plus.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Update
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.wdtt.plus.AppReleaseInfo
import com.wdtt.plus.AppReleaseAsset
import com.wdtt.plus.AppUpdateDownloadProgress
import com.wdtt.plus.AppUpdateKind
import com.wdtt.plus.RemoteVersionSource

@Composable
fun AppUpdateDialog(
    release: AppReleaseInfo,
    updateKind: AppUpdateKind = AppUpdateKind.NewVersion,
    apkAsset: AppReleaseAsset?,
    isDownloading: Boolean,
    downloadProgress: AppUpdateDownloadProgress?,
    downloadStatus: String,
    onPostpone: () -> Unit,
    onUpdate: () -> Unit,
    onOpenRelease: () -> Unit
) {
    val isTagOnly = release.source == RemoteVersionSource.Tag
    val isSameVersionFix = updateKind == AppUpdateKind.SameVersionFix
    val title = when {
        isSameVersionFix -> "Доступно исправление"
        isTagOnly -> "Найден новый tag"
        else -> "Доступно обновление"
    }
    val canDownloadInApp = !isTagOnly && apkAsset != null
    val description = when {
        isSameVersionFix && canDownloadInApp ->
            "Версия ${release.versionTag} не изменилась, но APK в релизе обновлён. Это исправление текущей версии; WDTT Plus скачает подходящий файл и откроет установку Android."
        isSameVersionFix ->
            "Версия ${release.versionTag} не изменилась, но APK в релизе обновлён. Не удалось подобрать файл для этого устройства, можно открыть страницу релиза."
        isTagOnly ->
            "На GitHub обнаружен более новый tag ${release.versionTag}. Похоже, опубликованный release ещё не догнал его."
        canDownloadInApp ->
            "Вышла новая версия приложения ${release.versionTag}. WDTT Plus скачает подходящий APK и откроет системное окно установки Android."
        else ->
            "Вышла новая версия приложения ${release.versionTag}. Не удалось подобрать APK для этого устройства, можно открыть страницу релиза."
    }
    val primaryLabel = when {
        isDownloading -> "Скачивается..."
        canDownloadInApp -> "Скачать"
        else -> "Открыть"
    }

    Dialog(
        onDismissRequest = {},
        properties = DialogProperties(
            usePlatformDefaultWidth = false,
            dismissOnBackPress = false,
            dismissOnClickOutside = false
        )
    ) {
        Surface(
            shape = RoundedCornerShape(28.dp),
            color = MaterialTheme.colorScheme.surface,
            contentColor = MaterialTheme.colorScheme.onSurface,
            tonalElevation = 8.dp,
            modifier = Modifier.fillMaxWidth(0.92f)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 22.dp, vertical = 20.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Update,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(Modifier.width(10.dp))
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(
                            text = title,
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            text = release.versionTag,
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }

                Text(
                    text = description,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    lineHeight = 20.sp
                )

                if (canDownloadInApp) {
                    Text(
                        text = "Файл: ${apkAsset.name}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        lineHeight = 18.sp
                    )
                }

                if (isDownloading || downloadProgress != null || downloadStatus.isNotBlank()) {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        if (isDownloading) {
                            val fraction = downloadProgress?.fraction
                            if (fraction != null) {
                                LinearProgressIndicator(
                                    progress = { fraction },
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .height(8.dp)
                                        .clip(RoundedCornerShape(4.dp))
                                )
                            } else {
                                LinearProgressIndicator(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .height(8.dp)
                                        .clip(RoundedCornerShape(4.dp))
                                )
                            }
                        }
                        val progressText = downloadProgress?.percent?.let { " $it%" }.orEmpty()
                        if (downloadStatus.isNotBlank() || progressText.isNotBlank()) {
                            Text(
                                text = "${downloadStatus.ifBlank { "Скачивание..." }}$progressText",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                lineHeight = 18.sp
                            )
                        }
                    }
                }

                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.35f))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    OutlinedButton(
                        onClick = onPostpone,
                        enabled = !isDownloading,
                        modifier = Modifier
                            .weight(1f)
                            .heightIn(min = 50.dp),
                        shape = RoundedCornerShape(22.dp)
                    ) {
                        Text("Позже", fontWeight = FontWeight.SemiBold)
                    }

                    Button(
                        onClick = onUpdate,
                        enabled = !isDownloading,
                        modifier = Modifier
                            .weight(1f)
                            .heightIn(min = 50.dp),
                        shape = RoundedCornerShape(22.dp)
                    ) {
                        Text(primaryLabel, fontWeight = FontWeight.Bold)
                    }
                }

                if (!isTagOnly) {
                    TextButton(
                        onClick = onOpenRelease,
                        enabled = !isDownloading,
                        modifier = Modifier.align(Alignment.CenterHorizontally)
                    ) {
                        Text("Открыть GitHub вручную")
                    }
                }
            }
        }
    }
}
