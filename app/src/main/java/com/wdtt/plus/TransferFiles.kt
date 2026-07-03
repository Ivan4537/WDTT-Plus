package com.wdtt.plus

import android.content.Context
import android.content.ContentValues
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.ImageDecoder
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RectF
import android.graphics.Typeface
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import androidx.core.content.FileProvider
import androidx.core.content.ContextCompat
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.InvertedLuminanceSource
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.io.File
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

object TransferFiles {
    private const val MAX_TRANSFER_BYTES = 5 * 1024 * 1024
    const val MAX_QR_TEXT_BYTES = 2_600

    fun createQrBitmap(context: Context, text: String, size: Int = 900): Bitmap {
        require(text.toByteArray(StandardCharsets.UTF_8).size <= MAX_QR_TEXT_BYTES) {
            "Эти данные слишком велики для одного QR-кода. Передайте их файлом."
        }
        val icon = loadAppIcon(context)
        val highCorrection = runCatching {
            createQrMatrix(text, size, ErrorCorrectionLevel.H)
        }.getOrNull()
        if (highCorrection != null) {
            val plain = renderQr(highCorrection, size)
            val branded = drawCenteredIcon(plain, icon)
            if (runCatching { decodeQrBitmap(branded) }.getOrNull() == text) return branded
        }

        val compact = renderQr(createQrMatrix(text, size, ErrorCorrectionLevel.L), size)
        return drawFooter(compact, icon)
    }

    private fun createQrMatrix(text: String, size: Int, correction: ErrorCorrectionLevel) =
        QRCodeWriter().encode(
            text,
            BarcodeFormat.QR_CODE,
            size,
            size,
            mapOf(
                com.google.zxing.EncodeHintType.CHARACTER_SET to "UTF-8",
                com.google.zxing.EncodeHintType.ERROR_CORRECTION to correction,
                com.google.zxing.EncodeHintType.MARGIN to 2
            )
        )

    private fun renderQr(matrix: com.google.zxing.common.BitMatrix, size: Int): Bitmap {
        val pixels = IntArray(size * size)
        for (y in 0 until size) {
            val offset = y * size
            for (x in 0 until size) {
                pixels[offset + x] = if (matrix[x, y]) Color.BLACK else Color.WHITE
            }
        }
        return Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888).apply {
            setPixels(pixels, 0, size, 0, 0, size, size)
        }
    }

    private fun drawCenteredIcon(qr: Bitmap, icon: Bitmap): Bitmap {
        val result = qr.copy(Bitmap.Config.ARGB_8888, true)
        val canvas = Canvas(result)
        val iconSize = (qr.width * 0.075f).toInt()
        val plateSize = (iconSize * 1.22f).toInt()
        val centerX = qr.width / 2f
        val centerY = qr.height / 2f
        canvas.drawCircle(
            centerX,
            centerY,
            plateSize / 2f,
            Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.WHITE }
        )
        val iconLeft = (qr.width - iconSize) / 2f
        val iconTop = (qr.height - iconSize) / 2f
        val iconBounds = RectF(iconLeft, iconTop, iconLeft + iconSize, iconTop + iconSize)
        canvas.save()
        canvas.clipPath(Path().apply { addOval(iconBounds, Path.Direction.CW) })
        canvas.drawBitmap(icon, null, iconBounds, Paint(Paint.ANTI_ALIAS_FLAG or Paint.FILTER_BITMAP_FLAG))
        canvas.restore()
        return result
    }

    private fun loadAppIcon(context: Context): Bitmap {
        val drawable = ContextCompat.getDrawable(context, R.mipmap.ic_launcher)?.mutate()
            ?: throw IllegalStateException("Не удалось загрузить иконку WDTT Plus.")
        val size = 192
        return Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888).also { bitmap ->
            val canvas = Canvas(bitmap)
            drawable.setBounds(0, 0, size, size)
            drawable.draw(canvas)
        }
    }

    private fun drawFooter(qr: Bitmap, icon: Bitmap): Bitmap {
        val footerHeight = (qr.width * 0.13f).toInt()
        val result = Bitmap.createBitmap(qr.width, qr.height + footerHeight, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(result)
        canvas.drawColor(Color.WHITE)
        canvas.drawBitmap(qr, 0f, 0f, null)
        val iconSize = (footerHeight * 0.56f).toInt()
        val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.rgb(35, 35, 45)
            textSize = footerHeight * 0.30f
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        }
        val label = "WDTT Plus"
        val spacing = footerHeight * 0.14f
        val groupWidth = iconSize + spacing + textPaint.measureText(label)
        val iconLeft = (qr.width - groupWidth) / 2f
        val iconTop = qr.height + (footerHeight - iconSize) / 2f
        canvas.drawBitmap(icon, null, RectF(iconLeft, iconTop, iconLeft + iconSize, iconTop + iconSize), Paint(Paint.ANTI_ALIAS_FLAG))
        val textX = iconLeft + iconSize + spacing
        val textY = qr.height + footerHeight / 2f - (textPaint.ascent() + textPaint.descent()) / 2f
        canvas.drawText(label, textX, textY, textPaint)
        return result
    }

    fun decodeQrImage(context: Context, uri: Uri): String {
        val source = ImageDecoder.createSource(context.contentResolver, uri)
        val bitmap = ImageDecoder.decodeBitmap(source) { decoder, info, _ ->
            decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
            val width = info.size.width
            val height = info.size.height
            val longest = maxOf(width, height)
            if (longest > 2400) {
                val scale = 2400f / longest
                decoder.setTargetSize((width * scale).toInt(), (height * scale).toInt())
            }
        }.copy(Bitmap.Config.ARGB_8888, false)
        return decodeQrBitmap(bitmap)
    }

    private fun decodeQrBitmap(bitmap: Bitmap): String {
        val pixels = IntArray(bitmap.width * bitmap.height)
        bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)
        val sourcePixels = RGBLuminanceSource(bitmap.width, bitmap.height, pixels)
        val hints = mapOf(
            DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
            DecodeHintType.TRY_HARDER to true,
            DecodeHintType.CHARACTER_SET to "UTF-8"
        )
        val reader = MultiFormatReader().apply { setHints(hints) }
        return runCatching {
            reader.decodeWithState(BinaryBitmap(HybridBinarizer(sourcePixels))).text
        }.recoverCatching {
            reader.reset()
            reader.setHints(hints)
            reader.decodeWithState(BinaryBitmap(HybridBinarizer(InvertedLuminanceSource(sourcePixels)))).text
        }.getOrElse {
            throw IllegalArgumentException("На выбранном изображении не найден читаемый QR-код.")
        }.also { reader.reset() }
    }

    fun readText(context: Context, uri: Uri): String {
        val bytes = context.contentResolver.openInputStream(uri)?.use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            var total = 0
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                total += count
                require(total <= MAX_TRANSFER_BYTES) { "Файл передачи слишком большой." }
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        } ?: throw IllegalArgumentException("Не удалось открыть выбранный файл.")
        return bytes.toString(StandardCharsets.UTF_8).removePrefix("\uFEFF").trim()
    }

    fun writeTransferText(context: Context, fileName: String, text: String): Uri {
        val directory = File(context.cacheDir, "transfers").apply { mkdirs() }
        directory.listFiles()?.forEach { file ->
            if (System.currentTimeMillis() - file.lastModified() > 24L * 60L * 60L * 1000L) file.delete()
        }
        val safeName = fileName.toSafeTransferFileName("WDTT-Plus-transfer")
        val file = File(directory, safeName).apply { writeText(text, Charsets.UTF_8) }
        return FileProvider.getUriForFile(context, "${context.packageName}.files", file)
    }

    fun writeQrPng(context: Context, fileName: String, bitmap: Bitmap): Uri {
        val directory = File(context.cacheDir, "transfers").apply { mkdirs() }
        val safeName = fileName.toSafeTransferFileName("WDTT-Plus-QR.png")
        val file = File(directory, safeName)
        file.outputStream().use { output ->
            require(bitmap.compress(Bitmap.CompressFormat.PNG, 100, output)) { "Не удалось создать изображение QR-кода." }
        }
        return FileProvider.getUriForFile(context, "${context.packageName}.files", file)
    }

    fun saveQrToGallery(context: Context, fileName: String, bitmap: Bitmap): Uri {
        val values = ContentValues().apply {
            put(MediaStore.Images.Media.DISPLAY_NAME, fileName)
            put(MediaStore.Images.Media.MIME_TYPE, "image/png")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                put(MediaStore.Images.Media.RELATIVE_PATH, "${Environment.DIRECTORY_PICTURES}/WDTT Plus")
                put(MediaStore.Images.Media.IS_PENDING, 1)
            }
        }
        val collection = MediaStore.Images.Media.EXTERNAL_CONTENT_URI
        val uri = context.contentResolver.insert(collection, values)
            ?: throw IllegalStateException("Не удалось создать изображение в галерее.")
        try {
            context.contentResolver.openOutputStream(uri)?.use { output ->
                require(bitmap.compress(Bitmap.CompressFormat.PNG, 100, output)) {
                    "Не удалось сохранить QR-код."
                }
            } ?: throw IllegalStateException("Не удалось открыть файл изображения.")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                values.clear()
                values.put(MediaStore.Images.Media.IS_PENDING, 0)
                context.contentResolver.update(uri, values, null, null)
            }
            return uri
        } catch (error: Exception) {
            context.contentResolver.delete(uri, null, null)
            throw error
        }
    }

    private fun String.toSafeTransferFileName(fallback: String): String =
        replace(Regex("[^\\p{L}\\p{N}._-]+"), "-")
            .replace(Regex("-+"), "-")
            .trim('-', '.', '_')
            .ifBlank { fallback }
}
