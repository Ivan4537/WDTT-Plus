package com.wdtt.plus.ui

import android.os.Build
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.material3.ButtonColors
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ButtonElevation
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.LocalTextStyle
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.graphics.BlendMode
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.graphicsLayer

/**
 * Filled button used throughout the app.
 *
 * Some MIUI builds keep the surrounding text style color when Material 3
 * changes a button's content color. Icons then use the intended contrasting
 * color, while labels remain almost indistinguishable from the background.
 * The workaround is deliberately limited to Xiaomi-family firmware. Every
 * other device receives Material's original content without another layout or
 * color layer.
 */
@Composable
internal fun Button(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    shape: Shape = ButtonDefaults.shape,
    colors: ButtonColors = ButtonDefaults.buttonColors(),
    elevation: ButtonElevation? = ButtonDefaults.buttonElevation(),
    border: BorderStroke? = null,
    contentPadding: PaddingValues = ButtonDefaults.ContentPadding,
    interactionSource: MutableInteractionSource? = null,
    content: @Composable RowScope.() -> Unit,
) {
    val needsMiuiWorkaround = needsMiuiFilledButtonContrastWorkaround(
        manufacturer = Build.MANUFACTURER.orEmpty(),
        brand = Build.BRAND.orEmpty(),
    )
    androidx.compose.material3.Button(
        onClick = onClick,
        modifier = modifier,
        enabled = enabled,
        shape = shape,
        colors = colors,
        elevation = elevation,
        border = border,
        contentPadding = contentPadding,
        interactionSource = interactionSource,
    ) {
        if (!needsMiuiWorkaround) {
            content()
        } else {
            val resolvedContentColor = if (enabled) colors.contentColor else colors.disabledContentColor
            CompositionLocalProvider(
                LocalContentColor provides resolvedContentColor,
                LocalTextStyle provides LocalTextStyle.current.copy(color = resolvedContentColor),
            ) {
                Row(
                    modifier = Modifier
                        .graphicsLayer {
                            compositingStrategy = androidx.compose.ui.graphics.CompositingStrategy.Offscreen
                        }
                        .drawWithContent {
                            drawContent()
                            drawRect(
                                color = resolvedContentColor.copy(alpha = 1f),
                                blendMode = BlendMode.SrcIn,
                            )
                        },
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    content()
                }
            }
        }
    }
}

internal fun needsMiuiFilledButtonContrastWorkaround(
    manufacturer: String,
    brand: String,
): Boolean {
    val normalizedManufacturer = manufacturer.trim().lowercase()
    val normalizedBrand = brand.trim().lowercase()
    return normalizedManufacturer in XIAOMI_DEVICE_NAMES ||
        normalizedBrand in XIAOMI_DEVICE_NAMES
}

private val XIAOMI_DEVICE_NAMES = setOf("xiaomi", "redmi", "poco")
