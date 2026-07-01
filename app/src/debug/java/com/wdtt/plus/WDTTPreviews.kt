package com.wdtt.plus

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.wdtt.plus.ui.DeployTab
import com.wdtt.plus.ui.InfoTab
import com.wdtt.plus.ui.LogsTab
import com.wdtt.plus.ui.SettingsTab

@Composable
private fun PreviewScreen(content: @Composable () -> Unit) {
    WDTTTheme(themeMode = "dark", dynamicColor = false, themePalette = "indigo") {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(MaterialTheme.colorScheme.background)
                .padding(top = 12.dp)
        ) {
            content()
        }
    }
}

@Preview(
    name = "Deploy Tab",
    showBackground = true,
    widthDp = 393,
    heightDp = 852
)
@Composable
private fun DeployTabPreview() {
    PreviewScreen {
        DeployTab()
    }
}

@Preview(
    name = "Info Tab",
    showBackground = true,
    widthDp = 393,
    heightDp = 852
)
@Composable
private fun InfoTabPreview() {
    PreviewScreen {
        InfoTab()
    }
}

@Preview(
    name = "Tunnel Tab",
    showBackground = true,
    widthDp = 393,
    heightDp = 852
)
@Composable
private fun TunnelTabPreview() {
    PreviewScreen {
        SettingsTab()
    }
}

@Preview(
    name = "Logs Tab",
    showBackground = true,
    widthDp = 393,
    heightDp = 852
)
@Composable
private fun LogsTabPreview() {
    PreviewScreen {
        LogsTab()
    }
}
