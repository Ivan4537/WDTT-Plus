package com.wdtt.plus.ui

import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import com.wdtt.plus.SettingsStore
import com.wdtt.plus.ServerSetupCompletion
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay

internal class ServerInstallCompletionNavigation(
    val showSuccessBanner: MutableState<Boolean>,
    val successCountdown: MutableIntState,
    val successProfile: MutableState<Int?>,
    val firstInstallTunnelProfile: MutableState<Int?>,
    val firstInstallationProfile: MutableState<Int?>,
    val firstInstallationNavigationRevision: MutableState<Int?>,
    val firstInstallationNavigationCancelled: MutableState<Boolean>,
    val navigationRevision: State<Int>,
)

@Composable
internal fun rememberServerInstallCompletionNavigation(
    activeProfile: Int,
    navigationRevision: Int,
    visible: Boolean,
    pendingCompletionProfile: Int?,
    otherServerWindowOpen: Boolean,
    onOpenTunnel: (Int, Int) -> Unit,
): ServerInstallCompletionNavigation {
    val showSuccessBanner = rememberSaveable { mutableStateOf(false) }
    val successCountdown = rememberSaveable { mutableIntStateOf(5) }
    val successProfile = rememberSaveable { mutableStateOf<Int?>(null) }
    val firstInstallTunnelProfile = rememberSaveable { mutableStateOf<Int?>(null) }
    val firstInstallationProfile = rememberSaveable { mutableStateOf<Int?>(null) }
    val firstInstallationNavigationRevision = rememberSaveable { mutableStateOf<Int?>(null) }
    val firstInstallationNavigationCancelled = rememberSaveable { mutableStateOf(false) }
    val currentNavigationRevision = rememberUpdatedState(navigationRevision)
    val currentActiveProfile by rememberUpdatedState(activeProfile)
    val latestOnOpenTunnel by rememberUpdatedState(onOpenTunnel)
    val state = remember {
        ServerInstallCompletionNavigation(showSuccessBanner, successCountdown, successProfile,
            firstInstallTunnelProfile, firstInstallationProfile, firstInstallationNavigationRevision,
            firstInstallationNavigationCancelled, currentNavigationRevision)
    }
    LaunchedEffect(visible, activeProfile, navigationRevision, otherServerWindowOpen, firstInstallationProfile.value) {
        if (firstInstallationProfile.value != null &&
            (!canOpenInitialServerTunnel(firstInstallationProfile.value, firstInstallationNavigationRevision.value,
                activeProfile, navigationRevision, visible, firstInstallationNavigationCancelled.value) || otherServerWindowOpen)) {
            firstInstallationNavigationCancelled.value = true
            firstInstallTunnelProfile.value = null
        }
    }
    LaunchedEffect(showSuccessBanner.value, visible, activeProfile, pendingCompletionProfile, navigationRevision, otherServerWindowOpen) {
        if (showSuccessBanner.value && visible && successProfile.value == activeProfile && pendingCompletionProfile == null) {
            while (successCountdown.intValue > 0) {
                delay(1000)
                successCountdown.intValue--
            }
            showSuccessBanner.value = false
            if (firstInstallTunnelProfile.value == activeProfile && !otherServerWindowOpen &&
                canOpenInitialServerTunnel(firstInstallationProfile.value, firstInstallationNavigationRevision.value,
                    currentActiveProfile, currentNavigationRevision.value, visible, firstInstallationNavigationCancelled.value)) {
                firstInstallTunnelProfile.value = null
                latestOnOpenTunnel(activeProfile, currentNavigationRevision.value)
            }
        }
    }
    return state
}

@Composable
internal fun ServerSetupCompletionSection(
    settingsStore: SettingsStore,
    completion: ServerSetupCompletion?,
    activeProfile: Int,
    visible: Boolean,
    isDeploying: Boolean,
    navigation: ServerInstallCompletionNavigation,
    otherServerWindowOpen: Boolean,
) {
    val scope = rememberCoroutineScope()
    val currentActiveProfile by rememberUpdatedState(activeProfile)
    completion?.takeIf { visible && !isDeploying && it.profileIndex == activeProfile }?.let { completed ->
        val draft = ServerSetupDraft(host = completed.host, user = completed.user,
            sshPassword = completed.sshPassword, sshPort = completed.sshPort, authMode = completed.authMode,
            mainPassword = completed.mainPassword, dns1 = completed.dns1, dns2 = completed.dns2,
            dtlsPort = completed.dtlsPort.toString(), wgPort = completed.wgPort.toString(), localPort = completed.localPort.toString(),
            adminId = completed.adminId, botToken = completed.botToken)
        FirstServerSetupResultDialog(draft, tunnelPrepared = completed.tunnelPrepared,
            onFinish = {
                scope.launch {
                    settingsStore.dismissServerSetupCompletion(completed.profileIndex)
                    if (currentActiveProfile != completed.profileIndex) return@launch
                    navigation.successProfile.value = completed.profileIndex
                    navigation.firstInstallTunnelProfile.value = completed.profileIndex.takeIf {
                        !otherServerWindowOpen && canOpenInitialServerTunnel(navigation.firstInstallationProfile.value,
                            navigation.firstInstallationNavigationRevision.value, currentActiveProfile, navigation.navigationRevision.value,
                            visible, navigation.firstInstallationNavigationCancelled.value)
                    }
                    navigation.successCountdown.intValue = 5
                    navigation.showSuccessBanner.value = true
                }
            })
    }
}
