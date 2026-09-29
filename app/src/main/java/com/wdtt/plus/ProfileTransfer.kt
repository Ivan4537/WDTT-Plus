package com.wdtt.plus

import android.content.Context
import android.os.Build
import kotlinx.coroutines.flow.first
import java.util.TimeZone

data class ProfileTransferState(
    val managed: Boolean,
    val capability: RemoteAccessCapability,
    val revision: Long,
    val message: String,
)

internal fun RemoteProfileAction.isUsableFor(
    state: ProfileTransferState,
    nowSeconds: Long = System.currentTimeMillis() / 1000L,
): Boolean = state.managed && state.capability.available &&
    binding == state.capability.binding && expiresAtSeconds > nowSeconds

/** A cached lifecycle decision is deliberately insufficient to expose this action. */
internal suspend fun fetchProfileTransferAction(
    context: Context,
    store: SettingsStore,
    profile: Int,
    expected: ProfileTransferState,
): RemoteProfileAction? {
    if (!expected.managed || !expected.capability.available) return null
    val status = AccessLifecycleGateway.fetch(
        context = context,
        capability = expected.capability,
        device = store.getOrCreateConnectDeviceId(),
        client = BuildConfig.VERSION_NAME,
        system = Build.VERSION.RELEASE.orEmpty(),
        timezone = TimeZone.getDefault().id,
        profileRevision = expected.revision,
    )
    val current = store.profileTransferState(profile).first()
    if (!current.managed || current.capability != expected.capability ||
        current.revision != expected.revision
    ) return null
    val action = status.profileAction?.takeIf { it.isUsableFor(current) } ?: return null
    // Keep only explanatory text for offline use, never the URL or its authorization data.
    store.saveProfileTransferMessage(profile, current, action.action.message)
    return action
}
