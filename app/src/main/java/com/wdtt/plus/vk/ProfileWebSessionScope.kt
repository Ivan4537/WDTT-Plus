package com.wdtt.plus.vk

import android.app.Application
import android.content.Context
import android.content.Intent
import com.wdtt.plus.LocalContinuationProfile

/** One OS/WebView data partition for each of the app's three local profile slots. */
internal object ProfileWebSessionScope {
    private const val SLOT = "local_profile_slot"
    private const val IDENTITY = "local_profile_identity"

    fun requireValid(profile: LocalContinuationProfile) {
        require(profile.index in 0..2 && profile.identity.matches(Regex("[a-f0-9]{64}"))) {
            "Не удалось определить профиль для входа."
        }
    }

    fun modernActivity(index: Int) = activity("Modern", index)
    fun nativeActivity(index: Int) = activity("Native", index)
    private fun activity(engine: String, index: Int): String {
        require(index in 0..2)
        return "com.wdtt.plus.vk.${engine}VkProfile${index}Activity"
    }

    fun processSuffix(index: Int): String {
        require(index in 0..2)
        return ":local_web_auth_p$index"
    }

    fun webDataSuffix(index: Int): String {
        require(index in 0..2)
        return "local-vk-profile-$index-v1"
    }

    fun put(intent: Intent, profile: LocalContinuationProfile) {
        requireValid(profile)
        intent.putExtra(SLOT, profile.index).putExtra(IDENTITY, profile.identity)
    }

    fun read(context: Context, intent: Intent): LocalContinuationProfile {
        val profile = LocalContinuationProfile(intent.getIntExtra(SLOT, -1), intent.getStringExtra(IDENTITY).orEmpty())
        requireValid(profile)
        check(Application.getProcessName() == context.packageName + processSuffix(profile.index)) {
            "Окно входа не соответствует выбранному профилю."
        }
        return profile
    }
}
