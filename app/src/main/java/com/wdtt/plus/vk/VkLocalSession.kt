package com.wdtt.plus.vk

import android.content.Context
import android.webkit.CookieManager
import android.webkit.WebStorage
import androidx.webkit.WebStorageCompat
import androidx.webkit.WebViewFeature
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeout
import com.wdtt.plus.LocalContinuationProfile

/** Only engines of the SAME local profile share a session; each slot has its own process. */
internal class VkLocalSession(private val storage: Storage) {
    interface Storage {
        val remembered: Boolean
        val logoutPending: Boolean
        val owner: String
        fun remember()
        fun beginLogout()
        fun removeNativeToken()
        fun finishLogout()
        fun saveOwner(identity: String)
    }

    val logoutPending get() = storage.logoutPending
    // Only a routing hint. VK and the backend still verify the current account.
    val remembered get() = storage.remembered && !logoutPending

    fun observeBridgeStage(stage: String) {
        if (stage in setOf("AUTH_REQUEST", "AUTH_READY", "AUTO_READY")) rememberAuthenticatedWebSession()
    }

    fun rememberAuthenticatedWebSession() {
        if (!logoutPending) storage.remember()
    }

    suspend fun logout(clearWebData: suspend () -> Unit) {
        // Persist a barrier BEFORE clearing separate token/cookie stores. A killed
        // Activity or failed cookie callback must not resurrect the other engine's account.
        storage.beginLogout()
        storage.removeNativeToken()
        clearWebData()
        storage.finishLogout()
    }

    suspend fun finishPendingLogout(clearWebData: suspend () -> Unit) {
        if (logoutPending) logout(clearWebData)
    }

    suspend fun prepareProfile(identity: String, clearWebData: suspend () -> Unit) {
        require(identity.matches(Regex("[a-f0-9]{64}")))
        // A reset/replaced slot cannot inherit its previous profile's account.
        // Commit the new owner only AFTER clearing all of the slot's old web data.
        if (storage.owner != identity) {
            logout(clearWebData)
            storage.saveOwner(identity)
        } else {
            finishPendingLogout(clearWebData)
        }
    }

    companion object {
        fun nativeTokenPreferences(context: Context, profile: LocalContinuationProfile) =
            context.getSharedPreferences("native-vk-session-profile-${profile.index}", Context.MODE_PRIVATE)

        fun forContext(context: Context, profile: LocalContinuationProfile): VkLocalSession {
            ProfileWebSessionScope.requireValid(profile)
            val session = context.getSharedPreferences("vk-web-session-profile-${profile.index}", Context.MODE_PRIVATE)
            val native = nativeTokenPreferences(context, profile)
            return VkLocalSession(object : Storage {
                override val remembered get() = session.getBoolean("has_vk_web_session", false)
                override val logoutPending get() = session.getBoolean("logout_pending", false)
                override val owner get() = session.getString("owner", "").orEmpty()
                override fun remember() {
                    session.edit().putBoolean("has_vk_web_session", true).apply()
                }
                override fun beginLogout() {
                    check(session.edit().putBoolean("logout_pending", true)
                        .remove("has_vk_web_session").commit()) { "SESSION_REMOVE" }
                }
                override fun removeNativeToken() {
                    // Deliberately preserve the operation ledger, permits and saved results.
                    check(native.edit().remove("token").commit()) { "TOKEN_REMOVE" }
                }
                override fun finishLogout() {
                    check(session.edit().remove("logout_pending").commit()) { "SESSION_REMOVE" }
                }
                override fun saveOwner(identity: String) {
                    check(session.edit().putString("owner", identity).commit()) { "SESSION_OWNER" }
                }
            })
        }

        suspend fun clearWebData() {
            val cleared = CompletableDeferred<Unit>()
            if (WebViewFeature.isFeatureSupported(WebViewFeature.DELETE_BROWSING_DATA)) {
                // Includes cookies, HTTP cache and service-worker/JS storage. Await
                // completion BEFORE allowing another account to open in this slot.
                WebStorageCompat.deleteBrowsingData(WebStorage.getInstance()) { cleared.complete(Unit) }
                withTimeout(10_000) { cleared.await() }
                CookieManager.getInstance().flush()
                return
            }
            // false means the cookie jar was already empty, not an error.
            CookieManager.getInstance().removeAllCookies { cleared.complete(Unit) }
            withTimeout(5_000) { cleared.await() }
            CookieManager.getInstance().flush()
            WebStorage.getInstance().deleteAllData()
        }
    }
}
