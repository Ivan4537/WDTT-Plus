package com.wdtt.plus.vk

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Person
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.json.JSONObject

internal object VkAccountChoicePolicy {
    // Anonymous cookies alone are not proof of login, but they MUST NOT allow
    // silently skipping account selection if a login hint was lost on process death.
    fun required(remembered: Boolean, hasCookies: Boolean, hasToken: Boolean = false) =
        remembered || hasCookies || hasToken
}

internal class VkAccountIdentity(val id: Long, val name: String) {
    companion object {
        fun from(id: Long, name: String): VkAccountIdentity {
            require(id > 0 && name.length <= 160)
            val clean = name.filterNot { it.isISOControl() || it in '\u202a'..'\u202e' || it in '\u2066'..'\u2069' }
                .trim().replace(Regex("\\s+"), " ")
            require(clean.isNotBlank())
            return VkAccountIdentity(id, clean)
        }

        fun fromApi(json: JSONObject): VkAccountIdentity {
            check(!json.has("error")) { "ACCOUNT_UNAVAILABLE" }
            val profiles = json.getJSONArray("response")
            require(profiles.length() == 1)
            val profile = profiles.getJSONObject(0)
            return from(profile.getLong("id"),
                listOf(profile.optString("first_name"), profile.optString("last_name"))
                    .filter(String::isNotBlank).joinToString(" "))
        }
    }
}

internal class VkAccountMessage(val account: VkAccountIdentity, val nonce: String) {
    fun continueReply(): String = JSONObject().put("nonce", nonce).put("action", "continue").toString()

    companion object {
        fun parse(raw: String, expectedState: String): VkAccountMessage {
            require(raw.length <= 4096 && expectedState.isNotBlank())
            val json = JSONObject(raw)
            require(json.getString("event") == "account" && json.getString("state") == expectedState)
            val nonce = json.getString("nonce")
            require(nonce.matches(Regex("ac1_[A-Za-z0-9_-]{16,96}")))
            return VkAccountMessage(VkAccountIdentity.from(json.getLong("id"), json.getString("name")), nonce)
        }
    }
}

@Composable
internal fun VkAccountChoicePanel(account: VkAccountIdentity, enabled: Boolean = true,
    onContinue: () -> Unit, onLogout: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Icon(Icons.Default.Person, null, Modifier.size(32.dp), tint = MaterialTheme.colorScheme.primary)
            Column(Modifier.weight(1f)) {
                Text("Аккаунт ВК этого профиля", style = MaterialTheme.typography.bodySmall)
                Text(account.name, style = MaterialTheme.typography.titleMedium)
            }
        }
        Text("Продолжить с этим аккаунтом или войти в другой?", style = MaterialTheme.typography.bodyMedium)
        Button(onClick = onContinue, enabled = enabled, modifier = Modifier.fillMaxWidth()) { Text("Продолжить") }
        OutlinedButton(onClick = onLogout, enabled = enabled, modifier = Modifier.fillMaxWidth()) { Text("Выйти из ВК") }
    }
}
