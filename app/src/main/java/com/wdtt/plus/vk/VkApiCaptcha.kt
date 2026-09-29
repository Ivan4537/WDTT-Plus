package com.wdtt.plus.vk

import org.json.JSONObject

/** A definitive API rejection, not a timeout or permission to replay an uncertain call. */
internal class VkApiCaptcha private constructor(val url: String, private val parameters: Map<String, String>) {
    fun continuation(success: String): Map<String, String> {
        require(validProof(success))
        return parameters + mapOf("captcha_key" to "", "success_token" to success)
    }
    companion object {
        fun validProof(value: String) = value.matches(Regex("[A-Za-z0-9._~+/=-]{1,8192}"))
        suspend fun continueRejected(
            result: JSONObject,
            solve: suspend (VkApiCaptcha) -> String,
            send: suspend (Map<String, String>) -> JSONObject,
        ): JSONObject {
            if (result.optJSONObject("error")?.optInt("error_code") != 14) return result
            val challenge = parse(result) ?: error("ВК не предоставил доступную страницу проверки.")
            // No loop. A second rejection is returned to the caller as an error.
            return send(challenge.continuation(solve(challenge)))
        }

        fun parse(response: JSONObject): VkApiCaptcha? {
            val error = response.optJSONObject("error") ?: return null
            if (error.optInt("error_code") != 14 || response.has("response")) return null
            val url = error.optString("redirect_uri")
            val sid = error.optString("captcha_sid")
            if (url.length !in 1..16384 || !VkCaptchaPolicy.captchaPage(url) || !sid.matches(Regex("[A-Za-z0-9_-]{1,256}"))) return null
            val fields = linkedMapOf("captcha_sid" to sid)
            for (key in listOf("captcha_ts", "captcha_attempt")) {
                val value = error.optString(key)
                if (value.isNotEmpty()) {
                    if (!value.matches(Regex("[0-9]{1,20}"))) return null
                    fields[key] = value
                }
            }
            return VkApiCaptcha(url, fields)
        }

        // Used ONLY while an explicit REST error 14 challenge is open. Never
        // attached to login/consent; no tokens, responses or bodies go to logs.
        val completionScript = """
            (() => {
              if (window.__wdttApiCaptchaInstalled || !window.WDTTApiCaptchaResult ||
                  !/(?:not_robot|captcha)/i.test(location.pathname)) return;
              window.__wdttApiCaptchaInstalled = true;
              const channel = window.WDTTApiCaptchaResult;
              let nonce = '';
              channel.onmessage = event => {
                try {
                  const value = JSON.parse(event.data).observe;
                  if (typeof value === 'string' && /^[A-Za-z0-9_-]{16,80}${'$'}/.test(value)) nonce = value;
                } catch (_) {}
              };
              channel.postMessage(JSON.stringify({page: location.href}));
              const emit = json => {
                const token = json && json.response && json.response.success_token;
                if (nonce && typeof token === 'string' && /^[A-Za-z0-9._~+/=-]{1,8192}${'$'}/.test(token)) {
                  channel.postMessage(JSON.stringify({nonce, proof: token}));
                }
              };
              const isCheck = raw => {
                try {
                  const url = new URL(raw, location.href);
                  return url.protocol === 'https:' &&
                    /^(id|api)\.vk\.(ru|com)${'$'}/.test(url.hostname) &&
                    url.pathname.endsWith('/captchaNotRobot.check');
                } catch (_) { return false; }
              };
              const fetchOriginal = window.fetch;
              if (fetchOriginal) window.fetch = function(input) {
                const result = fetchOriginal.apply(this, arguments);
                if (nonce && isCheck(typeof input === 'string' ? input : input && input.url)) {
                  result.then(response => response.clone().json().then(emit).catch(() => {})).catch(() => {});
                }
                return result;
              };
              const open = XMLHttpRequest.prototype.open, send = XMLHttpRequest.prototype.send;
              const checks = new WeakSet();
              XMLHttpRequest.prototype.open = function(method, url) {
                checks.delete(this); if (nonce && isCheck(url)) checks.add(this);
                return open.apply(this, arguments);
              };
              XMLHttpRequest.prototype.send = function() {
                if (checks.has(this)) this.addEventListener('load', () => {
                  try { emit(this.responseType === 'json' ? this.response : JSON.parse(this.responseText)); } catch (_) {}
                }, {once: true});
                return send.apply(this, arguments);
              };
            })();
        """.trimIndent()
    }
}
