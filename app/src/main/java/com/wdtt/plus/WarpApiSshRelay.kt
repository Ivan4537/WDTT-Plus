package com.wdtt.plus

import android.content.Context
import com.jcraft.jsch.Session
import java.io.Closeable

private const val WARP_API_RELAY_TARGET = "api.cloudflareclient.com"
private const val WARP_API_RELAY_TARGET_PORT = 443

internal sealed interface WarpApiSshRelayStartResult {
    data class Ready(val relay: WarpApiSshRelay) : WarpApiSshRelayStartResult
    data object MissingProfileAccess : WarpApiSshRelayStartResult
    data class Failed(val message: String) : WarpApiSshRelayStartResult
}

/**
 * A short-lived loopback-only TCP relay backed by the SSH access already stored for the active
 * Deploy profile. The forwarding target is fixed to Cloudflare's WARP enrollment API. No server
 * endpoint, SSH username or credential is passed to the native process or written to logs.
 */
internal class WarpApiSshRelay private constructor(
    private val session: Session,
    val port: Int,
) : Closeable {
    val loopbackAddress: String
        get() = "127.0.0.1:$port"

    @Volatile
    private var closed = false

    override fun close() {
        if (closed) return
        synchronized(this) {
            if (closed) return
            closed = true
            runCatching { session.delPortForwardingL("127.0.0.1", port) }
            runCatching { session.disconnect() }
        }
    }

    companion object {
        suspend fun start(
            context: Context,
            profileIndex: Int,
        ): WarpApiSshRelayStartResult {
            val profile = SettingsStore(context.applicationContext)
                .sshConnectionForProfile(profileIndex)
                ?: return WarpApiSshRelayStartResult.MissingProfileAccess

            var session: Session? = null
            return try {
                session = createSshSession(
                    host = profile.host,
                    user = profile.user,
                    credentials = profile.credentials,
                    port = profile.port,
                )
                val localPort = session.setPortForwardingL(
                    "127.0.0.1",
                    0,
                    WARP_API_RELAY_TARGET,
                    WARP_API_RELAY_TARGET_PORT,
                )
                if (localPort !in 1..65535) {
                    throw IllegalStateException("SSH не выделил локальный порт")
                }
                WarpApiSshRelayStartResult.Ready(
                    WarpApiSshRelay(session = session, port = localPort),
                )
            } catch (error: Exception) {
                runCatching { session?.disconnect() }
                WarpApiSshRelayStartResult.Failed(safeRelayError(error))
            }
        }

        private fun safeRelayError(error: Throwable): String {
            val detail = generateSequence(error) { it.cause }
                .mapNotNull { it.message }
                .joinToString(" ")
                .lowercase()
            return when {
                "auth fail" in detail || "отклонил пароль" in detail || "отклонил приватный ключ" in detail ->
                    "SSH-сервер отклонил данные входа"
                "timeout" in detail || "20 секунд" in detail ->
                    "SSH-сервер не ответил вовремя"
                "refused" in detail || "порт отклонил" in detail ->
                    "SSH-порт отклонил подключение"
                "administratively prohibited" in detail || "port forwarding" in detail ->
                    "SSH-сервер запретил TCP-переадресацию"
                else -> "не удалось подготовить SSH-переадресацию"
            }
        }
    }
}
