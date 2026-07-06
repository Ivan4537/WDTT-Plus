package com.wdtt.plus

import com.jcraft.jsch.JSch
import com.jcraft.jsch.JSchException
import com.jcraft.jsch.Session
import java.util.Properties

const val MAX_SSH_PRIVATE_KEY_CHARS = 128 * 1024

data class SshCredentials(
    val password: String = "",
    val privateKey: String = "",
    val privateKeyPassphrase: String = "",
    val allowPasswordAuthentication: Boolean = true
) {
    val hasAuthentication: Boolean
        get() = (privateKey.isNotBlank() && sshPrivateKeyIssue(privateKey) == null) ||
            (allowPasswordAuthentication && password.isNotBlank())

    val usesPrivateKey: Boolean
        get() = privateKey.isNotBlank()

    val usesPasswordAuthentication: Boolean
        get() = allowPasswordAuthentication && password.isNotBlank()
}

fun sshCredentialsForMode(
    mode: String,
    password: String,
    privateKey: String,
    privateKeyPassphrase: String
): SshCredentials = if (mode == "key") {
    SshCredentials(
        password = password,
        privateKey = privateKey,
        privateKeyPassphrase = privateKeyPassphrase,
        allowPasswordAuthentication = false
    )
} else {
    SshCredentials(password = password, allowPasswordAuthentication = true)
}

fun normalizeSshPrivateKey(value: String): String =
    value.removePrefix("\uFEFF").replace("\r\n", "\n").trim()

fun sshPrivateKeyIssue(value: String): String? {
    val key = normalizeSshPrivateKey(value)
    if (key.isBlank()) return "Приватный ключ не указан."
    if (key.length > MAX_SSH_PRIVATE_KEY_CHARS) return "Файл ключа слишком большой. Максимум — 128 КБ."
    if (" PUBLIC KEY-----" in key.lineSequence().firstOrNull().orEmpty()) {
        return "Выбран публичный ключ. Нужен приватный ключ."
    }
    val supportedHeaders = listOf(
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----"
    )
    val header = supportedHeaders.firstOrNull(key::startsWith)
        ?: return "Формат ключа не распознан. Поддерживаются OpenSSH и PEM-приватные ключи."
    val footer = header.replace("BEGIN", "END")
    if (!key.endsWith(footer)) return "Приватный ключ обрезан или повреждён: не найден конец ключа."
    return null
}

internal fun friendlySshConnectionError(message: String, credentials: SshCredentials): String = when {
    message.contains("invalid privatekey", ignoreCase = true) ->
        "Приватный SSH-ключ повреждён или имеет неподдерживаемый формат."
    message.contains("decrypt", ignoreCase = true) || message.contains("passphrase", ignoreCase = true) ->
        "Не удалось расшифровать приватный SSH-ключ. Проверьте пароль ключа."
    message.contains("Auth fail", ignoreCase = true) && credentials.usesPrivateKey &&
        !credentials.usesPasswordAuthentication ->
        "SSH-сервер отклонил приватный ключ. Проверьте логин SSH, наличие соответствующего публичного ключа на сервере и пароль ключа."
    message.contains("Auth fail", ignoreCase = true) && credentials.usesPasswordAuthentication &&
        !credentials.usesPrivateKey ->
        "SSH-сервер отклонил пароль. Проверьте логин SSH и пароль."
    message.contains("Auth fail", ignoreCase = true) ->
        "SSH-сервер отклонил пароль и приватный ключ. Проверьте логин SSH, ключ и пароль ключа."
    message.contains("connection refused", ignoreCase = true) ->
        "SSH-сервер доступен, но порт отклонил подключение. Проверьте SSH-порт и настройки SSH-сервера."
    message.contains("unknownhost", ignoreCase = true) ||
        message.contains("unknown host", ignoreCase = true) ->
        "Не удалось найти SSH-сервер. Проверьте IP-адрес или домен."
    message.contains("timeout", ignoreCase = true) ->
        "SSH-сервер не ответил за 20 секунд. Проверьте адрес, порт, сеть и межсетевой экран."
    else -> "Не удалось подключиться по SSH: ${message.ifBlank { "неизвестная ошибка" }}"
}

fun createSshSession(
    host: String,
    user: String,
    credentials: SshCredentials,
    port: Int = 22
): Session {
    require(host.isNotBlank()) { "Не указан адрес SSH-сервера." }
    require(port in 1..65535) { "SSH-порт должен быть от 1 до 65535." }
    require(credentials.hasAuthentication) { "Укажите SSH-пароль или приватный SSH-ключ." }

    try {
        val jsch = JSch()
        val privateKey = normalizeSshPrivateKey(credentials.privateKey)
        if (privateKey.isNotBlank()) {
            sshPrivateKeyIssue(privateKey)?.let { throw IllegalArgumentException(it) }
            jsch.addIdentity(
                "wdtt-plus-memory-key",
                privateKey.toByteArray(Charsets.UTF_8),
                null,
                credentials.privateKeyPassphrase.takeIf { it.isNotEmpty() }?.toByteArray(Charsets.UTF_8)
            )
        }

        val session = jsch.getSession(user.ifBlank { "root" }, host.trim(), port)
        if (credentials.allowPasswordAuthentication && credentials.password.isNotBlank()) {
            session.setPassword(credentials.password)
        }
        session.setConfig(Properties().apply {
            put("StrictHostKeyChecking", "no")
            put("ServerAliveInterval", "10")
            put("ServerAliveCountMax", "6")
            put("ConnectTimeout", "15000")
            put(
                "PreferredAuthentications",
                when {
                    privateKey.isNotBlank() && credentials.allowPasswordAuthentication -> "publickey,password,keyboard-interactive"
                    privateKey.isNotBlank() -> "publickey"
                    credentials.allowPasswordAuthentication -> "password,keyboard-interactive"
                    else -> "publickey"
                }
            )
        })
        session.connect(20_000)
        return session
    } catch (error: IllegalArgumentException) {
        throw error
    } catch (error: JSchException) {
        val message = error.message.orEmpty()
        throw IllegalStateException(friendlySshConnectionError(message, credentials), error)
    }
}
