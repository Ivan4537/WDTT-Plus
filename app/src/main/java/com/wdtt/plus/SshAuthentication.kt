package com.wdtt.plus

import com.jcraft.jsch.JSch
import com.jcraft.jsch.JSchException
import com.jcraft.jsch.Session
import java.util.Properties

const val MAX_SSH_PRIVATE_KEY_CHARS = 128 * 1024

private const val JSCH_BC_EDDSA_KEYPAIRGEN = "com.jcraft.jsch.bc.KeyPairGenEdDSA"
private const val JSCH_BC_ED25519_SIGNATURE = "com.jcraft.jsch.bc.SignatureEd25519"
private const val JSCH_BC_ED448_SIGNATURE = "com.jcraft.jsch.bc.SignatureEd448"

@Volatile
private var jschEdDsaConfigured = false

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

internal fun configureJschEdDsaCompatibility() {
    if (jschEdDsaConfigured) return
    synchronized(JSch::class.java) {
        if (jschEdDsaConfigured) return
        JSch.setConfig("keypairgen.eddsa", JSCH_BC_EDDSA_KEYPAIRGEN)
        JSch.setConfig("keypairgen_fromprivate.eddsa", JSCH_BC_EDDSA_KEYPAIRGEN)
        JSch.setConfig("ssh-ed25519", JSCH_BC_ED25519_SIGNATURE)
        JSch.setConfig("ssh-ed448", JSCH_BC_ED448_SIGNATURE)
        jschEdDsaConfigured = true
    }
}

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
    message.contains("SignatureEd25519", ignoreCase = true) ||
        message.contains("ssh-ed25519", ignoreCase = true) && (
            message.contains("not available", ignoreCase = true) ||
                message.contains("unsupported", ignoreCase = true) ||
                message.contains("Java15", ignoreCase = true) ||
                message.contains("class not found", ignoreCase = true)
            ) ->
        "Приложение не смогло использовать Ed25519 SSH-ключ. Обновите приложение или попробуйте RSA-ключ в формате OpenSSH/PEM."
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

private fun Throwable.messageWithCauses(): String =
    generateSequence(this) { it.cause }
        .mapNotNull { it.message?.takeIf(String::isNotBlank) }
        .joinToString(": ")

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
        configureJschEdDsaCompatibility()
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
        val message = error.messageWithCauses()
        throw IllegalStateException(friendlySshConnectionError(message, credentials), error)
    }
}
