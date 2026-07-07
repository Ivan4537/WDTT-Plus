package com.wdtt.plus

import com.jcraft.jsch.JSch
import com.jcraft.jsch.KeyPair
import java.io.ByteArrayOutputStream
import java.io.File
import org.junit.Assume.assumeTrue
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SshAuthenticationTest {
    private val openSshKey = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        dGVzdA==
        -----END OPENSSH PRIVATE KEY-----
    """.trimIndent()

    @Test
    fun acceptsStructurallyCompleteOpenSshKey() {
        assertNull(sshPrivateKeyIssue(openSshKey))
        assertTrue(SshCredentials(privateKey = openSshKey).hasAuthentication)
    }

    @Test
    fun rejectsPublicAndTruncatedKeys() {
        assertTrue(sshPrivateKeyIssue("ssh-ed25519 AAAA test") != null)
        assertTrue(sshPrivateKeyIssue("-----BEGIN OPENSSH PRIVATE KEY-----\nabc") != null)
    }

    @Test
    fun passwordRemainsAValidFallback() {
        assertTrue(SshCredentials(password = "secret").hasAuthentication)
        assertFalse(SshCredentials().hasAuthentication)
    }

    @Test
    fun selectedModePreventsSavedKeyFromHijackingPasswordLogin() {
        val passwordMode = sshCredentialsForMode("password", "secret", openSshKey, "key-pass")
        assertTrue(passwordMode.hasAuthentication)
        assertFalse(passwordMode.usesPrivateKey)
        assertTrue(passwordMode.usesPasswordAuthentication)

        val keyMode = sshCredentialsForMode("key", "sudo-pass", openSshKey, "key-pass")
        assertTrue(keyMode.usesPrivateKey)
        assertTrue(keyMode.hasAuthentication)
        assertFalse(keyMode.usesPasswordAuthentication)
        assertFalse(keyMode.allowPasswordAuthentication)
    }

    @Test
    fun ed25519UsesBundledAndroidCompatibleImplementation() {
        configureJschEdDsaCompatibility()

        assertEquals("com.jcraft.jsch.bc.KeyPairGenEdDSA", JSch.getConfig("keypairgen.eddsa"))
        assertEquals("com.jcraft.jsch.bc.KeyPairGenEdDSA", JSch.getConfig("keypairgen_fromprivate.eddsa"))
        assertEquals("com.jcraft.jsch.bc.SignatureEd25519", JSch.getConfig("ssh-ed25519"))
        assertEquals("com.jcraft.jsch.bc.SignatureEd448", JSch.getConfig("ssh-ed448"))
    }

    @Test
    fun privateKeyPresenceDoesNotDisablePasswordModeByItself() {
        val credentials = SshCredentials(
            password = "secret",
            privateKey = openSshKey,
            privateKeyPassphrase = "key-pass",
            allowPasswordAuthentication = true
        )

        assertTrue(credentials.hasAuthentication)
        assertTrue(credentials.usesPasswordAuthentication)
        assertTrue(credentials.usesPrivateKey)
    }

    @Test
    fun authenticationFailureExplainsTheSelectedMethod() {
        assertEquals(
            "SSH-сервер отклонил пароль. Проверьте логин SSH и пароль.",
            friendlySshConnectionError("Auth fail", SshCredentials(password = "secret"))
        )
        assertEquals(
            "SSH-сервер отклонил приватный ключ. Проверьте логин SSH, наличие соответствующего публичного ключа на сервере и пароль ключа.",
            friendlySshConnectionError("Auth fail", SshCredentials(privateKey = openSshKey))
        )
    }

    @Test
    fun generatedPemKeyCanBeLoadedByBundledJsch() {
        val jsch = JSch()
        val pair = KeyPair.genKeyPair(jsch, KeyPair.RSA, 2048)
        val output = ByteArrayOutputStream()
        pair.writePrivateKey(output, "key-passphrase".toByteArray())
        pair.dispose()
        val privateKey = output.toString(Charsets.UTF_8.name())

        assertNull(sshPrivateKeyIssue(privateKey))
        JSch().addIdentity(
            "test-key",
            privateKey.toByteArray(),
            null,
            "key-passphrase".toByteArray()
        )
    }

    @Test
    fun optionalLocalSshIntegration() {
        val port = System.getenv("WDTT_TEST_SSH_PORT")?.toIntOrNull()
        val host = System.getenv("WDTT_TEST_SSH_HOST").orEmpty().ifBlank { "127.0.0.1" }
        val user = System.getenv("WDTT_TEST_SSH_USER").orEmpty()
        val keyFile = System.getenv("WDTT_TEST_SSH_KEY")?.let(::File)
        val keyPassphrase = System.getenv("WDTT_TEST_SSH_KEY_PASSPHRASE").orEmpty()
        assumeTrue(port != null && host.isNotBlank() && user.isNotBlank() && keyFile?.isFile == true)

        val session = createSshSession(
            host = host,
            user = user,
            credentials = SshCredentials(
                privateKey = keyFile!!.readText(),
                privateKeyPassphrase = keyPassphrase
            ),
            port = port!!
        )
        try {
            assertTrue(session.isConnected)
        } finally {
            session.disconnect()
        }
    }
}
