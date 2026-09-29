package com.wdtt.plus.vk

import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject

/** Relay cannot read credentials/results or forge a mutation permit. No server secret in APK. */
internal object NativeVkCrypto {
    private const val PUBLIC_KEY = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEECxFJu55s4aJHQIWzzGLegkLacvTHxdZDB2tFyAD8d33krcIJtJohsMJorGy4gKmdTqWwNCiNE2+9gkIZhetyQ=="
    private val context = "wdtt-native-e2e-v1".toByteArray()
    private fun encode(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)
    private fun decode(value: String) = Base64.getDecoder().decode(value)
    class Exchange(val request: String, private val key: ByteArray, private val digest: ByteArray) {
        fun response(raw: String): JSONObject {
            val json = JSONObject(raw)
            val nonce = decode(json.getString("n"))
            require(nonce.size == 12)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD(context + ":response:".toByteArray() + digest)
            return JSONObject(cipher.doFinal(decode(json.getString("c"))).toString(Charsets.UTF_8))
        }
    }
    fun exchange(raw: String, publicKey: String = PUBLIC_KEY): Exchange {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val server = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(decode(publicKey)))
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(pair.private); agreement.doPhase(server, true)
        val key = MessageDigest.getInstance("SHA-256").digest(agreement.generateSecret() + context)
        val body = raw.toByteArray(Charsets.UTF_8)
        val nonce = ByteArray(12).also(SecureRandom()::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(context + ":request".toByteArray())
        val json = JSONObject().put("e", encode(pair.public.encoded)).put("n", encode(nonce))
            .put("c", encode(cipher.doFinal(body))).toString()
        require(json.toByteArray().size <= 768)
        return Exchange(json, key, MessageDigest.getInstance("SHA-256").digest(body))
    }
}
