package com.wdtt.plus.vk

import android.net.Network
import java.net.Proxy
import java.util.concurrent.TimeUnit
import okhttp3.ConnectionPool
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject

internal class VkHttpFailure(val status: Int) : Exception("HTTP $status")

internal object VkHttp {
    fun builder(): OkHttpClient.Builder = OkHttpClient.Builder()
        .retryOnConnectionFailure(false)
        .followRedirects(false).followSslRedirects(false)
        // OkHttp can otherwise follow a 503 + Retry-After: 0 even with connection retries off.
        .addNetworkInterceptor { chain ->
            val response = chain.proceed(chain.request())
            if (!response.isSuccessful) {
                val code = response.code
                response.close()
                throw VkHttpFailure(code)
            }
            response
        }
        .proxy(Proxy.NO_PROXY)
        .connectionPool(ConnectionPool(0, 1, TimeUnit.SECONDS))
        .connectTimeout(12, TimeUnit.SECONDS).readTimeout(20, TimeUnit.SECONDS)
        .callTimeout(35, TimeUnit.SECONDS)

    fun client(network: Network): OkHttpClient = builder()
        .socketFactory(network.socketFactory)
        .dns(object : okhttp3.Dns {
            override fun lookup(hostname: String): List<java.net.InetAddress> =
                network.getAllByName(hostname).toList()
        })
        .build()

    /** Check permission to create a network-bound socket without connecting anywhere. */
    fun checkSocketAccess(client: OkHttpClient) {
        client.socketFactory.createSocket().use { socket ->
            check(!socket.isConnected) { "Socket preflight must not connect." }
        }
    }

    fun post(client: OkHttpClient, endpoint: String, fields: Map<String, String>): JSONObject {
        require(endpoint in setOf(VkApiProtocol.START_ENDPOINT, VkApiProtocol.USER_ENDPOINT))
        return request(client, endpoint, fields)
    }

    // Also exercised against a local fake server. No logging, interceptors or generic app proxy.
    internal fun request(client: OkHttpClient, endpoint: String, fields: Map<String, String>): JSONObject {
        val body = FormBody.Builder().apply { fields.forEach { (k, v) -> add(k, v) } }.build()
        val request = Request.Builder().url(endpoint).post(body)
            .header("Connection", "close").header("Cache-Control", "no-store").build()
        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) throw VkHttpFailure(response.code)
            val bytes = response.body?.byteStream()?.use { it.readBytesBounded() }
                ?: throw IllegalStateException("Empty response")
            return JSONObject(bytes.toString(Charsets.UTF_8))
        }
    }

    private fun java.io.InputStream.readBytesBounded(): ByteArray {
        val result = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(4096)
        while (true) {
            val size = read(buffer)
            if (size < 0) return result.toByteArray()
            require(result.size() + size <= 65_536)
            result.write(buffer, 0, size)
        }
    }
}
