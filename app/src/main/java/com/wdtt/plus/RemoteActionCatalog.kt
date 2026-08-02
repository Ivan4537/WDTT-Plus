package com.wdtt.plus

import android.content.Context
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.util.UUID

/**
 * Provider-neutral UI action prepared by a remote service.
 *
 * The application does not interpret the destination or reconstruct either
 * URL. It only validates the generic HTTPS boundary and opens the exact
 * backend-provided target.
 */
data class RemoteUiAction(
    val title: String,
    val message: String,
    val label: String,
    val target: RemoteLaunchTarget,
    val confirmationTitle: String = "",
    val confirmationMessage: String = "",
    val confirmationLabel: String = "",
    val progressLabel: String = "",
    val preparingMessage: String = "",
    val stoppingMessage: String = "",
    val openingMessage: String = "",
    val successMessage: String = "",
    val cancelledMessage: String = "",
    val failureMessage: String = "",
    val compactMessage: String = "",
    val compactLabel: String = "",
    val compactLinkText: String = "",
    val compactButtonVisible: Boolean = true,
    val cancelLabel: String = "",
    val form: RemoteActionForm? = null,
)

data class RemoteActionFormChoice(
    val label: String,
    val value: String,
)

data class RemoteActionForm(
    val token: String,
    val submitUrl: String,
    val title: String,
    val message: String,
    val choices: List<RemoteActionFormChoice>,
    val inputLabel: String,
    val inputSuffix: String,
    val initialValue: String,
    val minimum: Long,
    val maximum: Long,
    val maxCharacters: Int,
    val supportingText: String,
    val invalidText: String,
    val submitLabel: String,
    val busyLabel: String,
    val failureMessage: String,
    val fallbackLabel: String,
)

class RemoteActionExecutionException(message: String) : IllegalStateException(message)

data class RemoteActionCatalog(
    val actions: Map<String, RemoteUiAction> = emptyMap(),
) {
    fun at(placement: String): RemoteUiAction? = actions[placement]

    companion object {
        val Empty = RemoteActionCatalog()
    }
}

object RemoteActionCatalogGateway {
    private const val CACHE_TTL_MS = 10 * 60 * 1000L
    private const val MAX_RESPONSE_CHARS = 32 * 1024
    private val placements = setOf("tunnel", "profile", "about")
    private val fetchMutex = Mutex()

    @Volatile
    private var cachedAt = 0L

    @Volatile
    private var cachedCatalog = RemoteActionCatalog.Empty

    fun hasFreshCache(): Boolean =
        System.currentTimeMillis() - cachedAt in 0 until CACHE_TTL_MS

    fun cached(): RemoteActionCatalog = cachedCatalog

    suspend fun fetch(force: Boolean = false): RemoteActionCatalog {
        val now = System.currentTimeMillis()
        if (!force && now - cachedAt in 0 until CACHE_TTL_MS) return cachedCatalog
        return withContext(Dispatchers.IO) {
            fetchMutex.withLock {
                val current = System.currentTimeMillis()
                if (!force && current - cachedAt in 0 until CACHE_TTL_MS) {
                    return@withLock cachedCatalog
                }
                runCatching { request() }
                    .onSuccess { received ->
                        cachedCatalog = received
                        cachedAt = current
                    }
                cachedCatalog
            }
        }
    }

    suspend fun fetchQuestionAction(): RemoteUiAction? =
        withContext(Dispatchers.IO) {
            runCatching { request(context = "question").at("about") }.getOrNull()
        }

    suspend fun execute(
        form: RemoteActionForm,
        requestId: String,
        value: String,
    ): RemoteLaunchTarget = withContext(Dispatchers.IO) {
        require(validOpaqueToken(form.token)) { "Действие устарело. Обновите экран." }
        require(safeExternalUrl(form.submitUrl)) { "Получен небезопасный адрес действия." }
        require(runCatching { UUID.fromString(requestId) }.isSuccess) {
            "Не удалось подготовить действие."
        }
        require(value.length in 1..32) { form.invalidText }
        var connection: HttpURLConnection? = null
        try {
            connection = URL(form.submitUrl).openConnection() as HttpURLConnection
            connection.requestMethod = "POST"
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 7_000
            connection.readTimeout = 12_000
            connection.doOutput = true
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
            val payload = JSONObject()
                .put("token", form.token)
                .put("request_id", requestId)
                .put("value", value)
                .put("client", BuildConfig.VERSION_NAME)
                .put("system", android.os.Build.VERSION.RELEASE.orEmpty())
                .toString()
                .toByteArray(Charsets.UTF_8)
            connection.outputStream.use { it.write(payload) }
            val status = connection.responseCode
            val stream = if (status in 200..299) {
                connection.inputStream
            } else {
                connection.errorStream
            }
            val body = stream?.use { it.readUtf8TextLimited(MAX_RESPONSE_CHARS) }.orEmpty()
            if (status !in 200..299) {
                val detail = runCatching {
                    JSONObject(body).optString("detail").trim().take(240)
                }.getOrDefault("")
                throw RemoteActionExecutionException(
                    detail.ifBlank { form.failureMessage }
                )
            }
            parseExecutionTarget(body)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: RemoteActionExecutionException) {
            throw error
        } catch (error: Exception) {
            throw RemoteActionExecutionException(form.failureMessage)
        } finally {
            connection?.disconnect()
        }
    }

    private fun request(context: String? = null): RemoteActionCatalog {
        var connection: HttpURLConnection? = null
        return try {
            val query = buildList {
                if (BuildConfig.REMOTE_ACTION_PREVIEW) add("preview=1")
                if (context == "question") add("context=question")
            }.joinToString("&").let { if (it.isBlank()) "" else "?$it" }
            connection = URL(
                "https://${BuildConfig.WDTT_PLUS_DOMAIN}/api/client/actions$query"
            ).openConnection() as HttpURLConnection
            connection.requestMethod = "GET"
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 5_000
            connection.readTimeout = 6_000
            connection.setRequestProperty("Accept", "application/json")
            val status = connection.responseCode
            if (status !in 200..299) return RemoteActionCatalog.Empty
            parse(connection.inputStream.use { it.readUtf8TextLimited(MAX_RESPONSE_CHARS) })
        } finally {
            connection?.disconnect()
        }
    }

    internal fun parse(body: String): RemoteActionCatalog {
        if (body.length > MAX_RESPONSE_CHARS) return RemoteActionCatalog.Empty
        val root = runCatching { JSONObject(body) }.getOrNull()
            ?: return RemoteActionCatalog.Empty
        if (root.optInt("version", 0) != 1) return RemoteActionCatalog.Empty
        val source = root.optJSONObject("actions") ?: return RemoteActionCatalog.Empty
        val actions = placements.mapNotNull { placement ->
            val item = source.optJSONObject(placement) ?: return@mapNotNull null
            parseAction(item)?.let { placement to it }
        }.toMap()
        return RemoteActionCatalog(actions)
    }

    private fun parseAction(item: JSONObject): RemoteUiAction? {
        val title = item.optString("title").trim().take(120)
        val message = item.optString("message").trim().take(400)
        val label = item.optString("label").trim().take(80)
        val confirmationTitle = item.optString("confirmation_title").trim().take(120)
        val confirmationMessage = item.optString("confirmation_message").trim().take(1600)
        val confirmationLabel = item.optString("confirmation_label").trim().take(80)
        val progressLabel = item.optString("progress_label").trim().take(80)
        val preparingMessage = item.optString("preparing_message").trim().take(240)
        val stoppingMessage = item.optString("stopping_message").trim().take(240)
        val openingMessage = item.optString("opening_message").trim().take(240)
        val successMessage = item.optString("success_message").trim().take(400)
        val cancelledMessage = item.optString("cancelled_message").trim().take(240)
        val failureMessage = item.optString("failure_message").trim().take(240)
        val compactMessage = item.optString("compact_message").trim().take(400)
        val compactLabel = item.optString("compact_label").trim().take(80)
        val compactLinkText = item.optString("compact_link_text").trim().take(120)
        val compactButtonVisible = item.optBoolean("compact_button_visible", true)
        val cancelLabel = item.optString("cancel_label").trim().take(80)
        val primary = item.optString("url").trim()
        val fallback = item.optString("fallback").trim()
        val handler = item.optString("handler").trim()
        val alternateHandlers = parseAlternateHandlers(item) ?: return null
        val formSource = item.optJSONObject("form")
        val form = formSource?.let(::parseForm)
        if (title.isBlank() || message.isBlank() || label.isBlank()) return null
        if (!safeExternalUrl(primary)) return null
        if (fallback.isNotBlank() && !safeExternalUrl(fallback)) return null
        if (handler.isNotBlank() && !safePackageName(handler)) return null
        if (formSource != null && form == null) return null
        return RemoteUiAction(
            title = title,
            message = message,
            label = label,
            confirmationTitle = confirmationTitle,
            confirmationMessage = confirmationMessage,
            confirmationLabel = confirmationLabel,
            progressLabel = progressLabel,
            preparingMessage = preparingMessage,
            stoppingMessage = stoppingMessage,
            openingMessage = openingMessage,
            successMessage = successMessage,
            cancelledMessage = cancelledMessage,
            failureMessage = failureMessage,
            compactMessage = compactMessage,
            compactLabel = compactLabel,
            compactLinkText = compactLinkText,
            compactButtonVisible = compactButtonVisible,
            cancelLabel = cancelLabel,
            form = form,
            target = RemoteLaunchTarget(
                primaryUrl = primary,
                fallbackUrl = fallback,
                preferredHandler = handler,
                alternateHandlers = alternateHandlers,
            ),
        )
    }

    private fun parseForm(item: JSONObject): RemoteActionForm? {
        val token = item.optString("token").trim()
        val submitUrl = item.optString("submit_url").trim()
        val title = item.optString("title").trim().take(120)
        val message = item.optString("message").trim().take(600)
        val inputLabel = item.optString("input_label").trim().take(80)
        val inputSuffix = item.optString("input_suffix").trim().take(16)
        val initialValue = item.optString("initial_value").trim().take(32)
        val minimum = item.optLong("minimum", Long.MIN_VALUE)
        val maximum = item.optLong("maximum", Long.MIN_VALUE)
        val maxCharacters = item.optInt("max_characters", 0)
        val supportingText = item.optString("supporting_text").trim().take(160)
        val invalidText = item.optString("invalid_text").trim().take(160)
        val submitLabel = item.optString("submit_label").trim().take(120)
        val busyLabel = item.optString("busy_label").trim().take(80)
        val failureMessage = item.optString("failure_message").trim().take(240)
        val fallbackLabel = item.optString("fallback_label").trim().take(80)
        val choicesSource = item.optJSONArray("choices") ?: return null
        if (
            !validOpaqueToken(token) ||
            !safeExternalUrl(submitUrl) ||
            title.isBlank() ||
            message.isBlank() ||
            inputLabel.isBlank() ||
            initialValue.isBlank() ||
            minimum < 0 ||
            maximum < minimum ||
            maximum > 1_000_000_000L ||
            maxCharacters !in 1..12 ||
            supportingText.isBlank() ||
            invalidText.isBlank() ||
            submitLabel.isBlank() ||
            busyLabel.isBlank() ||
            failureMessage.isBlank() ||
            fallbackLabel.isBlank() ||
            choicesSource.length() !in 1..8
        ) {
            return null
        }
        val initialNumber = initialValue.toLongOrNull() ?: return null
        if (initialNumber !in minimum..maximum) return null
        val choices = (0 until choicesSource.length()).mapNotNull { index ->
            val choice = choicesSource.optJSONObject(index) ?: return@mapNotNull null
            val choiceLabel = choice.optString("label").trim().take(40)
            val choiceValue = choice.optString("value").trim()
            if (choiceLabel.isBlank() || choiceValue.length !in 1..256) {
                null
            } else {
                RemoteActionFormChoice(choiceLabel, choiceValue)
            }
        }
        if (choices.size != choicesSource.length()) return null
        return RemoteActionForm(
            token = token,
            submitUrl = submitUrl,
            title = title,
            message = message,
            choices = choices,
            inputLabel = inputLabel,
            inputSuffix = inputSuffix,
            initialValue = initialValue,
            minimum = minimum,
            maximum = maximum,
            maxCharacters = maxCharacters,
            supportingText = supportingText,
            invalidText = invalidText,
            submitLabel = submitLabel,
            busyLabel = busyLabel,
            failureMessage = failureMessage,
            fallbackLabel = fallbackLabel,
        )
    }

    internal fun parseExecutionTarget(body: String): RemoteLaunchTarget {
        if (body.length > MAX_RESPONSE_CHARS) {
            throw RemoteActionExecutionException("Получен слишком большой ответ.")
        }
        val root = runCatching { JSONObject(body) }.getOrNull()
            ?: throw RemoteActionExecutionException("Получен некорректный ответ.")
        if (root.optInt("version", 0) != 1) {
            throw RemoteActionExecutionException("Версия ответа не поддерживается.")
        }
        val primary = root.optString("url").trim()
        val fallback = root.optString("fallback").trim()
        val handler = root.optString("handler").trim()
        val alternateHandlers = parseAlternateHandlers(root)
            ?: throw RemoteActionExecutionException("Получены небезопасные обработчики действия.")
        if (
            !safeExternalUrl(primary) ||
            (fallback.isNotBlank() && !safeExternalUrl(fallback)) ||
            (handler.isNotBlank() && !safePackageName(handler))
        ) {
            throw RemoteActionExecutionException("Получен небезопасный адрес действия.")
        }
        return RemoteLaunchTarget(
            primaryUrl = primary,
            fallbackUrl = fallback,
            preferredHandler = handler,
            alternateHandlers = alternateHandlers,
        )
    }

    private fun validOpaqueToken(value: String): Boolean =
        value.length in 24..256 && Regex("^[A-Za-z0-9._-]+$").matches(value)

    private fun safeExternalUrl(value: String): Boolean {
        if (value.length !in 1..2048) return false
        val uri = runCatching { URI(value) }.getOrNull() ?: return false
        return uri.scheme.equals("https", ignoreCase = true) &&
            !uri.host.isNullOrBlank() &&
            uri.rawUserInfo.isNullOrBlank() &&
            (uri.port == -1 || uri.port == 443)
    }

    private fun safePackageName(value: String): Boolean =
        value.length in 3..255 &&
            Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+$").matches(value)

    private fun parseAlternateHandlers(item: JSONObject): List<String>? {
        val handlers = item.optJSONArray("alternate_handlers") ?: return emptyList()
        if (handlers.length() > 7) return null
        return (0 until handlers.length())
            .map { index -> handlers.optString(index).trim() }
            .takeIf { values ->
                values.all { it.isNotBlank() && safePackageName(it) } &&
                    values.distinct().size == values.size
            }
    }
}

object RemoteUiActionLauncher {
    suspend fun open(context: Context, action: RemoteUiAction): Boolean =
        withContext(Dispatchers.Main.immediate) {
            runCatching {
                RemoteContinuationLauncher.launch(context, action.target)
                true
            }.getOrDefault(false)
        }
}
