package com.phishguard.app

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/** Calls the PhishGuard server's JSON API: `POST /api/v1/analyze`. */
object AiClient {
    /**
     * The deployed PhishGuard server. For a local `npm run dev`, use
     * `http://10.0.2.2:3000` on the emulator (debug builds only).
     */
    const val SERVER_URL = "https://phishguard.sonu-kumar.in"

    private const val CONNECT_TIMEOUT_MS = 10_000
    private const val READ_TIMEOUT_MS = 120_000

    /** Sends one message for analysis. Never throws; failures are in the [Result]. */
    suspend fun explain(text: String, serverUrl: String = SERVER_URL): Result<AiReport> =
        withContext(Dispatchers.IO) {
            runCatching {
                val connection = URL(serverUrl.trimEnd('/') + "/api/v1/analyze")
                    .openConnection() as HttpURLConnection
                try {
                    connection.requestMethod = "POST"
                    connection.connectTimeout = CONNECT_TIMEOUT_MS
                    connection.readTimeout = READ_TIMEOUT_MS
                    connection.doOutput = true
                    connection.setRequestProperty("Content-Type", "application/json")
                    connection.outputStream.use {
                        it.write(JSONObject().put("text", text).toString().toByteArray())
                    }
                    if (connection.responseCode != HttpURLConnection.HTTP_OK) {
                        val body = connection.errorStream?.bufferedReader()?.readText().orEmpty()
                        error(
                            AiReport.errorFrom(body)
                                ?: "Server returned ${connection.responseCode}"
                        )
                    }
                    AiReport.fromResponse(connection.inputStream.bufferedReader().readText())
                } finally {
                    connection.disconnect()
                }
            }
        }
}
