package com.phishguard.app

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

data class AiFlag(val title: String, val evidence: String, val explanation: String)

data class AiReport(
    val headline: String,
    val summary: String,
    val redFlags: List<AiFlag>,
    val safetySteps: List<String>,
    val ifAlreadyClicked: List<String>,
    val notice: String?,
)

/** Calls the PhishGuard web app's /api/analyze endpoint (NDJSON stream). */
object AiClient {
    suspend fun explain(serverUrl: String, text: String): Result<AiReport> =
        withContext(Dispatchers.IO) {
            runCatching {
                val connection = URL(serverUrl.trimEnd('/') + "/api/analyze")
                    .openConnection() as HttpURLConnection
                try {
                    connection.requestMethod = "POST"
                    connection.connectTimeout = 10_000
                    connection.readTimeout = 120_000
                    connection.doOutput = true
                    connection.setRequestProperty("Content-Type", "application/json")
                    connection.outputStream.use {
                        it.write(JSONObject().put("text", text).toString().toByteArray())
                    }
                    if (connection.responseCode != 200) {
                        val body = connection.errorStream?.bufferedReader()?.readText().orEmpty()
                        val message = runCatching { JSONObject(body).getString("error") }
                            .getOrDefault("Server returned ${connection.responseCode}")
                        error(message)
                    }
                    var report: AiReport? = null
                    connection.inputStream.bufferedReader().forEachLine { line ->
                        if (line.isBlank()) return@forEachLine
                        val event = JSONObject(line)
                        when (event.getString("type")) {
                            "report" -> report = parse(event.getJSONObject("report"))
                            "error" -> error(event.getString("message"))
                        }
                    }
                    report ?: error("The server sent no result")
                } finally {
                    connection.disconnect()
                }
            }
        }

    private fun JSONArray.strings() = List(length()) { getString(it) }

    private fun parse(o: JSONObject): AiReport {
        val flags = o.getJSONArray("redFlags")
        return AiReport(
            headline = o.getString("headline"),
            summary = o.getString("summary"),
            redFlags = List(flags.length()) {
                val f = flags.getJSONObject(it)
                AiFlag(f.getString("title"), f.getString("evidence"), f.getString("explanation"))
            },
            safetySteps = o.getJSONArray("safetySteps").strings(),
            ifAlreadyClicked = o.getJSONArray("ifAlreadyClicked").strings(),
            notice = o.optString("notice").takeIf { it.isNotBlank() },
        )
    }
}
