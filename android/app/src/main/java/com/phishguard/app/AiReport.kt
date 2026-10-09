package com.phishguard.app

import org.json.JSONArray
import org.json.JSONObject

data class AiFlag(val title: String, val evidence: String, val explanation: String)

/** The parts of the server's report that the app shows. */
data class AiReport(
    val headline: String,
    val summary: String,
    val redFlags: List<AiFlag>,
    val safetySteps: List<String>,
    val ifAlreadyClicked: List<String>,
    val notice: String?,
) {
    companion object {
        /** Parses the body of a successful `POST /api/v1/analyze` response. */
        fun fromResponse(body: String): AiReport {
            val report = JSONObject(body).getJSONObject("report")
            val flags = report.getJSONArray("redFlags")
            return AiReport(
                headline = report.getString("headline"),
                summary = report.getString("summary"),
                redFlags = List(flags.length()) { index ->
                    val flag = flags.getJSONObject(index)
                    AiFlag(
                        flag.getString("title"),
                        flag.getString("evidence"),
                        flag.getString("explanation"),
                    )
                },
                safetySteps = report.getJSONArray("safetySteps").strings(),
                ifAlreadyClicked = report.getJSONArray("ifAlreadyClicked").strings(),
                notice = report.optString("notice").takeIf { it.isNotBlank() },
            )
        }

        /** The `error` message from a failed response, or null if there is none. */
        fun errorFrom(body: String): String? =
            runCatching { JSONObject(body).getString("error") }.getOrNull()

        private fun JSONArray.strings() = List(length()) { getString(it) }
    }
}
