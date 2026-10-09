package com.phishguard.app

import org.json.JSONArray
import org.json.JSONObject

/** The server's verdict on a message. Unlike the on-device [Verdict], it can be "unverified". */
enum class ReportVerdict { DANGEROUS, SUSPICIOUS, UNVERIFIED, LIKELY_SAFE }

/** How sure the server is about a website, from worst to best. */
enum class SiteClassification { CONFIRMED_MALICIOUS, SUSPICIOUS, UNVERIFIED, NO_KNOWN_ISSUES }

enum class CheckOutcome { GOOD, NEUTRAL, CAUTION, BAD, UNAVAILABLE }

data class AiFlag(
    val title: String,
    val evidence: String,
    val explanation: String,
    val severity: Severity = Severity.MEDIUM,
)

/** One line of evidence in the website check, with its effect on the trust score. */
data class SiteCheck(
    val label: String,
    val outcome: CheckOutcome,
    val summary: String,
    val evidence: String,
    val impact: Int,
)

/** The server's verification of the main link in a message. */
data class SiteReport(
    val domain: String,
    val classification: SiteClassification,
    /** 0 (no trust) to 100. */
    val trustScore: Int,
    val scoreNote: String?,
    val headline: String,
    val summary: String,
    val recommendedAction: String,
    val checks: List<SiteCheck>,
    val redirectChain: List<String>,
)

/** The parts of the server's report that the app shows. */
data class AiReport(
    val verdict: ReportVerdict,
    val riskScore: Int,
    val headline: String,
    val summary: String,
    val redFlags: List<AiFlag>,
    val safetySteps: List<String>,
    val ifAlreadyClicked: List<String>,
    val notice: String?,
    val site: SiteReport?,
) {
    companion object {
        /** Parses the body of a successful `POST /api/v1/analyze` response. */
        fun fromResponse(body: String): AiReport {
            val report = JSONObject(body).getJSONObject("report")
            val flags = report.getJSONArray("redFlags")
            return AiReport(
                verdict = enumOr(report.optString("verdict"), ReportVerdict.SUSPICIOUS),
                riskScore = report.optInt("riskScore", 0).coerceIn(0, 100),
                headline = report.getString("headline"),
                summary = report.getString("summary"),
                redFlags = List(flags.length()) { index ->
                    val flag = flags.getJSONObject(index)
                    AiFlag(
                        flag.getString("title"),
                        flag.getString("evidence"),
                        flag.getString("explanation"),
                        enumOr(flag.optString("severity"), Severity.MEDIUM),
                    )
                },
                safetySteps = report.getJSONArray("safetySteps").strings(),
                ifAlreadyClicked = report.getJSONArray("ifAlreadyClicked").strings(),
                notice = report.textOrNull("notice"),
                site = report.optJSONObject("site")?.let(::site),
            )
        }

        /** The `error` message from a failed response, or null if there is none. */
        fun errorFrom(body: String): String? =
            runCatching { JSONObject(body).getString("error") }.getOrNull()

        private fun site(json: JSONObject): SiteReport {
            val checks = json.optJSONArray("checks") ?: JSONArray()
            return SiteReport(
                domain = json.optString("domain"),
                classification = enumOr(
                    json.optString("classification"),
                    SiteClassification.UNVERIFIED,
                ),
                trustScore = json.optInt("trustScore", 50).coerceIn(0, 100),
                scoreNote = json.textOrNull("scoreNote"),
                headline = json.optString("headline"),
                summary = json.optString("summary"),
                recommendedAction = json.optString("recommendedAction"),
                checks = List(checks.length()) { index ->
                    val check = checks.getJSONObject(index)
                    SiteCheck(
                        label = check.optString("label"),
                        outcome = enumOr(check.optString("outcome"), CheckOutcome.NEUTRAL),
                        summary = check.optString("summary"),
                        evidence = check.optString("evidence"),
                        impact = check.optInt("impact", 0),
                    )
                },
                redirectChain = (json.optJSONArray("redirectChain") ?: JSONArray()).strings(),
            )
        }

        /**
         * Reads a server enum such as "no_known_issues". A value this version of the app does
         * not know becomes [fallback] instead of crashing, so a newer server stays compatible.
         */
        private inline fun <reified T : Enum<T>> enumOr(value: String, fallback: T): T =
            enumValues<T>().firstOrNull { it.name.equals(value, ignoreCase = true) } ?: fallback

        private fun JSONObject.textOrNull(key: String): String? =
            if (isNull(key)) null else optString(key).takeIf { it.isNotBlank() }

        private fun JSONArray.strings() = List(length()) { getString(it) }
    }
}
