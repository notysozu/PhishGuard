package com.phishguard.app

import org.json.JSONArray
import org.json.JSONObject

/** A notification the scanner flagged, kept so the user can review it. */
data class FlaggedItem(
    val id: Long,
    val packageName: String,
    val appName: String,
    val text: String,
    val time: Long,
    val score: Int,
    val signals: List<Signal>,
) {
    val verdict get() = PhishScanner.verdict(score)
}

/** JSON encoding of flagged items for on-device storage. */
object FlaggedItemJson {
    fun encode(items: List<FlaggedItem>): String =
        JSONArray().also { array -> items.forEach { array.put(toJson(it)) } }.toString()

    /** Returns the items in [json]; entries that cannot be read are skipped. */
    fun decode(json: String): List<FlaggedItem> {
        val array = runCatching { JSONArray(json) }.getOrElse { return emptyList() }
        return (0 until array.length()).mapNotNull { index ->
            runCatching { fromJson(array.getJSONObject(index)) }.getOrNull()
        }
    }

    private fun toJson(item: FlaggedItem) = JSONObject().apply {
        put("id", item.id)
        put("pkg", item.packageName)
        put("app", item.appName)
        put("text", item.text)
        put("time", item.time)
        put("score", item.score)
        put("signals", JSONArray().also { array ->
            item.signals.forEach { signal ->
                array.put(JSONObject().apply {
                    put("category", signal.category.name)
                    put("severity", signal.severity.name)
                    put("evidence", signal.evidence)
                    put("reason", signal.reason)
                })
            }
        })
    }

    private fun fromJson(json: JSONObject): FlaggedItem {
        val signals = json.getJSONArray("signals")
        return FlaggedItem(
            id = json.getLong("id"),
            packageName = json.getString("pkg"),
            appName = json.getString("app"),
            text = json.getString("text"),
            time = json.getLong("time"),
            score = json.getInt("score"),
            signals = List(signals.length()) { index ->
                val signal = signals.getJSONObject(index)
                Signal(
                    Category.valueOf(signal.getString("category")),
                    Severity.valueOf(signal.getString("severity")),
                    signal.getString("evidence"),
                    signal.getString("reason"),
                )
            },
        )
    }
}
