package com.phishguard.app

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

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

/**
 * App state shared between the listener service and the UI. Only flagged
 * notifications are kept; everything else is counted and discarded.
 */
object Store {
    private const val MAX_ITEMS = 50
    private const val PREFS = "phishguard"
    private const val KEY_SCANNED = "scanned"
    private const val KEY_SERVER = "server_url"

    /** The deployed PhishGuard server. For a local `npm run dev`, use http://10.0.2.2:3000 on the emulator. */
    const val DEFAULT_SERVER = "https://phishguard.sonu-kumar.in"

    val flagged = MutableStateFlow<List<FlaggedItem>>(emptyList())
    val scannedCount = MutableStateFlow(0)
    val listenerConnected = MutableStateFlow(false)

    private var loaded = false

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private fun file(context: Context) = File(context.filesDir, "flagged.json")

    @Synchronized
    fun init(context: Context) {
        if (loaded) return
        loaded = true
        scannedCount.value = prefs(context).getInt(KEY_SCANNED, 0)
        flagged.value = runCatching {
            val array = JSONArray(file(context).readText())
            List(array.length()) { fromJson(array.getJSONObject(it)) }
        }.getOrDefault(emptyList())
    }

    @Synchronized
    fun recordScan(context: Context) {
        scannedCount.value += 1
        prefs(context).edit().putInt(KEY_SCANNED, scannedCount.value).apply()
    }

    @Synchronized
    fun add(context: Context, item: FlaggedItem) {
        flagged.value = (listOf(item) + flagged.value).take(MAX_ITEMS)
        save(context)
    }

    @Synchronized
    fun clear(context: Context) {
        flagged.value = emptyList()
        scannedCount.value = 0
        prefs(context).edit().remove(KEY_SCANNED).apply()
        save(context)
    }

    fun serverUrl(context: Context): String =
        prefs(context).getString(KEY_SERVER, null) ?: DEFAULT_SERVER

    fun setServerUrl(context: Context, url: String) =
        prefs(context).edit().putString(KEY_SERVER, url.trim()).apply()

    private fun save(context: Context) {
        val array = JSONArray()
        flagged.value.forEach { array.put(toJson(it)) }
        runCatching { file(context).writeText(array.toString()) }
    }

    private fun toJson(item: FlaggedItem) = JSONObject().apply {
        put("id", item.id)
        put("pkg", item.packageName)
        put("app", item.appName)
        put("text", item.text)
        put("time", item.time)
        put("score", item.score)
        put("signals", JSONArray().also { array ->
            item.signals.forEach {
                array.put(JSONObject().apply {
                    put("category", it.category.name)
                    put("severity", it.severity.name)
                    put("evidence", it.evidence)
                    put("reason", it.reason)
                })
            }
        })
    }

    private fun fromJson(o: JSONObject): FlaggedItem {
        val signals = o.getJSONArray("signals")
        return FlaggedItem(
            id = o.getLong("id"),
            packageName = o.getString("pkg"),
            appName = o.getString("app"),
            text = o.getString("text"),
            time = o.getLong("time"),
            score = o.getInt("score"),
            signals = List(signals.length()) {
                val s = signals.getJSONObject(it)
                Signal(
                    Category.valueOf(s.getString("category")),
                    Severity.valueOf(s.getString("severity")),
                    s.getString("evidence"),
                    s.getString("reason"),
                )
            },
        )
    }
}
