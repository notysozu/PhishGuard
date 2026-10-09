package com.phishguard.app

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import java.io.File
import java.util.concurrent.Executors

/**
 * App state shared between the listener service and the UI. Only flagged
 * notifications are kept; everything else is counted and discarded.
 */
object Store {
    private const val MAX_ITEMS = 50
    private const val PREFS = "phishguard"
    private const val KEY_SCANNED = "scanned"

    val flagged = MutableStateFlow<List<FlaggedItem>>(emptyList())
    val scannedCount = MutableStateFlow(0)

    private var loaded = false

    /** File writes happen here, off the main thread and in order. */
    private val io = Executors.newSingleThreadExecutor()

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private fun file(context: Context) = File(context.filesDir, "flagged.json")

    /** Loads saved state once per process. Safe to call from any entry point. */
    @Synchronized
    fun init(context: Context) {
        if (loaded) return
        loaded = true
        scannedCount.value = prefs(context).getInt(KEY_SCANNED, 0)
        flagged.value = runCatching { FlaggedItemJson.decode(file(context).readText()) }
            .getOrDefault(emptyList())
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

    private fun save(context: Context) {
        val target = file(context)
        val json = FlaggedItemJson.encode(flagged.value)
        io.execute { runCatching { target.writeText(json) } }
    }
}
