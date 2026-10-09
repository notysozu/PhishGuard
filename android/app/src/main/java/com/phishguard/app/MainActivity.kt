package com.phishguard.app

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import com.phishguard.app.ui.DetailScreen
import com.phishguard.app.ui.HomeScreen
import com.phishguard.app.ui.PhishGuardTheme

class MainActivity : ComponentActivity() {
    /** The flagged notification being viewed, if any. */
    private val selectedId = mutableStateOf<Long?>(null)

    /** Something the user pasted or shared to check by hand. Never stored. */
    private val pasted = mutableStateOf<FlaggedItem?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Store.init(this)
        Alerts.ensureChannels(this)
        handle(intent)
        enableEdgeToEdge()
        setContent { PhishGuardTheme { PhishGuardApp(selectedId, pasted) } }
    }

    // Tapping a warning, or sharing to PhishGuard, while the app is open arrives here.
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handle(intent)
    }

    private fun handle(intent: Intent) {
        val itemId = intent.getLongExtra(Alerts.EXTRA_ITEM_ID, NO_ITEM)
        val shared = intent.takeIf { it.action == Intent.ACTION_SEND }
            ?.getStringExtra(Intent.EXTRA_TEXT)
            ?.trim()
        when {
            itemId != NO_ITEM -> {
                pasted.value = null
                selectedId.value = itemId
            }
            !shared.isNullOrEmpty() -> {
                selectedId.value = null
                pasted.value = pastedItem(shared.take(MAX_CHECK_CHARS))
            }
        }
    }

    private companion object {
        const val NO_ITEM = -1L
    }
}

/** Matches the server's input limit. */
internal const val MAX_CHECK_CHARS = 20_000

@Composable
private fun PhishGuardApp(selectedId: MutableState<Long?>, pasted: MutableState<FlaggedItem?>) {
    val flagged by Store.flagged.collectAsState()
    val selected = flagged.firstOrNull { it.id == selectedId.value }
    val manual = pasted.value
    when {
        selected != null -> {
            BackHandler { selectedId.value = null }
            DetailScreen(
                item = selected,
                title = "From ${selected.appName}",
                checkOnOpen = false,
                onBack = { selectedId.value = null },
            )
        }
        manual != null -> {
            BackHandler { pasted.value = null }
            DetailScreen(
                item = manual,
                title = "Your check",
                checkOnOpen = true,
                onBack = { pasted.value = null },
            )
        }
        else -> HomeScreen(
            flagged = flagged,
            onOpen = { selectedId.value = it.id },
            onCheck = { text -> pasted.value = pastedItem(text) },
        )
    }
}

/** Wraps pasted or shared text as an item, with the on-device scan as its first findings. */
private fun pastedItem(text: String): FlaggedItem {
    val assessment = PhishScanner.assess(text)
    val now = System.currentTimeMillis()
    return FlaggedItem(
        id = now,
        packageName = "",
        appName = "You",
        text = text,
        time = now,
        score = assessment.score,
        signals = assessment.signals,
    )
}
