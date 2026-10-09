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
    /** The flagged item being viewed, or null for the home screen. */
    private val selectedId = mutableStateOf<Long?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Store.init(this)
        Alerts.ensureChannels(this)
        selectedId.value = intent.itemId()
        enableEdgeToEdge()
        setContent { PhishGuardTheme { PhishGuardApp(selectedId) } }
    }

    // Tapping a warning while the app is open arrives here.
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        intent.itemId()?.let { selectedId.value = it }
    }

    private fun Intent.itemId(): Long? =
        getLongExtra(Alerts.EXTRA_ITEM_ID, NO_ITEM).takeIf { it != NO_ITEM }

    private companion object {
        const val NO_ITEM = -1L
    }
}

@Composable
private fun PhishGuardApp(selectedId: MutableState<Long?>) {
    val flagged by Store.flagged.collectAsState()
    val selected = flagged.firstOrNull { it.id == selectedId.value }
    if (selected == null) {
        HomeScreen(flagged, onOpen = { selectedId.value = it.id })
    } else {
        BackHandler { selectedId.value = null }
        DetailScreen(selected, onBack = { selectedId.value = null })
    }
}
