package com.phishguard.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.format.DateUtils
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LifecycleResumeEffect
import kotlinx.coroutines.launch

private val Teal = Color(0xFF0F766E)
private val Red = Color(0xFFDC2626)
private val Amber = Color(0xFFD97706)
private val Green = Color(0xFF059669)

private val Verdict.color
    get() = when (this) {
        Verdict.DANGEROUS -> Red
        Verdict.SUSPICIOUS -> Amber
        Verdict.LIKELY_SAFE -> Green
    }

private val Verdict.label
    get() = when (this) {
        Verdict.DANGEROUS -> "Likely a scam"
        Verdict.SUSPICIOUS -> "Be careful"
        Verdict.LIKELY_SAFE -> "Looks okay"
    }

private val Severity.color
    get() = when (this) {
        Severity.HIGH -> Red
        Severity.MEDIUM -> Amber
        Severity.LOW -> Color.Gray
    }

class MainActivity : ComponentActivity() {
    private val selectedId = mutableStateOf<Long?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Store.init(this)
        Alerts.ensureChannels(this)
        selectedId.value = intent.itemId()
        enableEdgeToEdge()
        setContent {
            val colors = if (isSystemInDarkTheme()) darkColorScheme(primary = Color(0xFF2DD4BF))
            else lightColorScheme(primary = Teal)
            MaterialTheme(colorScheme = colors) { App(selectedId) }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        intent.itemId()?.let { selectedId.value = it }
    }

    private fun Intent.itemId(): Long? =
        getLongExtra(Alerts.EXTRA_ITEM_ID, -1).takeIf { it != -1L }
}

@Composable
private fun App(selectedId: MutableState<Long?>) {
    val flagged by Store.flagged.collectAsState()
    val selected = flagged.firstOrNull { it.id == selectedId.value }
    if (selected != null) {
        BackHandler { selectedId.value = null }
        DetailScreen(selected, onBack = { selectedId.value = null })
    } else {
        HomeScreen(flagged, onOpen = { selectedId.value = it.id })
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun HomeScreen(flagged: List<FlaggedItem>, onOpen: (FlaggedItem) -> Unit) {
    val context = LocalContext.current
    val scanned by Store.scannedCount.collectAsState()

    fun hasAccess() =
        context.packageName in NotificationManagerCompat.getEnabledListenerPackages(context)
    fun canNotify() = Build.VERSION.SDK_INT < 33 || ContextCompat.checkSelfPermission(
        context, Manifest.permission.POST_NOTIFICATIONS
    ) == PackageManager.PERMISSION_GRANTED

    var access by remember { mutableStateOf(hasAccess()) }
    var notify by remember { mutableStateOf(canNotify()) }
    LifecycleResumeEffect(Unit) {
        access = hasAccess()
        notify = canNotify()
        onPauseOrDispose { }
    }
    val askNotify = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { notify = it }

    Scaffold(topBar = { TopAppBar(title = { Text("PhishGuard") }) }) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                StatusCard(
                    on = access,
                    scanned = scanned,
                    flagged = flagged.size,
                    onEnable = {
                        context.startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
                    },
                )
            }
            if (!notify) item {
                SetupCard(
                    title = "Allow warnings",
                    body = "PhishGuard needs permission to show you a warning when it spots a scam.",
                    action = "Allow",
                    onClick = { askNotify.launch(Manifest.permission.POST_NOTIFICATIONS) },
                )
            }
            if (access && notify) item {
                OutlinedButton(onClick = { Alerts.sendTest(context) }, modifier = Modifier.fillMaxWidth()) {
                    Text("Send a fake scam message to test")
                }
            }
            item {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        "Flagged notifications",
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.weight(1f),
                    )
                    if (flagged.isNotEmpty()) TextButton(onClick = { Store.clear(context) }) {
                        Text("Clear")
                    }
                }
            }
            if (flagged.isEmpty()) item {
                Text(
                    if (access) "Nothing suspicious so far. You'll get a warning here the moment something looks off."
                    else "Turn on live checking above to get started.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            items(flagged, key = { it.id }) { item -> FlaggedRow(item, onClick = { onOpen(item) }) }
        }
    }
}

@Composable
private fun StatusCard(on: Boolean, scanned: Int, flagged: Int, onEnable: () -> Unit) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = if (on) Teal else MaterialTheme.colorScheme.surfaceVariant,
            contentColor = if (on) Color.White else MaterialTheme.colorScheme.onSurfaceVariant,
        ),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(20.dp)) {
            Text(
                if (on) "Live checking is on" else "Live checking is off",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.SemiBold,
            )
            Spacer(Modifier.height(6.dp))
            if (on) {
                Text("$scanned notifications checked · $flagged flagged")
                Spacer(Modifier.height(6.dp))
                Text(
                    "Checks happen on this phone. Notifications that look fine are never stored.",
                    style = MaterialTheme.typography.bodySmall,
                )
            } else {
                Text(
                    "To check messages as they arrive, PhishGuard needs notification access. " +
                        "On the next screen, switch on PhishGuard.",
                )
                Spacer(Modifier.height(12.dp))
                Button(onClick = onEnable) { Text("Turn on") }
            }
        }
    }
}

@Composable
private fun SetupCard(title: String, body: String, action: String, onClick: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(4.dp))
            Text(body, style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(8.dp))
            Button(onClick = onClick) { Text(action) }
        }
    }
}

@Composable
private fun FlaggedRow(item: FlaggedItem, onClick: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth().clickable(onClick = onClick)) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(10.dp).background(item.verdict.color, CircleShape))
                Spacer(Modifier.width(8.dp))
                Text(
                    item.verdict.label,
                    color = item.verdict.color,
                    style = MaterialTheme.typography.labelLarge,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    "${item.appName} · " + DateUtils.getRelativeTimeSpanString(item.time),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.height(6.dp))
            Text(
                item.text,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

private sealed interface AiState {
    data object Idle : AiState
    data object Loading : AiState
    data class Done(val report: AiReport) : AiState
    data class Failed(val message: String) : AiState
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DetailScreen(item: FlaggedItem, onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var ai by remember(item.id) { mutableStateOf<AiState>(AiState.Idle) }
    val report = (ai as? AiState.Done)?.report

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("From ${item.appName}") },
                navigationIcon = { TextButton(onClick = onBack) { Text("Back") } },
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                Card(
                    colors = CardDefaults.cardColors(containerColor = item.verdict.color.copy(alpha = 0.12f)),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(Modifier.padding(16.dp)) {
                        Text(
                            "${item.verdict.label} · risk ${item.score}/100",
                            color = item.verdict.color,
                            style = MaterialTheme.typography.labelLarge,
                        )
                        Spacer(Modifier.height(6.dp))
                        Text(
                            report?.headline ?: when (item.verdict) {
                                Verdict.DANGEROUS -> "This looks like a scam. Don't tap or reply."
                                else -> "Something is off here. Treat it with caution."
                            },
                            style = MaterialTheme.typography.titleMedium,
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            report?.summary
                                ?: "This notification shows tricks scammers commonly use. The highlighted parts below are the warning signs.",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                }
            }
            item { HighlightedMessage(item) }

            if (report != null) {
                items(report.redFlags) { ReasonCard(it.title, it.evidence, it.explanation, null) }
                item { Steps("What to do now", report.safetySteps) }
                if (report.ifAlreadyClicked.isNotEmpty())
                    item { Steps("If you already tapped, replied or paid", report.ifAlreadyClicked) }
                report.notice?.let {
                    item { Text(it, style = MaterialTheme.typography.bodySmall) }
                }
            } else {
                items(item.signals) {
                    ReasonCard(it.category.title, it.evidence, "${it.reason}. ${it.category.why}", it.severity)
                }
                item {
                    Steps(
                        "What to do now",
                        listOf(
                            "Don't tap any links or call numbers in the message.",
                            "Don't reply, even to say \"stop\".",
                            "If it claims to be from a company you use, open their official app yourself to check.",
                            "Report it as spam in the app it came from, then delete it.",
                        ),
                    )
                }
                item {
                    when (val state = ai) {
                        AiState.Loading -> Row(verticalAlignment = Alignment.CenterVertically) {
                            CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                            Spacer(Modifier.width(12.dp))
                            Text("Asking the AI analyst…")
                        }
                        else -> Column {
                            if (state is AiState.Failed) Text(
                                "Couldn't get an AI explanation: ${state.message}",
                                color = MaterialTheme.colorScheme.error,
                                style = MaterialTheme.typography.bodySmall,
                            )
                            OutlinedButton(
                                onClick = {
                                    ai = AiState.Loading
                                    scope.launch {
                                        ai = AiClient.explain(Store.serverUrl(context), item.text).fold(
                                            onSuccess = { AiState.Done(it) },
                                            onFailure = { AiState.Failed(it.message ?: "unknown error") },
                                        )
                                    }
                                },
                                modifier = Modifier.fillMaxWidth(),
                            ) { Text("Explain with AI") }
                            Text(
                                "Sends this one message to your PhishGuard server.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun HighlightedMessage(item: FlaggedItem) {
    val text = buildAnnotatedString {
        append(item.text)
        for (signal in item.signals) {
            val start = item.text.indexOf(signal.evidence, ignoreCase = true)
            if (start < 0) continue
            addStyle(
                SpanStyle(background = signal.severity.color.copy(alpha = 0.25f)),
                start,
                start + signal.evidence.length,
            )
        }
    }
    Text(
        text,
        fontFamily = FontFamily.Monospace,
        style = MaterialTheme.typography.bodyMedium,
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(12.dp))
            .padding(12.dp),
    )
}

@Composable
private fun ReasonCard(title: String, evidence: String, explanation: String, severity: Severity?) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(title, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                if (severity != null) Box(Modifier.size(8.dp).background(severity.color, CircleShape))
            }
            if (evidence.isNotBlank()) {
                Spacer(Modifier.height(4.dp))
                Text(
                    evidence,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.height(6.dp))
            Text(explanation, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun Steps(title: String, steps: List<String>) {
    Column {
        Text(title, style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(6.dp))
        steps.forEachIndexed { i, step ->
            Text("${i + 1}. $step", style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(4.dp))
        }
    }
}
