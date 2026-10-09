package com.phishguard.app.ui

import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.phishguard.app.AiClient
import com.phishguard.app.AiReport
import com.phishguard.app.FlaggedItem
import com.phishguard.app.Guidance
import com.phishguard.app.ReportVerdict
import kotlinx.coroutines.launch

private sealed interface ServerState {
    data object Idle : ServerState
    data object Loading : ServerState
    data class Done(val report: AiReport) : ServerState
    data class Failed(val message: String) : ServerState
}

/**
 * The result for one message or link. It opens with the on-device findings;
 * the server's fuller check (AI explanation and website verification) is
 * fetched when the user asks, or straight away when [checkOnOpen] is set.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun DetailScreen(
    item: FlaggedItem,
    title: String,
    checkOnOpen: Boolean,
    onBack: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    var server by remember(item.id) {
        mutableStateOf(if (checkOnOpen) ServerState.Loading else ServerState.Idle)
    }
    val report = (server as? ServerState.Done)?.report

    suspend fun check() {
        server = ServerState.Loading
        server = AiClient.explain(item.text).fold(
            onSuccess = { ServerState.Done(it) },
            onFailure = { ServerState.Failed(it.message ?: "unknown error") },
        )
    }
    LaunchedEffect(item.id) { if (checkOnOpen) check() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(title) },
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
                when {
                    report != null -> VerdictCard(
                        verdict = report.verdict,
                        riskScore = report.riskScore,
                        headline = report.headline,
                        summary = report.summary,
                    )
                    // A pasted link has no on-device verdict worth showing while we wait.
                    checkOnOpen && server is ServerState.Loading -> CheckingCard()
                    else -> VerdictCard(
                        verdict = item.verdict.asReportVerdict(),
                        riskScore = item.score,
                        headline = Guidance.headline(item.verdict),
                        summary = Guidance.summary(item.verdict),
                    )
                }
            }
            item {
                // Highlight what the current findings quote: the server's once it has answered.
                val highlights = report?.redFlags?.map { Highlight(it.evidence, it.severity) }
                    ?: item.signals.map { Highlight(it.evidence, it.severity) }
                HighlightedMessage(item.text, highlights)
            }

            if (report != null) {
                report.site?.let { site -> item { SiteCard(site) } }
                items(report.redFlags) { flag ->
                    ReasonCard(flag.title, flag.evidence, flag.explanation, flag.severity)
                }
                item { Steps("What to do now", report.safetySteps) }
                if (report.ifAlreadyClicked.isNotEmpty()) {
                    item { Steps("If you already tapped, replied or paid", report.ifAlreadyClicked) }
                }
                report.notice?.let { notice ->
                    item { Text(notice, style = MaterialTheme.typography.bodySmall) }
                }
            } else {
                items(item.signals) { signal ->
                    ReasonCard(
                        title = signal.category.title,
                        evidence = signal.evidence,
                        explanation = "${signal.reason}. ${signal.category.why}",
                        severity = signal.severity,
                    )
                }
                if (item.signals.isNotEmpty()) {
                    item { Steps("What to do now", Guidance.SAFETY_STEPS) }
                }
                if (server !is ServerState.Loading || !checkOnOpen) {
                    item { ServerRequest(server, onRequest = { scope.launch { check() } }) }
                }
            }
        }
    }
}

@Composable
private fun VerdictCard(verdict: ReportVerdict, riskScore: Int, headline: String, summary: String) {
    Card(
        colors = CardDefaults.cardColors(containerColor = verdict.color.copy(alpha = 0.12f)),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(16.dp)) {
            Text(
                "${verdict.label} · risk $riskScore/100",
                color = verdict.color,
                style = MaterialTheme.typography.labelLarge,
            )
            Spacer(Modifier.height(6.dp))
            Text(
                headline,
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.semantics { heading() },
            )
            Spacer(Modifier.height(4.dp))
            Text(summary, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun CheckingCard() {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            Modifier.padding(16.dp).semantics { liveRegion = LiveRegionMode.Polite },
            verticalAlignment = Alignment.CenterVertically,
        ) {
            CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp)
            Spacer(Modifier.width(12.dp))
            Column {
                Text("Checking…", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Website age, threat lists, reputation and redirects.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

/** The button that asks the server for its fuller check, with progress and errors. */
@Composable
private fun ServerRequest(state: ServerState, onRequest: () -> Unit) {
    // A live region, so progress and errors are announced by screen readers.
    Column(Modifier.semantics { liveRegion = LiveRegionMode.Polite }) {
        if (state is ServerState.Loading) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(12.dp))
                Text("Asking the AI analyst and checking the website…")
            }
            return@Column
        }
        if (state is ServerState.Failed) {
            Text(
                "Couldn't complete the full check: ${state.message}",
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
        }
        OutlinedButton(onClick = onRequest, modifier = Modifier.fillMaxWidth()) {
            Text(if (state is ServerState.Failed) "Try again" else "Explain with AI and verify website")
        }
        Text(
            "Sends this one message to the PhishGuard server.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
