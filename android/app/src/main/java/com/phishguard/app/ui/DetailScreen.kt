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
import kotlinx.coroutines.launch

private sealed interface AiState {
    data object Idle : AiState
    data object Loading : AiState
    data class Done(val report: AiReport) : AiState
    data class Failed(val message: String) : AiState
}

/** Why one notification was flagged, with an optional AI explanation. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun DetailScreen(item: FlaggedItem, onBack: () -> Unit) {
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
                VerdictCard(
                    item = item,
                    headline = report?.headline ?: Guidance.headline(item.verdict),
                    summary = report?.summary ?: Guidance.SUMMARY,
                )
            }
            item { HighlightedMessage(item.text, item.signals) }

            if (report != null) {
                items(report.redFlags) { flag ->
                    ReasonCard(flag.title, flag.evidence, flag.explanation)
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
                item { Steps("What to do now", Guidance.SAFETY_STEPS) }
                item {
                    AiRequest(
                        state = ai,
                        onRequest = {
                            ai = AiState.Loading
                            scope.launch {
                                ai = AiClient.explain(item.text).fold(
                                    onSuccess = { AiState.Done(it) },
                                    onFailure = { AiState.Failed(it.message ?: "unknown error") },
                                )
                            }
                        },
                    )
                }
            }
        }
    }
}

@Composable
private fun VerdictCard(item: FlaggedItem, headline: String, summary: String) {
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
                headline,
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.semantics { heading() },
            )
            Spacer(Modifier.height(4.dp))
            Text(summary, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

/** The "Explain with AI" button, its progress indicator and any error. */
@Composable
private fun AiRequest(state: AiState, onRequest: () -> Unit) {
    // A live region, so progress and errors are announced by screen readers.
    Column(Modifier.semantics { liveRegion = LiveRegionMode.Polite }) {
        if (state is AiState.Loading) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(12.dp))
                Text("Asking the AI analyst…")
            }
            return@Column
        }
        if (state is AiState.Failed) {
            Text(
                "Couldn't get an AI explanation: ${state.message}",
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
        }
        OutlinedButton(onClick = onRequest, modifier = Modifier.fillMaxWidth()) {
            Text("Explain with AI")
        }
        Text(
            "Sends this one message to the PhishGuard server.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
