package com.phishguard.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.phishguard.app.Severity
import com.phishguard.app.Signal

/** A section title that screen readers announce as a heading. */
@Composable
internal fun SectionHeading(text: String, modifier: Modifier = Modifier) {
    Text(
        text,
        style = MaterialTheme.typography.titleMedium,
        modifier = modifier.semantics { heading() },
    )
}

/** Severity as a labelled pill, so it does not depend on colour alone. */
@Composable
internal fun SeverityBadge(severity: Severity) {
    Text(
        severity.label,
        style = MaterialTheme.typography.labelSmall,
        color = severity.color,
        modifier = Modifier
            .background(severity.color.copy(alpha = 0.12f), RoundedCornerShape(50))
            .padding(horizontal = 8.dp, vertical = 2.dp),
    )
}

/** The notification text with each piece of evidence highlighted. */
@Composable
internal fun HighlightedMessage(text: String, signals: List<Signal>) {
    val annotated = buildAnnotatedString {
        append(text)
        for (signal in signals) {
            val start = text.indexOf(signal.evidence, ignoreCase = true)
            if (start < 0) continue
            addStyle(
                SpanStyle(background = signal.severity.color.copy(alpha = 0.25f)),
                start,
                start + signal.evidence.length,
            )
        }
    }
    Text(
        annotated,
        fontFamily = FontFamily.Monospace,
        style = MaterialTheme.typography.bodyMedium,
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(12.dp))
            .padding(12.dp),
    )
}

/** One warning sign: what it is, the quoted evidence, and why it matters. */
@Composable
internal fun ReasonCard(
    title: String,
    evidence: String,
    explanation: String,
    severity: Severity? = null,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        // Merged so a screen reader reads the card as one item.
        Column(Modifier.padding(16.dp).semantics(mergeDescendants = true) {}) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    title,
                    style = MaterialTheme.typography.titleSmall,
                    modifier = Modifier.weight(1f),
                )
                if (severity != null) SeverityBadge(severity)
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

/** A titled, numbered list of steps. */
@Composable
internal fun Steps(title: String, steps: List<String>) {
    Column {
        SectionHeading(title)
        Spacer(Modifier.height(6.dp))
        steps.forEachIndexed { index, step ->
            Text("${index + 1}. $step", style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(4.dp))
        }
    }
}
