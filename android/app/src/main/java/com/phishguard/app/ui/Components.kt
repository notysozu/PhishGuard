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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.phishguard.app.Severity

/** A section title that screen readers announce as a heading. */
@Composable
internal fun SectionHeading(text: String, modifier: Modifier = Modifier) {
    Text(
        text,
        style = MaterialTheme.typography.titleMedium,
        modifier = modifier.semantics { heading() },
    )
}

/** A small labelled pill. The label carries the meaning; the colour only reinforces it. */
@Composable
internal fun Badge(label: String, color: Color) {
    Text(
        label,
        style = MaterialTheme.typography.labelSmall,
        color = color,
        modifier = Modifier
            .background(color.copy(alpha = 0.12f), RoundedCornerShape(50))
            .padding(horizontal = 8.dp, vertical = 2.dp),
    )
}

/** A quote to highlight in the message, and how serious it is. */
internal data class Highlight(val quote: String, val severity: Severity)

/** The message text with each piece of evidence highlighted. */
@Composable
internal fun HighlightedMessage(text: String, highlights: List<Highlight>) {
    val annotated = buildAnnotatedString {
        append(text)
        for ((quote, severity) in highlights) {
            val start = if (quote.isBlank()) -1 else text.indexOf(quote, ignoreCase = true)
            if (start < 0) continue
            addStyle(
                SpanStyle(background = severity.color.copy(alpha = 0.25f)),
                start,
                start + quote.length,
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
                if (severity != null) Badge(severity.label, severity.color)
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
