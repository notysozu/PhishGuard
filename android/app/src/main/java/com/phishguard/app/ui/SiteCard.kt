package com.phishguard.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.phishguard.app.CheckOutcome
import com.phishguard.app.SiteCheck
import com.phishguard.app.SiteReport

/**
 * The server's website verification: classification, trust score, recommended
 * action, and every check with its evidence and its effect on the score.
 */
@Composable
internal fun SiteCard(site: SiteReport) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                SectionHeading("Website check", Modifier.weight(1f))
                Badge(site.classification.label, site.classification.color)
            }
            Text(
                site.domain,
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Spacer(Modifier.height(12.dp))
            TrustScore(site)

            Spacer(Modifier.height(12.dp))
            Text(site.headline, style = MaterialTheme.typography.titleSmall)
            Text(site.summary, style = MaterialTheme.typography.bodyMedium)

            Spacer(Modifier.height(10.dp))
            Column(
                Modifier
                    .fillMaxWidth()
                    .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(10.dp))
                    .padding(12.dp),
            ) {
                Text("Recommended action", style = MaterialTheme.typography.labelLarge)
                Text(site.recommendedAction, style = MaterialTheme.typography.bodyMedium)
            }

            Spacer(Modifier.height(14.dp))
            Text("How the score was reached", style = MaterialTheme.typography.titleSmall)
            Text(
                "Starts at 50. Each check adds or removes the points shown. " +
                    "A check that could not run changes nothing.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            site.checks.forEach { check ->
                HorizontalDivider(Modifier.padding(vertical = 10.dp))
                CheckRow(check)
            }

            if (site.redirectChain.size > 1) {
                HorizontalDivider(Modifier.padding(vertical = 10.dp))
                Text("Where the link leads", style = MaterialTheme.typography.titleSmall)
                site.redirectChain.forEachIndexed { index, address ->
                    Text(
                        "${index + 1}. $address",
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            Spacer(Modifier.height(12.dp))
            Text(
                "A good rating doesn't guarantee a website is legitimate, and a missing " +
                    "profile doesn't mean it is a scam.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun TrustScore(site: SiteReport) {
    // Read out as one value instead of a label, a number and an unlabelled bar.
    Column(
        Modifier.clearAndSetSemantics {
            contentDescription =
                "Trust score ${site.trustScore} out of 100: ${site.classification.label}"
        }
    ) {
        Row {
            Text(
                "Trust score",
                style = MaterialTheme.typography.labelLarge,
                modifier = Modifier.weight(1f),
            )
            Text("${site.trustScore}/100", style = MaterialTheme.typography.labelLarge)
        }
        Spacer(Modifier.height(6.dp))
        LinearProgressIndicator(
            progress = { site.trustScore / 100f },
            color = site.classification.color,
            modifier = Modifier.fillMaxWidth(),
        )
    }
    site.scoreNote?.let {
        Spacer(Modifier.height(4.dp))
        Text(
            it,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/** "+10", "−25", or a dash for a check that could not run. */
private fun SiteCheck.impactText() = when {
    outcome == CheckOutcome.UNAVAILABLE -> "–"
    impact > 0 -> "+$impact"
    impact < 0 -> "−${-impact}"
    else -> "0"
}

private fun SiteCheck.impactSpoken() = when {
    outcome == CheckOutcome.UNAVAILABLE || impact == 0 -> "no effect on the score"
    impact > 0 -> "adds $impact points"
    else -> "removes ${-impact} points"
}

@Composable
private fun CheckRow(check: SiteCheck) {
    Column(Modifier.semantics(mergeDescendants = true) {}) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Badge(check.outcome.label, check.outcome.color)
            Spacer(Modifier.width(8.dp))
            Text(
                check.label,
                style = MaterialTheme.typography.labelLarge,
                modifier = Modifier.weight(1f),
            )
            Text(
                check.impactText(),
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.semantics { contentDescription = check.impactSpoken() },
            )
        }
        Spacer(Modifier.height(4.dp))
        Text(check.summary, style = MaterialTheme.typography.bodyMedium)
        Text(
            check.evidence,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
