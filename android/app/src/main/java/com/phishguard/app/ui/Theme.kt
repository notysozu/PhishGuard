package com.phishguard.app.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import com.phishguard.app.CheckOutcome
import com.phishguard.app.ReportVerdict
import com.phishguard.app.Severity
import com.phishguard.app.SiteClassification
import com.phishguard.app.Verdict

internal val Teal = Color(0xFF0F766E)
private val TealLight = Color(0xFF2DD4BF)
private val Red = Color(0xFFDC2626)
private val Amber = Color(0xFFB45309)
private val Green = Color(0xFF047857)
private val Gray = Color(0xFF64748B)
private val Sky = Color(0xFF0369A1)

@Composable
fun PhishGuardTheme(content: @Composable () -> Unit) {
    val colors = if (isSystemInDarkTheme()) darkColorScheme(primary = TealLight)
    else lightColorScheme(primary = Teal)
    MaterialTheme(colorScheme = colors, content = content)
}

// Each state has a text label as well as a colour, so it never relies on colour alone.

internal val Verdict.color
    get() = when (this) {
        Verdict.DANGEROUS -> Red
        Verdict.SUSPICIOUS -> Amber
        Verdict.LIKELY_SAFE -> Green
    }

internal val Verdict.label
    get() = when (this) {
        Verdict.DANGEROUS -> "Likely a scam"
        Verdict.SUSPICIOUS -> "Be careful"
        Verdict.LIKELY_SAFE -> "Looks okay"
    }

internal val Severity.color
    get() = when (this) {
        Severity.HIGH -> Red
        Severity.MEDIUM -> Amber
        Severity.LOW -> Gray
    }

internal val Severity.label
    get() = when (this) {
        Severity.HIGH -> "High risk"
        Severity.MEDIUM -> "Medium risk"
        Severity.LOW -> "Low risk"
    }

/** The on-device verdict expressed in the server's terms, so one card can show either. */
internal fun Verdict.asReportVerdict() = when (this) {
    Verdict.DANGEROUS -> ReportVerdict.DANGEROUS
    Verdict.SUSPICIOUS -> ReportVerdict.SUSPICIOUS
    Verdict.LIKELY_SAFE -> ReportVerdict.LIKELY_SAFE
}

internal val ReportVerdict.color
    get() = when (this) {
        ReportVerdict.DANGEROUS -> Red
        ReportVerdict.SUSPICIOUS -> Amber
        ReportVerdict.UNVERIFIED -> Sky
        ReportVerdict.LIKELY_SAFE -> Green
    }

internal val ReportVerdict.label
    get() = when (this) {
        ReportVerdict.DANGEROUS -> "Likely a scam"
        ReportVerdict.SUSPICIOUS -> "Be careful"
        ReportVerdict.UNVERIFIED -> "Not verified"
        ReportVerdict.LIKELY_SAFE -> "Looks okay"
    }

internal val SiteClassification.color
    get() = when (this) {
        SiteClassification.CONFIRMED_MALICIOUS -> Red
        SiteClassification.SUSPICIOUS -> Amber
        SiteClassification.UNVERIFIED -> Sky
        SiteClassification.NO_KNOWN_ISSUES -> Green
    }

internal val SiteClassification.label
    get() = when (this) {
        SiteClassification.CONFIRMED_MALICIOUS -> "Known dangerous"
        SiteClassification.SUSPICIOUS -> "Suspicious"
        SiteClassification.UNVERIFIED -> "Unverified"
        SiteClassification.NO_KNOWN_ISSUES -> "No known problems"
    }

internal val CheckOutcome.color
    get() = when (this) {
        CheckOutcome.GOOD -> Green
        CheckOutcome.NEUTRAL, CheckOutcome.UNAVAILABLE -> Gray
        CheckOutcome.CAUTION -> Amber
        CheckOutcome.BAD -> Red
    }

internal val CheckOutcome.label
    get() = when (this) {
        CheckOutcome.GOOD -> "Good sign"
        CheckOutcome.NEUTRAL -> "No concern"
        CheckOutcome.CAUTION -> "Caution"
        CheckOutcome.BAD -> "Warning"
        CheckOutcome.UNAVAILABLE -> "Not checked"
    }
