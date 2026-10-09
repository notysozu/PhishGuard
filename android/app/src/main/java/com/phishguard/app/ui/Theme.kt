package com.phishguard.app.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import com.phishguard.app.Severity
import com.phishguard.app.Verdict

internal val Teal = Color(0xFF0F766E)
private val TealLight = Color(0xFF2DD4BF)
private val Red = Color(0xFFDC2626)
private val Amber = Color(0xFFB45309)
private val Green = Color(0xFF047857)
private val Gray = Color(0xFF64748B)

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
