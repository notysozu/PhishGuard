package com.phishguard.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PhishScannerTest {
    private fun score(text: String) = PhishScanner.assess(text).score

    @Test
    fun lookalikeBankMessageIsDangerous() {
        val assessment = PhishScanner.assess(
            "PayPal\nUrgent: your account has been suspended. Verify your identity " +
                "within 24 hours: http://paypal.com.account-verify.secure-login.xyz/restore"
        )
        assertEquals(Verdict.DANGEROUS, assessment.verdict)
        assertTrue(assessment.isFlagged)
    }

    @Test
    fun deliveryFeeTextWithShortenerIsFlagged() {
        val assessment = PhishScanner.assess(
            "USPS: Your package could not be delivered. Pay a small redelivery fee " +
                "of \$1.99: https://bit.ly/3xUsps-redeliver"
        )
        assertTrue(assessment.isFlagged)
        assertTrue(assessment.signals.any { it.category == Category.PAYMENT_REQUEST })
    }

    @Test
    fun leetSpeakBrandIsCaught() {
        val signals = PhishScanner.scan("Claim at www.amaz0n-rewards.top/claim")
        assertEquals(Severity.HIGH, signals.single().severity)
        assertEquals("www.amaz0n-rewards.top/claim", signals.single().evidence)
    }

    @Test
    fun rawIpAndHiddenDestinationLinksAreHighSeverity() {
        assertEquals(Severity.HIGH, PhishScanner.scan("Open http://198.51.100.7/login").single().severity)
        assertEquals(Severity.HIGH, PhishScanner.scan("Open https://bank.com@evil.example.com/a").single().severity)
    }

    @Test
    fun oneSignalPerLinkListsEveryReason() {
        val signal = PhishScanner.scan("http://paypal.com.a.b.secure-login.xyz/x").single()
        assertTrue(signal.reason.contains("actually goes to secure-login.xyz"))
        assertTrue(signal.reason.contains("subdomains"))
        assertTrue(signal.reason.contains("not encrypted"))
    }

    @Test
    fun ordinaryMessagesAreNotFlagged() {
        assertEquals(0, score("Mum\nDinner at 8? I'll bring dessert."))
        assertEquals(0, score("Amazon\nYour order has shipped. Track it at https://www.amazon.in/orders"))
        assertEquals(0, score("Priya\nsent the notes to priya@gmail.com"))
        assertFalse(PhishScanner.assess("See you tomorrow").isFlagged)
    }

    @Test
    fun evidenceIsAlwaysAVerbatimQuote() {
        val text = "URGENT!! Share the OTP now and claim your prize at www.amaz0n-rewards.top/claim."
        for (signal in PhishScanner.scan(text)) assertTrue(signal.evidence, text.contains(signal.evidence))
    }

    @Test
    fun repeatsOfOneCategoryCannotReachDangerousAlone() {
        val assessment = PhishScanner.assess("urgent act now right away last chance today only final notice")
        assertTrue(assessment.score < PhishScanner.DANGEROUS_AT)
    }

    @Test
    fun aBrandNameOnAThrowawayEndingIsNotTheBrand() {
        assertEquals(Severity.HIGH, PhishScanner.scan("Sign in at https://paypal.xyz/login").single().severity)
        assertEquals(0, score("Sign in at https://www.paypal.com/signin"))
    }

    @Test
    fun advanceFeesAndTaxesToClaimAPrizeAreFlagged() {
        for (text in listOf("pay the clearance fee", "tax upfront", "pay the tax first", "release charges apply")) {
            assertTrue(text, PhishScanner.scan(text).any { it.category == Category.PAYMENT_REQUEST })
        }
    }

    @Test
    fun verdictThresholds() {
        assertEquals(Verdict.LIKELY_SAFE, PhishScanner.verdict(PhishScanner.SUSPICIOUS_AT - 1))
        assertEquals(Verdict.SUSPICIOUS, PhishScanner.verdict(PhishScanner.SUSPICIOUS_AT))
        assertEquals(Verdict.SUSPICIOUS, PhishScanner.verdict(PhishScanner.DANGEROUS_AT - 1))
        assertEquals(Verdict.DANGEROUS, PhishScanner.verdict(PhishScanner.DANGEROUS_AT))
    }

    @Test
    fun registrableDomainHandlesTwoPartSuffixes() {
        assertEquals("example.co.uk", PhishScanner.registrableDomain("login.secure.example.co.uk"))
        assertEquals("example.com", PhishScanner.registrableDomain("a.b.example.com"))
    }
}
