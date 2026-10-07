package com.phishguard.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PhishScannerTest {
    private fun score(text: String) = PhishScanner.score(PhishScanner.scan(text))

    @Test
    fun lookalikeBankMessageIsDangerous() {
        val text = "PayPal\nUrgent: your account has been suspended. Verify your identity " +
            "within 24 hours: http://paypal.com.account-verify.secure-login.xyz/restore"
        assertEquals(Verdict.DANGEROUS, PhishScanner.verdict(score(text)))
    }

    @Test
    fun deliveryFeeTextWithShortenerIsFlagged() {
        val text = "USPS: Your package could not be delivered. Pay a small redelivery fee " +
            "of \$1.99: https://bit.ly/3xUsps-redeliver"
        assertTrue(score(text) >= PhishScanner.SUSPICIOUS_AT)
    }

    @Test
    fun leetSpeakBrandIsCaught() {
        val signals = PhishScanner.scan("Claim at www.amaz0n-rewards.top/claim")
        assertEquals(Severity.HIGH, signals.single().severity)
        assertEquals("www.amaz0n-rewards.top/claim", signals.single().evidence)
    }

    @Test
    fun ordinaryMessagesAreNotFlagged() {
        assertEquals(0, score("Mum\nDinner at 8? I'll bring dessert."))
        assertEquals(0, score("Amazon\nYour order has shipped. Track it at https://www.amazon.in/orders"))
        assertEquals(0, score("Priya\nsent the notes to priya@gmail.com"))
    }
}
