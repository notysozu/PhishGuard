package com.phishguard.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class AiReportTest {
    private val body = """
        {"report": {
          "verdict": "dangerous", "riskScore": 95, "mode": "ai",
          "headline": "This is a scam.",
          "summary": "It pretends to be your bank.",
          "redFlags": [
            {"category": "suspicious_link", "severity": "high",
             "evidence": "http://sbi.secure-login.xyz", "title": "Fake link",
             "explanation": "It goes somewhere else."}
          ],
          "reassuringSigns": [],
          "safetySteps": ["Open the bank's app yourself."],
          "ifAlreadyClicked": ["Change your password.", "Call your bank."]
        }}
    """.trimIndent()

    @Test
    fun parsesTheServerReport() {
        val report = AiReport.fromResponse(body)
        assertEquals("This is a scam.", report.headline)
        assertEquals("It pretends to be your bank.", report.summary)
        assertEquals(
            listOf(AiFlag("Fake link", "http://sbi.secure-login.xyz", "It goes somewhere else.")),
            report.redFlags,
        )
        assertEquals(listOf("Open the bank's app yourself."), report.safetySteps)
        assertEquals(2, report.ifAlreadyClicked.size)
        assertNull(report.notice)
    }

    @Test
    fun keepsTheNoticeWhenTheServerSendsOne() {
        val withNotice = body.replace("\"mode\": \"ai\",", "\"mode\": \"pattern\", \"notice\": \"Scanner only.\",")
        assertEquals("Scanner only.", AiReport.fromResponse(withNotice).notice)
    }

    @Test
    fun malformedResponsesThrowInsteadOfReturningAHalfReport() {
        assertThrows(Exception::class.java) { AiReport.fromResponse("<html>502</html>") }
        assertThrows(Exception::class.java) { AiReport.fromResponse("""{"report": {"headline": "x"}}""") }
    }

    @Test
    fun readsTheErrorMessageFromAFailedResponse() {
        assertEquals("Too many checks.", AiReport.errorFrom("""{"error": "Too many checks."}"""))
        assertNull(AiReport.errorFrom("Bad Gateway"))
        assertNull(AiReport.errorFrom(""))
    }
}
