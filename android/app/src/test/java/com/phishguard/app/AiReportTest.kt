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

    private val bodyWithSite = body.replace(
        "\"reassuringSigns\": [],",
        """
        "reassuringSigns": [],
        "site": {
          "url": "https://example-lottery.com/", "finalUrl": "https://example-lottery.com/",
          "domain": "example-lottery.com", "classification": "unverified", "trustScore": 45,
          "scoreNote": null,
          "headline": "Unverified website",
          "summary": "No reliable confirmation of the lottery organizer was found.",
          "recommendedAction": "Verify the announcement on the organizer's official website.",
          "checks": [
            {"id": "domain_age", "label": "Domain age and ownership", "outcome": "bad",
             "summary": "Created only 12 days ago", "evidence": "Registered on 1 January 2026.",
             "impact": -25, "source": {"name": "ICANN", "url": "https://lookup.icann.org/"}},
            {"id": "trustpilot", "label": "Trustpilot reputation", "outcome": "unavailable",
             "summary": "Not checked", "evidence": "No API key.", "impact": 0},
            {"id": "future", "label": "A check added later", "outcome": "brand_new_outcome",
             "summary": "s", "evidence": "e", "impact": 3}
          ],
          "redirectChain": ["https://bit.ly/abc", "https://example-lottery.com/"]
        },
        """.trimIndent(),
    )

    @Test
    fun parsesTheWebsiteCheck() {
        val site = AiReport.fromResponse(bodyWithSite).site!!
        assertEquals("example-lottery.com", site.domain)
        assertEquals(SiteClassification.UNVERIFIED, site.classification)
        assertEquals(45, site.trustScore)
        assertNull(site.scoreNote)
        assertEquals("Verify the announcement on the organizer's official website.", site.recommendedAction)
        assertEquals(
            SiteCheck("Domain age and ownership", CheckOutcome.BAD, "Created only 12 days ago", "Registered on 1 January 2026.", -25),
            site.checks[0],
        )
        assertEquals(CheckOutcome.UNAVAILABLE, site.checks[1].outcome)
        assertEquals(2, site.redirectChain.size)
    }

    @Test
    fun valuesFromANewerServerFallBackInsteadOfCrashing() {
        val site = AiReport.fromResponse(bodyWithSite).site!!
        assertEquals(CheckOutcome.NEUTRAL, site.checks[2].outcome)
        val odd = body.replace("\"verdict\": \"dangerous\"", "\"verdict\": \"something_new\"")
        assertEquals(ReportVerdict.SUSPICIOUS, AiReport.fromResponse(odd).verdict)
    }

    @Test
    fun readsTheServerVerdictIncludingUnverified() {
        assertEquals(ReportVerdict.DANGEROUS, AiReport.fromResponse(body).verdict)
        assertEquals(95, AiReport.fromResponse(body).riskScore)
        assertNull(AiReport.fromResponse(body).site)
        val unverified = body.replace("\"verdict\": \"dangerous\"", "\"verdict\": \"unverified\"")
        assertEquals(ReportVerdict.UNVERIFIED, AiReport.fromResponse(unverified).verdict)
    }

    @Test
    fun parsesTheServerReport() {
        val report = AiReport.fromResponse(body)
        assertEquals("This is a scam.", report.headline)
        assertEquals("It pretends to be your bank.", report.summary)
        assertEquals(
            listOf(AiFlag("Fake link", "http://sbi.secure-login.xyz", "It goes somewhere else.", Severity.HIGH)),
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
