package com.phishguard.app

// On-device pattern scanner, a Kotlin port of lib/phishguard/signals.ts in the
// web app. It never opens or resolves a link: everything is parsed as text.

enum class Severity(val weight: Int) { LOW(8), MEDIUM(18), HIGH(32) }

enum class Verdict { DANGEROUS, SUSPICIOUS, LIKELY_SAFE }

enum class Category(val title: String, val why: String) {
    URGENCY(
        "Pressure to act fast",
        "Scammers rush you so you don't stop to think or ask someone. Real organisations give you time."
    ),
    THREAT(
        "Scare tactics",
        "Fear makes people act without checking. A real company won't threaten you out of the blue in a message."
    ),
    SUSPICIOUS_LINK(
        "Link isn't what it seems",
        "The part of a web address just before the first single slash is where it really goes. Scammers dress that up to look familiar."
    ),
    CREDENTIAL_REQUEST(
        "Asks for private details",
        "Genuine companies never ask for passwords or one-time codes by message."
    ),
    PAYMENT_REQUEST(
        "Asks for unusual payment",
        "Gift cards, crypto and wire transfers can't be reversed, which is exactly why scammers ask for them."
    ),
    TOO_GOOD_TO_BE_TRUE(
        "Too good to be true",
        "You can't win a prize draw you never entered. The \"reward\" is bait to get your details or a fee."
    ),
    ATTACHMENT(
        "Risky attachment",
        "Unexpected files can install harmful software when opened."
    ),
    GENERIC_GREETING(
        "Doesn't know your name",
        "Companies you have an account with normally address you by name. Mass scams can't."
    ),
}

data class Signal(
    val category: Category,
    val severity: Severity,
    /** Exact substring of the scanned text, so the UI can highlight it. */
    val evidence: String,
    val reason: String,
)

object PhishScanner {
    const val SUSPICIOUS_AT = 30
    const val DANGEROUS_AT = 65

    private val SHORTENERS = setOf(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
        "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "t.ly",
    )

    private val RISKY_TLDS = setOf(
        "xyz", "top", "click", "link", "zip", "mov", "tk", "ml", "ga", "cf", "gq",
        "icu", "cam", "rest", "buzz", "monster", "live", "shop", "support", "info",
    )

    private val TWO_PART_TLDS = setOf(
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.in", "net.in", "org.in",
        "gov.in", "co.nz", "co.za", "com.br", "co.jp", "com.sg", "com.mx",
    )

    private val BRANDS = listOf(
        "paypal", "amazon", "apple", "icloud", "microsoft", "outlook", "office365",
        "google", "gmail", "netflix", "facebook", "instagram", "whatsapp", "linkedin",
        "dropbox", "docusign", "chase", "wellsfargo", "bankofamerica", "citibank",
        "hsbc", "barclays", "fedex", "dhl", "ups", "usps", "irs", "coinbase",
        "binance", "sbi", "hdfc", "icici", "paytm", "phonepe", "flipkart",
    )

    private class Phrase(
        pattern: String,
        val category: Category,
        val severity: Severity,
        val reason: String,
    ) {
        val regex = Regex(pattern, setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE))
    }

    private val PHRASES = listOf(
        Phrase(
            """\b(urgent(ly)?|immediate(ly)?|act now|right away|as soon as possible|within \d+ ?(hours?|hrs?|minutes?|mins?|days?)|final (notice|warning|reminder)|expires? (today|soon|in \d+)|last chance|today only)\b""",
            Category.URGENCY, Severity.MEDIUM, "Pressures the reader to act quickly",
        ),
        Phrase(
            """\b(account (has been |will be |is )?(suspended|locked|closed|disabled|restricted|terminated|deactivated|blocked)|will be (suspended|closed|terminated|blocked|deactivated)|legal action|arrest warrant|unauthorized (access|login|transaction|activity)|unusual (activity|sign-?in)|suspicious (activity|login))\b""",
            Category.THREAT, Severity.HIGH, "Threatens a loss or penalty to cause fear",
        ),
        Phrase(
            """\b(verify your (account|identity|information|details)|confirm your (account|identity|password|details|information)|update your (payment|billing|account|card) (details|information|info|method)?|enter your (password|pin|otp|card)|share (the |your )?(otp|pin|password|cvv)|(social security|ssn|aadhaar|pan) (number|card)?|login credentials|one[- ]time (password|code)|kyc (update|verification|expired|pending))\b""",
            Category.CREDENTIAL_REQUEST, Severity.HIGH, "Asks for a password, code or personal details",
        ),
        Phrase(
            """\b(gift cards?|wire transfer|western union|moneygram|bitcoin|crypto(currency)?|processing fee|customs fee|redelivery fee|pay (a |the )?(small )?fee|send (the )?money)\b""",
            Category.PAYMENT_REQUEST, Severity.HIGH, "Asks for money through a hard-to-reverse payment method",
        ),
        Phrase(
            """\b(you('ve| have) won|congratulations|lottery|prize|free (gift|iphone|reward)|claim your (reward|prize|refund|gift)|selected as a winner|inheritance|100% (free|guaranteed))\b""",
            Category.TOO_GOOD_TO_BE_TRUE, Severity.MEDIUM, "Promises an unexpected reward",
        ),
        Phrase(
            """^\s*(dear|hello|hi) (valued )?(customer|user|client|member|account holder|sir/?madam|sir or madam)\b""",
            Category.GENERIC_GREETING, Severity.LOW, "Generic greeting instead of the recipient's name",
        ),
        Phrase(
            """\b[\w-]+\.(exe|scr|zip|rar|iso|js|vbs|bat|docm|xlsm|html?|apk)\b""",
            Category.ATTACHMENT, Severity.MEDIUM, "Mentions a file type commonly used to deliver malware",
        ),
    )

    private val URL = Regex(
        """\b(?:https?://|www\.)[^\s<>"')\]]+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|info|xyz|top|click|link|co|io|me|ly|in|uk|us|ru|cn|tk|icu|shop|live|app|site|online)\b(?:/[^\s<>"')\]]*)?""",
        RegexOption.IGNORE_CASE,
    )
    private val IP = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")
    private val USERINFO = Regex("""^https?://[^/]*@""", RegexOption.IGNORE_CASE)

    private fun parseHost(raw: String): String? {
        val authority = raw.replace(Regex("^https?://", RegexOption.IGNORE_CASE), "")
            .takeWhile { it != '/' && it != '?' && it != '#' }
        val host = authority.substringAfterLast('@').substringBefore(':')
            .lowercase().removePrefix("www.")
        return host.takeIf { it.contains('.') }
    }

    fun registrableDomain(host: String): String {
        val labels = host.split('.')
        if (labels.size <= 2) return host
        val lastTwo = labels.takeLast(2).joinToString(".")
        return if (lastTwo in TWO_PART_TLDS) labels.takeLast(3).joinToString(".") else lastTwo
    }

    private fun deLeet(s: String) = s
        .replace('0', 'o').replace('1', 'l').replace('!', 'l').replace('|', 'l')
        .replace('3', 'e').replace('5', 's').replace('4', 'a').replace('@', 'a')
        .replace("rn", "m").replace("vv", "w")

    private fun impersonatedBrand(host: String): String? {
        val sld = registrableDomain(host).substringBefore('.')
        val labels = host.split('.', '-')
        for (brand in BRANDS) {
            if (sld == brand) return null // the brand's own domain
            fun matches(s: String) = if (brand.length <= 4) s == brand else brand in s
            if (labels.any { matches(it) || matches(deLeet(it)) }) return brand
        }
        return null
    }

    /** One signal per link: the worst severity found, with every reason listed. */
    private fun checkUrl(raw: String): Signal? {
        val host = parseHost(raw) ?: return null
        val found = mutableListOf<Pair<Severity, String>>()
        val domain = registrableDomain(host)

        val brand = impersonatedBrand(host)
        if (brand != null)
            found += Severity.HIGH to "Link uses the name \"$brand\" but actually goes to $domain"
        if (IP.matches(host))
            found += Severity.HIGH to "Link points to a raw IP address instead of a named website"
        if ("xn--" in host)
            found += Severity.HIGH to "Link uses look-alike international characters (punycode)"
        if (USERINFO.containsMatchIn(raw))
            found += Severity.HIGH to "Link contains \"@\", which hides the real destination"
        if (domain in SHORTENERS)
            found += Severity.MEDIUM to "Shortened link hides where it really goes"
        val tld = host.substringAfterLast('.')
        if (tld in RISKY_TLDS && brand == null)
            found += Severity.LOW to "Link ends in \".$tld\", an ending often used for throwaway sites"
        if (host.split('.').size >= 5)
            found += Severity.MEDIUM to "Link has an unusually long chain of subdomains"
        if (raw.startsWith("http://", ignoreCase = true))
            found += Severity.LOW to "Link is not encrypted (http instead of https)"

        if (found.isEmpty()) return null
        found.sortByDescending { it.first }
        return Signal(
            Category.SUSPICIOUS_LINK,
            found.first().first,
            raw,
            found.joinToString("; ") { it.second },
        )
    }

    fun scan(text: String): List<Signal> {
        val signals = mutableListOf<Signal>()

        val seenUrls = mutableSetOf<String>()
        for (m in URL.findAll(text)) {
            val url = m.value.trimEnd('.', ',', ';', ':', '!', '?')
            // Skip the domain half of an email address.
            if (m.range.first > 0 && text[m.range.first - 1] == '@') continue
            if (seenUrls.add(url)) checkUrl(url)?.let { signals += it }
        }

        for (p in PHRASES) {
            val seen = mutableSetOf<String>()
            for (m in p.regex.findAll(text)) {
                val evidence = m.value.trim()
                if (seen.add(evidence.lowercase()))
                    signals += Signal(p.category, p.severity, evidence, p.reason)
            }
        }
        return signals
    }

    /** Repeats of the same category add less, so ten "urgent"s don't max the score. */
    fun score(signals: List<Signal>): Int {
        val perCategory = mutableMapOf<Category, Int>()
        var score = 0.0
        for (s in signals) {
            val n = perCategory.getOrDefault(s.category, 0)
            perCategory[s.category] = n + 1
            score += s.severity.weight.toDouble() / (n + 1)
        }
        return minOf(100, Math.round(score).toInt())
    }

    fun verdict(score: Int) = when {
        score >= DANGEROUS_AT -> Verdict.DANGEROUS
        score >= SUSPICIOUS_AT -> Verdict.SUSPICIOUS
        else -> Verdict.LIKELY_SAFE
    }
}
