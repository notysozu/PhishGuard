package com.phishguard.app

/** Wording shown for a flagged notification before any AI explanation is requested. */
object Guidance {
    fun headline(verdict: Verdict) = when (verdict) {
        Verdict.DANGEROUS -> "This looks like a scam. Don't tap or reply."
        else -> "Something is off here. Treat it with caution."
    }

    const val SUMMARY =
        "This notification shows tricks scammers commonly use. " +
            "The highlighted parts below are the warning signs."

    val SAFETY_STEPS = listOf(
        "Don't tap any links or call numbers in the message.",
        "Don't reply, even to say \"stop\".",
        "If it claims to be from a company you use, open their official app yourself to check.",
        "Report it as spam in the app it came from, then delete it.",
    )
}
