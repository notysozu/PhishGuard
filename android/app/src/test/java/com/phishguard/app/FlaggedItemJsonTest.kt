package com.phishguard.app

import org.junit.Assert.assertEquals
import org.junit.Test

class FlaggedItemJsonTest {
    private val item = FlaggedItem(
        id = 42,
        packageName = "com.example.sms",
        appName = "Messages",
        text = "Urgent: \"verify\" at http://sbi.secure-login.xyz\nनमस्ते",
        time = 1_700_000_000_000,
        score = 82,
        signals = listOf(
            Signal(Category.URGENCY, Severity.MEDIUM, "Urgent", "Pressures the reader"),
            Signal(Category.SUSPICIOUS_LINK, Severity.HIGH, "http://sbi.secure-login.xyz", "Look-alike"),
        ),
    )

    @Test
    fun roundTripsItemsExactly() {
        val items = listOf(item, item.copy(id = 43, signals = emptyList()))
        assertEquals(items, FlaggedItemJson.decode(FlaggedItemJson.encode(items)))
    }

    @Test
    fun corruptOrEmptyFilesDecodeToNothing() {
        assertEquals(emptyList<FlaggedItem>(), FlaggedItemJson.decode(""))
        assertEquals(emptyList<FlaggedItem>(), FlaggedItemJson.decode("not json"))
        assertEquals(emptyList<FlaggedItem>(), FlaggedItemJson.decode("[]"))
    }

    @Test
    fun oneUnreadableEntryDoesNotLoseTheRest() {
        val good = FlaggedItemJson.encode(listOf(item))
        val withBadEntry = good.dropLast(1) + """,{"id":1,"pkg":"x"}]"""
        assertEquals(listOf(item), FlaggedItemJson.decode(withBadEntry))
    }
}
