package com.phishguard.app

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification

/**
 * Checks every incoming notification on the device as it arrives. All
 * scanning happens on the phone; nothing is sent anywhere from here.
 */
class PhishNotificationListener : NotificationListenerService() {

    // Apps re-post the same notification often (progress, read state); scan each text once.
    private val lastSeen = object : LinkedHashMap<String, Int>() {
        override fun removeEldestEntry(eldest: Map.Entry<String, Int>) = size > 200
    }

    override fun onListenerConnected() {
        Store.init(this)
        Alerts.ensureChannels(this)
    }

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        val notification = sbn.notification
        if (sbn.packageName == packageName && notification.channelId == Alerts.ALERT_CHANNEL) return
        if (sbn.isOngoing || notification.flags and Notification.FLAG_GROUP_SUMMARY != 0) return

        val extras = notification.extras
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString().orEmpty()
        val body = (extras.getCharSequence(Notification.EXTRA_BIG_TEXT)
            ?: extras.getCharSequence(Notification.EXTRA_TEXT))?.toString().orEmpty()
        val text = listOf(title, body).filter { it.isNotBlank() }.joinToString("\n")
        if (text.isBlank()) return

        val hash = text.hashCode()
        if (lastSeen.put(sbn.key, hash) == hash) return

        Store.recordScan(this)
        val assessment = PhishScanner.assess(text)
        if (!assessment.isFlagged) return

        val item = FlaggedItem(
            id = System.currentTimeMillis(),
            packageName = sbn.packageName,
            appName = appLabel(sbn.packageName),
            text = text,
            time = sbn.postTime,
            score = assessment.score,
            signals = assessment.signals,
        )
        Store.add(this, item)
        Alerts.warn(this, item)
    }

    private fun appLabel(pkg: String): String = runCatching {
        packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString()
    }.getOrDefault(pkg)
}
