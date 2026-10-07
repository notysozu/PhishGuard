package com.phishguard.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent

object Alerts {
    /** Our own warnings. The listener ignores this channel so it never scans itself. */
    const val ALERT_CHANNEL = "alerts"
    private const val TEST_CHANNEL = "test"
    const val EXTRA_ITEM_ID = "item_id"

    private val TEST_MESSAGES = listOf(
        "Bank Alert" to "Urgent: your account has been suspended. Verify your identity within 24 hours at http://sbi.kyc-update.secure-login.xyz/verify",
        "USPS" to "Your package could not be delivered. Pay a small redelivery fee of \$1.99: https://bit.ly/3xUsps-redeliver",
        "Lucky Draw" to "Congratulations! You have won a free iPhone. Share the OTP and pay a processing fee at www.amaz0n-rewards.top/claim",
    )
    private var testIndex = 0

    private fun manager(context: Context) =
        context.getSystemService(NotificationManager::class.java)

    fun ensureChannels(context: Context) {
        manager(context).createNotificationChannels(
            listOf(
                NotificationChannel(ALERT_CHANNEL, "Scam warnings", NotificationManager.IMPORTANCE_HIGH)
                    .apply { description = "Warns you when another notification looks like a scam" },
                NotificationChannel(TEST_CHANNEL, "Test messages", NotificationManager.IMPORTANCE_DEFAULT)
                    .apply { description = "Fake scam messages you send yourself to try PhishGuard" },
            )
        )
    }

    fun warn(context: Context, item: FlaggedItem) {
        val open = PendingIntent.getActivity(
            context,
            item.id.toInt(),
            Intent(context, MainActivity::class.java)
                .putExtra(EXTRA_ITEM_ID, item.id)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val title = when (item.verdict) {
            Verdict.DANGEROUS -> "Likely scam in a ${item.appName} notification"
            else -> "Be careful with a ${item.appName} notification"
        }
        val reason = item.signals.maxBy { it.severity }.category.title
        val body = "$reason. Don't tap links in it — tap here to see why."
        val notification = Notification.Builder(context, ALERT_CHANNEL)
            .setSmallIcon(R.drawable.ic_shield)
            .setColor(context.getColor(R.color.brand))
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(Notification.BigTextStyle().bigText(body))
            .setCategory(Notification.CATEGORY_STATUS)
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        manager(context).notify(item.id.toInt(), notification)
    }

    /** Posts a fake scam message so the user can see the live check work. */
    fun sendTest(context: Context) {
        val (title, text) = TEST_MESSAGES[testIndex++ % TEST_MESSAGES.size]
        val notification = Notification.Builder(context, TEST_CHANNEL)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setAutoCancel(true)
            .build()
        manager(context).notify(-testIndex, notification)
    }
}
