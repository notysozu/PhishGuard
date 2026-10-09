package com.phishguard.app.ui

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.text.format.DateUtils
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LifecycleResumeEffect
import com.phishguard.app.Alerts
import com.phishguard.app.FlaggedItem
import com.phishguard.app.MAX_CHECK_CHARS
import com.phishguard.app.R
import com.phishguard.app.Store

private fun Context.hasNotificationAccess() =
    packageName in NotificationManagerCompat.getEnabledListenerPackages(this)

private fun Context.canPostNotifications() =
    Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
        ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) ==
        PackageManager.PERMISSION_GRANTED

/** Status, a box to check a link or message by hand, and the flagged notifications. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun HomeScreen(
    flagged: List<FlaggedItem>,
    onOpen: (FlaggedItem) -> Unit,
    onCheck: (String) -> Unit,
) {
    val context = LocalContext.current
    val scanned by Store.scannedCount.collectAsState()

    // Both permissions are changed outside the app, so re-check on every resume.
    var hasAccess by remember { mutableStateOf(context.hasNotificationAccess()) }
    var canNotify by remember { mutableStateOf(context.canPostNotifications()) }
    LifecycleResumeEffect(Unit) {
        hasAccess = context.hasNotificationAccess()
        canNotify = context.canPostNotifications()
        onPauseOrDispose { }
    }
    val askToNotify = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted -> canNotify = granted }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            painterResource(R.drawable.ic_shield),
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                        )
                        Spacer(Modifier.width(8.dp))
                        Text("PhishGuard")
                    }
                },
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                StatusCard(
                    isOn = hasAccess,
                    scanned = scanned,
                    flagged = flagged.size,
                    onEnable = {
                        context.startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
                    },
                )
            }
            item { CheckCard(onCheck) }
            if (!canNotify) item {
                SetupCard(
                    title = "Allow warnings",
                    body = "PhishGuard needs permission to show you a warning when it spots a scam.",
                    action = "Allow",
                    onClick = {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            askToNotify.launch(Manifest.permission.POST_NOTIFICATIONS)
                        }
                    },
                )
            }
            item {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    SectionHeading("Flagged notifications", Modifier.weight(1f))
                    if (hasAccess && canNotify) {
                        TextButton(onClick = { Alerts.sendTest(context) }) { Text("Send a test") }
                    }
                    if (flagged.isNotEmpty()) {
                        TextButton(onClick = { Store.clear(context) }) { Text("Clear") }
                    }
                }
            }
            if (flagged.isEmpty()) item {
                Text(
                    if (hasAccess) {
                        "Nothing suspicious so far. You'll get a warning here the moment " +
                            "something looks off."
                    } else {
                        "Turn on live checking above to get started."
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            items(flagged, key = { it.id }) { item ->
                FlaggedRow(item, onClick = { onOpen(item) })
            }
        }
    }
}

@Composable
private fun StatusCard(isOn: Boolean, scanned: Int, flagged: Int, onEnable: () -> Unit) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = if (isOn) Teal else MaterialTheme.colorScheme.surfaceVariant,
            contentColor = if (isOn) Color.White else MaterialTheme.colorScheme.onSurfaceVariant,
        ),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(20.dp)) {
            Text(
                if (isOn) "Live checking is on" else "Live checking is off",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.semantics { heading() },
            )
            Spacer(Modifier.height(6.dp))
            if (isOn) {
                Text("$scanned notifications checked · $flagged flagged")
                Spacer(Modifier.height(6.dp))
                Text(
                    "Checks happen on this phone. Notifications that look fine are never stored.",
                    style = MaterialTheme.typography.bodySmall,
                )
            } else {
                Text(
                    "To check messages as they arrive, PhishGuard needs notification access. " +
                        "On the next screen, switch on PhishGuard.",
                )
                Spacer(Modifier.height(12.dp))
                Button(onClick = onEnable) { Text("Turn on") }
            }
        }
    }
}

/** Lets the user paste a website address or a message and have it checked now. */
@Composable
private fun CheckCard(onCheck: (String) -> Unit) {
    var text by rememberSaveable { mutableStateOf("") }
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            SectionHeading("Check a website or message")
            Spacer(Modifier.height(4.dp))
            Text(
                "Paste a lottery or shopping link, or a message you are unsure about.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = text,
                onValueChange = { text = it.take(MAX_CHECK_CHARS) },
                label = { Text("Link or message") },
                placeholder = { Text("https://example-lottery.com") },
                maxLines = 4,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = { onCheck(text.trim()) },
                enabled = text.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Check") }
            Text(
                "Sent to the PhishGuard server to verify. Your phone never opens the link.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 6.dp),
            )
        }
    }
}

@Composable
private fun SetupCard(title: String, body: String, action: String, onClick: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            SectionHeading(title)
            Spacer(Modifier.height(4.dp))
            Text(body, style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(8.dp))
            Button(onClick = onClick) { Text(action) }
        }
    }
}

@Composable
private fun FlaggedRow(item: FlaggedItem, onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(
                onClickLabel = "See why this was flagged",
                role = Role.Button,
                onClick = onClick,
            ),
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(10.dp).background(item.verdict.color, CircleShape))
                Spacer(Modifier.width(8.dp))
                Text(
                    item.verdict.label,
                    color = item.verdict.color,
                    style = MaterialTheme.typography.labelLarge,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    "${item.appName} · " + DateUtils.getRelativeTimeSpanString(item.time),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.height(6.dp))
            Text(
                item.text,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}
