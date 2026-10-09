# PhishGuard for Android

Checks every notification on the phone as it arrives and warns you when one
looks like a scam.

## How it works

- [PhishNotificationListener](app/src/main/java/com/phishguard/app/PhishNotificationListener.kt)
  is a `NotificationListenerService`. Android hands it each new notification.
- [PhishScanner](app/src/main/java/com/phishguard/app/PhishScanner.kt) scores the
  text on the phone (a Kotlin port of the web app's `signals.ts`).
- A score of 30 or more posts a PhishGuard warning. Tapping it opens the
  message with the warning signs highlighted and explained.
- "Explain with AI" on a flagged message sends that one message to the
  PhishGuard server's `POST /api/v1/analyze` and shows the two-agent report.

| File | Role |
| --- | --- |
| `PhishScanner.kt` | Pattern scanner and risk score (pure Kotlin) |
| `PhishNotificationListener.kt` | Receives notifications and runs the scanner |
| `Alerts.kt` | Notification channels and the warning itself |
| `Store.kt`, `FlaggedItem.kt` | Flagged items, kept in app-private storage |
| `AiClient.kt`, `AiReport.kt` | Server call and response parsing |
| `ui/` | Compose screens, shared components and theme |

Notifications that look fine are counted and discarded. Only flagged ones are
stored (the last 50, in app-private storage).

## Build and run

Needs JDK 17–24 (Gradle 8.14 does not run on JDK 25+).

```bash
export JAVA_HOME=~/Library/Java/JavaVirtualMachines/jbr-21.0.11/Contents/Home
./gradlew installDebug
```

Open the app, tap **Turn on**, and enable PhishGuard under notification access.
Then tap **Send a fake scam message to test**.

AI explanations come from the deployed server at
`https://phishguard.sonu-kumar.in`. To use another server (for example a local
`npm run dev` at `http://10.0.2.2:3000` from the emulator), change
`SERVER_URL` in [AiClient.kt](app/src/main/java/com/phishguard/app/AiClient.kt).
Plain `http` is only allowed in debug builds.

Screenshots are in the [main README](../README.md#android).
