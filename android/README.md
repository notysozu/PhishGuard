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

For AI explanations, enter your deployed server's address (for example
`https://your-project.vercel.app`) under "Server address" in the app. The
default `http://10.0.2.2:3000` reaches a local `npm run dev` from the emulator.
Plain `http` is only allowed in debug builds.
