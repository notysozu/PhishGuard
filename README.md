# PhishGuard — the explainable security agent

Paste a suspicious email, text message or link. Instead of a bare safe/unsafe
label, PhishGuard highlights the exact phrases and links that are warning
signs, explains each trick in plain language, and tells you what to do next.

## Run it

```bash
npm install
cp .env.example .env.local   # then add your GEMINI_API_KEY
npm run dev
```

Open http://localhost:3000. Without an API key the app still works, using the
built-in pattern scanner only (the result is labelled as such).

## How it works

A LangGraph workflow in [lib/phishguard/graph.ts](lib/phishguard/graph.ts):

```
START → scan → detect → explain → END
          │       │
          └───────┴──→ pattern_report → END   (no API key, or the AI call failed)
```

| Node | What it does |
| --- | --- |
| `scan` | Deterministic scanner ([signals.ts](lib/phishguard/signals.ts)): look-alike and mismatched domains, shorteners, raw-IP links, spoofed senders, urgency, threats, credential and payment requests. |
| `detect` | Agent 1, a security analyst. Confirms or rejects the scanner's hints, adds what it missed, and returns a structured verdict with verbatim evidence quotes. |
| `explain` | Agent 2, an educator. Rewrites the analyst's findings in calm, jargon-free language with safety and recovery steps. It cannot change the verdict. |
| `pattern_report` | Offline fallback that builds the report from scanner results and template wording. |

The API route ([app/api/analyze/route.ts](app/api/analyze/route.ts)) streams
each step to the browser as NDJSON so the user sees progress.

## API

Other clients (the Android app in [android/](android/)) use a plain JSON endpoint:

```
POST /api/v1/analyze
Content-Type: application/json

{ "text": "<message to check>" }
```

It returns `200 { "report": { verdict, riskScore, headline, summary, redFlags,
reassuringSigns, safetySteps, ifAlreadyClicked, mode, notice? } }`, or
`{ "error": "..." }` with a 4xx/5xx status.

## Deploy to Vercel

```bash
npx vercel            # first run links the project and creates a preview
npx vercel env add GEMINI_API_KEY production
npx vercel --prod
```

Then put the production URL into the Android app's "Server address" field.

## Security notes

- Links in the pasted message are parsed as text only and never fetched.
- The pasted message is treated as untrusted: it is wrapped in tags, and both
  agents are instructed to ignore instructions inside it and to report such
  attempts as a red flag.
- Agent output is schema-constrained (zod structured outputs), and React
  escapes everything rendered.
- Input is capped at 20,000 characters and the route has a basic per-IP rate
  limit (in-memory; use a shared store if you deploy more than one instance).
- Nothing is stored server-side.
# PhishGuard
