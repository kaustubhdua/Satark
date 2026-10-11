# SATARK Next.js security and UX follow-up

## Scope
This branch adds an explicitly opt-in URLhaus reputation lookup to the Next.js analysis flow and hardens the in-memory rate-limit key selection. It does not enable external lookups by default, open submitted URLs, or claim that a URL is safe when a provider returns no listing.

## Configuration
- `GROQ_API_KEY`: server-side secret required for AI triage.
- `URLHAUS_AUTH_KEY`: server-side secret for URLhaus API access.
- `SATARK_ENABLE_THREAT_INTEL=true`: explicit server-side feature flag. Leave unset/false until provider configuration and data-sharing copy are reviewed.

Never prefix these variables with `NEXT_PUBLIC_`. Do not commit their values.

## Data sharing
Groq receives submitted text for AI triage. URLhaus receives the first extracted HTTP(S) URL, including its path and query string, only when the user checks the opt-in control and the server feature flag is enabled. Users should not submit private or signed URLs for external lookup. Do not submit credentials, private URLs, authentication tokens, or other secrets. A provider no-match is inconclusive, not safe.

## Limitations and release gates
- This is a reputation lookup, not a malware sandbox or complete threat-intelligence verdict.
- The in-memory rate limiter remains per server instance; configure a shared/platform rate limit before broad public exposure.
- AbuseIPDB is intentionally not called for domains or arbitrary messages. It requires a valid IP address and should be integrated separately with strict IP parsing and explicit disclosure.
- Automated tests and CI must pass before merge. Production provider verification is a separate release gate.
