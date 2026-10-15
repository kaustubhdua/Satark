# Outbound provider redirect policy

SATARK's server-side calls to Supabase Auth, PostgREST, Storage, and the configured local Ollama endpoint must reject HTTP redirects unless a reviewed provider-specific contract explicitly requires and validates them.

## Why

A redirect changes the destination of a request. Automatically following it can send authorization headers or other request data to a different origin, hide a provider misconfiguration, or make a compromised provider response redirect server-side traffic somewhere unintended.

## Implementation rule

- Use `redirect: 'error'` for outbound provider `fetch` calls.
- Keep the destination host and scheme constrained by the existing configuration checks.
- Keep request timeouts and bounded response handling.
- Treat a redirect as provider unavailability; do not retry the new location automatically.
- Never fetch a decoded QR destination or user-submitted URL as a side effect of analysis.
- If a provider contract later requires redirects, implement explicit manual redirect handling with a strict origin allowlist and revalidation rather than enabling automatic following.

## Regression test

`tests/test_outbound_fetch_redirect_policy.py` checks that every provider fetch in the reviewed route set explicitly rejects redirects. Run the complete test suite and web typecheck/build before merge; the static test is not a substitute for integration testing against the configured provider.
