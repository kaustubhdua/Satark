# FIRSTLIGHT trusted response executor foundation

This module is a local, open-source foundation for a trusted response executor. It adds a durable approval lifecycle and audit log, but it is **not yet connected to the browser approval UI or the SATARK's self-hosted simulation-only approval records**. Do not describe the complete response workflow as production-ready until that integration and live acceptance are finished.

## Controls implemented

- Allowlist limited to Defender device isolation and Entra session revocation.
- Every request is bound to tenant, case, requester, exact target, reason, parameters, idempotency key, and expiry.
- Four-eyes approval: the requester cannot approve or deny their own request.
- One-time execution claim is committed before the provider handler runs; the same approval cannot be executed twice.
- Provider submission is a separate state from provider-side verification; the executor identity is persisted, and verification is rejected if performed by the requester, approver, or executor.
- Any exception after execution starts becomes `unknown`; the system does not blindly retry a potentially successful provider operation.
- Restart recovery marks abandoned `executing` records as `unknown`, then requires independent provider reconciliation.
- SQLite transaction durability, immutable action/target/payload bindings, restrictive action payloads, append-only audit triggers, and a SHA-256 hash chain.
- No network endpoint is exposed by this module; a trusted caller must authenticate the operator and authorize the tenant/case before invoking it.

## Local tests

Run:

```bash
python -m unittest -v tests.test_firstlight_response_executor
```

The tests use mocked provider handlers and a temporary in-memory database. They test the guardrails, not real Microsoft actions.

## Integration required before enabling live response

1. Wire the ledger to the authenticated server-side response route and replace the current simulation-only UI path. Never trust tenant, actor, case, approval or role claims supplied only by the browser.
2. Use a persistent, access-controlled database volume, or implement the same lifecycle on the existing tenant-scoped database with equivalent transactional guarantees.
3. Connect the two allowlisted actions to the existing Microsoft adapters, passing only the approved target and parameters. Keep credentials server-side.
4. Implement provider-specific status polling and independently verify the resulting state. A successful POST means submitted, not verified.
5. On startup, call `recover_interrupted_executions()`; reconcile all `unknown` results manually or with a read-only provider verifier before taking another action.
6. Export and independently anchor audit hashes. SQLite triggers/hash chains are tamper-evident against ordinary application mistakes, not privileged host administrators.
7. Run dedicated tenant-isolation tests and authorized Defender/Entra lab acceptance before enabling the live-response feature flag.

The current Supabase approval consumption restrictions must remain in place until the authenticated server-side integration is complete and reviewed. This ledger does not grant authority to execute any action by itself.
