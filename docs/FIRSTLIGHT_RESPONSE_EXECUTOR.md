# FIRSTLIGHT guarded response executor

The response executor is integrated into the authenticated FIRSTLIGHT API and persistent case workspace. It is disabled by default. It is not an autonomous containment agent.

## Supported actions

- `defender.isolate_device` — Microsoft Defender for Endpoint device isolation.
- `entra.revoke_sessions` — Microsoft Entra ID session revocation.

No shell execution, arbitrary URL, network firewall rule, target discovery, or action outside this allowlist is accepted.

## Approval lifecycle

1. An owner, responder or analyst creates a request bound to tenant, case, action, exact target, reason, restricted payload, idempotency key and expiry.
2. A different owner/responder approves or denies it (four-eyes control).
3. A third owner/responder executes it. The server rechecks case membership, verifies approval state, requires the exact target confirmation, and checks the server-side feature flag and Microsoft configuration before claiming execution.
4. The ledger commits the one-time execution claim before making the provider request. Replays are rejected.
5. Provider submission is stored as `submitted`, not `verified`. An uncertain outcome becomes `unknown`; the system never retries it automatically.
6. A fourth, distinct operator checks the provider console and records an independent attestation with the provider action/audit reference.

## API and UI

The authenticated routes are mounted under `/api/firstlight/live-response`:

- `GET /status?tenant_id=...&case_id=...`
- `GET /approvals?tenant_id=...&case_id=...`
- `POST /approvals`
- `PATCH /approvals`
- `POST /execute`
- `POST /verify`
- `GET /audit?tenant_id=...&case_id=...`

The Next.js FIRSTLIGHT persistent case panel provides request, approve/deny, execute and independent-verification controls. The browser sends only case-bound action details; Microsoft credentials stay in the trusted API environment.

## Persistence and recovery

The append-only SQLite ledger is stored at `FIRSTLIGHT_RESPONSE_DB`. Local Compose mounts it under the shared `/data` volume at `/data/firstlight-response.sqlite3`. Use a durable, access-controlled volume and include it in backup/restore procedures.

On API startup, any record left in `executing` is changed to `unknown` and a recovery event is appended. This is deliberate: the provider may have acted before the process crashed. Reconcile it with the provider before taking any further action.

The audit chain detects ordinary edits/reordering. It is not an external timestamp, hardware signature, or protection from a privileged administrator who can rewrite the database file. Export and independently anchor audit digests for stronger tamper evidence.

## Configuration

Keep these values only in the private API secret manager:

- `SATARK_ENABLE_LIVE_RESPONSE=true` (otherwise execution is blocked)
- `MICROSOFT_TENANT_ID`
- `MICROSOFT_CLIENT_ID`
- `MICROSOFT_CLIENT_SECRET`

Use least-privilege Microsoft application permissions and admin consent. Defender isolation requires the appropriate Defender machine-isolation permission; Entra session revocation requires the corresponding Graph permission. Confirm the current vendor permission names and tenant policy before enabling.

## Safety boundary

No real provider action was performed by the repository tests. Tests use a mocked handler to verify authorization, four-eyes approval, distinct executor/verifier, exact target confirmation, idempotency, persistence and audit integrity. Enable this feature only in an authorized test tenant with a disposable endpoint/account and a documented unisolation/session-recovery plan.
