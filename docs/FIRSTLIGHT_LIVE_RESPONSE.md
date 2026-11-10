# FIRSTLIGHT live response integrations

## Current integration

The FIRSTLIGHT persistent case workspace includes a guarded live-response panel backed by the authenticated FastAPI response API and a durable SQLite ledger.

Supported Microsoft actions:

- Microsoft Defender for Endpoint device isolation.
- Microsoft Entra ID session revocation.

No network firewall rule, arbitrary shell command, automatic AI action, or other containment action is supported.

## Default state

Live response is **disabled by default**. The status endpoint reports whether the server feature flag and Microsoft credentials are configured. Merely creating or approving a request never contacts Microsoft.

Set these values only in the trusted API runtime:

- `SATARK_ENABLE_LIVE_RESPONSE=true`
- `MICROSOFT_TENANT_ID`
- `MICROSOFT_CLIENT_ID`
- `MICROSOFT_CLIENT_SECRET`

The app registration must have least-privilege application permissions and admin consent for the selected action. Defender isolation and Entra session revocation have separate permissions and operational consequences. Validate them against current Microsoft documentation and the tenant's policy.

## Human controls

- The request is bound to one tenant, case, action, exact target, reason, parameters, idempotency key and expiry.
- Requester cannot approve or deny their own request.
- A third operator distinct from requester and approver executes the action.
- The server checks membership again, verifies the feature flag and credentials, and requires an exact target confirmation such as `CONFIRM ISOLATE <machine-id>`.
- The action is claimed once in the durable ledger before the provider call. Replays are rejected.
- A provider submission is recorded as `submitted`, never as completed containment.
- An uncertain network/process outcome becomes `unknown` and is not retried automatically.
- A fourth distinct operator records a verification attestation only after checking the Microsoft console. SATARK records the attestation; it does not independently infer provider state.

## Operational recovery

Use a dedicated lab tenant and disposable test device/account. Preserve a separate administrator path. For Defender, document and test the vendor-supported unisolation process before testing isolation. For Entra, document the expected sign-in/session recovery process. Do not test on personal or production accounts.

## Verification status

Automated tests mock the Microsoft adapter and verify the durable workflow. No real Microsoft tenant, credentials, machine, or user was available for live acceptance in this change. Do not claim provider connectivity, successful containment, or production readiness until a separately authorized lab run has been recorded.

Official references:
- https://learn.microsoft.com/en-us/defender-endpoint/api/isolate-machine
- https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions
