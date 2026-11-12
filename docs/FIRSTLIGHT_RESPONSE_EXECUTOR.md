# FIRSTLIGHT guarded Wazuh response executor

## Supported actions

The current implementation uses Wazuh Manager API Active Response only:

- `wazuh.block_ip` — invokes the fixed Wazuh 4.x built-in `firewall-drop` command with one validated IPv4 address.
- `wazuh.disable_account` — invokes the fixed Wazuh 4.x built-in `disable-account` command with one validated local account name.

There is no Microsoft Defender, Entra, Graph API, OAuth app registration or Microsoft tenant dependency. Arbitrary shell commands, custom script names, all-agent broadcasts and free-form command arguments are not supported.

## Approval lifecycle

1. A tenant member requests an action bound to one case, numeric Wazuh agent ID, validated action payload, reason, idempotency key and expiry.
2. A different owner/responder approves or denies the request.
3. A third operator executes the approved action after re-checking membership, action/agent allowlists and exact confirmation.
4. A separate operator verifies the endpoint-side state and records the Wazuh task/log reference and result.
5. The durable SQLite ledger records each transition in a hash-chained append-only audit sequence.

The live-response feature flag is disabled by default. The API never chooses targets from AI output and never infers that an accepted API request means the endpoint is contained.

## Required configuration

- `SATARK_ENABLE_LIVE_RESPONSE=true` — only after a lab review.
- `FIRSTLIGHT_WAZUH_MANAGER_API_URL` — private HTTPS Manager API URL.
- `FIRSTLIGHT_WAZUH_MANAGER_USERNAME` / `FIRSTLIGHT_WAZUH_MANAGER_PASSWORD` — least-privilege API identity with Active Response execution permission and read access to the explicitly allowlisted agent inventory; FIRSTLIGHT verifies exact agent identity, active status and supported OS before submission.
- `FIRSTLIGHT_WAZUH_MANAGER_CA_BUNDLE` — optional trusted private CA file.
- `FIRSTLIGHT_WAZUH_RESPONSE_AGENT_IDS` — explicit numeric disposable-agent allowlist.

The Manager API should be reachable only from the private FIRSTLIGHT API network. Do not expose port 55000 publicly. TLS verification is mandatory for network endpoints. HTTP is accepted only for explicit localhost tests.

## Failure and recovery behavior

- Approval bindings (tenant, case, action, target, reason and payload) are immutable.
- Idempotency keys prevent duplicate requests.
- Requester, approver, executor and verifier identities are separated.
- An interrupted or ambiguous provider call becomes `unknown`; the executor never retries it automatically.
- A provider submission is not endpoint verification.
- The audit hash chain detects ordinary record mutation but is not tamper-proof against a privileged host administrator. Export/anchor audit records independently for stronger evidence integrity.

## Lab acceptance

Before enabling response in a real environment, test with a disposable enrolled agent:

- Wazuh Manager API TLS, authentication and least-privilege role.
- Agent ID allowlist enforcement and target scoping.
- `firewall-drop` action and reversal on the target operating system.
- `disable-account` behavior and account recovery on supported Linux/macOS agents; this action does not terminate existing sessions.
- Manager/agent logs, audit references, API timeout and ambiguous-outcome recovery.
- A complete case request → approval → third-party execution → independent verification workflow.

Automated tests mock the Wazuh API. They are not proof of live endpoint execution.

References:
- https://documentation.wazuh.com/current/user-manual/api/reference.html
- https://documentation.wazuh.com/current/user-manual/capabilities/active-response/default-active-response-scripts.html
- https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html
