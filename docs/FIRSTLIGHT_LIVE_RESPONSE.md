# FIRSTLIGHT Wazuh Active Response

## Current integration

FIRSTLIGHT uses Wazuh 4.14.x as its only endpoint-response provider. The lab bootstrap pins 4.14.10. There is no Microsoft Defender or Entra integration, SDK, tenant configuration, or runtime dependency.

The authenticated case workspace is backed by the durable SQLite response ledger. It exposes only one guarded action: `wazuh.block_ip` → SATARK's custom Wazuh 4.14.x `!satark-firewall-drop` agent script with a persistent local TTL watchdog, restricted to one active, explicitly allowlisted Linux agent and one globally routable IPv4 address outside protected networks. It is hidden unless an operator has completed and attested to a disposable-lab timeout/reversal test. `wazuh.disable_account` is deliberately unavailable: the 4.x manual Active Response API request does not carry a per-request timeout, and a local account lock must not be exposed until a reversible, independently verified TTL workflow exists.

The API never accepts arbitrary shell commands, agent discovery, or all-agent execution. Before submission, the adapter reads `/manager/info` and the exact agent record, and refuses to send commands unless the Manager reports version 4.14.x and the agent is active Linux. Wazuh 5.x is not supported by this adapter because its Active Response architecture removed the 4.x `PUT /active-response` endpoint. The API also rejects non-global IPv4 addresses and any address inside the required protected-network denylist.

## Required server configuration

Set these only in the trusted FIRSTLIGHT API runtime:

- `SATARK_ENABLE_LIVE_RESPONSE=true` — explicit opt-in; default is false.
- `FIRSTLIGHT_WAZUH_MANAGER_API_URL` — private Wazuh Manager API base URL, normally HTTPS port 55000.
- `FIRSTLIGHT_WAZUH_MANAGER_USERNAME` and `FIRSTLIGHT_WAZUH_MANAGER_PASSWORD` — least-privilege Wazuh API account.
- `FIRSTLIGHT_WAZUH_MANAGER_CA_BUNDLE` — optional path to the private CA certificate; TLS verification remains enabled.
- `FIRSTLIGHT_WAZUH_RESPONSE_AGENT_IDS` — comma-separated numeric IDs of disposable Linux lab agents only.
- `FIRSTLIGHT_WAZUH_PROTECTED_IPS` — required comma-separated IP/CIDR denylist containing the Manager, API, VPN, DNS and other critical infrastructure networks.
- `FIRSTLIGHT_WAZUH_RESPONSE_TTL_SECONDS` — the agent-side watchdog timeout that was independently verified in the lab; must be 60–900 seconds.
- `FIRSTLIGHT_WAZUH_RESPONSE_TTL_VERIFIED=true` — operator attestation that the configured Manager timeout and endpoint-side reversal were tested successfully with a disposable agent. This flag is not an automatic proof and must not be set before that test.
- `FIRSTLIGHT_WAZUH_MANAGER_ALLOW_HTTP=true` — accepted only for localhost development; never use it for a network endpoint.

The response identity must have only the Wazuh API permissions needed to submit Active Response. Account disable is not exposed. Keep the API private and do not publish port 55000 to the public internet.

## Human controls

- The request is bound to one tenant, case, action, exact agent ID, validated parameters, reason, idempotency key and expiry.
- Requester cannot approve or deny their own request.
- A third operator distinct from requester and approver executes the action.
- The server re-checks case membership, feature flag, agent allowlist, fixed action and exact confirmation.
- Confirmation strings are `CONFIRM BLOCK_IP <agent-id>` or `CONFIRM DISABLE_ACCOUNT <agent-id>`.
- The action is claimed once in the durable ledger before the provider call. Replays are rejected.
- A Wazuh API acceptance is recorded as `submitted`, never as verified containment.
- An uncertain network/process outcome becomes `unknown` and is not retried automatically.
- A separate operator records a verification attestation only after checking the agent and endpoint state independently.

## Operational safety

Use disposable lab endpoints. Configure and test Wazuh's own Active Response command definitions and timeout/reversal behavior before enabling this feature. In particular, `firewall-drop` and `disable-account` have operational consequences and may interrupt network or user access. Keep out-of-band administrative access and a documented recovery route. Never add production agents to the response allowlist until an independent security review approves the policy.

## Verification status

Automated tests use a mocked Wazuh Manager API and validate request shape, fixed command allowlisting, agent scoping, TLS policy, explicit confirmation and the durable four-eyes ledger. These tests do not prove that a real lab manager accepted or executed a command. Record real lab API responses, endpoint-side state, recovery behavior and audit evidence before enabling live response outside a disposable environment.

Official references:
- Wazuh Server API — Active Response: https://documentation.wazuh.com/4.14/user-manual/api/reference.html
- Wazuh Active Response module: https://github.com/wazuh/wazuh/tree/master/src/active-response
