# FIRSTLIGHT Wazuh Active Response

## Current integration

FIRSTLIGHT uses Wazuh as its only endpoint-response provider. There is no Microsoft Defender or Entra integration, SDK, tenant configuration, or runtime dependency.

The authenticated case workspace is backed by the durable SQLite response ledger. It supports two fixed Wazuh built-in Active Response commands:

- `wazuh.block_ip` → Wazuh `firewall-drop`, with one validated IPv4 address.
- `wazuh.disable_account` → Wazuh `disable-account`, with one validated local account name.

The API never accepts arbitrary shell commands, script names, command arguments, agent discovery, or all-agent execution. It submits only to a single explicitly allowlisted Wazuh agent ID.

## Required server configuration

Set these only in the trusted FIRSTLIGHT API runtime:

- `SATARK_ENABLE_LIVE_RESPONSE=true` — explicit opt-in; default is false.
- `FIRSTLIGHT_WAZUH_MANAGER_API_URL` — private Wazuh Manager API base URL, normally HTTPS port 55000.
- `FIRSTLIGHT_WAZUH_MANAGER_USERNAME` and `FIRSTLIGHT_WAZUH_MANAGER_PASSWORD` — least-privilege Wazuh API account.
- `FIRSTLIGHT_WAZUH_MANAGER_CA_BUNDLE` — optional path to the private CA certificate; TLS verification remains enabled.
- `FIRSTLIGHT_WAZUH_RESPONSE_AGENT_IDS` — comma-separated numeric IDs of disposable lab agents only.
- `FIRSTLIGHT_WAZUH_MANAGER_ALLOW_HTTP=true` — accepted only for localhost development; never use it for a network endpoint.

The response identity must have only the Wazuh API permissions needed to submit Active Response. Keep the API private and do not publish port 55000 to the public internet.

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
- Wazuh Server API — Active Response: https://documentation.wazuh.com/current/user-manual/api/reference.html
- Wazuh Active Response module: https://github.com/wazuh/wazuh/tree/master/src/active-response
