"""Preview a Wazuh response request; live execution is case-approval-only.

This CLI deliberately cannot call the Wazuh Manager API. Submit and execute
responses through the authenticated FIRSTLIGHT case workspace so tenant
membership, four-eyes approval, a third executor and the durable audit ledger
cannot be bypassed.
"""
from __future__ import annotations

import argparse
import json
import re
import sys

from integrations.response_actions import ResponseIntegrationError, _validate_payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", required=True, choices=("block-ip", "disable-account"))
    parser.add_argument("--agent-id", required=True, help="Exact numeric Wazuh agent ID")
    parser.add_argument("--ip-address", help="IPv4 address for block-ip")
    parser.add_argument("--username", help="Local account name for disable-account (Linux/macOS allowlist only)")
    parser.add_argument("--reason", required=True, help="Case reference and justification; 1–1000 characters")
    args = parser.parse_args(argv)

    action = "wazuh.block_ip" if args.action == "block-ip" else "wazuh.disable_account"
    payload = {"ip_address": args.ip_address} if action == "wazuh.block_ip" else {"username": args.username}
    if not re.fullmatch(r"\d{3,}", args.agent_id):
        print("Preview refused: Wazuh agent ID must be numeric.", file=sys.stderr)
        return 2
    if not args.reason.strip() or len(args.reason.strip()) > 1000:
        print("Preview refused: a reason of 1–1000 characters is required.", file=sys.stderr)
        return 2
    try:
        validated = _validate_payload(action, payload)
    except ResponseIntegrationError as exc:
        print(f"Preview refused: {exc}", file=sys.stderr)
        return 2

    field = "ip_address" if action == "wazuh.block_ip" else "username"
    confirmation = ("CONFIRM BLOCK_IP " if action == "wazuh.block_ip" else "CONFIRM DISABLE_ACCOUNT ") + args.agent_id
    print(json.dumps({
        "provider": "Wazuh Active Response",
        "action": action,
        "agent_id": args.agent_id,
        field: validated[0],
        "reason": args.reason.strip(),
        "confirmation_phrase_for_case_workspace": confirmation,
        "live_execution": False,
        "execution_route": "Authenticated FIRSTLIGHT case request → distinct approver → third executor → independent verification",
        "note": "This command only previews the request. It never contacts Wazuh or executes a response.",
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
