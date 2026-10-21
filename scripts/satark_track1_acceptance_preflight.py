#!/usr/bin/env python3
"""Fail-closed configuration preflight for SATARK Track 1 acceptance.

This validates only that operator-supplied configuration is structurally safe.
It does NOT contact Supabase/Wazuh/Microsoft, prove authorization, or pass live
acceptance. Never print credential values.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from urllib.parse import urlsplit

EXPECTED_TEST_PROJECT_REF = "ibvgxgvcqcfnoyrlwywa"
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")

GROUPS = {
    "tenant": (
        "SATARK_TEST_SUPABASE_URL",
        "SATARK_TEST_SUPABASE_PUBLISHABLE_KEY",
        "SATARK_TEST_USER_A_EMAIL",
        "SATARK_TEST_USER_A_PASSWORD",
        "SATARK_TEST_TENANT_A_ID",
        "SATARK_TEST_USER_B_EMAIL",
        "SATARK_TEST_USER_B_PASSWORD",
        "SATARK_TEST_TENANT_B_ID",
        "SATARK_TEST_VIEWER_EMAIL",
        "SATARK_TEST_VIEWER_PASSWORD",
        "SATARK_TEST_VIEWER_TENANT_ID",
    ),
    "wazuh": (
        "FIRSTLIGHT_API_BASE_URL",
        "FIRSTLIGHT_WAZUH_SYNC_TOKEN",
        "FIRSTLIGHT_WAZUH_TENANT_ID",
        "FIRSTLIGHT_WAZUH_CASE_ID",
        "FIRSTLIGHT_WAZUH_ACCEPTANCE_CONFIRM_TENANT_ID",
        "FIRSTLIGHT_WAZUH_ACCEPTANCE_CONFIRM_CASE_ID",
        "FIRSTLIGHT_WAZUH_ACCEPTANCE_ALLOW_WRITES",
    ),
    "response": (
        "FIRSTLIGHT_RESPONSE_ACCEPTANCE_ENABLED",
        "FIRSTLIGHT_RESPONSE_ACCEPTANCE_TENANT_ID",
        "FIRSTLIGHT_RESPONSE_ACCEPTANCE_CASE_ID",
    ),
    "production": (
        "SUPABASE_URL",
        "SUPABASE_PUBLISHABLE_KEY",
        "FIRSTLIGHT_SHARED_RATE_LIMITER_URL",
    ),
}


def validate(mode: str, env: dict[str, str]) -> list[str]:
    errors: list[str] = []
    missing = [key for key in GROUPS[mode] if not env.get(key, "").strip()]
    if missing:
        errors.append("Missing required variables: " + ", ".join(missing))

    if mode == "tenant":
        url = env.get("SATARK_TEST_SUPABASE_URL", "").strip()
        parsed = urlsplit(url)
        if url and (parsed.scheme != "https" or not parsed.hostname):
            errors.append("SATARK_TEST_SUPABASE_URL must be a valid HTTPS URL")
        if url and parsed.hostname and not parsed.hostname.endswith(".supabase.co"):
            errors.append("Tenant tests must target a Supabase project URL")
        if url and parsed.hostname:
            ref = parsed.hostname.split(".")[0]
            if ref != EXPECTED_TEST_PROJECT_REF:
                errors.append("Tenant tests must target the approved isolated test project ref")
        ids = [env.get(k, "").strip() for k in (
            "SATARK_TEST_TENANT_A_ID", "SATARK_TEST_TENANT_B_ID", "SATARK_TEST_VIEWER_TENANT_ID"
        )]
        if all(ids):
            if not all(UUID_RE.fullmatch(v) for v in ids):
                errors.append("All tenant IDs must be UUIDs")
            if ids[0] == ids[1]:
                errors.append("Tenant A and Tenant B IDs must differ")
        emails = [env.get(k, "").strip().casefold() for k in (
            "SATARK_TEST_USER_A_EMAIL", "SATARK_TEST_USER_B_EMAIL", "SATARK_TEST_VIEWER_EMAIL"
        )]
        if all(emails) and len(set(emails)) != len(emails):
            errors.append("The three test identities must use distinct email addresses")

    if mode == "wazuh":
        if env.get("FIRSTLIGHT_WAZUH_SYNC_TOKEN", "") and len(env["FIRSTLIGHT_WAZUH_SYNC_TOKEN"]) < 32:
            errors.append("FIRSTLIGHT_WAZUH_SYNC_TOKEN must be at least 32 characters")
        for primary, confirmation in (
            ("FIRSTLIGHT_WAZUH_TENANT_ID", "FIRSTLIGHT_WAZUH_ACCEPTANCE_CONFIRM_TENANT_ID"),
            ("FIRSTLIGHT_WAZUH_CASE_ID", "FIRSTLIGHT_WAZUH_ACCEPTANCE_CONFIRM_CASE_ID"),
        ):
            if env.get(primary, "").strip() and env.get(confirmation, "").strip() and env[primary].strip().casefold() != env[confirmation].strip().casefold():
                errors.append(f"{confirmation} must exactly match {primary}")
        if env.get("FIRSTLIGHT_WAZUH_ACCEPTANCE_ALLOW_WRITES") != "I_AUTHORIZE_WRITES_TO_THIS_TEST_CASE":
            errors.append("Explicit isolated-test write confirmation is required")

    if mode == "response" and env.get("FIRSTLIGHT_RESPONSE_ACCEPTANCE_ENABLED", "").casefold() not in ("false", "0", "no", "disabled"):
        errors.append("Live response acceptance is intentionally disabled by this preflight; use a separately reviewed authorized lab procedure")

    if mode == "production":
        url = env.get("SUPABASE_URL", "").strip()
        parsed = urlsplit(url)
        if url and (parsed.scheme != "https" or not parsed.hostname or not parsed.hostname.endswith(".supabase.co")):
            errors.append("SUPABASE_URL must be a valid HTTPS Supabase URL")
        # This check is intentionally not a deploy action; production config needs a human-reviewed project mapping.
        if url and EXPECTED_TEST_PROJECT_REF in parsed.hostname if parsed.hostname else False:
            errors.append("Production configuration must not point at the isolated test project")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=tuple(GROUPS), help="configuration group to preflight")
    args = parser.parse_args()
    errors = validate(args.mode, dict(os.environ))
    if errors:
        print("NOT READY — configuration preflight failed (no secrets printed).")
        for error in errors:
            print("- " + error)
        print("This tool does not execute live tests or prove acceptance.")
        return 2
    print("CONFIGURATION SHAPE VALID — no live test was run and no acceptance gate has passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
