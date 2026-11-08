#!/usr/bin/env python3
"""Fail-closed configuration preflight for SATARK Track 1 acceptance.

This validates only operator-supplied configuration shape. It does NOT contact
PostgreSQL, Wazuh, Microsoft, or production services, and it never prints secrets.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from urllib.parse import urlsplit

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")

GROUPS = {
    "tenant": (
        "SATARK_TEST_POSTGRES_URL",
        "SATARK_TEST_USER_A_EMAIL", "SATARK_TEST_USER_A_PASSWORD", "SATARK_TEST_TENANT_A_ID",
        "SATARK_TEST_USER_B_EMAIL", "SATARK_TEST_USER_B_PASSWORD", "SATARK_TEST_TENANT_B_ID",
        "SATARK_TEST_VIEWER_EMAIL", "SATARK_TEST_VIEWER_PASSWORD", "SATARK_TEST_VIEWER_TENANT_ID",
    ),
    "wazuh": (
        "FIRSTLIGHT_WAZUH_INDEXER_URL", "FIRSTLIGHT_WAZUH_INDEXER_USERNAME",
        "FIRSTLIGHT_WAZUH_INDEXER_PASSWORD", "FIRSTLIGHT_WAZUH_ALLOWED_AGENT_IDS",
        "FIRSTLIGHT_WAZUH_INITIAL_SINCE", "FIRSTLIGHT_WAZUH_TENANT_ID",
        "FIRSTLIGHT_WAZUH_CASE_ID", "FIRSTLIGHT_WAZUH_ACCEPTANCE_CONFIRM_TENANT_ID",
        "FIRSTLIGHT_WAZUH_ACCEPTANCE_CONFIRM_CASE_ID", "FIRSTLIGHT_WAZUH_ACCEPTANCE_ALLOW_WRITES",
    ),
    "response": (
        "FIRSTLIGHT_RESPONSE_ACCEPTANCE_ENABLED",
        "FIRSTLIGHT_RESPONSE_ACCEPTANCE_TENANT_ID",
        "FIRSTLIGHT_RESPONSE_ACCEPTANCE_CASE_ID",
    ),
    "production": ("SATARK_API_INTERNAL_URL", "SATARK_DATABASE_URL"),
}


def _postgres_url(value: str, name: str) -> tuple[str, str] | None:
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"postgresql", "postgresql+psycopg"} or not parsed.hostname or not parsed.path.strip("/"):
            return None
        return parsed.hostname.casefold(), parsed.path.strip("/").casefold()
    except ValueError:
        return None


def _https_origin(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        return parsed.scheme == "https" and bool(parsed.hostname) and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment
    except ValueError:
        return False


def validate(mode: str, env: dict[str, str]) -> list[str]:
    errors: list[str] = []
    missing = [key for key in GROUPS[mode] if not env.get(key, "").strip()]
    if missing:
        errors.append("Missing required variables: " + ", ".join(missing))

    if mode == "tenant":
        test_db = _postgres_url(env.get("SATARK_TEST_POSTGRES_URL", "").strip(), "SATARK_TEST_POSTGRES_URL")
        if env.get("SATARK_TEST_POSTGRES_URL") and not test_db:
            errors.append("SATARK_TEST_POSTGRES_URL must be a PostgreSQL URL with a database name")
        production_db = _postgres_url(env.get("SATARK_DATABASE_URL", "").strip(), "SATARK_DATABASE_URL")
        if test_db and production_db and test_db == production_db:
            errors.append("Tenant tests must use an isolated database, not the configured production database")
        ids = [env.get(k, "").strip() for k in (
            "SATARK_TEST_TENANT_A_ID", "SATARK_TEST_TENANT_B_ID", "SATARK_TEST_VIEWER_TENANT_ID"
        )]
        if all(ids):
            if not all(UUID_RE.fullmatch(v) for v in ids):
                errors.append("All tenant IDs must be UUIDs")
            if len(set(ids)) != len(ids):
                errors.append("Tenant A, Tenant B, and viewer tenant IDs must be distinct")
        emails = [env.get(k, "").strip().casefold() for k in (
            "SATARK_TEST_USER_A_EMAIL", "SATARK_TEST_USER_B_EMAIL", "SATARK_TEST_VIEWER_EMAIL"
        )]
        if all(emails) and len(set(emails)) != len(emails):
            errors.append("The three test identities must use distinct email addresses")

    if mode == "wazuh":
        url = env.get("FIRSTLIGHT_WAZUH_INDEXER_URL", "").strip()
        allow_http = env.get("FIRSTLIGHT_WAZUH_ALLOW_HTTP", "").casefold() in {"1", "true", "yes"}
        if url:
            parsed = urlsplit(url)
            allowed_schemes = {"https", "http"} if allow_http else {"https"}
            if parsed.scheme not in allowed_schemes or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                errors.append("FIRSTLIGHT_WAZUH_INDEXER_URL must be a safe HTTPS URL without embedded credentials, query, or fragment")
        agents = [item.strip() for item in env.get("FIRSTLIGHT_WAZUH_ALLOWED_AGENT_IDS", "").split(",") if item.strip()]
        if env.get("FIRSTLIGHT_WAZUH_ALLOWED_AGENT_IDS") and (
            not 1 <= len(agents) <= 100 or any(not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", item) for item in agents)
        ):
            errors.append("FIRSTLIGHT_WAZUH_ALLOWED_AGENT_IDS must list 1–100 valid agent IDs")
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
        if env.get("SATARK_API_INTERNAL_URL") and not _https_origin(env["SATARK_API_INTERNAL_URL"].strip()):
            errors.append("SATARK_API_INTERNAL_URL must be a safe HTTPS URL without credentials, query, or fragment")
        if env.get("SATARK_DATABASE_URL") and not _postgres_url(env["SATARK_DATABASE_URL"].strip(), "SATARK_DATABASE_URL"):
            errors.append("SATARK_DATABASE_URL must be a PostgreSQL URL with a database name")

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
