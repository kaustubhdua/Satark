#!/usr/bin/env python3
"""Generate a private .env for docker-compose.production.yml.

Creates every secret the stack can generate itself (database passwords, API and
sync tokens, the Redis REST token and the MFA encryption key) and leaves the
values only an operator can supply (SMTP account, Wazuh connection details,
backup repository) clearly marked. It never overwrites an existing file.

    python3 scripts/bootstrap_selfhost.py --domain security.example.org --email admin@example.org
"""
from __future__ import annotations

import argparse
import os
import re
import secrets
import sys
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "deploy" / "production.env.example"
OPERATOR_KEYS = (
    "SATARK_SMTP_HOST", "SATARK_SMTP_USERNAME", "SATARK_SMTP_PASSWORD", "SATARK_SMTP_FROM",
    "FIRSTLIGHT_WAZUH_INDEXER_URL", "FIRSTLIGHT_WAZUH_INDEXER_USERNAME", "FIRSTLIGHT_WAZUH_INDEXER_PASSWORD",
    "FIRSTLIGHT_WAZUH_MANAGER_API_URL", "FIRSTLIGHT_WAZUH_MANAGER_USERNAME", "FIRSTLIGHT_WAZUH_MANAGER_PASSWORD",
    "FIRSTLIGHT_WAZUH_TENANT_ID", "FIRSTLIGHT_WAZUH_CASE_ID", "FIRSTLIGHT_WAZUH_ACTOR_ID",
)


def fernet_key() -> str:
    try:
        from cryptography.fernet import Fernet
    except ImportError:  # keep the script dependency-free: a Fernet key is 32 url-safe base64 bytes
        import base64
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    return Fernet.generate_key().decode()


def build(template: str, domain: str, email: str) -> tuple[str, list[str]]:
    runtime, backup = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    values = {
        "SATARK_DOMAIN": domain,
        "ACME_EMAIL": email,
        "POSTGRES_PASSWORD": secrets.token_urlsafe(32),
        "SATARK_RUNTIME_DB_PASSWORD": runtime,
        "SATARK_BACKUP_DB_PASSWORD": backup,
        "SATARK_DATABASE_URL": f"postgresql+psycopg://satark_runtime:{quote(runtime, safe='')}@db:5432/satark",
        "SATARK_BACKUP_DATABASE_URL": f"postgresql+psycopg://satark_backup:{quote(backup, safe='')}@db:5432/satark",
        "SATARK_MFA_ENCRYPTION_KEY": fernet_key(),
        "FIRSTLIGHT_API_TOKEN": secrets.token_hex(32),
        "FIRSTLIGHT_WAZUH_SYNC_TOKEN": secrets.token_hex(32),
        "REDIS_REST_TOKEN": secrets.token_hex(32),
    }
    lines = []
    for line in template.splitlines():
        match = re.match(r"^([A-Z][A-Z0-9_]*)=", line)
        if match and match.group(1) in values:
            line = f"{match.group(1)}={values[match.group(1)]}"
        lines.append(line)
    todo = [key for key in OPERATOR_KEYS if re.search(rf"^{key}=(REPLACE|.*example|.*\.private)", template, re.M)]
    return "\n".join(lines) + "\n", todo


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--domain", required=True, help="public DNS name served by Caddy")
    parser.add_argument("--email", required=True, help="ACME / Let's Encrypt contact address")
    parser.add_argument("--output", default=str(ROOT / ".env"))
    parser.add_argument("--force", action="store_true", help="overwrite an existing file")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?", args.domain) or "." not in args.domain:
        parser.error("--domain must be a bare DNS name such as security.example.org")
    output = Path(args.output)
    if output.exists() and not args.force:
        parser.error(f"{output} already exists; refusing to overwrite (use --force to replace it)")
    text, todo = build(TEMPLATE.read_text(encoding="utf-8"), args.domain, args.email)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    print(f"Wrote {output} (mode 600) with generated secrets. It is gitignored; never commit it.")
    print("Still yours to fill in before `docker compose -f docker-compose.production.yml up -d`:")
    for key in todo:
        print(f"  - {key}")
    print("Wazuh values need a running Wazuh deployment (see scripts/bootstrap_wazuh_lab.sh and docs).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
