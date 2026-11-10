"""Fail the build if application runtime source/configuration reintroduces Supabase."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_FILES = [
    ROOT / "web" / "src",
    ROOT / "android" / "app" / "src" / "main",
    ROOT / "android" / "app" / "build.gradle.kts",
    ROOT / "android" / "build.gradle.kts",
    ROOT / "android" / "settings.gradle.kts",
    ROOT / "web" / "next.config.ts",
    ROOT / "web" / "Dockerfile",
    ROOT / "web" / "scripts",
    ROOT / "web" / "package.json",
    ROOT / "web" / "package-lock.json",
    ROOT / "web" / ".env.example",
    ROOT / ".env.example",
    ROOT / "docker-compose.local.yml",
    ROOT / "Dockerfile.firstlight-api",
    ROOT / "Dockerfile.firstlight-worker",
    ROOT / "Dockerfile.firstlight-investigation-worker",
    ROOT / "firstlight_api.py",
    ROOT / "satark_backend.py",
    ROOT / "firstlight_wazuh_worker.py",
    ROOT / "firstlight_investigation_worker.py",
    ROOT / "requirements.txt",
    ROOT / "Dockerfile.streamlit",
    ROOT / "ui",
    ROOT / "firstlight-api-requirements.txt",
    ROOT / "scripts" / "satark_track1_acceptance_preflight.py",
    ROOT / ".github" / "workflows",
]
FORBIDDEN = re.compile(
    r"(?i:SUPABASE_(?:URL|PUBLISHABLE_KEY|SERVICE_ROLE_KEY|ANON_KEY|DB_PASSWORD|JWT_SECRET|DATABASE_URL)"
    r"|@supabase|supabase[.]co|/auth/v1|/rest/v1|/storage/v1"
    r"|from[ ]+supabase|import[ ]+supabase"
    r"|(?:^|[<>=\s])supabase(?:[<>=\s]|$))"
)


def source_files():
    # Include every first-party root Python module, not only the new API files.
    yield from (path for path in ROOT.glob("*.py") if path.is_file())
    for entry in RUNTIME_FILES:
        if entry.is_file():
            yield entry
        elif entry.is_dir():
            yield from (path for path in entry.rglob("*") if path.is_file())


def main() -> int:
    violations = []
    cli_config = ROOT / "supabase" / "config.toml"
    if cli_config.exists():
        violations.append("supabase/config.toml: unused Supabase CLI project configuration must not ship")
    for path in source_files():
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for line_number, line in enumerate(content.splitlines(), 1):
            if FORBIDDEN.search(line):
                violations.append(f"{path.relative_to(ROOT)}:{line_number}: {line.strip()[:200]}")
    if violations:
        print("Supabase runtime/configuration dependency detected:")
        print("\n".join(violations))
        return 1
    print("PASS: no Supabase SDK, runtime, CLI project config, REST, Storage, or Auth dependency.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
