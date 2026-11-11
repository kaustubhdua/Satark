#!/usr/bin/env python3
"""Fail CI if Microsoft Defender/Entra integrations return to runtime source.

Historical migration notes may explain the removal, but application code,
configuration, dependencies, containers and workflow definitions must remain
provider-independent. Wazuh is the supported endpoint integration.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()
EXTENSIONS = {
    ".py", ".pyi", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".kt", ".java", ".xml", ".json", ".yml", ".yaml", ".toml",
    ".sh", ".txt", ".properties", ".gradle", ".kts",
}
FORBIDDEN = re.compile(
    r"api\.security\.microsoft\.com"
    r"|graph\.microsoft\.com"
    r"|login\.microsoftonline\.com"
    r"|microsoft\.graph"
    r"|azure\.identity"
    r"|\bmsal\b"
    r"|(?<![A-Za-z0-9_])MICROSOFT_[A-Z0-9_]+"\n    r"|NEXT_PUBLIC_MICROSOFT_[A-Z0-9_]+"
    r"|defender\.isolate_device"
    r"|entra\.revoke_sessions"
    r"|microsoft\s+defender",
    re.IGNORECASE,
)
SKIP_PARTS = {
    ".git", ".next", "node_modules", ".venv", "venv", "__pycache__",
    "build", "dist", "docs", "tests", "test", "assets", "coverage", ".gradle",
}


def runtime_files() -> list[Path]:
    files: set[Path] = set()
    for path in ROOT.iterdir():
        if path.is_file() and (path.suffix in EXTENSIONS or path.name in {
            ".env.example", "Dockerfile", "Dockerfile.firstlight-api",
            "Dockerfile.firstlight-worker", "Dockerfile.firstlight-investigation-worker",
        }):
            files.add(path)
    scan_roots = (
        ROOT / "integrations",
        ROOT / "scripts",
        ROOT / "web",
        ROOT / "android",
        ROOT / ".github" / "workflows",
        ROOT / "deploy",
    )
    for base in scan_roots:
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or path.suffix not in EXTENSIONS:
                continue
            if any(part in SKIP_PARTS for part in path.parts):
                continue
            files.add(path)
    for manifest in (ROOT / "web" / "package.json", ROOT / "web" / "package-lock.json"):
        if manifest.is_file():
            files.add(manifest)
    files.discard(SELF)
    return sorted(files)


def main() -> int:
    violations: list[str] = []
    for path in runtime_files():
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for line_number, line in enumerate(content.splitlines(), start=1):
            if FORBIDDEN.search(line):
                relative = path.relative_to(ROOT)
                violations.append(f"{relative}:{line_number}: forbidden Microsoft endpoint/identity integration")
    if violations:
        print("\n".join(violations), file=sys.stderr)
        return 1
    print("Provider boundary passed: runtime source/configuration contains no Microsoft Defender or Entra integration.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
