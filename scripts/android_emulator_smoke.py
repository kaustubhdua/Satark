#!/usr/bin/env python3
"""Smoke-test the exact SATARK APK on an Android emulator.

The accessibility hierarchy is viewport-scoped on some Android images, so
inspect multiple scroll positions instead of assuming every card is visible
in the first dump. This is a launch/UI smoke test, not physical-device QA.
"""
from __future__ import annotations

import argparse
import subprocess
import time
from pathlib import Path


def run(*args: str, timeout: int = 45) -> str:
    result = subprocess.run(args, check=True, capture_output=True, text=True, timeout=timeout)
    return result.stdout


def dump_hierarchy(path: Path) -> str:
    run("adb", "shell", "uiautomator", "dump", "/sdcard/satark-window.xml", timeout=60)
    run("adb", "pull", "/sdcard/satark-window.xml", str(path), timeout=60)
    return path.read_text(encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", type=Path, default=Path("artifacts"))
    args = parser.parse_args()
    apk = args.artifact_dir / "apk" / "app-debug.apk"
    if not apk.is_file() or apk.stat().st_size == 0:
        raise SystemExit(f"debug APK is missing or empty: {apk}")

    args.artifact_dir.mkdir(parents=True, exist_ok=True)
    run("adb", "install", "-r", str(apk), timeout=180)
    run("adb", "shell", "am", "force-stop", "com.satark.mobile")
    run("adb", "shell", "am", "start", "-n", "com.satark.mobile/.MainActivity")

    deadline = time.monotonic() + 180
    xml_path = args.artifact_dir / "satark-window.xml"
    snapshots: list[str] = []
    while time.monotonic() < deadline:
        try:
            activities = run("adb", "shell", "dumpsys", "activity", "activities")
            if "com.satark.mobile/.MainActivity" in activities:
                snapshots = [dump_hierarchy(xml_path)]
                break
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            pass
        time.sleep(3)

    if not snapshots:
        raise SystemExit("SATARK MainActivity did not become visible on the emulator")

    # Scroll through the long, intentionally single-screen app so that
    # off-viewport accessibility nodes are checked as well.
    for _ in range(4):
        try:
            run("adb", "shell", "input", "swipe", "540", "1700", "540", "650", "450")
            time.sleep(1)
            snapshots.append(dump_hierarchy(xml_path))
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            break

    combined = "\n".join(snapshots)
    required = ("File Guard", "Choose files to scan", "Choose a folder to monitor")
    missing = [label for label in required if label not in combined]
    if missing:
        raise SystemExit("SATARK UI is missing expected labels or accessible controls: " + ", ".join(missing))

    logs = run("adb", "logcat", "-d", "-t", "4000", timeout=60)
    fatal = ("FATAL EXCEPTION", "com.chaquo.python.PyException")
    if any(marker in logs for marker in fatal):
        raise SystemExit("SATARK crashed during emulator launch; inspect logcat artifact")
    print("SATARK emulator smoke passed: MainActivity, file/folder actions and crash markers verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
