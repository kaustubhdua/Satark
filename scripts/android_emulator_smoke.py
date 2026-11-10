#!/usr/bin/env python3
"""Smoke-test the exact SATARK APK on an Android emulator.

Kept in a checked-in file rather than an inline shell heredoc because
android-emulator-runner executes its script through /bin/sh.
"""
from __future__ import annotations

import argparse
import subprocess
import time
from pathlib import Path


def run(*args: str, timeout: int = 45) -> str:
    result = subprocess.run(args, check=True, capture_output=True, text=True, timeout=timeout)
    return result.stdout


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
    # am start -W can report a timeout on slow software-rendered hosted
    # emulators even when the activity eventually becomes responsive.
    run("adb", "shell", "am", "start", "-n", "com.satark.mobile/.MainActivity")
    deadline = time.monotonic() + 180
    xml_path = args.artifact_dir / "satark-window.xml"
    xml = ""
    while time.monotonic() < deadline:
        try:
            activities = run("adb", "shell", "dumpsys", "activity", "activities")
            if "com.satark.mobile/.MainActivity" in activities:
                run("adb", "shell", "uiautomator", "dump", "/sdcard/satark-window.xml", timeout=60)
                run("adb", "pull", "/sdcard/satark-window.xml", str(xml_path), timeout=60)
                xml = xml_path.read_text(encoding="utf-8")
                required = ("File Guard", "Quick scan", "BUNDLED EMBER2024 STARTER", "HASHES")
                if all(label in xml for label in required):
                    break
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            pass
        time.sleep(3)

    if not xml:
        raise SystemExit("SATARK activity did not expose an accessibility hierarchy")
    required = ("File Guard", "Quick scan", "BUNDLED EMBER2024 STARTER", "HASHES")
    missing = [label for label in required if label not in xml]
    if missing:
        raise SystemExit("SATARK UI is missing expected labels: " + ", ".join(missing))
    logs = run("adb", "logcat", "-d", "-t", "4000", timeout=60)
    fatal = ("FATAL EXCEPTION", "com.chaquo.python.PyException")
    if any(marker in logs for marker in fatal):
        raise SystemExit("SATARK crashed during emulator launch; inspect logcat artifact")
    print("SATARK emulator smoke passed: activity, accessibility labels and crash markers verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
