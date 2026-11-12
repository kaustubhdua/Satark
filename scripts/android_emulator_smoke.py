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


PACKAGE = "com.satark.mobile"
ACTIVITY = f"{PACKAGE}/.MainActivity"


def run(*args: str, timeout: int = 45, check: bool = True) -> str:
    result = subprocess.run(args, check=check, capture_output=True, text=True, timeout=timeout)
    return result.stdout + (result.stderr if not check else "")


def dump_hierarchy(path: Path) -> str:
    run("adb", "shell", "uiautomator", "dump", "/sdcard/satark-window.xml", timeout=60)
    run("adb", "pull", "/sdcard/satark-window.xml", str(path), timeout=60)
    return path.read_text(encoding="utf-8")


def activity_snapshot() -> str:
    """Read multiple Android surfaces because dumpsys output differs by API image."""
    chunks: list[str] = []
    for command in (
        ("adb", "shell", "dumpsys", "activity", "activities"),
        ("adb", "shell", "dumpsys", "activity", "top"),
        ("adb", "shell", "dumpsys", "window"),
    ):
        try:
            chunks.append(run(*command, timeout=30))
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as error:
            chunks.append(f"{command[-1]} unavailable: {error}")
    return "\n".join(chunks)


def is_satark_foreground(snapshot: str) -> bool:
    """Accept both short and fully-qualified component names on Android 15/16."""
    for line in snapshot.splitlines():
        lowered = line.lower()
        if PACKAGE in lowered and "mainactivity" in lowered and any(
            marker in lowered
            for marker in ("resumed", "focus", "activity ", "activityrecord", "topresumed")
        ):
            return True
    return False


def failure_diagnostics(start_output: str, artifact_dir: Path) -> None:
    """Persist useful failure context instead of reporting only a timeout."""
    diagnostics = [
        "=== am start -W output ===",
        start_output,
        "=== foreground activity snapshot ===",
        activity_snapshot(),
    ]
    try:
        logs = run("adb", "logcat", "-d", "-t", "12000", timeout=60, check=False)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as error:
        logs = f"Unable to collect logcat: {error}"
    log_path = artifact_dir / "satark-emulator-logcat.txt"
    log_path.write_text(logs, encoding="utf-8")
    diagnostics.extend(("=== recent app/system errors (full logcat saved) ===", "\n".join(
        line for line in logs.splitlines()
        if PACKAGE in line or any(marker in line.lower() for marker in (
            "fatal exception", "fatal signal", "chaquopy", "androidruntime",
            "unable to start", "permission denial", "crash"
        ))
    )[-12000:]))
    print("\n".join(diagnostics))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", type=Path, default=Path("artifacts"))
    args = parser.parse_args()
    apk = args.artifact_dir / "apk" / "app-debug.apk"
    if not apk.is_file() or apk.stat().st_size == 0:
        raise SystemExit(f"debug APK is missing or empty: {apk}")

    args.artifact_dir.mkdir(parents=True, exist_ok=True)
    print(run("adb", "install", "-r", str(apk), timeout=180))
    # Android 13+ otherwise opens the notification permission dialog on first
    # launch, making the app's activity look backgrounded to the smoke check.
    # Pre-grant only this non-sensitive notification permission in the disposable
    # CI emulator; physical-device consent behavior remains a manual QA item.
    run("adb", "shell", "pm", "grant", PACKAGE, "android.permission.POST_NOTIFICATIONS", check=False)
    run("adb", "shell", "am", "force-stop", PACKAGE)
    start_output = run("adb", "shell", "am", "start", "-W", "-n", ACTIVITY, timeout=90, check=False)
    if "Error:" in start_output or "Exception" in start_output:
        failure_diagnostics(start_output, args.artifact_dir)
        raise SystemExit("Android rejected the SATARK launch intent; see emulator diagnostics")

    deadline = time.monotonic() + 180
    xml_path = args.artifact_dir / "satark-window.xml"
    snapshots: list[str] = []
    while time.monotonic() < deadline:
        try:
            state = activity_snapshot()
            if is_satark_foreground(state):
                snapshots = [dump_hierarchy(xml_path)]
                break
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            pass
        time.sleep(3)

    if not snapshots:
        failure_diagnostics(start_output, args.artifact_dir)
        raise SystemExit("SATARK MainActivity did not become the foreground activity on the emulator")

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
        failure_diagnostics(start_output, args.artifact_dir)
        raise SystemExit("SATARK UI is missing expected labels or accessible controls: " + ", ".join(missing))

    logs = run("adb", "logcat", "-d", "-t", "4000", timeout=60)
    fatal = ("FATAL EXCEPTION", "com.chaquo.python.PyException")
    if any(marker in logs for marker in fatal):
        (args.artifact_dir / "satark-emulator-logcat.txt").write_text(logs, encoding="utf-8")
        raise SystemExit("SATARK crashed during emulator launch; inspect satark-emulator-logcat.txt")
    print("SATARK emulator smoke passed: foreground MainActivity, file/folder actions and crash markers verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
