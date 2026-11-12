#!/usr/bin/python3
"""TTL-backed firewall blocks for SATARK's Wazuh 4.x Active Response agent."""
from __future__ import annotations

import fcntl
import ipaddress
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

DEFAULT_STATE_DIR = "/var/lib/satark-response"
MAX_TTL_SECONDS = 900
MIN_TTL_SECONDS = 60


class ResponseStateError(RuntimeError):
    pass


def _paths() -> tuple[Path, Path, Path]:
    directory = Path(os.getenv("SATARK_RESPONSE_STATE_DIR", DEFAULT_STATE_DIR))
    return directory, directory / "blocks.json", directory / "state.lock"


def _iptables() -> str:
    binary = shutil.which("iptables")
    if not binary:
        raise ResponseStateError("iptables is not installed; refusing to apply firewall response.")
    return binary


def _run_iptables(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [_iptables(), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def _valid_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ResponseStateError("Response target is not a valid IP address.") from None
    if address.version != 4 or not address.is_global:
        raise ResponseStateError("Only globally routable IPv4 addresses are supported.")
    return str(address)


def _valid_ttl(value: str | int) -> int:
    try:
        ttl = int(value)
    except (TypeError, ValueError):
        raise ResponseStateError("TTL must be an integer number of seconds.") from None
    if not MIN_TTL_SECONDS <= ttl <= MAX_TTL_SECONDS:
        raise ResponseStateError("TTL must be between 60 and 900 seconds.")
    return ttl


def _load(path: Path) -> dict[str, float]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError):
        raise ResponseStateError("SATARK response state is unreadable; refusing to change firewall rules.") from None
    if not isinstance(data, dict):
        raise ResponseStateError("SATARK response state has an invalid format.")
    result: dict[str, float] = {}
    for ip, expiry in data.items():
        try:
            result[_valid_ip(str(ip))] = float(expiry)
        except (ValueError, TypeError, ResponseStateError):
            raise ResponseStateError("SATARK response state contains an invalid entry.") from None
    return result


def _save(path: Path, state: dict[str, float]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="blocks.", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _owned_rule(ip: str) -> tuple[str, ...]:
    # A unique iptables comment distinguishes SATARK-owned rules from an
    # operator-created DROP rule for the same address.
    return ("-s", ip, "-m", "comment", "--comment", f"SATARK:{ip}", "-j", "DROP")


def _delete_owned_rule(ip: str) -> None:
    # Remove only the exact rule carrying SATARK's ownership marker; never
    # delete an operator's pre-existing or subsequently-added firewall rule.
    # Bound the loop in case a damaged host contains duplicate SATARK rules.
    rule = _owned_rule(ip)
    for _ in range(16):
        check = _run_iptables("-C", "INPUT", *rule)
        if check.returncode != 0:
            return
        delete = _run_iptables("-D", "INPUT", *rule)
        if delete.returncode != 0:
            raise ResponseStateError("Could not remove the SATARK firewall rule.")


def add_block(ip_value: str, ttl_value: str | int, *, now: float | None = None) -> dict[str, Any]:
    ip = _valid_ip(ip_value)
    ttl = _valid_ttl(ttl_value)
    current_time = time.time() if now is None else float(now)
    directory, state_path, lock_path = _paths()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        state = _load(state_path)
        expiry = current_time + ttl
        if ip in state:
            owned = _run_iptables("-C", "INPUT", *_owned_rule(ip))
            if owned.returncode != 0:
                raise ResponseStateError("SATARK recorded a block but its owned firewall rule is missing.")
            state[ip] = expiry
            _save(state_path, state)
            return {"status": "extended", "ip_address": ip, "expires_at": expiry}
        existing = _run_iptables("-C", "INPUT", "-s", ip, "-j", "DROP")
        if existing.returncode == 0:
            return {"status": "already_blocked_unowned", "ip_address": ip}
        # Record ownership before changing the firewall. If the process dies
        # after insertion, the watchdog still knows the expiry and can reverse it.
        state[ip] = expiry
        _save(state_path, state)
        inserted = _run_iptables("-I", "INPUT", "1", *_owned_rule(ip))
        if inserted.returncode != 0:
            state.pop(ip, None)
            _save(state_path, state)
            raise ResponseStateError("iptables rejected the SATARK firewall block.")
        return {"status": "blocked", "ip_address": ip, "expires_at": expiry}


def remove_block(ip_value: str) -> dict[str, Any]:
    ip = _valid_ip(ip_value)
    directory, state_path, lock_path = _paths()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        state = _load(state_path)
        if ip not in state:
            return {"status": "not_owned", "ip_address": ip}
        _delete_owned_rule(ip)
        state.pop(ip, None)
        _save(state_path, state)
        return {"status": "removed", "ip_address": ip}


def expire_due(*, now: float | None = None) -> list[str]:
    current_time = time.time() if now is None else float(now)
    directory, state_path, lock_path = _paths()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    expired: list[str] = []
    with lock_path.open("a+", encoding="utf-8") as lock:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        state = _load(state_path)
        for ip, expiry in list(state.items()):
            if expiry > current_time:
                continue
            _delete_owned_rule(ip)
            state.pop(ip, None)
            expired.append(ip)
        if expired:
            _save(state_path, state)
    return expired
