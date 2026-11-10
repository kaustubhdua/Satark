"""Durable, fail-closed approval ledger for FIRSTLIGHT response actions.

This module does not expose a network endpoint and never chooses targets. A trusted
server-side caller must authenticate identities and pass an already-authorized tenant
and case. External actions are at-most-once: an interrupted or uncertain provider call
is marked unknown and must be reconciled manually before any further action.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping


class ResponseExecutionError(RuntimeError):
    """Safe error for a rejected or unsafe response operation."""


_ALLOWED_ACTIONS = {"wazuh.block_ip", "wazuh.disable_account"}
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _text(value: str, label: str, limit: int) -> str:
    if not isinstance(value, str):
        raise ResponseExecutionError(f"{label} must be text.")
    value = value.strip()
    if not value or len(value) > limit or any(ord(ch) < 32 for ch in value):
        raise ResponseExecutionError(f"{label} is invalid.")
    return value


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ResponseExecutionError("Clock must return a timezone-aware datetime.")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class ResponseApproval:
    approval_id: str
    tenant_id: str
    case_id: str
    action: str
    target: str
    reason: str
    payload: Mapping[str, Any]
    requested_by: str
    status: str
    expires_at: str
    approved_by: str | None
    idempotency_key: str
    created_at: str | None = None
    approved_at: str | None = None
    decision_reason: str | None = None
    executor_id: str | None = None
    provider_reference: str | None = None
    result_detail: str | None = None


@dataclass(frozen=True)
class ExecutionOutcome:
    approval_id: str
    status: str
    provider_reference: str | None
    detail: str


class ResponseLedger:
    """SQLite-backed approval lifecycle and append-only hash-chained audit.

    Use a persistent local volume with restrictive filesystem permissions. SQLite's
    append-only triggers protect against ordinary application updates, not a privileged
    host administrator who can rewrite the database file; export/anchor the audit chain
    independently for stronger tamper evidence.
    """

    def __init__(self, database: str | Path, *, clock: Callable[[], datetime] | None = None):
        self.database = str(database)
        if self.database != ":memory:":
            Path(self.database).parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.database, timeout=5, isolation_level=None, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.execute("PRAGMA busy_timeout=5000")
        if self.database != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
        self._initialize()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _now(self) -> datetime:
        return _utc(self._clock())

    def _initialize(self) -> None:
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS response_approvals (
          approval_id TEXT PRIMARY KEY,
          tenant_id TEXT NOT NULL,
          case_id TEXT NOT NULL,
          action TEXT NOT NULL,
          target TEXT NOT NULL,
          reason TEXT NOT NULL,
          payload_json TEXT NOT NULL,
          requested_by TEXT NOT NULL,
          status TEXT NOT NULL CHECK(status IN ('pending','approved','denied','expired','executing','submitted','verified','failed','unknown')),
          created_at TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          approved_by TEXT,
          executor_id TEXT,
          approved_at TEXT,
          decision_reason TEXT,
          idempotency_key TEXT NOT NULL UNIQUE,
          provider_reference TEXT,
          result_detail TEXT,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS response_audit_events (
          sequence INTEGER PRIMARY KEY AUTOINCREMENT,
          occurred_at TEXT NOT NULL,
          approval_id TEXT NOT NULL,
          tenant_id TEXT NOT NULL,
          case_id TEXT NOT NULL,
          actor_id TEXT NOT NULL,
          event_type TEXT NOT NULL,
          event_json TEXT NOT NULL,
          previous_hash TEXT NOT NULL,
          event_hash TEXT NOT NULL UNIQUE
        );
        CREATE TRIGGER IF NOT EXISTS response_audit_no_update
          BEFORE UPDATE ON response_audit_events BEGIN SELECT RAISE(ABORT, 'response audit is append-only'); END;
        CREATE TRIGGER IF NOT EXISTS response_audit_no_delete
          BEFORE DELETE ON response_audit_events BEGIN SELECT RAISE(ABORT, 'response audit is append-only'); END;
        CREATE TRIGGER IF NOT EXISTS response_approval_binding_immutable
          BEFORE UPDATE ON response_approvals
          WHEN OLD.approval_id IS NOT NEW.approval_id
            OR OLD.tenant_id IS NOT NEW.tenant_id
            OR OLD.case_id IS NOT NEW.case_id
            OR OLD.action IS NOT NEW.action
            OR OLD.target IS NOT NEW.target
            OR OLD.reason IS NOT NEW.reason
            OR OLD.payload_json IS NOT NEW.payload_json
            OR OLD.requested_by IS NOT NEW.requested_by
            OR OLD.created_at IS NOT NEW.created_at
            OR OLD.expires_at IS NOT NEW.expires_at
            OR OLD.idempotency_key IS NOT NEW.idempotency_key
          BEGIN SELECT RAISE(ABORT, 'response approval binding is immutable'); END;
        CREATE INDEX IF NOT EXISTS response_approvals_case_idx
          ON response_approvals(tenant_id, case_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS response_approvals_status_expiry_idx
          ON response_approvals(status, expires_at);
        CREATE INDEX IF NOT EXISTS response_audit_approval_idx
          ON response_audit_events(approval_id, sequence);
        """)
        # Upgrade existing local ledgers without deleting approvals or audit history.
        columns = {row["name"] for row in self._db.execute("PRAGMA table_info(response_approvals)")}
        if "executor_id" not in columns:
            self._db.execute("ALTER TABLE response_approvals ADD COLUMN executor_id TEXT")

    def _event(self, approval_id: str, tenant_id: str, case_id: str, actor_id: str,
               event_type: str, data: Mapping[str, Any], occurred_at: str) -> None:
        previous = self._db.execute(
            "SELECT event_hash FROM response_audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous["event_hash"] if previous else "0" * 64
        event_json = _canonical(dict(data))
        material = _canonical({
            "occurred_at": occurred_at, "approval_id": approval_id, "tenant_id": tenant_id,
            "case_id": case_id, "actor_id": actor_id, "event_type": event_type,
            "event_json": event_json, "previous_hash": previous_hash,
        })
        event_hash = hashlib.sha256(material.encode("utf-8")).hexdigest()
        self._db.execute(
            "INSERT INTO response_audit_events(occurred_at,approval_id,tenant_id,case_id,actor_id,event_type,event_json,previous_hash,event_hash) VALUES(?,?,?,?,?,?,?,?,?)",
            (occurred_at, approval_id, tenant_id, case_id, actor_id, event_type, event_json, previous_hash, event_hash),
        )

    @staticmethod
    def _validate_payload(action: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise ResponseExecutionError("Action payload must be an object.")
        value = dict(payload)
        if action == "wazuh.block_ip":
            if set(value) != {"ip_address"} or not isinstance(value["ip_address"], str) or len(value["ip_address"]) > 64:
                raise ResponseExecutionError("Wazuh IP block payload must contain one bounded ip_address.")
        elif action == "wazuh.disable_account":
            if set(value) != {"username"} or not isinstance(value["username"], str) or len(value["username"]) > 128:
                raise ResponseExecutionError("Wazuh account-disable payload must contain one bounded username.")
        else:
            raise ResponseExecutionError("Action is not allowlisted for live execution.")
        try:
            encoded = _canonical(value).encode("utf-8")
        except (TypeError, ValueError, RecursionError) as exc:
            raise ResponseExecutionError("Action payload is not valid bounded JSON.") from exc
        if len(encoded) > 4096:
            raise ResponseExecutionError("Action payload exceeds 4 KiB.")
        return value

    def create_approval(self, *, tenant_id: str, case_id: str, requested_by: str,
                        action: str, target: str, reason: str, payload: Mapping[str, Any],
                        idempotency_key: str, expires_in_seconds: int = 600) -> ResponseApproval:
        tenant_id = _text(tenant_id, "tenant_id", 128)
        case_id = _text(case_id, "case_id", 128)
        requested_by = _text(requested_by, "requested_by", 128)
        target = _text(target, "target", 256)
        reason = _text(reason, "reason", 1000)
        idempotency_key = _text(idempotency_key, "idempotency_key", 128)
        if action not in _ALLOWED_ACTIONS:
            raise ResponseExecutionError("Action is not allowlisted for live execution.")
        if not isinstance(expires_in_seconds, int) or isinstance(expires_in_seconds, bool) or not 30 <= expires_in_seconds <= 86400:
            raise ResponseExecutionError("Approval expiry must be between 30 seconds and 24 hours.")
        normalized_payload = self._validate_payload(action, payload)
        now = self._now()
        expires = now + timedelta(seconds=expires_in_seconds)
        approval_id = str(uuid.uuid4())
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._db.execute(
                    "INSERT INTO response_approvals(approval_id,tenant_id,case_id,action,target,reason,payload_json,requested_by,status,created_at,expires_at,idempotency_key,updated_at) VALUES(?,?,?,?,?,?,?,?,'pending',?,?,?,?)",
                    (approval_id, tenant_id, case_id, action, target, reason, _canonical(normalized_payload), requested_by,
                     now.isoformat(), expires.isoformat(), idempotency_key, now.isoformat()),
                )
                self._event(approval_id, tenant_id, case_id, requested_by, "approval.requested",
                            {"action": action, "target": target, "reason": reason, "payload": normalized_payload,
                             "expires_at": expires.isoformat(), "idempotency_key": idempotency_key}, now.isoformat())
                self._db.commit()
            except sqlite3.IntegrityError as exc:
                self._db.rollback()
                raise ResponseExecutionError("Approval ID or idempotency key already exists; do not retry blindly.") from exc
            except Exception:
                self._db.rollback()
                raise
        return self.get_approval(approval_id, tenant_id=tenant_id, case_id=case_id)

    def get_approval(self, approval_id: str, *, tenant_id: str, case_id: str) -> ResponseApproval:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM response_approvals WHERE approval_id=? AND tenant_id=? AND case_id=?",
                (approval_id, tenant_id, case_id),
            ).fetchone()
        if row is None:
            raise ResponseExecutionError("Approval not found for this tenant and case.")
        return self._to_approval(row)

    def list_approvals(self, *, tenant_id: str, case_id: str) -> list[ResponseApproval]:
        """List a bounded case-scoped approval history without exposing other tenants."""
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM response_approvals WHERE tenant_id=? AND case_id=? ORDER BY created_at DESC LIMIT 100",
                (tenant_id, case_id),
            ).fetchall()
        return [self._to_approval(row) for row in rows]

    def list_audit_events(self, *, tenant_id: str, case_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM response_audit_events WHERE tenant_id=? AND case_id=? ORDER BY sequence",
                (tenant_id, case_id),
            ).fetchall()
        return [dict(row) for row in rows]

    def verify_audit_chain(self) -> bool:
        with self._lock:
            rows = self._db.execute("SELECT * FROM response_audit_events ORDER BY sequence").fetchall()
        previous_hash = "0" * 64
        for row in rows:
            if row["previous_hash"] != previous_hash:
                return False
            material = _canonical({
                "occurred_at": row["occurred_at"], "approval_id": row["approval_id"],
                "tenant_id": row["tenant_id"], "case_id": row["case_id"], "actor_id": row["actor_id"],
                "event_type": row["event_type"], "event_json": row["event_json"],
                "previous_hash": row["previous_hash"],
            })
            calculated = hashlib.sha256(material.encode("utf-8")).hexdigest()
            if not _HEX_SHA256.fullmatch(row["event_hash"]) or calculated != row["event_hash"]:
                return False
            previous_hash = row["event_hash"]
        return True

    def decide(self, approval_id: str, *, tenant_id: str, case_id: str,
               decided_by: str, approve: bool, decision_reason: str) -> ResponseApproval:
        decided_by = _text(decided_by, "decided_by", 128)
        decision_reason = _text(decision_reason, "decision_reason", 1000)
        now = self._now().isoformat()
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                row = self._db.execute(
                    "SELECT * FROM response_approvals WHERE approval_id=? AND tenant_id=? AND case_id=?",
                    (approval_id, tenant_id, case_id),
                ).fetchone()
                if row is None:
                    raise ResponseExecutionError("Approval not found for this tenant and case.")
                if row["status"] != "pending":
                    raise ResponseExecutionError("Approval is no longer pending.")
                if row["requested_by"] == decided_by:
                    raise ResponseExecutionError("Four-eyes control: the requester cannot approve or deny their own request.")
                if self._now() >= datetime.fromisoformat(row["expires_at"]):
                    self._db.execute("UPDATE response_approvals SET status='expired',updated_at=? WHERE approval_id=?", (now, approval_id))
                    self._event(approval_id, tenant_id, case_id, decided_by, "approval.expired", {}, now)
                    self._db.commit()
                    raise ResponseExecutionError("Approval has expired.")
                status = "approved" if approve else "denied"
                self._db.execute(
                    "UPDATE response_approvals SET status=?,approved_by=?,approved_at=?,decision_reason=?,updated_at=? WHERE approval_id=? AND status='pending'",
                    (status, decided_by, now, decision_reason, now, approval_id),
                )
                self._event(approval_id, tenant_id, case_id, decided_by,
                            "approval.approved" if approve else "approval.denied",
                            {"decision_reason": decision_reason}, now)
                self._db.commit()
            except Exception:
                if self._db.in_transaction:
                    self._db.rollback()
                raise
        return self.get_approval(approval_id, tenant_id=tenant_id, case_id=case_id)

    def execute_approved(self, approval_id: str, *, tenant_id: str, case_id: str,
                         executor_id: str,
                         handler: Callable[[ResponseApproval], Mapping[str, Any]]) -> ExecutionOutcome:
        """Claim once, then invoke the supplied trusted provider adapter.

        Handler result status must be submitted, failed, or unknown. Verification is
        a separate operation. Exceptions and ambiguous outcomes become unknown and are
        never automatically retried.
        """
        executor_id = _text(executor_id, "executor_id", 128)
        now = self._now().isoformat()
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                row = self._db.execute(
                    "SELECT * FROM response_approvals WHERE approval_id=? AND tenant_id=? AND case_id=?",
                    (approval_id, tenant_id, case_id),
                ).fetchone()
                if row is None:
                    raise ResponseExecutionError("Approval not found for this tenant and case.")
                if row["status"] != "approved":
                    raise ResponseExecutionError("Only an approved, unused response may execute.")
                if self._now() >= datetime.fromisoformat(row["expires_at"]):
                    self._db.execute("UPDATE response_approvals SET status='expired',updated_at=? WHERE approval_id=?", (now, approval_id))
                    self._event(approval_id, tenant_id, case_id, executor_id, "execution.expired", {}, now)
                    self._db.commit()
                    raise ResponseExecutionError("Approval has expired; no provider request was made.")
                self._db.execute("UPDATE response_approvals SET status='executing',executor_id=?,updated_at=? WHERE approval_id=? AND status='approved'", (executor_id, now, approval_id))
                self._event(approval_id, tenant_id, case_id, executor_id, "execution.claimed", {}, now)
                self._db.commit()
                claimed = self._db.execute("SELECT * FROM response_approvals WHERE approval_id=?", (approval_id,)).fetchone()
                approval = self._to_approval(claimed)
            except Exception:
                if self._db.in_transaction:
                    self._db.rollback()
                raise
        try:
            result = handler(approval)
            if not isinstance(result, Mapping):
                raise ResponseExecutionError("Provider adapter returned an invalid result.")
            status = result.get("status")
            if status not in {"submitted", "failed", "unknown"}:
                raise ResponseExecutionError("Provider adapter must return submitted, failed, or unknown; verification is a separate step.")
            reference = result.get("provider_reference")
            if reference is not None:
                reference = _text(str(reference), "provider_reference", 256)
            detail = result.get("detail", "")
            detail = _text(str(detail), "detail", 500) if detail else "No provider detail supplied."
        except Exception:
            # The provider may have acted before the connection failed. Never blindly retry.
            status, reference, detail = "unknown", None, "Execution outcome is uncertain; reconcile with the provider before any further action."
        finished = self._now().isoformat()
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                current = self._db.execute("SELECT status FROM response_approvals WHERE approval_id=?", (approval_id,)).fetchone()
                if current is None or current["status"] != "executing":
                    raise ResponseExecutionError("Execution state changed unexpectedly; investigate the audit log.")
                self._db.execute(
                    "UPDATE response_approvals SET status=?,provider_reference=?,result_detail=?,updated_at=? WHERE approval_id=? AND status='executing'",
                    (status, reference, detail, finished, approval_id),
                )
                self._event(approval_id, tenant_id, case_id, executor_id, "execution." + status,
                            {"provider_reference": reference, "detail": detail}, finished)
                self._db.commit()
            except Exception:
                if self._db.in_transaction:
                    self._db.rollback()
                raise
        return ExecutionOutcome(approval_id, status, reference, detail)

    def recover_interrupted_executions(self) -> int:
        """Mark abandoned executing records unknown; never retry a provider action.

        Call during trusted service startup before accepting new execution requests. A
        process crash may happen after the provider acted, so reconcile provider state.
        """
        now = self._now().isoformat()
        recovered = 0
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                rows = self._db.execute(
                    "SELECT approval_id,tenant_id,case_id FROM response_approvals WHERE status='executing' ORDER BY created_at"
                ).fetchall()
                for row in rows:
                    self._db.execute(
                        "UPDATE response_approvals SET status='unknown',result_detail=?,updated_at=? WHERE approval_id=? AND status='executing'",
                        ("Process restarted during execution; reconcile provider state before any further action.", now, row["approval_id"]),
                    )
                    self._event(row["approval_id"], row["tenant_id"], row["case_id"], "system:recovery",
                                "execution.recovered_unknown", {"automatic_retry": False}, now)
                    recovered += 1
                self._db.commit()
            except Exception:
                if self._db.in_transaction:
                    self._db.rollback()
                raise
        return recovered

    def record_verification(self, approval_id: str, *, tenant_id: str, case_id: str,
                            verifier_id: str, status: str, provider_reference: str,
                            detail: str) -> ResponseApproval:
        """Record independent provider-side verification; never infer it from submission."""
        verifier_id = _text(verifier_id, "verifier_id", 128)
        provider_reference = _text(provider_reference, "provider_reference", 256)
        detail = _text(detail, "detail", 500)
        if status not in {"verified", "failed", "unknown"}:
            raise ResponseExecutionError("Verification status must be verified, failed, or unknown.")
        now = self._now().isoformat()
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                row = self._db.execute(
                    "SELECT * FROM response_approvals WHERE approval_id=? AND tenant_id=? AND case_id=?",
                    (approval_id, tenant_id, case_id),
                ).fetchone()
                if row is None:
                    raise ResponseExecutionError("Approval not found for this tenant and case.")
                if row["status"] not in {"submitted", "unknown"}:
                    raise ResponseExecutionError("Only submitted or uncertain actions can be reconciled.")
                if not row["executor_id"]:
                    raise ResponseExecutionError("Executor identity is unavailable; independent verification cannot be established for this legacy action.")
                if verifier_id in {row["executor_id"], row["approved_by"], row["requested_by"]}:
                    raise ResponseExecutionError("Independent verification requires an identity distinct from requester, approver, and executor.")
                if row["provider_reference"] and row["provider_reference"] != provider_reference:
                    raise ResponseExecutionError("Provider reference does not match the submitted action.")
                self._db.execute(
                    "UPDATE response_approvals SET status=?,provider_reference=?,result_detail=?,updated_at=? WHERE approval_id=?",
                    (status, provider_reference, detail, now, approval_id),
                )
                self._event(approval_id, tenant_id, case_id, verifier_id, "verification." + status,
                            {"provider_reference": provider_reference, "detail": detail}, now)
                self._db.commit()
            except Exception:
                if self._db.in_transaction:
                    self._db.rollback()
                raise
        return self.get_approval(approval_id, tenant_id=tenant_id, case_id=case_id)

    @staticmethod
    def _to_approval(row: sqlite3.Row) -> ResponseApproval:
        return ResponseApproval(
            approval_id=row["approval_id"], tenant_id=row["tenant_id"], case_id=row["case_id"],
            action=row["action"], target=row["target"], reason=row["reason"],
            payload=json.loads(row["payload_json"]), requested_by=row["requested_by"],
            status=row["status"], expires_at=row["expires_at"], approved_by=row["approved_by"],
            idempotency_key=row["idempotency_key"], created_at=row["created_at"],
            approved_at=row["approved_at"], decision_reason=row["decision_reason"],
            executor_id=row["executor_id"], provider_reference=row["provider_reference"],
            result_detail=row["result_detail"],
        )
