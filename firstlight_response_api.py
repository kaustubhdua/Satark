"""Authenticated FIRSTLIGHT response approval API.

The API is disabled by default. It never derives targets from investigation output.
Every action is bound to a case, requires four-eyes approval, an explicit target
confirmation, a third execution identity, and a durable at-most-once ledger.
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from dataclasses import asdict
from typing import Any, Iterator

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from firstlight_response_executor import ResponseApproval, ResponseExecutionError, ResponseLedger
from integrations.response_actions import (
    ResponseIntegrationError,
    isolate_defender_device,
    preflight_live_response,
    revoke_entra_user_sessions,
    live_response_enabled,
)
from satark_backend import Case, User, db_session, current_user, require_membership

router = APIRouter(prefix="/api/firstlight/live-response", tags=["FIRSTLIGHT guarded response"])


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    tenant_id: str = Field(min_length=36, max_length=36)
    case_id: str = Field(min_length=36, max_length=36)
    action: str = Field(min_length=1, max_length=64)
    target: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=1, max_length=1000)
    payload: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str = Field(min_length=8, max_length=128)
    expires_in_seconds: int = Field(default=600, ge=30, le=86400)


class ApprovalDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    tenant_id: str
    case_id: str
    approval_id: str
    decision: str
    reason: str = Field(min_length=1, max_length=1000)


class ExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    tenant_id: str
    case_id: str
    approval_id: str
    confirmation: str = Field(min_length=1, max_length=600)


class VerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    tenant_id: str
    case_id: str
    approval_id: str
    status: str
    provider_reference: str = Field(min_length=1, max_length=256)
    detail: str = Field(min_length=1, max_length=500)


@contextmanager
def _ledger_scope() -> Iterator[ResponseLedger]:
    path = os.getenv("FIRSTLIGHT_RESPONSE_DB", "/tmp/satark/firstlight-response.sqlite3")
    ledger = ResponseLedger(path)
    try:
        yield ledger
    finally:
        ledger.close()


def recover_interrupted_executions() -> int:
    """Fail closed after restart; an in-flight provider request is never retried."""
    with _ledger_scope() as ledger:
        return ledger.recover_interrupted_executions()


def _case_access(db: Session, user: User, tenant_id: str, case_id: str, roles: set[str]) -> None:
    require_membership(db, user, tenant_id, roles)
    case = db.scalar(select(Case.id).where(Case.id == case_id, Case.tenant_id == tenant_id))
    if not case:
        raise HTTPException(404, "Case not found.")


def _approval_json(item: ResponseApproval) -> dict[str, Any]:
    return asdict(item)


@router.get("/status")
def response_status(
    tenant_id: str,
    case_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(db_session),
):
    _case_access(db, user, tenant_id, case_id, {"owner", "responder", "analyst", "viewer"})
    configured = all(os.getenv(name, "").strip() for name in (
        "MICROSOFT_TENANT_ID", "MICROSOFT_CLIENT_ID", "MICROSOFT_CLIENT_SECRET"
    ))
    return {
        "enabled": live_response_enabled(),
        "credentials_configured": configured,
        "actions": ["defender.isolate_device", "entra.revoke_sessions"],
        "execution_policy": "four-eyes approval, separate executor, exact target confirmation, at-most-once",
        "default_mode": "disabled",
    }


@router.get("/approvals")
def list_response_approvals(
    tenant_id: str,
    case_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(db_session),
):
    _case_access(db, user, tenant_id, case_id, {"owner", "responder", "analyst", "viewer"})
    with _ledger_scope() as ledger:
        items = ledger.list_approvals(tenant_id=tenant_id, case_id=case_id)
    return {"approvals": [_approval_json(item) for item in items]}


@router.post("/approvals", status_code=201)
def request_response_approval(
    body: ApprovalRequest,
    user: User = Depends(current_user),
    db: Session = Depends(db_session),
):
    _case_access(db, user, body.tenant_id, body.case_id, {"owner", "responder", "analyst"})
    with _ledger_scope() as ledger:
        try:
            item = ledger.create_approval(
                tenant_id=body.tenant_id, case_id=body.case_id, requested_by=user.id,
                action=body.action, target=body.target, reason=body.reason,
                payload=body.payload, idempotency_key=body.idempotency_key,
                expires_in_seconds=body.expires_in_seconds,
            )
        except ResponseExecutionError as exc:
            raise HTTPException(409, str(exc)) from None
    return {"approval": _approval_json(item), "live_execution_enabled": live_response_enabled()}


@router.patch("/approvals")
def decide_response_approval(
    body: ApprovalDecision,
    user: User = Depends(current_user),
    db: Session = Depends(db_session),
):
    if body.decision not in {"approved", "denied"}:
        raise HTTPException(422, "decision must be approved or denied")
    _case_access(db, user, body.tenant_id, body.case_id, {"owner", "responder"})
    with _ledger_scope() as ledger:
        try:
            item = ledger.decide(
                body.approval_id, tenant_id=body.tenant_id, case_id=body.case_id,
                decided_by=user.id, approve=body.decision == "approved",
                decision_reason=body.reason,
            )
        except ResponseExecutionError as exc:
            raise HTTPException(409, str(exc)) from None
    return {"approval": _approval_json(item)}


@router.post("/execute")
def execute_response(
    body: ExecuteRequest,
    user: User = Depends(current_user),
    db: Session = Depends(db_session),
):
    _case_access(db, user, body.tenant_id, body.case_id, {"owner", "responder"})
    with _ledger_scope() as ledger:
        try:
            approval = ledger.get_approval(body.approval_id, tenant_id=body.tenant_id, case_id=body.case_id)
            if user.id in {approval.requested_by, approval.approved_by}:
                raise HTTPException(403, "A separate third operator must execute the approved response.")
            try:
                preflight_live_response(approval.action, approval.target, body.confirmation)
            except ResponseIntegrationError as exc:
                raise HTTPException(503, str(exc)) from None

            def handler(item: ResponseApproval) -> dict[str, Any]:
                if item.action == "defender.isolate_device":
                    result = isolate_defender_device(
                        item.target, confirmation=body.confirmation,
                        isolation_type=str(item.payload["isolation_type"]), reason=item.reason,
                    )
                elif item.action == "entra.revoke_sessions":
                    result = revoke_entra_user_sessions(
                        item.target, confirmation=body.confirmation, reason=item.reason,
                    )
                else:
                    raise ResponseIntegrationError("Action is not allowlisted for live response.")
                return asdict(result)

            outcome = ledger.execute_approved(
                body.approval_id, tenant_id=body.tenant_id, case_id=body.case_id,
                executor_id=user.id, handler=handler,
            )
        except HTTPException:
            raise
        except ResponseExecutionError as exc:
            raise HTTPException(409, str(exc)) from None
    return {
        "outcome": asdict(outcome),
        "message": "Provider submission is not proof of completed containment. Obtain independent provider-side verification.",
    }


@router.post("/verify")
def verify_response(
    body: VerificationRequest,
    user: User = Depends(current_user),
    db: Session = Depends(db_session),
):
    _case_access(db, user, body.tenant_id, body.case_id, {"owner", "responder"})
    with _ledger_scope() as ledger:
        try:
            item = ledger.record_verification(
                body.approval_id, tenant_id=body.tenant_id, case_id=body.case_id,
                verifier_id=user.id, status=body.status,
                provider_reference=body.provider_reference, detail=body.detail,
            )
        except ResponseExecutionError as exc:
            raise HTTPException(409, str(exc)) from None
    return {
        "approval": _approval_json(item),
        "verification_kind": "independent_operator_attestation",
        "note": "The operator must first verify the result in the provider console. SATARK records the attestation; it does not infer provider state.",
    }


@router.get("/audit")
def response_audit(
    tenant_id: str,
    case_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(db_session),
):
    _case_access(db, user, tenant_id, case_id, {"owner", "responder", "analyst", "viewer"})
    with _ledger_scope() as ledger:
        events = ledger.list_audit_events(tenant_id=tenant_id, case_id=case_id)
        valid = ledger.verify_audit_chain()
    return {"events": events, "chain_valid": valid, "chain_scope": "whole local response ledger"}
