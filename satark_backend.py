"""Self-hosted SATARK application backend.

No Supabase SDK, Auth, PostgREST, Storage, or RPC calls are used here.
PostgreSQL is the production database; SQLite is supported for local use/tests.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import APIRouter, Depends, Header, HTTPException, Request, UploadFile, File, Form
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session

router = APIRouter(prefix="/api", tags=["SATARK self-hosted"])
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PASSWORDS = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)
SESSION_TTL_DAYS = 14
MAX_UPLOAD = 4 * 1024 * 1024


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def database_url() -> str:
    value = os.getenv("SATARK_DATABASE_URL", "").strip()
    if value:
        return value
    path = Path(os.getenv("SATARK_SQLITE_PATH", "./data/satark.db"))
    path.parent.mkdir(parents=True, exist_ok=True)
    return "sqlite:///" + str(path.resolve())


DB_URL = database_url()
engine = create_engine(DB_URL, pool_pre_ping=True, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "satark_users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SessionRecord(Base):
    __tablename__ = "satark_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("satark_users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Tenant(Base):
    __tablename__ = "satark_tenants"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(160))
    created_by: Mapped[str] = mapped_column(ForeignKey("satark_users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Membership(Base):
    __tablename__ = "satark_memberships"
    __table_args__ = (UniqueConstraint("tenant_id", "user_id", name="uq_satark_membership"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(ForeignKey("satark_tenants.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("satark_users.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(16))


class Case(Base):
    __tablename__ = "satark_cases"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(ForeignKey("satark_tenants.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(240))
    status: Mapped[str] = mapped_column(String(24), default="open")
    severity: Mapped[str] = mapped_column(String(16), default="unknown")
    assigned_to: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("satark_users.id"))
    metadata_json: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CaseNote(Base):
    __tablename__ = "satark_case_notes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("satark_cases.id", ondelete="CASCADE"), index=True)
    body: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Evidence(Base):
    __tablename__ = "satark_evidence"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("satark_cases.id", ondelete="CASCADE"), index=True)
    object_key: Mapped[str] = mapped_column(String(512), unique=True)
    source_label: Mapped[str] = mapped_column(String(160))
    event_kind: Mapped[str] = mapped_column(String(100))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    summary: Mapped[str] = mapped_column(String(8192))
    source_sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    content_type: Mapped[str] = mapped_column(String(160))
    original_filename: Mapped[str] = mapped_column(String(100))
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Finding(Base):
    __tablename__ = "satark_findings"
    __table_args__ = (UniqueConstraint("tenant_id", "case_id", "finding_key", name="uq_satark_finding_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("satark_cases.id", ondelete="CASCADE"), index=True)
    finding_key: Mapped[str] = mapped_column(String(160))
    title: Mapped[str] = mapped_column(String(240))
    severity: Mapped[str] = mapped_column(String(16))
    detail: Mapped[str] = mapped_column(Text)
    evidence_refs: Mapped[list] = mapped_column(JSON, default=list)
    source: Mapped[str] = mapped_column(String(160))
    confidence: Mapped[float | None] = mapped_column(nullable=True)
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Report(Base):
    __tablename__ = "satark_reports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("satark_cases.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(240))
    snapshot: Mapped[dict] = mapped_column(JSON)
    snapshot_sha256: Mapped[str] = mapped_column(String(64))
    report_version: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    __tablename__ = "satark_audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), index=True)
    actor_id: Mapped[str] = mapped_column(String(36))
    event_type: Mapped[str] = mapped_column(String(100))
    payload: Mapped[dict] = mapped_column(JSON)
    previous_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_session(db: Session, user: User) -> str:
    token = secrets.token_urlsafe(48)
    db.add(SessionRecord(user_id=user.id, token_hash=token_digest(token), expires_at=utcnow() + timedelta(days=SESSION_TTL_DAYS)))
    return token


def current_user(request: Request, authorization: str | None = Header(default=None), db: Session = Depends(db_session)) -> User:
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
    if not token:
        token = request.cookies.get("satark_session")
    if not token or len(token) > 256:
        raise HTTPException(401, "Sign in is required.")
    row = db.scalar(select(SessionRecord).where(SessionRecord.token_hash == token_digest(token), SessionRecord.revoked_at.is_(None)))
    if not row or row.expires_at <= utcnow():
        raise HTTPException(401, "Your session is invalid or expired.")
    user = db.get(User, row.user_id)
    if not user or not user.is_active:
        raise HTTPException(401, "Your account is disabled.")
    return user


def require_membership(db: Session, user: User, tenant_id: str, roles: set[str] | None = None) -> Membership:
    if not UUID_RE.fullmatch(tenant_id):
        raise HTTPException(400, "A valid tenant_id is required.")
    membership = db.scalar(select(Membership).where(Membership.tenant_id == tenant_id, Membership.user_id == user.id))
    if not membership or (roles and membership.role not in roles):
        raise HTTPException(403, "Workspace access denied.")
    return membership


def audit(db: Session, tenant_id: str, actor: str, event_type: str, payload: dict) -> None:
    previous = db.scalar(select(AuditEvent).where(AuditEvent.tenant_id == tenant_id).order_by(AuditEvent.created_at.desc()).limit(1))
    previous_hash = previous.event_hash if previous else "0" * 64
    record = {"tenant_id": tenant_id, "actor_id": actor, "event_type": event_type, "payload": payload, "previous_hash": previous_hash}
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    db.add(AuditEvent(tenant_id=tenant_id, actor_id=actor, event_type=event_type, payload=payload, previous_hash=previous_hash, event_hash=digest))


class Credentials(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=128)


class WorkspaceInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=160)


class CaseInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str
    title: str = Field(min_length=1, max_length=240)
    status: str = "open"
    severity: str = "unknown"
    metadata: dict = Field(default_factory=dict)


class NoteInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str
    case_id: str
    body: str = Field(min_length=1, max_length=4000)


class FindingInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str
    case_id: str
    finding_key: str = Field(min_length=1, max_length=160)
    title: str = Field(min_length=1, max_length=240)
    severity: str = "unknown"
    detail: str = Field(min_length=1, max_length=8192)
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)
    source: str = Field(default="FIRSTLIGHT deterministic rules", max_length=160)
    confidence: float | None = None


def user_json(user: User) -> dict:
    return {"id": user.id, "email": user.email}


def case_json(row: Case) -> dict:
    return {"id": row.id, "tenant_id": row.tenant_id, "title": row.title, "status": row.status, "severity": row.severity,
            "assigned_to": row.assigned_to, "created_by": row.created_by, "created_at": row.created_at.isoformat(),
            "updated_at": row.updated_at.isoformat(), "metadata": row.metadata_json}


@router.on_event("startup")
def initialize_self_hosted_backend():
    # create_all is a bootstrap for local mode only. Production schema changes
    # must be applied by reviewed Alembic migrations before deployment.
    if os.getenv("SATARK_AUTO_CREATE_SCHEMA", "false").lower() == "true":
        Base.metadata.create_all(engine)


@router.get("/health/storage")
def storage_health():
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("SELECT 1")
        return {"status": "ok", "database": "connected", "provider": "self-hosted"}
    except Exception:
        raise HTTPException(503, "Self-hosted database is unavailable.")


@router.post("/auth/signup", status_code=201)
def signup(body: Credentials, request: Request, db: Session = Depends(db_session)):
    email = body.email.strip().lower()
    if not EMAIL_RE.fullmatch(email):
        raise HTTPException(400, "Enter a valid email address.")
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "An account with this email already exists.")
    user = User(email=email, password_hash=PASSWORDS.hash(body.password))
    db.add(user)
    db.flush()
    token = issue_session(db, user)
    db.commit()
    response = {"user": user_json(user), "expires_in": SESSION_TTL_DAYS * 86400}
    return response_with_session(request, response, token)


def response_with_session(request: Request, body: dict, token: str):
    from fastapi.responses import JSONResponse
    response = JSONResponse(body)
    response.set_cookie("satark_session", token, httponly=True, secure=request.url.scheme == "https", samesite="lax",
                        max_age=SESSION_TTL_DAYS * 86400, path="/")
    return response


@router.post("/auth/login")
def login(body: Credentials, request: Request, db: Session = Depends(db_session)):
    email = body.email.strip().lower()
    user = db.scalar(select(User).where(User.email == email))
    valid = False
    if user and user.is_active:
        try:
            valid = PASSWORDS.verify(user.password_hash, body.password)
        except VerifyMismatchError:
            valid = False
    if not valid or not user:
        # Perform a dummy hash verification path for unknown accounts to reduce timing leaks.
        raise HTTPException(401, "Email or password is incorrect.")
    token = issue_session(db, user)
    db.commit()
    return response_with_session(request, {"user": user_json(user), "expires_in": SESSION_TTL_DAYS * 86400}, token)


@router.get("/auth/session")
def session_info(user: User = Depends(current_user)):
    return {"user": user_json(user)}


@router.post("/auth/logout")
def logout(request: Request, db: Session = Depends(db_session), user: User = Depends(current_user)):
    token = request.cookies.get("satark_session") or ""
    row = db.scalar(select(SessionRecord).where(SessionRecord.user_id == user.id, SessionRecord.token_hash == token_digest(token))) if token else None
    if row:
        row.revoked_at = utcnow()
        db.commit()
    from fastapi.responses import JSONResponse
    response = JSONResponse({"ok": True})
    response.delete_cookie("satark_session", path="/", httponly=True, secure=request.url.scheme == "https", samesite="lax")
    return response


@router.post("/workspaces", status_code=201)
def create_workspace(body: WorkspaceInput, user: User = Depends(current_user), db: Session = Depends(db_session)):
    tenant = Tenant(name=body.name.strip(), created_by=user.id)
    db.add(tenant)
    db.flush()
    db.add(Membership(tenant_id=tenant.id, user_id=user.id, role="owner"))
    audit(db, tenant.id, user.id, "workspace.created", {"workspace_id": tenant.id})
    db.commit()
    return {"id": tenant.id, "name": tenant.name, "role": "owner"}


@router.get("/workspaces")
def list_workspaces(user: User = Depends(current_user), db: Session = Depends(db_session)):
    rows = db.execute(select(Tenant, Membership.role).join(Membership, Membership.tenant_id == Tenant.id).where(Membership.user_id == user.id).order_by(Tenant.created_at.asc())).all()
    return {"workspaces": [{"id": tenant.id, "name": tenant.name, "role": role} for tenant, role in rows]}


@router.get("/cases")
def list_cases(tenant_id: str, user: User = Depends(current_user), db: Session = Depends(db_session)):
    require_membership(db, user, tenant_id)
    rows = db.scalars(select(Case).where(Case.tenant_id == tenant_id).order_by(Case.updated_at.desc()).limit(100)).all()
    return {"cases": [case_json(row) for row in rows]}


@router.post("/cases", status_code=201)
def create_case(body: CaseInput, user: User = Depends(current_user), db: Session = Depends(db_session)):
    require_membership(db, user, body.tenant_id, {"owner", "responder", "analyst"})
    if body.status not in {"open", "contained", "resolved", "archived"} or body.severity not in {"unknown", "low", "medium", "high", "critical"}:
        raise HTTPException(400, "Invalid case status or severity.")
    row = Case(tenant_id=body.tenant_id, title=body.title.strip(), status=body.status, severity=body.severity, created_by=user.id, metadata_json=body.metadata)
    db.add(row)
    db.flush()
    audit(db, body.tenant_id, user.id, "case.created", {"case_id": row.id})
    db.commit()
    return {"case": case_json(row)}


@router.get("/cases/notes")
def list_notes(tenant_id: str, case_id: str, user: User = Depends(current_user), db: Session = Depends(db_session)):
    require_membership(db, user, tenant_id)
    case = db.scalar(select(Case).where(Case.id == case_id, Case.tenant_id == tenant_id))
    if not case:
        raise HTTPException(404, "Case not found.")
    rows = db.scalars(select(CaseNote).where(CaseNote.tenant_id == tenant_id, CaseNote.case_id == case_id).order_by(CaseNote.created_at.asc()).limit(200)).all()
    return {"notes": [{"id": r.id, "tenant_id": r.tenant_id, "case_id": r.case_id, "body": r.body, "created_by": r.created_by, "created_at": r.created_at.isoformat()} for r in rows]}


@router.post("/cases/notes", status_code=201)
def create_note(body: NoteInput, user: User = Depends(current_user), db: Session = Depends(db_session)):
    require_membership(db, user, body.tenant_id, {"owner", "responder", "analyst"})
    if not db.scalar(select(Case.id).where(Case.id == body.case_id, Case.tenant_id == body.tenant_id)):
        raise HTTPException(404, "Case not found.")
    row = CaseNote(tenant_id=body.tenant_id, case_id=body.case_id, body=body.body.strip(), created_by=user.id)
    db.add(row)
    audit(db, body.tenant_id, user.id, "case.note.created", {"case_id": body.case_id, "note_id": row.id})
    db.commit()
    return {"note": {"id": row.id, "tenant_id": row.tenant_id, "case_id": row.case_id, "body": row.body, "created_by": row.created_by, "created_at": row.created_at.isoformat()}}


@router.get("/findings")
def list_findings(tenant_id: str, case_id: str, user: User = Depends(current_user), db: Session = Depends(db_session)):
    require_membership(db, user, tenant_id)
    rows = db.scalars(select(Finding).where(Finding.tenant_id == tenant_id, Finding.case_id == case_id).order_by(Finding.created_at.asc()).limit(500)).all()
    return {"findings": [{"id": r.id, "tenant_id": r.tenant_id, "case_id": r.case_id, "finding_key": r.finding_key, "title": r.title, "severity": r.severity, "detail": r.detail, "evidence_refs": r.evidence_refs, "source": r.source, "confidence": r.confidence, "created_by": r.created_by, "created_at": r.created_at.isoformat()} for r in rows]}


@router.post("/findings", status_code=201)
def create_finding(body: FindingInput, user: User = Depends(current_user), db: Session = Depends(db_session)):
    require_membership(db, user, body.tenant_id, {"owner", "responder", "analyst"})
    if not db.scalar(select(Case.id).where(Case.id == body.case_id, Case.tenant_id == body.tenant_id)):
        raise HTTPException(404, "Case not found.")
    if body.confidence is not None and not 0 <= body.confidence <= 1:
        raise HTTPException(400, "confidence must be between 0 and 1.")
    row = Finding(tenant_id=body.tenant_id, case_id=body.case_id, finding_key=body.finding_key, title=body.title, severity=body.severity, detail=body.detail, evidence_refs=body.evidence_refs, source=body.source, confidence=body.confidence, created_by=user.id)
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "This finding already exists for this case.")
    return {"finding": {"id": row.id, "tenant_id": row.tenant_id, "case_id": row.case_id, "finding_key": row.finding_key, "title": row.title, "severity": row.severity, "detail": row.detail, "evidence_refs": row.evidence_refs, "source": row.source, "confidence": row.confidence, "created_by": row.created_by, "created_at": row.created_at.isoformat()}}


@router.get("/reports")
def list_reports(tenant_id: str, case_id: str, user: User = Depends(current_user), db: Session = Depends(db_session)):
    require_membership(db, user, tenant_id)
    rows = db.scalars(select(Report).where(Report.tenant_id == tenant_id, Report.case_id == case_id).order_by(Report.created_at.desc()).limit(100)).all()
    return {"reports": [{"id": r.id, "tenant_id": r.tenant_id, "case_id": r.case_id, "title": r.title, "report_version": r.report_version, "snapshot_sha256": r.snapshot_sha256, "created_by": r.created_by, "created_at": r.created_at.isoformat()} for r in rows]}


@router.post("/reports", status_code=201)
def create_report(body: dict, user: User = Depends(current_user), db: Session = Depends(db_session)):
    tenant_id, case_id = body.get("tenant_id"), body.get("case_id")
    require_membership(db, user, str(tenant_id), {"owner", "responder", "analyst"})
    case = db.scalar(select(Case).where(Case.id == case_id, Case.tenant_id == tenant_id))
    if not case:
        raise HTTPException(404, "Case not found.")
    snapshot = body.get("snapshot")
    if not isinstance(snapshot, dict) or len(json.dumps(snapshot).encode()) > 256 * 1024:
        raise HTTPException(400, "A bounded report snapshot is required.")
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    row = Report(tenant_id=tenant_id, case_id=case_id, title=str(body.get("title") or "Investigation report")[:240], snapshot=snapshot, snapshot_sha256=digest, created_by=user.id)
    db.add(row)
    audit(db, tenant_id, user.id, "report.created", {"report_id": row.id, "case_id": case_id, "sha256": digest})
    db.commit()
    return {"report": {"id": row.id, "tenant_id": tenant_id, "case_id": case_id, "title": row.title, "report_version": row.report_version, "snapshot_sha256": digest, "created_by": user.id, "created_at": row.created_at.isoformat()}}


@router.post("/evidence", status_code=201)
async def upload_evidence(
    tenant_id: str = Form(...), case_id: str = Form(...), source_label: str = Form("Uploaded evidence"),
    event_kind: str = Form("file"), observed_at: str = Form(...), summary: str = Form("Evidence file uploaded."),
    file: UploadFile = File(...), user: User = Depends(current_user), db: Session = Depends(db_session),
):
    require_membership(db, user, tenant_id, {"owner", "responder", "analyst"})
    if not db.scalar(select(Case.id).where(Case.id == case_id, Case.tenant_id == tenant_id)):
        raise HTTPException(404, "Case not found.")
    raw = await file.read(MAX_UPLOAD + 1)
    if not raw or len(raw) > MAX_UPLOAD:
        raise HTTPException(413, "Evidence must be between 1 byte and 4 MiB.")
    content_type = (file.content_type or "application/octet-stream")[:160]
    # Minimal magic checks prevent trusting the browser-supplied MIME type.
    signatures = {
        "application/pdf": raw.startswith(b"%PDF-"),
        "image/png": raw.startswith(b"\x89PNG\r\n\x1a\n"),
        "image/jpeg": raw.startswith(b"\xff\xd8\xff"),
        "application/zip": raw.startswith(b"PK\x03\x04"),
        "text/plain": b"\x00" not in raw[:8192],
        "application/json": b"\x00" not in raw[:8192],
    }
    if content_type in signatures and not signatures[content_type]:
        raise HTTPException(415, "File content does not match its declared type.")
    digest = hashlib.sha256(raw).hexdigest()
    evidence_id = str(uuid.uuid4())
    root = Path(os.getenv("SATARK_EVIDENCE_DIR", "./data/evidence")).resolve()
    object_dir = root / tenant_id / case_id
    object_dir.mkdir(parents=True, exist_ok=True)
    object_path = object_dir / evidence_id
    temporary = object_dir / (evidence_id + ".part")
    try:
        with temporary.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, object_path)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise HTTPException(503, "Private evidence storage is unavailable.")
    name = re.sub(r"[^A-Za-z0-9._-]", "_", (file.filename or "evidence.bin"))[-100:]
    try:
        when = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
        if when.tzinfo is None:
            raise ValueError()
    except ValueError:
        object_path.unlink(missing_ok=True)
        raise HTTPException(400, "observed_at must include an explicit timezone.")
    row = Evidence(id=evidence_id, tenant_id=tenant_id, case_id=case_id, object_key=str(object_path), source_label=source_label[:160], event_kind=event_kind[:100], observed_at=when, summary=summary[:8192], source_sha256=digest, size_bytes=len(raw), content_type=content_type, original_filename=name, created_by=user.id)
    db.add(row)
    audit(db, tenant_id, user.id, "evidence.uploaded", {"evidence_id": evidence_id, "sha256": digest, "size_bytes": len(raw)})
    try:
        db.commit()
    except Exception:
        db.rollback()
        object_path.unlink(missing_ok=True)
        raise
    return {"evidence": {"id": row.id, "tenant_id": tenant_id, "case_id": case_id, "source_label": row.source_label, "event_kind": row.event_kind, "observed_at": row.observed_at.isoformat(), "summary": row.summary, "source_sha256": digest, "size_bytes": row.size_bytes, "content_type": row.content_type, "original_filename": name, "created_by": user.id, "created_at": row.created_at.isoformat()}}


@router.get("/evidence")
def list_evidence(tenant_id: str, case_id: str, user: User = Depends(current_user), db: Session = Depends(db_session)):
    require_membership(db, user, tenant_id)
    rows = db.scalars(select(Evidence).where(Evidence.tenant_id == tenant_id, Evidence.case_id == case_id).order_by(Evidence.observed_at.asc()).limit(500)).all()
    return {"evidence": [{"id": r.id, "tenant_id": r.tenant_id, "case_id": r.case_id, "source_label": r.source_label, "event_kind": r.event_kind, "observed_at": r.observed_at.isoformat(), "summary": r.summary, "source_sha256": r.source_sha256, "size_bytes": r.size_bytes, "content_type": r.content_type, "original_filename": r.original_filename, "created_by": r.created_by, "created_at": r.created_at.isoformat()} for r in rows]}


@router.get("/evidence/{evidence_id}/download")
def download_evidence(evidence_id: str, tenant_id: str, user: User = Depends(current_user), db: Session = Depends(db_session)):
    row = db.get(Evidence, evidence_id)
    if not row or row.tenant_id != tenant_id:
        raise HTTPException(404, "Evidence not found.")
    require_membership(db, user, tenant_id)
    path = Path(row.object_key).resolve()
    root = Path(os.getenv("SATARK_EVIDENCE_DIR", "./data/evidence")).resolve()
    if root not in path.parents or not path.is_file():
        raise HTTPException(404, "Evidence object not found.")
    if hashlib.sha256(path.read_bytes()).hexdigest() != row.source_sha256:
        raise HTTPException(409, "Evidence integrity verification failed.")
    return FileResponse(path, media_type=row.content_type, filename=row.original_filename, headers={"Cache-Control": "no-store"})
