"""Self-hosted SATARK application backend.

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
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, create_engine, select, update
from sqlalchemy.exc import IntegrityError
from firstlight_wazuh import fetch_configured_alerts, WazuhConfigurationError, WazuhConnectorError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
from sqlalchemy import event

router = APIRouter(prefix="/api", tags=["SATARK self-hosted"])
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PASSWORDS = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)
SESSION_TTL_DAYS = 14
DUMMY_PASSWORD_HASH = PASSWORDS.hash("not-a-real-user-password-for-timing-equalization")
MAX_UPLOAD = 4 * 1024 * 1024


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def database_url() -> str:
    value = os.getenv("SATARK_DATABASE_URL", "").strip()
    if value:
        if value.startswith("postgresql://"):
            return value.replace("postgresql://", "postgresql+psycopg://", 1)
        return value
    path = Path(os.getenv("SATARK_SQLITE_PATH", "/tmp/satark/satark.db"))
    path.parent.mkdir(parents=True, exist_ok=True)
    return "sqlite:///" + str(path.resolve())


DB_URL = database_url()
engine = create_engine(DB_URL, pool_pre_ping=True, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)

if DB_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=10000")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()


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
    __table_args__ = (UniqueConstraint("tenant_id", "case_id", "source_sha256", name="uq_satark_evidence_digest"),)
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
    metadata_json: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
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




class Approval(Base):
    __tablename__ = "satark_approvals"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), index=True)
    case_id: Mapped[str] = mapped_column(String(36), index=True)
    action_key: Mapped[str] = mapped_column(String(120))
    action_payload: Mapped[dict] = mapped_column(JSON)
    payload_sha256: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    requested_by: Mapped[str] = mapped_column(String(36))
    decided_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IngestionCheckpoint(Base):
    __tablename__ = "satark_ingestion_checkpoints"
    __table_args__ = (UniqueConstraint("tenant_id", "case_id", "source_key", name="uq_satark_ingestion_checkpoint"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), index=True)
    case_id: Mapped[str] = mapped_column(String(36), index=True)
    source_key: Mapped[str] = mapped_column(String(256))
    last_event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_batch_count: Mapped[int] = mapped_column(Integer, default=0)
    last_status: Mapped[str] = mapped_column(String(16), default="ok")
    last_error: Mapped[str | None] = mapped_column(String(80), nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class InvestigationJob(Base):
    __tablename__ = "satark_investigation_jobs"
    __table_args__ = (UniqueConstraint("tenant_id", "case_id", "idempotency_key", name="uq_satark_job_idempotency"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), index=True)
    case_id: Mapped[str] = mapped_column(String(36), index=True)
    requested_by: Mapped[str] = mapped_column(String(36))
    idempotency_key: Mapped[str | None] = mapped_column(String(160), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="queued")
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    result_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()



def enforce_same_origin(request: Request) -> None:
    from urllib.parse import urlsplit
    origin = request.headers.get("origin", "")
    host = request.headers.get("host", "").lower()
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme).split(",")[0].strip().lower()
    try:
        parsed = urlsplit(origin)
        if not origin or parsed.netloc.lower() != host or parsed.scheme.lower() != scheme:
            raise HTTPException(403, "Cross-origin authentication requests are not allowed.")
    except ValueError:
        raise HTTPException(403, "Cross-origin authentication requests are not allowed.")

def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_session(db: Session, user: User) -> str:
    token = secrets.token_urlsafe(48)
    db.add(SessionRecord(user_id=user.id, token_hash=token_digest(token), expires_at=utcnow() + timedelta(days=SESSION_TTL_DAYS)))
    return token


def current_user(request: Request, authorization: str | None = Header(default=None), db: Session = Depends(db_session)) -> User:
    bearer_token = authorization[7:].strip() if authorization and authorization.startswith("Bearer ") else ""
    # An empty Authorization header is not bearer authentication. Treat it as
    # cookie authentication so the normal CSRF origin check still applies.
    token = bearer_token or request.cookies.get("satark_session")
    if not token or len(token) > 256:
        raise HTTPException(401, "Sign in is required.")
    row = db.scalar(select(SessionRecord).where(SessionRecord.token_hash == token_digest(token), SessionRecord.revoked_at.is_(None)))
    expiry = row.expires_at.replace(tzinfo=timezone.utc) if row and row.expires_at.tzinfo is None else (row.expires_at if row else None)
    if not row or expiry <= utcnow():
        raise HTTPException(401, "Your session is invalid or expired.")
    # Cookie-authenticated unsafe requests must originate from this exact origin.
    # Bearer clients are not ambient-cookie authenticated and do not use this CSRF path.
    if not bearer_token and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        # Validate both origin host and scheme. Behind the Next.js BFF, the
        # forwarded scheme is set by the trusted same-origin proxy.
        enforce_same_origin(request)
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
    # Serialize audit-head reads/writes per tenant on PostgreSQL to prevent forked chains.
    db.scalar(select(Tenant).where(Tenant.id == tenant_id).with_for_update())
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


@router.get("/health")
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
    enforce_same_origin(request)
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
    return response_with_session(request, response, token, status_code=201)


def response_with_session(request: Request, body: dict, token: str, status_code: int = 200):
    from fastapi.responses import JSONResponse
    response = JSONResponse(body, status_code=status_code)
    response.set_cookie("satark_session", token, httponly=True, secure=request.headers.get("x-forwarded-proto", request.url.scheme).split(",")[0].strip() == "https", samesite="lax",
                        max_age=SESSION_TTL_DAYS * 86400, path="/")
    return response


@router.post("/auth/login")
def login(body: Credentials, request: Request, db: Session = Depends(db_session)):
    enforce_same_origin(request)
    email = body.email.strip().lower()
    user = db.scalar(select(User).where(User.email == email))
    valid = False
    try:
        valid = PASSWORDS.verify(user.password_hash if user and user.is_active else DUMMY_PASSWORD_HASH, body.password)
    except VerifyMismatchError:
        valid = False
    if not valid or not user or not user.is_active:
        # Perform a dummy hash verification path for unknown accounts to reduce timing leaks.
        raise HTTPException(401, "Email or password is incorrect.")
    token = issue_session(db, user)
    db.commit()
    return response_with_session(request, {"user": user_json(user), "expires_in": SESSION_TTL_DAYS * 86400}, token)


@router.get("/auth/session")
def session_info(request: Request, user: User = Depends(current_user), db: Session = Depends(db_session)):
    token = request.cookies.get("satark_session") or ""
    row = db.scalar(select(SessionRecord).where(
        SessionRecord.user_id == user.id,
        SessionRecord.token_hash == token_digest(token),
        SessionRecord.revoked_at.is_(None),
    )) if token else None
    if not row:
        raise HTTPException(401, "A cookie-backed SATARK session is required.")
    expiry = row.expires_at.replace(tzinfo=timezone.utc) if row.expires_at.tzinfo is None else row.expires_at
    return {"user": user_json(user), "expires_at": expiry.isoformat(),
            "expires_in": max(0, int((expiry - utcnow()).total_seconds()))}


@router.post("/auth/refresh")
def refresh_session(request: Request, db: Session = Depends(db_session), user: User = Depends(current_user)):
    enforce_same_origin(request)
    token = request.cookies.get("satark_session") or ""
    if not token:
        raise HTTPException(401, "A cookie-backed SATARK session is required.")
    now = utcnow()
    # Atomic one-time rotation: a concurrent replay cannot mint a second session.
    changed = db.execute(
        update(SessionRecord)
        .where(
            SessionRecord.user_id == user.id,
            SessionRecord.token_hash == token_digest(token),
            SessionRecord.revoked_at.is_(None),
            SessionRecord.expires_at > now,
        )
        .values(revoked_at=now)
    )
    if changed.rowcount != 1:
        db.rollback()
        raise HTTPException(409, "Session is expired, revoked, or has already been rotated.")
    next_token = issue_session(db, user)
    db.commit()
    return response_with_session(request, {
        "user": user_json(user), "expires_in": SESSION_TTL_DAYS * 86400,
    }, next_token)


@router.post("/auth/logout")
def logout(request: Request, db: Session = Depends(db_session), user: User = Depends(current_user)):
    token = request.cookies.get("satark_session") or ""
    row = db.scalar(select(SessionRecord).where(SessionRecord.user_id == user.id, SessionRecord.token_hash == token_digest(token))) if token else None
    if row:
        row.revoked_at = utcnow()
        db.commit()
    from fastapi.responses import JSONResponse
    response = JSONResponse({"ok": True})
    response.delete_cookie("satark_session", path="/", httponly=True, secure=request.headers.get("x-forwarded-proto", request.url.scheme).split(",")[0].strip() == "https", samesite="lax")
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


@router.get("/workspaces/members")
def list_workspace_members(tenant_id: str, user: User = Depends(current_user), db: Session = Depends(db_session)):
    require_membership(db, user, tenant_id)
    rows = db.execute(
        select(User.id, User.email, Membership.role)
        .join(Membership, Membership.user_id == User.id)
        .where(Membership.tenant_id == tenant_id)
        .order_by(User.email.asc())
        .limit(500)
    ).all()
    return {"members": [{"user_id": user_id, "email": email, "role": role} for user_id, email, role in rows]}


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


@router.patch("/cases")
def update_case(body: dict, user: User = Depends(current_user), db: Session = Depends(db_session)):
    tenant_id, case_id = body.get("tenant_id"), body.get("case_id") or body.get("id")
    require_membership(db, user, str(tenant_id), {"owner", "responder"})
    row = db.scalar(select(Case).where(Case.id == case_id, Case.tenant_id == tenant_id))
    if not row:
        raise HTTPException(404, "Case not found.")
    allowed = {"title", "status", "severity", "assigned_to", "metadata"}
    if not any(key in body for key in allowed):
        raise HTTPException(400, "At least one case field must be provided for update.")
    if "title" in body:
        if not isinstance(body["title"], str) or not body["title"].strip() or len(body["title"]) > 240:
            raise HTTPException(400, "Case title is invalid.")
        row.title = body["title"].strip()
    if "status" in body:
        if body["status"] not in {"open", "contained", "resolved", "archived"}:
            raise HTTPException(400, "Invalid case status.")
        row.status = body["status"]
    if "severity" in body:
        if body["severity"] not in {"unknown", "info", "low", "medium", "high", "critical"}:
            raise HTTPException(400, "Invalid case severity.")
        row.severity = body["severity"]
    if "assigned_to" in body:
        assignee = body["assigned_to"]
        if assignee is not None:
            membership = db.scalar(select(Membership).where(Membership.tenant_id == tenant_id, Membership.user_id == assignee))
            if not membership or membership.role not in {"owner", "responder", "analyst"}:
                raise HTTPException(400, "The assignee must be an active workspace member.")
        row.assigned_to = assignee
    if "metadata" in body:
        if not isinstance(body["metadata"], dict) or len(json.dumps(body["metadata"]).encode()) > 16 * 1024:
            raise HTTPException(400, "Case metadata is invalid or oversized.")
        row.metadata_json = body["metadata"]
    row.updated_at = utcnow()
    audit(db, tenant_id, user.id, "case.updated", {"case_id": row.id, "fields": sorted(key for key in allowed if key in body)})
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
    db.flush()
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
    db.flush()
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
    when = when.astimezone(timezone.utc)
    row = Evidence(id=evidence_id, tenant_id=tenant_id, case_id=case_id, object_key=str(object_path), source_label=source_label[:160], event_kind=event_kind[:100], observed_at=when, summary=summary[:8192], source_sha256=digest, size_bytes=len(raw), content_type=content_type, original_filename=name, metadata_json={}, created_by=user.id)
    db.add(row)
    audit(db, tenant_id, user.id, "evidence.uploaded", {"evidence_id": evidence_id, "sha256": digest, "size_bytes": len(raw)})
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        object_path.unlink(missing_ok=True)
        raise HTTPException(409, "Identical evidence already exists in this case.")
    except Exception:
        db.rollback()
        object_path.unlink(missing_ok=True)
        raise
    return {"evidence": {"id": row.id, "tenant_id": tenant_id, "case_id": case_id, "source_label": row.source_label, "event_kind": row.event_kind, "observed_at": row.observed_at.isoformat(), "summary": row.summary, "source_sha256": digest, "size_bytes": row.size_bytes, "content_type": row.content_type, "original_filename": name, "created_by": user.id, "created_at": row.created_at.isoformat()}}


@router.post("/evidence/records", status_code=201)
def create_evidence_record(body: dict, user: User = Depends(current_user), db: Session = Depends(db_session)):
    tenant_id, case_id = body.get("tenant_id"), body.get("case_id")
    require_membership(db, user, str(tenant_id), {"owner", "responder", "analyst"})
    if not isinstance(case_id, str) or not db.scalar(select(Case.id).where(Case.id == case_id, Case.tenant_id == tenant_id)):
        raise HTTPException(404, "Case not found.")
    source = str(body.get("source_label") or "Imported event").strip()
    kind = str(body.get("event_kind") or "observation").strip()
    summary = str(body.get("summary") or "").strip()
    if not source or len(source) > 160 or not kind or len(kind) > 100 or not summary or len(summary) > 8192:
        raise HTTPException(400, "Evidence metadata is invalid or oversized.")
    try:
        observed = datetime.fromisoformat(str(body.get("observed_at", "")).replace("Z", "+00:00"))
        if observed.tzinfo is None:
            raise ValueError()
    except ValueError:
        raise HTTPException(400, "observed_at must include an explicit timezone.")
    observed = observed.astimezone(timezone.utc)
    metadata = body.get("metadata") if isinstance(body.get("metadata"), dict) else {}
    raw = json.dumps(metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(raw) > MAX_UPLOAD:
        raise HTTPException(413, "Evidence metadata exceeds 4 MiB.")
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
    digest = hashlib.sha256(raw).hexdigest()
    row = Evidence(id=evidence_id, tenant_id=tenant_id, case_id=case_id, object_key=str(object_path),
        source_label=source, event_kind=kind, observed_at=observed, summary=summary,
        source_sha256=digest, size_bytes=len(raw), content_type="application/json",
        original_filename="evidence.json", metadata_json=metadata, created_by=user.id)
    db.add(row)
    db.flush()
    audit(db, tenant_id, user.id, "evidence.record.imported", {"evidence_id": evidence_id, "sha256": digest})
    try:
        db.commit()
    except Exception:
        db.rollback()
        object_path.unlink(missing_ok=True)
        raise
    return {"evidence": {"id": row.id, "tenant_id": tenant_id, "case_id": case_id,
        "source_label": source, "event_kind": kind, "observed_at": observed.isoformat(),
        "summary": summary, "source_sha256": digest, "created_by": user.id,
        "metadata": metadata, "created_at": row.created_at.isoformat()}}


@router.get("/firstlight/evidence/source")
def download_wazuh_source(tenant_id: str, case_id: str, path: str, user: User = Depends(current_user), db: Session = Depends(db_session)):
    require_membership(db, user, tenant_id)
    expected = re.fullmatch(rf"{re.escape(tenant_id)}/{re.escape(case_id)}/wazuh/([0-9a-f]{{64}})\.json", path)
    if not expected:
        raise HTTPException(400, "The source-object path is invalid for this case.")
    row = db.scalar(select(Evidence).where(Evidence.tenant_id == tenant_id,
        Evidence.case_id == case_id, Evidence.source_sha256 == expected.group(1),
        Evidence.content_type == "application/json"))
    if not row:
        raise HTTPException(404, "The preserved source object was not found.")
    object_path = Path(row.object_key).resolve()
    root = Path(os.getenv("SATARK_EVIDENCE_DIR", "./data/evidence")).resolve()
    if root not in object_path.parents or not object_path.is_file():
        raise HTTPException(404, "The source object was not found.")
    raw = object_path.read_bytes()
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), row.source_sha256):
        raise HTTPException(409, "Source-object integrity verification failed.")
    return Response(content=raw, media_type="application/json",
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


@router.get("/evidence")
def list_evidence(tenant_id: str, case_id: str, user: User = Depends(current_user), db: Session = Depends(db_session)):
    require_membership(db, user, tenant_id)
    rows = db.scalars(select(Evidence).where(Evidence.tenant_id == tenant_id, Evidence.case_id == case_id).order_by(Evidence.observed_at.asc()).limit(500)).all()
    return {"evidence": [{"id": r.id, "tenant_id": r.tenant_id, "case_id": r.case_id, "source_label": r.source_label, "event_kind": r.event_kind, "observed_at": r.observed_at.isoformat(), "summary": r.summary, "source_sha256": r.source_sha256, "size_bytes": r.size_bytes, "content_type": r.content_type, "original_filename": r.original_filename, "metadata": r.metadata_json, "created_by": r.created_by, "created_at": r.created_at.isoformat()} for r in rows]}


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



@router.get("/audit/events")
def list_audit_events(tenant_id: str, case_id: str, user: User = Depends(current_user), db: Session = Depends(db_session)):
    require_membership(db, user, tenant_id)
    if not db.scalar(select(Case.id).where(Case.id == case_id, Case.tenant_id == tenant_id)):
        raise HTTPException(404, "Case not found.")
    rows = db.scalars(select(AuditEvent).where(AuditEvent.tenant_id == tenant_id)
        .order_by(AuditEvent.created_at.asc()).limit(1000)).all()
    events = [{"id": row.id, "action": row.event_type, "details": row.payload,
        "actor_id": row.actor_id, "created_at": row.created_at.isoformat(),
        "event_hash": row.event_hash} for row in rows if row.payload.get("case_id") == case_id]
    return {"events": events[-500:]}


@router.get("/audit/verify")
def verify_audit_chain(tenant_id: str, user: User = Depends(current_user), db: Session = Depends(db_session)):
    require_membership(db, user, tenant_id)
    rows = db.scalars(select(AuditEvent).where(AuditEvent.tenant_id == tenant_id).order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())).all()
    previous = "0" * 64
    for row in rows:
        record = {"tenant_id": row.tenant_id, "actor_id": row.actor_id, "event_type": row.event_type,
                  "payload": row.payload, "previous_hash": row.previous_hash}
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        actual = hashlib.sha256(canonical.encode()).hexdigest()
        if row.previous_hash != previous or not hmac.compare_digest(actual, row.event_hash):
            return {"tenant_id": tenant_id, "chain_valid": False, "events_checked": len(rows),
                    "failed_event_id": row.id, "failure": "hash_or_link_mismatch"}
        previous = row.event_hash
    return {"tenant_id": tenant_id, "chain_valid": True, "events_checked": len(rows),
            "head_sha256": previous, "verified_at": utcnow().isoformat()}


@router.get("/evidence/records")
def list_evidence_records(tenant_id: str, case_id: str, user: User = Depends(current_user), db: Session = Depends(db_session)):
    return list_evidence(tenant_id, case_id, user, db)


@router.get("/evidence/{evidence_id}/verify")
def verify_evidence(evidence_id: str, tenant_id: str, user: User = Depends(current_user), db: Session = Depends(db_session)):
    row = db.get(Evidence, evidence_id)
    if not row or row.tenant_id != tenant_id:
        raise HTTPException(404, "Evidence not found.")
    require_membership(db, user, tenant_id)
    path = Path(row.object_key).resolve()
    root = Path(os.getenv("SATARK_EVIDENCE_DIR", "./data/evidence")).resolve()
    if root not in path.parents or not path.is_file():
        raise HTTPException(404, "Evidence object not found.")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    matched = hmac.compare_digest(actual, row.source_sha256)
    return {"evidence_id": row.id, "algorithm": "SHA-256", "expected_sha256": row.source_sha256,
            "actual_sha256": actual, "matched": matched, "verified_at": utcnow().isoformat(),
            "note": "Digest match verifies stored bytes against the upload record; it does not prove original source authenticity."}


@router.get("/reports/{report_id}")
def get_report(report_id: str, tenant_id: str, user: User = Depends(current_user), db: Session = Depends(db_session)):
    row = db.get(Report, report_id)
    if not row or row.tenant_id != tenant_id:
        raise HTTPException(404, "Report not found.")
    require_membership(db, user, tenant_id)
    canonical = json.dumps(row.snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    actual = hashlib.sha256(canonical.encode()).hexdigest()
    matched = hmac.compare_digest(actual, row.snapshot_sha256)
    payload = {"id": row.id, "tenant_id": row.tenant_id, "case_id": row.case_id, "title": row.title,
               "report_version": row.report_version, "snapshot": row.snapshot, "snapshot_sha256": row.snapshot_sha256,
               "created_by": row.created_by, "created_at": row.created_at.isoformat()}
    from fastapi.responses import JSONResponse
    return JSONResponse({"report": payload, "integrity": {"algorithm": "SHA-256", "expected_sha256": row.snapshot_sha256,
            "actual_sha256": actual, "matched": matched}}, status_code=200 if matched else 409)


@router.get("/firstlight/approvals")
def list_approvals(tenant_id: str, case_id: str, user: User = Depends(current_user), db: Session = Depends(db_session)):
    require_membership(db, user, tenant_id)
    rows = db.scalars(select(Approval).where(Approval.tenant_id == tenant_id, Approval.case_id == case_id).order_by(Approval.created_at.desc()).limit(100)).all()
    return {"approvals": [{"id": r.id, "tenant_id": r.tenant_id, "case_id": r.case_id, "action_key": r.action_key,
        "action_payload": r.action_payload, "payload_sha256": r.payload_sha256, "status": r.status,
        "requested_by": r.requested_by, "decided_by": r.decided_by, "decision_reason": r.decision_reason,
        "decided_at": r.decided_at.isoformat() if r.decided_at else None, "expires_at": r.expires_at.isoformat(),
        "consumed_at": r.consumed_at.isoformat() if r.consumed_at else None, "created_at": r.created_at.isoformat()} for r in rows]}


@router.post("/firstlight/approvals", status_code=201)
def request_approval(body: dict, user: User = Depends(current_user), db: Session = Depends(db_session)):
    tenant_id, case_id = body.get("tenant_id"), body.get("case_id")
    action_key, payload = body.get("action_key"), body.get("action_payload")
    require_membership(db, user, str(tenant_id), {"owner", "responder", "analyst"})
    if not isinstance(case_id, str) or not db.scalar(select(Case.id).where(Case.id == case_id, Case.tenant_id == tenant_id)):
        raise HTTPException(404, "Case not found.")
    if not isinstance(action_key, str) or not re.fullmatch(r"simulation\.[a-z0-9][a-z0-9._-]{0,110}", action_key):
        raise HTTPException(400, "Only named simulation actions can be approved.")
    if not isinstance(payload, dict) or payload.get("mode") != "simulation":
        raise HTTPException(400, "Response approvals are simulation-only.")
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    if len(encoded.encode()) > 16 * 1024:
        raise HTTPException(413, "Action payload exceeds 16 KiB.")
    digest = hashlib.sha256(encoded.encode()).hexdigest()
    row = Approval(tenant_id=tenant_id, case_id=case_id, action_key=action_key, action_payload=payload,
                   payload_sha256=digest, requested_by=user.id, expires_at=utcnow() + timedelta(hours=24))
    db.add(row)
    db.flush()
    audit(db, tenant_id, user.id, "approval.requested", {"approval_id": row.id, "case_id": case_id, "payload_sha256": digest})
    db.commit()
    return {"approval": {"id": row.id, "tenant_id": tenant_id, "case_id": case_id, "action_key": action_key,
        "action_payload": payload, "payload_sha256": digest, "status": row.status, "requested_by": user.id,
        "expires_at": row.expires_at.isoformat(), "created_at": row.created_at.isoformat()}}


@router.patch("/firstlight/approvals")
def decide_approval(body: dict, user: User = Depends(current_user), db: Session = Depends(db_session)):
    approval_id = body.get("approval_id")
    decision, reason = body.get("decision"), body.get("reason")
    if not isinstance(approval_id, str) or not UUID_RE.fullmatch(approval_id) or decision not in {"approved", "rejected"}:
        raise HTTPException(400, "A valid approval_id and approved/rejected decision are required.")
    row = db.get(Approval, approval_id)
    if not row:
        raise HTTPException(404, "Approval not found.")
    require_membership(db, user, row.tenant_id, {"owner", "responder"})
    if row.requested_by == user.id:
        raise HTTPException(403, "An approval requester cannot approve their own request.")
    expiry = row.expires_at.replace(tzinfo=timezone.utc) if row.expires_at.tzinfo is None else row.expires_at
    if row.status != "pending" or row.consumed_at is not None or expiry <= utcnow():
        raise HTTPException(409, "Approval is expired, already decided, or already consumed.")
    row.status = decision
    row.decided_by = user.id
    row.decision_reason = str(reason or "")[:1000] or None
    row.decided_at = utcnow()
    audit(db, row.tenant_id, user.id, "approval.decided", {"approval_id": row.id, "decision": decision})
    db.commit()
    return {"approval": {"id": row.id, "status": row.status, "decided_by": row.decided_by,
        "decision_reason": row.decision_reason, "decided_at": row.decided_at.isoformat()}}


@router.get("/firstlight/jobs")
def list_investigation_jobs(tenant_id: str, case_id: str | None = None, job_id: str | None = None,
                            user: User = Depends(current_user), db: Session = Depends(db_session)):
    require_membership(db, user, tenant_id)
    query = select(InvestigationJob).where(InvestigationJob.tenant_id == tenant_id)
    if job_id:
        if not UUID_RE.fullmatch(job_id):
            raise HTTPException(400, "A valid job_id is required.")
        query = query.where(InvestigationJob.id == job_id)
    elif case_id:
        if not UUID_RE.fullmatch(case_id):
            raise HTTPException(400, "A valid case_id is required.")
        query = query.where(InvestigationJob.case_id == case_id)
    else:
        raise HTTPException(400, "A case_id or job_id is required.")
    rows = db.scalars(query.order_by(InvestigationJob.created_at.desc()).limit(100)).all()
    values = [{"id": r.id, "tenant_id": r.tenant_id, "case_id": r.case_id, "status": r.status,
        "requested_by": r.requested_by, "idempotency_key": r.idempotency_key, "result": r.result,
        "result_sha256": r.result_sha256, "error_code": r.error_code, "attempts": r.attempts,
        "max_attempts": r.max_attempts, "created_at": r.created_at.isoformat(),
        "updated_at": r.updated_at.isoformat()} for r in rows]
    if job_id:
        if not values:
            raise HTTPException(404, "Investigation job not found.")
        return {"job": values[0]}
    return {"jobs": values}


@router.post("/firstlight/jobs", status_code=202)
def enqueue_investigation(body: dict, user: User = Depends(current_user), db: Session = Depends(db_session)):
    tenant_id, case_id = body.get("tenant_id"), body.get("case_id")
    require_membership(db, user, str(tenant_id), {"owner", "responder", "analyst"})
    if not isinstance(case_id, str) or not db.scalar(select(Case.id).where(Case.id == case_id, Case.tenant_id == tenant_id)):
        raise HTTPException(404, "Case not found.")
    idempotency_key = body.get("idempotency_key")
    if not isinstance(idempotency_key, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{8,160}", idempotency_key):
        raise HTTPException(400, "A stable 8–160 character idempotency_key is required.")
    existing = db.scalar(select(InvestigationJob).where(InvestigationJob.tenant_id == tenant_id, InvestigationJob.case_id == case_id, InvestigationJob.idempotency_key == idempotency_key))
    if existing:
        return {"job": {"id": existing.id, "tenant_id": existing.tenant_id, "case_id": existing.case_id, "status": existing.status, "requested_by": existing.requested_by, "created_at": existing.created_at.isoformat()}}
    row = InvestigationJob(tenant_id=tenant_id, case_id=case_id, requested_by=user.id, idempotency_key=idempotency_key)
    db.add(row)
    try:
        db.flush()
        audit(db, tenant_id, user.id, "investigation.queued", {"job_id": row.id, "case_id": case_id})
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.scalar(select(InvestigationJob).where(InvestigationJob.tenant_id == tenant_id,
            InvestigationJob.case_id == case_id, InvestigationJob.idempotency_key == idempotency_key))
        if not existing:
            raise HTTPException(503, "The investigation queue could not safely resolve a duplicate request.")
        row = existing
    return {"job": {"id": row.id, "tenant_id": tenant_id, "case_id": case_id, "status": row.status,
        "requested_by": row.requested_by, "created_at": row.created_at.isoformat()}}


@router.post("/firstlight/investigate")
def investigate_persisted_case(body: dict, user: User = Depends(current_user), db: Session = Depends(db_session)):
    tenant_id, case_id = body.get("tenant_id"), body.get("case_id")
    require_membership(db, user, str(tenant_id), {"owner", "responder", "analyst"})
    case = db.scalar(select(Case).where(Case.id == case_id, Case.tenant_id == tenant_id))
    if not case:
        raise HTTPException(404, "Case not found.")
    rows = db.scalars(select(Evidence).where(Evidence.tenant_id == tenant_id, Evidence.case_id == case_id).order_by(Evidence.observed_at.asc()).limit(501)).all()
    if len(rows) > 500:
        raise HTTPException(413, "Case evidence exceeds the 500-record investigation limit.")
    from firstlight_engine import investigate_case, sha256_record
    envelopes = []
    integrity = []
    for row in rows:
        path = Path(row.object_key).resolve()
        root = Path(os.getenv("SATARK_EVIDENCE_DIR", "./data/evidence")).resolve()
        if root not in path.parents or not path.is_file():
            continue
        raw = path.read_bytes()
        actual = hashlib.sha256(raw).hexdigest()
        valid = hmac.compare_digest(actual, row.source_sha256)
        try:
            details = json.loads(raw.decode("utf-8")) if row.content_type == "application/json" else {}
        except (ValueError, UnicodeDecodeError):
            details = {}
        record = {"event_id": row.id, "timestamp": row.observed_at.isoformat(), "source": row.source_label,
            "kind": row.event_kind, "summary": row.summary, "details": details if isinstance(details, dict) else {}}
        digest = sha256_record(record)
        integrity.append({"evidence_id": row.id, "valid": valid, "status": "VERIFIED" if valid else "HASH MISMATCH"})
        envelopes.append({"evidence_id": row.id, "record": record, "sha256": digest if valid else row.source_sha256,
            "collected_at": row.created_at.isoformat(), "integrity_status": "verified" if valid else "mismatch"})
    result = investigate_case({"case_id": case_id, "title": case.title}, envelopes)
    return {"schema_version": "1.1", "case_id": case_id, "integrity": integrity,
        "integrity_summary": {"total": len(integrity), "verified": sum(1 for x in integrity if x["valid"]),
        "mismatched": sum(1 for x in integrity if not x["valid"])}, "investigation": result,
        "agent_analysis": {"enabled": False, "mode": "deterministic_only", "agents": []},
        "limitations": ["Only evidence already stored in this SATARK case was analyzed.",
        "Evidence digest verification is limited to the stored bytes and does not independently prove original source authenticity.",
        "No live response action was executed."]}



@router.get("/firstlight/wazuh/alerts")
def list_wazuh_alerts(tenant_id: str, limit: int = 100, since: str | None = None,
                      user: User = Depends(current_user), db: Session = Depends(db_session)):
    require_membership(db, user, tenant_id)
    if not 1 <= limit <= 500:
        raise HTTPException(422, "limit must be between 1 and 500")
    configured_tenant = os.getenv("FIRSTLIGHT_WAZUH_TENANT_ID", "").strip().lower()
    if not UUID_RE.fullmatch(configured_tenant):
        raise HTTPException(503, "Wazuh connector tenant is not configured.")
    if not hmac.compare_digest(tenant_id.lower(), configured_tenant):
        raise HTTPException(403, "Wazuh source is not configured for this workspace.")
    if len(os.getenv("FIRSTLIGHT_WAZUH_INDEXER_USERNAME", "")) == 0 or len(os.getenv("FIRSTLIGHT_WAZUH_INDEXER_PASSWORD", "")) == 0:
        raise HTTPException(503, "Wazuh connector is not configured.")
    try:
        events = fetch_configured_alerts(limit=limit, since=since, order="desc")
    except WazuhConfigurationError as exc:
        raise HTTPException(503, "Wazuh connector configuration is invalid.") from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except WazuhConnectorError as exc:
        raise HTTPException(502, "Wazuh Indexer is temporarily unavailable.") from exc
    return {"source": "wazuh-indexer", "mode": "read_only_fetch", "persisted": False,
        "count": len(events), "events": events,
        "limitations": ["One bounded page only; alerts are not automatically persisted.",
            "Requires a dedicated read-only Wazuh Indexer account.",
            "A source digest does not independently prove authenticity."]}
