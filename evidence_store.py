"""Optional S3-compatible private evidence object store.

The default SATARK evidence backend is a private local filesystem volume. Set
``SATARK_EVIDENCE_BACKEND=s3`` to store new evidence objects in an S3-compatible
bucket (AWS S3, MinIO, Cloudflare R2, Backblaze B2, ...). Rows written by either
backend remain readable: the stored ``object_key`` is ``s3://bucket/key`` for
S3 objects and an absolute filesystem path otherwise.

Configuration (all via environment, never committed):

  SATARK_EVIDENCE_BACKEND   ``filesystem`` (default) or ``s3``
  SATARK_S3_BUCKET          required for s3
  SATARK_S3_PREFIX          optional key prefix, e.g. ``evidence/``
  SATARK_S3_ENDPOINT_URL    optional, for MinIO/R2/B2 and other compatible stores
  SATARK_S3_REGION          optional region name
  SATARK_S3_SSE             optional ``AES256`` or ``aws:kms``
  SATARK_S3_KMS_KEY_ID      optional KMS key when SATARK_S3_SSE=aws:kms

Credentials use boto3's standard provider chain (environment, shared config,
instance/task role). Install the optional dependency with
``pip install -r requirements-s3.txt``.

Security properties: the configured bucket is pinned, so a database row cannot
redirect a read to a different bucket; keys are built only from canonical UUIDs;
objects are written with a SHA-256 integrity header and are re-hashed by the
caller on every read; evidence is never made public.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Callable

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
S3_SCHEME = "s3://"


class EvidenceStoreError(RuntimeError):
    """The object store is unavailable or misconfigured."""


class EvidenceNotFound(EvidenceStoreError):
    """The requested evidence object does not exist."""


def backend_name() -> str:
    value = os.getenv("SATARK_EVIDENCE_BACKEND", "filesystem").strip().lower()
    if value not in {"filesystem", "s3"}:
        raise EvidenceStoreError("SATARK_EVIDENCE_BACKEND must be 'filesystem' or 's3'.")
    return value


def is_s3_key(object_key: str) -> bool:
    return isinstance(object_key, str) and object_key.startswith(S3_SCHEME)


def _default_client_factory() -> Any:
    try:
        import boto3  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - exercised only without the optional dependency
        raise EvidenceStoreError(
            "S3 evidence storage requires boto3. Install requirements-s3.txt."
        ) from exc
    kwargs: dict[str, Any] = {}
    if os.getenv("SATARK_S3_ENDPOINT_URL"):
        kwargs["endpoint_url"] = os.environ["SATARK_S3_ENDPOINT_URL"]
    if os.getenv("SATARK_S3_REGION"):
        kwargs["region_name"] = os.environ["SATARK_S3_REGION"]
    return boto3.client("s3", **kwargs)


# Tests replace this factory with an in-memory fake; production uses boto3.
client_factory: Callable[[], Any] = _default_client_factory


@dataclass(frozen=True)
class S3Location:
    bucket: str
    key: str

    def uri(self) -> str:
        return f"{S3_SCHEME}{self.bucket}/{self.key}"


def _config() -> tuple[str, str]:
    bucket = os.getenv("SATARK_S3_BUCKET", "").strip()
    if not bucket:
        raise EvidenceStoreError("SATARK_S3_BUCKET is required when SATARK_EVIDENCE_BACKEND=s3.")
    prefix = os.getenv("SATARK_S3_PREFIX", "").strip().lstrip("/")
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    if ".." in prefix.split("/"):
        raise EvidenceStoreError("SATARK_S3_PREFIX must not contain '..'.")
    return bucket, prefix


def build_location(tenant_id: str, case_id: str, evidence_id: str) -> S3Location:
    for value in (tenant_id, case_id, evidence_id):
        if not isinstance(value, str) or not UUID_RE.fullmatch(value.lower()):
            raise EvidenceStoreError("Evidence identifiers must be canonical UUIDs.")
    bucket, prefix = _config()
    return S3Location(bucket, f"{prefix}{tenant_id.lower()}/{case_id.lower()}/{evidence_id.lower()}")


def parse_location(object_key: str) -> S3Location:
    """Parse a stored key and refuse anything outside the configured bucket/prefix."""
    if not is_s3_key(object_key):
        raise EvidenceStoreError("Not an S3 evidence key.")
    bucket, _, key = object_key[len(S3_SCHEME):].partition("/")
    configured_bucket, prefix = _config()
    if bucket != configured_bucket or not key or ".." in key.split("/") or not key.startswith(prefix):
        raise EvidenceNotFound("Evidence object not found.")
    return S3Location(bucket, key)


def _is_missing(exc: Exception) -> bool:
    response = getattr(exc, "response", None)
    code = str((response or {}).get("Error", {}).get("Code", "")) if isinstance(response, dict) else ""
    return code in {"404", "NoSuchKey", "NotFound"}


def put_object(tenant_id: str, case_id: str, evidence_id: str, raw: bytes, sha256_hex: str) -> str:
    """Write one immutable evidence object and return its ``s3://`` object key."""
    location = build_location(tenant_id, case_id, evidence_id)
    extra: dict[str, Any] = {"Metadata": {"sha256": sha256_hex}, "ContentType": "application/octet-stream"}
    sse = os.getenv("SATARK_S3_SSE", "").strip()
    if sse:
        if sse not in {"AES256", "aws:kms"}:
            raise EvidenceStoreError("SATARK_S3_SSE must be AES256 or aws:kms.")
        extra["ServerSideEncryption"] = sse
        if sse == "aws:kms" and os.getenv("SATARK_S3_KMS_KEY_ID"):
            extra["SSEKMSKeyId"] = os.environ["SATARK_S3_KMS_KEY_ID"]
    try:
        client_factory().put_object(Bucket=location.bucket, Key=location.key, Body=raw, **extra)
    except EvidenceStoreError:
        raise
    except Exception as exc:
        raise EvidenceStoreError("S3 evidence storage is unavailable.") from exc
    return location.uri()


def get_object(object_key: str) -> bytes:
    location = parse_location(object_key)
    try:
        response = client_factory().get_object(Bucket=location.bucket, Key=location.key)
        return response["Body"].read()
    except EvidenceStoreError:
        raise
    except Exception as exc:
        if _is_missing(exc):
            raise EvidenceNotFound("Evidence object not found.") from exc
        raise EvidenceStoreError("S3 evidence storage is unavailable.") from exc


def delete_object(object_key: str) -> None:
    """Best-effort removal of an object that never got a database row."""
    location = parse_location(object_key)
    try:
        client_factory().delete_object(Bucket=location.bucket, Key=location.key)
    except Exception:
        # An orphan is recoverable; never mask the original request error.
        pass
