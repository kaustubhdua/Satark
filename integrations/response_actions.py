"""Guarded Microsoft response adapters for authorized SATARK deployments.

Live actions are deliberately opt-in and require explicit per-action confirmation.
This module never discovers assets or chooses targets automatically.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


class ResponseIntegrationError(RuntimeError):
    """A safe, user-displayable integration failure."""


@dataclass(frozen=True)
class ActionResult:
    provider: str
    action: str
    target: str
    status: str
    detail: str
    provider_reference: str | None = None


def _request_json(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    timeout: float = 12.0,
) -> tuple[int, Any]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Accept": "application/json", **(headers or {})},
    )
    try:
        # Do not follow redirects for credential-bearing API requests.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, hdrs, newurl):
                return None

        opener = urllib.request.build_opener(NoRedirect)
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(1_000_001)
            if len(raw) > 1_000_000:
                raise ResponseIntegrationError("Response exceeded the allowed size.")
            text = raw.decode("utf-8", errors="replace")
            return response.status, json.loads(text) if text else {}
    except urllib.error.HTTPError as exc:
        # Do not echo provider response bodies, which may contain tenant details.
        raise ResponseIntegrationError(
            f"Provider rejected the request (HTTP {exc.code}). Check permissions and target ID."
        ) from None
    except urllib.error.URLError:
        raise ResponseIntegrationError("Provider could not be reached. Check network and service configuration.") from None
    except (TimeoutError, json.JSONDecodeError):
        raise ResponseIntegrationError("Provider timed out or returned an invalid response.") from None


def _required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ResponseIntegrationError(f"Missing server-side configuration: {name}.")
    return value


def _confirm(action: str, target: str, confirmation: str) -> None:
    if os.getenv("SATARK_ENABLE_LIVE_RESPONSE", "").lower() != "true":
        raise ResponseIntegrationError(
            "Live response is disabled. Set SATARK_ENABLE_LIVE_RESPONSE=true only in an authorized test deployment."
        )
    expected = f"CONFIRM {action} {target}"
    if confirmation != expected:
        raise ResponseIntegrationError(f"Explicit confirmation required: {expected}")
    if not target or len(target) > 256 or any(ord(ch) < 32 for ch in target):
        raise ResponseIntegrationError("Target identifier is invalid.")


def preflight_live_response(action: str, target: str, confirmation: str) -> None:
    """Validate the explicit execution gate and required server configuration before claiming an approval."""
    phrases = {
        "defender.isolate_device": "ISOLATE",
        "entra.revoke_sessions": "REVOKE_SESSIONS",
    }
    phrase = phrases.get(action)
    if not phrase:
        raise ResponseIntegrationError("Action is not allowlisted for live response.")
    _confirm(phrase, target, confirmation)
    tenant = _required_env("MICROSOFT_TENANT_ID")
    _required_env("MICROSOFT_CLIENT_ID")
    _required_env("MICROSOFT_CLIENT_SECRET")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", tenant):
        raise ResponseIntegrationError("Microsoft tenant ID has an invalid format.")


def _access_token(scope: str) -> str:
    tenant = _required_env("MICROSOFT_TENANT_ID")
    client_id = _required_env("MICROSOFT_CLIENT_ID")
    client_secret = _required_env("MICROSOFT_CLIENT_SECRET")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", tenant):
        raise ResponseIntegrationError("Microsoft tenant ID has an invalid format.")
    form = urllib.parse.urlencode({
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scope,
        "grant_type": "client_credentials",
    }).encode("utf-8")
    request = urllib.request.Request(
        f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        data=form,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
    )
    try:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, hdrs, newurl):
                return None
        with urllib.request.build_opener(NoRedirect).open(request, timeout=12) as response:
            payload = json.loads(response.read(65537).decode("utf-8"))
            token = payload.get("access_token")
            if not isinstance(token, str) or not token:
                raise ResponseIntegrationError("Microsoft identity provider did not return an access token.")
            return token
    except urllib.error.HTTPError as exc:
        raise ResponseIntegrationError(
            f"Microsoft authentication failed (HTTP {exc.code}); verify tenant, app registration and permissions."
        ) from None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        raise ResponseIntegrationError("Microsoft authentication endpoint could not be reached or returned invalid data.") from None


def isolate_defender_device(
    device_id: str,
    *,
    confirmation: str,
    isolation_type: str = "Full",
    reason: str,
) -> ActionResult:
    """Request isolation of one explicitly identified Defender for Endpoint device."""
    _confirm("ISOLATE", device_id, confirmation)
    if isolation_type not in {"Full", "Selective", "UnManagedDevice"}:
        raise ResponseIntegrationError("Isolation type must be Full, Selective or UnManagedDevice.")
    reason = reason.strip()
    if not reason or len(reason) > 1000:
        raise ResponseIntegrationError("A reason of 1–1000 characters is required.")
    token = _access_token("https://api.security.microsoft.com/.default")
    status, payload = _request_json(
        "https://api.security.microsoft.com/api/machines/"
        + urllib.parse.quote(device_id, safe="") + "/isolate",
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        body={"Comment": f"SATARK approved response: {reason}", "IsolationType": isolation_type},
    )
    reference = payload.get("id") or payload.get("machineActionId") if isinstance(payload, dict) else None
    return ActionResult("Microsoft Defender for Endpoint", "isolate_device", device_id,
                        "submitted" if status in {200, 201, 202} else "unknown",
                        "Provider accepted the isolation request; verify final machine-action status in Defender.",
                        str(reference)[:256] if reference else None)


def revoke_entra_user_sessions(
    user_id_or_upn: str,
    *,
    confirmation: str,
    reason: str,
) -> ActionResult:
    """Invalidate refresh tokens and browser session cookies for one Entra user."""
    _confirm("REVOKE_SESSIONS", user_id_or_upn, confirmation)
    if not re.fullmatch(r"[A-Za-z0-9@._-]{1,256}", user_id_or_upn):
        raise ResponseIntegrationError("User ID or UPN contains unsupported characters.")
    reason = reason.strip()
    if not reason or len(reason) > 1000:
        raise ResponseIntegrationError("A reason of 1–1000 characters is required.")
    token = _access_token("https://graph.microsoft.com/.default")
    target = urllib.parse.quote(user_id_or_upn, safe="")
    status, _ = _request_json(
        f"https://graph.microsoft.com/v1.0/users/{target}/revokeSignInSessions",
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        body={},
    )
    return ActionResult("Microsoft Entra ID", "revoke_sign_in_sessions", user_id_or_upn,
                        "submitted" if 200 <= status < 300 else "unknown",
                        "Provider accepted the session-revocation request; token invalidation can take several minutes.",
                        None)


def live_response_enabled() -> bool:
    """Safe capability check for UI gating; does not validate credentials or permissions."""
    return os.getenv("SATARK_ENABLE_LIVE_RESPONSE", "").lower() == "true"
