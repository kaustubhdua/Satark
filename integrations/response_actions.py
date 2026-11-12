"""Guarded Wazuh Active Response adapter for self-hosted FIRSTLIGHT.

Only explicitly allowlisted agents and two fixed Wazuh commands are supported.
This module never constructs shell commands or accepts arbitrary command names.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping


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


def _required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ResponseIntegrationError(f"Missing server-side configuration: {name}.")
    return value


def live_response_enabled() -> bool:
    """Explicit opt-in; response remains disabled in every default installation."""
    return os.getenv("SATARK_ENABLE_LIVE_RESPONSE", "").lower() == "true"


def _agent_allowlist() -> set[str]:
    values = {item.strip() for item in os.getenv("FIRSTLIGHT_WAZUH_RESPONSE_AGENT_IDS", "").split(",") if item.strip()}
    if not values or any(not re.fullmatch(r"\d{3,}", item) for item in values):
        raise ResponseIntegrationError("Configure FIRSTLIGHT_WAZUH_RESPONSE_AGENT_IDS with explicit numeric lab agent IDs.")
    return values


def _protected_networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    raw = _required_env("FIRSTLIGHT_WAZUH_PROTECTED_IPS")
    try:
        networks = [ipaddress.ip_network(item.strip(), strict=False) for item in raw.split(",") if item.strip()]
    except ValueError:
        raise ResponseIntegrationError("FIRSTLIGHT_WAZUH_PROTECTED_IPS must contain valid IP addresses or CIDRs.") from None
    if not networks:
        raise ResponseIntegrationError("FIRSTLIGHT_WAZUH_PROTECTED_IPS must include the Manager, API and protected infrastructure networks.")
    return networks


def _verified_response_ttl() -> int:
    if os.getenv("FIRSTLIGHT_WAZUH_RESPONSE_TTL_VERIFIED", "").lower() != "true":
        raise ResponseIntegrationError("Live IP response is unavailable until the Wazuh lab proves automatic timeout and reversal.")
    raw = _required_env("FIRSTLIGHT_WAZUH_RESPONSE_TTL_SECONDS")
    if not raw.isdigit() or not 60 <= int(raw) <= 900:
        raise ResponseIntegrationError("FIRSTLIGHT_WAZUH_RESPONSE_TTL_SECONDS must be between 60 and 900 seconds.")
    return int(raw)


def available_response_actions() -> list[str]:
    """Expose only the lab-verified, time-bounded Linux IP block action."""
    if not live_response_enabled():
        return []
    try:
        _agent_allowlist()
        _protected_networks()
        _verified_response_ttl()
        _base_url()
        _required_env("FIRSTLIGHT_WAZUH_MANAGER_USERNAME")
        _required_env("FIRSTLIGHT_WAZUH_MANAGER_PASSWORD")
    except ResponseIntegrationError:
        return []
    return ["wazuh.block_ip"]


def _base_url() -> str:
    value = _required_env("FIRSTLIGHT_WAZUH_MANAGER_API_URL").rstrip("/")
    parsed = urllib.parse.urlsplit(value)
    allow_http = os.getenv("FIRSTLIGHT_WAZUH_MANAGER_ALLOW_HTTP", "").lower() == "true"
    if parsed.scheme != "https" and not (parsed.scheme == "http" and allow_http and parsed.hostname in {"localhost", "127.0.0.1"}):
        raise ResponseIntegrationError("Wazuh Manager API must use HTTPS (HTTP is allowed only for explicit localhost tests).")
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ResponseIntegrationError("Wazuh Manager API URL is invalid.")
    return value


def _ssl_context() -> ssl.SSLContext:
    ca_file = os.getenv("FIRSTLIGHT_WAZUH_MANAGER_CA_BUNDLE", "").strip()
    return ssl.create_default_context(cafile=ca_file or None)


def _request(url: str, *, method: str = "GET", headers: Mapping[str, str] | None = None,
             body: Mapping[str, Any] | None = None, basic_auth: tuple[str, str] | None = None) -> tuple[int, Any]:
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    request_headers = {"Accept": "application/json", **dict(headers or {})}
    if data is not None:
        request_headers["Content-Type"] = "application/json"
    if basic_auth:
        import base64
        encoded = base64.b64encode(f"{basic_auth[0]}:{basic_auth[1]}".encode()).decode("ascii")
        request_headers["Authorization"] = f"Basic {encoded}"
    request = urllib.request.Request(url, data=data, method=method, headers=request_headers)

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            return None

    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=_ssl_context()))
    try:
        with opener.open(request, timeout=12) as response:
            raw = response.read(1_000_001)
            if len(raw) > 1_000_000:
                raise ResponseIntegrationError("Wazuh response exceeded the allowed size.")
            text = raw.decode("utf-8", errors="replace")
            try:
                payload = json.loads(text) if text else {}
            except json.JSONDecodeError:
                payload = text.strip()
            return response.status, payload
    except urllib.error.HTTPError as exc:
        raise ResponseIntegrationError(f"Wazuh Manager API rejected the request (HTTP {exc.code}).") from None
    except urllib.error.URLError:
        raise ResponseIntegrationError("Wazuh Manager API could not be reached; check endpoint, TLS and network.") from None
    except (TimeoutError, ssl.SSLError):
        raise ResponseIntegrationError("Wazuh Manager API timed out or failed TLS verification.") from None


def _token() -> str:
    base = _base_url()
    username = _required_env("FIRSTLIGHT_WAZUH_MANAGER_USERNAME")
    password = _required_env("FIRSTLIGHT_WAZUH_MANAGER_PASSWORD")
    status, payload = _request(
        base + "/security/user/authenticate?raw=true",
        method="POST",
        basic_auth=(username, password),
    )
    token = payload if isinstance(payload, str) else payload.get("data", {}).get("token") if isinstance(payload, dict) else None
    if status != 200 or not isinstance(token, str) or not token.strip():
        raise ResponseIntegrationError("Wazuh Manager API authentication did not return a bearer token.")
    return token.strip()


def _verify_manager_compatibility(token: str) -> str:
    """The PUT /active-response adapter is intentionally pinned to Wazuh 4.14.x."""
    status, payload = _request(
        _base_url() + "/manager/info",
        headers={"Authorization": f"Bearer {token}"},
    )
    items = payload.get("data", {}).get("affected_items", []) if isinstance(payload, dict) else []
    version = items[0].get("version", "") if items and isinstance(items[0], dict) else ""
    if status != 200 or not isinstance(version, str) or not re.fullmatch(r"v?4\.14\.\d+", version):
        raise ResponseIntegrationError(
            "This Active Response adapter requires a verified Wazuh Manager 4.14.x version. "
            "Wazuh 5.x uses a different Active Response workflow and is not supported by this adapter."
        )
    return version.removeprefix("v")


def _verify_agent_target(token: str, agent_id: str, action: str) -> None:
    """Require one exact, connected Wazuh agent before submitting a response."""
    query = urllib.parse.urlencode({"agents_list": agent_id})
    status, payload = _request(
        _base_url() + "/agents?" + query,
        headers={"Authorization": f"Bearer {token}"},
    )
    data = payload.get("data", {}) if isinstance(payload, dict) else {}
    items = data.get("affected_items", []) if isinstance(data, dict) else []
    if status != 200 or not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
        raise ResponseIntegrationError("Wazuh did not return exactly one matching agent; no response was submitted.")
    agent = items[0]
    returned_id = str(agent.get("id", agent.get("agent_id", "")))
    if returned_id != agent_id or str(agent.get("status", "")).lower() != "active":
        raise ResponseIntegrationError("The selected Wazuh agent is missing, mismatched, or not active; no response was submitted.")
    os_info = agent.get("os") if isinstance(agent.get("os"), dict) else {}
    platform = str(os_info.get("platform", "")).strip().lower()
    name = str(os_info.get("name", "")).strip().lower()
    if not (platform == "linux" or any(name.startswith(prefix) for prefix in (
        "ubuntu", "debian", "centos", "red hat", "rhel", "fedora",
        "rocky", "almalinux", "amazon linux", "opensuse", "suse",
        "arch", "gentoo",
    ))):
        raise ResponseIntegrationError(
            "Wazuh firewall-drop is restricted to verified Linux agents; no response was submitted."
        )


def preflight_live_response(action: str, target: str, confirmation: str) -> None:
    """Check explicit opt-in, action allowlist, target allowlist and credentials."""
    expected = "BLOCK_IP" if action == "wazuh.block_ip" else None
    if not expected:
        raise ResponseIntegrationError("Action is not allowlisted; only the lab-verified Wazuh IP block action is supported, and account disable is not supported.")
    if not live_response_enabled():
        raise ResponseIntegrationError("Live response is disabled. Enable it only in an authorized isolated lab.")
    _verified_response_ttl()
    _protected_networks()
    if confirmation != f"CONFIRM {expected} {target}":
        raise ResponseIntegrationError(f"Explicit confirmation required: CONFIRM {expected} {target}")
    if target not in _agent_allowlist():
        raise ResponseIntegrationError("Target agent is not in FIRSTLIGHT_WAZUH_RESPONSE_AGENT_IDS.")
    if action == "wazuh.disable_account" and target not in _account_disable_allowlist():
        raise ResponseIntegrationError("Account disable is restricted to FIRSTLIGHT_WAZUH_ACCOUNT_DISABLE_AGENT_IDS (Linux/macOS lab agents only).")
    _base_url()
    _required_env("FIRSTLIGHT_WAZUH_MANAGER_USERNAME")
    _required_env("FIRSTLIGHT_WAZUH_MANAGER_PASSWORD")


def _validate_payload(action: str, payload: Mapping[str, Any]) -> list[str]:
    if not isinstance(payload, Mapping):
        raise ResponseIntegrationError("Response payload must be an object.")
    if action == "wazuh.block_ip":
        if set(payload) != {"ip_address"}:
            raise ResponseIntegrationError("IP block payload must contain only ip_address.")
        try:
            address = ipaddress.ip_address(str(payload["ip_address"]))
        except ValueError:
            raise ResponseIntegrationError("ip_address must be a valid IPv4 address.") from None
        if address.version != 4 or not address.is_global:
            raise ResponseIntegrationError("Only globally routable unicast IPv4 addresses can be blocked.")
        if any(address in network for network in _protected_networks()):
            raise ResponseIntegrationError("The target IP is inside a protected infrastructure network.")
        return [str(address)]
    raise ResponseIntegrationError("Action is not allowlisted for Wazuh live response.")


def execute_wazuh_response(action: str, agent_id: str, payload: Mapping[str, Any], *,
                           confirmation: str, reason: str) -> ActionResult:
    """Submit one fixed Wazuh built-in Active Response command to one allowlisted agent."""
    preflight_live_response(action, agent_id, confirmation)
    reason = reason.strip()
    if not reason or len(reason) > 1000:
        raise ResponseIntegrationError("A reason of 1–1000 characters is required.")
    command, args = "firewall-drop", _validate_payload(action, payload)
    token = _token()
    manager_version = _verify_manager_compatibility(token)
    _verify_agent_target(token, agent_id, action)
    query = urllib.parse.urlencode({"agents_list": agent_id, "wait_for_complete": "true"})
    status, response = _request(
        _base_url() + "/active-response?" + query,
        method="PUT",
        headers={"Authorization": f"Bearer {token}"},
        body={"command": command, "arguments": args, "custom": False},
    )
    if status not in {200, 201, 202} or not isinstance(response, dict) or response.get("error") not in {0, None}:
        raise ResponseIntegrationError("Wazuh did not confirm that the Active Response command was accepted.")
    data = response.get("data", {})
    affected = data.get("affected_items", []) if isinstance(data, dict) else []
    failed = data.get("failed_items", []) if isinstance(data, dict) else []
    if failed or not affected or agent_id not in {str(item) for item in affected}:
        raise ResponseIntegrationError("Wazuh reported a failed or mismatched target response.")
    return ActionResult(
        "Wazuh Active Response",
        command,
        agent_id,
        "submitted",
        f"Wazuh Manager {manager_version} accepted the command for the explicitly allowlisted agent. Independently verify the agent state; submission is not proof of containment.",
        None,
    )
