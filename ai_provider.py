"""Local Ollama client and model-selection helpers for SATARK.

The public interface mirrors the small subset of the OpenAI chat API used by
SATARK so the analysis workflow can stay provider-agnostic. No API key is used.
"""
import base64
import json
import os
import ipaddress
from urllib.parse import urlsplit
from types import SimpleNamespace
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


TEXT_MODEL_PREFERENCES = [
    os.getenv("SATARK_OLLAMA_TEXT_MODEL", "qwen2.5:3b"),
    "llama3.2:3b",
]
VISION_MODEL_PREFERENCES = [
    os.getenv("SATARK_OLLAMA_VISION_MODEL", "qwen2.5vl:3b"),
]
VISION_MODEL_IMAGE_LIMITS = {
    "qwen2.5vl:3b": 4,
}


class LocalOllamaClient:
    """Small synchronous client for a locally controlled Ollama server."""

    def __init__(self, base_url=None, timeout=None):
        candidate = (base_url or os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")).strip().rstrip("/")
        parsed = urlsplit(candidate)
        host = parsed.hostname or ""
        local_host = host.lower() in {"localhost", "ollama", "::1"}
        private_ip = False
        try:
            address = ipaddress.ip_address(host)
            private_ip = address.is_private or address.is_loopback
        except ValueError:
            pass
        if parsed.scheme != "http" or not (local_host or private_ip):
            raise ValueError("OLLAMA_BASE_URL must point to localhost or a private-network Ollama host.")
        self.base_url = candidate
        self.timeout = float(timeout or os.getenv("OLLAMA_TIMEOUT_SECONDS", "120"))
        self.models = SimpleNamespace(list=self._list_models)
        self.chat = SimpleNamespace(
            completions=SimpleNamespace(create=self._chat_completion)
        )

    def _request_json(self, path, payload=None, timeout=None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            self.base_url + path,
            data=data,
            headers={"Accept": "application/json", **({"Content-Type": "application/json"} if data is not None else {})},
            method="GET" if data is None else "POST",
        )
        try:
            with urlopen(request, timeout=timeout or self.timeout) as response:
                raw = response.read(8 * 1024 * 1024 + 1)
                if len(raw) > 8 * 1024 * 1024:
                    raise RuntimeError("Local Ollama response exceeded the allowed size.")
                return json.loads(raw.decode("utf-8"))
        except HTTPError as exc:
            raise RuntimeError(f"Local Ollama returned HTTP {exc.code}.") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise RuntimeError("Local Ollama is unavailable. Start Ollama and download a supported model.") from exc

    def _list_models(self):
        payload = self._request_json("/api/tags", timeout=min(self.timeout, 5))
        items = payload.get("models", []) if isinstance(payload, dict) else []
        return SimpleNamespace(data=[
            SimpleNamespace(id=str(item.get("name", "")))
            for item in items
            if isinstance(item, dict) and item.get("name")
        ])

    @staticmethod
    def _message_parts(messages):
        normalized = []
        for message in messages or []:
            role = str(message.get("role", "user"))
            content = message.get("content", "")
            images = []
            if isinstance(content, list):
                text_parts = []
                for part in content:
                    if not isinstance(part, dict):
                        continue
                    if part.get("type") == "text" and isinstance(part.get("text"), str):
                        text_parts.append(part["text"])
                    elif part.get("type") == "image_url":
                        url = part.get("image_url", {}).get("url", "")
                        if isinstance(url, str) and url.startswith("data:") and "," in url:
                            header, encoded = url.split(",", 1)
                            if ";base64" in header and len(encoded) <= 1_300_000:
                                try:
                                    base64.b64decode(encoded, validate=True)
                                    images.append(encoded)
                                except (ValueError, base64.binascii.Error):
                                    continue
                content = "\n".join(text_parts)
            normalized.append({"role": role, "content": str(content)[:60_000], **({"images": images[:6]} if images else {})})
        return normalized

    def _chat_completion(self, **kwargs):
        messages = self._message_parts(kwargs.get("messages"))
        options = {
            "temperature": float(kwargs.get("temperature", 0.1)),
            "num_predict": max(64, min(int(kwargs.get("max_tokens", 900)), 2048)),
        }
        payload = {
            "model": str(kwargs.get("model") or TEXT_MODEL_PREFERENCES[0]),
            "messages": messages,
            "stream": False,
            "options": options,
        }
        response_format = kwargs.get("response_format")
        if isinstance(response_format, dict) and response_format.get("type") == "json_schema":
            schema_wrapper = response_format.get("json_schema")
            schema = schema_wrapper.get("schema") if isinstance(schema_wrapper, dict) else None
            if isinstance(schema, dict):
                # Ollama's native /api/chat accepts the JSON Schema itself in
                # the format field; validation still happens locally afterward.
                payload["format"] = schema
            else:
                payload["format"] = "json"
        elif response_format:
            payload["format"] = "json"
        result = self._request_json("/api/chat", payload)
        message = result.get("message", {}) if isinstance(result, dict) else {}
        content = message.get("content", "") if isinstance(message, dict) else ""
        if not isinstance(content, str):
            raise RuntimeError("Local Ollama returned an invalid message.")
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=content))],
            model=payload["model"],
        )


def get_client(api_key=None):
    """Return the local Ollama client; the legacy api_key argument is ignored."""
    del api_key
    return LocalOllamaClient()


def discover_models(client):
    """Return models installed on the configured local Ollama instance."""
    try:
        listing = client.models.list()
        items = getattr(listing, "data", listing)
        ids = set()
        for item in items or []:
            mid = getattr(item, "id", None)
            if mid:
                ids.add(str(mid))
            elif isinstance(item, dict) and item.get("name"):
                ids.add(str(item["name"]))
        return ids
    except Exception:
        return set()


def choose_model(available, preferences):
    if not available:
        return preferences[0] if preferences else None
    for model in preferences:
        if model in available:
            return model
    return None


def model_status(client):
    available = discover_models(client)
    return (
        available,
        choose_model(available, TEXT_MODEL_PREFERENCES),
        choose_model(available, VISION_MODEL_PREFERENCES),
    )
