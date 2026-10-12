"""Safe public-URL fetching with DNS-pinned connections and visible-text extraction.

The fetcher fails closed on malformed URLs, private/reserved DNS answers,
unsafe redirects, oversized responses, and non-web content. It deliberately
connects to an IP address from the validated DNS result instead of resolving the
hostname a second time during connection establishment.
"""

import http.client
import ipaddress
import socket
import ssl
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from config import (
    URL_FETCH_TIMEOUT_SECONDS,
    URL_MAX_BYTES,
    URL_MAX_REDIRECTS,
    URL_MAX_TEXT_CHARS,
    URL_USER_AGENT,
)
from satark_utils import safe_text

_REDIRECT_CODES = {301, 302, 303, 307, 308}
_ACCEPTED_TYPES = {
    "text/html",
    "application/xhtml+xml",
    "text/plain",
    "application/xml",
    "text/xml",
}


class VisibleTextParser(HTMLParser):
    """Extract visible-ish text while excluding common non-visible elements."""

    def __init__(self):
        super().__init__()
        self.parts = []
        self._skip_tags = []
        self._ignored_tags = {"script", "style", "noscript", "svg"}

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if self._skip_tags:
            self._skip_tags.append(tag)
        elif tag in self._ignored_tags:
            self._skip_tags.append(tag)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self._skip_tags and tag == self._skip_tags[-1]:
            self._skip_tags.pop()

    def handle_data(self, data):
        if not self._skip_tags and data.strip():
            self.parts.append(data.strip())

    def text(self):
        return "\n".join(self.parts)


def _validated_destination(url):
    """Return (parsed URL, validated IPs); never trust a later DNS lookup."""
    parsed = urlparse(safe_text(url))
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("For safety, only public HTTP/HTTPS URLs can be fetched.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing credentials are not allowed.")

    host = parsed.hostname.rstrip(".").lower()
    if (
        not host
        or host in {"localhost", "localhost.localdomain"}
        or host.endswith(".localhost")
        or "%" in host
    ):
        raise ValueError("The URL points to a local or unsafe network address.")

    try:
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("The URL contains an invalid port.") from exc
    if not (1 <= port <= 65535):
        raise ValueError("The URL contains an invalid port.")
    # This fetcher is for public web pages, not a general-purpose port scanner.
    # Restrict outbound connections to the standard port for the selected scheme.
    expected_port = 443 if parsed.scheme == "https" else 80
    if port != expected_port:
        raise ValueError("For safety, only standard HTTP (80) and HTTPS (443) ports can be fetched.")

    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError) as exc:
        raise ValueError("The URL hostname could not be resolved safely.") from exc
    if not records:
        raise ValueError("The URL hostname could not be resolved safely.")

    addresses = []
    for record in records:
        try:
            address = ipaddress.ip_address(record[4][0])
        except (ValueError, IndexError, TypeError) as exc:
            raise ValueError("The URL hostname returned an invalid address.") from exc
        # Reject the whole hostname if any answer is non-global or not a
        # unicast destination. Python considers some multicast addresses global,
        # so is_global alone is not a sufficient outbound-fetch policy.
        if (
            not address.is_global
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
            or address.is_loopback
            or address.is_link_local
        ):
            raise ValueError("The URL points to a private or unsafe network address.")
        value = str(address)
        if value not in addresses:
            addresses.append(value)

    return parsed, addresses


def is_public_url(url):
    """Return True only for HTTP(S) URLs whose DNS answers are all global IPs."""
    try:
        _validated_destination(url)
        return True
    except (ValueError, OSError, TypeError):
        return False


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection whose TCP socket connects to an already-validated IP."""

    def __init__(self, host, port, address, timeout):
        self._connect_address = address
        super().__init__(host=host, port=port, timeout=timeout)

    def connect(self):
        self.sock = socket.create_connection(
            (self._connect_address, self.port),
            self.timeout,
            self.source_address,
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to an IP while retaining hostname TLS checks."""

    def __init__(self, host, port, address, timeout):
        self._connect_address = address
        super().__init__(host=host, port=port, timeout=timeout, context=ssl.create_default_context())

    def connect(self):
        raw_socket = socket.create_connection(
            (self._connect_address, self.port),
            self.timeout,
            self.source_address,
        )
        try:
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            raise


def _open_pinned_request(url, address):
    """Open one GET request without automatic redirects or environment proxies."""
    parsed = urlparse(url)
    port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
    connection_type = _PinnedHTTPSConnection if parsed.scheme == "https" else _PinnedHTTPConnection
    connection = connection_type(
        host=parsed.hostname,
        port=port,
        address=address,
        timeout=URL_FETCH_TIMEOUT_SECONDS,
    )
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    try:
        connection.request(
            "GET",
            target,
            headers={
                "User-Agent": URL_USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,text/plain",
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
        )
        return connection, connection.getresponse()
    except Exception:
        connection.close()
        raise


def _read_limited_response(response):
    declared_length = response.headers.get("Content-Length")
    if declared_length is not None:
        try:
            declared_size = int(declared_length)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError("The remote server returned an invalid content length.") from exc
        if declared_size < 0:
            raise ValueError("The remote server returned an invalid content length.")
        if declared_size > URL_MAX_BYTES:
            raise ValueError("The remote response is larger than SATARK's safety limit.")

    raw = response.read(URL_MAX_BYTES + 1)
    if len(raw) > URL_MAX_BYTES:
        raise ValueError("The remote response is larger than SATARK's safety limit.")
    return raw


def fetch_url_text(url):
    """Fetch a bounded public web page while pinning each request to validated DNS."""
    current_url = safe_text(url)
    redirect_count = 0

    while True:
        try:
            parsed, addresses = _validated_destination(current_url)
        except (ValueError, OSError, TypeError) as exc:
            raise ValueError(str(exc) or "The URL was blocked by SATARK's safety checks.") from exc

        connection = None
        response = None
        try:
            connection, response = _open_pinned_request(current_url, addresses[0])
            if response.status in _REDIRECT_CODES:
                location = response.headers.get("Location")
                if not location:
                    raise ValueError("The remote server returned a redirect without a destination.")
                if redirect_count >= URL_MAX_REDIRECTS:
                    raise ValueError("The URL exceeded SATARK's redirect safety limit.")
                next_url = urljoin(current_url, location)
                next_parsed = urlparse(next_url)
                if parsed.scheme == "https" and next_parsed.scheme != "https":
                    raise ValueError("SATARK blocked an insecure HTTPS-to-HTTP redirect.")
                current_url = next_url
                redirect_count += 1
                continue

            if response.status < 200 or response.status >= 300:
                raise ValueError("The remote server did not return a successful web page.")

            content_type = response.headers.get("Content-Type", "").lower()
            media_type = content_type.split(";", 1)[0].strip()
            if media_type not in _ACCEPTED_TYPES:
                raise ValueError(
                    "SATARK only reads public HTML, XML, or plain-text pages. "
                    "This URL returned an unsupported content type."
                )
            raw = _read_limited_response(response)
        finally:
            if response is not None:
                response.close()
            if connection is not None:
                connection.close()

        decoded = raw.decode("utf-8", errors="replace")
        if media_type == "text/plain":
            return decoded[:URL_MAX_TEXT_CHARS]
        parser = VisibleTextParser()
        parser.feed(decoded)
        parser.close()
        text = parser.text() or decoded
        return text[:URL_MAX_TEXT_CHARS]
