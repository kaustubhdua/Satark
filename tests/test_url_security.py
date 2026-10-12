"""Security boundary tests for URL fetching; no real network is used."""
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlparse

from url_security import (
    _PinnedHTTPSConnection,
    _read_limited_response,
    fetch_url_text,
    is_public_url,
)


def fake_response(
    body=b"<html><body>Hello</body></html>",
    headers=None,
    status=200,
):
    response = Mock()
    response.status = status
    response.headers = headers or {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Length": str(len(body)),
    }
    response.read.return_value = body
    return response


def fake_connection():
    connection = Mock()
    connection.close = Mock()
    return connection


class URLSecurityTests(unittest.TestCase):
    def test_non_http_schemes_credentials_and_local_hosts_fail_closed(self):
        for url in (
            "file:///etc/passwd",
            "ftp://example.com/file",
            "https://user:password@example.com/",
            "http://localhost/",
            "http://127.0.0.1/",
        ):
            with self.subTest(url=url):
                self.assertFalse(is_public_url(url))

    def test_zero_and_out_of_range_ports_are_rejected(self):
        for url in (
            "http://example.com:0/",
            "https://example.com:65536/",
        ):
            with self.subTest(url=url):
                self.assertFalse(is_public_url(url))

    def test_only_standard_web_ports_are_allowed(self):
        for url in (
            "http://example.com:8080/",
            "https://example.com:8443/",
            "https://example.com:80/",
            "http://example.com:443/",
        ):
            with self.subTest(url=url):
                self.assertFalse(is_public_url(url))

        answers = [(None, None, None, None, ("93.184.216.34", 80))]
        with patch("url_security.socket.getaddrinfo", return_value=answers):
            self.assertTrue(is_public_url("http://example.com:80/"))
        answers = [(None, None, None, None, ("93.184.216.34", 443))]
        with patch("url_security.socket.getaddrinfo", return_value=answers):
            self.assertTrue(is_public_url("https://example.com:443/"))

    def test_mixed_public_and_private_dns_answers_fail_closed(self):
        answers = [
            (None, None, None, None, ("93.184.216.34", 443)),
            (None, None, None, None, ("10.0.0.5", 443)),
        ]
        with patch("url_security.socket.getaddrinfo", return_value=answers):
            self.assertFalse(is_public_url("https://example.com/"))

    def test_dns_resolution_failure_fails_closed(self):
        with patch("url_security.socket.getaddrinfo", side_effect=OSError("dns unavailable")):
            self.assertFalse(is_public_url("https://example.com/"))

    def test_non_unicast_global_addresses_are_rejected(self):
        # Multicast can report is_global=True in Python's ipaddress module,
        # but is never an acceptable destination for user-submitted URL fetches.
        for address in ("224.0.0.1", "239.255.255.250", "ff02::1"):
            with self.subTest(address=address):
                answer = [(None, None, None, None, (address, 443, 0, 0) if ":" in address else (address, 443))]
                with patch("url_security.socket.getaddrinfo", return_value=answer):
                    self.assertFalse(is_public_url("https://example.com/"))

    def test_https_connection_uses_pinned_ip_and_hostname_for_tls(self):
        raw_socket = Mock()
        tls_socket = Mock()
        context = Mock()
        context.wrap_socket.return_value = tls_socket
        with patch("url_security.socket.create_connection", return_value=raw_socket) as connect, patch(
            "url_security.ssl.create_default_context", return_value=context
        ):
            connection = _PinnedHTTPSConnection(
                host="example.com", port=443, address="93.184.216.34", timeout=2
            )
            connection.connect()
        connect.assert_called_once_with(("93.184.216.34", 443), 2, None)
        context.wrap_socket.assert_called_once_with(raw_socket, server_hostname="example.com")
        self.assertIs(connection.sock, tls_socket)

    def test_unsupported_binary_content_is_rejected(self):
        response = fake_response(
            b"\\x00\\x01\\x02",
            {"Content-Type": "application/octet-stream", "Content-Length": "3"},
        )
        with patch("url_security._validated_destination", return_value=(urlparse("https://example.com/file.bin"), ["93.184.216.34"])), patch(
            "url_security._open_pinned_request", return_value=(fake_connection(), response)
        ):
            with self.assertRaisesRegex(ValueError, "unsupported content type"):
                fetch_url_text("https://example.com/file.bin")
        response.close.assert_called_once()

    def test_oversized_declared_response_is_rejected_before_read(self):
        response = fake_response(b"tiny", {"Content-Type": "text/plain", "Content-Length": "999999999"})
        with self.assertRaisesRegex(ValueError, "larger than"):
            _read_limited_response(response)
        response.read.assert_not_called()

    def test_malformed_content_length_is_rejected(self):
        response = fake_response(b"tiny", {"Content-Type": "text/plain", "Content-Length": "unknown"})
        with self.assertRaisesRegex(ValueError, "invalid content length"):
            _read_limited_response(response)

    def test_response_read_limit_is_enforced(self):
        from config import URL_MAX_BYTES

        response = fake_response(b"x" * (URL_MAX_BYTES + 1), {"Content-Type": "text/plain"})
        with self.assertRaisesRegex(ValueError, "larger than"):
            _read_limited_response(response)

    def test_html_parser_excludes_script_and_style_text(self):
        response = fake_response(
            b"<html><body>Visible<script>secret()</script><style>.hidden{}</style><p>Text</p></body></html>",
            {"Content-Type": "text/html", "Content-Length": "100"},
        )
        with patch("url_security._validated_destination", return_value=(urlparse("https://example.com/"), ["93.184.216.34"])), patch(
            "url_security._open_pinned_request", return_value=(fake_connection(), response)
        ):
            result = fetch_url_text("https://example.com/")
        self.assertIn("Visible", result)
        self.assertIn("Text", result)
        self.assertNotIn("secret", result)
        self.assertNotIn(".hidden", result)

    def test_redirect_is_revalidated_and_uses_new_pinned_destination(self):
        first = fake_response(
            headers={"Content-Type": "text/html", "Location": "https://other.example/page"},
            status=302,
        )
        second = fake_response(
            b"<html><body>Destination</body></html>",
            {"Content-Type": "text/html", "Content-Length": "35"},
        )
        first_connection, second_connection = fake_connection(), fake_connection()
        with patch(
            "url_security._validated_destination",
            side_effect=lambda url: (urlparse(url), ["93.184.216.34" if urlparse(url).hostname == "example.com" else "1.1.1.1"]),
        ) as validate, patch(
            "url_security._open_pinned_request",
            side_effect=[(first_connection, first), (second_connection, second)],
        ) as open_request:
            result = fetch_url_text("https://example.com/start")
        self.assertIn("Destination", result)
        self.assertEqual(validate.call_count, 2)
        self.assertEqual(open_request.call_args_list[0].args[1], "93.184.216.34")
        self.assertEqual(open_request.call_args_list[1].args[1], "1.1.1.1")
        first.close.assert_called_once()
        second.close.assert_called_once()

    def test_redirect_budget_is_enforced(self):
        from config import URL_MAX_REDIRECTS

        responses = [
            (fake_connection(), fake_response(headers={"Location": f"https://example.com/{i}"}, status=302))
            for i in range(URL_MAX_REDIRECTS + 1)
        ]
        with patch("url_security._validated_destination", return_value=(urlparse("https://example.com/"), ["93.184.216.34"])), patch(
            "url_security._open_pinned_request", side_effect=responses
        ):
            with self.assertRaisesRegex(ValueError, "redirect safety limit"):
                fetch_url_text("https://example.com/")

    def test_https_to_http_redirect_is_rejected(self):
        response = fake_response(
            headers={"Content-Type": "text/html", "Location": "http://example.com/plain"},
            status=302,
        )
        with patch("url_security._validated_destination", return_value=(urlparse("https://example.com/"), ["93.184.216.34"])), patch(
            "url_security._open_pinned_request", return_value=(fake_connection(), response)
        ):
            with self.assertRaisesRegex(ValueError, "insecure HTTPS-to-HTTP"):
                fetch_url_text("https://example.com/")

    def test_ipv4_mapped_ipv6_private_destination_is_rejected(self):
        answer = [(None, None, None, None, ("::ffff:127.0.0.1", 443, 0, 0))]
        with patch("url_security.socket.getaddrinfo", return_value=answer):
            self.assertFalse(is_public_url("https://example.com/"))

    def test_ipv6_loopback_and_link_local_destinations_are_rejected(self):
        for address in ("::1", "fe80::1", "fc00::1"):
            with self.subTest(address=address):
                answer = [(None, None, None, None, (address, 443, 0, 0))]
                with patch("url_security.socket.getaddrinfo", return_value=answer):
                    self.assertFalse(is_public_url("https://example.com/"))

    def test_malformed_bracketed_ipv6_url_fails_closed(self):
        for url in ("https://[::1", "https://example.com:bad/", "https://example.com:99999/"):
            with self.subTest(url=url):
                self.assertFalse(is_public_url(url))

    def test_redirect_to_private_destination_is_revalidated_and_blocked(self):
        response = fake_response(
            headers={"Content-Type": "text/html", "Location": "https://127.0.0.1/admin"},
            status=302,
        )
        connection = fake_connection()
        with patch(
            "url_security._validated_destination",
            side_effect=[
                (urlparse("https://example.com/start"), ["93.184.216.34"]),
                ValueError("The URL points to a private or unsafe network address."),
            ],
        ) as validate, patch(
            "url_security._open_pinned_request", return_value=(connection, response)
        ) as open_request:
            with self.assertRaisesRegex(ValueError, "private or unsafe"):
                fetch_url_text("https://example.com/start")
        self.assertEqual(validate.call_count, 2)
        open_request.assert_called_once()
        response.close.assert_called_once()
        connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
