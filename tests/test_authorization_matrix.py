"""Every API route must be listed in docs/AUTHORIZATION_MATRIX.md and authenticated unless explicitly public."""
import re
import unittest
from pathlib import Path

import satark_backend

DOC = (Path(__file__).resolve().parent.parent / "docs" / "AUTHORIZATION_MATRIX.md").read_text(encoding="utf-8")
PUBLIC = {
    "/api/health", "/api/health/storage",
    "/api/auth/email-verification/request", "/api/auth/email-verification/complete",
    "/api/auth/signup", "/api/auth/login",
    "/api/auth/password-reset/request", "/api/auth/password-reset/complete",
}


def routes():
    for route in satark_backend.router.routes:
        for method in sorted((getattr(route, "methods", None) or set()) - {"HEAD", "OPTIONS"}):
            yield method, route.path, [getattr(d.call, "__name__", "") for d in route.dependant.dependencies]


class AuthorizationMatrixTests(unittest.TestCase):
    def test_every_route_is_documented(self):
        rows = set(re.findall(r"^\| (\w+) \| (\S+) \|", DOC, re.M))
        for method, path, _ in routes():
            self.assertIn((method, path), rows, f"{method} {path} missing from AUTHORIZATION_MATRIX.md")

    def test_documented_routes_exist(self):
        actual = {(m, p) for m, p, _ in routes()}
        for method, path in re.findall(r"^\| (\w+) \| (\S+) \|", DOC, re.M):
            if method in {"GET", "POST", "PATCH", "DELETE"}:
                self.assertIn((method, path), actual, f"{method} {path} documented but not implemented")

    def test_non_public_routes_require_authentication(self):
        for method, path, deps in routes():
            if path not in PUBLIC:
                self.assertIn("current_user", deps, f"{method} {path} must require authentication")


if __name__ == "__main__":
    unittest.main()
