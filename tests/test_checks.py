"""Unit tests for the OpenAPI checks and live probing.

Run from the project root:  python3 -m unittest discover -s tests -v
"""

import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.checks import check_spec
from api.probe import probe_spec


def spec_with(paths, servers=None):
    return {"openapi": "3.0.0", "paths": paths,
            "servers": servers or []}


class TestChecks(unittest.TestCase):
    def test_unauthenticated_is_high(self):
        spec = spec_with({"/open": {"get": {"operationId": "o1",
                                            "responses": {"200": {},
                                                          "429": {}}}}})
        findings = check_spec(spec)
        self.assertTrue(any(f["check"] == "no-auth-required"
                            for f in findings))

    def test_authenticated_is_clean(self):
        spec = spec_with({"/closed": {"get": {
            "operationId": "o1", "security": [{"BearerAuth": []}],
            "responses": {"200": {}, "429": {}}}}})
        self.assertEqual(check_spec(spec), [])

    def test_plaintext_server(self):
        spec = spec_with({}, [{"url": "http://api.acme.example"}])
        findings = check_spec(spec)
        self.assertTrue(any(f["check"] == "plaintext-server"
                            for f in findings))

    def test_sensitive_response_field(self):
        schema = {"type": "object",
                  "properties": {"password": {"type": "string"}}}
        spec = spec_with({"/u": {"get": {
            "operationId": "o1", "security": [{"ApiKeyAuth": []}],
            "responses": {"200": {"content": {
                "application/json": {"schema": schema}}}, "429": {}}}}})
        findings = check_spec(spec)
        self.assertTrue(any(f["check"] == "sensitive-data-exposed"
                            for f in findings))

    def test_missing_rate_limit(self):
        spec = spec_with({"/x": {"get": {
            "operationId": "o1", "security": [{"ApiKeyAuth": []}],
            "responses": {"200": {}}}}})
        findings = check_spec(spec)
        self.assertTrue(any(f["check"] == "no-rate-limit"
                            for f in findings))


class TestProbe(unittest.TestCase):
    def _server(self, status_by_prefix):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                for prefix, status in status_by_prefix.items():
                    if self.path.startswith(prefix):
                        self.send_response(status)
                        self.end_headers()
                        self.wfile.write(b"{}")
                        return
                self.send_response(404)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server

    def test_public_endpoint_flagged(self):
        server = self._server({"/pets": 200, "/users": 401})
        try:
            spec = spec_with({
                "/pets": {"get": {"operationId": "o1", "responses": {}}},
                "/users/{id}": {"get": {"operationId": "o2",
                                        "responses": {}}}})
            findings, errors = probe_spec(
                spec, f"http://127.0.0.1:{server.server_address[1]}")
            self.assertEqual(
                [(f["check"], f["object"]) for f in findings],
                [("endpoint-public", "GET /pets")])
            self.assertEqual(errors, [])
        finally:
            server.shutdown()


if __name__ == "__main__":
    unittest.main()
