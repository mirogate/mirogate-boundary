"""Network-boundary tests use local capture servers, never paid/cloud APIs."""

import contextlib
import http.client
import json
import socket
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

from mirogate_boundary.proxy import create_server


TOKEN = "local-test-token-" + "x" * 40
PLACEHOLDER = "<BOUNDARY_EMAIL_random>"


class FakeVault:
    def restore(self, text, strict=True):
        if "UNKNOWN_PLACEHOLDER" in text:
            raise ValueError("unknown reference")
        return text.replace(PLACEHOLDER, "alice@example.com")


class FakeEngine:
    def __init__(self):
        self.vault = FakeVault()

    def protect(self, text):
        if "DETECTOR_ERROR" in text:
            raise RuntimeError("exception must never leak alice@example.com")
        if "SECRET_KEY" in text:
            return SimpleNamespace(text=None, decision="block", receipt={"decision": "block"})
        masked = text.replace("alice@example.com", PLACEHOLDER)
        return SimpleNamespace(
            text=masked, decision="allow" if masked == text else "tokenize",
            receipt={"decision": "allow" if masked == text else "tokenize"},
        )


@contextlib.contextmanager
def capture_upstream(mode="echo"):
    captured = []

    class Capture(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            raw = self.rfile.read(int(self.headers["Content-Length"]))
            body = json.loads(raw)
            captured.append((dict(self.headers), body, raw))
            if mode == "redirect":
                self.send_response(307)
                self.send_header("Location", "/redirected")
                self.end_headers()
                return
            if mode == "error":
                self.send_response(429)
                self.end_headers()
                self.wfile.write(b"provider secret response must not escape")
                return
            content = body["messages"][-1]["content"]
            if mode == "unknown":
                content = "UNKNOWN_PLACEHOLDER"
            if mode == "foreign_token":
                content = "<MB1_" + "f" * 32 + ">"
            if mode == "repeat":
                content *= 3000
            if mode == "large":
                content = "x" * 4096
            result = {
                "id": "test", "object": "chat.completion", "created": 1,
                "model": body["model"], "choices": [{
                    "index": 0, "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }],
            }
            if mode == "tools":
                result["choices"][0]["message"]["tool_calls"] = [{"name": "unsafe"}]
            raw = json.dumps(result).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = HTTPServer(("127.0.0.1", 0), Capture)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v1/chat/completions", captured
    finally:
        server.shutdown()
        server.server_close()
        worker.join(2)


@contextlib.contextmanager
def gateway(upstream_url, **kwargs):
    factory = kwargs.pop("engine_factory", FakeEngine)
    server = create_server(factory, upstream_url, "upstream-only-key", TOKEN, port=0, **kwargs)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        worker.join(2)


def send(port, body=None, *, headers=None, raw=None, path="/v1/chat/completions", method="POST"):
    actual_headers = {"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"}
    actual_headers.update(headers or {})
    if raw is None:
        raw = json.dumps(body or {
            "model": "example-model", "messages": [{"role": "user", "content": "alice@example.com"}],
        }).encode()
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request(method, path, body=raw, headers=actual_headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


class ProxyTests(unittest.TestCase):
    def test_only_masked_text_reaches_upstream_and_credentials_are_separate(self):
        receipts = []
        with capture_upstream() as (url, captured), gateway(url, receipt_sink=receipts.append) as port:
            status, body = send(port)
        self.assertEqual(status, 200)
        headers, request, raw = captured[0]
        self.assertNotIn(b"alice@example.com", raw)
        self.assertEqual(request["messages"][0]["content"], PLACEHOLDER)
        self.assertEqual(headers["Authorization"], "Bearer upstream-only-key")
        self.assertNotIn(TOKEN, str(headers))
        self.assertEqual(body["choices"][0]["message"]["content"], PLACEHOLDER)
        self.assertNotIn("alice@example.com", str(receipts))

    def test_opt_in_restores_display_content(self):
        with capture_upstream() as (url, captured), gateway(url, restore=True) as port:
            status, body = send(port)
        self.assertEqual(status, 200)
        self.assertEqual(body["choices"][0]["message"]["content"], "alice@example.com")
        self.assertNotIn(b"alice@example.com", captured[0][2])

    def test_actual_rule_engine_arabic_roundtrip_and_fresh_vault_cleanup(self):
        from mirogate_boundary.core import Engine
        from mirogate_boundary.detectors import RuleDetector
        engines = []
        def factory():
            engine = Engine(RuleDetector())
            engines.append(engine)
            return engine
        original = "اسم العميل: ليلى منصور\nالبريد: layla@example.com\nالهاتف: +٩٦٦٥٥١٢٣٤٥٦٧"
        with capture_upstream() as (url, captured), gateway(url, restore=True, engine_factory=factory) as port:
            status, result = send(port, {"model": "model", "messages": [{"role": "user", "content": original}]})
        self.assertEqual(status, 200)
        self.assertEqual(result["choices"][0]["message"]["content"], original)
        sent = captured[0][1]["messages"][0]["content"]
        for private in ("ليلى منصور", "layla@example.com", "+٩٦٦٥٥١٢٣٤٥٦٧"):
            self.assertNotIn(private, sent)
        with self.assertRaises(ValueError):
            engines[0].vault.restore(sent)

    def test_actual_secret_detection_blocks_and_records_metadata(self):
        from mirogate_boundary.core import Engine
        from mirogate_boundary.detectors import RuleDetector
        receipts = []
        with capture_upstream() as (url, captured), gateway(
            url, engine_factory=lambda: Engine(RuleDetector()), receipt_sink=receipts.append,
        ) as port:
            status, _ = send(port, {"model": "model", "messages": [{
                "role": "user", "content": "api_key: sk-proj-abcdefghijk12345678901234567890",
            }]})
        self.assertEqual(status, 403)
        self.assertEqual(captured, [])
        self.assertEqual(receipts[-1]["decision"], "block")
        self.assertNotIn("abcdefghijk", str(receipts))

    def test_block_and_detector_error_never_reach_provider(self):
        with capture_upstream() as (url, captured), gateway(url) as port:
            for content, expected in [("SECRET_KEY", 403), ("DETECTOR_ERROR", 503)]:
                with self.subTest(content=content):
                    status, body = send(port, {"model": "model", "messages": [{"role": "user", "content": content}]})
                    self.assertEqual(status, expected)
                    self.assertNotIn("alice@example.com", str(body))
            self.assertEqual(captured, [])

    def test_unsupported_payloads_never_reach_provider(self):
        with capture_upstream() as (url, captured), gateway(url) as port:
            messages = [{"role": "user", "content": "safe"}]
            for extra in ({"tools": []}, {"metadata": {"name": "secret"}}, {"stream": True}, {"stop": "secret"}, {"n": 2}):
                with self.subTest(extra=extra):
                    self.assertEqual(send(port, {"model": "model", "messages": messages, **extra})[0], 422)
            for message in (
                {"role": "user", "content": [{"type": "image_url", "image_url": "https://example.com"}]},
                {"role": "tool", "content": "secret"},
                {"role": "user", "content": "safe", "name": "secret"},
                {"role": "assistant", "content": "safe", "tool_calls": []},
            ):
                self.assertEqual(send(port, {"model": "model", "messages": [message]})[0], 422)
            self.assertEqual(captured, [])

    def test_system_developer_user_and_assistant_are_all_scanned(self):
        with capture_upstream() as (url, captured), gateway(url) as port:
            status, _ = send(port, {"model": "model", "messages": [
                {"role": role, "content": "alice@example.com"}
                for role in ("system", "developer", "user", "assistant")
            ]})
        self.assertEqual(status, 200)
        self.assertNotIn(b"alice@example.com", captured[0][2])

    def test_sensitive_model_identifier_is_blocked(self):
        with capture_upstream() as (url, captured), gateway(url) as port:
            status, _ = send(port, {"model": "SECRET_KEY", "messages": [{"role": "user", "content": "safe"}]})
        self.assertEqual(status, 422)
        self.assertEqual(captured, [])

    def test_auth_origin_host_and_media_type_checks(self):
        with capture_upstream() as (url, captured), gateway(url) as port:
            for headers, expected in (
                ({"Authorization": "Bearer wrong"}, 401),
                ({"Origin": "https://evil.example"}, 403),
                ({"Host": "evil.example"}, 403),
                ({"Content-Type": "text/plain"}, 415),
                ({"Content-Encoding": "gzip"}, 415),
                ({"Transfer-Encoding": "chunked"}, 415),
            ):
                with self.subTest(headers=headers):
                    self.assertEqual(send(port, headers=headers)[0], expected)
            self.assertEqual(captured, [])

    def test_repeated_early_rejections_return_stable_status_with_split_writes(self):
        # http.client sends request headers and the body separately. Closing with
        # that body unread caused intermittent Windows TCP-reset/lost-response
        # failures; errors must remain visible, not be swallowed by the test.
        with capture_upstream() as (url, captured), gateway(url) as port:
            for attempt in range(20):
                for headers, expected in (
                    ({"Authorization": "Bearer wrong"}, 401),
                    ({"Host": "evil.example"}, 403),
                    ({"Content-Type": "text/plain"}, 415),
                ):
                    with self.subTest(attempt=attempt, headers=headers):
                        status, body = send(port, headers=headers)
                        self.assertEqual(status, expected)
                        self.assertIn("error", body)
            self.assertEqual(captured, [])

    def test_unauthorized_incomplete_huge_body_does_not_hold_gateway(self):
        with capture_upstream() as (url, captured), gateway(url) as port:
            stalled = socket.create_connection(("127.0.0.1", port), timeout=2)
            try:
                stalled.sendall((
                    f"POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                    "Authorization: Bearer wrong\r\nContent-Type: application/json\r\n"
                    "Content-Length: 999999999\r\n\r\n"
                ).encode())
                # Keep the rejected socket open without providing the promised
                # body or reading its response; the serial server must move on.
                started = time.monotonic()
                self.assertEqual(send(port)[0], 200)
                self.assertLess(time.monotonic() - started, 1.5)
                self.assertEqual(len(captured), 1)
            finally:
                stalled.close()

    def test_invalid_json_duplicate_keys_and_nan(self):
        with capture_upstream() as (url, captured), gateway(url) as port:
            for raw in (b'{"model":"x","model":"y"}', b'{"temperature":NaN}', b'bad json', b'\xff'):
                with self.subTest(raw=raw[:64]):
                    self.assertEqual(send(port, raw=raw)[0], 400)
            # Python versions differ in the JSON nesting limit. Either parser
            # rejection or strict-schema rejection must happen before egress.
            self.assertIn(send(port, raw=b'[' * 2000 + b']' * 2000)[0], (400, 422))
            self.assertEqual(captured, [])

    def test_lone_surrogate_content_is_rejected_before_inference(self):
        with capture_upstream() as (url, captured), gateway(url) as port:
            status, _ = send(port, raw=b'{"model":"model","messages":[{"role":"user","content":"\\ud800"}]}')
            self.assertEqual(status, 422)
            self.assertEqual(captured, [])

    def test_request_size_and_endpoint_limits(self):
        with capture_upstream() as (url, captured), gateway(url, max_request_bytes=16) as port:
            self.assertEqual(send(port)[0], 413)
            self.assertEqual(send(port, path="/v1/responses")[0], 404)
            self.assertEqual(send(port, path="/v1/chat/completions?leak=value")[0], 404)
            self.assertEqual(captured, [])

    def test_redirect_is_never_followed(self):
        with capture_upstream("redirect") as (url, captured), gateway(url) as port:
            status, _ = send(port)
        self.assertEqual(status, 502)
        self.assertEqual(len(captured), 1)

    def test_provider_errors_are_scrubbed(self):
        with capture_upstream("error") as (url, captured), gateway(url) as port:
            status, body = send(port)
        self.assertEqual(status, 502)
        self.assertNotIn("provider secret", str(body))

    def test_upstream_tool_actions_and_unknown_restoration_rejected(self):
        for mode in ("tools", "unknown"):
            with self.subTest(mode=mode), capture_upstream(mode) as (url, captured), gateway(url, restore=True) as port:
                self.assertEqual(send(port)[0], 502)

    def test_upstream_response_size_limit(self):
        with capture_upstream("large") as (url, captured), gateway(url, max_response_bytes=512) as port:
            status, _ = send(port)
        self.assertEqual(status, 502)

    def test_actual_vault_rejects_foreign_tokens_and_expansion(self):
        from mirogate_boundary.core import Engine, Span
        class TestDetector:
            def detect(self, text):
                return [] if text == "model" else [Span(0, len(text), "private_person", "test")]
        for mode in ("foreign_token", "repeat"):
            with self.subTest(mode=mode), capture_upstream(mode) as (url, captured), gateway(
                url, restore=True, engine_factory=lambda: Engine(TestDetector()),
            ) as port:
                status, _ = send(port, {"model": "model", "messages": [{
                    "role": "user", "content": "A" * 500,
                }]})
                self.assertEqual(status, 502)

    def test_receipt_failure_prevents_egress(self):
        def failed_sink(receipt):
            raise OSError("no audit storage")
        with capture_upstream() as (url, captured), gateway(url, receipt_sink=failed_sink) as port:
            self.assertEqual(send(port)[0], 503)
            self.assertEqual(captured, [])

    def test_fresh_engine_per_request(self):
        created = []
        def factory():
            engine = FakeEngine()
            created.append(engine)
            return engine
        with capture_upstream() as (url, captured):
            server = create_server(factory, url, None, TOKEN, port=0)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                self.assertEqual(send(server.server_port)[0], 200)
                self.assertEqual(send(server.server_port)[0], 200)
            finally:
                server.shutdown()
                server.server_close()
                worker.join(2)
        self.assertEqual(len(created), 2)
        self.assertIsNot(created[0].vault, created[1].vault)

    def test_unsafe_configuration_rejected(self):
        for kwargs in (
            {"host": "0.0.0.0"}, {"local_token": "short"},
            {"upstream_url": "http://api.example.com/v1/chat/completions"},
            {"upstream_url": "https://user:password@example.com/v1/chat/completions"},
            {"upstream_url": "https://example.com/v1/chat/completions?key=secret"},
            {"upstream_url": "https://example.com/other"},
            {"upstream_key": "injected\r\nHeader: value"},
        ):
            config = dict(engine_factory=FakeEngine, upstream_url="https://api.example.com/v1/chat/completions", upstream_key=None, local_token=TOKEN, port=0)
            config.update(kwargs)
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                create_server(**config)


if __name__ == "__main__":
    unittest.main()
