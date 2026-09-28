"""A deliberately narrow, opt-in, loopback text-chat egress gateway.

This is not an operating-system firewall. Applications must explicitly send
requests here; unsupported API shapes fail closed instead of passing through.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import math
import re
import socket
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

MAX_REQUEST_BYTES = 1_048_576
MAX_RESPONSE_BYTES = 2_097_152
DEFAULT_TIMEOUT = 30.0
_ROLES = {"system", "developer", "user", "assistant"}
_FIELDS = {
    "model", "messages", "temperature", "top_p", "max_tokens",
    "max_completion_tokens", "seed", "n", "stream",
}


class _Rejected(Exception):
    def __init__(self, status: int, code: str) -> None:
        self.status = status
        self.code = code


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("non-finite JSON number")


def _json_loads(raw: bytes):
    return json.loads(
        raw.decode("utf-8"), object_pairs_hook=_unique_object,
        parse_constant=_invalid_constant,
    )


def _number(value: Any, low: float, high: float, *, integer=False) -> bool:
    if isinstance(value, bool) or not isinstance(value, int if integer else (int, float)):
        return False
    try:
        return math.isfinite(value) and low <= value <= high
    except OverflowError:
        return False


def _validate_request(body: Any) -> None:
    if not isinstance(body, dict) or not {"model", "messages"} <= body.keys():
        raise _Rejected(422, "invalid_chat_schema")
    if body.keys() - _FIELDS:
        raise _Rejected(422, "unsupported_request_field")
    model = body["model"]
    if not isinstance(model, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}", model):
        raise _Rejected(422, "invalid_model")
    messages = body["messages"]
    if not isinstance(messages, list) or not 1 <= len(messages) <= 256:
        raise _Rejected(422, "invalid_messages")
    for message in messages:
        if not isinstance(message, dict) or set(message) != {"role", "content"}:
            raise _Rejected(422, "unsupported_message_shape")
        if not isinstance(message["role"], str) or message["role"] not in _ROLES or not isinstance(message["content"], str):
            raise _Rejected(422, "unsupported_message_content")
        if any(0xD800 <= ord(char) <= 0xDFFF for char in message["content"]):
            raise _Rejected(422, "invalid_unicode_text")
    for key, low, high, integer in (
        ("temperature", 0, 2, False), ("top_p", 0, 1, False),
        ("max_tokens", 1, 1_000_000, True),
        ("max_completion_tokens", 1, 1_000_000, True),
        ("seed", -(2**63), 2**63 - 1, True), ("n", 1, 1, True),
    ):
        if key in body and not _number(body[key], low, high, integer=integer):
            raise _Rejected(422, "unsupported_parameter_value")
    if "stream" in body and body["stream"] is not False:
        raise _Rejected(422, "streaming_not_supported")


def _response_content(body: Any) -> list[dict]:
    """Reject actionable/structured outputs; return assistant display messages."""
    if not isinstance(body, dict) or not isinstance(body.get("choices"), list):
        raise _Rejected(502, "invalid_upstream_response")
    if len(body["choices"]) != 1:
        raise _Rejected(502, "unsupported_upstream_response")
    messages = []
    for choice in body["choices"]:
        if not isinstance(choice, dict):
            raise _Rejected(502, "unsupported_upstream_response")
        if choice.get("finish_reason") not in (None, "stop", "length", "content_filter"):
            raise _Rejected(502, "unsupported_upstream_response")
        message = choice.get("message")
        if not isinstance(message, dict) or message.get("role") != "assistant":
            raise _Rejected(502, "unsupported_upstream_response")
        if message.keys() - {"role", "content", "refusal"}:
            raise _Rejected(502, "unsupported_upstream_response")
        if not isinstance(message.get("content"), (str, type(None))):
            raise _Rejected(502, "unsupported_upstream_response")
        if not isinstance(message.get("refusal"), (str, type(None))):
            raise _Rejected(502, "unsupported_upstream_response")
        messages.append(message)
    return messages


class BoundaryHTTPServer(HTTPServer):
    """Serial by design: no unbounded inference threads or shared request vaults."""

    allow_reuse_address = True
    request_queue_size = 8

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(self.boundary_timeout)
        return connection, address

    def handle_error(self, request, client_address):
        # Never let stdlib error tracebacks disclose request paths or payloads.
        return


def create_server(
    engine_factory: Callable[[], Any], upstream_url: str, upstream_key: str | None,
    local_token: str, host: str = "127.0.0.1", port: int = 8787,
    restore: bool = False, receipt_sink: Callable[[dict], None] | None = None,
    *, timeout: float = DEFAULT_TIMEOUT, max_request_bytes: int = MAX_REQUEST_BYTES,
    max_response_bytes: int = MAX_RESPONSE_BYTES,
) -> BoundaryHTTPServer:
    """Validate configuration and bind locally; caller owns serve/shutdown.

    ``upstream_url`` is the complete endpoint URL, e.g.
    ``https://api.openai.com/v1/chat/completions``. Configuring it explicitly
    authorizes that one destination; client-supplied URLs are never accepted.
    The factory MUST supply a fresh Engine with a fresh Vault for each request.
    """
    if not isinstance(host, str) or not _loopback(host):
        raise ValueError("gateway must bind to a loopback address")
    if not isinstance(local_token, str) or len(local_token) < 32 or not local_token.isascii():
        raise ValueError("local token must contain at least 32 ASCII characters")
    if any(ch.isspace() or ord(ch) < 33 or ord(ch) > 126 for ch in local_token):
        raise ValueError("local token must not contain whitespace or control characters")
    if upstream_key is not None and (
        not isinstance(upstream_key, str) or "\r" in upstream_key or "\n" in upstream_key
    ):
        raise ValueError("invalid provider credential")
    try:
        target = urlsplit(upstream_url)
        target.port  # Access validates an explicitly supplied port.
    except (ValueError, TypeError):
        raise ValueError("invalid upstream endpoint") from None
    if (
        target.scheme not in {"http", "https"} or not target.hostname
        or target.username is not None or target.password is not None
        or target.query or target.fragment or target.path != "/v1/chat/completions"
        or (target.scheme == "http" and not _loopback(target.hostname))
        or any(ch.isspace() or ord(ch) < 32 for ch in upstream_url)
    ):
        raise ValueError("upstream must be HTTPS or loopback HTTP with /v1/chat/completions")
    if not _number(timeout, 0.1, 300) or not _number(max_request_bytes, 1, 16_777_216, integer=True):
        raise ValueError("invalid request limits")
    if not _number(max_response_bytes, 1, 16_777_216, integer=True):
        raise ValueError("invalid response limit")
    opener = build_opener(ProxyHandler({}), _NoRedirects())

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"
        server_version = "MirogateBoundary"
        sys_version = ""

        def log_message(self, format, *args):
            return

        def _reply(self, status, body):
            raw = json.dumps(body, ensure_ascii=True, allow_nan=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(raw)
            self.close_connection = True
            if status >= 400 and not getattr(self, "_body_consumed", False):
                self._finish_early_rejection()

        def _finish_early_rejection(self):
            """Send FIN before closing an unread request, without trusting its size.

            Windows can discard a response with a TCP reset if the client sent
            headers and body separately and we close with unread incoming bytes.
            Half-close the response, then discard at most 64 KiB for at most 50 ms.
            No parsing, authentication, inference or logging happens during drain.
            A malicious/incomplete sender still loses the connection at the bound.
            """
            try:
                self.wfile.flush()
                self.connection.shutdown(socket.SHUT_WR)
                deadline = time.monotonic() + 0.05
                remaining_bytes = 65_536
                while remaining_bytes:
                    remaining_time = deadline - time.monotonic()
                    if remaining_time <= 0:
                        break
                    self.connection.settimeout(remaining_time)
                    discarded = self.connection.recv(min(4096, remaining_bytes))
                    if not discarded:
                        break
                    remaining_bytes -= len(discarded)
            except (OSError, TimeoutError):
                # The response was already sent; no second response or raw error.
                pass

        def send_error(self, code, message=None, explain=None):
            self._reply(code, {"error": {"code": "invalid_http_request"}})

        def do_POST(self):
            try:
                self._post()
            except _Rejected as exc:
                self._reply(exc.status, {"error": {"code": exc.code}})
            except (TimeoutError, socket.timeout):
                self._reply(408, {"error": {"code": "request_timeout"}})
            except (BrokenPipeError, ConnectionResetError):
                self.close_connection = True
            except Exception:
                self._reply(503, {"error": {"code": "boundary_unavailable"}})

        def _post(self):
            if self.path != "/v1/chat/completions":
                raise _Rejected(404, "unsupported_endpoint")
            if self.headers.get_all("Origin"):
                raise _Rejected(403, "browser_origin_not_allowed")
            host_values = self.headers.get_all("Host", [])
            expected_port = self.server.server_address[1]
            allowed_hosts = {
                f"127.0.0.1:{expected_port}", f"localhost:{expected_port}",
                f"[{host}]:{expected_port}" if ":" in host else f"{host}:{expected_port}",
            }
            if len(host_values) != 1 or host_values[0].lower() not in allowed_hosts:
                raise _Rejected(403, "invalid_local_host")
            auth = self.headers.get_all("Authorization", [])
            expected = ("Bearer " + local_token).encode("ascii")
            if len(auth) != 1 or not hmac.compare_digest(auth[0].encode("utf-8"), expected):
                raise _Rejected(401, "local_authorization_required")
            if self.headers.get_all("Transfer-Encoding") or self.headers.get_all("Content-Encoding"):
                raise _Rejected(415, "encoded_requests_not_supported")
            content_types = self.headers.get_all("Content-Type", [])
            if len(content_types) != 1 or content_types[0].lower().strip() not in {
                "application/json", "application/json; charset=utf-8",
            }:
                raise _Rejected(415, "json_content_type_required")
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,10}", lengths[0]):
                raise _Rejected(411, "valid_content_length_required")
            length = int(lengths[0])
            if not 0 < length <= max_request_bytes:
                raise _Rejected(413, "request_size_limit")
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise _Rejected(400, "incomplete_request")
            self._body_consumed = True
            try:
                body = _json_loads(raw)
            except (ValueError, UnicodeError, RecursionError):
                raise _Rejected(400, "invalid_json") from None
            _validate_request(body)
            engine = engine_factory()
            try:
                self._exchange(body, engine)
            finally:
                # Best-effort immediate release, not a memory-zeroization claim.
                clear = getattr(engine.vault, "clear", None)
                if clear is not None:
                    try:
                        clear()
                    except Exception:
                        self.close_connection = True

        def _record(self, receipts):
            if receipt_sink is not None:
                for receipt in receipts:
                    receipt_sink(receipt)

        def _exchange(self, body, engine):
            # The configured model identifier is not exempt from inspection.
            model_result = engine.protect(body["model"])
            if model_result.decision != "allow" or model_result.text != body["model"]:
                self._record([model_result.receipt])
                raise _Rejected(422, "sensitive_model_identifier")
            receipts = [model_result.receipt]
            for message in body["messages"]:
                result = engine.protect(message["content"])
                receipts.append(result.receipt)
                if result.decision == "block" or result.text is None:
                    self._record(receipts)
                    raise _Rejected(403, "policy_blocked")
                if result.decision not in {"allow", "tokenize"} or not isinstance(result.text, str):
                    raise _Rejected(503, "invalid_protection_result")
                message["content"] = result.text
            self._record(receipts)
            sanitized = json.dumps(body, ensure_ascii=True, allow_nan=False).encode("utf-8")
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
            if upstream_key:
                headers["Authorization"] = "Bearer " + upstream_key
            request = Request(upstream_url, data=sanitized, headers=headers, method="POST")
            try:
                with opener.open(request, timeout=timeout) as response:
                    if response.getcode() != 200 or response.headers.get_content_type() != "application/json":
                        raise _Rejected(502, "unsupported_upstream_response")
                    if response.headers.get("Content-Encoding") not in (None, "identity"):
                        raise _Rejected(502, "encoded_upstream_response")
                    upstream_bytes = response.read(max_response_bytes + 1)
            except (HTTPError, URLError, TimeoutError, socket.timeout):
                raise _Rejected(502, "upstream_request_failed") from None
            if len(upstream_bytes) > max_response_bytes:
                raise _Rejected(502, "upstream_response_size_limit")
            try:
                upstream_body = _json_loads(upstream_bytes)
            except (ValueError, UnicodeError, RecursionError):
                raise _Rejected(502, "invalid_upstream_json") from None
            display_messages = _response_content(upstream_body)
            if restore:
                for message in display_messages:
                    if isinstance(message.get("content"), str):
                        try:
                            message["content"] = engine.vault.restore(message["content"], strict=True)
                        except Exception:
                            raise _Rejected(502, "unsafe_restoration_reference") from None
            self._reply(200, upstream_body)

    server_type = BoundaryHTTPServer
    if ":" in host:
        class IPv6BoundaryHTTPServer(BoundaryHTTPServer):
            address_family = socket.AF_INET6
        server_type = IPv6BoundaryHTTPServer
    server = server_type((host, port), Handler)
    server.boundary_timeout = float(timeout)
    return server


def serve(
    engine_factory, upstream_url, upstream_key, local_token, host="127.0.0.1",
    port=8787, restore=False, receipt_sink=None,
):
    """Run until interrupted. Configuration errors are raised before serving."""
    server = create_server(
        engine_factory, upstream_url, upstream_key, local_token, host, port,
        restore, receipt_sink,
    )
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
