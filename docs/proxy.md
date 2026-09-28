# Opt-in text-chat gateway

The first release provides a deliberately narrow local gateway for applications
that can use an OpenAI-compatible chat-completions endpoint. Configure your client
to send to `http://127.0.0.1:8787/v1/chat/completions`, using the gateway's local
bearer token. The provider credential belongs only in the gateway configuration.

This gateway protects requests actually sent through it. It does **not** intercept
other processes, direct provider requests, telemetry, shell commands, MCP traffic,
file uploads, or arbitrary network traffic. It is not an operating-system firewall.
Detection can miss sensitive information. Replacing detected spans is reversible
pseudonymization, not a claim of anonymity or regulatory compliance.

## Supported contract

- Only `POST /v1/chat/completions`, with JSON and an explicit `Content-Length`.
- Required `model` and `messages`. Every message must have exactly `role` and
  string `content`; roles: `system`, `developer`, `user`, `assistant`.
- Optional numeric parameters: `temperature`, `top_p`, `max_tokens`,
  `max_completion_tokens`, `seed`; optional `n: 1` and `stream: false`.
- Every message's content is inspected. The model identifier is also inspected;
  a model identifier needing masking is rejected instead of modified.
- Unknown fields, metadata, message names, tool calls/results, content arrays,
  images, audio, file references, JSON schemas, and streaming are rejected.
- Unsupported response message structures and action-bearing tool calls are
  rejected. The gateway does not execute tools or interpret model output.

The allowlist is intentionally small. A client that automatically adds extra
parameters must disable them before it can use this release. Detector context is
per message; information whose sensitivity is only apparent across messages may
be missed. All messages in one request share a fresh token vault for consistency.
Separate requests never share a vault, so no persistent conversation mapping is
promised. Clients must resubmit original local history for each request, where it
is inspected again. Do not store masked provider history as an authoritative
source of sensitive values.

## Local security controls

The server accepts loopback bindings only, requires a bearer token with at least
32 printable ASCII characters, checks tokens in constant time, rejects browser
`Origin` headers, and validates the local `Host` header. Generate the local token
with a cryptographic random generator; length alone does not provide entropy.
Never publish it or reuse a provider API key as the local token.

Only one explicitly configured upstream endpoint is used. It must be HTTPS,
except that plain HTTP is permitted for a loopback test/local model endpoint.
Embedded URL credentials, query strings, and redirects are rejected. The local
authorization header is never forwarded. Environment proxy variables are not
used, avoiding an implicit additional destination. No incoming headers are copied
to the provider; only JSON content type, accept, and the separately configured
provider authorization are sent.

Default limits are 1 MiB incoming JSON, 256 messages, 2 MiB upstream response, and
30-second network socket timeouts. Processing is serial to prevent unbounded
parallel inference; this is a local developer tool, not a multi-tenant service.
Early HTTP rejection half-closes the response and discards at most 64 KiB for at
most 50 ms to avoid losing the error response to a Windows TCP reset; it never
waits for an unauthorized request's declared body length. Socket timeouts are
inactivity limits, not whole-request or model-inference CPU deadlines.
Local processes able to read your environment, process memory, or token can use
the gateway. Those processes are outside its trust boundary.

Any detector error, policy block, invalid payload, or receipt-sink error before
the provider call prevents that request from being sent. A provider error after
sending cannot undo that already-completed transmission. Errors use fixed codes;
request content, provider error bodies, and request paths are not logged. Receipt
sinks receive only the engine's sanitized receipt, never the incoming body.

## Response restoration is off by default

By default the client receives provider text with placeholders intact. Explicitly
enabling restoration restores recognized request-local tokens only inside
`choices[].message.content`. It does not restore refusal fields, tool arguments,
URLs in metadata, or arbitrary JSON fields. Unknown/invalid token references fail
the response rather than requesting values from another session. Restoration
does not make generated content trustworthy: treat display text as untrusted,
and never pass it to tools or execute it without a separate authorization layer.

## Python API

For a live-provider example, configure the local process environment (not a checked-in
file). Generate `BOUNDARY_LOCAL_TOKEN` with `boundary token`; set the separate
`BOUNDARY_UPSTREAM_KEY` to your own provider credential. Start the server with the
explicit endpoint in README.md. In another terminal, set the same local token and
`BOUNDARY_MODEL` to a model identifier supported by your provider, then run:

```sh
python examples/client.py
```

Unlike `examples/capture_demo.py`, this sends the transformed synthetic prompt to
your configured provider and may incur provider charges. It has not been validated
against a paid provider endpoint in this release; compatibility is tested against
the documented request/response subset with local capture servers. No provider key
is required for the capture demo, unit tests or synthetic local-model evaluation.

For embedding:

```python
from mirogate_boundary.proxy import serve

# Make a new Engine and Vault on each call; a detector may be reused only if its
# implementation allows that. Load model weights before opening the server.
serve(
    engine_factory=make_fresh_engine,
    upstream_url="https://api.openai.com/v1/chat/completions",
    upstream_key=provider_key,
    local_token=random_local_token,
    restore=False,
)
```

`create_server(...)` has the same arguments and returns a bound server for
embedding/tests. Call `serve_forever()`, then `shutdown()` from another thread and
`server_close()`. Additional test/embedding options are `timeout`,
`max_request_bytes`, and `max_response_bytes`. Proxy tests use a local capture
server and fake detector to test the transport independently of model accuracy.
They are not evidence of real-detector recall or a production security audit.
