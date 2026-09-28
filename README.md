# Mirogate Boundary

[![Test and package](https://github.com/mirogate/mirogate-boundary/actions/workflows/test.yml/badge.svg)](https://github.com/mirogate/mirogate-boundary/actions/workflows/test.yml)

Local-first text egress guardrails for AI applications, with an Arabic-focused privacy evaluation suite.

**v0.1 is an experimental developer tool, not a security guarantee.** Detection can miss personal data, especially contextual, multilingual, obfuscated, or inferred information. Use synthetic inputs first. A request that passes the detector can still contain sensitive data.

Boundary separates three jobs: **detect locally → apply policy → forward only through an explicitly configured transport**. The default detector is hybrid (local OpenAI Privacy Filter plus deterministic rules); model setup is explicit, and failures never silently switch to rules-only mode.

## What ships

- Python library and `boundary` CLI: protect text files/stdin, run the benchmark, and verify receipt chains.
- Unicode-aware deterministic rules for structured identifiers, alongside an adapter for OpenAI's local Privacy Filter runtime and its Viterbi decoder.
- Policies: allow, tokenize, or block by detected category. Detected secrets always block.
- Opaque random placeholders with consistent mapping inside a bounded, expiring, in-memory vault.
- Authenticated loopback proxy for a deliberately small **text-only, non-streaming `/v1/chat/completions` subset**.
- Content-free decision receipts and hash-chain verification, including an optional independently stored head.
- Synthetic Arabic/mixed-language test cases with machine-readable detection metrics and explicit negative controls.

| Input or capability | v0.1 behavior |
| --- | --- |
| Text files / stdin | Local scan and pseudonymization |
| Text system, developer, user, assistant messages | Inspected by the proxy |
| Detected secret in a request | Request blocked before forwarding |
| Detector crash or invalid output | Request fails closed |
| Streaming, tools/tool calls, media, unknown request fields | Rejected; no passthrough |
| Restore visible assistant text | Explicit opt-in, same request only |
| Restore executable tool arguments | Unsupported |
| PDFs, OCR, arbitrary MCP traffic, Anthropic/Responses APIs | Unsupported |
| Traffic that bypasses this proxy | Outside the boundary |

## Quick start: no model download needed

Requires Python 3.11+. The core has no runtime dependencies beyond Python's standard library.

```bash
git clone https://github.com/mirogate/mirogate-boundary.git
cd mirogate-boundary
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# PowerShell: .\.venv\Scripts\Activate.ps1
python -m pip install -e .
boundary scan --detector rules --file examples/contact.txt
```

This explicitly chooses the **limited rules-only** detector. It does not download or run an AI model and is not adequate for general names or contextual personal data.

For an end-to-end demonstration with a local mock provider (zero external AI calls):

```bash
python examples/capture_demo.py
```

It displays the exact transformed body the mock provider received and checks local restoration. This is a transport demonstration using synthetic data, not a model-accuracy test.

The example output replaces the email and phone with random `<MB1_…>` placeholders. Tokens differ across runs. The text is **pseudonymized, not anonymized**. Context and undetected values may still identify someone.

```bash
boundary scan --detector rules --file examples/secret.txt
```

A detected secret returns `decision: block`, `text: null`, and exit code 2. Errors return exit code 3 without echoing the input. Scanning prints transformed text locally; your shell or calling application may record that output, so do not assume it is safe to log.

## Local model and hybrid mode

Follow [model setup](docs/model-setup.md) to install the pinned official runtime and checkpoint locally. Model files are downloaded only during explicit setup, not while protecting a request. No customer text is sent to a hosted detector.

```bash
boundary scan --detector hybrid --checkpoint checkpoints/privacy-filter --file examples/contact.txt
```

See the [evaluation report](docs/evaluation.md) for which execution paths were actually measured. Adapter tests alone are not model accuracy results.

## Python API

```python
from mirogate_boundary.core import Engine
from mirogate_boundary.detectors import RuleDetector

engine = Engine(RuleDetector())  # explicitly limited rules mode
result = engine.protect("Email: demo@example.com")
assert result.decision == "tokenize"
assert "demo@example.com" not in result.text
assert engine.vault.restore(result.text) == "Email: demo@example.com"
engine.vault.clear()
```

Do not send the vault to a provider. Create a new Engine for each trust domain. The proxy uses a fresh engine/vault per request; there is **no cross-request conversation memory**. Python cannot promise secure memory erasure, and swap/crash dumps are outside this tool's control.

## Text-only proxy

Generate a local credential with `boundary token`, set it as `BOUNDARY_LOCAL_TOKEN`, and set your provider key separately as `BOUNDARY_UPSTREAM_KEY`. Do not paste real credentials into issues or examples.

```bash
boundary proxy --detector hybrid --checkpoint checkpoints/privacy-filter \
  --upstream https://api.openai.com/v1/chat/completions
```

Point a compatible client at `http://127.0.0.1:8787/v1` using the **local** token, with streaming and tools disabled. The CLI accepts an explicit upstream endpoint; this example does not endorse a provider. [Proxy configuration, threat boundaries and examples](docs/proxy.md).

Unsupported fields cause an error; this intentionally does **not** claim drop-in compatibility with every agent or SDK. Do not make the proxy public or put real data through it until you have evaluated its misses on your own lawful test set. It is a local development server, not a hardened shared production service.

## Reproduce the evidence

```bash
python -m unittest discover -s tests -v
boundary bench --detector rules --dataset benchmarks/arabic-privacy-v0.1.jsonl \
  --output benchmarks/results/rules-local.json
```

Use the same dataset with `--detector opf` or `--detector hybrid` and an explicit checkpoint for model-backed runs. Read the [dataset card](benchmarks/README.md) and [evaluation report](docs/evaluation.md). These small synthetic cases are development evidence, not representative population estimates, independent certification, or a model leaderboard.

## Receipts without raw content

```bash
boundary scan --detector rules --file examples/contact.txt --receipts receipts.local.jsonl
boundary verify receipts.local.jsonl
# Store the returned head separately, then verify against that trusted copy:
boundary verify receipts.local.jsonl --expected-head YOUR_PREVIOUSLY_SAVED_HEAD
```

Receipts contain category counts, input character count and decision, never original values, transformed text, or text hashes. They are not zero-information: counts disclose limited metadata. Hash chaining detects unanchored edits, but an attacker with the file can rewrite the whole chain or truncate it. Only an independently trusted head helps detect those changes. Receipts do not prove that every network request used this proxy.

## Why Mirogate is building this

Our [Secure AI Engineering Framework](https://github.com/mirogate/secure-ai-engineering-framework) described data classification and routing. Boundary makes a narrow part executable and testable. Our [Arabic-Native Agent Bench](https://github.com/mirogate/arabic-native-agent-bench) established a related principle: Arabic behavior deserves native tests, not just translated English examples.

Credit to Abdullah Alsaidi's [Maskode](https://github.com/abdullahalsaidi16/maskode), whose local filtering work in an OpenCode fork inspired this exploration, and to [OpenAI Privacy Filter](https://github.com/openai/privacy-filter) and its [model card](https://huggingface.co/openai/privacy-filter). Boundary is independently implemented; it does not claim to be the first privacy proxy, a new foundation model, or endorsed by those projects.

## Contribute

The most valuable contributions are synthetic missed-entity cases, false-positive examples, Arabic dialect/transliteration coverage, and independently reproduced model-backed runs. Never submit actual customer records, real secrets, or identifying incident data. Read [CONTRIBUTING](CONTRIBUTING.md), [SECURITY](SECURITY.md), and the [threat model](docs/threat-model.md).

License: Apache-2.0 for code and synthetic corpus. See [LICENSE](LICENSE). Third-party runtimes and weights keep their own licenses; they are not bundled.
