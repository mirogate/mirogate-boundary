# Mirogate Boundary v0.1.0 — experimental developer release

Local-first text egress policies and an Arabic-focused privacy diagnostic corpus.

## Included

- Dependency-free Python core, CLI, request-local token vault and configurable detected-category policy; detected secrets always block.
- Unicode-aware deterministic rules and an optional pinned local OpenAI Privacy Filter/Viterbi adapter.
- Authenticated loopback text-only chat-completions proxy, with explicit unsupported-input rejection, credential separation, bounded restoration and content-free decision receipts.
- 99 AI-authored synthetic diagnostic cases, negative controls, scorer tests and machine-readable reports.
- English/Arabic onboarding, a local capture demo, threat model, safe contribution guidance and a private vulnerability-reporting channel.
- Source distribution and pure-Python wheel. Model weights and heavyweight runtime dependencies are not bundled.

## Verification

80 automated core, detector-contract, scorer, CLI, audit and proxy tests passed on the development machine. The core matrix passed on Linux and Windows with Python 3.11 and 3.13. The built wheel was installed separately and exercised with synthetic input. These tests are not an independent security audit.

See [the evaluation report](https://github.com/mirogate/mirogate-boundary/blob/v0.1.0/docs/evaluation.md) for actual detector measurements, model execution provenance and the host-specific Windows Application Control limitation. On the 99-case synthetic development corpus, hybrid detection achieved 81.11% exact-entity recall and 93.11% annotated-character coverage, with seven sensitive cases incompletely covered and false positives on four of 18 negative controls. These are diagnostic results, not real-world privacy guarantees. Rules-only accuracy must not be quoted as a model score.

## Important limits

This is experimental, reversible pseudonymization, not a privacy/security guarantee or production DLP service. Detectors can miss sensitive values. Only applications using the supported proxy contract are covered. Streaming, tools, media, general MCP traffic, PDF/OCR and other API schemas are unsupported and are not implied by the project name. No paid-provider endpoint was used for validation.

Review [the threat model](https://github.com/mirogate/mirogate-boundary/blob/v0.1.0/docs/threat-model.md) and test synthetic data before any sensitive workload. Submit only synthetic cases; never upload customer records or live credentials.
