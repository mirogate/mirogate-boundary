# Roadmap: evidence before broader compatibility

Shipped v0.1 is the text-only contract described in README.md. The items below are proposals, not current capabilities or delivery commitments.

1. Independently reproduce model-backed runs on several machines; add reviewed, separately held-out Arabic datasets and dialect/transliteration coverage. Track precision/recall and complete sensitive-span coverage separately.
2. Add task-utility and faithful-restoration benchmarks: assess whether removing identifying data damages the intended task, with synthetic inputs and clearly disclosed model versions.
3. Design explicit tool-result and MCP adapters with schema-based authorization. Never automatically restore values into executable tool arguments.
4. Study streaming only with a documented buffering/enforcement strategy and chunk-boundary tests. Do not market uninspected chunks as filtered.
5. Add an explicit local-route policy with verifiable destination controls and independently tested fallback behavior.
6. Add PDF/OCR/document handling as separately tested parsers, with resource limits and clear unsupported cases.

Before any production claim: independent security review, operational resource limits, hardened multi-user deployment design, and tests against realistic lawful data with human-reviewed labels.
