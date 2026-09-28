# Local OpenAI Privacy Filter

Boundary's optional detector runs the official OpenAI Privacy Filter locally through
the upstream `opf.OPF` Python API, with its constrained Viterbi decoder and pinned
calibration. It does not use an inference API or send input text to Hugging Face.
The dependency-free rules detector remains useful for structured text, but is not a
replacement for contextual entity recognition.

## Explicit, reproducible setup

Use Python 3.11+ and a dedicated virtual environment. Commands below are PowerShell;
on Linux/macOS use `.venv/bin/python` in place of `.venv/Scripts/python.exe`.

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install -e .
.venv/Scripts/python.exe -m pip install "https://github.com/openai/privacy-filter/archive/f7f00ca7fb869683eb732c010299d901457f19c3.zip"
.venv/Scripts/python.exe -c "from mirogate_boundary.detectors import download_model; print(download_model('checkpoints/privacy-filter'))"
```

Only the setup command downloads data: public weights, model configuration,
calibration, and the tokenizer. It uses Hugging Face model revision
`7ffa9a043d54d1be65afb281eddf0ffbe629385b` and keeps the official `original/`
checkpoint format. Weights alone are 2,798,984,088 bytes. Leave room for the Python
runtime and model working memory. CPU inference may be slow, particularly on low-RAM
machines; a successful install does not establish acceptable serving latency.

The ignored `checkpoints/` directory must never contain customer documents. Setup
does not inspect any private files. It is a separate action, never an implicit
fallback while processing a request.

## Use the detector

```python
from mirogate_boundary.core import Engine
from mirogate_boundary.detectors import (
    HybridDetector, OpenAIPrivacyDetector, RuleDetector,
)

model = OpenAIPrivacyDetector("checkpoints/privacy-filter/original", device="cpu")
engine = Engine(HybridDetector(RuleDetector(), model))
result = engine.protect("Email the customer at synthetic.person@example.com")
print(result.decision)
print(result.text)  # Pseudonymized if detected; never treat this as proven anonymous.
```

The model adapter validates the pinned weights, configuration, calibration and
tokenizer hashes before loading. It requires every artifact to exist locally;
missing or modified artifacts fail. The official tokenizer is primed from its
verified local cache. No remote inference or rules-only fallback is attempted.
CPU threads are capped at two. Model calls are serialized because upstream runtime
initialization is lazy. `context_window_length=1024` bounds each inference window;
upstream windowing handles longer supported text. A short prompt still requires
the full model weights to be resident or paged into memory.

`detect(text)` returns original-string character offsets, labels and source names,
not raw span text. A tokenizer round-trip mismatch, invalid offsets, unexpected
label, or inference failure rejects the request through the engine. The upstream
API does not expose span confidence: the shared `Span.score=1.0` field is a
compatibility constant and **must not be described as model confidence**.

## Boundaries and evaluation

- This model was primarily trained on English. Non-English and non-Latin scripts
  need separate evaluation; do not infer Arabic quality from English results.
- The rules handle selected Arabic/Persian digits, Unicode format controls,
  contextual Arabic/English labels, common email/phone forms, selected-country
  IBAN shapes, and recognizable credential patterns. They do not recognize every
  name, natural-language address, secret, national ID, encoding, dialect, or OCR error.
- Rule matches and model matches can be wrong. Checksum-invalid IBAN-like strings
  and dummy credentials can still be classified as sensitive; these are detection
  rules, not account validators.
- The model recognizes a fixed taxonomy. It does not establish consent, legal
  compliance, data sensitivity in every context, or network-wide protection.
- Unit tests using fake OPF results establish adapter behavior only. They are not
  model-accuracy measurements. Only reports explicitly marked as actual inference
  count as model baselines.
- A no-detections result is not proof that a payload contains no private data.
  Apply data minimization and restrict network egress separately.

## Sources and attribution

Runtime: [OpenAI Privacy Filter source, pinned commit](https://github.com/openai/privacy-filter/tree/f7f00ca7fb869683eb732c010299d901457f19c3).
Model and stated limitations: [official model card](https://huggingface.co/openai/privacy-filter).
The upstream runtime and model are Apache-2.0 licensed; Boundary does not redistribute
their weights. Mirogate is independent of OpenAI and this project is not endorsed
by OpenAI.
