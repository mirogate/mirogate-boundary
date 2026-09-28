# Arabic Privacy Boundary Bench v0.1

This is a small **synthetic development diagnostic**, not a held-out benchmark or a privacy certification. It contains 99 cases, 90 labelled entities and 18 entirely negative controls across 10 families. The examples and annotations were AI-authored for this project and have not received independent human annotation review.

The corpus was written as a separate workstream from the detector implementation. It is public development material: developers can inspect it, so future improvements on it must not be presented as independent generalization evidence. There is no training/test split in v0.1.

## Composition

| Family | Cases | What it exercises |
| --- | ---: | --- |
| `arabic_names` | 12 | Labelled and contextual Arabic names, patronymics, diacritics, English/Arabic mixing, Arabizi context, Persian and Urdu samples |
| `phone_digits` | 12 | Western, Arabic-Indic and Persian digits, mixed scripts, separators, international prefixes |
| `email` | 10 | Reserved example domains, plus tags, Unicode local parts, obfuscation and zero-width characters |
| `financial_ids` | 10 | IBAN specimens, account identifiers, labelled national IDs/passports and a payment-card test number |
| `addresses_dates` | 9 | Fictional addresses and private birth dates contrasted with public release dates in negative controls |
| `secrets` | 10 | Inert API-key shapes, passwords, bearer/JWT-like strings, connection strings, a dummy PEM and OTP |
| `unicode_adversarial` | 8 | Astral emoji offsets, joiners, bidi controls, full-width email characters and Arabic tatweel |
| `workflow_payloads` | 7 | JSON-like tool results, log text, Markdown tables, repeated values and mixed-language support requests |
| `private_urls` | 3 | Private-context URLs using reserved example domains |
| `negative_controls` | 18 | Public organization/city names, code identifiers, numeric counts, dates, versions and public documentation URLs |

The rows resembling JSON, logs or MCP results are **text-detection cases**. They do not test actual transport adapters, parser behavior, tool execution, or MCP integration. Those need separate integration tests. No PDFs, image/OCR pipeline, audio, encoded binary payloads or real customer records are included.

## Provenance and safe handling

Every row declares `provenance: "synthetic"`. No customer dataset, scraped personal profile or genuine credential was used. Email/URL hosts use reserved example domains. The corpus also uses invented person/address strings, deliberately inert secrets, test/specimen financial values, and artificial telephone/ID strings. Synthetic origin does **not** establish that every phone/ID string is unassigned in the real world. Never contact numbers, authenticate with fixture credentials, or use these examples as actual identity data.

All annotations are an explicit policy choice: private persons, contacts, addresses, birth dates, account/identity numbers, private-context URLs, and secrets. Public organization names, city mentions and release dates are unlabelled. Ambiguous contextual labels should be reviewed before relying on a score. Report annotation corrections with the case ID and rationale; do not submit real personal data in issues.

## Format and offsets

`arabic-privacy-v0.1.jsonl` contains one UTF-8 JSON object per line:

```json
{"id":"example-1","family":"email","text":"a@example.com","spans":[{"start":0,"end":13,"category":"private_email"}],"provenance":"synthetic"}
```

Spans use zero-based, end-exclusive **Python Unicode code-point** offsets into the original, unnormalised string. These are not UTF-8 byte or JavaScript UTF-16 indices. Gold spans never overlap. The emoji case explicitly tests this distinction. Categories match the eight Privacy Filter labels: `private_person`, `private_email`, `private_phone`, `private_address`, `account_number`, `private_url`, `private_date`, `secret`.

## Reproduce

From an installed source checkout:

```sh
boundary bench --detector rules --dataset benchmarks/arabic-privacy-v0.1.jsonl --output benchmarks/results/rules-local.json
boundary bench --detector opf --checkpoint /absolute/path/to/checkpoint --device cpu --dataset benchmarks/arabic-privacy-v0.1.jsonl --output benchmarks/results/opf-local.json
boundary bench --detector hybrid --checkpoint /absolute/path/to/checkpoint --device cpu --dataset benchmarks/arabic-privacy-v0.1.jsonl --output benchmarks/results/hybrid-local.json
python -m unittest discover -s tests -p test_benchmark.py -v
```

Model commands require the optional local runtime and a predownloaded checkpoint; see the model setup documentation. They never silently substitute rules for model inference. An invalid span or a detector failure aborts evaluation instead of dropping a difficult case.

Each report records corpus SHA-256, detector class/source-module hash, caller-supplied model/runtime metadata, Python/platform, case counts and timing. Reports contain case IDs and aggregate counts, not input text or detected values. Callers must not insert private data in the optional metadata.

## What the scores mean

- **Strict entity precision/recall/F1** require identical start, end and category. Duplicate predictions are false positives. One overlong span is not a strict match.
- **Character coverage recall** is the union of predicted characters intersected with annotated characters, regardless of category. Its typed counterpart also requires matching labels. Coverage may be high even when strict F1 is poor; neither proves anonymity.
- **Uncovered gold character rate** is the fraction of annotated characters not covered by any prediction. It is not an observed network leak rate: a policy might block the entire request.
- **Non-sensitive character redaction rate** measures predicted characters outside the annotations divided by unlabelled characters. It is only a coarse over-redaction measure, not downstream task utility.
- **Sensitive-case full coverage rate** requires every annotated character in a sensitive case to be covered.
- **Negative-case false-positive rate** is the share of entirely negative cases with any prediction.
- **Latency** includes the first inference and excludes detector/model construction. Percentiles use nearest rank over one run of short cases. This is not a throughput, cold-start, long-context, memory or production-capacity benchmark.

A metric with no applicable denominator is JSON `null`, not a perfect score. Scorer tests include perfect, empty, partial, wrong-label, duplicate, over-redaction and invalid-output controls. Those are scorer controls, **not model results**.

## Interpretation limits and next contributions

This release contains too few examples to compare languages, countries, dialects, demographic groups, real deployments or competing products reliably. Persian/Urdu/Arabizi examples are edge probes, not language benchmarks. We report no confidence interval, significance claim, human-audited accuracy, security guarantee, compliance status, task-utility gain, memory measurement or full egress coverage.

Useful next contributions are independently reviewed annotations; larger, consented or rigorously synthetic held-out suites; realistic document lengths; positive/negative pairs; dialectal variation; encoded/OCR cases; and separately measured downstream task utility. Preserve provenance and record when a detector was tuned against a corpus version.
