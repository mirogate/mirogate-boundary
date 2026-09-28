# Evaluation: measured results and limits

The checked-in rules-only run on Arabic Privacy Boundary Bench v0.1 demonstrates why a local policy layer must expose detector limitations. The rules recognized many structured contacts, but they left 625 of 1,756 annotated sensitive characters uncovered. This is a detection diagnostic, not a measurement of data actually sent over a network.

## Rules-only development snapshot

The checked-in [raw report](../benchmarks/results/rules-v0.1.json) was generated on 2026-09-28 using the installed Mirogate Boundary 0.1.0 package and Python 3.13.14 on Windows 11. Corpus: 99 synthetic cases, 90 annotated entities, 81 sensitive cases and 18 negative controls. The corpus and detector source hashes are embedded in the report. This final rules run followed an independently identified short-secret rule correction; its detection counts match the earlier development run, and the corpus was not changed or used to tune that correction.

| Metric | Measured result |
| --- | ---: |
| Strict entity precision | 82.26% (51 / 62 predictions) |
| Strict entity recall | 56.67% (51 / 90 entities) |
| Strict entity F1 | 67.11% |
| Sensitive-character coverage | 64.41% (1,131 / 1,756 characters) |
| Fully covered sensitive cases | 59.26% (48 / 81 cases) |
| Entirely uncovered entities | 34 / 90 |
| Negative controls with false positives | 1 / 18 |
| Unlabelled characters predicted sensitive | 40 / 2,297 (1.74%) |
| Total detector time, one run | 44.493 ms |
| Median / p95 short-case latency | 0.250 / 1.406 ms |

These timings are from one developer-machine run, excluding initialization. They do not establish production throughput, model latency, cold-start time, memory use or a performance advantage over another product. Reruns may differ. The JSON report is authoritative for this snapshot.

## Where the rules struggled

Structured telephone samples were fully covered, but this tiny sample does not establish comprehensive phone detection. Contextual names were much harder: strict recall for the `arabic_names` family was 1 / 13, with 31 / 152 sensitive characters covered. Some labelled entities were covered with overlong boundaries and therefore failed strict scoring.

The corpus deliberately retains misses: obfuscated emails (`email-08`, `email-09`), contextual names, birth dates, selected financial formats, connection-string/password-like examples and private-context URLs. The rules also overmatched a code-expression negative control (`negative-06`). These cases are a contribution to the evaluation surface, not examples to delete to improve the headline score.

The ten `secrets` cases had 6 / 10 strict matches and 254 / 355 sensitive characters covered. Default blocking only applies when a secret is **detected**. A missed secret remains a missed secret; fail-closed transport validation does not fix detection false negatives.

## Local model comparison

At the time this initial report was authored, the OpenAI Privacy Filter and hybrid comparisons were still pending. This file must be updated only after actual model inference finishes, with checkpoint revision/runtime metadata and raw reports. The rules-only figures above must never be described as Privacy Filter results. There are no fabricated or inferred model scores in this report.

## What has and has not been measured

The scorer reports strict spans, character coverage, false positives, case IDs and detector latency. It does not measure provider-side output quality, irreversible anonymization, re-identification risk, actual network exfiltration, every agent's transport behavior, task utility, long-context coverage, process-memory erasure, or regulatory compliance.

The release's separate automated tests exercise policy, vault/restoration and supported proxy behavior. Those tests and these detection scores answer different questions. A successful parser-blocking test is not a claim that a statistical detector finds every private value.

The corpus is AI-authored synthetic development material, not a held-out population sample, and annotations have not been independently human-reviewed. Its scores should guide investigation and reproducible regression checks. See the [dataset and metric documentation](../benchmarks/README.md) before comparing results or quoting a percentage publicly.
