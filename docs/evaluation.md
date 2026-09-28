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

Actual OPF and hybrid inference completed on 2026-09-28 in a Linux GitHub Actions CPU runner: [verified run](https://github.com/mirogate/mirogate-boundary/actions/runs/36476642007), source commit `0c0bb1b82d9a46264c3f17400272bdab0d3ae0ae`. Both modes processed all 99 cases with fresh predictions. The same loaded model was used in OPF-then-hybrid order; predictions were not cached. Raw reports: [OPF](../benchmarks/results/opf-v0.1.json), [hybrid](../benchmarks/results/hybrid-v0.1.json).

| Metric, same synthetic corpus | Rules | OPF alone | Hybrid |
| --- | ---: | ---: | ---: |
| Strict entity precision | 82.26% | 69.62% | 67.59% |
| Strict entity recall | 56.67% | 61.11% | 81.11% |
| Strict entity F1 | 67.11% | 65.09% | 73.74% |
| Annotated-character coverage | 64.41% | 81.72% | 93.11% |
| Sensitive cases fully covered | 48 / 81 | 66 / 81 | 74 / 81 |
| Entirely uncovered entities | 34 / 90 | 16 / 90 | 6 / 90 |
| Negative controls with predictions | 1 / 18 | 3 / 18 | 4 / 18 |
| Unlabelled-character redaction rate | 1.74% | 7.27% | 8.92% |

Hybrid covered more annotated text on this corpus but also produced more false positives. It still left 121 annotated characters uncovered, including six entirely missed entities and one partially covered entity. Sensitive cases `person-02`, `person-05`, `person-10`, `account-09`, `secret-07`, `mixed-01` and `url-02` were not fully covered. This is not a leak-free result. Character coverage ignores category; strict metrics score the detector's span proposals, including distinct overlapping proposals, rather than the final merged masking output.

### Execution details

The runner used Ubuntu 24.04, Python 3.11.13, `torch==2.8.0+cpu`, two PyTorch threads, a guest exposing four logical AMD EPYC 9V74 CPUs and 16.77 GB physical RAM. Model revision: `7ffa9a043d54d1be65afb281eddf0ffbe629385b`; official runtime commit: `f7f00ca7fb869683eb732c010299d901457f19c3`. The adapter used the pinned Viterbi calibration and a 1,024-token context window, without tuning thresholds or training on this corpus. Exact dependency versions, file hashes and settings are in each raw report.

Total detector time was 52.179 s for OPF and 52.033 s for hybrid; median/p95 short-case latency was 495.859/883.575 ms and 496.155/871.472 ms respectively. These are one-run, warm-model timings. Adapter construction (3.572 s) and one prior synthetic smoke inference (3.830 s, including lazy initialization) were excluded. Hybrid ran second against the already-warm model; do not infer a performance advantage from these small timing differences. Rules timing came from a different Windows machine and is not a controlled cross-mode performance comparison. Peak process memory and long-context latency were not measured.

The preliminary smoke email was missed and that outcome is preserved in both reports. An initial harness run stopped on an inappropriate smoke accuracy assertion; the corrected harness records that accuracy observation and continues, without changing the prompt, model, corpus or thresholds. Inference failures or invalid spans still abort the evaluation.

Python socket connect/DNS/datagram APIs were blocked during construction, smoke and corpus inference, with zero attempted calls recorded. This is a scoped regression assertion, **not** an OS-level network sandbox or proof about native libraries, subprocesses or other applications. Only public synthetic text was used; no hosted AI inference API or provider credential was used.

The separate Windows development-host attempt stopped before inference because Application Control blocked a PyTorch DLL. Its policy was left unchanged. These Linux scores are not evidence of model execution on that Windows host; see [the setup record](model-setup.md).

To reproduce, follow the pinned dependency/setup steps in [.github/workflows/model-evaluation.yml](../.github/workflows/model-evaluation.yml) on an appropriate Linux environment and run `python scripts/evaluate_models.py --checkpoint checkpoints/privacy-filter --output build/model-evaluation`. The script enforces the exact public corpus hash and records the source commit. Maintainers can also run the manual workflow; it never triggers model downloads on pull requests.

## What has and has not been measured

The scorer reports strict spans, character coverage, false positives, case IDs and detector latency. It does not measure provider-side output quality, irreversible anonymization, re-identification risk, actual network exfiltration, every agent's transport behavior, task utility, long-context coverage, process-memory erasure, or regulatory compliance.

The release's separate automated tests exercise policy, vault/restoration and supported proxy behavior. Those tests and these detection scores answer different questions. A successful parser-blocking test is not a claim that a statistical detector finds every private value.

The corpus is AI-authored synthetic development material, not a held-out population sample, and annotations have not been independently human-reviewed. Its scores should guide investigation and reproducible regression checks. See the [dataset and metric documentation](../benchmarks/README.md) before comparing results or quoting a percentage publicly.
