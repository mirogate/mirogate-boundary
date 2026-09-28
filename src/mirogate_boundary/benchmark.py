"""Reproducible, text-free scoring for the synthetic Boundary diagnostic corpus.

This measures detector spans, not end-to-end network privacy or real-world safety.
Offsets are Python Unicode code points in the original, unnormalised input text.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import inspect
import json
import math
import platform
import sys
import time
from collections import Counter, defaultdict
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol


SCHEMA_VERSION = "1.0"
CATEGORIES = frozenset({
    "private_person", "private_email", "private_phone", "private_address",
    "account_number", "private_url", "private_date", "secret",
})
WARNING = (
    "This small, synthetic, author-labelled development corpus is not a held-out "
    "or representative evaluation. Scores do not establish real-world privacy, "
    "anonymity, compliance, or complete egress protection. No independent human "
    "annotation review has been performed."
)


class Detector(Protocol):
    def detect(self, text: str) -> list[Any]: ...


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def _span_tuple(span: Any, text_length: int, *, context: str) -> tuple[int, int, str]:
    try:
        if isinstance(span, Mapping):
            start, end, category = span["start"], span["end"], span["category"]
        else:
            start, end, category = span.start, span.end, span.category
    except (KeyError, AttributeError, TypeError) as exc:
        raise ValueError(f"Malformed span in {context}") from exc
    if (
        type(start) is not int or type(end) is not int
        or not 0 <= start < end <= text_length
        or not isinstance(category, str) or category not in CATEGORIES
    ):
        raise ValueError(f"Invalid offsets or category in {context}")
    return start, end, category


def load_dataset(dataset_path: str | Path) -> tuple[list[dict[str, Any]], str]:
    """Validate a corpus and return its cases and exact byte-level SHA-256.

    Gold spans cannot overlap. Detector predictions may overlap; duplicate
    predictions count as false positives instead of being silently deduplicated.
    """
    raw = Path(dataset_path).read_bytes()
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line_number, line in enumerate(raw.decode("utf-8-sig").splitlines(), 1):
        if not line.strip():
            continue
        context = f"dataset line {line_number}"
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {context}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"Expected object in {context}")
        if any(not isinstance(row.get(key), str) or not row[key] for key in ("id", "family", "text", "provenance")):
            raise ValueError(f"Missing string fields in {context}")
        if row["id"] in seen:
            raise ValueError(f"Duplicate case ID in {context}")
        if not isinstance(row.get("spans"), list):
            raise ValueError(f"Missing spans array in {context}")
        spans = sorted(_span_tuple(span, len(row["text"]), context=context) for span in row["spans"])
        for previous, current in zip(spans, spans[1:]):
            if previous[1] > current[0]:
                raise ValueError(f"Overlapping gold spans in {context}")
        seen.add(row["id"])
        rows.append({**row, "_spans": spans})
    if not rows:
        raise ValueError("Dataset must contain at least one case")
    return rows, hashlib.sha256(raw).hexdigest()


def _character_set(spans: list[tuple[int, int, str]]) -> set[int]:
    return {position for start, end, _ in spans for position in range(start, end)}


def _metrics(counts: Counter[str]) -> dict[str, Any]:
    tp, fp, fn = counts["true_positive"], counts["false_positive"], counts["false_negative"]
    return {
        "counts": dict(sorted(counts.items())),
        "entity_strict": {
            "precision": _ratio(tp, tp + fp),
            "recall": _ratio(tp, tp + fn),
            "f1": _ratio(2 * tp, 2 * tp + fp + fn),
        },
        "character_coverage_recall": _ratio(counts["covered_gold_characters"], counts["gold_characters"]),
        "typed_character_coverage_recall": _ratio(counts["typed_covered_gold_characters"], counts["gold_characters"]),
        "uncovered_gold_character_rate": _ratio(counts["uncovered_gold_characters"], counts["gold_characters"]),
        "non_sensitive_character_redaction_rate": _ratio(counts["extra_predicted_characters"], counts["non_sensitive_characters"]),
        "sensitive_case_full_coverage_rate": _ratio(counts["sensitive_cases_fully_covered"], counts["sensitive_cases"]),
        "negative_case_false_positive_rate": _ratio(counts["negative_cases_with_predictions"], counts["negative_cases"]),
    }


def _case_counts(
    text: str,
    gold: list[tuple[int, int, str]],
    predicted: list[tuple[int, int, str]],
) -> Counter[str]:
    gold_counts, prediction_counts = Counter(gold), Counter(predicted)
    tp = sum((gold_counts & prediction_counts).values())
    gold_chars, predicted_chars = _character_set(gold), _character_set(predicted)
    covered = gold_chars & predicted_chars
    typed_covered = set()
    for category in CATEGORIES:
        typed_covered.update(
            _character_set([span for span in gold if span[2] == category])
            & _character_set([span for span in predicted if span[2] == category])
        )
    fully_covered = sum(set(range(start, end)) <= predicted_chars for start, end, _ in gold)
    zero_covered = sum(not (set(range(start, end)) & predicted_chars) for start, end, _ in gold)
    return Counter({
        "cases": 1,
        "gold_entities": len(gold),
        "predicted_entities": len(predicted),
        "true_positive": tp,
        "false_positive": len(predicted) - tp,
        "false_negative": len(gold) - tp,
        "gold_characters": len(gold_chars),
        "covered_gold_characters": len(covered),
        "typed_covered_gold_characters": len(typed_covered),
        "uncovered_gold_characters": len(gold_chars - predicted_chars),
        "non_sensitive_characters": len(text) - len(gold_chars),
        "extra_predicted_characters": len(predicted_chars - gold_chars),
        "fully_covered_gold_entities": fully_covered,
        "partially_covered_gold_entities": len(gold) - fully_covered - zero_covered,
        "zero_covered_gold_entities": zero_covered,
        "sensitive_cases": int(bool(gold)),
        "sensitive_cases_fully_covered": int(bool(gold) and gold_chars <= predicted_chars),
        "negative_cases": int(not gold),
        "negative_cases_with_predictions": int(not gold and bool(predicted)),
    })


def _percentile(values: list[float], percentage: float) -> float:
    """Nearest-rank percentile, reported explicitly for reproducibility."""
    ordered = sorted(values)
    return round(ordered[max(0, math.ceil(percentage * len(ordered)) - 1)], 3)


def evaluate(
    detector: Detector,
    dataset_path: str | Path,
    *,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the real detector; return only IDs, counts, metrics and provenance.

    ``metadata`` should describe model_id, model_revision, device, dtype,
    dependency versions and/or configuration. It must never contain input text,
    secrets or user data; it is copied into the report. Model loading is excluded
    from latency. The first inference is included, without a hidden warmup.

    A detector error or invalid prediction aborts the run: failed cases are not
    silently dropped. This intentionally reports *detection*, not policy-block,
    pseudonymization utility, restoration correctness or actual egress outcomes.
    """
    rows, corpus_hash = load_dataset(dataset_path)
    overall: Counter[str] = Counter()
    families: dict[str, Counter[str]] = defaultdict(Counter)
    per_case = []
    durations = []
    for index, row in enumerate(rows, 1):
        started = time.perf_counter()
        try:
            detected = list(detector.detect(row["text"]))
        except Exception:
            # Detector exception messages may include input text or secrets.
            raise RuntimeError(f"Detector failed on dataset case {index}") from None
        duration = (time.perf_counter() - started) * 1000
        predictions = [_span_tuple(span, len(row["text"]), context=f"prediction for case {index}") for span in detected]
        counts = _case_counts(row["text"], row["_spans"], predictions)
        overall.update(counts)
        families[row["family"]].update(counts)
        durations.append(duration)
        per_case.append({"id": row["id"], "family": row["family"], **_metrics(counts), "duration_ms": round(duration, 3)})
    try:
        package_version = importlib.metadata.version("mirogate-boundary")
    except importlib.metadata.PackageNotFoundError:
        package_version = "source-tree (uninstalled)"
    module = inspect.getmodule(type(detector))
    module_path = getattr(module, "__file__", None)
    source_hash = hashlib.sha256(Path(module_path).read_bytes()).hexdigest() if module_path and Path(module_path).is_file() else None
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "warning": WARNING,
        "dataset": {
            "name": Path(dataset_path).name,
            "sha256": corpus_hash,
            "cases": len(rows),
            "provenance_counts": dict(Counter(row["provenance"] for row in rows)),
            "offset_unit": "Unicode code points in original text",
        },
        "detector": {"class": f"{type(detector).__module__}.{type(detector).__qualname__}", "module_sha256": source_hash, "metadata": dict(metadata or {})},
        "software": {"mirogate_boundary": package_version, "python": sys.version.split()[0], "platform": platform.platform()},
        "overall": _metrics(overall),
        "families": {family: _metrics(counts) for family, counts in sorted(families.items())},
        "latency_ms": {
            "total": round(sum(durations), 3),
            "mean": round(sum(durations) / len(durations), 3),
            "p50": _percentile(durations, 0.50),
            "p95": _percentile(durations, 0.95),
            "max": round(max(durations), 3),
            "method": "perf_counter; nearest-rank percentiles; model construction excluded; first inference included",
        },
        "cases": per_case,
    }
