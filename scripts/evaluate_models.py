"""Run actual local inference on the checked-in synthetic development corpus.

No input argument accepts private data or arbitrary datasets. Setup/downloads are
separate. Both evaluations make fresh model calls using one resident model; no
detection cache, gold-label substitution, or unsuccessful-case filtering exists.
Python socket monkeypatches are an offline regression assertion, not an OS sandbox.
"""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import re
import socket
import subprocess
import time
from unittest.mock import patch

from mirogate_boundary.benchmark import evaluate, load_dataset
from mirogate_boundary.detectors import (
    HybridDetector, MODEL_REVISION, OPF_REVISION, OpenAIPrivacyDetector, RuleDetector,
)

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "benchmarks" / "arabic-privacy-v0.1.jsonl"
DATASET_SHA256 = "2a8c7c256a0061db846c0b794b679804833e721f719485de97473a7687af6caa"
DIRECT_DEPENDENCIES = {
    "torch": "2.8.0+cpu", "numpy": "2.3.3", "packaging": "25.0",
    "huggingface-hub": "0.35.0", "safetensors": "0.6.2", "tiktoken": "0.11.0",
    "opf": "0.1.0",
}
SMOKE = "Please contact synthetic.person@example.com."


@contextmanager
def offline_socket_guard():
    """Reject ordinary Python network connection/DNS/datagram APIs and count attempts.

    Native libraries, subprocesses, raw system calls and other processes are outside
    this monkeypatch. A passing assertion does not prove network-wide isolation.
    """
    state = {"blocked_attempts": 0}

    def reject(*args, **kwargs):
        state["blocked_attempts"] += 1
        raise RuntimeError("Network access is forbidden during local model evaluation")

    targets = (
        "socket.create_connection", "socket.getaddrinfo", "socket.gethostbyname",
        "socket.gethostbyname_ex", "socket.socket.connect", "socket.socket.connect_ex",
        "socket.socket.sendto",
    )
    with ExitStack() as stack:
        for target in targets:
            stack.enter_context(patch(target, side_effect=reject))
        yield state


def validate_corpus() -> None:
    rows, digest = load_dataset(DATASET)
    if digest != DATASET_SHA256 or len(rows) != 99:
        raise RuntimeError("This runner accepts only the published 99-case v0.1 corpus")
    if any(row["provenance"] != "synthetic" for row in rows):
        raise RuntimeError("Model workflow requires an entirely synthetic corpus")


def self_test() -> None:
    validate_corpus()
    with offline_socket_guard() as state:
        try:
            socket.create_connection(("127.0.0.1", 9))
        except RuntimeError:
            pass
        else:
            raise AssertionError("Offline socket guard did not reject a connection")
        if state["blocked_attempts"] != 1:
            raise AssertionError("Offline socket attempt accounting failed")
    print("Fixed synthetic corpus and Python socket-guard self-test passed.", flush=True)


def environment_metadata() -> dict:
    installed = {item.metadata["Name"]: item.version for item in metadata.distributions()}
    for name, expected in DIRECT_DEPENDENCIES.items():
        if metadata.version(name) != expected:
            raise RuntimeError(f"Expected pinned evaluation dependency: {name}=={expected}")
    commit = os.environ.get("GITHUB_SHA")
    if commit is None:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, timeout=10,
        ).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise RuntimeError("A valid source commit is required for evaluation provenance")
    cpu_name = platform.processor()
    cpu_info = Path("/proc/cpuinfo")
    if cpu_info.is_file():
        for line in cpu_info.read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                cpu_name = line.split(":", 1)[1].strip()
                break
    physical_memory = None
    if hasattr(os, "sysconf"):
        try:
            physical_memory = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
        except (ValueError, OSError):
            pass
    paths = (
        "scripts/evaluate_models.py", "src/mirogate_boundary/detectors.py",
        "src/mirogate_boundary/benchmark.py", "src/mirogate_boundary/core.py",
    )
    return {
        "actual_model_inference": True,
        "source_commit": commit,
        "source_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in paths},
        "model_revision": MODEL_REVISION,
        "runtime_revision": OPF_REVISION,
        "installed_distributions": dict(sorted(installed.items())),
        "hardware": {"machine": platform.machine(), "cpu_model": cpu_name,
                     "logical_cpu_count": os.cpu_count(), "physical_memory_bytes": physical_memory,
                     "device": "cpu", "torch_threads": 2},
        "runner": {"github_actions": os.environ.get("GITHUB_ACTIONS") == "true",
                   "image_os": os.environ.get("ImageOS"), "image_version": os.environ.get("ImageVersion")},
        "method": {
            "corpus": "Fixed 99-case public synthetic v0.1 development corpus; not held out",
            "model_instances": 1,
            "prediction_cache": False,
            "order": ["one synthetic offline smoke inference", "opf", "hybrid"],
            "timing": "Every corpus inference is timed, including each mode's first corpus case. Earlier smoke and adapter construction are excluded. Hybrid reuses the already-warm model but performs fresh inference for every case.",
            "offline_scope": "Python socket connect, DNS and datagram APIs blocked for adapter construction, smoke and corpus inference; not an OS-level network sandbox or proof about native/subprocess I/O.",
            "configuration": "Official constrained Viterbi decoder and pinned calibration; no threshold tuning or training on this corpus",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "build" / "model-evaluation")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    self_test()
    if args.self_test:
        return 0
    if args.checkpoint is None:
        parser.error("--checkpoint is required; run boundary model-setup explicitly first")
    run_metadata = environment_metadata()
    args.output.mkdir(parents=True, exist_ok=True)
    with offline_socket_guard() as offline:
        start = time.perf_counter()
        model = OpenAIPrivacyDetector(args.checkpoint, device="cpu")
        run_metadata["adapter_construction_seconds"] = time.perf_counter() - start
        # Upstream model loading is lazy: smoke timing may include weight loading.
        start = time.perf_counter()
        smoke_spans = model.detect(SMOKE)
        run_metadata["smoke_seconds_including_lazy_initialization"] = time.perf_counter() - start
        email_start = SMOKE.index("synthetic.person@example.com")
        email_end = email_start + len("synthetic.person@example.com")
        # This smoke checks offline execution, not model accuracy. Preserve a miss
        # instead of replacing the prompt or refusing to measure poor performance.
        smoke_email_covered = any(span.category == "private_email" and span.start <= email_start
                                  and span.end >= email_end for span in smoke_spans)
        run_metadata["smoke"] = {
            "text_sha256": hashlib.sha256(SMOKE.encode()).hexdigest(),
            "expected_email_fully_covered": smoke_email_covered,
            "predicted_category_counts": dict(Counter(span.category for span in smoke_spans)),
            "purpose": "Offline execution assertion only; detection accuracy is recorded without a pass threshold",
        }
        if offline["blocked_attempts"]:
            raise RuntimeError("Local model attempted network access despite local setup")
        print(json.dumps({"offline_smoke_completed": True,
                          "expected_email_fully_covered": smoke_email_covered}), flush=True)
        for mode, detector in (("opf", model), ("hybrid", HybridDetector(RuleDetector(), model))):
            print(f"Starting {mode}: 99 fresh synthetic-case inferences.", flush=True)
            started_at = datetime.now(timezone.utc).isoformat()
            start = time.perf_counter()
            report = evaluate(detector, DATASET, metadata=detector.metadata)
            evaluation_seconds = time.perf_counter() - start
            if offline["blocked_attempts"]:
                raise RuntimeError("Local evaluation attempted network access")
            report["execution"] = {
                **run_metadata,
                "mode": mode,
                "started_at": started_at,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "evaluation_wall_seconds_including_scoring": evaluation_seconds,
                "offline_assertion": {"passed": True, **offline},
            }
            report["latency_ms"]["method"] = (
                "perf_counter; nearest-rank percentiles; all corpus inferences timed; "
                "adapter construction and one prior smoke inference excluded; "
                "shared model evaluated in OPF-then-hybrid order; no cached detections"
            )
            destination = args.output / f"{mode}-v0.1.json"
            destination.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            print(json.dumps({"mode": mode, "cases": report["dataset"]["cases"],
                              "strict_f1": report["overall"]["entity_strict"]["f1"],
                              "character_coverage": report["overall"]["character_coverage_recall"],
                              "seconds": evaluation_seconds}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
