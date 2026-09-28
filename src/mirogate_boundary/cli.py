"""CLI defaults to hybrid detection and never falls back silently."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import secrets
import sys

from . import __version__
from .core import BoundaryError, Engine, Policy


def _json(value):
    print(json.dumps(value, ensure_ascii=False, indent=2))


def make_detector(args):
    from .detectors import RuleDetector, OpenAIPrivacyDetector, HybridDetector
    if args.detector == "rules":
        return RuleDetector()
    if not args.checkpoint:
        raise BoundaryError("checkpoint_required_see_docs_model_setup")
    model = OpenAIPrivacyDetector(args.checkpoint, device=args.device)
    return model if args.detector == "opf" else HybridDetector(RuleDetector(), model)


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Mirogate Boundary: local-first text egress policies")
    parser.add_argument("--version", action="version", version=__version__)
    subs = parser.add_subparsers(dest="command", required=True)
    scan = subs.add_parser("scan", help="Protect UTF-8 text locally; input is never logged")
    scan.add_argument("--file", type=Path, help="UTF-8 text file; otherwise stdin")
    scan.add_argument("--receipts", type=Path, help="Append content-free receipt to this local log")
    scan.add_argument("--policy", type=Path, help='JSON category actions, e.g. {"private_person":"block"}')
    bench = subs.add_parser("bench", help="Evaluate synthetic labelled cases; not a safety certification")
    bench.add_argument("--dataset", type=Path, required=True)
    bench.add_argument("--output", type=Path)
    proxy = subs.add_parser("proxy", help="Serve strict text-only /v1/chat/completions on loopback")
    proxy.add_argument("--upstream", required=True, help="Explicit full upstream chat/completions endpoint")
    proxy.add_argument("--port", type=int, default=8787)
    proxy.add_argument("--restore", action="store_true", help="Opt-in restore assistant display text locally")
    proxy.add_argument("--receipts", type=Path)
    proxy.add_argument("--policy", type=Path)
    check = subs.add_parser("verify", help="Check receipt chain integrity, optionally against a trusted head")
    check.add_argument("file", type=Path)
    check.add_argument("--expected-head")
    subs.add_parser("token", help="Generate a random local proxy credential; keep it private")
    setup = subs.add_parser("model-setup", help="Explicitly download the pinned model and tokenizer (several GB)")
    setup.add_argument("--destination", type=Path, default=Path("checkpoints/privacy-filter"))
    for sub in (scan, bench, proxy):
        sub.add_argument("--detector", choices=("rules", "opf", "hybrid"), default="hybrid")
        sub.add_argument("--checkpoint", help="Existing local OPF checkpoint; never auto-downloaded")
        sub.add_argument("--device", default="cpu", choices=("cpu", "cuda"))
    args = parser.parse_args(argv)
    try:
        if args.command == "token":
            print(secrets.token_urlsafe(32))
            return 0
        if args.command == "verify":
            from .audit import verify
            _json(verify(args.file, args.expected_head))
            return 0
        if args.command == "model-setup":
            from .detectors import download_model
            download_model(args.destination)
            _json({"status": "model_download_complete", "next": "See docs/model-setup.md for runtime installation and verification."})
            return 0
        detector = make_detector(args)
        if args.command == "bench":
            from .benchmark import evaluate
            report = evaluate(detector, args.dataset, metadata=getattr(detector, "metadata", {"mode": args.detector, "device": args.device}))
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            _json(report)
            return 0
        policy = Policy(json.loads(args.policy.read_text(encoding="utf-8"))) if args.policy else Policy()
        if args.command == "scan":
            if args.file:
                if args.file.stat().st_size > 524288:
                    raise BoundaryError("input_too_large")
                raw = args.file.read_bytes()
            else:
                raw = sys.stdin.buffer.read(524289)
            if len(raw) > 524288:
                raise BoundaryError("input_too_large")
            text = raw.decode("utf-8-sig", errors="strict")
            result = Engine(detector, policy).protect(text)
            if args.receipts:
                from .audit import append
                append(args.receipts, result.receipt)
            _json({"decision": result.decision, "text": result.text, "receipt": result.receipt})
            return 2 if result.decision == "block" else 0
        from .proxy import serve
        from .audit import append
        token = os.environ.get("BOUNDARY_LOCAL_TOKEN", "")
        if len(token) < 32:
            raise BoundaryError("set_BOUNDARY_LOCAL_TOKEN_at_least_32_characters")
        print(f"Boundary {__version__}: loopback port {args.port}; detector={args.detector}; text-only; restore={args.restore}", file=sys.stderr)
        serve(lambda: Engine(detector, policy), upstream_url=args.upstream,
              upstream_key=os.environ.get("BOUNDARY_UPSTREAM_KEY"), local_token=token,
              port=args.port, restore=args.restore,
              receipt_sink=(lambda r: append(args.receipts, r)) if args.receipts else None)
        return 0
    except (BoundaryError, OSError, ValueError, ImportError, RuntimeError):
        # Do not echo exception strings: OS paths and detector/provider errors can contain input.
        print(json.dumps({"error": "boundary_failed_closed", "help": "Check local setup, input, policy and docs; no automatic detector fallback."}), file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        return 130
