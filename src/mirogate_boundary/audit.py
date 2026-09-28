"""Content-free hash-chain receipts. Authenticity needs an independently trusted tip."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path

from .core import BoundaryError, CATEGORIES

GENESIS = "0" * 64
MAX_LOG_BYTES = 16 * 1024 * 1024


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BoundaryError("duplicate_receipt_key")
        result[key] = value
    return result


def validate_receipt(receipt: dict):
    if not isinstance(receipt, dict) or set(receipt) != {"schema", "categories", "characters", "spans", "decision"}:
        raise BoundaryError("invalid_receipt")
    if receipt["schema"] != "mirogate.boundary.receipt.v1" or receipt["decision"] not in {"allow", "tokenize", "block"}:
        raise BoundaryError("invalid_receipt")
    if any(type(receipt[k]) is not int or receipt[k] < 0 for k in ("characters", "spans")):
        raise BoundaryError("invalid_receipt")
    if not isinstance(receipt["categories"], dict) or any(k not in CATEGORIES or type(v) is not int or v < 0 for k,v in receipt["categories"].items()):
        raise BoundaryError("invalid_receipt")


def verify(path: str | Path, expected_head: str | None = None) -> dict:
    path = Path(path)
    if path.stat().st_size > MAX_LOG_BYTES:
        raise BoundaryError("receipt_log_limit")
    previous = GENESIS
    count = 0
    try:
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                entry = json.loads(line, object_pairs_hook=_unique_object)
                if not isinstance(entry, dict) or set(entry) != {"sequence", "previous", "receipt", "hash"}:
                    raise BoundaryError("invalid_receipt_chain")
                validate_receipt(entry["receipt"])
                digest = entry.pop("hash")
                if (type(entry["sequence"]) is not int or entry["sequence"] != count
                    or entry["previous"] != previous
                    or digest != hashlib.sha256(canonical(entry)).hexdigest()):
                    raise BoundaryError("invalid_receipt_chain")
                previous = digest
                count += 1
    except (UnicodeError, json.JSONDecodeError, KeyError, TypeError, RecursionError):
        raise BoundaryError("invalid_receipt_chain") from None
    if expected_head is not None and previous != expected_head:
        raise BoundaryError("receipt_anchor_mismatch")
    return {"valid": True, "entries": count, "head": previous,
            "anchored": expected_head is not None}


def append(path: str | Path, receipt: dict) -> str:
    validate_receipt(receipt)
    path = Path(path)
    lock = path.with_name(path.name + ".lock")
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise BoundaryError("receipt_log_locked") from None
    try:
        os.close(descriptor)
        state = verify(path) if path.exists() else {"entries": 0, "head": GENESIS}
        entry = {"sequence": state["entries"], "previous": state["head"], "receipt": receipt}
        entry["hash"] = hashlib.sha256(canonical(entry)).hexdigest()
        encoded = canonical(entry) + b"\n"
        if (path.stat().st_size if path.exists() else 0) + len(encoded) > MAX_LOG_BYTES:
            raise BoundaryError("receipt_log_limit")
        descriptor = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "ab") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        return entry["hash"]
    finally:
        lock.unlink()
