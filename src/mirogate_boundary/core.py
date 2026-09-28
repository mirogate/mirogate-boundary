"""Detection is probabilistic; policy and supported transport behavior are explicit."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import math
import re
import secrets
import time
from types import MappingProxyType
from typing import Protocol

CATEGORIES = frozenset({"private_person", "private_email", "private_phone", "private_address",
                        "account_number", "private_url", "private_date", "secret"})
TOKEN_PATTERN = re.compile(r"<MB1_[a-f0-9]{32}>")


class BoundaryError(ValueError):
    """Safe to turn into a generic client error; never contains input text."""


class DetectorError(BoundaryError):
    pass


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    category: str
    source: str
    score: float = 1.0


class Detector(Protocol):
    def detect(self, text: str) -> list[Span]: ...


@dataclass(frozen=True)
class Policy:
    """Default pseudonymization, with secrets always blocked in this release."""
    actions: dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        checked = dict(self.actions)
        if any(k not in CATEGORIES or v not in {"allow", "tokenize", "block"}
               for k, v in checked.items()):
            raise BoundaryError("invalid_policy")
        if checked.get("secret", "block") != "block":
            raise BoundaryError("secrets_must_block")
        object.__setattr__(self, "actions", MappingProxyType(checked))

    def action(self, category: str) -> str:
        if category == "secret":
            return "block"
        return self.actions.get(category, "tokenize")


class Vault:
    """Bounded, expiring in-memory value mapping. No persistence or zeroization claim."""
    def __init__(self, ttl: float = 900, max_entries: int = 4096,
                 max_characters: int = 1_000_000):
        if not math.isfinite(ttl) or ttl <= 0 or max_entries <= 0 or max_characters <= 0:
            raise BoundaryError("invalid_vault_limits")
        self._expires = time.monotonic() + ttl
        self._max_entries = max_entries
        self._max_characters = max_characters
        self._chars = 0
        self._forward: dict[tuple[str, str], str] = {}
        self._reverse: dict[str, str] = {}

    def _check(self):
        if time.monotonic() >= self._expires:
            self.clear()
            raise BoundaryError("vault_expired")

    def tokenize(self, value: str, category: str) -> str:
        self._check()
        key = (category, value)
        if key in self._forward:
            return self._forward[key]
        if len(self._reverse) >= self._max_entries or self._chars + len(value) > self._max_characters:
            raise BoundaryError("vault_capacity")
        token = f"<MB1_{secrets.token_hex(16)}>"
        while token in self._reverse:
            token = f"<MB1_{secrets.token_hex(16)}>"
        self._forward[key] = token
        self._reverse[token] = value
        self._chars += len(value)
        return token

    def restore(self, text: str, strict: bool = True, max_characters: int = 1_000_000) -> str:
        self._check()
        if len(text) > max_characters:
            raise BoundaryError("restore_limit")
        matches = list(TOKEN_PATTERN.finditer(text))
        if strict:
            remainder = TOKEN_PATTERN.sub("", text)
            if "<MB1_" in remainder or any(m.group() not in self._reverse for m in matches):
                raise BoundaryError("unknown_or_malformed_token")
        expanded_size = len(text)
        for match in matches:
            expanded_size += len(self._reverse.get(match.group(), match.group())) - len(match.group())
            if expanded_size > max_characters:
                raise BoundaryError("restore_limit")
        # Single substitution pass: restored originals are never interpreted as new tokens.
        return TOKEN_PATTERN.sub(lambda m: self._reverse.get(m.group(), m.group()), text)

    def clear(self):
        self._forward.clear()
        self._reverse.clear()
        self._chars = 0


@dataclass(frozen=True)
class Protection:
    text: str | None
    decision: str
    receipt: dict


def validated_spans(text: str, spans: list[Span]) -> list[Span]:
    """Reject corrupt detector output and return sorted spans for policy merging."""
    if not isinstance(spans, (list, tuple)) or len(spans) > len(text) * 8 + 8:
        raise DetectorError("invalid_detector_output")
    for span in spans:
        if (not isinstance(span, Span) or type(span.start) is not int or type(span.end) is not int
            or not 0 <= span.start < span.end <= len(text) or span.category not in CATEGORIES
            or not isinstance(span.score, (float, int)) or not math.isfinite(span.score)
            or not 0 <= span.score <= 1):
            raise DetectorError("invalid_detector_span")
    return sorted(set(spans), key=lambda s: (s.start, s.end, s.category))


class Engine:
    def __init__(self, detector: Detector, policy: Policy | None = None,
                 vault: Vault | None = None, max_characters: int = 131_072):
        self.detector = detector
        self.policy = policy or Policy()
        self.vault = vault or Vault()
        self.max_characters = max_characters

    def protect(self, text: str) -> Protection:
        if not isinstance(text, str) or len(text) > self.max_characters:
            raise BoundaryError("text_limit")
        if "<MB1_" in text:
            raise BoundaryError("reserved_token_input")
        try:
            spans = validated_spans(text, self.detector.detect(text))
        except BoundaryError:
            raise
        except Exception:
            raise DetectorError("detector_failed") from None
        counts = dict(sorted(Counter(s.category for s in spans).items()))
        receipt = {"schema": "mirogate.boundary.receipt.v1", "categories": counts,
                   "characters": len(text), "spans": len(spans)}
        if any(self.policy.action(s.category) == "block" for s in spans):
            return Protection(None, "block", {**receipt, "decision": "block"})
        masked = [s for s in spans if self.policy.action(s.category) == "tokenize"]
        # Merge overlapping spans. Adjacent entities remain distinct, preserving stable tokens.
        unions: list[tuple[int, int, str]] = []
        for span in masked:
            if unions and span.start < unions[-1][1]:
                start, end, category = unions.pop()
                unions.append((start, max(end, span.end), category))
            else:
                unions.append((span.start, span.end, span.category))
        parts = []
        cursor = 0
        for start, end, category in unions:
            parts.extend((text[cursor:start], self.vault.tokenize(text[start:end], category)))
            cursor = end
        parts.append(text[cursor:])
        decision = "tokenize" if unions else "allow"
        return Protection("".join(parts), decision, {**receipt, "decision": decision})
