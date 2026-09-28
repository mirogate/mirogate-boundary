"""Local detectors. Rules are deliberately incomplete; no network inference exists here.

Offsets always refer to the unmodified Python string. Scores are an API-compatible
constant, not calibrated probabilities. Detection and policy enforcement are separate.
"""

from __future__ import annotations

import hashlib
from importlib import metadata as package_metadata
import json
import os
from pathlib import Path
import re
from threading import Lock
from typing import Protocol
import unicodedata
from urllib.request import urlopen

from .core import Span

OPF_REVISION = "f7f00ca7fb869683eb732c010299d901457f19c3"
MODEL_REVISION = "7ffa9a043d54d1be65afb281eddf0ffbe629385b"
MODEL_SHA256 = "9c262cbe68a0c8a50590a648ef8341a2b7d3be1fa11dfb79893fe0b03ce57b5c"
_CONFIG_SHA256 = "048a20604a3622de208d30df57cd5424bb583639b9ba20ddd7da593d3f89a248"
_CALIBRATION_SHA256 = "bbc8611ef08a55ed72d64856cbbbb9a91db8dfa881f0a92e2afbad6e4bbc775a"
_TOKENIZER_URL = "https://openaipublic.blob.core.windows.net/encodings/o200k_base.tiktoken"
_TOKENIZER_CACHE_KEY = hashlib.sha1(_TOKENIZER_URL.encode()).hexdigest()
_TOKENIZER_SHA256 = "446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d"
_CATEGORIES = frozenset({"private_person", "private_email", "private_phone",
                         "private_address", "account_number", "private_url",
                         "private_date", "secret"})


class Detector(Protocol):
    def detect(self, text: str) -> list[Span]: ...


def _normalized(text: str) -> tuple[str, list[int], list[int]]:
    """Compatibility-fold characters and digits while retaining original offsets.

    Format controls and combining marks are ignored for matching, not stripped from
    the returned source or sent upstream. This catches selected obfuscations but is
    not a general Unicode/confusable or encoded-data defense.
    """
    chars: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    for index, char in enumerate(text):
        if unicodedata.category(char) in {"Cf", "Mn", "Me"}:
            if ends:
                ends[-1] = index + 1
            continue
        for folded in unicodedata.normalize("NFKC", char):
            if unicodedata.category(folded) in {"Cf", "Mn", "Me"}:
                continue
            try:
                folded = str(unicodedata.decimal(folded))
            except ValueError:
                pass
            chars.append(folded)
            starts.append(index)
            ends.append(index + 1)
    return "".join(chars), starts, ends


_EMAIL = re.compile(r"(?<![\w.+-])[\w!#$%&'*+/=?^`{|}~-]+(?:\.[\w!#$%&'*+/=?^`{|}~-]+)*@[\w-]+(?:\.[\w-]+)+(?![\w-])", re.UNICODE)
_INTERNATIONAL_PHONE = re.compile(r"(?<![\w+])(?:\+|00)[1-9][0-9 ()\t.-]{6,24}[0-9](?!\w)")
_DOMESTIC_PHONE = re.compile(r"(?<![\w+])0[0-9](?:[ ()\t-]*[0-9]){7,9}(?![\w-])")
_PHONE_LABEL = re.compile(r"(?:\b(?:phone|telephone|tel|mobile|whatsapp)\b|(?:رقم[ \t]+)?(?:الهاتف|هاتف|الجوال|جوال|الموبايل|موبايل|واتساب))[\s\"']{0,4}[:=：]?[ \t\"']{0,4}(?P<value>\+?[0-9][0-9 ()\t.-]{4,24}[0-9])(?!\w)", re.I)
_ID_LABEL = re.compile(r"(?:\b(?:national[ _-]?id|emirates[ _-]?id|identity[ _-]?(?:number|no)|passport(?:[ _-]?(?:number|no))?|account[ _-]?(?:number|no)|customer[ _-]?id|ssn)\b|(?:رقم[ \t]+)?(?:الهوية|الاقامة|الإقامة|الحساب|البطاقة|الجواز|الرقم[ \t]+الوطني|رقم[ \t]+وطني))[\s\"']{0,4}[:=：]?[ \t\"']{0,4}(?P<value>[A-Za-z0-9][A-Za-z0-9 -]{3,27}[A-Za-z0-9])(?!\w)", re.I)
_NAME_LABEL = re.compile(r"(?:\b(?:full[ _-]?name|customer[ _-]?name|patient[ _-]?name|contact[ _-]?name)\b|(?:الاسم[ \t]+الكامل|اسم[ \t]+(?:العميل|المريض|المستلم)))[\s\"']{0,4}[:=：][ \t\"']{0,4}(?P<value>[^\n\r,،;؛<>\"'=:\d]{2,100})", re.I)
_ADDRESS_LABEL = re.compile(r"(?:\b(?:home[ _-]?address|shipping[ _-]?address|billing[ _-]?address|street[ _-]?address)\b|(?:عنوان[ \t]+(?:السكن|المنزل|الشحن|العميل)))[\s\"']{0,4}[:=：][ \t\"']{0,4}(?P<value>[^\n\r;؛<>\"']{4,180})", re.I)
_SECRET_PREFIX = r"(?:\b(?:api[ _-]?key|access[ _-]?token|auth[ _-]?token|secret(?:[ _-]?key)?|password|passwd|client[ _-]?secret)\b|(?:كلمة[ \t]+(?:المرور|السر)|مفتاح[ \t]+(?:الواجهة|سري)))[\s\"']{0,4}[:=：][ \t]{0,4}"
_SECRET_LABEL = re.compile(_SECRET_PREFIX + r"(?P<value>[^\s\"',;؛<>}]{1,512})", re.I)
_SECRET_QUOTED = re.compile(_SECRET_PREFIX + r"(?P<quote>[\"'])(?P<value>[^\r\n]{1,512}?)(?P=quote)", re.I)
_SECRET_TOKENS = re.compile(r"(?<![\w-])(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}|(?:gh[pousr]_[A-Za-z0-9]{20,})|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{15,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})(?![\w-])")
_BEARER = re.compile(r"\bBearer[ \t]+(?P<value>[A-Za-z0-9._~+/-]{8,}=*)", re.I)
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----|\Z)")
_URL_CREDENTIALS = re.compile(r"\bhttps?://(?P<value>[^\s/@:]+:[^\s/@]+)@[^\s/]+", re.I)
_SIGNED_URL = re.compile(r"\bhttps?://[^\s<>\"']+[?&](?:token|access_token|api_key|signature|sig|X-Amz-Signature)=[^\s<>\"']+", re.I)
_IBAN_LENGTHS = {"AE": 23, "BH": 22, "DE": 22, "DZ": 24, "EG": 29,
                 "FR": 27, "GB": 22, "IQ": 23, "JO": 30, "KW": 30,
                 "LB": 28, "LY": 25, "OM": 23, "PS": 29, "QA": 29,
                 "SA": 24, "TN": 24, "TR": 26}
_IBAN = re.compile(r"(?<![A-Za-z0-9])(?:" + "|".join(
    country + r"[ \t]*[0-9][ \t]*[0-9]" + r"(?:[ \t]*[A-Za-z0-9]){" + str(length - 4) + "}"
    for country, length in _IBAN_LENGTHS.items()) + r")(?![A-Za-z0-9])", re.I)


class RuleDetector:
    """Auditable starter rules for structured English/Arabic text.

    Unlabelled names, natural-language addresses, dialects, dates, arbitrary
    secrets, non-covered national formats, encodings and images can be missed.
    Invalid-looking identifiers are masked too; this is not ID/IBAN validation.
    """

    name = "rules-v1"
    metadata = {"detector": "rules-v1", "inference": "deterministic-rules", "rules_version": 1}

    def detect(self, text: str) -> list[Span]:
        normalized, starts, ends = _normalized(text)
        found: list[Span] = []

        def add(pattern: re.Pattern[str], category: str, group: str | int = 0,
                digit_bounds: tuple[int, int] | None = None) -> None:
            for match in pattern.finditer(normalized):
                start, end = match.span(group)
                while end > start and normalized[end - 1].isspace():
                    end -= 1
                if end <= start:
                    continue
                value = normalized[start:end]
                if digit_bounds is not None:
                    count = sum(char.isdecimal() for char in value)
                    if not digit_bounds[0] <= count <= digit_bounds[1]:
                        continue
                if category == "account_number" and pattern is _ID_LABEL:
                    # Contextual IDs end before following prose. Spaces are
                    # allowed only between digit groups; hyphens remain part of IDs.
                    id_match = re.match(r"[A-Za-z]{0,3}[0-9]+(?:[ -][0-9]+)*", value)
                    if id_match is None or len(re.sub(r"\D", "", id_match[0])) < 4:
                        continue
                    end = start + len(id_match[0])
                found.append(Span(starts[start], ends[end - 1], category, self.name))

        add(_EMAIL, "private_email")
        add(_INTERNATIONAL_PHONE, "private_phone", digit_bounds=(8, 15))
        add(_DOMESTIC_PHONE, "private_phone", digit_bounds=(9, 11))
        add(_PHONE_LABEL, "private_phone", "value", (6, 15))
        add(_IBAN, "account_number")
        add(_ID_LABEL, "account_number", "value")
        add(_NAME_LABEL, "private_person", "value")
        add(_ADDRESS_LABEL, "private_address", "value")
        add(_SECRET_TOKENS, "secret")
        add(_SECRET_LABEL, "secret", "value")
        add(_SECRET_QUOTED, "secret", "value")
        add(_BEARER, "secret", "value")
        add(_PRIVATE_KEY, "secret")
        add(_URL_CREDENTIALS, "secret", "value")
        add(_SIGNED_URL, "private_url")
        # Preserve overlaps for the core policy to merge with secret precedence.
        return sorted(set(found), key=lambda span: (span.start, span.end, span.category))


class HybridDetector:
    """Union of detector spans. Errors propagate; there is no silent downgrade."""

    name = "hybrid-v1"

    def __init__(self, *detectors: Detector):
        if not detectors:
            raise ValueError("HybridDetector requires at least one detector")
        self.detectors = detectors
        self.metadata = {"detector": self.name,
                         "components": [getattr(item, "metadata", {"detector": type(item).__name__})
                                        for item in detectors]}

    def detect(self, text: str) -> list[Span]:
        grouped: dict[tuple[int, int, str], Span] = {}
        for detector in self.detectors:
            for span in detector.detect(text):
                key = (span.start, span.end, span.category)
                if key in grouped:
                    prior = grouped[key]
                    sources = "+".join(sorted(set(prior.source.split("+") + [span.source])))
                    grouped[key] = Span(span.start, span.end, span.category, sources,
                                        max(prior.score, span.score))
                else:
                    grouped[key] = span
        return sorted(grouped.values(), key=lambda span: (span.start, span.end, span.category))


def download_model(destination: str | Path) -> Path:
    """Explicit setup only: download pinned public weights and tokenizer, no user text.

    Not called by any detector or request handler. Requires the documented optional
    OPF dependencies. Keep the resulting directory outside version control.
    """
    import tiktoken

    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    checkpoint = destination / "original"
    checkpoint.mkdir(exist_ok=True)
    artifacts = {"config.json": _CONFIG_SHA256, "model.safetensors": MODEL_SHA256,
                 "viterbi_calibration.json": _CALIBRATION_SHA256}
    for filename, expected_hash in artifacts.items():
        final_path = checkpoint / filename
        if final_path.is_file():
            with final_path.open("rb") as stream:
                if hashlib.file_digest(stream, "sha256").hexdigest() == expected_hash:
                    continue
        # Download only fixed public artifacts. Partial files never become an active
        # checkpoint, and content hashes are checked before atomic promotion.
        part_path = checkpoint / (filename + ".download")
        url = f"https://huggingface.co/openai/privacy-filter/resolve/{MODEL_REVISION}/original/{filename}"
        digest = hashlib.sha256()
        with urlopen(url, timeout=30) as response, part_path.open("wb") as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
                digest.update(chunk)
        if digest.hexdigest() != expected_hash:
            raise RuntimeError("Downloaded OPF artifact failed integrity verification")
        part_path.replace(final_path)
    tokenizer_cache = checkpoint / "tiktoken"
    tokenizer_cache.mkdir(exist_ok=True)
    prior = os.environ.get("TIKTOKEN_CACHE_DIR")
    os.environ["TIKTOKEN_CACHE_DIR"] = str(tokenizer_cache)
    try:
        # Loading in an already-used interpreter can reuse tiktoken's process cache.
        # Explicit read_file_cached also ensures this particular on-disk cache exists.
        from tiktoken.load import read_file_cached
        read_file_cached(_TOKENIZER_URL, _TOKENIZER_SHA256)
        tiktoken.get_encoding("o200k_base")
    finally:
        if prior is None:
            os.environ.pop("TIKTOKEN_CACHE_DIR", None)
        else:
            os.environ["TIKTOKEN_CACHE_DIR"] = prior
    return checkpoint


class OpenAIPrivacyDetector:
    """Official OPF Viterbi inference using explicit local, pinned-checkpoint files.

    The constructor verifies weights before loading. Missing/bad files, tokenizer
    round-trip mismatch, unexpected labels, or inference errors fail closed.
    The official API returns no span confidence; score=1.0 is not probability.
    """

    name = "openai-privacy-filter-viterbi"
    model_revision = MODEL_REVISION
    runtime_revision = OPF_REVISION

    def __init__(self, checkpoint: str | Path, device: str = "cpu"):
        if device not in {"cpu", "cuda"}:
            raise ValueError("OPF device must be cpu or cuda")
        self.checkpoint = Path(checkpoint).resolve()
        if not (self.checkpoint / "config.json").is_file() and (self.checkpoint / "original").is_dir():
            self.checkpoint = self.checkpoint / "original"
        if not self.checkpoint.is_dir():
            raise RuntimeError("Local OPF checkpoint unavailable; follow docs/model-setup.md")
        for filename in ("config.json", "model.safetensors", "viterbi_calibration.json"):
            if not (self.checkpoint / filename).is_file():
                raise RuntimeError("Local OPF checkpoint incomplete; run explicit model setup")
        for filename, expected in (("config.json", _CONFIG_SHA256),
                                   ("viterbi_calibration.json", _CALIBRATION_SHA256)):
            if hashlib.sha256((self.checkpoint / filename).read_bytes()).hexdigest() != expected:
                raise RuntimeError("OPF configuration does not match the pinned model revision")
        config = json.loads((self.checkpoint / "config.json").read_text(encoding="utf-8"))
        if config.get("encoding") != "o200k_base":
            raise RuntimeError("Unsupported OPF tokenizer; this adapter pins o200k_base")
        with (self.checkpoint / "model.safetensors").open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != MODEL_SHA256:
                raise RuntimeError("OPF weights do not match the pinned model revision")
        tokenizer_cache = self.checkpoint / "tiktoken"
        if not (tokenizer_cache / _TOKENIZER_CACHE_KEY).is_file():
            raise RuntimeError("Local tokenizer cache unavailable; run explicit model setup")
        if hashlib.sha256((tokenizer_cache / _TOKENIZER_CACHE_KEY).read_bytes()).hexdigest() != _TOKENIZER_SHA256:
            raise RuntimeError("Local tokenizer cache failed integrity check; run explicit setup")
        try:
            direct_url = json.loads(package_metadata.distribution("opf").read_text("direct_url.json") or "{}")
            revision = direct_url.get("vcs_info", {}).get("commit_id")
            archive_url = f"https://github.com/openai/privacy-filter/archive/{OPF_REVISION}.zip"
            if revision != OPF_REVISION and direct_url.get("url") != archive_url:
                raise RuntimeError("OPF runtime is not the pinned source; follow docs/model-setup.md")
            from opf import OPF
            import torch
            import tiktoken
        except (ImportError, package_metadata.PackageNotFoundError):
            raise RuntimeError("Optional OPF runtime unavailable; follow docs/model-setup.md") from None
        if os.environ.get("OPF_EXPERTS_PER_TOKEN"):
            raise RuntimeError("Custom OPF expert counts are unsupported by the pinned adapter")
        # Prime the verified on-disk tokenizer synchronously, before serving requests.
        # No model/download fallback is used. Cache integrity is checked by tiktoken.
        prior = os.environ.get("TIKTOKEN_CACHE_DIR")
        os.environ["TIKTOKEN_CACHE_DIR"] = str(tokenizer_cache)
        try:
            tiktoken.get_encoding("o200k_base")
        finally:
            if prior is None:
                os.environ.pop("TIKTOKEN_CACHE_DIR", None)
            else:
                os.environ["TIKTOKEN_CACHE_DIR"] = prior
        if device == "cpu":
            torch.set_num_threads(2)
        self._opf = OPF(model=str(self.checkpoint), device=device, decode_mode="viterbi",
                        output_mode="typed", output_text_only=False,
                        context_window_length=1024)
        self._lock = Lock()
        self.metadata = {"detector": self.name, "model_id": "openai/privacy-filter",
                         "model_revision": MODEL_REVISION, "runtime_revision": OPF_REVISION,
                         "device": device, "dtype": config["param_dtype"],
                         "decoder": "viterbi", "context_window_length": 1024,
                         "cpu_threads": 2 if device == "cpu" else None,
                         "model_sha256": MODEL_SHA256, "torch_version": torch.__version__}

    def detect(self, text: str) -> list[Span]:
        if not text:
            return []
        # The upstream runtime is lazy and not guaranteed thread-safe on first use.
        with self._lock:
            result = self._opf.redact(text)
        if result.warning or result.text != text:
            raise RuntimeError("OPF tokenizer round-trip mismatch; request rejected")
        spans: list[Span] = []
        for span in result.detected_spans:
            if span.label not in _CATEGORIES:
                raise RuntimeError("OPF returned an unsupported category")
            if not (0 <= span.start < span.end <= len(text)) or text[span.start:span.end] != span.text:
                raise RuntimeError("OPF returned invalid source offsets")
            spans.append(Span(span.start, span.end, span.label, self.name))
        return spans
