"""Detector unit contracts. Model integration tests use fakes, not model scores."""
import tempfile
from pathlib import Path
import random
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mirogate_boundary.core import Span
from mirogate_boundary.detectors import (
    HybridDetector, OpenAIPrivacyDetector, RuleDetector, _normalized,
)


class RulesTests(unittest.TestCase):
    def setUp(self):
        self.detector = RuleDetector()

    def assertDetected(self, text, value, category):
        matches = [(text[s.start:s.end], s.category) for s in self.detector.detect(text)]
        self.assertIn((value, category), matches)

    def test_ascii_email_and_phone(self):
        self.assertDetected("Contact alice@example.com.", "alice@example.com", "private_email")
        self.assertDetected("Call +44 7700 900123.", "+44 7700 900123", "private_phone")

    def test_arabic_indic_and_persian_phone(self):
        self.assertDetected("هاتف: +٩٧١ ٥٠ ١٢٣ ٤٥٦٧", "+٩٧١ ٥٠ ١٢٣ ٤٥٦٧", "private_phone")
        self.assertDetected("موبايل: ۰۹۳۳۱۲۳۴۵۶", "۰۹۳۳۱۲۳۴۵۶", "private_phone")

    def test_normalization_preserves_original_offsets(self):
        text = "بريد: ａｌｉｃｅ＠ｅｘａｍｐｌｅ．ｃｏｍ!"
        self.assertDetected(text, "ａｌｉｃｅ＠ｅｘａｍｐｌｅ．ｃｏｍ", "private_email")
        self.assertDetected("+٩٧١\u200b٥٠١٢٣٤٥٦٧", "+٩٧١\u200b٥٠١٢٣٤٥٦٧", "private_phone")
        normalized, starts, ends = _normalized("ﻻ١٢")
        self.assertEqual(normalized, "لا12")
        self.assertEqual(starts[:2], [0, 0])
        self.assertEqual(ends[:2], [1, 1])

    def test_labelled_arabic_person_address(self):
        self.assertDetected("اسم العميل: ليلى يوسف الحسن، شكراً", "ليلى يوسف الحسن", "private_person")
        self.assertDetected("عنوان السكن: دمشق شارع النور ٢١", "دمشق شارع النور ٢١", "private_address")

    def test_labelled_ids(self):
        self.assertDetected("رقم الهوية: ٧٨٤-١٩٨٨-١٢٣٤٥٦٧-١", "٧٨٤-١٩٨٨-١٢٣٤٥٦٧-١", "account_number")
        self.assertDetected("passport: AB12345678 and expires soon", "AB12345678", "account_number")
        self.assertDetected('"account_number": "123456789012"', "123456789012", "account_number")

    def test_iban_without_requiring_valid_checksum(self):
        self.assertDetected("IBAN SA03 8000 0000 6080 1016 7519", "SA03 8000 0000 6080 1016 7519", "account_number")
        self.assertDetected("حساب: AE٠٧٠٣٣١٢٣٤٥٦٧٨٩٠١٢٣٤٥٦", "AE٠٧٠٣٣١٢٣٤٥٦٧٨٩٠١٢٣٤٥٦", "account_number")

    def test_secrets(self):
        for text, value in [
            ("api_key=sk-example1234567890", "sk-example1234567890"),
            ('"password": "synthetic-pass-321"', "synthetic-pass-321"),
            ("Authorization: Bearer abcdefgh12345678", "abcdefgh12345678"),
            ("https://user:syntheticpass@example.com/path", "user:syntheticpass"),
            ("-----BEGIN PRIVATE KEY-----\nSYNTHETIC\n-----END PRIVATE KEY-----",
             "-----BEGIN PRIVATE KEY-----\nSYNTHETIC\n-----END PRIVATE KEY-----"),
        ]:
            with self.subTest(text=text):
                self.assertDetected(text, value, "secret")

    def test_public_prose_and_numbers_remain(self):
        for text in ["Public release v0.1.0 ships today.", "هذا اختبار عام للمشروع.",
                     "Price 45.75; date 2026-09-28.", "The order contains 120 units.",
                     "Read https://example.com/docs for public instructions."]:
            with self.subTest(text=text):
                self.assertEqual(self.detector.detect(text), [])

    def test_does_not_claim_unlabelled_name_detection(self):
        self.assertEqual(self.detector.detect("قابلت سعاد في المكتب اليوم"), [])

    def test_all_offsets_bounded(self):
        text = "📎\u200f +۹۷۱ ۵۰ ۱۲۳ ۴۵۶۷ بريدُ nora@example.com"
        for span in self.detector.detect(text):
            self.assertTrue(0 <= span.start < span.end <= len(text))
            self.assertEqual(span.score, 1.0)

    def test_unicode_offset_invariants_on_deterministic_random_text(self):
        rng = random.Random(20260928)
        alphabet = "abc012٠١٢۰۱۲أبﻻَُُ\u200b\u200f＠．+()-_. \n📎"
        for _ in range(200):
            text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 150)))
            normalized, starts, ends = _normalized(text)
            self.assertEqual(len(normalized), len(starts))
            self.assertEqual(len(starts), len(ends))
            for start, end in zip(starts, ends):
                self.assertTrue(0 <= start < end <= len(text))
            for span in self.detector.detect(text):
                self.assertTrue(0 <= span.start < span.end <= len(text))


class HybridTests(unittest.TestCase):
    def test_requires_detectors(self):
        with self.assertRaises(ValueError):
            HybridDetector()

    def test_never_silently_falls_back(self):
        class Broken:
            def detect(self, text):
                raise RuntimeError("unavailable")
        with self.assertRaises(RuntimeError):
            HybridDetector(RuleDetector(), Broken()).detect("a@example.com")

    def test_preserves_overlaps_for_policy(self):
        class Fixed:
            def detect(self, text):
                return [Span(0, 5, "secret", "test"), Span(1, 4, "private_person", "other")]
        spans = HybridDetector(Fixed(), Fixed()).detect("value")
        self.assertEqual(len(spans), 2)

    def test_deduplicates_exact_entities_preserving_sources(self):
        class First:
            def detect(self, text):
                return [Span(0, 5, "secret", "first")]
        class Second:
            def detect(self, text):
                return [Span(0, 5, "secret", "second")]
        self.assertEqual(HybridDetector(First(), Second()).detect("value"),
                         [Span(0, 5, "secret", "first+second")])


class ModelAdapterContractTests(unittest.TestCase):
    def adapter(self, result):
        # Only test adapter contract, explicitly without loading a real model.
        adapter = OpenAIPrivacyDetector.__new__(OpenAIPrivacyDetector)
        from threading import Lock
        adapter._lock = Lock()
        adapter._opf = SimpleNamespace(redact=lambda text: result)
        return adapter

    def test_explicit_missing_checkpoint_fails_without_download(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(RuntimeError):
                OpenAIPrivacyDetector(Path(tmp) / "missing")
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_rejects_unsupported_device(self):
        with self.assertRaises(ValueError):
            OpenAIPrivacyDetector("missing", "remote")

    def test_incomplete_root_checkpoint_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = Path(tmp) / "original"
            original.mkdir()
            with patch("mirogate_boundary.detectors.urlopen", side_effect=AssertionError("network")):
                with self.assertRaises(RuntimeError):
                    OpenAIPrivacyDetector(tmp)

    def test_untrusted_config_fails_before_runtime_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            checkpoint = Path(tmp)
            # Temporary test artifacts are fixture data, not a model download.
            for filename in ("config.json", "model.safetensors", "viterbi_calibration.json"):
                (checkpoint / filename).write_bytes(b"untrusted")
            with patch("mirogate_boundary.detectors.urlopen", side_effect=AssertionError("network")):
                with self.assertRaisesRegex(RuntimeError, "configuration"):
                    OpenAIPrivacyDetector(tmp)

    def test_maps_official_char_spans(self):
        result = SimpleNamespace(text="ليلى", warning=None,
            detected_spans=[SimpleNamespace(start=0, end=4, label="private_person", text="ليلى")])
        self.assertEqual(self.adapter(result).detect("ليلى"),
                         [Span(0, 4, "private_person", "openai-privacy-filter-viterbi")])

    def test_round_trip_mismatch_fails_closed(self):
        result = SimpleNamespace(text="changed", warning="mismatch", detected_spans=[])
        with self.assertRaises(RuntimeError):
            self.adapter(result).detect("original")

    def test_unknown_label_fails_closed(self):
        result = SimpleNamespace(text="value", warning=None,
            detected_spans=[SimpleNamespace(start=0, end=5, label="new_type", text="value")])
        with self.assertRaises(RuntimeError):
            self.adapter(result).detect("value")

    def test_bad_offsets_fail_closed(self):
        result = SimpleNamespace(text="value", warning=None,
            detected_spans=[SimpleNamespace(start=0, end=99, label="secret", text="value")])
        with self.assertRaises(RuntimeError):
            self.adapter(result).detect("value")


if __name__ == "__main__":
    unittest.main()
