"""Scorer controls prove metric behavior, not detector capability."""

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from mirogate_boundary.benchmark import evaluate, load_dataset


CORPUS = Path(__file__).resolve().parents[1] / "benchmarks" / "arabic-privacy-v0.1.jsonl"


def row(text="a@example.com", spans=None, identifier="case-1"):
    return {"id": identifier, "family": "test", "text": text,
            "spans": spans if spans is not None else [{"start": 0, "end": len(text), "category": "private_email"}],
            "provenance": "synthetic"}


class FixedDetector:
    def __init__(self, spans):
        self.spans = spans

    def detect(self, text):
        return self.spans


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.tmp_path = Path(self.directory.name)

    def dataset(self, rows):
        path = self.tmp_path / "fixture.jsonl"
        path.write_text("\n".join(json.dumps(item) for item in rows), encoding="utf-8")
        return path

    def test_corpus_is_varied_and_offsets_valid(self):
        rows, digest = load_dataset(CORPUS)
        self.assertGreaterEqual(len(rows), 80)
        self.assertGreaterEqual(len({item["family"] for item in rows}), 9)
        self.assertGreaterEqual(sum(not item["spans"] for item in rows), 15)
        self.assertEqual(len(digest), 64)
        self.assertTrue(all(item["provenance"] == "synthetic" for item in rows))
        emoji_case = next(item for item in rows if item["id"] == "unicode-01")
        span = emoji_case["spans"][0]
        self.assertEqual(emoji_case["text"][span["start"]:span["end"]], "parcel@example.com")

    def test_perfect_span_control(self):
        report = evaluate(FixedDetector([SimpleNamespace(start=0, end=13, category="private_email")]), self.dataset([row()]))
        self.assertEqual(report["overall"]["entity_strict"], {"precision": 1.0, "recall": 1.0, "f1": 1.0})
        self.assertEqual(report["overall"]["character_coverage_recall"], 1.0)
        self.assertNotIn("a@example.com", json.dumps(report))

    def test_no_prediction_control(self):
        overall = evaluate(FixedDetector([]), self.dataset([row()]))["overall"]
        self.assertEqual(overall["entity_strict"], {"precision": None, "recall": 0.0, "f1": 0.0})
        self.assertEqual(overall["character_coverage_recall"], 0.0)
        self.assertEqual(overall["counts"]["zero_covered_gold_entities"], 1)

    def test_partial_span_and_wrong_category_are_distinguished(self):
        detector = FixedDetector([{"start": 0, "end": 2, "category": "private_person"}])
        overall = evaluate(detector, self.dataset([row(text="abcd")]))["overall"]
        self.assertEqual(overall["entity_strict"]["recall"], 0.0)
        self.assertEqual(overall["character_coverage_recall"], 0.5)
        self.assertEqual(overall["typed_character_coverage_recall"], 0.0)
        self.assertEqual(overall["counts"]["partially_covered_gold_entities"], 1)

    def test_over_redaction_and_false_positive(self):
        text = "xx private yy"
        gold = [{"start": 3, "end": 10, "category": "private_person"}]
        detector = FixedDetector([{"start": 0, "end": len(text), "category": "private_person"}])
        overall = evaluate(detector, self.dataset([row(text=text, spans=gold)]))["overall"]
        self.assertEqual(overall["character_coverage_recall"], 1.0)
        self.assertEqual(overall["non_sensitive_character_redaction_rate"], 1.0)
        self.assertEqual(overall["entity_strict"]["f1"], 0.0)

    def test_duplicates_are_false_positives(self):
        span = {"start": 0, "end": 13, "category": "private_email"}
        report = evaluate(FixedDetector([span, span]), self.dataset([row()]))
        self.assertEqual(report["overall"]["entity_strict"]["precision"], 0.5)
        self.assertEqual(report["overall"]["counts"]["false_positive"], 1)

    def test_negative_control_has_null_recall(self):
        detector = FixedDetector([{"start": 0, "end": 4, "category": "secret"}])
        overall = evaluate(detector, self.dataset([row("safe", spans=[])]))["overall"]
        self.assertIsNone(overall["entity_strict"]["recall"])
        self.assertEqual(overall["negative_case_false_positive_rate"], 1.0)

    def test_invalid_predictions_abort_instead_of_silent_drop(self):
        for bad_span in [
            {"start": -1, "end": 3, "category": "secret"},
            {"start": 0, "end": 99, "category": "secret"},
            {"start": True, "end": 3, "category": "secret"},
            {"start": 0, "end": 0, "category": "secret"},
            {"start": 0, "end": 3, "category": "unknown"},
        ]:
            with self.subTest(span=bad_span), self.assertRaisesRegex(ValueError, "Invalid offsets"):
                evaluate(FixedDetector([bad_span]), self.dataset([row()]))

    def test_detector_exception_does_not_expose_text(self):
        class Broken:
            def detect(self, text):
                raise ValueError(text)
        with self.assertRaisesRegex(RuntimeError, "Detector failed on dataset case 1") as error:
            evaluate(Broken(), self.dataset([row()]))
        self.assertTrue(error.exception.__suppress_context__)

    def test_gold_validation_and_hash(self):
        first = self.dataset([row()])
        _, before = load_dataset(first)
        first.write_text(first.read_text() + "\n", encoding="utf-8")
        _, after = load_dataset(first)
        self.assertNotEqual(before, after)
        duplicate = self.dataset([row(), row()])
        with self.assertRaisesRegex(ValueError, "Duplicate case"):
            load_dataset(duplicate)

    def test_metadata_is_recorded(self):
        metadata = {"model_id": "local/example", "model_revision": "abc123", "device": "cpu"}
        report = evaluate(FixedDetector([]), self.dataset([row()]), metadata=metadata)
        self.assertEqual(report["detector"]["metadata"], metadata)
        self.assertTrue(report["warning"])
        self.assertGreaterEqual(report["latency_ms"]["p95"], 0)


if __name__ == "__main__":
    unittest.main()
