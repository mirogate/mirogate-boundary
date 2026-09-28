import json
from pathlib import Path
import tempfile
import unittest
from mirogate_boundary.audit import append, verify
from mirogate_boundary.core import BoundaryError


class AuditTests(unittest.TestCase):
    def test_chain_anchor_tampering_and_truncation(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/"receipts.jsonl"
            receipt = {"schema":"mirogate.boundary.receipt.v1", "categories":{}, "characters":4,"spans":0,"decision":"allow"}
            append(path, receipt)
            head = append(path,receipt)
            self.assertEqual(verify(path,head)["entries"],2)
            lines = path.read_text().splitlines()
            path.write_text(lines[0]+"\n")
            self.assertTrue(verify(path)["valid"])
            with self.assertRaises(BoundaryError): verify(path,head)
            entry = json.loads(lines[0]); entry["receipt"]["characters"] = 55
            path.write_text(json.dumps(entry)+"\n")
            with self.assertRaises(BoundaryError): verify(path)

    def test_no_arbitrary_receipt_fields(self):
        with tempfile.TemporaryDirectory() as temp, self.assertRaises(BoundaryError):
            append(Path(temp)/"log",{"text":"should not log"})

    def test_duplicate_fields_cannot_hide_unhashed_content(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/"log"
            receipt = {"schema":"mirogate.boundary.receipt.v1", "categories":{}, "characters":0,"spans":0,"decision":"allow"}
            head = append(path,receipt)
            original = path.read_text()
            path.write_text(original.replace('"decision":"allow"', '"decision":"hidden data","decision":"allow"'))
            with self.assertRaises(BoundaryError): verify(path,head)

    def test_concurrent_writer_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/"log"
            path.with_name("log.lock").touch()
            receipt = {"schema":"mirogate.boundary.receipt.v1", "categories":{}, "characters":0,"spans":0,"decision":"allow"}
            with self.assertRaises(BoundaryError): append(path,receipt)
