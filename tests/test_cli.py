import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class CLITests(unittest.TestCase):
    def run_cli(self, *args, payload=b""):
        return subprocess.run([sys.executable, "-m", "mirogate_boundary", *args],
                              input=payload, capture_output=True, timeout=20)

    def test_rules_scan_stdin(self):
        result = self.run_cli("scan", "--detector", "rules", payload="راسل demo@example.com".encode())
        self.assertEqual(result.returncode, 0, result.stderr)
        body = json.loads(result.stdout)
        self.assertEqual(body["decision"], "tokenize")
        self.assertNotIn(b"demo@example.com", result.stdout)

    def test_secret_block_exit(self):
        result = self.run_cli("scan", "--detector", "rules", payload=b'api_key="sk-test_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"')
        self.assertEqual(result.returncode,2)
        self.assertIsNone(json.loads(result.stdout)["text"])

    def test_default_no_checkpoint_no_fallback(self):
        result = self.run_cli("scan", payload=b"sensitive input not echoed")
        self.assertEqual(result.returncode,3)
        self.assertNotIn(b"sensitive input",result.stderr)
        self.assertFalse(result.stdout)

    def test_invalid_utf8_safe_error(self):
        result = self.run_cli("scan","--detector","rules",payload=b"\xffprivate")
        self.assertEqual(result.returncode,3)
        self.assertNotIn(b"private",result.stderr)

    def test_receipts_cli(self):
        with tempfile.TemporaryDirectory() as temp:
            path = str(Path(temp)/"receipt.jsonl")
            scanned = self.run_cli("scan","--detector","rules","--receipts",path,payload=b"demo@example.com")
            self.assertEqual(scanned.returncode,0)
            verified = self.run_cli("verify",path)
            self.assertEqual(verified.returncode,0)
            self.assertTrue(json.loads(verified.stdout)["valid"])
            self.assertNotIn("example",Path(path).read_text())

    def test_model_setup_help_explicit(self):
        result = self.run_cli("model-setup","--help")
        self.assertEqual(result.returncode,0)

    def test_no_raw_traceback_for_bad_policy(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/"policy.json"
            path.write_text('{"private_person":"invalid"}')
            result = self.run_cli("scan","--detector","rules","--policy",str(path),payload=b"hello")
            self.assertEqual(result.returncode,3)
            self.assertNotIn(b"Traceback",result.stderr)
