import math
import unittest
from unittest.mock import patch
from mirogate_boundary.core import BoundaryError, DetectorError, Engine, Policy, Span, Vault


class Fixed:
    def __init__(self, spans): self.spans = spans
    def detect(self, text): return self.spans


class CoreTests(unittest.TestCase):
    def test_roundtrip_and_stability(self):
        text = "a@example.com and a@example.com"
        engine = Engine(Fixed([Span(0,13,"private_email","test"), Span(18,31,"private_email","test")]))
        result = engine.protect(text)
        self.assertEqual(result.decision, "tokenize")
        self.assertNotIn("example.com", result.text)
        a, b = result.text.split(" and ")
        self.assertEqual(a,b)
        self.assertEqual(engine.vault.restore(result.text), text)
        self.assertNotIn("example", str(result.receipt))

    def test_overlap_covers_all(self):
        engine = Engine(Fixed([Span(0,4,"private_person","a"),Span(2,6,"private_email","b")]))
        result = engine.protect("abcdef rest")
        self.assertEqual(engine.vault.restore(result.text), "abcdef rest")
        self.assertNotIn("abcdef", result.text)

    def test_block_wins(self):
        result = Engine(Fixed([Span(0,1,"secret","test")])).protect("x")
        self.assertEqual(result.decision,"block")
        self.assertIsNone(result.text)

    def test_policy_cannot_disable_secrets(self):
        with self.assertRaises(BoundaryError): Policy({"secret":"allow"})
        source = {"private_person":"block"}
        policy = Policy(source)
        source["private_person"] = "allow"
        self.assertEqual(policy.action("private_person"),"block")

    def test_explicit_allow(self):
        result = Engine(Fixed([Span(0,1,"private_person","test")]), Policy({"private_person":"allow"})).protect("x")
        self.assertEqual(result.text,"x")
        self.assertEqual(result.decision,"allow")

    def test_invalid_detector_outputs(self):
        for span in [Span(-1,1,"private_email","x"), Span(0,5,"private_email","x"),
                     Span(0,1,"unknown","x"),Span(0,1,"secret","x",math.nan)]:
            with self.subTest(span=span), self.assertRaises(DetectorError): Engine(Fixed([span])).protect("hi")

    def test_detector_failure_sanitized(self):
        class Broken:
            def detect(self,text): raise RuntimeError(text)
        with self.assertRaisesRegex(DetectorError,"^detector_failed$"):
            Engine(Broken()).protect("private stuff")

    def test_tokens_not_accepted_as_input(self):
        with self.assertRaises(BoundaryError): Engine(Fixed([])).protect("<MB1_fake>")

    def test_cross_vault_and_malformed(self):
        first, second = Vault(), Vault()
        token = first.tokenize("x","private_person")
        with self.assertRaises(BoundaryError): second.restore(token)
        with self.assertRaises(BoundaryError): first.restore("<MB1_bad>")

    def test_expiry_and_bounds(self):
        vault = Vault(ttl=1,max_entries=1)
        token = vault.tokenize("x","private_person")
        with self.assertRaises(BoundaryError): vault.tokenize("y","private_person")
        with patch("mirogate_boundary.core.time.monotonic", return_value=vault._expires+1):
            with self.assertRaises(BoundaryError): vault.restore(token)
        self.assertFalse(vault._reverse)

    def test_restore_expansion_bound(self):
        vault = Vault()
        token = vault.tokenize("x"*100,"private_person")
        with self.assertRaises(BoundaryError): vault.restore(token*2,max_characters=150)

    def test_unicode_offsets(self):
        text = "☎ أحمد."
        result = Engine(Fixed([Span(2,6,"private_person","test")])).protect(text)
        self.assertTrue(result.text.startswith("☎ <MB1_"))
        self.assertTrue(result.text.endswith("."))

    def test_empty_and_limits(self):
        self.assertEqual(Engine(Fixed([])).protect("").text, "")
        with self.assertRaises(BoundaryError): Engine(Fixed([]),max_characters=1).protect("long")
