#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("matrix", Path(__file__).with_name("vpn-readiness-matrix.py"))
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="foxvpn-matrix-test-")
        self.addCleanup(self.work.cleanup)
        self.report = Path(self.work.name) / "matrix.json"
        matrix.atomic_write(self.report, matrix.plan("macos-tun", "0.1.28", "a" * 64))
        (self.report.parent / "evidence.txt").write_text("public fixture evidence", encoding="utf-8")

    def result(self, id_, **changes):
        case = next(c for c in matrix.CASES if c[0] == id_)
        value = {"status": "pass", "observations": {c: True for c in case[3]},
                 "evidence": ["evidence.txt"], "note": "public operator fixture", "authorized_window": "test-only-window"}
        value.update(changes)
        return value

    def load(self):
        return json.loads(self.report.read_text(encoding="utf-8"))

    def test_pending_is_incomplete_and_never_physical_acceptance(self):
        result = matrix.validate(self.load(), self.report)
        self.assertFalse(result["protocol_complete"])
        self.assertEqual(len(result["unresolved"]), len(matrix.CASES))
        self.assertIsInstance(result["physical_acceptance"], str)

    def test_missing_false_and_extra_checks_rejected_without_report_write(self):
        before = self.report.read_bytes()
        for observations in [{}, {"native_ipv6_not_mapped": False}, {**self.result("ipv6")["observations"], "fake": True}]:
            with self.assertRaises(ValueError):
                matrix.record(self.report, "ipv6", self.result("ipv6", observations=observations))
            self.assertEqual(before, self.report.read_bytes())

    def test_disruptive_pass_requires_window_and_evidence(self):
        for change in [{"authorized_window": None}, {"evidence": []}, {"note": ""}]:
            with self.assertRaises(ValueError):
                matrix.record(self.report, "sleep", self.result("sleep", **change))

    def test_hash_tamper_and_evidence_escape_rejected(self):
        matrix.record(self.report, "ipv4", self.result("ipv4"))
        (self.report.parent / "evidence.txt").write_text("changed")
        with self.assertRaises(ValueError):
            matrix.validate(self.load(), self.report)
        with self.assertRaises(ValueError):
            matrix.confined_evidence(self.report, "../outside")
        with self.assertRaises(ValueError):
            matrix.confined_evidence(self.report, str(self.report))

    def test_unsupported_is_unresolved_and_cannot_hide_missing_ipv6(self):
        matrix.record(self.report, "ipv6", {"status": "unsupported", "note": "No native IPv6 on fixture network"})
        self.assertIn("ipv6", matrix.validate(self.load(), self.report)["unresolved"])
        with self.assertRaises(ValueError):
            matrix.record(self.report, "ipv6", {"status": "not_applicable", "note": "No IPv6"})

    def test_case_requirements_cannot_be_removed(self):
        report = self.load()
        report["cases"][0]["required_checks"] = []
        with self.assertRaises(ValueError):
            matrix.validate(report, self.report)

    def test_retest_cannot_reuse_old_assertions(self):
        matrix.record(self.report, "ipv4", self.result("ipv4"))
        with self.assertRaises(ValueError):
            matrix.record(self.report, "ipv4", {"status": "pass", "note": "Retested", "evidence": ["evidence.txt"]})

    @unittest.skipUnless(hasattr(Path, "symlink_to"), "No symlink support")
    def test_evidence_symlink_parent_rejected(self):
        directory = self.report.parent / "actual"
        directory.mkdir()
        (directory / "proof.txt").write_text("public proof")
        link = self.report.parent / "alias"
        try:
            link.symlink_to(directory, target_is_directory=True)
        except OSError:
            self.skipTest("OS denies fixture symlinks")
        with self.assertRaises(ValueError):
            matrix.confined_evidence(self.report, "alias/proof.txt")

    def test_all_operator_assertions_complete_protocol_only(self):
        for id_, _, _, _ in matrix.CASES:
            matrix.record(self.report, id_, self.result(id_))
        result = matrix.validate(self.load(), self.report)
        self.assertTrue(result["protocol_complete"])
        self.assertIn("requires review", result["physical_acceptance"])

    def test_helper_n_a_only_for_proxy_scope(self):
        report = matrix.plan("windows-proxy", "0.1.28", "a" * 64)
        matrix.atomic_write(self.report, report)
        matrix.record(self.report, "helper_crash", {"status": "not_applicable", "note": "Windows proxy has no Mac helper"})
        self.assertNotIn("helper_crash", matrix.validate(self.load(), self.report)["unresolved"])


if __name__ == "__main__":
    unittest.main()
