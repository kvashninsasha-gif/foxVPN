#!/usr/bin/env python3
import datetime
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("audit_gate", Path(__file__).with_name("audit-dependencies.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class AuditPolicyTests(unittest.TestCase):
    def setUp(self):
        self.today = datetime.date(2026, 10, 11)
        self.baseline = json.loads((Path(__file__).parents[1] / "docs/dependency-audit-baseline.json").read_text())
        self.findings = [{field: item[field] for field in ("advisory", "package", "version", "kind")} for item in self.baseline["rust"]]
        self.trees = {target: {("serde", "1.0.229")} for target in gate.TARGETS}

    def evaluate(self):
        return gate.assess(self.findings, self.baseline, self.trees, self.today)

    def test_known_absent_platform_findings_remain_visible(self):
        results, unused = self.evaluate()
        self.assertEqual(len(results), 2)
        self.assertFalse(unused)
        self.assertTrue(all(item["status"] == "reviewed_exception" for item in results))

    def test_reachable_build_dependency_fails(self):
        self.trees[gate.TARGETS[0]].add(("glib", "0.18.5"))
        results, _ = self.evaluate()
        self.assertEqual(results[0]["status"], "unresolved")

    def test_new_version_or_advisory_is_not_suppressed(self):
        for field, changed in [("version", "0.18.6"), ("advisory", "RUSTSEC-2099-0001"), ("kind", "vulnerability")]:
            findings = [dict(item) for item in self.findings]
            findings[0][field] = changed
            results, _ = gate.assess(findings, self.baseline, self.trees, self.today)
            self.assertEqual(results[0]["status"], "unresolved")

    def test_expired_and_excessive_or_future_reviews_fail(self):
        for field, changed in [("expires", "2026-10-10"), ("expires", "2027-12-31"), ("reviewed", "2026-10-12")]:
            baseline = json.loads(json.dumps(self.baseline))
            baseline["rust"][0][field] = changed
            with self.assertRaises(ValueError):
                gate.assess(self.findings, baseline, self.trees, self.today)

    def test_no_blanket_npm_exceptions_or_missing_targets(self):
        self.baseline["npm"] = ["*"]
        with self.assertRaises(ValueError):
            self.evaluate()
        self.baseline["npm"] = []
        del self.trees[gate.TARGETS[0]]
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_removed_findings_need_baseline_cleanup(self):
        _, unused = gate.assess([], self.baseline, self.trees, self.today)
        self.assertEqual(len(unused), 2)

    def test_npm_new_advisory_is_unresolved(self):
        raw = {"auditReportVersion": 2, "metadata": {"vulnerabilities": {"total": 1}},
               "vulnerabilities": {"public-fixture": {"severity": "high", "via": [{"source": 123}], "nodes": ["node_modules/public-fixture"], "range": "<2", "fixAvailable": True}}}
        self.assertEqual(gate.npm_findings(raw)[0]["status"], "unresolved")
        raw["error"] = {"code": "API_DOWN"}
        with self.assertRaises(ValueError):
            gate.npm_findings(raw)

    def test_scanner_filtering_and_inconsistent_counts_fail(self):
        raw = {"settings": {"ignore": [], "target_arch": [], "target_os": [], "severity": None,
                             "informational_warnings": ["unmaintained", "unsound", "notice"]},
               "vulnerabilities": {"count": 0, "list": []}, "warnings": {}}
        self.assertEqual(gate.rust_findings(raw), [])
        raw["settings"]["ignore"] = ["RUSTSEC-2024-0429"]
        with self.assertRaises(ValueError):
            gate.rust_findings(raw)
        raw["settings"]["ignore"] = []
        raw["vulnerabilities"]["count"] = 1
        with self.assertRaises(ValueError):
            gate.rust_findings(raw)

    def test_windows_npm_uses_node_entrypoint_without_shell(self):
        with tempfile.TemporaryDirectory(prefix="foxvpn-audit-public-") as work:
            root = Path(work)
            cli = root / "node_modules/npm/bin/npm-cli.js"
            cli.parent.mkdir(parents=True)
            cli.write_text("public fixture")
            command = gate.windows_npm_command(root / "npm.cmd", "node.exe", ["audit", "--json"])
            self.assertEqual(command, ["node.exe", str(cli), "audit", "--json"])
            cli.unlink()
            with self.assertRaises(ValueError):
                gate.windows_npm_command(root / "npm.cmd", "node.exe", ["--version"])

    def test_missing_scanner_invalidates_stale_success_and_owned_evidence(self):
        with tempfile.TemporaryDirectory(prefix="foxvpn-audit-failure-public-") as work:
            output = Path(work)
            (output / "summary.json").write_text('{"passed":true}')
            (output / "npm.json").write_text("stale public npm report")
            (output / "operator-note.txt").write_text("leave unrelated local note intact")
            env = {**os.environ, "PATH": str(output / "missing-tools")}
            result = subprocess.run([sys.executable, str(Path(gate.__file__)), "--report-dir", str(output)],
                                    env=env, capture_output=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            summary = json.loads((output / "summary.json").read_text())
            self.assertFalse(summary["passed"])
            self.assertTrue(summary["error"])
            self.assertFalse((output / "npm.json").exists())
            self.assertNotIn("operator-note.txt", summary["evidence_sha256"])
            self.assertTrue((output / "operator-note.txt").exists())

if __name__ == "__main__":
    unittest.main()
