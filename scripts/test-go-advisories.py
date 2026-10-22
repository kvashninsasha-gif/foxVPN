#!/usr/bin/env python3
import copy
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("go_gate", Path(__file__).with_name("check-go-advisories.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def stream(events):
    return "\n\n".join(json.dumps(event) for event in events) + "\n"


class GoAdvisoryTests(unittest.TestCase):
    def setUp(self):
        self.date = datetime.date(2026, 10, 11)
        self.advisory = {"id": gate.REVIEW_ID, "schema_version": "1.3.1", "modified": gate.REVIEW_MODIFIED,
                         "summary": "Public OpenPGP advisory fixture",
                         "affected": [{"package": {"name": gate.CRYPTO_MODULE, "ecosystem": "Go"},
                                       "ecosystem_specific": {"imports": [{"path": path} for path in sorted(gate.OPENPGP_PATHS)]}}]}
        self.frame = {"module": gate.CRYPTO_MODULE, "version": gate.CRYPTO_VERSION,
                      "package": gate.OPENPGP + "/packet", "receiver": "golang",
                      "function": "org/x/crypto/openpgp/packet/*"}
        self.events = [{"config": {"protocol_version": "v1.0.0", "scanner_name": "govulncheck", "scanner_version": "v1.8.0",
                                   "db": "https://vuln.go.dev", "db_last_modified": "2026-10-08T22:31:09Z", "scan_mode": "binary", "scan_level": "symbol"}},
                       {"SBOM": {"go_version": gate.EXPECTED_GO, "roots": [gate.ROOT_MODULE],
                                 "modules": [{"path": "stdlib", "version": gate.EXPECTED_GO},
                                             {"path": "github.com/sagernet/sing-box", "version": "(devel)"},
                                             {"path": gate.CRYPTO_MODULE, "version": gate.CRYPTO_VERSION},
                                             {"path": "google.golang.org/grpc", "version": "v1.83.2"}]}},
                       {"osv": self.advisory}, {"finding": {"osv": gate.REVIEW_ID, "trace": [self.frame]}}]
        self.graph = [{"ImportPath": "runtime", "Imports": []}, {"ImportPath": "net/http", "Imports": ["runtime"]},
                      {"ImportPath": gate.CRYPTO_MODULE + "/chacha20poly1305", "Imports": ["runtime"],
                       "Module": {"Path": gate.CRYPTO_MODULE, "Version": gate.CRYPTO_VERSION}},
                      {"ImportPath": "google.golang.org/grpc", "Imports": ["net/http"],
                       "Module": {"Path": "google.golang.org/grpc", "Version": "v1.83.2"}}]
        self.graph.append({"ImportPath": gate.ROOT_PACKAGE, "Imports": [record["ImportPath"] for record in self.graph],
                           "Deps": [record["ImportPath"] for record in self.graph]})

    def assess(self, events=None, graph=None, date=None):
        return gate.assess(stream(events if events is not None else self.events),
                           stream(graph if graph is not None else self.graph), date or self.date)

    def test_only_exact_wildcard_and_complete_graph_has_dated_visible_assessment(self):
        result = self.assess()
        self.assertTrue(result["passed"])
        self.assertIn(gate.REVIEW_ID, result["reviewed_findings"])
        self.assertEqual(result["reviewed_findings"][gate.REVIEW_ID]["expires"], "2026-12-31")
        self.assertEqual(len(result["report_sha256"]), 64)
        self.assertEqual(len(result["production_graph_sha256"]), 64)
        self.assertEqual(result["finding_levels"][gate.REVIEW_ID], {"module": 0, "package": 0, "symbol": 1})

    def test_real_openpgp_function_is_never_suppressed_by_absent_graph(self):
        for function, receiver in [("ReadMessage", ""), ("Decrypt", "PrivateKey"), ("*", "golang"), ("Read*", "golang")]:
            events = copy.deepcopy(self.events)
            frame = events[-1]["finding"]["trace"][0]
            frame["function"] = function
            if receiver:
                frame["receiver"] = receiver
            else:
                del frame["receiver"]
            result = self.assess(events=events)
            self.assertFalse(result["passed"])
            self.assertIn(gate.REVIEW_ID, result["symbol_advisories"])

    def test_mixed_wildcard_and_genuine_symbol_keeps_whole_advisory_unresolved(self):
        events = copy.deepcopy(self.events)
        events.append({"finding": {"osv": gate.REVIEW_ID, "trace": [{**self.frame, "function": "ReadMessage"}]}})
        self.assertFalse(self.assess(events=events)["passed"])

    def test_openpgp_or_vendored_child_in_graph_prevents_exclusion(self):
        for package in [gate.OPENPGP, gate.OPENPGP + "/packet", "vendor/" + gate.OPENPGP, "example.org/module/vendor/" + gate.OPENPGP]:
            graph = copy.deepcopy(self.graph)
            graph.append({"ImportPath": package, "Imports": []})
            graph[-2]["Deps"].append(package)
            self.assertFalse(self.assess(graph=graph)["passed"])

    def test_truncated_graph_missing_root_or_import_closure_rejected(self):
        graphs = [self.graph[:-1], self.graph[1:], copy.deepcopy(self.graph), copy.deepcopy(self.graph)]
        graphs[2][-1]["Deps"].pop()
        graphs[3][0]["Imports"] = ["public/missing-package"]
        for graph in graphs:
            with self.assertRaises(ValueError):
                self.assess(graph=graph)

    def test_plain_sentinel_list_and_duplicate_error_incomplete_graph_rejected(self):
        with self.assertRaises(ValueError):
            gate.assess(stream(self.events), gate.ROOT_PACKAGE + "\n" + gate.CRYPTO_MODULE + "/chacha20poly1305\n", self.date)
        for field, value in [("Incomplete", True), ("Error", {"Err": "fixture failure"}), ("DepsErrors", [{"Err": "fixture failure"}])]:
            graph = copy.deepcopy(self.graph)
            graph[0][field] = value
            with self.assertRaises(ValueError):
                self.assess(graph=graph)
        with self.assertRaises(ValueError):
            self.assess(graph=[*self.graph, self.graph[0]])

    def test_missing_or_wrong_config_sbom_rejected(self):
        for events in [self.events[1:], self.events[:1] + self.events[2:]]:
            with self.assertRaises(ValueError):
                self.assess(events=events)
        for section, field, value in [("config", "scan_mode", "source"), ("config", "scan_level", "package"),
                                      ("config", "db", "https://public-fixture.invalid"), ("config", "scanner_version", "v0.0.0"),
                                      ("config", "db_last_modified", "malformed"),
                                      ("SBOM", "modules", []), ("SBOM", "roots", ["other/root"])]:
            events = copy.deepcopy(self.events)
            next(item[section] for item in events if section in item)[field] = value
            with self.assertRaises(ValueError):
                self.assess(events=events)

    def test_missing_definition_empty_or_incomplete_trace_rejected(self):
        events = copy.deepcopy(self.events)
        events[-1]["finding"]["osv"] = "GO-2099-0001"
        with self.assertRaises(ValueError):
            self.assess(events=events)
        for trace in [[], [{}], [{"module": gate.CRYPTO_MODULE}], [{"module": gate.CRYPTO_MODULE, "version": gate.CRYPTO_VERSION, "function": "ReadMessage"}]]:
            events = copy.deepcopy(self.events)
            events[-1]["finding"]["trace"] = trace
            with self.assertRaises(ValueError):
                self.assess(events=events)

    def test_new_advisory_and_module_only_finding_always_fail(self):
        for trace in [[{"module": "google.golang.org/grpc", "version": "v1.83.1"}],
                      [{"module": "google.golang.org/grpc", "version": "v1.83.1", "package": "google.golang.org/grpc/internal/transport", "function": "HandleStreams"}]]:
            events = copy.deepcopy(self.events)
            events += [{"osv": {"id": "GO-2026-6443", "summary": "Public new finding fixture"}},
                       {"finding": {"osv": "GO-2026-6443", "trace": trace}}]
            result = self.assess(events=events)
            self.assertFalse(result["passed"])
            self.assertIn("GO-2026-6443", result["symbol_advisories"])

    def test_changed_advisory_crypto_toolchain_or_review_date_no_exclusion(self):
        for field, value in [("modified", "2026-10-11T00:00:00Z"), ("schema_version", "1.4.0")]:
            events = copy.deepcopy(self.events)
            events[2]["osv"][field] = value
            self.assertFalse(self.assess(events=events)["passed"])
        events = copy.deepcopy(self.events)
        events[1]["SBOM"]["go_version"] = "go1.26.9"
        events[1]["SBOM"]["modules"][0]["version"] = "go1.26.9"
        self.assertFalse(self.assess(events=events)["passed"])
        for date in [datetime.date(2026, 10, 10), datetime.date(2027, 1, 1)]:
            self.assertFalse(self.assess(date=date)["passed"])

    def test_advisory_scope_or_trace_package_change_is_not_suppressed(self):
        events = copy.deepcopy(self.events)
        events[2]["osv"]["affected"][0]["ecosystem_specific"]["imports"][0]["path"] = "golang.org/x/crypto/ssh"
        self.assertFalse(self.assess(events=events)["passed"])
        events = copy.deepcopy(self.events)
        events[-1]["finding"]["trace"][0]["package"] = "golang.org/x/crypto/ssh"
        self.assertFalse(self.assess(events=events)["passed"])

    def test_module_version_mismatch_fails_closed(self):
        graph = copy.deepcopy(self.graph)
        graph[2]["Module"]["Version"] = "v0.56.0"
        with self.assertRaises(ValueError):
            self.assess(graph=graph)

    def test_module_only_openpgp_finding_without_wildcard_is_unresolved(self):
        events = copy.deepcopy(self.events)
        events[-1]["finding"]["trace"] = [{"module": gate.CRYPTO_MODULE, "version": gate.CRYPTO_VERSION}]
        self.assertFalse(self.assess(events=events)["passed"])

    def test_malformed_trailing_events_error_and_duplicates_rejected(self):
        conflicting = copy.deepcopy(self.events[2])
        conflicting["osv"]["modified"] = "2026-10-11T00:00:00Z"
        for data in ["", "[]", stream(self.events) + "broken", stream(self.events) + '{"error":{"message":"failed"}}',
                     stream([*self.events, self.events[0]]), stream([*self.events, self.events[1]]),
                     stream([*self.events, conflicting])]:
            with self.assertRaises(ValueError):
                gate.assess(data, stream(self.graph), self.date)

    def test_identical_repeated_osv_definitions_do_not_drop_findings(self):
        result = self.assess(events=[*self.events, copy.deepcopy(self.events[2])])
        self.assertEqual(result["finding_count"], 1)
        self.assertIn(gate.REVIEW_ID, result["reviewed_findings"])

    def test_clean_complete_binary_report_passes_without_ignoring_definitions(self):
        result = self.assess(events=self.events[:-1])
        self.assertTrue(result["passed"])
        self.assertFalse(result["reviewed_findings"])
        self.assertEqual(result["finding_count"], 0)

    def test_cli_malformed_report_outputs_failure_json_not_success(self):
        with tempfile.TemporaryDirectory(prefix="foxvpn-go-audit-public-") as work:
            report = Path(work) / "report.json"
            report.write_text("{}")
            result = subprocess.run([sys.executable, gate.__file__, str(report)], capture_output=True, text=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(json.loads(result.stdout)["passed"])

    def test_cli_crlf_hash_binds_actual_file_bytes(self):
        with tempfile.TemporaryDirectory(prefix="foxvpn-go-audit-crlf-public-") as work:
            report, graph = Path(work) / "report.json", Path(work) / "graph.json"
            report_bytes = stream(self.events[:-1]).replace("\n", "\r\n").encode()
            graph_bytes = stream(self.graph).replace("\n", "\r\n").encode()
            report.write_bytes(report_bytes)
            graph.write_bytes(graph_bytes)
            run = subprocess.run([sys.executable, gate.__file__, str(report), "--compiled-packages", str(graph)], capture_output=True, text=True, timeout=15)
            self.assertEqual(run.returncode, 0, run.stdout)
            result = json.loads(run.stdout)
            self.assertEqual(result["report_sha256"], hashlib.sha256(report_bytes).hexdigest())
            self.assertEqual(result["production_graph_sha256"], hashlib.sha256(graph_bytes).hexdigest())


if __name__ == "__main__":
    unittest.main()
