#!/usr/bin/env python3
"""Create and validate a physical VPN acceptance protocol; never changes network state.

No stop/start, sleep, reboot, packet capture, shell command, or network request is
executed by this tool. Operator evidence is explicitly separate from automated
schema/hash validation. Keep the working report/evidence private.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import tempfile

# Stable check IDs prevent a vague "works" note from closing a scenario.
# Physical observations and a controlled test endpoint/capture remain necessary.
CASES = [
    ("identity", False, "Final installed app/helper/core identities", ["app_version_matches", "artifact_hashes_match", "components_match"]),
    ("baseline", False, "Before connection: known direct egress, DNS, route and proxy baseline", ["baseline_recorded", "network_working", "previous_proxy_dns_routes_recorded"]),
    ("ipv4", False, "IPv4 HTTPS to controlled endpoint", ["native_ipv4", "expected_egress", "scope_observed"]),
    ("ipv6", False, "Native IPv6 HTTPS; IPv4-mapped answers do not qualify", ["native_ipv6_not_mapped", "expected_egress", "scope_observed"]),
    ("dns", False, "Unique DNS canary with resolver-side/capture evidence", ["canary_correlated", "expected_resolver", "no_unexpected_plain_dns_in_covered_scope"]),
    ("udp", False, "UDP nonce echo with endpoint/capture evidence", ["udp_nonce_echoed", "expected_egress", "scope_observed"]),
    ("quic", False, "HTTP/3-only request; fallback to HTTP/2 does not qualify", ["http3_negotiated", "expected_egress", "scope_observed"]),
    ("rules", False, "VPN/direct exact and wildcard rules, precedence and Smart/Custom", ["vpn_rule_egress", "direct_rule_egress", "wildcard_and_exact_precedence", "smart_custom_default_verified"]),
    ("proxy_browsers", False, "Each supported browser with and without explicit proxy", ["browser_versions_recorded", "proxy_scope_verified", "outside_scope_described"]),
    ("failover", True, "Primary and every configured reserve fail in turn", ["all_reserves_exercised", "bounded_backoff", "active_server_matches", "no_leak_in_covered_scope"]),
    ("no_reserve", True, "All servers unavailable", ["no_retry_spin", "state_is_honest", "covered_scope_matches_fail_policy", "recovery_verified"]),
    ("offline", True, "Network offline then restored", ["covered_scope_matches_fail_policy", "bounded_recovery", "no_stale_action", "network_restored"]),
    ("wifi", True, "Wi-Fi/network switch with changed interface and DNS", ["old_interface_removed", "bootstrap_dns_refreshed", "covered_scope_matches_fail_policy", "network_restored"]),
    ("sleep", True, "Sleep/wake with real elapsed wall time", ["sleep_wake_recorded", "no_retry_burst", "covered_scope_matches_fail_policy", "network_restored"]),
    ("reboot", True, "Cold/reboot and login with autostart on/off", ["boot_login_recorded", "autostart_and_intent_respected", "covered_scope_matches_fail_policy", "network_restored"]),
    ("core_crash", True, "Core crash while transferring controlled traffic", ["old_process_reaped", "bounded_recovery", "covered_scope_matches_fail_policy", "network_restored"]),
    ("gui_crash", True, "GUI abrupt exit then restart", ["core_lifetime_policy_verified", "own_settings_recovered", "no_unrequested_connection", "network_restored"]),
    ("helper_crash", True, "Mac helper crash while protected", ["helper_recovery_verified", "covered_scope_matches_fail_policy", "own_settings_recovered", "network_restored"]),
    ("disconnect", True, "Disconnect/cancel during recovery", ["new_user_intent_wins", "only_own_proxy_dns_pf_routes_restored", "network_restored"]),
    ("restore", True, "Exit/update/uninstall restore previous proxy/DNS/PF state", ["previous_settings_equal", "foreign_edits_preserved", "network_restored"]),
    ("update", True, "Final installer/updater and failed launch recovery", ["signed_version_policy_preserved", "profile_preserved", "failed_launch_recovery", "network_restored"]),
    ("backup", False, "Native public Mac↔Windows backup exchange", ["native_both_directions", "complete_profile_preserved", "independent_destination_encryption"]),
]
SCOPES = ("macos-tun", "macos-proxy", "windows-proxy")
STATUSES = ("pending", "pass", "fail", "blocked", "unsupported", "not_applicable")


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_write(path, report):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".matrix-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def plan(scope, version, artifact):
    if scope not in SCOPES or not isinstance(version, str) or not version.strip():
        raise ValueError("A supported scope and final version are required")
    if not isinstance(artifact, str) or len(artifact) != 64 or any(c not in "0123456789abcdef" for c in artifact):
        raise ValueError("Final artifact SHA256 required")
    return {"schema": 1, "scope": scope, "version": version, "artifact_sha256": artifact,
            "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "validation_scope": "operator assertions and evidence integrity; no automatic physical acceptance",
            "cases": [{"id": id_, "title": title, "disruptive": disruptive, "required_checks": checks,
                       "status": "pending", "observations": {}, "evidence": [], "note": "", "authorized_window": None}
                      for id_, disruptive, title, checks in CASES]}


def confined_evidence(report_path, relative):
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError("Evidence path must be relative to report directory")
    root = Path(report_path).resolve().parent
    candidate = root / relative
    if any(part.is_symlink() for part in (candidate, *candidate.parents) if part != root and root in part.parents) or not candidate.is_file():
        raise ValueError("Evidence must be an existing regular file")
    candidate = candidate.resolve(strict=True)
    if root not in candidate.parents:
        raise ValueError("Evidence must stay within the private report directory")
    return candidate


def validate(report, report_path):
    canonical = plan(report.get("scope"), report.get("version", ""), report.get("artifact_sha256", ""))
    if report.get("schema") != 1 or len(report.get("cases", [])) != len(CASES):
        raise ValueError("Wrong matrix schema/case count")
    unresolved = []
    for expected, case in zip(canonical["cases"], report["cases"]):
        for field in ("id", "title", "disruptive", "required_checks"):
            if case.get(field) != expected[field]:
                raise ValueError("Case identity/requirements were modified")
        status = case.get("status")
        if status not in STATUSES:
            raise ValueError("Unknown case status")
        if status != "pending" and (not isinstance(case.get("note"), str) or not case["note"].strip()):
            raise ValueError("Every result needs a concrete operator note")
        if status == "not_applicable":
            if case["id"] != "helper_crash" or report["scope"] == "macos-tun":
                raise ValueError("Only helper_crash outside Mac TUN is not applicable")
            continue
        if status != "pass":
            unresolved.append(case["id"])
        else:
            if case["disruptive"] and not case.get("authorized_window"):
                raise ValueError("Disruptive pass needs the agreed maintenance window reference")
            if set(case["observations"]) != set(case["required_checks"]) or any(value is not True for value in case["observations"].values()):
                raise ValueError("Pass requires every concrete check observed true")
            if not case.get("evidence"):
                raise ValueError("Pass requires evidence files")
        for evidence in case.get("evidence", []):
            path = confined_evidence(report_path, evidence["file"])
            if digest(path) != evidence["sha256"]:
                raise ValueError("Evidence hash changed: " + evidence["file"])
    return {"protocol_complete": not unresolved, "unresolved": unresolved,
            "physical_acceptance": "requires review of operator evidence; tool only verifies protocol/hash consistency"}


def record(report_path, case_id, result):
    report_path = Path(report_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    validate(report, report_path)
    case = next((c for c in report["cases"] if c["id"] == case_id), None)
    if case is None:
        raise ValueError("Unknown case")
    if set(result) - {"status", "observations", "evidence", "note", "authorized_window"}:
        raise ValueError("Unexpected result fields")
    # A new result must supply fresh assertions/evidence; never inherit a prior pass.
    for field, default in (("status", "pending"), ("observations", {}), ("note", ""), ("authorized_window", None)):
        case[field] = result.get(field, default)
    case["evidence"] = [{"file": file, "sha256": digest(confined_evidence(report_path, file))}
                        for file in result.get("evidence", [])]
    validate(report, report_path)
    atomic_write(report_path, report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--scope", choices=SCOPES, required=True)
    init.add_argument("--version", required=True)
    init.add_argument("--artifact", type=Path, required=True)
    init.add_argument("--report", type=Path, required=True)
    add = sub.add_parser("record")
    add.add_argument("--report", type=Path, required=True)
    add.add_argument("--case", required=True)
    add.add_argument("--result", type=Path, required=True)
    check = sub.add_parser("check")
    check.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "init":
        if args.report.exists():
            raise ValueError("Refusing to replace an existing matrix")
        atomic_write(args.report, plan(args.scope, args.version, digest(args.artifact)))
    elif args.command == "record":
        record(args.report, args.case, json.loads(args.result.read_text(encoding="utf-8")))
    else:
        result = validate(json.loads(args.report.read_text(encoding="utf-8")), args.report)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["protocol_complete"] else 2
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, TypeError, OSError) as error:
        raise SystemExit("Matrix rejected: " + str(error))
