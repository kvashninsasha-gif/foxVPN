#!/usr/bin/env python3
"""Audit current lockfiles. Exact dated RustSec assessments, no blanket ignores.

Fetches the current RustSec database and npm advisory API. A scanner outage,
invalid report, changed lockfile, new finding, expired assessment or a package
newly reachable on a shipped target fails the gate. Native/Go vendor scanning
is a separate gate; this script must never call the combined build all-clear.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

TARGETS = ("aarch64-apple-darwin", "x86_64-apple-darwin", "x86_64-pc-windows-msvc")


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def rust_findings(raw):
    settings = raw["settings"]
    if settings.get("ignore") or settings.get("target_arch") or settings.get("target_os") or settings.get("severity") is not None:
        raise ValueError("cargo-audit filtering/ignore policy is forbidden")
    if not {"unmaintained", "unsound", "notice"}.issubset(set(settings["informational_warnings"])):
        raise ValueError("cargo-audit omitted informational advisory categories")
    section = raw["vulnerabilities"]
    if not isinstance(section["list"], list) or section["count"] != len(section["list"]):
        raise ValueError("Invalid cargo-audit vulnerability count")
    findings = []
    for kind, entries in [("vulnerability", section["list"]), *raw.get("warnings", {}).items()]:
        if not isinstance(entries, list):
            raise ValueError("Invalid cargo-audit warnings")
        for item in entries:
            package = item["package"]
            advisory = item.get("advisory") or {}
            versions = item.get("versions")
            if versions is None:
                versions = {}
            if not isinstance(versions, dict):
                raise ValueError("Invalid cargo-audit versions")
            findings.append({"advisory": advisory.get("id", "YANKED"), "package": package["name"],
                             "version": package["version"], "kind": kind,
                             "title": advisory.get("title", "Yanked package"),
                             "url": advisory.get("url"), "patched": versions.get("patched", [])})
    return findings


def tree_packages(text):
    found = set()
    for line in text.splitlines():
        match = re.match(r"^([A-Za-z0-9_-]+) v([^\s]+)(?:\s|$)", line)
        if match:
            found.add(match.groups())
    if not found:
        raise ValueError("Empty/unparseable cargo target tree")
    return found


def assess(findings, baseline, trees, today):
    if baseline.get("schema") != 1 or baseline.get("npm") != [] or set(trees) != set(TARGETS):
        raise ValueError("Wrong assessment schema, npm baseline or target coverage")
    indexed = {}
    for item in baseline["rust"]:
        key = tuple(item[field] for field in ("advisory", "package", "version", "kind"))
        if key in indexed or any(not item.get(field) for field in ("rationale", "source", "reviewed", "expires", "disposition")):
            raise ValueError("Duplicate/incomplete advisory assessment")
        if not item["source"].startswith("https://rustsec.org/advisories/" + item["advisory"]):
            raise ValueError("Assessment needs its primary RustSec source")
        reviewed = datetime.date.fromisoformat(item["reviewed"])
        expires = datetime.date.fromisoformat(item["expires"])
        if reviewed > today or expires < today or not 0 < (expires - reviewed).days <= 90:
            raise ValueError("Advisory review expired/future or exceeds 90 days")
        indexed[key] = item
    results = []
    for finding in findings:
        key = tuple(finding[field] for field in ("advisory", "package", "version", "kind"))
        review = indexed.get(key)
        reachable = [target for target, packages in trees.items() if (finding["package"], finding["version"]) in packages]
        accepted = False
        if review:
            if review["disposition"] == "not_in_shipped_targets":
                accepted = not reachable
            elif review["disposition"] == "unmaintained_transitive":
                accepted = finding["kind"] == "unmaintained"
            else:
                raise ValueError("Unknown disposition")
        results.append({**finding, "reachable_targets": reachable, "assessment": review,
                        "status": "reviewed_exception" if accepted else "unresolved"})
    # A resolved finding does not silently keep a stale wildcard exception alive.
    unused = [dict(zip(("advisory", "package", "version", "kind"), key))
              for key in indexed if key not in {tuple(f[field] for field in ("advisory", "package", "version", "kind")) for f in findings}]
    return results, unused


def npm_findings(raw):
    if raw.get("auditReportVersion") != 2 or "error" in raw:
        raise ValueError("npm audit API failed/unsupported report")
    vulns = raw["vulnerabilities"]
    if not isinstance(vulns, dict) or (bool(vulns) != (raw["metadata"]["vulnerabilities"]["total"] > 0)):
        raise ValueError("npm audit count inconsistent")
    return [{"package": name, "severity": info["severity"], "via": info["via"],
             "nodes": info["nodes"], "range": info["range"], "fix_available": info["fixAvailable"],
             "status": "unresolved"} for name, info in sorted(vulns.items())]


def windows_npm_command(npm_binary, node_binary, arguments):
    # Invoke the JS entrypoint directly. Never send paths/report input to cmd.exe.
    cli = Path(npm_binary).parent / "node_modules/npm/bin/npm-cli.js"
    if not node_binary or not cli.is_file():
        raise ValueError("Cannot locate the native npm JavaScript entrypoint")
    return [node_binary, str(cli), *arguments]


def execute(command, cwd, output, allowed=(0,)):
    if command[0] == "npm" and os.name == "nt":
        command = windows_npm_command(shutil.which("npm") or "", shutil.which("node"), command[1:])
    result = subprocess.run(command, cwd=cwd, stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=300)
    output.write_text(result.stdout, encoding="utf-8")
    output.with_suffix(".stderr.txt").write_text(result.stderr, encoding="utf-8")
    if result.returncode not in allowed:
        raise ValueError(f"Scanner/target tree command failed ({result.returncode}): {command[0]}")
    return result.stdout, result.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", required=True, type=Path)
    parser.add_argument("--baseline", type=Path, default=Path("docs/dependency-audit-baseline.json"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.report_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    summary_path = output / "summary.json"
    summary_path.unlink(missing_ok=True)
    # Invalidate only this tool's outputs. An early scanner failure must not
    # leave last run's npm/tree evidence looking current in the artifact.
    evidence_names = ["rustsec.json", "npm.json", "cargo_audit-version.txt", "npm-version.txt", "rustc-version.txt",
                      *[target + "-tree.txt" for target in TARGETS]]
    evidence_paths = [output / name for name in evidence_names]
    evidence_paths += [path.with_suffix(".stderr.txt") for path in evidence_paths]
    for path in evidence_paths:
        path.unlink(missing_ok=True)
    tracked = [root / name for name in ("Cargo.lock", "Cargo.toml", "apps/desktop/src-tauri/Cargo.toml", "apps/desktop/package-lock.json", "apps/desktop/package.json")]
    before = {str(path.relative_to(root)): sha256(path) for path in tracked}
    summary = {"schema": 1, "passed": False, "checked_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "scanner_host": sys.platform,
               "policy_script_sha256": sha256(Path(__file__)),
               "lockfiles_and_manifests": before, "targets": list(TARGETS),
               "scope": "RustSec Cargo.lock + production/build target reachability; npm all dependencies including development",
               "native_vendor_scope": "Not covered here; sing-box/Go and llama.cpp/native sources require their separate supplier/source gates"}
    try:
        baseline_path = args.baseline if args.baseline.is_absolute() else root / args.baseline
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        summary["baseline_sha256"] = sha256(baseline_path)
        versions = {}
        for name, command in (("cargo_audit", ["cargo", "audit", "--version"]), ("npm", ["npm", "--version"]), ("rustc", ["rustc", "--version"])):
            value, _ = execute(command, root, output / (name + "-version.txt"))
            versions[name] = value.strip()
        summary["scanner_versions"] = versions
        raw_rust, rust_code = execute(["cargo", "audit", "--json", "--deny", "warnings"], root, output / "rustsec.json", (0, 1))
        rust = json.loads(raw_rust)
        findings = rust_findings(rust)
        if rust_code == 1 and not findings:
            raise ValueError("cargo-audit failed without findings")
        summary["rustsec_database"] = rust["database"]
        trees = {}
        for target in TARGETS:
            raw, _ = execute(["cargo", "tree", "--locked", "--workspace", "--target", target,
                              "--edges", "normal,build", "--prefix", "none", "--format", "{p}"], root, output / (target + "-tree.txt"))
            trees[target] = tree_packages(raw)
        summary["rust"], summary["unused_assessments"] = assess(findings, baseline, trees, datetime.datetime.now(datetime.timezone.utc).date())
        raw_npm, npm_code = execute(["npm", "audit", "--json"], root / "apps/desktop", output / "npm.json", (0, 1))
        npm = json.loads(raw_npm)
        summary["npm"] = npm_findings(npm)
        summary["npm_metadata"] = npm["metadata"]
        if npm_code == 1 and not summary["npm"]:
            raise ValueError("npm audit failed without findings")
        if before != {str(path.relative_to(root)): sha256(path) for path in tracked}:
            raise ValueError("Lockfile or manifest changed during audit")
        summary["passed"] = not summary["npm"] and not any(item["status"] == "unresolved" for item in summary["rust"]) and not summary["unused_assessments"]
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        summary["error"] = str(error)
    summary["evidence_sha256"] = {path.name: sha256(path) for path in evidence_paths if path.is_file()}
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": summary["passed"], "rust_findings": len(summary.get("rust", [])),
                      "npm_findings": len(summary.get("npm", [])), "error": summary.get("error"),
                      "report": str(summary_path)}, ensure_ascii=False))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
