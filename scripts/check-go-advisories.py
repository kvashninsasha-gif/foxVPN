#!/usr/bin/env python3
"""Fail-closed govulncheck JSON-stream gate; exact dated OpenPGP wildcard review.

The scanner's binary JSON exit code alone does not enforce findings. Only an
unchanged reviewed wildcard advisory with a complete paired production package
graph can be assessed out; concrete symbols and every other finding fail.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re

ROOT_PACKAGE = "github.com/sagernet/sing-box/cmd/sing-box"
ROOT_MODULE = "github.com/sagernet/sing-box"
CRYPTO_MODULE = "golang.org/x/crypto"
CRYPTO_VERSION = "v0.57.0"
EXPECTED_GO = "go1.26.9"
REVIEW_ID = "GO-2026-5932"
REVIEW_MODIFIED = "2026-07-07T22:15:29Z"
REVIEWED = datetime.date(2026, 10, 11)
EXPIRES = datetime.date(2026, 12, 31)
OPENPGP = CRYPTO_MODULE + "/openpgp"
OPENPGP_PATHS = {OPENPGP, *[OPENPGP + "/" + name for name in ("packet", "armor", "clearsign", "errors", "elgamal", "s2k")]}


def objects(data):
    if not isinstance(data, str) or not data.strip():
        raise ValueError("Empty JSON stream")
    decoder = json.JSONDecoder()
    position = 0
    result = []
    while position < len(data):
        while position < len(data) and data[position].isspace():
            position += 1
        if position == len(data):
            break
        obj, position = decoder.raw_decode(data, position)
        if not isinstance(obj, dict):
            raise ValueError("JSON stream event must be an object")
        result.append(obj)
    return result


def parse_report(data):
    config = sbom = None
    advisories = {}
    matches = []
    for event in objects(data):
        if len(event) != 1:
            raise ValueError("Ambiguous scanner event")
        kind, value = next(iter(event.items()))
        if kind not in {"config", "SBOM", "osv", "finding", "progress"} or not isinstance(value, dict):
            raise ValueError("Unknown/error/malformed scanner event")
        if kind == "config":
            if config is not None:
                raise ValueError("Repeated scanner configuration")
            config = value
        elif kind == "SBOM":
            if sbom is not None:
                raise ValueError("Repeated SBOM")
            sbom = value
        elif kind == "osv":
            id_ = value.get("id")
            if not isinstance(id_, str) or not re.fullmatch(r"GO-[0-9]{4}-[0-9]{4,}", id_):
                raise ValueError("Missing/malformed advisory ID")
            # The same OSV can be emitted for multiple SBOM modules. Only an
            # identical repeated definition is safe; conflicting data fails.
            if id_ in advisories and advisories[id_] != value:
                raise ValueError("Conflicting repeated advisory definition")
            if not isinstance(value.get("summary"), str):
                raise ValueError("Missing advisory summary")
            advisories[id_] = value
        elif kind == "finding":
            if not isinstance(value.get("osv"), str) or not isinstance(value.get("trace"), list) or not value["trace"]:
                raise ValueError("Finding without advisory or nonempty trace")
            for frame in value["trace"]:
                if not isinstance(frame, dict) or any(not isinstance(frame.get(field), str) or not frame[field] for field in ("module", "version")):
                    raise ValueError("Finding has incomplete module/version trace")
                for field in ("package", "function", "receiver"):
                    if field in frame and (not isinstance(frame[field], str) or not frame[field]):
                        raise ValueError("Malformed symbol trace")
                if "function" in frame and "package" not in frame:
                    raise ValueError("Symbol trace without package")
            matches.append(value)
    if not config or any(config.get(field) != expected for field, expected in
                         (("protocol_version", "v1.0.0"), ("scanner_name", "govulncheck"), ("scanner_version", "v1.8.0"),
                          ("db", "https://vuln.go.dev"), ("scan_mode", "binary"), ("scan_level", "symbol"))):
        raise ValueError("Missing/unsupported binary symbol scan configuration")
    modified = config.get("db_last_modified")
    if not isinstance(modified, str):
        raise ValueError("Missing vulnerability database identity timestamp")
    try:
        if datetime.datetime.fromisoformat(modified.replace("Z", "+00:00")).tzinfo is None:
            raise ValueError("Database timestamp must contain timezone")
    except ValueError as error:
        raise ValueError("Malformed vulnerability database timestamp") from error
    if not sbom or not isinstance(sbom.get("go_version"), str) or not isinstance(sbom.get("modules"), list) or not sbom["modules"] or sbom.get("roots") != [ROOT_MODULE]:
        raise ValueError("Missing/malformed production binary SBOM")
    modules = {}
    for module in sbom["modules"]:
        if not isinstance(module, dict) or any(not isinstance(module.get(field), str) or not module[field] for field in ("path", "version")) or module["path"] in modules:
            raise ValueError("Malformed/duplicate SBOM module")
        modules[module["path"]] = module["version"]
    if modules.get("stdlib") != sbom["go_version"] or ROOT_MODULE not in modules:
        raise ValueError("Missing production/stdlib module in SBOM")
    if any(match["osv"] not in advisories for match in matches):
        raise ValueError("Finding references an absent advisory definition")
    return {"config": config, "SBOM": sbom, "modules": modules, "advisories": advisories, "findings": matches}


def findings(data):
    """Keep every reported advisory level; module/package-only is not all-clear."""
    report = parse_report(data)
    return {id_: report["advisories"][id_]["summary"] for id_ in sorted({finding["osv"] for finding in report["findings"]})}


def production_graph(data, report):
    records = {}
    for record in objects(data):
        path = record.get("ImportPath")
        if not isinstance(path, str) or not path or any(c.isspace() for c in path) or path in records:
            raise ValueError("Missing/duplicate/malformed production ImportPath")
        if record.get("Incomplete") or record.get("Error") or record.get("DepsErrors"):
            raise ValueError("Production package graph has resolution errors")
        for field in ("Imports", "Deps"):
            values = record.get(field, [])
            if not isinstance(values, list) or any(not isinstance(v, str) or not v for v in values) or len(values) != len(set(values)):
                raise ValueError("Malformed dependency list")
        if not isinstance(record.get("ImportMap", {}), dict):
            raise ValueError("Malformed import map")
        records[path] = record
    root = records.get(ROOT_PACKAGE)
    required = {"runtime", "net/http", CRYPTO_MODULE + "/chacha20poly1305", "google.golang.org/grpc"}
    if not root or "Deps" not in root or not required.issubset(records):
        raise ValueError("Missing production root/dependency graph")
    if set(root["Deps"]) != set(records) - {ROOT_PACKAGE}:
        raise ValueError("Truncated/unrelated production graph: root Deps closure differs")
    for record in records.values():
        import_map = record.get("ImportMap", {})
        for dependency in [*record.get("Imports", []), *record.get("Deps", [])]:
            dependency = import_map.get(dependency, dependency)
            if dependency != "C" and dependency not in records:
                raise ValueError("Production graph omits imported/dependent package")
        module = record.get("Module")
        if module:
            if not isinstance(module, dict) or not isinstance(module.get("Path"), str):
                raise ValueError("Malformed production module")
            if module["Path"] == CRYPTO_MODULE and (module.get("Version") != CRYPTO_VERSION or report["modules"].get(CRYPTO_MODULE) != CRYPTO_VERSION):
                raise ValueError("Production graph/SBOM crypto version mismatch")
    crypto = records[CRYPTO_MODULE + "/chacha20poly1305"].get("Module", {})
    if crypto.get("Path") != CRYPTO_MODULE or crypto.get("Version") != CRYPTO_VERSION:
        raise ValueError("Missing exact production crypto module version")
    return records


def is_openpgp(path):
    # Reject vendored OpenPGP too; no absence claim based on a path spelling.
    if path.startswith("vendor/"):
        path = path[len("vendor/"):]
    if "/vendor/" in path:
        path = path.split("/vendor/", 1)[1]
    return path == OPENPGP or path.startswith(OPENPGP + "/")


def wildcard_only(advisory, matches):
    if advisory.get("modified") != REVIEW_MODIFIED or advisory.get("schema_version") != "1.3.1":
        return False
    affected = advisory.get("affected")
    if not isinstance(affected, list) or len(affected) != 1 or not isinstance(affected[0], dict) or affected[0].get("package") != {"name": CRYPTO_MODULE, "ecosystem": "Go"}:
        return False
    specific = affected[0].get("ecosystem_specific", {})
    if not isinstance(specific, dict):
        return False
    imports = specific.get("imports", [])
    if not isinstance(imports, list):
        return False
    if len(imports) != len(OPENPGP_PATHS) or any(not isinstance(item, dict) or set(item) != {"path"} for item in imports) or {item["path"] for item in imports} != OPENPGP_PATHS:
        return False
    saw_wildcard = False
    for match in matches:
        for frame in match["trace"]:
            if frame["module"] != CRYPTO_MODULE or frame["version"] != CRYPTO_VERSION:
                return False
            package = frame.get("package")
            if package is not None and package not in OPENPGP_PATHS:
                return False
            if "function" in frame:
                # Actual binary scanner splits golang.org/.../* at its dot into
                # receiver='golang', function='org/.../*'. '*' elsewhere is not it.
                if package not in OPENPGP_PATHS or frame.get("receiver") != "golang" or frame["function"] != package.removeprefix("golang.") + "/*":
                    return False
                saw_wildcard = True
    return saw_wildcard


def assess(data, graph_data=None, today=None):
    report = parse_report(data)
    results = {id_: report["advisories"][id_]["summary"] for id_ in sorted({finding["osv"] for finding in report["findings"]})}
    records = production_graph(graph_data, report) if graph_data is not None else None
    reviewed = {}
    levels = {}
    for finding in report["findings"]:
        level = "symbol" if any(frame.get("function") for frame in finding["trace"]) else "package" if any(frame.get("package") for frame in finding["trace"]) else "module"
        counts = levels.setdefault(finding["osv"], {"module": 0, "package": 0, "symbol": 0})
        counts[level] += 1
    today = today or datetime.datetime.now(datetime.timezone.utc).date()
    if REVIEW_ID in results:
        matches = [finding for finding in report["findings"] if finding["osv"] == REVIEW_ID]
        if (records is not None and REVIEWED <= today <= EXPIRES and report["SBOM"]["go_version"] == EXPECTED_GO
                and report["modules"].get(CRYPTO_MODULE) == CRYPTO_VERSION
                and wildcard_only(report["advisories"][REVIEW_ID], matches)
                and not any(is_openpgp(path) for path in records)):
            reviewed[REVIEW_ID] = {"summary": results.pop(REVIEW_ID), "reviewed": REVIEWED.isoformat(), "expires": EXPIRES.isoformat(),
                                   "assessment": "Only reviewed pseudo-wildcard matches; OpenPGP absent from complete paired production graph",
                                   "source": "https://pkg.go.dev/vuln/" + REVIEW_ID}
    return {"passed": not results, "reviewed_findings": reviewed, "symbol_advisories": results,
            "finding_count": len(report["findings"]), "finding_levels": levels, "scanner": report["config"],
            "report_sha256": hashlib.sha256(data.encode()).hexdigest(),
            "production_graph_sha256": hashlib.sha256(graph_data.encode()).hexdigest() if graph_data is not None else None,
            "scope": "Every binary-report finding; graph-based exact wildcard review, not call reachability or device acceptance"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--compiled-packages", type=Path, help="Complete go list -deps -json stream from the paired production build")
    args = parser.parse_args()
    try:
        # Preserve byte identity across Windows CRLF and Unix LF. read_text()
        # universal-newline normalization would make the reported hash differ.
        result = assess(args.report.read_bytes().decode("utf-8"), args.compiled_packages.read_bytes().decode("utf-8") if args.compiled_packages else None)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"passed": False, "error": str(error)}, indent=2))
        return 1
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
