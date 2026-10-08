#!/usr/bin/env python3
"""Local AgentSec KB validator, query tool, static reviewer, and MCP stdio server.

The reviewer is intentionally small and transparent. It reads local files as data,
does not execute them, does not follow symlinks, and never performs network I/O.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "knowledge" / "rules"
CWE_DATA_DIR = ROOT / "data" / "cwe" / "4.20"
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "dist", "build", "__pycache__"}
TEXT_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".cs", ".rs", ".sh", ".yaml", ".yml", ".json", ".tf", ".html", ".jinja", ".tmpl"}
REQUIRED_RULE_FIELDS = {
    "id", "title", "status", "summary", "applies_to", "cwe_ids", "risk",
    "review_checks", "safe_tests", "remediation", "references", "provenance",
}


@dataclass(frozen=True)
class Detector:
    rule_id: str
    pattern: re.Pattern[str]
    title: str
    severity: str
    confidence: str
    impact: str


DETECTORS = (
    Detector(
        "ASKB-INJECT-002",
        re.compile(r"(?:os\.system\s*\(|subprocess\.(?:run|call|Popen)\s*\([^\n]*\bshell\s*=\s*True|(?:child_process\.)?exec\s*\()"),
        "Potential shell command construction",
        "critical",
        "medium",
        "Shell interpretation of untrusted data can permit execution beyond the intended command.",
    ),
    Detector(
        "ASKB-INJECT-001",
        re.compile(r"(?:SELECT|INSERT|UPDATE|DELETE)\b[^\n]*(?:\+|\.format\s*\(|f[\"'])", re.IGNORECASE),
        "Potential dynamic database query",
        "critical",
        "low",
        "Building database query syntax from dynamic values can change query semantics.",
    ),
    Detector(
        "ASKB-SECRETS-001",
        re.compile(r"(?:password|passwd|api[_-]?key|secret|access[_-]?token)\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']", re.IGNORECASE),
        "Potential hard-coded credential",
        "high",
        "medium",
        "A credential in source control can be copied, logged, or reused outside its intended scope.",
    ),
    Detector(
        "ASKB-SECRETS-001",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "Private key material in source file",
        "critical",
        "high",
        "Private key material in source control can enable unauthorized access until revoked.",
    ),
    Detector(
        "ASKB-CRYPTO-001",
        re.compile(r"(?:verify\s*=\s*False|CERT_NONE|rejectUnauthorized\s*:\s*false)", re.IGNORECASE),
        "TLS peer verification disabled",
        "high",
        "high",
        "Disabling peer verification can allow a connection to an untrusted endpoint.",
    ),
    Detector(
        "ASKB-XSS-001",
        re.compile(r"(?:\.innerHTML\s*=|dangerouslySetInnerHTML|\|\s*safe\b)"),
        "Potential raw HTML rendering",
        "high",
        "low",
        "Rendering untrusted markup without the correct context protection can execute attacker-controlled browser content.",
    ),
    Detector(
        "ASKB-DESER-001",
        re.compile(r"(?:pickle\.loads?\s*\(|yaml\.load\s*\(|unserialize\s*\()"),
        "Potential unsafe object deserialization",
        "critical",
        "medium",
        "Deserializing untrusted object formats can invoke unsafe behavior or create unsafe state.",
    ),
    Detector(
        "ASKB-LOG-001",
        re.compile(r"(?:logger\.[a-z]+|console\.log|print)\s*\([^\n]*(?:password|token|authorization|secret)", re.IGNORECASE),
        "Potential sensitive value logging",
        "medium",
        "low",
        "Logs and client-visible errors can expose information to unintended readers.",
    ),
    Detector(
        "ASKB-IAC-001",
        re.compile(r"(?:0\.0\.0\.0/0|::/0)"),
        "Potential unrestricted network exposure",
        "high",
        "low",
        "Broad network exposure may make a service reachable beyond its intended boundary.",
    ),
)


def json_output(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def load_rules() -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for rule_path in sorted(RULES_DIR.glob("*.json")):
        with rule_path.open(encoding="utf-8") as handle:
            rule = json.load(handle)
        rule["_path"] = str(rule_path.relative_to(ROOT))
        rules.append(rule)
    return rules


@lru_cache(maxsize=1)
def load_cwe_manifest() -> dict[str, Any]:
    with (CWE_DATA_DIR / "manifest.json").open(encoding="utf-8") as handle:
        return json.load(handle)


@lru_cache(maxsize=1)
def load_cwe_index() -> list[dict[str, Any]]:
    with (CWE_DATA_DIR / "index.json").open(encoding="utf-8") as handle:
        return json.load(handle)["entries"]


@lru_cache(maxsize=1)
def load_cwe_catalog() -> dict[str, Any]:
    with (CWE_DATA_DIR / "catalog.json").open(encoding="utf-8") as handle:
        return json.load(handle)


def public_rule(rule: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in rule.items() if key != "_path"}


def validate_rules() -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    paths = sorted(RULES_DIR.glob("*.json"))
    for rule_path in paths:
        relative_path = str(rule_path.relative_to(ROOT))
        try:
            with rule_path.open(encoding="utf-8") as handle:
                rule = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            errors.append({"path": relative_path, "error": f"invalid JSON: {exc}"})
            continue
        missing = sorted(REQUIRED_RULE_FIELDS - set(rule))
        if missing:
            errors.append({"path": relative_path, "error": f"missing required fields: {', '.join(missing)}"})
            continue
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not re.fullmatch(r"ASKB-[A-Z]+-[0-9]{3}", rule_id):
            errors.append({"path": relative_path, "error": "id must match ASKB-CATEGORY-000"})
        elif rule_id in seen_ids:
            errors.append({"path": relative_path, "error": f"duplicate rule id: {rule_id}"})
        else:
            seen_ids.add(rule_id)
        if rule.get("status") not in {"draft", "stable", "deprecated"}:
            errors.append({"path": relative_path, "error": "invalid status"})
        if rule.get("risk") not in {"low", "medium", "high", "critical"}:
            errors.append({"path": relative_path, "error": "invalid risk"})
        if not isinstance(rule.get("cwe_ids"), list) or not all(re.fullmatch(r"CWE-[0-9]+", value or "") for value in rule["cwe_ids"]):
            errors.append({"path": relative_path, "error": "cwe_ids must contain CWE identifiers"})
        provenance = rule.get("provenance")
        if not isinstance(provenance, dict) or provenance.get("origin") not in {"original", "adapted", "imported"}:
            errors.append({"path": relative_path, "error": "invalid provenance.origin"})

    mapping_path = ROOT / "mappings" / "cwe.json"
    try:
        mappings = json.loads(mapping_path.read_text(encoding="utf-8"))["mappings"]
        mapped_rule_ids = {entry["rule_id"] for entry in mappings}
        for rule_id in seen_ids - mapped_rule_ids:
            errors.append({"path": "mappings/cwe.json", "error": f"missing mapping for {rule_id}"})
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        errors.append({"path": "mappings/cwe.json", "error": f"invalid mapping file: {exc}"})
    cwe_data = validate_cwe_data()
    if not cwe_data["valid"]:
        errors.extend({"path": entry["path"], "error": entry["error"]} for entry in cwe_data["errors"])
    return {"valid": not errors, "rule_count": len(paths), "cwe_data": cwe_data, "errors": errors}


def validate_cwe_data() -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    try:
        manifest = load_cwe_manifest()
        catalog = load_cwe_catalog()
        index = load_cwe_index()
        counts = manifest.get("counts", {})
        for collection in ("weaknesses", "categories", "views", "external_references"):
            actual_count = len(catalog.get(collection, []))
            expected_count = counts.get(collection)
            if actual_count != expected_count:
                errors.append({"path": "data/cwe/4.20/catalog.json", "error": f"{collection} count is {actual_count}; expected {expected_count}"})
        expected_index_count = sum(counts.get(collection, 0) for collection in ("weaknesses", "categories", "views"))
        if len(index) != expected_index_count:
            errors.append({"path": "data/cwe/4.20/index.json", "error": f"entry count is {len(index)}; expected {expected_index_count}"})
        archive = ROOT / "vendor" / "cwe" / "4.20" / "cwec_v4.20.xml.zip"
        if archive.is_file():
            import hashlib
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            if digest != manifest.get("source_archive_sha256"):
                errors.append({"path": "vendor/cwe/4.20/cwec_v4.20.xml.zip", "error": "SHA-256 does not match manifest"})
        else:
            errors.append({"path": "vendor/cwe/4.20/cwec_v4.20.xml.zip", "error": "official source archive is missing"})
        return {"valid": not errors, "version": manifest.get("cwe_version"), "counts": counts, "errors": errors}
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        return {"valid": False, "version": None, "counts": {}, "errors": [{"path": "data/cwe/4.20", "error": str(exc)}]}


def search_rules(query: str, limit: int = 10) -> list[dict[str, Any]]:
    terms = {term.lower() for term in re.findall(r"[a-zA-Z0-9_-]+", query) if len(term) > 1}
    scored: list[tuple[int, dict[str, Any]]] = []
    for rule in load_rules():
        corpus = " ".join(
            [rule["id"], rule["title"], rule["summary"], *rule.get("tags", []), *rule.get("cwe_ids", [])]
        ).lower()
        score = sum(1 for term in terms if term in corpus)
        if score:
            scored.append((score, rule))
    scored.sort(key=lambda item: (-item[0], item[1]["id"]))
    return [{"score": score, "rule": public_rule(rule)} for score, rule in scored[:max(1, min(limit, 50))]]


def get_rule(rule_id: str) -> dict[str, Any] | None:
    normalized = rule_id.upper().strip()
    for rule in load_rules():
        if rule["id"] == normalized:
            return public_rule(rule)
    return None


def search_cwe(query: str, limit: int = 10) -> list[dict[str, Any]]:
    normalized_query = query.strip().upper()
    terms = {term.lower() for term in re.findall(r"[a-zA-Z0-9_-]+", query) if len(term) > 1}
    scored: list[tuple[int, dict[str, Any]]] = []
    for entry in load_cwe_index():
        corpus = " ".join(str(entry.get(key) or "") for key in ("id", "type", "name", "status", "summary", "abstraction", "structure")).lower()
        score = sum(1 for term in terms if term in corpus)
        if entry["id"].upper() == normalized_query:
            score += 100
        if score:
            scored.append((score, entry))
    scored.sort(key=lambda item: (-item[0], item[1]["id"]))
    return [{"score": score, "entry": entry} for score, entry in scored[:max(1, min(limit, 50))]]


def get_cwe(cwe_id: str) -> dict[str, Any] | None:
    normalized = cwe_id.upper().strip()
    if not re.fullmatch(r"CWE-[0-9]+", normalized):
        raise ValueError("CWE ID must match CWE-<number>")
    catalog = load_cwe_catalog()
    for collection in ("weaknesses", "categories", "views"):
        for entry in catalog.get(collection, []):
            if entry["id"] == normalized:
                return entry
    return None


def cwe_status() -> dict[str, Any]:
    manifest = load_cwe_manifest()
    return {
        "version": manifest["cwe_version"],
        "catalog_date": manifest["catalog_date"],
        "counts": manifest["counts"],
        "source_url": manifest["source_url"],
        "terms_url": manifest["terms_url"],
        "archive_sha256": manifest["source_archive_sha256"],
    }


def iter_text_files(target: Path) -> Iterable[Path]:
    for path in target.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in TEXT_SUFFIXES and path.stat().st_size <= 1_000_000:
            yield path


def looks_like_placeholder(line: str) -> bool:
    lowered = line.lower()
    return any(marker in lowered for marker in ("example", "placeholder", "changeme", "your_", "dummy", "test_"))


def review_path(path_value: str, max_files: int = 5_000) -> dict[str, Any]:
    target = Path(path_value).expanduser().resolve()
    if not target.exists():
        raise ValueError("path does not exist")
    if not target.is_dir():
        raise ValueError("path must be a directory")
    rules = {rule["id"]: rule for rule in load_rules()}
    findings: list[dict[str, Any]] = []
    scanned = 0
    for file_path in iter_text_files(target):
        scanned += 1
        if scanned > max_files:
            break
        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line_number, line in enumerate(lines, start=1):
            for detector in DETECTORS:
                if not detector.pattern.search(line):
                    continue
                if detector.rule_id == "ASKB-SECRETS-001" and looks_like_placeholder(line):
                    continue
                rule = rules[detector.rule_id]
                try:
                    relative_path = str(file_path.relative_to(target))
                except ValueError:
                    relative_path = str(file_path)
                findings.append({
                    "id": f"ASKB-F-{len(findings) + 1:04d}",
                    "rule_id": detector.rule_id,
                    "title": detector.title,
                    "severity": detector.severity,
                    "confidence": detector.confidence,
                    "cwe_ids": rule["cwe_ids"],
                    "evidence": {"path": relative_path, "line": line_number, "snippet": line.strip()[:500]},
                    "impact": detector.impact,
                    "safe_verification": rule["safe_tests"],
                    "remediation": rule["remediation"],
                    "references": rule["references"],
                    "disposition": "needs-human-review",
                })
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda item: (severity_order[item["severity"]], item["evidence"]["path"], item["evidence"]["line"]))
    for index, finding in enumerate(findings, start=1):
        finding["id"] = f"ASKB-F-{index:04d}"
    return {
        "target": str(target),
        "files_scanned": min(scanned, max_files),
        "scan_limited": scanned > max_files,
        "finding_count": len(findings),
        "findings": findings,
        "limitations": [
            "Static heuristic output requires human review.",
            "The reviewer does not execute code, inspect dependencies remotely, or prove exploitability.",
            "Only files under 1 MB with supported text extensions are inspected.",
        ],
    }


def tool_definitions() -> list[dict[str, Any]]:
    return [
        {
            "name": "agentsec_search_rules",
            "description": "Search the local AgentSec KB for original secure-development guidance. This is read-only and does not inspect a project.",
            "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 50}}, "required": ["query"]},
        },
        {
            "name": "agentsec_get_rule",
            "description": "Retrieve one AgentSec KB rule by ID, including safe review, testing, remediation, and source references.",
            "inputSchema": {"type": "object", "properties": {"rule_id": {"type": "string", "pattern": "^ASKB-[A-Za-z]+-[0-9]{3}$"}}, "required": ["rule_id"]},
        },
        {
            "name": "agentsec_review_path",
            "description": "Perform a local, non-executing heuristic source review. Use only for directories the user is authorized to assess. Findings require human review.",
            "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "max_files": {"type": "integer", "minimum": 1, "maximum": 5000}}, "required": ["path"]},
        },
        {
            "name": "agentsec_validate_kb",
            "description": "Validate local AgentSec KB rule structure, CWE mapping coverage, and the pinned official CWE data pack.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "agentsec_search_cwe",
            "description": "Search the complete local official CWE data pack by CWE ID, weakness name, type, status, or summary. Returns compact result metadata; use agentsec_get_cwe for full canonical content.",
            "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 50}}, "required": ["query"]},
        },
        {
            "name": "agentsec_get_cwe",
            "description": "Retrieve the complete canonical content for one CWE weakness, category, or view from the pinned official CWE data pack.",
            "inputSchema": {"type": "object", "properties": {"cwe_id": {"type": "string", "pattern": "^CWE-[0-9]+$"}}, "required": ["cwe_id"]},
        },
        {
            "name": "agentsec_cwe_status",
            "description": "Return version, counts, source URL, terms URL, and integrity checksum for the local official CWE data pack.",
            "inputSchema": {"type": "object", "properties": {}},
        },
    ]


def handle_tool_call(name: str, arguments: dict[str, Any]) -> Any:
    if name == "agentsec_search_rules":
        return search_rules(str(arguments["query"]), int(arguments.get("limit", 10)))
    if name == "agentsec_get_rule":
        rule = get_rule(str(arguments["rule_id"]))
        if rule is None:
            raise ValueError("rule not found")
        return rule
    if name == "agentsec_review_path":
        return review_path(str(arguments["path"]), int(arguments.get("max_files", 5_000)))
    if name == "agentsec_validate_kb":
        return validate_rules()
    if name == "agentsec_search_cwe":
        return search_cwe(str(arguments["query"]), int(arguments.get("limit", 10)))
    if name == "agentsec_get_cwe":
        entry = get_cwe(str(arguments["cwe_id"]))
        if entry is None:
            raise ValueError("CWE entry not found")
        return entry
    if name == "agentsec_cwe_status":
        return cwe_status()
    raise ValueError(f"unknown tool: {name}")


def mcp_response(message_id: Any, result: Any = None, error: dict[str, Any] | None = None) -> None:
    if message_id is None:
        return
    response: dict[str, Any] = {"jsonrpc": "2.0", "id": message_id}
    if error is not None:
        response["error"] = error
    else:
        response["result"] = result
    sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def serve() -> int:
    """Run a minimal newline-delimited JSON-RPC MCP server on standard I/O."""
    for raw_line in sys.stdin:
        request: dict[str, Any] = {}
        try:
            request = json.loads(raw_line)
            method = request.get("method")
            message_id = request.get("id")
            params = request.get("params", {})
            if method == "initialize":
                requested = params.get("protocolVersion")
                version = requested if requested in {"2024-11-05", "2025-03-26"} else "2025-03-26"
                mcp_response(message_id, {
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "agentsec-kb", "version": "0.2.0"},
                })
            elif method == "tools/list":
                mcp_response(message_id, {"tools": tool_definitions()})
            elif method == "tools/call":
                try:
                    result = handle_tool_call(params["name"], params.get("arguments", {}))
                    mcp_response(message_id, {
                        "content": [{"type": "text", "text": json.dumps(result, indent=2, sort_keys=True)}],
                        "structuredContent": result,
                    })
                except (KeyError, TypeError, ValueError) as exc:
                    mcp_response(message_id, {"content": [{"type": "text", "text": str(exc)}], "isError": True})
            elif method == "ping":
                mcp_response(message_id, {})
            elif method and message_id is not None:
                mcp_response(message_id, error={"code": -32601, "message": f"method not found: {method}"})
        except json.JSONDecodeError as exc:
            mcp_response(None, error={"code": -32700, "message": f"parse error: {exc.msg}"})
        except Exception as exc:  # Defensive boundary for a local stdio server.
            mcp_response(request.get("id"), error={"code": -32603, "message": str(exc)})
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate", help="validate rule files and mapping coverage")
    query_parser = subparsers.add_parser("query", help="search local security guidance")
    query_parser.add_argument("query")
    query_parser.add_argument("--limit", type=int, default=10)
    cwe_search_parser = subparsers.add_parser("cwe-search", help="search the full official CWE data pack")
    cwe_search_parser.add_argument("query")
    cwe_search_parser.add_argument("--limit", type=int, default=10)
    cwe_get_parser = subparsers.add_parser("cwe-get", help="retrieve complete canonical CWE content")
    cwe_get_parser.add_argument("cwe_id")
    subparsers.add_parser("cwe-status", help="show data-pack version and integrity metadata")
    get_parser = subparsers.add_parser("get", help="retrieve a rule")
    get_parser.add_argument("rule_id")
    review_parser = subparsers.add_parser("review", help="review a local directory without executing code")
    review_parser.add_argument("path")
    review_parser.add_argument("--max-files", type=int, default=5_000)
    subparsers.add_parser("serve", help="start newline-delimited JSON-RPC MCP server on stdio")
    args = parser.parse_args()

    try:
        if args.command == "validate":
            result = validate_rules()
            sys.stdout.write(json_output(result))
            return 0 if result["valid"] else 1
        if args.command == "query":
            sys.stdout.write(json_output(search_rules(args.query, args.limit)))
            return 0
        if args.command == "cwe-search":
            sys.stdout.write(json_output(search_cwe(args.query, args.limit)))
            return 0
        if args.command == "cwe-get":
            result = get_cwe(args.cwe_id)
            if result is None:
                print(f"CWE entry not found: {args.cwe_id}", file=sys.stderr)
                return 1
            sys.stdout.write(json_output(result))
            return 0
        if args.command == "cwe-status":
            sys.stdout.write(json_output(cwe_status()))
            return 0
        if args.command == "get":
            result = get_rule(args.rule_id)
            if result is None:
                print(f"rule not found: {args.rule_id}", file=sys.stderr)
                return 1
            sys.stdout.write(json_output(result))
            return 0
        if args.command == "review":
            sys.stdout.write(json_output(review_path(args.path, args.max_files)))
            return 0
        return serve()
    except (OSError, ValueError, TypeError) as exc:
        print(f"agentsec: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
