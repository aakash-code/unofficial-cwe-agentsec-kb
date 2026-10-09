#!/usr/bin/env python3
"""Local AgentSec KB validator, query tool, static reviewer, and MCP stdio server.

The reviewer is intentionally small and transparent. It reads local files as data,
does not execute them, does not follow symlinks, and never performs network I/O.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable


VERSION = "0.3.0"
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
    cwe_ids: tuple[str, ...] = ()  # narrower than the rule's CWEs when the pattern pins one weakness


# Uppercase SQL is matched as-is; lowercase also needs a WHERE so prose ("select an option from the list") doesn't match.
SQL = (
    r"(?:SELECT\b[^\n]*\bFROM\b|INSERT\s+INTO\b|UPDATE\b[^\n]*\bSET\b|DELETE\s+FROM\b"
    r"|select\b[^\n]*\bfrom\b[^\n]*\bwhere\b|insert\s+into\b|update\b[^\n]*\bset\b[^\n]*\bwhere\b|delete\s+from\b)"
)
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
        re.compile(
            rf"{SQL}[^\n]*(?:[\"']\s*\+|\.format\s*\(|[\"']\s*%\s*[\(\w])"  # concatenation, .format, % formatting
            rf"|\bf[\"'][^\n]*{SQL}[^\n]*\{{"  # Python f-string
            rf"|`[^`\n]*{SQL}[^`\n]*\$\{{",  # JS template literal
        ),
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
        re.compile(r"(?:pickle\.loads?\s*\(|cPickle\.loads?\s*\(|marshal\.loads?\s*\(|jsonpickle\.decode\s*\(|yaml\.unsafe_load\s*\(|yaml\.load\s*\((?![^\n]*SafeLoader)|\bunserialize\s*\()"),
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
        ("CWE-732",),
    ),
    Detector(
        "ASKB-AUTH-003",
        re.compile(r"(?:verify_signature[\"']?\s*:\s*False|algorithms?\s*[=:]\s*\[?[^\]\n]*[\"']none[\"'])", re.IGNORECASE),
        "Token signature verification disabled or 'none' algorithm accepted",
        "critical",
        "high",
        "Unverified tokens let any caller forge identity claims and impersonate other users.",
    ),
    Detector(
        "ASKB-CSRF-001",
        re.compile(r"(?:@csrf_exempt\b|WTF_CSRF_ENABLED\s*=\s*False|csrf\s*[:=]\s*false\b|\.disable\(\s*\)\s*;?\s*//\s*csrf|csrf\(\)\.disable\(\))", re.IGNORECASE),
        "CSRF protection disabled",
        "high",
        "medium",
        "Without CSRF protection, another site can submit state-changing requests using a logged-in user's cookies.",
        ("CWE-352",),
    ),
    Detector(
        "ASKB-SESSION-001",
        re.compile(r"(?:SESSION_COOKIE_(?:SECURE|HTTPONLY)\s*=\s*False|httpOnly\s*:\s*false|secure\s*:\s*false\s*[,}]|samesite\s*[=:]\s*[\"']?none\b)", re.IGNORECASE),
        "Session cookie missing a protective attribute",
        "medium",
        "medium",
        "Cookies without HttpOnly, Secure, or a restrictive SameSite value are easier to steal or misuse cross-site.",
    ),
    Detector(
        "ASKB-REDIRECT-001",
        re.compile(r"(?:\bredirect\s*\(\s*request\.(?:args|GET|POST|form|values|query_params)\b|\.redirect\s*\(\s*(?:\d+\s*,\s*)?req\.(?:query|body|params)\b)"),
        "Redirect target taken directly from the request",
        "medium",
        "medium",
        "Redirecting to a user-supplied destination lets attackers use the site to send users to malicious pages.",
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
    rule_cwes: dict[str, set[str]] = {}
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
        else:
            rule_cwes[rule_id] = set(rule["cwe_ids"])
            errors.extend({"path": relative_path, "error": problem} for problem in cwe_mapping_problems(rule["cwe_ids"]))
        provenance = rule.get("provenance")
        if not isinstance(provenance, dict) or provenance.get("origin") not in {"original", "adapted", "imported"}:
            errors.append({"path": relative_path, "error": "invalid provenance.origin"})

    mapping_path = ROOT / "mappings" / "cwe.json"
    try:
        mappings = json.loads(mapping_path.read_text(encoding="utf-8"))["mappings"]
        mapped: dict[str, set[str]] = {}
        for entry in mappings:
            pairs = mapped.setdefault(entry["rule_id"], set())
            if entry["cwe_id"] in pairs:
                errors.append({"path": "mappings/cwe.json", "error": f"duplicate mapping {entry['rule_id']} -> {entry['cwe_id']}"})
            pairs.add(entry["cwe_id"])
        for rule_id in sorted(seen_ids):
            if rule_id not in mapped:
                errors.append({"path": "mappings/cwe.json", "error": f"missing mapping for {rule_id}"})
            elif rule_id in rule_cwes and mapped[rule_id] != rule_cwes[rule_id]:
                errors.append({"path": "mappings/cwe.json", "error": f"{rule_id} maps {sorted(mapped[rule_id])} but the rule cites {sorted(rule_cwes[rule_id])}"})
        for rule_id in sorted(set(mapped) - seen_ids):
            errors.append({"path": "mappings/cwe.json", "error": f"mapping for unknown rule {rule_id}"})
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        errors.append({"path": "mappings/cwe.json", "error": f"invalid mapping file: {exc}"})
    cwe_data = validate_cwe_data()
    if not cwe_data["valid"]:
        errors.extend({"path": entry["path"], "error": entry["error"]} for entry in cwe_data["errors"])
    return {"valid": not errors, "rule_count": len(paths), "cwe_data": cwe_data, "errors": errors}


def cwe_mapping_problems(cwe_ids: Iterable[str]) -> list[str]:
    """Rules must cite real weaknesses that MITRE permits for root-cause mapping."""
    try:
        usage = cwe_mapping_usage()
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        return []  # validate_cwe_data reports the broken data pack
    problems = []
    for cwe_id in cwe_ids:
        if cwe_id not in usage:
            problems.append(f"{cwe_id} is not in the CWE {CWE_DATA_DIR.name} catalog")
        elif usage[cwe_id] in {"Discouraged", "Prohibited"}:
            problems.append(f"{cwe_id} has mapping usage {usage[cwe_id]}; cite a more specific allowed weakness")
    return problems


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


# Everyday terms MITRE's alternate terms don't cover, mapped to the allowed entry a reviewer usually means.
SEARCH_ALIASES = {
    "jwt": ("CWE-347",),
    "token signature": ("CWE-347",),
    "cors": ("CWE-942",),
    "timing attack": ("CWE-208",),
    "log injection": ("CWE-117",),
    "log forging": ("CWE-117",),
    "insecure randomness": ("CWE-338",),
    "weak random": ("CWE-338",),
    "zip slip": ("CWE-22",),
}


def fold(text: str) -> str:
    """Lowercase and treat hyphens, underscores, and spaces alike: zip-slip == zip slip, cross-site == cross site."""
    return re.sub(r"[\s_-]+", " ", text.lower()).strip()


def contains_phrase(haystack: str, phrase: str) -> bool:
    return re.search(rf"(?<![a-z0-9]){re.escape(phrase)}(?![a-z0-9])", haystack) is not None


def search_cwe(query: str, limit: int = 10) -> list[dict[str, Any]]:
    usage = cwe_mapping_usage()
    # An ID in any spelling (CWE-89, cwe 89, CWE_89) is an exact lookup: that entry or nothing.
    id_match = re.fullmatch(r"cwe[\s_-]*([0-9]+)", query.strip(), re.IGNORECASE)
    if id_match:
        cwe_id = f"CWE-{int(id_match.group(1))}"
        return [{"score": 100, "entry": {**entry, "mapping_usage": usage.get(cwe_id)}} for entry in load_cwe_index() if entry["id"] == cwe_id]
    phrase = fold(query)
    # "cwe" appears in every entry's ID, so it carries no signal as a search word.
    terms = {term for term in re.findall(r"[a-z0-9]+", phrase) if len(term) > 1 and term != "cwe"}
    alternate_terms = cwe_alternate_terms()
    aliased = {cwe_id for alias, ids in SEARCH_ALIASES.items() if contains_phrase(phrase, fold(alias)) for cwe_id in ids}
    scored: list[tuple[int, dict[str, Any]]] = []
    for entry in load_cwe_index():
        # MITRE's alternate terms carry the shorthand people search with: XSS, IDOR, XXE, prompt injection.
        title = fold(" | ".join([str(entry.get("name") or ""), *alternate_terms.get(entry["id"], [])]))
        corpus = fold(" ".join([title, *(str(entry.get(key) or "") for key in ("id", "type", "status", "summary", "abstraction", "structure"))]))
        # Title hits count double so the canonical entry outranks entries that only mention the term.
        score = sum((2 if term in title else 1) for term in terms if term in corpus)
        if len(phrase) > 2 and contains_phrase(title, phrase):
            score += 5
        # MITRE puts an entry's common name in quotes, e.g. "...Synchronization ('Race Condition')".
        nickname = re.search(r"\('([^']+)'\)", str(entry.get("name") or ""))
        if nickname and fold(nickname.group(1)) == phrase:
            score += 5
        if entry["id"] in aliased:
            score += 10
        if score <= 0:
            continue
        if entry.get("status") in {"Deprecated", "Obsolete"}:
            score = max(score - 5, 1)  # still listed when it matches, but ranked below current entries
        scored.append((score, entry))
    # Ties favor Base weaknesses, the abstraction MITRE prefers for root-cause mapping.
    abstraction_rank = {"Base": 0, "Variant": 1, "Class": 2, "Compound": 3, "Pillar": 4}
    scored.sort(key=lambda item: (-item[0], abstraction_rank.get(item[1].get("abstraction"), 5), item[1]["id"]))
    return [
        {"score": score, "entry": {**entry, "mapping_usage": usage.get(entry["id"])}}
        for score, entry in scored[:max(1, min(limit, 50))]
    ]


def find_child(node: dict[str, Any], tag: str) -> dict[str, Any] | None:
    return next((child for child in node.get("children") or [] if child.get("tag") == tag), None)


@lru_cache(maxsize=1)
def cwe_mapping_usage() -> dict[str, str | None]:
    """Map each CWE ID to MITRE's vulnerability-mapping usage (Allowed, Discouraged, Prohibited, ...)."""
    usage: dict[str, str | None] = {}
    catalog = load_cwe_catalog()
    for collection in ("weaknesses", "categories", "views"):
        for entry in catalog.get(collection, []):
            notes = find_child(entry["content"], "Mapping_Notes")
            value = find_child(notes, "Usage") if notes else None
            usage[entry["id"]] = value.get("text") if value else None
    return usage


@lru_cache(maxsize=1)
def cwe_alternate_terms() -> dict[str, list[str]]:
    terms: dict[str, list[str]] = {}
    for entry in load_cwe_catalog().get("weaknesses", []):
        block = find_child(entry["content"], "Alternate_Terms")
        for alternate in (block or {}).get("children") or []:
            term = find_child(alternate, "Term")
            if term and term.get("text"):
                terms.setdefault(entry["id"], []).append(term["text"])
    return terms


def render_node(node: dict[str, Any], lines: list[str]) -> None:
    attributes = " ".join(f"{key}={value}" for key, value in (node.get("attributes") or {}).items())
    text = (node.get("text") or "").strip()
    line = " ".join(part for part in (attributes, text) if part)
    if line:
        lines.append(line)
    for child in node.get("children") or []:
        render_node(child, lines)


def readable_cwe(entry: dict[str, Any], sections: list[str] | None = None) -> dict[str, Any]:
    """Render an entry's XML tree as plain-text sections so one entry fits an agent tool result."""
    wanted = {section.lower() for section in sections or []}
    rendered: dict[str, str] = {}
    for child in entry["content"].get("children") or []:
        tag = child["tag"]
        if wanted and "all" not in wanted and tag.lower() not in wanted:
            continue
        if not wanted and tag in DEFAULT_OMITTED_SECTIONS:
            continue
        lines: list[str] = []
        render_node({**child, "tag": tag}, lines)
        rendered[tag] = "\n".join(lines)
    available = [child["tag"] for child in entry["content"].get("children") or []]
    return {
        **{key: entry.get(key) for key in ("id", "type", "name", "status", "abstraction", "structure", "summary")},
        "mapping_usage": cwe_mapping_usage().get(entry["id"]),
        "url": f"https://cwe.mitre.org/data/definitions/{entry['id'].split('-')[1]}.html",
        "sections": rendered,
        "available_sections": available,
    }


DEFAULT_OMITTED_SECTIONS = {"Content_History"}


def get_cwe(cwe_id: str) -> dict[str, Any] | None:
    """Return the raw lossless catalog entry (XML tree as JSON)."""
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
    # os.walk lets us prune skipped directories instead of descending into node_modules and friends.
    for directory, subdirectories, files in os.walk(target, followlinks=False):
        subdirectories[:] = sorted(name for name in subdirectories if name not in SKIP_DIRS)
        for name in sorted(files):
            path = Path(directory, name)
            if path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            try:
                if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_000_000:
                    continue
            except OSError:
                continue
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
                    "cwe_ids": list(detector.cwe_ids or rule["cwe_ids"]),
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
            "description": "Retrieve one CWE weakness, category, or view from the pinned official CWE data pack as readable text sections, with MITRE's mapping_usage (Allowed, Allowed-with-Review, Discouraged, Prohibited). Content_History is omitted unless requested. Pass sections (e.g. [\"Potential_Mitigations\", \"Mapping_Notes\"] or [\"all\"]) to narrow or widen the result.",
            "inputSchema": {"type": "object", "properties": {"cwe_id": {"type": "string", "pattern": "^CWE-[0-9]+$"}, "sections": {"type": "array", "items": {"type": "string"}}}, "required": ["cwe_id"]},
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
        sections = arguments.get("sections")
        return readable_cwe(entry, [str(section) for section in sections] if isinstance(sections, list) else None)
    if name == "agentsec_cwe_status":
        return cwe_status()
    raise ValueError(f"unknown tool: {name}")


def mcp_response(message_id: Any, result: Any = None, error: dict[str, Any] | None = None, reply_without_id: bool = False) -> None:
    # Notifications (no id) never get a reply; parse and invalid-request errors reply with id null.
    if message_id is None and not reply_without_id:
        return
    response: dict[str, Any] = {"jsonrpc": "2.0", "id": message_id}
    if error is not None:
        response["error"] = error
    else:
        response["result"] = result
    sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
    sys.stdout.flush()


SUPPORTED_PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")


def serve() -> int:
    """Run a minimal newline-delimited JSON-RPC MCP server on standard I/O."""
    # MCP stdio is UTF-8; Windows consoles otherwise default to a legacy code page.
    for stream in (sys.stdin, sys.stdout):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    for raw_line in sys.stdin:
        request: dict[str, Any] = {}
        try:
            if not raw_line.strip():
                continue
            parsed = json.loads(raw_line)
            if not isinstance(parsed, dict):
                mcp_response(None, error={"code": -32600, "message": "invalid request"}, reply_without_id=True)
                continue
            request = parsed
            method = request.get("method")
            message_id = request.get("id")
            params = request["params"] if "params" in request else {}
            if not isinstance(params, dict):
                mcp_response(message_id, error={"code": -32602, "message": "params must be an object"})
                continue
            if method == "initialize":
                requested = params.get("protocolVersion")
                version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else SUPPORTED_PROTOCOL_VERSIONS[-1]
                mcp_response(message_id, {
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "agentsec-kb", "version": VERSION},
                })
            elif method == "tools/list":
                mcp_response(message_id, {"tools": tool_definitions()})
            elif method == "tools/call":
                try:
                    result = handle_tool_call(params["name"], params.get("arguments", {}))
                    # Compact text only: duplicating it as structuredContent doubles the size hosts count
                    # against their tool-output limit, and the largest CWE entries already run ~35k chars.
                    mcp_response(message_id, {
                        "content": [{"type": "text", "text": json.dumps(result, separators=(",", ":"))}],
                    })
                except (KeyError, TypeError, ValueError) as exc:
                    mcp_response(message_id, {"content": [{"type": "text", "text": str(exc)}], "isError": True})
            elif method == "ping":
                mcp_response(message_id, {})
            elif method and message_id is not None:
                mcp_response(message_id, error={"code": -32601, "message": f"method not found: {method}"})
        except json.JSONDecodeError as exc:
            mcp_response(None, error={"code": -32700, "message": f"parse error: {exc.msg}"}, reply_without_id=True)
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
    cwe_get_parser.add_argument("--section", action="append", dest="sections", help="section tag to include (repeatable; 'all' for every section)")
    cwe_get_parser.add_argument("--raw", action="store_true", help="print the lossless XML-derived tree instead of readable sections")
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
            sys.stdout.write(json_output(result if args.raw else readable_cwe(result, args.sections)))
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
