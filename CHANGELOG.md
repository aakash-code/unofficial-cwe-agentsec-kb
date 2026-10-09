# Changelog

All notable changes are recorded here using the Keep a Changelog style.

## [0.3.0] - 2026-10-09

### Fixed

- `agentsec_get_cwe` returned the raw XML tree (up to ~140 KB), which exceeded
  Claude Code's MCP output limit, so full CWE lookups failed. It now returns
  readable text sections (largest entry ~34 KB), omits `Content_History` by
  default, and accepts a `sections` filter. `cwe-get --raw` keeps the lossless tree.
- MCP tool results no longer duplicate the payload as `structuredContent`.
  List results were also invalid there.
- The server accepts the MCP protocol versions 2025-06-18 and 2025-11-25.
- Search no longer returns unrelated deprecated entries for queries with no
  match. `validate` reports duplicate mapping rows. The MCP server rejects
  falsy non-object `params`.
- Search treats hyphens, underscores, and spaces alike (`zip-slip`, `prompt-injection`).

### Added

- `mapping_usage` (MITRE's Allowed / Allowed-with-Review / Discouraged /
  Prohibited) on CWE search results and entries.
- CWE search ranks name matches higher and breaks ties toward Base weaknesses.
- `secure-development-review` skill rewritten to Anthropic's skill format, with
  review, build-securely, fix, and test-planning modes. Added the references
  `cwe-mapping.md`, `audit-checklist.md` (including AI/agent surfaces),
  `report-format.md`, and `security-testing.md`, plus a CLI fallback.
- The skill now requires a knowledge-base lookup for every CWE it cites and
  labels any it couldn't check `(unverified)`. Round 1 of the skill evaluation
  showed it citing well-known IDs from memory.
- `setup` skill now troubleshoots Python, data-pack, and MCP connection failures.
- Eight original rules: `ASKB-SSRF-001` (CWE-918), `ASKB-AUTH-002` object-level
  authorization (CWE-639), `ASKB-AUTH-003` token verification (CWE-347),
  `ASKB-CSRF-001`, `ASKB-SESSION-001`, `ASKB-REDIRECT-001`, `ASKB-LLM-001`
  prompt injection (CWE-1427), and `ASKB-LLM-002` agent tool privilege.
- Scanner detectors for disabled token verification, disabled CSRF protection,
  weak session-cookie flags, and request-controlled redirects. Unsafe
  deserialization now also covers `marshal`, `jsonpickle`, and `yaml.unsafe_load`.
- CWE search matches MITRE alternate terms, so IDOR, XSS, XXE, and
  "prompt injection" find the right entry. It ranks an entry's quoted common
  name (`'Race Condition'`) first and ranks deprecated entries last.
- `validate` rejects rules that cite non-existent, Discouraged, or Prohibited
  CWEs, and mappings that differ from a rule's `cwe_ids`.
- GitHub Actions CI on Linux, macOS, and Windows with Python 3.10 and 3.13.
- A safe-equivalents fixture asserts the scanner reports zero false positives.

- Curated search aliases for everyday terms MITRE has no alternate term for:
  JWT (CWE-347), CORS (CWE-942), timing attack, log injection, insecure
  randomness, and zip slip.

### Changed (rules)

- Code review on PR #1 tightened the guidance:
  - `ASKB-LLM-001` says message roles are not a security boundary and asks for the
    root cause to be confirmed before mapping to CWE-1427.
  - `ASKB-SESSION-001` treats SameSite=None as an exception that needs a
    documented cross-site flow.
  - `ASKB-SSRF-001` allowlists ports.
  - The skill references split eval/exec (CWE-95) from OS commands (CWE-78),
    test XSS per output context, and test CSRF against exact origins.
  - The skill references ask before running scanners that contact external
    services.

- `ASKB-INPUT-001` now maps to CWE-1287, CWE-1284, and CWE-1286 instead of
  CWE-20, and `ASKB-IAC-001` maps to CWE-732, CWE-250, and CWE-276 instead of
  CWE-284. MITRE discourages CWE-20 and CWE-284 for root-cause mapping.
- The scanner's SQL check now catches f-strings, JS template literals, and `%`
  formatting. It requires SQL structure, so prose containing "select" no
  longer matches.
- The reviewer prunes skipped directories such as `node_modules` instead of
  walking them.
- `pip install` now places everything under a single `agentsec_kb` package
  (plus its dist-info). It no longer puts top-level `tools/`, `data/`,
  `knowledge/`, and license files into site-packages, where they could clash
  with other packages. The `agentsec` command and repository layout are unchanged.
- The MCP server answers malformed or non-object messages with JSON-RPC errors
  instead of crashing, and uses UTF-8 stdio on every platform.

## [0.2.1] - 2026-10-09

### Changed

- Renamed the public project to **Unofficial CWE AgentSec KB** and added a
  prominent non-affiliation notice.
- Added portable and Codex plugin metadata, a Codex marketplace catalog, and
  documented skill and MCP installation.
- Added a native Claude Code plugin and Claude marketplace catalog, with a
  plugin-rooted, local read-only MCP server configuration.

## [0.2.0] - 2026-10-09

### Added

- Complete official CWE 4.20 data pack: 969 weaknesses, 422 categories, 59
  views, and 1,026 external references.
- The pinned official XML archive, SHA-256 integrity manifest, a lossless
  agent-friendly catalog, compact search index, and relationship graph.
- Offline CWE importer, full-CWE CLI commands, and three MCP tools for CWE
  search, full-entry retrieval, and version/integrity status.
- CWE source coverage documentation and explicit MITRE attribution notice.

## [0.1.0] - 2026-10-09

### Added

- Vendor-neutral, original secure-development knowledge base with 12 initial rules.
- CWE reference mappings, source provenance register, and attribution notices.
- Rule and finding JSON Schemas.
- Dependency-free local validator, query CLI, heuristic source reviewer, and MCP stdio server.
- Codex plugin, Claude project-instruction, and generic-agent adapters.
- Authorized-testing policy, threat model, governance, security disclosure, and contributor documentation.
- Fixture and MCP smoke tests.
