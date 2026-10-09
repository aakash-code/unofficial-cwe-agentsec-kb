# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Unofficial CWE AgentSec KB: a vendor-neutral security knowledge base for AI coding agents. It ships JSON secure-development rules, a pinned copy of the official CWE 4.20 catalog, and one dependency-free Python tool that serves as validator, query CLI, heuristic static reviewer, and MCP stdio server. The repo itself is also a Claude Code / Codex / Gemini CLI plugin.

It is an independent project, not affiliated with MITRE or the CWE Program. Keep that disclaimer intact in user-facing text, and never present the project as official CWE content.

## Commands

Python 3.10+, standard library only. Do not add third-party dependencies (runtime or build).

```sh
python3 tools/agentsec.py validate                 # rules, mappings, CWE data counts, archive SHA-256
python3 -m unittest discover -s tests -v           # full test suite
python3 -m unittest tests.test_agentsec.AgentSecTests.test_search_returns_command_rule  # one test
python3 tools/agentsec.py query "<text>"           # search rules
python3 tools/agentsec.py cwe-search "<text>"
python3 tools/agentsec.py cwe-get CWE-918 [--section Mapping_Notes] [--raw]
python3 tools/agentsec.py cwe-status
python3 tools/agentsec.py review tests/fixtures/vulnerable_app
python3 tools/agentsec.py serve                    # MCP server (newline-delimited JSON-RPC on stdio)
python3 tools/import_cwe.py --archive <cwec_vX.Y.xml.zip>   # regenerate data/cwe/<version>
```

The release checklist (`docs/releasing.md`) requires both `validate` and the unittest suite to pass.

## Architecture

- **`tools/agentsec.py`**: the entire runtime. The CLI subcommands and MCP tools (`tool_definitions` / `handle_tool_call`) wrap the same functions (`search_rules`, `get_rule`, `search_cwe`, `get_cwe`, `cwe_status`, `review_path`, `validate_rules`). If you add a capability, expose it in both places. The server implements `initialize`, `tools/list`, `tools/call`, and `ping`.
- **MCP output size**: Claude Code rejects tool results above ~25k tokens. That is why `agentsec_get_cwe` returns `readable_cwe()` text sections, not the raw tree, and why results are sent as compact text without a `structuredContent` copy. A test asserts the largest entry stays under 45k chars.
- **Rules**: `knowledge/rules/ASKB-<CATEGORY>-<NNN>.json`, which conform to `schemas/rule.schema.json`. `validate_rules()` enforces required fields, ID format, and the status/risk/provenance enums. It also checks that every cited CWE exists and is not Discouraged or Prohibited by MITRE, and that `mappings/cwe.json` lists exactly the rule's `cwe_ids` (one entry per rule/CWE pair). Check a candidate CWE's `mapping_usage` with `cwe-search` before using it.
- **Reviewer**: `DETECTORS` in `agentsec.py` are per-line regexes, each tied to a rule ID. All findings get `disposition: needs-human-review`. The reviewer never executes code, never follows symlinks, and never does network I/O. Keep it that way. A detector may set `cwe_ids` when the pattern pins one weakness narrower than its rule. `tests/fixtures/vulnerable_app/` must trigger exactly the (file, line, rule) set the test asserts, and `tests/fixtures/safe_app/` must produce zero findings. Add both a positive and a safe-equivalent line for any new detector.
- **CWE data**: `vendor/cwe/4.20/cwec_v4.20.xml.zip` is the verbatim official archive. Do not edit it. `tools/import_cwe.py` generates `data/cwe/4.20/{catalog,index,relationships,manifest}.json` from it. Do not hand-edit generated files. `validate` checks catalog/index counts against the manifest and the archive SHA-256. The CWE version path `4.20` is hard-coded in `agentsec.py` (`CWE_DATA_DIR`, the archive path).
- **Packaging**: `build_backend.py` is a custom stdlib-only PEP 517 backend (referenced from `pyproject.toml`). The wheel nests the runtime directories (`tools`, `knowledge`, `mappings`, `schemas`, `policies`, `data`, `vendor`, plus license files) under `agentsec_kb/`. Skills, adapters, and plugin manifests are not in the wheel, so `agentsec_kb/tools/agentsec.py` still finds `../data` and `../knowledge`, and it installs the `agentsec` console script (`agentsec_kb.tools.agentsec:main`). `test_wheel_installs_everything_under_one_package` guards this.
- **Agent adapters / plugin manifests**: these are thin layers over the core.
  - `skills/` contains the `secure-development-review` skill (a lean `SKILL.md` plus `references/` loaded on demand) and the `setup` skill. Skills call the CLI fallback through `${CLAUDE_PLUGIN_ROOT}`.
  - `adapters/` holds per-agent instruction templates. `adapters/claude/CLAUDE.md` is a template for *target* projects, not guidance for this repo.
  - Plugin manifests: `plugin.json`, `.claude-plugin/`, `.codex-plugin/`, `.agents/plugins/marketplace.json`, `gemini-extension.json`.
  - MCP configs: `.mcp.json`, `mcp.json`.

## Conventions

- **Version bumps**: the version string lives in `pyproject.toml`, `plugin.json`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json` (two places), `.codex-plugin/plugin.json`, `gemini-extension.json`, `CITATION.cff`, `VERSION` in `tools/agentsec.py` (MCP `serverInfo`), `VERSION` in `build_backend.py`, and the `--ref vX.Y.Z` in README. Update all of them together with `CHANGELOG.md`. `test_version_is_consistent_everywhere` fails if they drift. Use semver per `GOVERNANCE.md`.
- **Test assertions**: tests hard-code the rule count (`20`) and CWE weakness count (`969`). Update them when you add rules or import a new CWE release.
- **Rule content**: rules must be original defensive guidance. Do not copy third-party text. Record any adapted material's provenance and license in `SOURCES.md`. Include safe validation steps, not exploit payloads.
- **Commits**: commits need a DCO `Signed-off-by:` line (see `CONTRIBUTING.md`).
- **Safety scope**: do not add network access, active testing, or code execution to the tool. See `policies/authorized-testing.md` and `THREAT_MODEL.md`.
