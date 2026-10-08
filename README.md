# AgentSec KB

**AgentSec KB** is a vendor-neutral, open-source security knowledge base for AI coding agents. It helps agents perform secure-development reviews, plan authorized security tests, normalize findings, and explain remediation using an auditable, portable rule set.

It is designed to work with Codex, Claude Code, and other coding agents without locking users into a model or platform. It includes the complete official **CWE 4.20** XML catalog as a pinned, queryable data pack.

## What it provides

- Original, versioned secure-development rules in JSON.
- Complete official CWE 4.20 content: weaknesses, categories, views, external
  references, relationships, mitigations, detection methods, examples, and
  other XML fields represented losslessly in a local catalog.
- A stable JSON Schema for rules and findings.
- CWE reference mappings, without redistributing CWE descriptions.
- A dependency-free local command-line reviewer and MCP-compatible stdio server.
- Codex, Claude, and generic-agent adapter templates.
- Fixture-based tests and governance, disclosure, provenance, and safe-testing policies.

## What it is not

AgentSec KB is not a vulnerability scanner, an exploit framework, a guarantee of security, or authorization to test systems. It does not make network requests, execute reviewed code, access credentials, or actively probe targets. Use it only for code and systems you are authorized to assess.

## Quick start

Requirements: Python 3.10+; no third-party Python packages.

```sh
python3 tools/agentsec.py validate
python3 tools/agentsec.py query "untrusted command execution"
python3 tools/agentsec.py cwe-status
python3 tools/agentsec.py cwe-search "server-side request forgery"
python3 tools/agentsec.py cwe-get CWE-918
python3 tools/agentsec.py review tests/fixtures/vulnerable_app
python3 tools/agentsec.py serve
python3 -m unittest discover -s tests -v
```

Optional offline-friendly installation creates an `agentsec` command:

```sh
python3 -m pip install .
agentsec validate
```

The included build backend uses only the Python standard library; installing or
running the core does not download runtime dependencies.

The `review` command is a deliberately small, transparent baseline that detects a handful of high-signal patterns. Treat its output as leads for human review, not proof of a vulnerability.

## Agent integrations

- **Codex:** see [adapters/codex/README.md](adapters/codex/README.md).
- **Claude Code:** see [adapters/claude/README.md](adapters/claude/README.md).
- **Other agents:** see [adapters/generic/README.md](adapters/generic/README.md).

All integrations can use the same local MCP server:

```sh
python3 /absolute/path/to/agentsec-kb/tools/agentsec.py serve
```

## Project layout

```text
knowledge/rules/       Canonical original security guidance
mappings/              External-standard identifiers and reference URLs
vendor/cwe/4.20/       Pinned official CWE XML archive and required notice
data/cwe/4.20/         Generated full CWE catalog, index, graph, and manifest
schemas/               JSON Schemas for data exchanged by agents
policies/              Authorized-testing and agent safety boundaries
tools/                 Dependency-free validator, reviewer, and MCP server
adapters/              Thin vendor-specific instruction/configuration layers
tests/                 Fixtures and automated tests
docs/                  Architecture and release guidance
```

## Licensing and sources

Unless a file says otherwise, original work in this repository is licensed under the [MIT License](LICENSE). The complete official CWE 4.20 XML archive and its derived data pack are governed by the [CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html), including MITRE attribution requirements. See [NOTICE](NOTICE), [CREDITS.md](CREDITS.md), [SOURCES.md](SOURCES.md), and [CWE source coverage](docs/cwe-source-coverage.md).

## Contributing and security reports

Read [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md), and [SECURITY.md](SECURITY.md). Contributors must submit original work or clearly identify the license and provenance of any imported material.
