# Unofficial CWE AgentSec KB

> **Independent project — not official CWE content distribution.** This is an
> independent open-source project. It is not affiliated with, endorsed by, or
> maintained by The MITRE Corporation, the CWE Program, DHS, or CISA. CWE™ is a
> trademark of The MITRE Corporation.

Unofficial CWE AgentSec KB is a vendor-neutral security knowledge base for AI
coding agents. It helps agents perform secure-development reviews, plan
authorized security tests, normalize findings, and explain remediation using an
auditable, portable rule set.

It works with Codex, Claude Code, and other coding agents without locking users
into a model or platform. It includes a pinned, queryable copy of the complete
official **CWE 4.20** XML catalog, preserved under the applicable MITRE terms.

## What it provides

- Original, versioned secure-development rules in JSON.
- Complete official CWE 4.20 content: weaknesses, categories, views, external
  references, relationships, mitigations, detection methods, examples, and
  other XML fields represented losslessly in a local catalog.
- A stable JSON Schema for rules and findings.
- Version, source, and SHA-256 integrity metadata for the bundled CWE release.
- A dependency-free local command-line reviewer and MCP-compatible stdio server.
- Codex, Claude, and generic-agent adapter templates.
- Fixture-based tests and governance, disclosure, provenance, and safe-testing policies.

## What it is not

AgentSec KB is not a vulnerability scanner, an exploit framework, a guarantee of security, or authorization to test systems. It does not make network requests, execute reviewed code, access credentials, or actively probe targets. Use it only for code and systems you are authorized to assess.

## Install and use the command-line tool

Requirements: Python 3.10+; no third-party Python packages.

Clone the repository:

```sh
git clone https://github.com/aakash-code/unofficial-cwe-agentsec-kb.git
cd unofficial-cwe-agentsec-kb
```

Run directly from the clone:

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

Or install the local package to create an `agentsec` command:

```sh
python3 -m pip install .
agentsec validate
```

The included build backend uses only the Python standard library; installing or
running the core does not download runtime dependencies.

The `review` command is a deliberately small, transparent baseline that detects a handful of high-signal patterns. Treat its output as leads for human review, not proof of a vulnerability.

## MCP server: any compatible coding agent

The local MCP server is read-only, needs no credentials, does not contact the
network, and never executes reviewed code. It exposes security-rule search,
full CWE catalog retrieval, integrity status, and a small local heuristic review
tool. Only connect it to directories you are authorized to assess.

Start it manually:

```sh
python3 /absolute/path/to/unofficial-cwe-agentsec-kb/tools/agentsec.py serve
```

For a host that accepts stdio MCP configuration, add this configuration and
replace `/absolute/path/to/...` with your clone location:

```json
{
  "mcpServers": {
    "unofficial_cwe_agentsec_kb": {
      "type": "stdio",
      "command": "python3",
      "args": [
        "/absolute/path/to/unofficial-cwe-agentsec-kb/tools/agentsec.py",
        "serve"
      ]
    }
  }
}
```

Available tools:

- `agentsec_search_rules` and `agentsec_get_rule`
- `agentsec_search_cwe`, `agentsec_get_cwe`, and `agentsec_cwe_status`
- `agentsec_review_path` — authorized local review only
- `agentsec_validate_kb`

## Codex: install the skill and MCP plugin

This repository is a portable agent plugin and also includes Codex compatibility
files. The root `skills/` directory contains the skill; `mcp.json` and
`.mcp.json` configure the bundled local stdio server.

### Recommended: install from the Codex plugin marketplace

In Codex CLI, register this repository's marketplace:

```sh
codex plugin marketplace add aakash-code/unofficial-cwe-agentsec-kb --sparse .agents/plugins
```

Restart the Codex or ChatGPT desktop app, open **Plugins Directory**, select the
**Unofficial CWE AgentSec KB** marketplace, then install
**Unofficial CWE AgentSec KB**. For a repository where it should be enabled,
add this to `.codex/config.toml`:

```toml
[plugins."unofficial-cwe-agentsec-kb@unofficial-cwe-agentsec"]
enabled = true
```

The plugin starts the local server with `python3 tools/agentsec.py serve`. Test
it in a new conversation with: “Use secure-development-review to review this
authorized local project.”

### Manual: install only the skill

Copy the portable skill to the project that should use it:

```sh
mkdir -p /path/to/your-project/.codex/skills
cp -R skills/secure-development-review /path/to/your-project/.codex/skills/
```

Then add the MCP configuration shown above using the location where your Codex
client stores MCP connections. The skill gives the agent the review workflow;
the MCP server supplies the searchable local knowledge base. See [Codex
integration notes](adapters/codex/README.md).

## Claude Code (Anthropic): install the plugin, skill, and MCP server

This repository includes a native Claude Code plugin manifest, an Anthropic
marketplace manifest, the `secure-development-review` skill, and a bundled
local MCP server. The server reads this knowledge base and only reviews local
paths that you explicitly authorize; it uses no API keys and makes no network
requests.

### Recommended: install from the Claude Code marketplace

Register the marketplace once:

```sh
claude plugin marketplace add aakash-code/unofficial-cwe-agentsec-kb
```

Install the plugin for the current repository (use `--scope user` to make it
available to your user account, or omit the flag and choose a scope in the
interactive plugin panel):

```sh
claude plugin install unofficial-cwe-agentsec-kb@unofficial-cwe-agentsec --scope project
claude plugin list
```

In a Claude Code session, `/plugin` lets you review the plugin before
installing; `/mcp` shows whether its local MCP server is connected. Start a new
session and ask: “Use secure-development-review to review this authorized local
project.”

### Manual: add the MCP server

From this repository clone, add a project-scoped server:

```sh
claude mcp add --scope project --transport stdio unofficial_cwe_agentsec_kb -- python3 "$PWD/tools/agentsec.py" serve
claude mcp get unofficial_cwe_agentsec_kb
```

Claude Code stores project-scoped server settings in `.mcp.json`. Review and
approve that configuration when Claude Code prompts you; only commit it when
the whole team should use the server.

### Manual: add only the skill or project instructions

To make the workflow available without installing the plugin, copy the skill
into the target project's Claude Code skills directory:

```sh
mkdir -p /path/to/your-project/.claude/skills
cp -R skills/secure-development-review /path/to/your-project/.claude/skills/
```

For persistent project guidance, also copy
[adapters/claude/CLAUDE.md](adapters/claude/CLAUDE.md) to the target project as
`CLAUDE.md`. See the [Claude integration notes](adapters/claude/README.md).

## Other MCP-compatible agents

For Cursor, Cline, Continue, Windsurf, or another MCP-compatible agent, use the
JSON MCP configuration above and provide
[adapters/generic/SECURITY_AGENT.md](adapters/generic/SECURITY_AGENT.md) as
project instructions. Require the structured format in
[adapters/generic/OUTPUT_CONTRACT.md](adapters/generic/OUTPUT_CONTRACT.md).

## How agents should use the knowledge base

1. Confirm that the requested assessment is authorized.
2. Search the relevant rule or CWE first; retrieve only the needed CWE entry.
3. Treat automated results as leads, not proof.
4. Report evidence, confidence, CWE references, safe verification, remediation,
   and limitations.
5. Do not perform active testing, contact external targets, expose secrets, or
   provide intrusive attack instructions without explicit authorized scope.

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

## Official CWE content, license, and attribution

Original Unofficial CWE AgentSec KB work is licensed under the [MIT License](LICENSE). The
official CWE 4.20 XML archive and its derived data pack are governed by the
[CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html), including
MITRE attribution requirements. This project does not claim ownership of CWE
content and must not be presented as the official CWE website or a MITRE
product. See [NOTICE](NOTICE), [CREDITS.md](CREDITS.md), [SOURCES.md](SOURCES.md),
and [CWE source coverage](docs/cwe-source-coverage.md).

## Contributing and security reports

Read [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md), and [SECURITY.md](SECURITY.md). Contributors must submit original work or clearly identify the license and provenance of any imported material.
