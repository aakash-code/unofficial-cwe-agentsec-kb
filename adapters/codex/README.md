# Codex integration

AgentSec KB ships as a Codex plugin at the repository root. The plugin manifest
loads the `secure-development-review` skill and starts the local MCP server
with `python3 tools/agentsec.py serve` from the plugin root.

The plugin follows the official OpenAI plugin layout: a `.codex-plugin/plugin.json`
manifest points to a skill directory and an `.mcp.json` server configuration.
The skill is a directory with a `SKILL.md` manifest and instructions. See the
[OpenAI plugin documentation](https://developers.openai.com/api/docs/guides/agents-api/tools/plugins)
and [skills documentation](https://developers.openai.com/api/docs/guides/tools-skills).

## Local use

Keep this repository intact and make its root available as a plugin/capability
directory in your Codex environment. The server needs Python 3.10+ and no
additional dependencies.

Before installing, review the plugin files and run:

```sh
python3 tools/agentsec.py validate
python3 -m unittest discover -s tests -v
```

## Expected tools

- `agentsec_search_rules` — search portable guidance.
- `agentsec_get_rule` — fetch full rule details.
- `agentsec_review_path` — local, read-only heuristic review of an authorized directory.
- `agentsec_validate_kb` — verify rule and mapping integrity.
- `agentsec_search_cwe` — search the complete pinned official CWE catalog.
- `agentsec_get_cwe` — retrieve full canonical content for one CWE entry.
- `agentsec_cwe_status` — verify CWE version, source, counts, and checksum.

The `agentsec_review_path` tool does not execute code or contact networks. Its
findings are leads for human review, not confirmed vulnerabilities.
