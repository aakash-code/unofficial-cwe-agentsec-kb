---
name: setup
description: Verify or troubleshoot the Unofficial CWE AgentSec KB install — its local CWE 4.20 data pack and the unofficial_cwe_agentsec_kb MCP server. Use after installing the plugin, when agentsec_* tools are missing or erroring, or when the user asks whether the security knowledge base is working.
---

# AgentSec KB setup check

Run these in order and stop at the first failure. Report the exact error.

1. **MCP path.** If `agentsec_validate_kb` is available, call it. A result with
   `"valid": true` and `cwe_data.version` `4.20` means everything works. Say so
   and stop.
2. **CLI path.** Run `python3 "<plugin root>/tools/agentsec.py" validate`.
   The plugin root is `${CLAUDE_PLUGIN_ROOT}` in Claude Code. In other hosts
   it's two directories above this skill's folder.
   - `python3: command not found` or a version below 3.10 (`python3 --version`):
     the user needs Python 3.10+ on `PATH`. The tool needs no other packages.
   - Validation errors: report them verbatim. A SHA-256 mismatch or missing
     archive means the data pack is damaged. Reinstall the plugin. Don't
     download replacement data.
3. **CLI works but the MCP tools are missing.** The server didn't start.
   - Claude Code: ask the user to run `/mcp` and look at
     `unofficial_cwe_agentsec_kb`, or to run `claude mcp list` in a terminal.
     Check that `claude plugin list` shows `unofficial-cwe-agentsec-kb` as
     enabled. Restart Claude Code after installing or enabling the plugin.
   - Gemini CLI: `gemini extensions list` and `gemini mcp list`. If the server
     shows as disconnected, the project may need `gemini trust`.
   - Other hosts: check the host's MCP server list and restart it after
     installing the plugin.
   - Until it's fixed, the `secure-development-review` skill can use the CLI
     fallback.

The server is local and read-only. It doesn't execute reviewed code, make
network requests, or use credential stores. Its review tool does read the
text files under the path it's given, so point it only at code the user
wants reviewed. Setup never modifies the user's project
and never tests any external target.
