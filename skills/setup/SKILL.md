---
name: setup
description: Verify or troubleshoot the Unofficial CWE AgentSec KB install — its local CWE 4.20 data pack and the unofficial_cwe_agentsec_kb MCP server. Use after installing the plugin, when agentsec_* tools are missing or erroring, or when the user asks whether the security knowledge base is working.
---

# AgentSec KB setup check

Run these in order and stop at the first failure. Report the exact error.

1. **MCP path.** If `agentsec_validate_kb` is available, call it. A result with
   `"valid": true` and `cwe_data.version` `4.20` means everything works. Say so
   and stop.
2. **CLI path.** Run
   `python3 "${CLAUDE_PLUGIN_ROOT}/tools/agentsec.py" validate`.
   - `python3: command not found` or a version below 3.10 (`python3 --version`):
     the user needs Python 3.10+ on `PATH`. The tool needs no other packages.
   - Validation errors: report them verbatim. A SHA-256 mismatch or missing
     archive means the data pack is damaged. Reinstall the plugin. Don't
     download replacement data.
3. **CLI works but the MCP tools are missing.** The server didn't start.
   - Ask the user to run `/mcp` and look at `unofficial_cwe_agentsec_kb`, or run
     `claude mcp list` in a terminal.
   - Check `claude plugin list` shows `unofficial-cwe-agentsec-kb` as enabled.
   - After installing or enabling the plugin, Claude Code must be restarted.
   - Until it's fixed, the `secure-development-review` skill can use the CLI
     fallback.

The server is local and read-only: it doesn't execute reviewed code, make
network requests, or read credentials. Setup never modifies the user's project
and never tests any external target.
