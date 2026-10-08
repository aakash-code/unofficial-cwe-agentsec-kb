---
name: setup
description: Verify the Unofficial CWE AgentSec KB plugin is ready by checking its local data pack and MCP server requirements.
---

Use this skill after installing the plugin or when its tools are unavailable.

1. Confirm Python 3.10+ is available.
2. Run `python3 tools/agentsec.py validate` from the plugin root.
3. Confirm the local CWE data pack validates and reports version 4.20.
4. Explain that the bundled MCP server is local, read-only, and uses
   `python3 tools/agentsec.py serve`.
5. If validation fails, report the exact error and do not claim the CWE catalog
   or source-review tools are available.

Do not download replacement data, alter a project, or test an external target
during setup.
