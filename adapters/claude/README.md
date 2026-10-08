# Claude Code integration

This directory provides portable project instructions rather than depending on
a particular Claude Code plugin format. Copy `CLAUDE.md` into the root of a
repository that should follow AgentSec KB review practices. If your Claude Code
installation supports skill folders, copy the `skills/secure-development-review`
directory using its documented project-skill location.

Optionally register this repository's local MCP server with your Claude Code
environment using the command below, with the absolute repository path:

```text
python3 /absolute/path/to/agentsec-kb/tools/agentsec.py serve
```

Review the server configuration and run `python3 tools/agentsec.py validate`
before enabling it. The server is local and read-only, but it may inspect the
directory supplied to its review tool.
