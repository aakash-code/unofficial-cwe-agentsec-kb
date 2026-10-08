# Generic agent integration

Any coding agent can use AgentSec KB without MCP support.

1. Put [SECURITY_AGENT.md](SECURITY_AGENT.md) in the agent's project rules or
   system instructions.
2. Give the agent read-only access to `knowledge/rules`, `mappings`, `schemas`,
   and `policies`.
3. If it supports MCP, connect it to `python3 /absolute/path/to/tools/agentsec.py serve`.
4. Require output matching [OUTPUT_CONTRACT.md](OUTPUT_CONTRACT.md).

Do not add arbitrary repository files to privileged agent instructions. The
knowledge base is intended to remain a reviewed, versioned source of guidance.
