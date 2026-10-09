# Architecture

AgentSec KB separates durable knowledge from agent-specific instructions.

```text
original rules + mappings + schemas      official CWE XML release
                 |                                |
                 +--------------+-----------------+
                                v
                  versioned catalog + index + graph
          |
          v
validator / query CLI / local static reviewer / MCP stdio server
          |
          +-- Claude Code plugin (skills + MCP)
          +-- Codex plugin and Gemini CLI extension
          +-- Claude project instructions
          +-- Generic agent prompt/output contract
```

The Python core relies only on the standard library so it can be audited and
run locally. Rules are JSON rather than prompt prose to enable validation,
versioning, testing, and reuse by non-Python implementations. The official CWE
archive is preserved verbatim under `vendor/cwe/<version>`; the importer creates
a lossless JSON catalog plus compact index and relationship graph under
`data/cwe/<version>`. This keeps official source content separable from
AgentSec KB's original guidance and makes each update reviewable.

The MCP server speaks newline-delimited JSON-RPC over UTF-8 stdio and
implements `initialize` (protocol versions 2024-11-05 through 2025-11-25),
`tools/list`, `tools/call`, and `ping`. Tool results are compact JSON text.
CWE entries are returned as readable text sections rather than the raw XML
tree, because hosts cap tool output (Claude Code rejects results above about
25k tokens) and the raw tree of a large entry exceeds that. `cwe-get --raw`
on the CLI still returns the lossless tree. Hosts that need a different
transport can wrap the core or invoke the CLI. The knowledge and finding
schemas are transport-independent.

`validate` enforces that every rule cites CWEs that exist in the pinned
catalog and that MITRE does not mark Discouraged or Prohibited for
vulnerability mapping, and that `mappings/cwe.json` matches each rule's
`cwe_ids` exactly.

The static reviewer intentionally implements a small set of high-signal
heuristics. It does not parse every language, infer data flow, or prove
exploitability. The finding output labels confidence and preserves evidence so
the user can review it.
