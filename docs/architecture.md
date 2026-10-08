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
          +-- Codex skill and plugin configuration
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

The tool offers `tools/list` and `tools/call` MCP methods using newline-delimited
JSON-RPC on standard input/output. Hosts that require different transport or
MCP protocol negotiation can wrap the core or invoke the CLI; the knowledge
and finding schema remain transport-independent.

The static reviewer intentionally implements a small set of high-signal
heuristics. It does not parse every language, infer data flow, or prove
exploitability. The finding output labels confidence and preserves evidence so
the user can review it.
