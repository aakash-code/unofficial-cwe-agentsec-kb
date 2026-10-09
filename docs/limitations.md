# Limitations

Unofficial CWE AgentSec KB is an intentionally conservative foundation, not a complete
application-security platform.

- The local reviewer uses per-line pattern matching, not parsing or data-flow
  analysis. It catches a few dozen high-signal patterns and misses anything
  that spans lines or depends on context (missing authorization, SSRF, most
  logic flaws). Use it for leads. The `secure-development-review` skill
  directs agents to trace data flow by hand.
- The 20 original rules cover common web, API, IaC, and LLM-agent weaknesses.
  For anything else, agents fall back to the full CWE catalog, which describes
  weaknesses but does not give project-specific fixes.
- Search is keyword-based over CWE names, alternate terms, and summaries, not
  semantic. Agents should try synonyms when a query returns nothing useful.
- Only a limited set of common source extensions and files below 1 MB are read.
- The tool does not resolve dependencies, inspect container images, run tests,
  access cloud accounts, or query vulnerability databases.
- CWE references classify weakness types; they do not confirm a vulnerability.
- Agent adapters cannot override the policies, sandboxing, or limitations of
  their host products.
- This project provides technical guidance, not legal, compliance, or incident
  response advice.

Every result should be reviewed by someone with context for the application,
its data, deployment, and authorized test scope.
