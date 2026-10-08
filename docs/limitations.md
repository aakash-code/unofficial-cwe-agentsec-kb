# Limitations

AgentSec KB 0.1.0 is an intentionally conservative foundation, not a complete
application-security platform.

- The local reviewer uses pattern matching, not complete parsing or data-flow
  analysis. It can miss issues and produce false positives.
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
