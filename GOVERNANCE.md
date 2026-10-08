# Governance

## Project principles

AgentSec KB is vendor-neutral, evidence-led, secure-by-design, transparent
about limitations, and open to contributors. Security guidance must not become
a mechanism for unsanctioned testing or destructive activity.

## Roles

- **Contributors** propose rules, fixes, tests, documentation, and adapters.
- **Reviewers** assess correctness, safety, sources, and tests.
- **Maintainers** merge changes, publish releases, handle disclosures, and
  protect the project license and provenance record.

Initially, the repository owner acts as the sole maintainer. Add at least two
active maintainers before declaring a stable 1.0 release.

## Decisions

Routine changes need one maintainer approval. Changes to licenses, safety
policy, schemas, release signing, or third-party imported content require two
maintainer approvals after a public discussion period of at least seven days.

## Releases

Use semantic versioning:

- **MAJOR:** incompatible schema, policy, or adapter behavior.
- **MINOR:** backward-compatible rules, tools, and adapters.
- **PATCH:** corrections and documentation-only fixes.

Each release must include a changelog, test results, source-register review,
and a statement of known limitations.
