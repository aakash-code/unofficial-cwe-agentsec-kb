# Contributing to AgentSec KB

Thank you for contributing. AgentSec KB values accuracy, clarity, safety, and
source provenance over rule count.

## Before contributing

1. Read [SECURITY.md](SECURITY.md), [policies/authorized-testing.md](policies/authorized-testing.md), and [SOURCES.md](SOURCES.md).
2. Open an issue or proposal for a new rule, integration, or material change.
3. Do not include secrets, production data, live-target output, exploit payloads, or material you cannot license for redistribution.

## Rule contributions

Each rule must:

- use the schema in `schemas/rule.schema.json`;
- describe original, actionable defensive guidance;
- name the applicable technology and scope;
- include a stable rule ID and one or more external references when relevant;
- distinguish a security weakness from an unverified suspicion;
- include safe validation guidance and a remediation path;
- be covered by tests if it changes automated behavior.

Avoid copied third-party text. If you adapt or include third-party material,
record exact provenance, license, attribution, and file location in
`SOURCES.md`, then obtain maintainer approval before merging.

## Contributions and sign-off

By submitting a contribution, you certify that you have the right to submit it
under this repository's license and that it is your original work or clearly
licensed compatible material. Add a sign-off line to each commit:

```text
Signed-off-by: Your Name <you@example.com>
```

This is the Developer Certificate of Origin (DCO) process. Maintainers may ask
for source records, test cases, or revisions before accepting a change.

## Review standards

Maintainers review for:

- technical soundness and evidence quality;
- false-positive and false-negative implications;
- safety and authorized-use boundaries;
- stable schemas and backward compatibility;
- licensing, trademarks, and attribution;
- documentation and automated tests.

## Reporting problems in guidance

If a rule could create material security risk, report it privately using
[SECURITY.md](SECURITY.md), not through a public issue.
