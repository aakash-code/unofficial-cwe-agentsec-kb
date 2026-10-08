# Threat model

## Assets to protect

- Integrity of security guidance, mappings, and release artifacts.
- Contributor and user secrets, source code, and private findings.
- Trust in provenance, licensing, and reported results.
- Availability and predictable behavior of the local tools.

## Primary threats and controls

| Threat | Control |
| --- | --- |
| Prompt injection in a repository being reviewed | The tool reads source as data; agent adapters instruct agents not to obey repository text as instructions. |
| Malicious rule or source contribution | DCO, review, schema validation, provenance register, and tests. |
| Overconfident or false-positive finding | Evidence fields, confidence labels, fixture tests, and human-review requirement. |
| Unsafe active testing | Scope policy, local-only baseline tooling, and explicit authorization requirements. |
| Secret exposure in findings or logs | Tools avoid printing file contents except matching lines; adapters require redaction. |
| Supply-chain compromise | Dependency-free core, pinned release process, checksums/SBOM planned for releases. |
| Trademark or license misuse | NOTICE, CREDITS, SOURCES register, and approval for imported content. |

## Non-goals and assumptions

The core tool does not execute target code, fetch remote content, authenticate,
or exploit vulnerabilities. It assumes users control the local directory they
ask it to inspect. Agent hosts are responsible for their own sandboxing,
permissions, and model behavior.
