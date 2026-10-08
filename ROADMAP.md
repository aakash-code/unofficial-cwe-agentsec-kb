# Roadmap

## 0.2 — Coverage and confidence

- Add language and framework packs for Python, JavaScript/TypeScript, Java, Go,
  cloud infrastructure, and CI/CD.
- Add regression fixtures for true positives and known false positives.
- Add rule metadata for applicability, maturity, and confidence rationale.
- Add SARIF export without changing the canonical finding schema.

## 0.3 — Supply chain and release integrity

- Generate an SBOM and signed release checksums.
- Add dependency-manifest inspection that works fully offline.
- Publish a contributor review checklist and release checklist.

## 1.0 — Stable interface

- Publish versioned schemas and compatibility guarantees.
- Add at least two active maintainers and a transparent security advisory path.
- Benchmark supported adapters against public, safe fixture suites.
- Document coverage, false-positive behavior, and non-goals by language.

## Deliberately out of scope

Active remote scanning, exploitation, credential attacks, destructive testing,
and vendor-specific model training are not planned for the core project.
