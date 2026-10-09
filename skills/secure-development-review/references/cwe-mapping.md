# Choosing the right CWE

A finding's CWE should name the **root-cause weakness** in the code, not its
consequence and not a navigation grouping.

## Read `mapping_usage` first

Every search hit and entry carries MITRE's vulnerability-mapping usage:

| Value | Meaning for you |
|---|---|
| `Allowed` | Fine to use when the code evidence fits the description. |
| `Allowed-with-Review` | Usable, but read `Mapping_Notes` and check a more specific child doesn't fit better. |
| `Discouraged` | Usually too broad or commonly misused (CWE-20 is the classic case). Look for a more precise child or sibling. Use it only if nothing better fits, and say why. |
| `Prohibited` | Never use as the finding's CWE. All Views and Categories are Prohibited. |

## Rules

1. **Views and Categories are for navigation.** Use them to discover
   weaknesses (e.g. CWE-699 Software Development, CWE-1003 Simplified Mapping),
   then map to a member weakness.
2. **Prefer Base or Variant** when the evidence supports it. Fall back to a
   Class only when the code doesn't justify anything narrower.
3. **Don't force specificity.** A child CWE that *sounds* closer is wrong if its
   technology, resource, or behavior doesn't match what the code does. MITRE's
   own mapping notes say this repeatedly.
4. **Weakness, not impact.** "Data disclosure", "account takeover", and "RCE"
   are outcomes. Ask what missing or incorrect control caused them: missing
   authorization (CWE-862), SQL injection (CWE-89), unsafe deserialization
   (CWE-502), and so on.
5. **One root cause per finding.** Add secondary CWEs only when each is
   independently evidenced in the code. Use relationship types (`ChildOf`,
   `CanPrecede`, `PeerOf`) to explain chains, but a relationship alone proves
   nothing about exploitability.
6. **Unmapped is acceptable.** If no entry fits without speculation, report the
   finding with `CWE: none — needs review` and state what evidence is missing.
7. **Deprecated or obsolete entries**: follow the replacement named in the entry.

## Confidence

- **High**: direct code path from untrusted source to sink, the CWE description
  matches, and the alternatives are clearly worse fits.
- **Medium**: strong match, but one environmental assumption is unverified
  (e.g. whether an endpoint is reachable without auth).
- **Low**: conceptual similarity only. Prefer `Needs Review` over a firm claim.

## Common correct mappings

| Code pattern | Usual root cause |
|---|---|
| String-built SQL with request data | CWE-89 |
| `shell=True` / `exec()` with user data | CWE-78 |
| Unescaped user data in HTML or DOM | CWE-79 |
| User-controlled file path | CWE-22 |
| Handler with no permission check | CWE-862 (no check) or CWE-863 (wrong check) |
| Object fetched by ID without an ownership check (IDOR) | CWE-639 |
| Fetching a user-supplied URL server-side | CWE-918 |
| `pickle` / `yaml.load` / Java native deserialization of input | CWE-502 |
| Secret literal in source | CWE-798 |
| TLS verification disabled | CWE-295 |
| Secrets or PII written to logs | CWE-532 |
| Password stored with a fast hash | CWE-916 |

Always confirm the entry with `agentsec_get_cwe` before reporting. This table
is a starting point, not a substitute.
