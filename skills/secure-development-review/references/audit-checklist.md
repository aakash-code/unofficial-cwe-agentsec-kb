# Audit checklist by domain

Use this to decide where to look. Skip domains that don't apply to the stack.
For each domain, `agentsec_search_cwe` with the listed terms finds candidate
entries. Start discovery from the views: CWE-699 (Software Development), CWE-1003 (Simplified Mapping), CWE-1435 (2025 Top 25), and CWE-1448 for AI/ML. Get a view with `sections: ["Members"]` to list its member weaknesses.

## Contents
- Input and injection
- Access control
- Authentication and sessions
- Secrets and sensitive data
- Files, paths, archives
- Serialization
- Web and browser
- Outbound requests
- Cryptography
- Concurrency and state
- Memory and native code
- Configuration, deployment, IaC
- Dependencies and supply chain
- Logging and errors
- AI / LLM / agent systems

## Input and injection
Is untrusted input neutralized *for the interpreter it reaches*? Check SQL/NoSQL,
ORM raw queries, LDAP, XPath, template engines, shell, `eval`, regex built
from input (ReDoS).
Search: `injection`, `neutralization`, `eval`, `regular expression`.

## Access control
Is every state-changing or data-returning handler checked server-side? Check
object ownership on ID lookups (IDOR), role checks, tenant isolation, and admin
routes. Hiding something in the UI is not access control.
Search: `missing authorization`, `incorrect authorization`, `user-controlled key`.

## Authentication and sessions
Check password storage, login rate limiting, reset and recovery flows, MFA
bypasses, session fixation and rotation, JWT validation (alg, exp, aud,
signature), and cookie flags (HttpOnly, Secure, SameSite).
Search: `authentication`, `session fixation`, `password hash`, `JWT`, `cookie`.

## Secrets and sensitive data
Check hard-coded keys, `.env` committed to git, secrets in client bundles,
PII in URLs or logs, and data that must be encrypted at rest or in transit.
Search: `hard-coded`, `cleartext`, `sensitive information`.

## Files, paths, archives
Check user-influenced paths, upload type and size checks, storage location
(web root?), zip-slip on extraction, symlink following, and temp-file
permissions.
Search: `path traversal`, `unrestricted upload`, `archive`, `link following`.

## Serialization
Check pickle, `yaml.load`, Java/.NET native serialization, PHP `unserialize`,
and JSON revivers that instantiate types.
Search: `deserialization`.

## Web and browser
Check output encoding per context, raw-HTML sinks (`innerHTML`,
`dangerouslySetInnerHTML`, `|safe`, `v-html`), CSRF on cookie-auth state
changes, open redirects, CORS with credentials and wildcard or reflected
origin, and missing CSP or clickjacking headers.
Search: `cross-site scripting`, `CSRF`, `open redirect`, `CORS`.

## Outbound requests
Check server-side fetches of user-supplied URLs (webhooks, previews,
importers), redirect following, and internal metadata endpoints.
Search: `server-side request forgery`.

## Cryptography
Check homegrown crypto, ECB mode, static IVs, weak hashes for passwords,
non-CSPRNG tokens, and disabled TLS verification.
Search: `cryptographic`, `random`, `certificate validation`.

## Concurrency and state
Check check-then-act races on balances, inventory, or quotas, TOCTOU on files,
and non-idempotent payment or webhook handlers.
Search: `race condition`, `time-of-check`.

## Memory and native code
Check C/C++ buffers, integer overflow in size math, format strings,
use-after-free, and `unsafe` blocks or FFI.
Search: `buffer overflow`, `integer overflow`, `format string`.

## Configuration, deployment, IaC
Check debug mode in production, default credentials, public buckets, `0.0.0.0/0`
ingress, over-broad IAM, containers running as root, and secrets in CI logs.
Search: `permissions`, `default`, `debug`.

## Dependencies and supply chain
Check unpinned or abandoned packages, install scripts, loading plugins from
untrusted paths, and fetching code at runtime. Use the ecosystem's audit tool
(`npm audit`, `pip-audit`, `osv-scanner`) for known CVEs. This KB covers weakness
types, not CVE data.
Search: `third-party component`, `untrusted search path`, `integrity check`.

## Logging and errors
Check stack traces returned to clients, verbose errors revealing internals,
log injection, and missing audit logs for security events.
Search: `error message`, `log`, `neutralization logs`.

## AI / LLM / agent systems
Review classic weaknesses *and* these:
- untrusted text (user input, retrieved docs, web pages, tool results)
  concatenated into system or privileged prompts
- model output flowing into SQL, shell, `eval`, file paths, HTML, or URLs
  without validation, which is the same injection class as any other untrusted input
- tool and MCP calls without per-action authorization; agents holding broader
  credentials than the task needs
- tool arguments built from model output (command or path injection)
- secrets or other tenants' data placed in the context window
- prompts and completions with PII written to logs
- persistent agent memory that one user can poison for another
- retrieval stores that accept unauthenticated writes

The rules `ASKB-LLM-001` (prompt injection) and `ASKB-LLM-002` (agent tool
privilege) give concrete fixes. Use `agentsec_get_rule` to fetch them.
Start from CWE-1448 (AI/ML view) for discovery, then map each finding to the
most specific allowed weakness that fits, which is often a classic one
(CWE-78, CWE-94, CWE-862, CWE-639).
