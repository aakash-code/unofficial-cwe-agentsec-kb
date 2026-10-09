# Planning and writing security tests

The goal is tests that prove a control works and stay in the suite as
regressions. Showing that an attack is possible against something live is out of scope.

## Default scope

Without asking, you may:
- write unit and integration tests in the user's project using synthetic data
- run the project's own test suite, linters, type checkers, and offline scanners
  such as `bandit`, `gitleaks`, or `semgrep` with local rule files
- start the app locally with synthetic data and send requests to it, when its
  configuration points only at local or mock services

Tell the user before running tools that contact external services. `npm audit`,
`pip-audit`, and `osv-scanner` send dependency names and versions to public
vulnerability databases. `trivy` downloads its database, and `semgrep --config
auto` fetches rules from a registry. If starting the app would reach real
third-party services, a shared database, or real credentials, ask first.

Ask first, and get the target, owner, time window, and rate limits in writing, before:
- sending traffic to any deployed environment (staging, preview URLs, prod)
- testing third-party APIs or services the user doesn't own
- anything destructive, load-heavy, or touching real user data or real secrets

If authorization for a non-local target is unclear, stop and say what you need.

## What a good security test looks like

Each test asserts that the **control** holds:

| Weakness | Test asserts |
|---|---|
| CWE-89 SQL injection | input containing `' OR '1'='1` is treated as a literal value; the query is parameterized |
| CWE-79 XSS | user input stays inert in every sink it reaches: HTML text, attributes, URLs, inline scripts. Each sink needs encoding for its context, so test each one separately |
| CWE-22 path traversal | `../`, absolute paths, and encoded variants are rejected or contained |
| CWE-862/639 authz / IDOR | for every verb the endpoint supports, user B using user A's object ID gets no A data in the body and causes no side effect (403/404 is typical) |
| CWE-918 SSRF | URLs resolving to loopback, link-local (169.254.x), or private ranges are refused, including after redirects |
| CWE-352 CSRF | a state-changing request from an untrusted origin without a valid token is refused. SameSite is not an origin check, because sibling subdomains count as same-site, so validate the exact trusted origins as well |
| CWE-307 brute force | the Nth failed login is throttled or locked |
| CWE-502 deserialization | untrusted input is never passed to an unsafe loader (unit test or lint rule) |
| CWE-798 secrets | a secret scanner runs in CI and the repo is clean |

Keep payloads minimal and harmless, just enough to show the input stays data.
Name tests after the property (`test_other_users_invoice_returns_404`), not
the attack.

## When the user asks for a "pentest" or "security testing"

1. Clarify the target: the code (static review plus local tests) or a deployed system.
2. For the code, run the review workflow in `SKILL.md`, then write regression
   tests for each confirmed finding.
3. For a deployed system, get the scope first (see above). Even then, prefer
   non-destructive checks and point to established tools the user runs
   (e.g. OWASP ZAP baseline against their own staging) over hand-rolled attack scripts.

## Fix verification

A finding is fixed only when the regression test fails on the old code and
passes on the new code, and a re-read of the change shows no bypass, such as
another route or verb reaching the same sink. Editing the code alone doesn't
count as fixed.
