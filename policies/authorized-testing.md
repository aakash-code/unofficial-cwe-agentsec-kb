# Authorized security testing policy

## Required conditions

Use AgentSec KB only when you have explicit authorization to assess the code,
repository, service, or environment. Define the owner, assets, permitted
methods, test window, rate limits, stop conditions, and reporting path before
performing any active testing.

## Default safe mode

The project defaults to offline, non-destructive work:

- source review and static checks;
- dependency and configuration review using local files;
- local unit and integration tests with synthetic data;
- threat modeling and remediation planning.

## Prohibited without separate, written approval

- testing external systems, production systems, or third-party dependencies;
- credential stuffing, phishing, denial-of-service, persistence, lateral
  movement, destructive changes, or data extraction;
- handling real secrets or personal data in prompts, fixtures, or findings;
- using a coding agent to bypass authorization or safety controls.

## Agent behavior

An adapter must ask for scope when a request could involve an external target.
It must stop if authorization is absent or unclear. Security findings should
describe impact and safe verification, not supply weaponized steps or payloads.
