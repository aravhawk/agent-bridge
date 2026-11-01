# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. If GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
is enabled, use "Report a vulnerability" on the repository's **Security**
tab. Otherwise, contact the repository owner privately; do not post
vulnerability details in public issues.

Include the affected version or commit, a description of the impact and steps
to reproduce. Never include real tokens, secrets, database URLs or message
content; use synthetic fixtures. You should receive an acknowledgement within
a few days. Fixes are released on `main` and credited in the advisory unless
you prefer otherwise.

## Supported versions

Only the latest commit on `main` is supported.

## Scope

In scope: anything that lets a caller bypass JWT verification, the subject
pin, peer audiences or directional scopes; read or complete another peer's
messages; choose a callback/webhook destination or signing secret; reach
private or non-public network addresses; recover callback secrets from
storage; or make a message act as permission.

Out of scope: weaknesses that require control of the deployment's environment
variables, the OAuth provider tenant or the database; denial of service
through the documented capacity limits; and the documented non-guarantees
(transport acceptance does not prove that an assistant woke or acted).

## Hardening notes for operators

- Keep every secret in your platform's secret store; `.env.example` must stay blank.
- Prefer `BRIDGE_ALLOWED_SUBJECT_SHA256` over the raw subject.
- Use a dedicated database and role for the bridge.
- Consider `BRIDGE_REQUIRE_ISSUER_UNDER_ORIGIN=true` and `BRIDGE_DATABASE_HOST_SUFFIX`
  to pin the issuer and database provider.
- Open readiness gates only after verifying each one, and rotate the webhook
  secret and storage key if you suspect exposure.
