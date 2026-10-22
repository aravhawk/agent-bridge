# Jarvis Friday Bridge · v1.0.0

Private, event-driven inbox messaging between Arav's Jarvis and Friday. Messages,
status updates and handoff requests are data; they never grant permission to run
code, perform production actions or change access. The receiver evaluates them
under Arav's independently authorized workflow. No Mac relay or recipient polling.

Canonical service: **https://jarvis-friday-bridge.aravhawk.com**

- Jarvis MCP: `/bridge/jarvis/mcp`
- Friday MCP: `/bridge/friday/mcp`
- Public version/liveness: `/health` (no private readiness or delivery operations)

This is the deployed v1 source. Normal delivery remains disabled pending native
integration evidence; deployment does not attest readiness. Existing production
bindings are reused, and setup documents do not authorize recreating them. The
old disabled deployment remains a separate rollback snapshot at commit
`fac3baf1ab0be6d70609b3520c97801fc734361b`.

See [architecture and invariants](docs/architecture.md) for the active lifecycle,
failure semantics and remaining integration limits. Historical setup records
and fixtures are separate from active v1.

## Verify source

Node24 and Python3; no real credentials needed:

```sh
npm ci --ignore-scripts
npm test
python3 scripts/audit_repo.py
```

The suite covers signature/issuer/audience/scope isolation, canonical routing,
health-only bootstrap, native subscription leases, atomic receipt/ACK handling,
durable dispatch, bounded retries and retention. Rollback-model fixtures exercise
old guard behavior without deploying old routes or configuration.

`npm run check:remote` makes credential-free requests only to the canonical v1
service, with no messages, subscriptions, grants or real bearer tokens. Before
an actual issuer is configured it expects metadata503 and closed bearer access.
See [configuration](docs/configuration.md) before using its optional flags.

## Deployment identity

Only Arav's Projects, team `team_rCVvKJ5rUgNP0LOPEwzfyl0z`.
New project **jarvis-friday-bridge**, `prj_rTBPrIoODxpC1A6sS2OQtlvc7cqE`.
Reuse the private repository `aravhawk/jarvis-friday-bridge`.
Do not modify the portfolio, other projects or the old deployment during cutover.

The v1 queue is `jarvis-friday-bridge-v1`; state table is `bridge_runtime_v1` in a
new isolated database. No old user/subscription/message state is silently copied.
The issuer and public client IDs come from the approved production provider;
there is no development-provider fallback or guessed live configuration.

[Message/receiver contract](docs/inbox-policy.md) ·
[Setup and configuration](docs/configuration.md) ·
[Cutover and confirmation bundle](docs/cutover.md)

Content reads expire after24h. Physical cleanup is best effort and can exhaust;
there is no finite physical-deletion guarantee. Strict count/size capacity and
seven-day replay tombstones bound live state. See the contract for exact limits.
