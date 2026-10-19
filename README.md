# Jarvis Friday Bridge

Private synthetic connectivity test between Jarvis and Friday, using an
isolated Vercel MCP backend, Clerk public OAuth clients, Neon storage and native
MCP Events. This repository includes the backend, the registered private plugin,
tests, schema and Vercel configuration.

The backend accepts only the fixed synthetic envelope. Native receivers,
subscription readiness and delivery bindings must be verified before sends.
Delivery is disabled. Jarvis subscription setup is enabled and its signed
callback/persisted subscription was verified on October 19. No random wake test
is armed. OAuth credentials remain in the native clients/provider; database and
runtime secrets remain in the isolated Vercel project's Production environment.

## Develop and check

Use Node24 and Python3. No environment file or real credential is needed for
the local tests.

```sh
npm ci --ignore-scripts
npm test
python3 scripts/audit_repo.py
```

Tests use in-memory transports, fixture identities and locally generated test
keys. They do not send real messages or call native assistants. The legacy
health/negative OAuth routes are also covered.

For explicitly requested credential-free checks against the existing isolated
public deployment, run `npm run check:remote`. Reports go to ignored `.reports/`.
These checks do not send real credentials, create grants or deliver events.

## Contents

| Path | Purpose |
|---|---|
| `api/`, `src/` | Authenticated MCP bridge, durable state, Events and queue worker |
| `legacy/` | Preserved health-only and rejecting diagnostic routes |
| `plugin/` | Actual registered portable plugin plus compatibility manifests |
| `test/` | Backend, protocol, storage, legacy and repository contract checks |
| `schema.sql` | Existing isolated database schema; no automatic migrations |
| `vercel.json` | Existing iad1/Node runtime and private queue configuration |
| `.env.example` | Blank secret slots and nonsecret public connection settings |
| `docs/source-provenance.json` | Initial production source reconciliation and portable plugin identity |
| `docs/configuration.md` | Runtime boundaries and current connection requirements |
| `scripts/package_plugin.py` | Package the existing plugin without creating a duplicate |

`plugin/` is the canonical registered plugin source. The backend's gated
`src/plugin-draft.mjs` preparation helper is retained from the deployed snapshot;
it is not used by the packaging script to regenerate the registered plugin.

## Existing deployment

Production: https://rn-jarvis-friday-discovery-20261018.vercel.app

- Friday MCP: `/bridge/friday/mcp`
- Jarvis MCP: `/bridge/jarvis/mcp`
- Original health-only MCP: `/mcp`

The product/repository name is **Jarvis Friday Bridge**. Existing RN deployment,
OAuth, event and test identifiers are preserved because they are protocol and
integration identities. Do not rename the Vercel project, aliases or clients
merely to match this repository.

Only **Arav's Projects**, team `team_rCVvKJ5rUgNP0LOPEwzfyl0z`, project
`prj_U4y7PBcoZN3cI2bE3NLE2GZGBFIG`, is in scope. This repository is linked to
that existing project; do not import it as a second project. Its Git settings
now show `aravhawk/jarvis-friday-bridge` connected using the existing GitHub
installation, with no new grant. Production tracks `main`. The root directory
is this repository root, Framework is Other, Node.js is 24.x, and build, output
and install commands use their defaults. Preserve Production secrets and all
disabled delivery gates. Do not change another project's Git connection.

The initial source commit passed all 59 local/CI tests and the staged/history
secret scans. After linkage, all 34 credential-free endpoint checks passed;
linking itself did not trigger a build. The first subsequent push to `main`
must verify a Git deployment's exact commit, Ready status, canonical URL and
the same endpoint checks. See `docs/configuration.md` for the verification
limits and disabled runtime gates.

## Remaining acceptance work

Jarvis native OAuth and discovery are verified through the managed custom MCP
app. Its authenticated no-argument `bridge_health` tool checks nonsecret
configuration readiness without storage, message or event operations. It uses
the existing resource policy and directional scopes; no new OAuth scope is
needed. A healthy response does not imply that delivery or subscriptions are
ready. Refresh the managed app's tool list after a backend tool change.

Jarvis's signed native Events subscription and callback protection are verified.
Friday's supported incoming webhook authentication/secret handoff,
supported Friday authorization and the native
post-expiry refresh test remain separate acceptance requirements. A discovered
tool, HTTP acceptance or caller-reported turn ID does not prove a hosted wake.
See `docs/configuration.md` before enabling either setup or delivery.
