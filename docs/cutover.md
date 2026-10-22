# Jarvis Friday Bridge v1.0.0 cutover and action bundle

> Historical migration plan. The v1 project and bindings now exist, and main
> deploys to jarvis-friday-bridge in Arav's Projects. The pending-creation and
> branch-routing statements below describe the original cutover, not current
> instructions to create credentials, databases, projects or subscriptions.
> Reuse the existing production resources. Delivery remains off; deployment is
> not evidence of a completed native integration. See architecture.md.

This document records proposed targets and staged work, not completed grants.
The immutable review commit and independent review must precede deployment and
activation. Publish the v1 review branch only: the legacy project tracks main,
so pushing this migration to main now would overwrite the disabled rollback.

## Fixed inventory and DNS handoff

| Purpose | Exact target |
|---|---|
| Private source | aravhawk/jarvis-friday-bridge |
| New project | jarvis-friday-bridge / prj_rTBPrIoODxpC1A6sS2OQtlvc7cqE |
| Allowed team | Arav's Projects / team_rCVvKJ5rUgNP0LOPEwzfyl0z |
| Canonical origin | https://jarvis-friday-bridge.aravhawk.com |
| New queue / SQL table | jarvis-friday-bridge-v1 / bridge_runtime_v1 |
| Disabled rollback project | rn-jarvis-friday-discovery-20261018 / prj_U4y7PBcoZN3cI2bE3NLE2GZGBFIG |
| Rollback source | fac3baf1ab0be6d70609b3520c97801fc734361b |

The new isolated project and domain association exist; application deployment,
new credentials and grants do not. Arav alone handles Cloudflare login and DNS.
The actual new-project record returned by Vercel is CNAME
`jarvis-friday-bridge` → `ad0e95eae8a3a32b.vercel-dns-017.com`, DNS only, TTL Auto.
No ownership TXT challenge or conflicting record was returned. Do not reuse the
old project's CNAME, change nameservers or touch apex/www/MX/other records.
Check actual propagation, Vercel domain status and HTTPS after Arav's edit.

## Concrete auth and Secret action-time bundle

Present these targets together immediately before creating new auth access.
Replace pending values with actual provider/native metadata before grant steps;
do not treat an open-ended approval as permission for unknown replacements.

1. Create a clean Clerk production realm named **Jarvis Friday Bridge**, using
   base domain `jarvis-friday-bridge.aravhawk.com`, provider-hosted consent and
   only the necessary existing-user sign-in strategy. A production realm creates
   provider credentials; do not create it prematurely. Never reveal/copy its
   backend keys into this service. The old development realm remains rollback.
   Record the exact resulting issuer/public metadata and required auth DNS
   records from the real Domains UI. Arav edits those DNS records himself.
   Provider DNS values are unavailable before creation and must not be guessed.
   When offered, select a subdomain-scoped **Secondary application**. A Primary
   application may produce `clerk.aravhawk.com`, which v1 deliberately rejects.
   Verify that the ACTUAL issuer is beneath `jarvis-friday-bridge.aravhawk.com`
   before creating native grants. If the required setup is unavailable, stop;
   do not weaken the issuer constraint or assume a different hostname will work.
2. Create two provided PUBLIC OAuth clients with required S256 PKCE, no client
   Secret/token-endpoint authentication, and JWT exact-resource audiences.
   Jarvis audience is the canonical origin + `/bridge/jarvis/mcp`, scopes
   `bridge:send:friday bridge:ack:jarvis offline_access`; Friday audience uses
   `/bridge/friday/mcp`, scopes `bridge:send:jarvis bridge:ack:friday offline_access`.
   Recheck actual native callbacks against the observed ChatGPT and Cursor
   callback URLs in configuration.md. Save only exact callback allowlists.
   No device grant, dynamic registration, OIDC identity scope or admin API key.
   Show actual public client IDs/issuer before authorizing native grants.
3. Provision a NEW isolated Neon database named **jarvis-friday-bridge**, using
   the scoped marketplace quote **Free / free_v3**, iad1, `auth=false`,
   `realtime=false`. Quote requires no payment method. Attach only Production of
   the NEW project, not Preview or another project. Recheck unchanged free quote
   at action time; stop if payment, legal terms or broader access is introduced.
   Provision DATABASE_URL natively as a sensitive Secret and apply schema.sql
   only to the new empty database. Never pull/display the credential.
4. Bind fresh sensitive Production values on the new project only:
   BRIDGE_SUBSCRIPTION_STORAGE_KEY (fresh32-byte encryption key),
   BRIDGE_ALLOWED_SUBJECT_SHA256 (the real NEW production user's digest), and
   FRIDAY_WEBHOOK_URL/FRIDAY_WEBHOOK_KEY (the dedicated NEW native receiver).
   Private transfer must name source and destination and never print values.
   Do not copy/decrypt old credentials or reuse the old subject, callback or
   webhook. A new webhook/key binding is a separate concrete access action.
5. Configure actual public issuer with all gates false. Connect both actual
   native clients and invoke authenticated bridge_health under their respective
   audiences/pins/scopes. Bootstrap exposes health only. Successful health proves
   at least one appropriate directional scope, not both send AND ACK scopes.
   Independently verify both required directional scopes on each actual client's
   grant/token before attestation, without exposing tokens/claims. If the native
   flow cannot supply that proof, leave the contract unattested. Prove actual JWT
   issuer and audience compatibility without logging tokens/claims. Only then
   attest BRIDGE_OAUTH_CONTRACT_VERIFIED=true and refresh those same apps' tools.
6. Create one final v1 native Jarvis subscription/receiver automation and one
   dedicated Friday receiver **jarvis-friday-bridge-inbox** under the policies in
   inbox-policy.md. Confirm exact callback binding, webhook contract and native
   finite lease renewal. Enable subscription setup separately; keep delivery
   false. Changed realm/native targets need the concrete access approval.
7. After both policies and bindings are independently verified, attest
   BRIDGE_RECEIVER_POLICY=inbox-v1 and FRIDAY_WEBHOOK_CONTRACT_VERIFIED=true.
   Then enable delivery under the approved final targets. Reserve NEW message
   IDs and run one native message+receipt+ACK in each direction. Prove actual
   native wake, scoped read, claim, atomic completion and quiet ACK; never reuse
   old synthetic windows/IDs or send while handlers are unverified.

## Provider costs and unresolved eligibility

Clerk's public pricing lists Hobby as free with custom domains, unlimited apps
and50,000 monthly retained users/app. Pro is$25/month or$20/month billed annually.
This does not establish production OAuth-provider application eligibility or a
required upgrade; inspect the actual product gate/quote before any purchase.
No plan purchase or new credential has been performed during preparation.

Neon's scoped native quote is Free/free_v3, no payment method,1GB/project and
100CU-hours/project. Existing integration configuration
`icfg_l6e7BP0Ypy0F523aXQYgbWrN` is shared installation metadata, not evidence that
any old database is exclusive to the bridge. Do not delete that installation.

Sources: [Clerk production setup](https://clerk.com/docs/guides/development/deployment/production),
[Clerk domain changes](https://clerk.com/docs/guides/development/deployment/changing-domains),
[Clerk pricing](https://clerk.com/pricing).

## Final migration and cleanup gates

Before deploying, verify review approval for the exact immutable diff. Link and
make the first CLOSED deployment only on the NEW project with an explicit
team/project check. After that deployment and canonical DNS/TLS readiness, run
the credential-free canonical HTTP boundary checks. Do not claim HTTP checks
against an undeployed canonical service. Repeat with actual public issuer/auth
flags after their setup, before grants/activation. Default aliases reject MCP.
No environment dump, old-project redeploy or main-branch overwrite is needed.

After successful final native two-way verification, inventory every obsolete
bridge-owned connection, OAuth client/realm, automation, routine, deployment,
database and DNS record. Show exact IDs, dependency checks and recoverability
for confirmation before irreversible deletion. A reused v1 repository/project,
shared integration or unrelated email/portfolio/T3 resource is never obsolete.
Do not delete old rollback evidence or resources before verified cutover and
that concrete deletion confirmation. No legacy activation or test send.
