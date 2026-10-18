-- Applied through the native Vercel SQL editor on 2026-10-18 to the approved
-- NEW isolated Neon database rn-jarvis-friday-test-20261018 (neondb).
-- Verified one empty version-1 row, revision 0; native read-only mode restored.
-- Existing applications and databases are outside this scope.
-- A single locked aggregate provides atomic message/outbox/receipt transitions
-- for this low-volume synthetic test. This is not a high-throughput design.
CREATE TABLE rn_bridge_runtime (
  id integer PRIMARY KEY CHECK (id=1),
  revision bigint NOT NULL DEFAULT 0,
  document jsonb NOT NULL CHECK (jsonb_typeof(document)='object' AND document->>'version'='1'),
  CHECK (octet_length(document::text) <= 4194304)
);
INSERT INTO rn_bridge_runtime (id, document) VALUES
  (1, '{"version":1,"messages":{},"subscriptions":{},"jobs":{},"receipts":{}}');
-- PostgresStore SELECTs this row FOR UPDATE and commits all transitions at once.
-- Callback URLs and signing secrets are AES-256-GCM ciphertext with subscription
-- ID as AAD. Do not delete persistent subscription state at end of tests.
-- No database service role should be shared with another project.
