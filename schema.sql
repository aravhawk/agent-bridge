-- Agent Bridge v1.0.0 schema. Apply once to a NEW, empty, dedicated database.
-- Preparation only; this source does not migrate or mutate a live database.
-- Existing applications and databases are outside this scope.
-- A single locked aggregate provides atomic message/outbox/receipt transitions
-- for this low-volume single-owner bridge. This is not a high-throughput design.
CREATE TABLE bridge_runtime_v1 (
  id integer PRIMARY KEY CHECK (id=1),
  revision bigint NOT NULL DEFAULT 0,
  document jsonb NOT NULL CHECK (jsonb_typeof(document)='object' AND document->>'version'='1'),
  CHECK (octet_length(document::text) <= 4194304)
);
INSERT INTO bridge_runtime_v1 (id, document) VALUES
  (1, '{"version":1,"messages":{},"subscriptions":{},"jobs":{},"receipts":{}}');
-- PostgresStore SELECTs this row FOR UPDATE and commits all transitions at once.
-- Callback URLs and signing secrets are AES-256-GCM ciphertext with subscription
-- ID as AAD. Do not delete persistent subscription state at end of tests.
-- No database service role should be shared with another project.
