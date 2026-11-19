-- PREPARATION ONLY. No default row: operator must explicitly supply the unique
-- source identity, epoch UUID and fingerprint of the EXISTING AES storage key.
-- This does not alter the bridge document. Every deployed writer must first
-- use FencedPostgresStore; retire/drain old deployments before freeze.
CREATE TABLE bridge_authority (
  id integer PRIMARY KEY CHECK(id=1),
  identity text NOT NULL,
  mode text NOT NULL CHECK(mode IN ('active','exported','frozen')),
  epoch text NOT NULL,
  key_id text NOT NULL,
  handoff text,
  export_target text,
  import_checksum text
);

-- Same document->authority lock order as both stores. Legacy SELECT FOR UPDATE
-- writers cannot bypass this trigger when they later issue their ordinary UPDATE.
CREATE FUNCTION bridge_writer_fence() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE current_mode text;
BEGIN
  SELECT mode INTO current_mode FROM bridge_authority WHERE id=1 FOR UPDATE;
  IF current_mode IS DISTINCT FROM 'active' THEN
    RAISE EXCEPTION 'bridge_writer_frozen' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER bridge_writer_fence BEFORE UPDATE ON bridge_runtime_v1
FOR EACH ROW EXECUTE FUNCTION bridge_writer_fence();
