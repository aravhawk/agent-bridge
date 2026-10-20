-- Executed only in the approved new Neon database through the Vercel SQL UI.
-- All attempted modifications are rolled back by nested exception blocks.
DO $rnverify$
DECLARE original_revision bigint; current_revision bigint;
BEGIN
  SELECT revision INTO STRICT original_revision FROM bridge_runtime_v1 WHERE id=1 FOR UPDATE;
  BEGIN
    UPDATE bridge_runtime_v1 SET revision=revision+1 WHERE id=1;
    RAISE EXCEPTION USING ERRCODE='P1001', MESSAGE='intentional rollback';
  EXCEPTION WHEN SQLSTATE 'P1001' THEN NULL;
  END;
  SELECT revision INTO STRICT current_revision FROM bridge_runtime_v1 WHERE id=1;
  IF current_revision <> original_revision THEN RAISE EXCEPTION 'rollback verification failed'; END IF;
  BEGIN
    INSERT INTO bridge_runtime_v1(id,document) VALUES (2, '{"version":1}'::jsonb);
    RAISE EXCEPTION 'single-row constraint failed';
  EXCEPTION WHEN check_violation THEN NULL;
  END;
  BEGIN
    UPDATE bridge_runtime_v1 SET document='{"version":2}'::jsonb WHERE id=1;
    RAISE EXCEPTION 'version constraint failed';
  EXCEPTION WHEN check_violation THEN NULL;
  END;
END
$rnverify$;
