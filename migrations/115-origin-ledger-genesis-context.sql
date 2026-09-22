-- Origin-ledger database context for a genuinely fresh Genesis installation.
--
-- The Housekeeper is created before operator onboarding and owns Genesis Guide
-- SAVE. The original function required a master identity at that point, so a
-- clean brain could not commit its first origin record. This successor derives
-- the first context from the database, company and active Genesis Housekeeper
-- epoch when no operator master exists. Once the ledger has a head, its exact
-- context is carried forward; later onboarding cannot rewrite the chain's
-- database identity.

CREATE OR REPLACE FUNCTION public.ob2_origin_database_context_hash(
  p_company_id text,
  p_signer_valid_from timestamptz,
  p_signer_cert_fingerprint text
) RETURNS bytea
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_database text := current_database();
  v_master text;
  v_anchor_kind text;
  v_anchor_fingerprint text;
  v_signer_count integer;
  v_database_bytes bytea;
  v_company_bytes bytea;
  v_anchor_kind_bytes bytea;
BEGIN
  SELECT master.fingerprint INTO v_master
    FROM public.aimos_master_identity master WHERE master.id = 1;
  IF v_master IS NULL THEN
    v_anchor_kind := 'housekeeper_genesis';
    v_anchor_fingerprint := p_signer_cert_fingerprint;
  ELSIF v_master ~ '^[0-9a-f]{64}$' THEN
    v_anchor_kind := 'operator_master';
    v_anchor_fingerprint := v_master;
  ELSE
    RAISE EXCEPTION 'origin_database_identity_invalid';
  END IF;
  IF p_company_id IS NULL OR p_company_id = ''
     OR p_signer_cert_fingerprint !~ '^[0-9a-f]{64}$'
     OR v_anchor_fingerprint !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'origin_database_identity_invalid';
  END IF;
  SELECT count(*)::integer INTO v_signer_count
    FROM public.agent_identity identity
   WHERE identity.agent_id = 'housekeeper'
     AND identity.valid_from = p_signer_valid_from
     AND identity.revoked_at IS NULL
     AND identity.valid_from <= clock_timestamp()
     AND identity.valid_until > clock_timestamp()
     AND identity.is_system_role IS TRUE
     AND encode(digest(convert_to(identity.cert, 'UTF8'), 'sha256'), 'hex') = p_signer_cert_fingerprint;
  IF v_signer_count <> 1 THEN RAISE EXCEPTION 'origin_signer_epoch_invalid'; END IF;
  v_database_bytes := convert_to(v_database, 'UTF8');
  v_company_bytes := convert_to(p_company_id, 'UTF8');
  v_anchor_kind_bytes := convert_to(v_anchor_kind, 'UTF8');
  RETURN digest(
    convert_to('hom.aimos.database-origin-context/v2', 'UTF8') || decode('00', 'hex')
    || int4send(octet_length(v_database_bytes)) || v_database_bytes
    || int4send(octet_length(v_company_bytes)) || v_company_bytes
    || int4send(octet_length(v_anchor_kind_bytes)) || v_anchor_kind_bytes
    || decode(v_anchor_fingerprint, 'hex')
    || decode(p_signer_cert_fingerprint, 'hex')
    || int8send(trunc(extract(epoch FROM p_signer_valid_from) * 1000)::bigint),
    'sha256'
  );
END
$function$;

CREATE OR REPLACE FUNCTION public.ob2_read_origin_ledger_state(p_company_id text)
RETURNS TABLE(
  prev_ledger_hash bytea,
  database_context_sha256 bytea,
  authority_profile_sha256 bytea,
  signer_agent_id text,
  signer_valid_from timestamptz,
  signer_cert_fingerprint text
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_entry_count integer;
  v_head_count integer;
BEGIN
  IF p_company_id IS NULL OR p_company_id = '' THEN RAISE EXCEPTION 'origin_company_scope_required'; END IF;
  SELECT identity.valid_from,
         encode(digest(convert_to(identity.cert, 'UTF8'), 'sha256'), 'hex')
    INTO signer_valid_from, signer_cert_fingerprint
    FROM public.agent_identity identity
   WHERE identity.agent_id = 'housekeeper' AND identity.revoked_at IS NULL
     AND identity.valid_from <= clock_timestamp() AND identity.valid_until > clock_timestamp()
     AND identity.is_system_role IS TRUE
   ORDER BY identity.valid_from DESC LIMIT 1;
  IF signer_valid_from IS NULL THEN RAISE EXCEPTION 'origin_signer_epoch_invalid'; END IF;
  signer_agent_id := 'housekeeper';
  authority_profile_sha256 := decode('14001dd244e7e3276eb27c145f00abe41ec121908c65a2cf1eef571b922037b3', 'hex');
  SELECT count(*)::integer INTO v_entry_count
    FROM public.aimos_origin_ledger_entries entry
   WHERE entry.company_id = p_company_id;
  SELECT count(*)::integer,
         (array_agg(entry.ledger_hash ORDER BY encode(entry.ledger_hash, 'hex')))[1],
         (array_agg(entry.database_context_sha256 ORDER BY encode(entry.ledger_hash, 'hex')))[1]
    INTO v_head_count, prev_ledger_hash, database_context_sha256
    FROM public.aimos_origin_ledger_entries entry
   WHERE entry.company_id = p_company_id
     AND NOT EXISTS (
       SELECT 1 FROM public.aimos_origin_ledger_entries successor
        WHERE successor.company_id = entry.company_id
          AND successor.prev_ledger_hash = entry.ledger_hash
     );
  IF v_head_count > 1 THEN RAISE EXCEPTION 'origin_ledger_existing_fork'; END IF;
  IF v_head_count = 0 AND v_entry_count > 0 THEN RAISE EXCEPTION 'origin_ledger_existing_cycle'; END IF;
  IF v_head_count = 0 THEN
    database_context_sha256 := public.ob2_origin_database_context_hash(
      p_company_id, signer_valid_from, signer_cert_fingerprint);
  ELSIF database_context_sha256 IS NULL OR octet_length(database_context_sha256) <> 32 THEN
    RAISE EXCEPTION 'origin_database_context_invalid';
  END IF;
  RETURN NEXT;
END
$function$;
