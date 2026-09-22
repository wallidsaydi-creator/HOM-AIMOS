-- AUD-021: indexed heads in the existing signed event ledger. No memory-row
-- mutation, new ledger, runtime privilege, or historical data rewrite.
CREATE INDEX IF NOT EXISTS aimos_credit_target_head ON public.aimos_events
  (company_id,key,signer_valid_from DESC,ledger_seq DESC)
  WHERE operation='memory_credit_projection' AND ledger_version=1 AND signer_agent_id='housekeeper';
CREATE INDEX IF NOT EXISTS aimos_credit_actor_head ON public.aimos_events
  (company_id,(metadata#>>'{visibility,subject_agent_id}'),signer_valid_from DESC,ledger_seq DESC)
  WHERE operation='memory_credit_projection' AND ledger_version=1 AND signer_agent_id='housekeeper';
CREATE INDEX IF NOT EXISTS aimos_credit_feedback_queue ON public.aimos_events
  (company_id,signer_valid_from,ledger_seq)
  WHERE operation='recall_calibration_observation_batch' AND ledger_version=1 AND signer_agent_id='housekeeper';
CREATE INDEX IF NOT EXISTS aimos_credit_processed_head ON public.aimos_events
  (company_id,signer_valid_from DESC,ledger_seq DESC)
  WHERE operation='memory_credit_observation_processed' AND ledger_version=1
    AND signer_agent_id='housekeeper' AND authority_kind='housekeeper_autonomous';
CREATE INDEX IF NOT EXISTS aimos_credit_feedback_identity ON public.aimos_events
  USING gin (metadata jsonb_path_ops)
  WHERE operation='recall_calibration_observation_batch' AND ledger_version=1 AND signer_agent_id='housekeeper';
