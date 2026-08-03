

























ALTER TABLE aimos_credential_lifecycle
  DROP CONSTRAINT IF EXISTS aimos_credential_lifecycle_event_type_check;

ALTER TABLE aimos_credential_lifecycle
  ADD CONSTRAINT aimos_credential_lifecycle_event_type_check
  CHECK (event_type IN ('STORE','ROTATE','REVOKE','VERIFY','USE'));

-- Visibility: confirm the constraint is updated + the USE event type is allowed.
SELECT 'aimos_credential_lifecycle_event_type_check' AS metric,
       pg_get_constraintdef(oid) AS value
  FROM pg_constraint
 WHERE conrelid = 'aimos_credential_lifecycle'::regclass
   AND conname = 'aimos_credential_lifecycle_event_type_check';