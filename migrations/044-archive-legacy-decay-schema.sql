-- Preserve historical rows while removing legacy decay mechanisms from the
-- live schema. This is a rename-only migration: no row or column is deleted.

DO $body$
BEGIN
  IF to_regclass('public.aimos_forgetting_curve') IS NOT NULL
     AND to_regclass('public.aimos_archived_learning_curve') IS NULL THEN
    ALTER TABLE public.aimos_forgetting_curve RENAME TO aimos_archived_learning_curve;
    ALTER TABLE public.aimos_archived_learning_curve RENAME COLUMN decay_constant TO legacy_coefficient;
    ALTER TABLE public.aimos_archived_learning_curve RENAME COLUMN forgetting_exponent TO legacy_exponent;
  END IF;

  IF to_regclass('public.aimos_retention_config') IS NOT NULL
     AND to_regclass('public.aimos_archived_retention_config') IS NULL THEN
    ALTER TABLE public.aimos_retention_config RENAME TO aimos_archived_retention_config;
    ALTER TABLE public.aimos_archived_retention_config RENAME COLUMN decay_rate TO legacy_rate;
  END IF;
END
$body$;
