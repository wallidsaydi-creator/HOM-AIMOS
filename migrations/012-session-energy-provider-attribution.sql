-- 012-session-energy-provider-attribution.sql
-- Add provider_id and model columns to session_energy for per-provider energy attribution.
-- Additive migration — existing rows get NULL for new columns, which is acceptable.
-- Aladdin compliance: no data deletion, no row modification of existing data.

CREATE TABLE IF NOT EXISTS session_energy (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id TEXT NOT NULL,
    joules_used DOUBLE PRECISION NOT NULL DEFAULT 0,
    provider_id TEXT,
    model TEXT,
    ts TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_session_energy_session ON session_energy(session_id);
CREATE INDEX IF NOT EXISTS idx_session_energy_provider ON session_energy(provider_id, ts DESC);

-- If the table already exists (from an earlier partial migration), add the columns
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'session_energy') THEN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'session_energy' AND column_name = 'provider_id') THEN
            ALTER TABLE session_energy ADD COLUMN provider_id TEXT;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'session_energy' AND column_name = 'model') THEN
            ALTER TABLE session_energy ADD COLUMN model TEXT;
        END IF;
    END IF;
END
$$;