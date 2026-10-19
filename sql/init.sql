-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:Meta
-- SPDX-License-Identifier: Apache-2.0

-- Hotel8:Meta - Metasearch connector tables.
CREATE SCHEMA IF NOT EXISTS meta;
DO $$ BEGIN
    CREATE TYPE meta.channel_type AS ENUM ('GOOGLE', 'TRIVAGO', 'KAYAK', 'SKYSCANNER', 'TRIPADVISOR', 'BING');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS meta.channels (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    property_id  UUID NOT NULL,
    env_id       UUID NOT NULL,
    channel_code TEXT NOT NULL,
    channel_name TEXT NOT NULL,
    channel_type meta.channel_type NOT NULL DEFAULT 'GOOGLE',
    is_active    BOOLEAN NOT NULL DEFAULT true,
    api_key_ref  TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_meta_channels_property ON meta.channels (property_id);
CREATE INDEX IF NOT EXISTS idx_meta_channels_env ON meta.channels (env_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_meta_channels_code ON meta.channels (property_id, channel_code);

CREATE TABLE IF NOT EXISTS meta.rate_ads (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    channel_id    UUID NOT NULL REFERENCES meta.channels(id),
    property_id   UUID NOT NULL,
    room_type_code TEXT NOT NULL,
    rate_plan_code TEXT NOT NULL,
    date          DATE NOT NULL,
    rate_amount   NUMERIC(12,2) NOT NULL DEFAULT 0,
    currency_code TEXT NOT NULL DEFAULT 'USD',
    available     BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_meta_ra_channel ON meta.rate_ads (channel_id);
CREATE INDEX IF NOT EXISTS idx_meta_ra_dates ON meta.rate_ads (date);

CREATE TABLE IF NOT EXISTS meta.clicks (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    channel_id    UUID NOT NULL REFERENCES meta.channels(id),
    property_id   UUID NOT NULL,
    env_id        UUID NOT NULL,
    click_date    TIMESTAMPTZ NOT NULL DEFAULT now(),
    search_date    DATE,
    referrer_url   TEXT,
    cost_per_click NUMERIC(12,4) NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_meta_clicks_channel ON meta.clicks (channel_id);
CREATE INDEX IF NOT EXISTS idx_meta_clicks_property ON meta.clicks (property_id);

ALTER TABLE meta.channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE meta.channels FORCE ROW LEVEL SECURITY;
ALTER TABLE meta.rate_ads ENABLE ROW LEVEL SECURITY;
ALTER TABLE meta.rate_ads FORCE ROW LEVEL SECURITY;
ALTER TABLE meta.clicks ENABLE ROW LEVEL SECURITY;
ALTER TABLE meta.clicks FORCE ROW LEVEL SECURITY;
-- env_id is the sole tenant key (architecture-principles.md §4.3).
DROP POLICY IF EXISTS meta_channels_rls ON meta.channels;
CREATE POLICY meta_channels_rls ON meta.channels USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS meta_ra_rls ON meta.rate_ads;
CREATE POLICY meta_ra_rls ON meta.rate_ads USING (channel_id IN (SELECT id FROM meta.channels));
DROP POLICY IF EXISTS meta_clicks_rls ON meta.clicks;
CREATE POLICY meta_clicks_rls ON meta.clicks USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
-- ──────────────────────────────────────────────────────────────────────────
-- Local outbox (DBX, architecture-principles §6.7) - producer path:
-- rows are appended in the SAME transaction as the domain change; the
-- shell's post-commit relay pushes them to Bus POST /v1/produce
-- (M2M sentin8:bus:produce, idempotency_key = row id).
-- Generated from sentin8_outbox::outbox_table_sql("meta").
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS meta.outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,
    stream_family   TEXT NOT NULL,
    payload         JSONB NOT NULL,
    publisher_id_token  TEXT,
    publisher_subject   TEXT,
    relayed         BOOLEAN NOT NULL DEFAULT false,
    relayed_at      TIMESTAMPTZ,
    relay_attempts  INT NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_outbox_unrelayed
    ON meta.outbox (created_at) WHERE relayed = false;
ALTER TABLE meta.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE meta.outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS outbox_select ON meta.outbox;
CREATE POLICY outbox_select ON meta.outbox FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_insert ON meta.outbox;
CREATE POLICY outbox_insert ON meta.outbox FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_update ON meta.outbox;
CREATE POLICY outbox_update ON meta.outbox FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
CREATE OR REPLACE FUNCTION meta.meta_notify_outbox() RETURNS TRIGGER
    LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM pg_notify('meta_outbox_changed', '');
    RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS outbox_notify_trigger ON meta.outbox;
CREATE TRIGGER outbox_notify_trigger
    AFTER INSERT ON meta.outbox
    FOR EACH ROW
    EXECUTE FUNCTION meta.meta_notify_outbox();

-- ──────────────────────────────────────────────────────────────────────────
-- Local audit journal (architecture-principles §6.8): same-transaction
-- journal rows; the shell's post-commit pusher ships them to Sys
-- POST /v1/audit (M2M sentin8:sys:audit:write). A Sys outage only delays
-- delivery - rows persist until pushed.
-- Generated from sentin8_audit::audit_journal_sql("meta").
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS meta.audit_journal (
    id              UUID PRIMARY KEY,
    env_id          UUID NOT NULL,
    action          TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id    TEXT,
    actor_user_id   TEXT,
    actor_subject_type TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    correlation_id  TEXT,
    before_state    JSONB,
    after_state     JSONB,
    details         JSONB,
    pushed          BOOLEAN NOT NULL DEFAULT false,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_meta_audit_journal_unpushed
    ON meta.audit_journal (created_at) WHERE pushed = false;
ALTER TABLE meta.audit_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE meta.audit_journal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_journal_dml ON meta.audit_journal;
CREATE POLICY audit_journal_dml ON meta.audit_journal
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

-- ──────────────────────────────────────────────────────────────────────────
-- Per-service role grants + search_path (§4.3e / VDC §VDC.3):
-- hotel8_{leaf}_service connects via PostgreSQL 18 OAuth (scope→role map in
-- hotel8.sys.pg_oauth_scope_map). search_path puts the service's OWN schema
-- FIRST (outbox/audit_journal resolution for the shell's relay + journal
-- pusher; unqualified domain tables resolve here), then public (RLS helpers).
-- `sentin8-cli vertical enroll`'s never-clobber block preserves this role-level setting.
-- ──────────────────────────────────────────────────────────────────────────
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hotel8_meta_service') THEN
        ALTER ROLE hotel8_meta_service SET search_path = meta, public;
        GRANT USAGE ON SCHEMA meta TO hotel8_meta_service;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA meta TO hotel8_meta_service;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA meta TO hotel8_meta_service;
    END IF;
END $$;


-- ═════════════════════════════════════════════════════════════════════════════
-- From migrations: extended
-- ═══════════════════════════════════════════════════════════════════════════
-- Migration 34: Hotel8:Meta extended for remaining H4 stories
-- H4.2.5: Property-to-channel configuration (hotel ID, rate multiplier, landing page)
-- H4.3.4: Rate accuracy verification
-- H4.4.2: UTM parameter generation

CREATE SCHEMA IF NOT EXISTS meta;
CREATE TABLE IF NOT EXISTS meta.channel_configs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    channel_id      UUID NOT NULL REFERENCES meta.channels(id),
    property_id     UUID NOT NULL,
    hotel_id        TEXT,
    rate_multiplier NUMERIC(5,2) NOT NULL DEFAULT 1.0,
    landing_page_url TEXT,
    utm_source      TEXT,
    utm_campaign    TEXT,
    is_enabled      BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_meta_cc_channel_prop ON meta.channel_configs (channel_id, property_id);
CREATE INDEX IF NOT EXISTS idx_meta_cc_property ON meta.channel_configs (property_id);

CREATE TABLE IF NOT EXISTS meta.sync_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    channel_id      UUID NOT NULL REFERENCES meta.channels(id),
    property_id     UUID,
    sync_type       TEXT NOT NULL DEFAULT 'ARI',
    records_pushed  INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'SYNCED',
    error_message   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_meta_sl_channel ON meta.sync_log (channel_id);

ALTER TABLE meta.channel_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE meta.channel_configs FORCE ROW LEVEL SECURITY;
ALTER TABLE meta.sync_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE meta.sync_log FORCE ROW LEVEL SECURITY;
CREATE POLICY meta_cc_rls ON meta.channel_configs USING (channel_id IN (SELECT id FROM meta.channels));
CREATE POLICY meta_sl_rls ON meta.sync_log USING (channel_id IN (SELECT id FROM meta.channels));
-- ── H12.9.B5: channel credential secrets (envelope-encrypted) ──
-- The plaintext api_key never lands in a table; only the sentin8-crypto
-- envelope (AES-256-GCM, platform master key) is persisted here. The
-- channel row references it via meta_channels.api_key_ref (store-by-ref).
CREATE TABLE IF NOT EXISTS meta.channel_secrets (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id           UUID NOT NULL,
    channel_id       UUID NOT NULL REFERENCES meta.channels(id),
    api_key_envelope TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, channel_id)
);
ALTER TABLE meta.channel_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE meta.channel_secrets FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
    CREATE POLICY meta_secrets_rls ON meta.channel_secrets
        USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
        WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
