-- ============================================================
-- Owlvex — PostgreSQL 16 schema
-- Run automatically on first container start via initdb.d
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================
-- FRAMEWORKS — STRIDE, OWASP, MITRE, CWE, CleanCode etc.
-- ============================================================
CREATE TABLE frameworks (
    id          UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    code        VARCHAR(50)  NOT NULL UNIQUE,       -- 'STRIDE', 'OWASP'
    name        VARCHAR(200) NOT NULL,
    version     VARCHAR(20)  NOT NULL,              -- 'OWASP-2021'
    description TEXT,
    category    VARCHAR(50),                        -- 'security', 'quality', 'compliance'
    is_active   BOOLEAN      DEFAULT true,
    plan_tier   VARCHAR(20)  DEFAULT 'developer',   -- 'free','developer','team','enterprise'
    created_at  TIMESTAMPTZ  DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  DEFAULT NOW()
);

-- ============================================================
-- RULES — individual rules within each framework
-- ============================================================
CREATE TABLE rules (
    id             UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    framework_id   UUID         NOT NULL REFERENCES frameworks(id) ON DELETE CASCADE,
    code           VARCHAR(50)  NOT NULL,            -- 'OWASP-A03', 'STRIDE-S1'
    title          VARCHAR(200) NOT NULL,
    description    TEXT         NOT NULL,
    severity       VARCHAR(20)  NOT NULL,            -- 'CRITICAL','HIGH','MEDIUM','LOW'
    languages      TEXT[]       DEFAULT '{}',        -- ['python','javascript','java']
    cwe_id         VARCHAR(20),
    prompt_hints   TEXT,                             -- what to tell the AI to look for
    fix_guidance   TEXT,                             -- remediation template
    rule_references JSONB       DEFAULT '[]',
    plan_tier      VARCHAR(20)  DEFAULT 'developer',
    is_active      BOOLEAN      DEFAULT true,
    created_at     TIMESTAMPTZ  DEFAULT NOW()
);

-- ============================================================
-- PROMPT TEMPLATES — our secret sauce / competitive advantage
-- ============================================================
CREATE TABLE prompt_templates (
    id           UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    framework_id UUID         REFERENCES frameworks(id) ON DELETE SET NULL,
    name         VARCHAR(200) NOT NULL,
    description  TEXT,
    language     VARCHAR(50)  DEFAULT 'all',
    template     TEXT         NOT NULL,              -- the actual prompt text
    variables    JSONB        DEFAULT '[]',          -- [{name, description, default}]
    is_baseline  BOOLEAN      DEFAULT false,         -- our shipped defaults
    is_active    BOOLEAN      DEFAULT true,
    version      INT          DEFAULT 1,
    plan_tier    VARCHAR(20)  DEFAULT 'developer',
    created_at   TIMESTAMPTZ  DEFAULT NOW()
);

-- ============================================================
-- LICENCES — one per paying customer / team
-- ============================================================
CREATE TABLE customers (
    id          UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    email       VARCHAR(200) NOT NULL UNIQUE,
    name        VARCHAR(200),
    company     VARCHAR(200),
    source      VARCHAR(50)  DEFAULT 'extension',
    pending_plan VARCHAR(20),
    email_verified_at TIMESTAMPTZ,
    verification_code_hash VARCHAR(64),
    verification_code_expires_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  DEFAULT NOW()
);

CREATE TABLE licences (
    id                      UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    customer_id             UUID         REFERENCES customers(id) ON DELETE SET NULL,
    licence_key_hash        VARCHAR(64)  NOT NULL UNIQUE,  -- SHA256 of key, never raw
    team_name               VARCHAR(200) NOT NULL,
    email                   VARCHAR(200) NOT NULL,
    plan                    VARCHAR(20)  NOT NULL,          -- 'free','developer','team','enterprise'
    seats                   INT          DEFAULT 1,
    seats_used              INT          DEFAULT 0,
    stripe_customer_id      VARCHAR(100),
    stripe_subscription_id  VARCHAR(100),
    features                JSONB        DEFAULT '{}',
    industry_packs          TEXT[]       DEFAULT '{}',
    is_active               BOOLEAN      DEFAULT true,
    expires_at              TIMESTAMPTZ,
    created_at              TIMESTAMPTZ  DEFAULT NOW(),
    updated_at              TIMESTAMPTZ  DEFAULT NOW()
);

-- ============================================================
-- LICENCE SEATS — individual users within a team licence
-- ============================================================
CREATE TABLE licence_seats (
    id          UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    licence_id  UUID         NOT NULL REFERENCES licences(id) ON DELETE CASCADE,
    user_email  VARCHAR(200) NOT NULL,
    user_name   VARCHAR(200),
    is_admin    BOOLEAN      DEFAULT false,
    last_seen   TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  DEFAULT NOW()
);

-- ============================================================
-- TEAM PROMPTS — prompts saved and shared within a team
-- ============================================================
CREATE TABLE team_prompts (
    id              UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    licence_id      UUID         NOT NULL REFERENCES licences(id) ON DELETE CASCADE,
    name            VARCHAR(200) NOT NULL,
    description     TEXT,
    system_prompt   TEXT         NOT NULL,
    frameworks      TEXT[]       DEFAULT '{}',
    model           VARCHAR(100),
    temperature     FLOAT        DEFAULT 0.1,
    is_team_default BOOLEAN      DEFAULT false,
    created_by      VARCHAR(200),
    parent_id       UUID         REFERENCES team_prompts(id),
    created_at      TIMESTAMPTZ  DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  DEFAULT NOW()
);

-- ============================================================
-- SCAN HISTORY — metadata only, NEVER source code
-- ============================================================
CREATE TABLE scan_history (
    id               UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    licence_id       UUID         NOT NULL REFERENCES licences(id),
    user_email       VARCHAR(200),
    file_hash        VARCHAR(64),                    -- SHA256 of code — for dedup/comparison
    file_name        VARCHAR(500),                   -- filename only, no path
    language         VARCHAR(50),
    prompt_id        UUID         REFERENCES team_prompts(id),
    prompt_snapshot  TEXT,                           -- snapshot of exact prompt used
    model            VARCHAR(100),
    provider         VARCHAR(50),                    -- 'azure-foundry','openai','anthropic','ollama'
    frameworks       TEXT[]       DEFAULT '{}',
    score            FLOAT,                          -- 0-10
    finding_count    INT          DEFAULT 0,
    findings_summary JSONB        DEFAULT '{}',      -- {critical:0,high:2,medium:5,low:3}
    token_count      INT,
    duration_ms      INT,
    status           VARCHAR(20)  DEFAULT 'completed',
    created_at       TIMESTAMPTZ  DEFAULT NOW()
);

-- ============================================================
-- COMPARISONS — A vs B scan comparisons
-- ============================================================
CREATE TABLE comparisons (
    id                UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    licence_id        UUID         NOT NULL REFERENCES licences(id),
    scan_a_id         UUID         NOT NULL REFERENCES scan_history(id),
    scan_b_id         UUID         NOT NULL REFERENCES scan_history(id),
    score_change      FLOAT,
    new_findings      INT          DEFAULT 0,
    resolved_findings INT          DEFAULT 0,
    diff_summary      JSONB        DEFAULT '{}',
    created_at        TIMESTAMPTZ  DEFAULT NOW()
);

-- ============================================================
-- USAGE EVENTS — product telemetry for pricing/trial flows
-- ============================================================
CREATE TABLE usage_events (
    id          UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    licence_id  UUID         NOT NULL REFERENCES licences(id) ON DELETE CASCADE,
    user_email  VARCHAR(200),
    event_name  VARCHAR(80)  NOT NULL,
    metadata    JSONB        DEFAULT '{}',
    created_at  TIMESTAMPTZ  DEFAULT NOW()
);

-- ============================================================
-- INDEXES
-- ============================================================
CREATE INDEX idx_rules_framework     ON rules(framework_id);
CREATE INDEX idx_rules_language      ON rules USING GIN(languages);
CREATE INDEX idx_scan_licence        ON scan_history(licence_id);
CREATE INDEX idx_scan_created        ON scan_history(created_at DESC);
CREATE INDEX idx_licence_key_hash    ON licences(licence_key_hash);
CREATE INDEX idx_customers_email     ON customers(email);
CREATE INDEX idx_team_prompts_lic    ON team_prompts(licence_id);
CREATE INDEX idx_licence_seats_lic   ON licence_seats(licence_id);
CREATE INDEX idx_comparisons_licence ON comparisons(licence_id);
CREATE INDEX idx_usage_events_licence ON usage_events(licence_id);
CREATE INDEX idx_usage_events_name ON usage_events(event_name);
