CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    seed TEXT NOT NULL,
    display_name TEXT,
    summary TEXT NOT NULL DEFAULT '',
    confidence NUMERIC(4,3) NOT NULL DEFAULT 0.000,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS identifiers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    confidence NUMERIC(4,3) NOT NULL DEFAULT 0.000,
    source TEXT NOT NULL DEFAULT 'unknown',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (profile_id, kind, value)
);

CREATE TABLE IF NOT EXISTS evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    source_type TEXT NOT NULL,
    source_uri TEXT,
    title TEXT,
    snippet TEXT NOT NULL DEFAULT '',
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    confidence NUMERIC(4,3) NOT NULL DEFAULT 0.000
);

CREATE TABLE IF NOT EXISTS searches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    query TEXT NOT NULL,
    status TEXT NOT NULL,
    result_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    from_profile_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    to_profile_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    relationship_type TEXT NOT NULL,
    confidence NUMERIC(4,3) NOT NULL DEFAULT 0.000,
    source TEXT NOT NULL DEFAULT 'unknown',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (from_profile_id <> to_profile_id)
);

CREATE TABLE IF NOT EXISTS profile_correlation_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    key_type TEXT NOT NULL,
    key_value TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'enrichment',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (profile_id, key_type, key_value)
);

CREATE TABLE IF NOT EXISTS osint_tools (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_path TEXT NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'url',
    url TEXT,
    description TEXT NOT NULL DEFAULT '',
    status TEXT,
    pricing TEXT,
    best_for TEXT,
    input_type TEXT,
    output_type TEXT,
    opsec TEXT,
    opsec_note TEXT,
    local_install BOOLEAN NOT NULL DEFAULT false,
    google_dork BOOLEAN NOT NULL DEFAULT false,
    registration BOOLEAN NOT NULL DEFAULT false,
    edit_url BOOLEAN NOT NULL DEFAULT false,
    api BOOLEAN NOT NULL DEFAULT false,
    invitation_only BOOLEAN NOT NULL DEFAULT false,
    deprecated BOOLEAN NOT NULL DEFAULT false,
    source_name TEXT NOT NULL DEFAULT 'OSINT Framework',
    source_url TEXT NOT NULL DEFAULT 'https://github.com/lockfale/osint-framework',
    source_license TEXT NOT NULL DEFAULT 'MIT',
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_identifiers_value ON identifiers (lower(value));
CREATE INDEX IF NOT EXISTS idx_evidence_profile ON evidence (profile_id);
CREATE INDEX IF NOT EXISTS idx_connections_from ON connections (from_profile_id);
CREATE INDEX IF NOT EXISTS idx_connections_to ON connections (to_profile_id);
CREATE INDEX IF NOT EXISTS idx_connections_pair_type_source
    ON connections (from_profile_id, to_profile_id, relationship_type, source);
CREATE INDEX IF NOT EXISTS idx_profile_correlation_keys_lookup
    ON profile_correlation_keys (key_type, lower(key_value));
CREATE UNIQUE INDEX IF NOT EXISTS idx_osint_tools_unique
    ON osint_tools (framework_path, name, COALESCE(url, ''));
CREATE INDEX IF NOT EXISTS idx_osint_tools_input ON osint_tools (lower(input_type));
CREATE INDEX IF NOT EXISTS idx_osint_tools_name ON osint_tools (lower(name));
CREATE INDEX IF NOT EXISTS idx_osint_tools_opsec ON osint_tools (opsec);
