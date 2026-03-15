-- Access rules: link user groups to asset groups with protocol and time constraints.
-- This table is the core of instance-level authorization in Vauban.

CREATE TABLE access_rules (
    id SERIAL PRIMARY KEY,
    uuid UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    user_group_id INTEGER NOT NULL REFERENCES vauban_groups(id) ON DELETE CASCADE,
    asset_group_id INTEGER NOT NULL REFERENCES asset_groups(id) ON DELETE CASCADE,
    allowed_protocols TEXT[] NOT NULL DEFAULT '{ssh,rdp}',
    valid_from TIMESTAMPTZ,
    valid_until TIMESTAMPTZ,
    require_mfa BOOLEAN NOT NULL DEFAULT false,
    require_justification BOOLEAN NOT NULL DEFAULT false,
    max_session_duration INTEGER,
    is_active BOOLEAN NOT NULL DEFAULT true,
    priority INTEGER NOT NULL DEFAULT 0,
    created_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    updated_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_group_id, asset_group_id)
);

CREATE INDEX idx_access_rules_uuid ON access_rules(uuid);
CREATE INDEX idx_access_rules_user_group ON access_rules(user_group_id);
CREATE INDEX idx_access_rules_asset_group ON access_rules(asset_group_id);
CREATE INDEX idx_access_rules_active ON access_rules(is_active) WHERE is_active = true;
