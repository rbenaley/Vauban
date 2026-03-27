-- Initial schema for VAUBAN Web
-- This migration creates all necessary tables

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    uuid UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    username VARCHAR(150) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(150),
    last_name VARCHAR(150),
    phone VARCHAR(20),
    is_active BOOLEAN NOT NULL DEFAULT true,
    is_staff BOOLEAN NOT NULL DEFAULT false,
    is_superuser BOOLEAN NOT NULL DEFAULT false,
    is_service_account BOOLEAN NOT NULL DEFAULT false,
    mfa_enabled BOOLEAN NOT NULL DEFAULT false,
    mfa_enforced BOOLEAN NOT NULL DEFAULT false,
    mfa_secret VARCHAR(255),
    preferences JSONB NOT NULL DEFAULT '{}',
    last_login TIMESTAMPTZ,
    last_login_ip INET,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    auth_source VARCHAR(10) NOT NULL DEFAULT 'local',
    external_id VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_deleted BOOLEAN NOT NULL DEFAULT false,
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_users_uuid ON users(uuid);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_active ON users(is_active) WHERE is_active = true;
CREATE INDEX idx_users_deleted ON users(is_deleted) WHERE is_deleted = false;

-- Vauban Groups table
CREATE TABLE vauban_groups (
    id SERIAL PRIMARY KEY,
    uuid UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    source VARCHAR(10) NOT NULL DEFAULT 'local',
    external_id VARCHAR(255),
    parent_id INTEGER REFERENCES vauban_groups(id) ON DELETE SET NULL,
    last_synced TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vauban_groups_uuid ON vauban_groups(uuid);
CREATE INDEX idx_vauban_groups_name ON vauban_groups(name);

-- User-Group many-to-many
CREATE TABLE user_groups (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES vauban_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

-- Asset Groups table
CREATE TABLE asset_groups (
    id SERIAL PRIMARY KEY,
    uuid UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL UNIQUE,
    slug VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    color VARCHAR(7) NOT NULL DEFAULT '#6366f1',
    icon VARCHAR(50) NOT NULL DEFAULT 'folder',
    parent_id INTEGER REFERENCES asset_groups(id) ON DELETE SET NULL,
    created_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    updated_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_deleted BOOLEAN NOT NULL DEFAULT false,
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_asset_groups_uuid ON asset_groups(uuid);
CREATE INDEX idx_asset_groups_slug ON asset_groups(slug);

-- Assets table
CREATE TABLE assets (
    id SERIAL PRIMARY KEY,
    uuid UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    ip_address INET,
    port INTEGER NOT NULL DEFAULT 22,
    asset_type VARCHAR(10) NOT NULL DEFAULT 'ssh',
    status VARCHAR(15) NOT NULL DEFAULT 'unknown',
    group_id INTEGER REFERENCES asset_groups(id) ON DELETE SET NULL,
    description TEXT,
    os_type VARCHAR(50),
    os_version VARCHAR(50),
    connection_config JSONB NOT NULL DEFAULT '{}',
    default_credential_id VARCHAR(36),
    require_mfa BOOLEAN NOT NULL DEFAULT false,
    require_justification BOOLEAN NOT NULL DEFAULT false,
    max_session_duration INTEGER NOT NULL DEFAULT 28800,
    last_seen TIMESTAMPTZ,
    created_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    updated_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_deleted BOOLEAN NOT NULL DEFAULT false,
    deleted_at TIMESTAMPTZ,
    UNIQUE(hostname, port)
);

CREATE INDEX idx_assets_uuid ON assets(uuid);
CREATE INDEX idx_assets_hostname ON assets(hostname);
CREATE INDEX idx_assets_type ON assets(asset_type);
CREATE INDEX idx_assets_status ON assets(status);
CREATE INDEX idx_assets_deleted ON assets(is_deleted) WHERE is_deleted = false;

-- Proxy Sessions table
CREATE TABLE proxy_sessions (
    id SERIAL PRIMARY KEY,
    uuid UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    credential_id VARCHAR(36) NOT NULL,
    credential_username VARCHAR(100) NOT NULL,
    session_type VARCHAR(10) NOT NULL,
    status VARCHAR(15) NOT NULL DEFAULT 'pending',
    client_ip INET NOT NULL,
    client_user_agent TEXT,
    proxy_instance VARCHAR(100),
    connected_at TIMESTAMPTZ,
    disconnected_at TIMESTAMPTZ,
    justification TEXT,
    is_recorded BOOLEAN NOT NULL DEFAULT true,
    recording_path VARCHAR(500),
    bytes_sent BIGINT NOT NULL DEFAULT 0,
    bytes_received BIGINT NOT NULL DEFAULT 0,
    commands_count INTEGER NOT NULL DEFAULT 0,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_proxy_sessions_uuid ON proxy_sessions(uuid);
CREATE INDEX idx_proxy_sessions_user ON proxy_sessions(user_id, created_at DESC);
CREATE INDEX idx_proxy_sessions_asset ON proxy_sessions(asset_id, created_at DESC);
CREATE INDEX idx_proxy_sessions_status ON proxy_sessions(status, created_at DESC);

