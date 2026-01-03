// @generated automatically by Diesel CLI.

diesel::table! {
    users (id) {
        id -> Int4,
        uuid -> Uuid,
        username -> Varchar,
        email -> Varchar,
        password_hash -> Varchar,
        first_name -> Nullable<Varchar>,
        last_name -> Nullable<Varchar>,
        phone -> Nullable<Varchar>,
        is_active -> Bool,
        is_staff -> Bool,
        is_superuser -> Bool,
        is_service_account -> Bool,
        mfa_enabled -> Bool,
        mfa_enforced -> Bool,
        mfa_secret -> Nullable<Varchar>,
        preferences -> Jsonb,
        last_login -> Nullable<Timestamptz>,
        last_login_ip -> Nullable<Text>,
        failed_login_attempts -> Int4,
        locked_until -> Nullable<Timestamptz>,
        auth_source -> Varchar,
        external_id -> Nullable<Varchar>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        is_deleted -> Bool,
        deleted_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    vauban_groups (id) {
        id -> Int4,
        uuid -> Uuid,
        name -> Varchar,
        description -> Nullable<Text>,
        source -> Varchar,
        external_id -> Nullable<Varchar>,
        parent_id -> Nullable<Int4>,
        last_synced -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    user_groups (user_id, group_id) {
        user_id -> Int4,
        group_id -> Int4,
    }
}

diesel::table! {
    assets (id) {
        id -> Int4,
        uuid -> Uuid,
        name -> Varchar,
        hostname -> Varchar,
        ip_address -> Nullable<Text>,
        port -> Int4,
        asset_type -> Varchar,
        status -> Varchar,
        group_id -> Nullable<Int4>,
        description -> Nullable<Text>,
        os_type -> Nullable<Varchar>,
        os_version -> Nullable<Varchar>,
        connection_config -> Jsonb,
        default_credential_id -> Nullable<Varchar>,
        require_mfa -> Bool,
        require_justification -> Bool,
        max_session_duration -> Int4,
        last_seen -> Nullable<Timestamptz>,
        created_by_id -> Nullable<Int4>,
        updated_by_id -> Nullable<Int4>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        is_deleted -> Bool,
        deleted_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    asset_groups (id) {
        id -> Int4,
        uuid -> Uuid,
        name -> Varchar,
        slug -> Varchar,
        description -> Nullable<Text>,
        color -> Varchar,
        icon -> Varchar,
        parent_id -> Nullable<Int4>,
        created_by_id -> Nullable<Int4>,
        updated_by_id -> Nullable<Int4>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        is_deleted -> Bool,
        deleted_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    proxy_sessions (id) {
        id -> Int4,
        uuid -> Uuid,
        user_id -> Int4,
        asset_id -> Int4,
        credential_id -> Varchar,
        credential_username -> Varchar,
        session_type -> Varchar,
        status -> Varchar,
        client_ip -> Text,
        client_user_agent -> Nullable<Text>,
        proxy_instance -> Nullable<Varchar>,
        connected_at -> Nullable<Timestamptz>,
        disconnected_at -> Nullable<Timestamptz>,
        justification -> Nullable<Text>,
        is_recorded -> Bool,
        recording_path -> Nullable<Varchar>,
        bytes_sent -> Int8,
        bytes_received -> Int8,
        commands_count -> Int4,
        metadata -> Jsonb,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::joinable!(proxy_sessions -> users (user_id));
diesel::joinable!(proxy_sessions -> assets (asset_id));
diesel::joinable!(assets -> asset_groups (group_id));
diesel::joinable!(user_groups -> users (user_id));
diesel::joinable!(user_groups -> vauban_groups (group_id));

diesel::allow_tables_to_appear_in_same_query!(
    users,
    vauban_groups,
    user_groups,
    assets,
    asset_groups,
    proxy_sessions,
);

