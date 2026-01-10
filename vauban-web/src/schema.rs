// @generated automatically by Diesel CLI.

diesel::table! {
    api_keys (id) {
        id -> Int4,
        uuid -> Uuid,
        user_id -> Int4,
        #[max_length = 100]
        name -> Varchar,
        #[max_length = 8]
        key_prefix -> Varchar,
        #[max_length = 64]
        key_hash -> Varchar,
        scopes -> Jsonb,
        last_used_at -> Nullable<Timestamptz>,
        last_used_ip -> Nullable<Inet>,
        expires_at -> Nullable<Timestamptz>,
        is_active -> Bool,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    asset_groups (id) {
        id -> Int4,
        uuid -> Uuid,
        #[max_length = 100]
        name -> Varchar,
        #[max_length = 100]
        slug -> Varchar,
        description -> Nullable<Text>,
        #[max_length = 7]
        color -> Varchar,
        #[max_length = 50]
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
    assets (id) {
        id -> Int4,
        uuid -> Uuid,
        #[max_length = 100]
        name -> Varchar,
        #[max_length = 255]
        hostname -> Varchar,
        ip_address -> Nullable<Inet>,
        port -> Int4,
        #[max_length = 10]
        asset_type -> Varchar,
        #[max_length = 15]
        status -> Varchar,
        group_id -> Nullable<Int4>,
        description -> Nullable<Text>,
        #[max_length = 50]
        os_type -> Nullable<Varchar>,
        #[max_length = 50]
        os_version -> Nullable<Varchar>,
        connection_config -> Jsonb,
        #[max_length = 36]
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
    auth_sessions (id) {
        id -> Int4,
        uuid -> Uuid,
        user_id -> Int4,
        #[max_length = 64]
        token_hash -> Varchar,
        ip_address -> Inet,
        user_agent -> Nullable<Text>,
        #[max_length = 255]
        device_info -> Nullable<Varchar>,
        last_activity -> Timestamptz,
        expires_at -> Timestamptz,
        is_current -> Bool,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    proxy_sessions (id) {
        id -> Int4,
        uuid -> Uuid,
        user_id -> Int4,
        asset_id -> Int4,
        #[max_length = 36]
        credential_id -> Varchar,
        #[max_length = 100]
        credential_username -> Varchar,
        #[max_length = 10]
        session_type -> Varchar,
        #[max_length = 15]
        status -> Varchar,
        client_ip -> Inet,
        client_user_agent -> Nullable<Text>,
        #[max_length = 100]
        proxy_instance -> Nullable<Varchar>,
        connected_at -> Nullable<Timestamptz>,
        disconnected_at -> Nullable<Timestamptz>,
        justification -> Nullable<Text>,
        is_recorded -> Bool,
        #[max_length = 500]
        recording_path -> Nullable<Varchar>,
        bytes_sent -> Int8,
        bytes_received -> Int8,
        commands_count -> Int4,
        metadata -> Jsonb,
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
    users (id) {
        id -> Int4,
        uuid -> Uuid,
        #[max_length = 150]
        username -> Varchar,
        #[max_length = 255]
        email -> Varchar,
        #[max_length = 255]
        password_hash -> Varchar,
        #[max_length = 150]
        first_name -> Nullable<Varchar>,
        #[max_length = 150]
        last_name -> Nullable<Varchar>,
        #[max_length = 20]
        phone -> Nullable<Varchar>,
        is_active -> Bool,
        is_staff -> Bool,
        is_superuser -> Bool,
        is_service_account -> Bool,
        mfa_enabled -> Bool,
        mfa_enforced -> Bool,
        #[max_length = 255]
        mfa_secret -> Nullable<Varchar>,
        preferences -> Jsonb,
        last_login -> Nullable<Timestamptz>,
        last_login_ip -> Nullable<Inet>,
        failed_login_attempts -> Int4,
        locked_until -> Nullable<Timestamptz>,
        #[max_length = 10]
        auth_source -> Varchar,
        #[max_length = 255]
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
        #[max_length = 100]
        name -> Varchar,
        description -> Nullable<Text>,
        #[max_length = 10]
        source -> Varchar,
        #[max_length = 255]
        external_id -> Nullable<Varchar>,
        parent_id -> Nullable<Int4>,
        last_synced -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::joinable!(api_keys -> users (user_id));
diesel::joinable!(assets -> asset_groups (group_id));
diesel::joinable!(auth_sessions -> users (user_id));
diesel::joinable!(proxy_sessions -> assets (asset_id));
diesel::joinable!(proxy_sessions -> users (user_id));
diesel::joinable!(user_groups -> users (user_id));
diesel::joinable!(user_groups -> vauban_groups (group_id));

diesel::allow_tables_to_appear_in_same_query!(
    api_keys,
    asset_groups,
    assets,
    auth_sessions,
    proxy_sessions,
    user_groups,
    users,
    vauban_groups,
);
