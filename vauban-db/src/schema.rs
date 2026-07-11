// @generated automatically by Diesel CLI.

diesel::table! {
    access_rules (id) {
        id -> Int4,
        uuid -> Uuid,
        #[max_length = 100]
        name -> Varchar,
        description -> Nullable<Text>,
        user_group_id -> Int4,
        asset_group_id -> Int4,
        allowed_protocols -> Array<Nullable<Text>>,
        valid_from -> Nullable<Timestamptz>,
        valid_until -> Nullable<Timestamptz>,
        require_mfa -> Bool,
        require_approval -> Bool,
        max_session_duration -> Nullable<Int4>,
        is_active -> Bool,
        priority -> Int4,
        created_by_id -> Nullable<Int4>,
        updated_by_id -> Nullable<Int4>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

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
    approval_audit_log (id) {
        id -> Int8,
        session_uuid -> Uuid,
        #[max_length = 16]
        decision -> Varchar,
        actor_user_id -> Nullable<Int4>,
        #[max_length = 150]
        actor_username -> Varchar,
        requester_user_id -> Nullable<Int4>,
        #[max_length = 150]
        requester_username -> Varchar,
        asset_uuid -> Uuid,
        #[max_length = 200]
        asset_name -> Varchar,
        #[max_length = 10]
        protocol -> Nullable<Varchar>,
        duration_override_seconds -> Nullable<Int4>,
        decision_reason -> Nullable<Text>,
        decision_ip -> Nullable<Inet>,
        decision_user_agent -> Nullable<Text>,
        #[max_length = 64]
        request_id -> Nullable<Varchar>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    asset_asset_groups (asset_id, asset_group_id) {
        asset_id -> Int4,
        asset_group_id -> Int4,
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
        #[max_length = 16]
        kind -> Varchar,
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
        port -> Int4,
        #[max_length = 20]
        asset_type -> Varchar,
        #[max_length = 15]
        status -> Varchar,
        description -> Nullable<Text>,
        connection_config -> Jsonb,
        created_by_id -> Nullable<Int4>,
        updated_by_id -> Nullable<Int4>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        is_deleted -> Bool,
        deleted_at -> Nullable<Timestamptz>,
        #[max_length = 100]
        connection_username -> Varchar,
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
        device_info -> Varchar,
        last_activity -> Timestamptz,
        expires_at -> Timestamptz,
        is_current -> Bool,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    email_outbox (id) {
        id -> Int8,
        event_id -> Uuid,
        #[max_length = 64]
        event_kind -> Varchar,
        #[max_length = 320]
        recipient -> Varchar,
        #[max_length = 255]
        recipient_name -> Varchar,
        #[max_length = 200]
        subject -> Varchar,
        body_text -> Text,
        body_html -> Nullable<Text>,
        #[max_length = 16]
        status -> Varchar,
        attempts -> Int4,
        max_attempts -> Int4,
        next_retry_at -> Nullable<Timestamptz>,
        last_error -> Nullable<Text>,
        created_at -> Timestamptz,
        sent_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    ews (id) {
        id -> Int8,
        uuid -> Uuid,
        request_uuid -> Uuid,
        user_id -> Int4,
        #[max_length = 128]
        name -> Varchar,
        public_key -> Text,
        #[max_length = 64]
        public_key_fingerprint -> Varchar,
        #[max_length = 40]
        key_algo -> Varchar,
        disabled_by_id -> Nullable<Int4>,
        disabled_at -> Nullable<Timestamptz>,
        offboarded_by_id -> Nullable<Int4>,
        offboarded_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    ews_audit_log (id) {
        id -> Int8,
        ews_uuid -> Nullable<Uuid>,
        request_uuid -> Nullable<Uuid>,
        #[max_length = 20]
        event -> Varchar,
        actor_user_id -> Nullable<Int4>,
        #[max_length = 150]
        actor_username -> Varchar,
        target_user_id -> Nullable<Int4>,
        #[max_length = 150]
        target_username -> Varchar,
        #[max_length = 128]
        ews_name -> Varchar,
        #[max_length = 64]
        public_key_fingerprint -> Varchar,
        decision_reason -> Nullable<Text>,
        actor_ip -> Nullable<Inet>,
        #[max_length = 64]
        request_id -> Nullable<Varchar>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    ews_onboarding_requests (id) {
        id -> Int8,
        uuid -> Uuid,
        user_id -> Int4,
        #[max_length = 128]
        name -> Varchar,
        public_key -> Text,
        #[max_length = 64]
        public_key_fingerprint -> Varchar,
        #[max_length = 40]
        key_algo -> Varchar,
        #[max_length = 250]
        justification -> Varchar,
        #[max_length = 10]
        status -> Varchar,
        decision_reason -> Nullable<Text>,
        decided_by_id -> Nullable<Int4>,
        decided_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
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
        #[max_length = 20]
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
        approved_by_id -> Nullable<Int4>,
        approved_at -> Nullable<Timestamptz>,
        max_session_duration -> Nullable<Int4>,
        expires_at -> Nullable<Timestamptz>,
        rejected_by_id -> Nullable<Int4>,
        rejected_at -> Nullable<Timestamptz>,
        decision_reason -> Nullable<Text>,
        #[max_length = 64]
        recording_blake3 -> Nullable<Varchar>,
        recording_size_bytes -> Nullable<Int8>,
        recording_duration_ms -> Nullable<Int8>,
        recording_event_count -> Nullable<Int4>,
        #[max_length = 32]
        recording_format -> Nullable<Varchar>,
        recording_width -> Nullable<Int2>,
        recording_height -> Nullable<Int2>,
        recording_segment_count -> Nullable<Int4>,
        #[max_length = 64]
        recording_codec -> Nullable<Varchar>,
        recording_finalized_at -> Nullable<Timestamptz>,
        #[max_length = 20]
        industrial_protocol -> Nullable<Varchar>,
        ews_uuid -> Nullable<Uuid>,
        #[max_length = 255]
        tunnel_target_addr -> Nullable<Varchar>,
        revoked_by_id -> Nullable<Int4>,
        revoked_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    secret_access_rules (id) {
        id -> Int4,
        uuid -> Uuid,
        #[max_length = 100]
        name -> Varchar,
        description -> Nullable<Text>,
        user_group_id -> Int4,
        secret_group_id -> Int4,
        valid_from -> Nullable<Timestamptz>,
        valid_until -> Nullable<Timestamptz>,
        is_active -> Bool,
        priority -> Int4,
        created_by_id -> Nullable<Int4>,
        updated_by_id -> Nullable<Int4>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    secret_groups (id) {
        id -> Int4,
        uuid -> Uuid,
        #[max_length = 100]
        name -> Varchar,
        #[max_length = 100]
        slug -> Varchar,
        description -> Nullable<Text>,
        #[max_length = 16]
        kind -> Varchar,
        created_by_id -> Nullable<Int4>,
        updated_by_id -> Nullable<Int4>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    secret_secret_groups (secret_id, secret_group_id) {
        secret_id -> Int4,
        secret_group_id -> Int4,
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
        last_totp_used_window -> Nullable<Int8>,
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

diesel::table! {
    vault_secrets (id) {
        id -> Int4,
        uuid -> Uuid,
        #[max_length = 255]
        name -> Varchar,
        description -> Nullable<Text>,
        ciphertext -> Text,
        version -> Int4,
        is_active -> Bool,
        created_by_id -> Nullable<Int4>,
        updated_by_id -> Nullable<Int4>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::joinable!(access_rules -> asset_groups (asset_group_id));
diesel::joinable!(access_rules -> vauban_groups (user_group_id));
diesel::joinable!(api_keys -> users (user_id));
diesel::joinable!(asset_asset_groups -> asset_groups (asset_group_id));
diesel::joinable!(asset_asset_groups -> assets (asset_id));
diesel::joinable!(auth_sessions -> users (user_id));
diesel::joinable!(proxy_sessions -> assets (asset_id));
diesel::joinable!(secret_access_rules -> secret_groups (secret_group_id));
diesel::joinable!(secret_access_rules -> vauban_groups (user_group_id));
diesel::joinable!(secret_secret_groups -> secret_groups (secret_group_id));
diesel::joinable!(secret_secret_groups -> vault_secrets (secret_id));
diesel::joinable!(user_groups -> users (user_id));
diesel::joinable!(user_groups -> vauban_groups (group_id));

diesel::allow_tables_to_appear_in_same_query!(
    access_rules,
    api_keys,
    approval_audit_log,
    asset_asset_groups,
    asset_groups,
    assets,
    auth_sessions,
    email_outbox,
    ews,
    ews_audit_log,
    ews_onboarding_requests,
    proxy_sessions,
    secret_access_rules,
    secret_groups,
    secret_secret_groups,
    user_groups,
    users,
    vauban_groups,
    vault_secrets,
);
