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
        require_justification -> Bool,
        max_session_duration -> Nullable<Int4>,
        is_active -> Bool,
        priority -> Int4,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
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
        is_deleted -> Bool,
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

diesel::joinable!(access_rules -> asset_groups (asset_group_id));
diesel::joinable!(access_rules -> vauban_groups (user_group_id));
diesel::joinable!(user_groups -> users (user_id));
diesel::joinable!(user_groups -> vauban_groups (group_id));

diesel::allow_tables_to_appear_in_same_query!(
    access_rules,
    asset_groups,
    user_groups,
    users,
    vauban_groups,
);
