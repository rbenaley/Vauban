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
diesel::joinable!(user_groups -> vauban_groups (group_id));

diesel::allow_tables_to_appear_in_same_query!(
    access_rules,
    asset_groups,
    user_groups,
    vauban_groups,
);
