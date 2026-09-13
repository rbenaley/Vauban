//! Integration test binary for behavioral pyramid surfaces.
//!
//! Filters:
//! - `cargo test --test integration_tests -- auth_tenant -- --test-threads=1`
//! - `cargo test --test integration_tests -- http_edge -- --test-threads=1`
//! - `cargo test --test integration_tests -- portal_shell -- --test-threads=1`
//! - `cargo test --test integration_tests -- admin_docs -- --test-threads=1`
//! - `cargo test --test integration_tests -- portal_issues -- --test-threads=1`
//! - `cargo test --test integration_tests -- admin_releases -- --test-threads=1`
//! - `cargo test --test integration_tests -- admin_companies -- --test-threads=1`
//! - `cargo test --test integration_tests -- org_account -- --test-threads=1`
//! - `cargo test --test integration_tests -- builds_entitlement -- --test-threads=1`
//! - `cargo test --test integration_tests -- release_notes_inline -- --test-threads=1`
//! - `cargo test --test integration_tests -- toasty_filters -- --test-threads=1`
//! - `cargo test --test integration_tests -- request_sql_dedup -- --test-threads=1`
//! - `cargo test --test integration_tests -- dashboard_stats -- --test-threads=1`
//! - `cargo test --test integration_tests -- toasty_migrations -- --test-threads=1`
//! - `cargo test --test integration_tests -- toasty_paginate -- --test-threads=1`
//! - `cargo test --test integration_tests -- docs_search_shard -- --test-threads=1`
//! - `cargo test --test integration_tests -- org_issues_search_shard -- --test-threads=1`
//! - `cargo test --test integration_tests -- admin_issues_search_shard -- --test-threads=1`
//! - `cargo test --test integration_tests -- issues_search_shard -- --test-threads=1`
//! - `cargo test --test integration_tests -- display_tz -- --test-threads=1`
//! - `cargo test --test integration_tests -- magic_link -- --test-threads=1`
//! - `cargo test --test integration_tests -- companies_magic_mail -- --test-threads=1`
//! - `cargo test --test integration_tests -- choose_org -- --test-threads=1`
//! - `cargo test --test integration_tests -- topcoat_boolean_attrs -- --test-threads=1`
//! - `cargo test --test integration_tests -- topcoat_0_6 -- --test-threads=1`
//! - `cargo test --test integration_tests -- topcoat_0_8 -- --test-threads=1`
//! - `cargo test --test integration_tests -- storage_ -- --test-threads=1`
//! - `cargo test --test integration_tests -- seed_data -- --test-threads=1`
//! - `cargo test --test integration_tests -- freebsd_pkg -- --test-threads=1`
//! - `cargo test --test integration_tests -- smtp_certs -- --test-threads=1`
//! - `cargo test --test integration_tests -- issue_notify -- --test-threads=1`
//! - `cargo test --test integration_tests -- issue_comment_edit -- --test-threads=1`
//! - `cargo test --test integration_tests -- issue_comment_format -- --test-threads=1`

mod admin_companies_battle_test;
mod admin_companies_e2e_test;
mod admin_companies_invariants_test;
mod admin_companies_proptest;
mod admin_companies_search_shard_battle_test;
mod admin_companies_search_shard_e2e_test;
mod admin_companies_search_shard_invariants_test;
mod admin_companies_search_shard_proptest;
mod admin_docs_battle_test;
mod admin_docs_e2e_test;
mod admin_docs_invariants_test;
mod admin_docs_proptest;
mod admin_issues_search_shard_battle_test;
mod admin_issues_search_shard_e2e_test;
mod admin_issues_search_shard_invariants_test;
mod admin_issues_search_shard_proptest;
mod admin_releases_battle_test;
mod admin_releases_e2e_test;
mod admin_releases_invariants_test;
mod admin_releases_proptest;
mod auth_tenant_battle_test;
mod auth_tenant_e2e_test;
mod auth_tenant_invariants_test;
mod auth_tenant_models_test;
mod auth_tenant_proptest;
mod builds_entitlement_battle_test;
mod builds_entitlement_e2e_test;
mod builds_entitlement_invariants_test;
mod builds_entitlement_proptest;
mod choose_org_battle_test;
mod choose_org_e2e_test;
mod common;
mod companies_magic_mail_e2e_test;
mod dashboard_stats_battle_test;
mod dashboard_stats_e2e_test;
mod dashboard_stats_invariants_test;
mod dashboard_stats_proptest;
mod display_tz_battle_test;
mod display_tz_e2e_test;
mod display_tz_invariants_test;
mod display_tz_proptest;
mod docs_bundle_battle_test;
mod docs_bundle_e2e_test;
mod docs_bundle_invariants_test;
mod docs_bundle_proptest;
mod docs_search_shard_battle_test;
mod docs_search_shard_e2e_test;
mod docs_search_shard_invariants_test;
mod docs_search_shard_proptest;
mod freebsd_pkg_invariants_test;
mod http_edge_battle_test;
mod http_edge_e2e_test;
mod http_edge_invariants_test;
mod http_edge_proptest;
mod issue_comment_edit_battle_test;
mod issue_comment_edit_e2e_test;
mod issue_comment_edit_invariants_test;
mod issue_comment_edit_proptest;
mod issue_comment_format_battle_test;
mod issue_comment_format_e2e_test;
mod issue_comment_format_invariants_test;
mod issue_comment_format_proptest;
mod issue_notify_battle_test;
mod issue_notify_e2e_test;
mod issue_notify_invariants_test;
mod issue_notify_proptest;
mod magic_link_battle_test;
mod magic_link_e2e_test;
mod magic_link_invariants_test;
mod mail_templates_battle_test;
mod mail_templates_e2e_test;
mod mail_templates_invariants_test;
mod mail_templates_proptest;
mod org_account_battle_test;
mod org_account_e2e_test;
mod org_account_invariants_test;
mod org_account_proptest;
mod org_issues_search_shard_battle_test;
mod org_issues_search_shard_e2e_test;
mod org_issues_search_shard_invariants_test;
mod org_issues_search_shard_proptest;
mod portal_issues_battle_test;
mod portal_issues_e2e_test;
mod portal_issues_invariants_test;
mod portal_issues_proptest;
mod portal_shell_battle_test;
mod portal_shell_e2e_test;
mod portal_shell_invariants_test;
mod portal_shell_proptest;
mod release_notes_inline_battle_test;
mod release_notes_inline_e2e_test;
mod release_notes_inline_invariants_test;
mod release_notes_inline_proptest;
mod request_sql_dedup_battle_test;
mod request_sql_dedup_e2e_test;
mod request_sql_dedup_invariants_test;
mod request_sql_dedup_proptest;
mod seed_data_battle_test;
mod seed_data_e2e_test;
mod seed_data_invariants_test;
mod seed_data_proptest;
mod smtp_certs_battle_test;
mod smtp_certs_e2e_test;
mod smtp_certs_invariants_test;
mod storage_battle_test;
mod storage_e2e_test;
mod storage_invariants_test;
mod storage_proptest;
mod toasty_filters_battle_test;
mod toasty_filters_e2e_test;
mod toasty_filters_invariants_test;
mod toasty_filters_proptest;
mod toasty_migrations_battle_test;
mod toasty_migrations_e2e_test;
mod toasty_migrations_invariants_test;
mod toasty_migrations_proptest;
mod toasty_paginate_battle_test;
mod toasty_paginate_e2e_test;
mod toasty_paginate_invariants_test;
mod toasty_paginate_proptest;
mod topcoat_0_6_battle_test;
mod topcoat_0_6_e2e_test;
mod topcoat_0_6_invariants_test;
mod topcoat_0_6_proptest;
mod topcoat_0_8_battle_test;
mod topcoat_0_8_e2e_test;
mod topcoat_0_8_invariants_test;
mod topcoat_0_8_proptest;
mod topcoat_boolean_attrs_invariants_test;
