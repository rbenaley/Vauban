#[test]
fn mcp_shared_sources_do_not_interpolate_untrusted_input() {
    for name in ["mcp_policy.rs", "mcp_mandate.rs", "mcp_drift_iam.rs"] {
        let src = match name {
            "mcp_policy.rs" => include_str!("../src/mcp_policy.rs"),
            "mcp_mandate.rs" => include_str!("../src/mcp_mandate.rs"),
            "mcp_drift_iam.rs" => include_str!("../src/mcp_drift_iam.rs"),
            _ => unreachable!(),
        };
        assert!(
            !src.contains("SELECT ") && !src.contains(".replace("),
            "{name} must not build a query or template from external input"
        );
    }
}

#[test]
fn service_proxy_mcp_discriminant_is_frozen() {
    assert_eq!(
        shared::messages::Service::ProxyMcp.as_token_discriminant(),
        10
    );
}
