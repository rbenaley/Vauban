//! MCP rule tools: approved names only, no leftover memory.
//!
//! vauban-access refuses rule writes that name a tool not approved on the
//! asset group, and erases names that leave the approved catalogue when
//! web asks it to (`AccessRequest::PruneMcpRuleTools`). Web must ask after
//! every write that can shrink an asset group's approved set: deleting an
//! asset, editing it, taking it out of a group, deleting a group, Discover,
//! Approve and drift quarantine. A forgotten call once let the modes of a
//! deleted asset come back on a new asset with the same tool names.

use std::path::{Path, PathBuf};

const PRUNE: &str = "mcp_rule_prune::prune_after";

/// The single list of writes that can shrink an approved set: (source file
/// under `src/`, function, what it changes).
const SHRINKING_WRITES: &[(&str, &str, &str)] = &[
    (
        "handlers/web/manage_assets.rs",
        "delete_asset_web",
        "deleting an MCP asset",
    ),
    (
        "handlers/web/manage_assets.rs",
        "update_asset_web",
        "editing an MCP asset (type or configuration)",
    ),
    (
        "handlers/web/asset_groups.rs",
        "asset_group_remove_asset",
        "taking an asset out of a group",
    ),
    (
        "handlers/web/asset_groups.rs",
        "delete_asset_group_web",
        "deleting an asset group",
    ),
    (
        "handlers/web/mcp_discover.rs",
        "discover_mcp_tools_web",
        "re-discovering a catalogue (changed tools go back to pending)",
    ),
    (
        "handlers/web/mcp_discover.rs",
        "approve_mcp_tools_web",
        "approving tools",
    ),
    (
        "services/mcp_tool_drift.rs",
        "handle_drift",
        "quarantining a changed tool",
    ),
];

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(src_dir().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

fn prod(src: &str) -> &str {
    src.split("#[cfg(test)]\nmod ").next().unwrap_or(src)
}

/// Body of `fn name` up to the next top-level item.
fn fn_body<'a>(src: &'a str, name: &str) -> Option<&'a str> {
    let start = [
        format!("pub async fn {name}("),
        format!("async fn {name}("),
        format!("pub fn {name}("),
    ]
    .iter()
    .find_map(|n| src.find(n.as_str()))?;
    let rest = &src[start + 1..];
    let end = [
        "\npub async fn ",
        "\nasync fn ",
        "\npub fn ",
        "\nfn ",
        "\n#[cfg(test)]",
    ]
    .iter()
    .filter_map(|m| rest.find(m))
    .min()
    .unwrap_or(rest.len());
    Some(&src[start..start + 1 + end])
}

/// Top-level functions of a file: (name, body).
fn functions(src: &str) -> Vec<(String, &str)> {
    let mut out = Vec::new();
    for marker in ["\npub async fn ", "\nasync fn ", "\npub fn ", "\nfn "] {
        let mut from = 0;
        while let Some(i) = src[from..].find(marker) {
            let at = from + i + marker.len();
            let name: String = src[at..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if let Some(body) = fn_body(src, &name) {
                out.push((name, body));
            }
            from = at;
        }
    }
    out
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = entry.path();
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

/// A function body that can shrink an approved set: tombstones an asset,
/// deletes asset group memberships, or rewrites an MCP catalogue.
fn shrinks_approved(body: &str) -> bool {
    let lines: Vec<&str> = body.lines().collect();
    lines.iter().enumerate().any(|(i, line)| {
        let t = line.trim();
        if t.starts_with("//") {
            return false;
        }
        let next = lines.get(i + 1).copied().unwrap_or("");
        let membership_delete = t.contains("diesel::delete(")
            && (t.contains("asset_asset_groups") || next.contains("asset_asset_groups"));
        membership_delete
            || t.starts_with("a::is_deleted.eq(true)")
            || t.starts_with("assets::is_deleted.eq(true)")
            || t.contains("apply_discovered_catalog(")
            || t.contains("approve_pending_catalog(")
            || t.contains("approve_tool_in_catalog(")
            || t.contains("apply_report(")
    })
}

#[test]
fn every_shrinking_write_asks_access_to_prune() {
    for (file, func, what) in SHRINKING_WRITES {
        let src = read(file);
        let body = fn_body(prod(&src), func).unwrap_or_else(|| {
            panic!("{file}: `{func}` ({what}) not found; update SHRINKING_WRITES")
        });
        let imported = src.contains("use crate::services::mcp_rule_prune::prune_after_")
            && body.contains("prune_after_");
        assert!(
            body.contains(PRUNE) || imported,
            "{file}::{func} ({what}) must call {PRUNE}* so vauban-access erases names that left the catalogue"
        );
    }
}

#[test]
fn no_handler_or_service_shrinks_a_catalogue_without_the_inventory() {
    let mut files = Vec::new();
    rs_files(&src_dir().join("handlers"), &mut files);
    rs_files(&src_dir().join("services"), &mut files);
    let root = src_dir();
    let mut missing = Vec::new();
    let mut seen = Vec::new();
    for path in files {
        let src = std::fs::read_to_string(&path).expect("read source");
        let rel = path
            .strip_prefix(&root)
            .expect("under src")
            .to_string_lossy()
            .replace('\\', "/");
        for (name, body) in functions(prod(&src)) {
            if !shrinks_approved(body) || !writes_db(body) {
                continue;
            }
            seen.push(format!("{rel}::{name}"));
            if !SHRINKING_WRITES
                .iter()
                .any(|(f, func, _)| *f == rel && *func == name)
            {
                missing.push(format!("{rel}::{name}"));
            }
        }
    }
    for known in [
        "handlers/web/manage_assets.rs::delete_asset_web",
        "handlers/web/asset_groups.rs::asset_group_remove_asset",
    ] {
        assert!(
            seen.iter().any(|s| s == known),
            "the sweep no longer detects {known}; fix shrinks_approved/writes_db"
        );
    }
    assert!(
        missing.is_empty(),
        "these can shrink an approved MCP catalogue but are not in SHRINKING_WRITES: {missing:?}"
    );
}

/// Pure catalogue transforms (config in, config out) are not writes; only
/// a body that persists something can leave a rule behind.
fn writes_db(body: &str) -> bool {
    [
        ".execute(",
        ".get_result(",
        "diesel::update(",
        "diesel::delete(",
    ]
    .iter()
    .any(|m| body.contains(m))
}

#[test]
fn prune_is_owned_by_access_and_never_widens() {
    let svc = read("services/mcp_rule_prune.rs");
    assert!(
        svc.contains(".prune_mcp_rule_tools(Some(scope.clone()))"),
        "web always scopes the prune to the groups that changed"
    );
    assert!(
        !prod(&svc).contains("prune_mcp_rule_tools(None)"),
        "only the access boot prunes every rule"
    );
    let client = read("ipc/access.rs");
    assert!(client.contains("AccessReq::PruneMcpRuleTools { asset_group_ids }"));
    let mcp_access = read("handlers/web/mcp_access.rs");
    assert!(
        mcp_access.contains("fn is_tools_refusal")
            && mcp_access.contains("shared::mcp_policy::RULE_TOOLS_NOT_APPROVED"),
        "the rule form shows the access refusal instead of a generic error"
    );
}
