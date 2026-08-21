//! Property tests for migration history ordering / uniqueness.

use proptest::prelude::*;
use toasty::migration::{History, HistoryEntry};

fn real_history_entries() -> Vec<(u64, String)> {
    let history = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/toasty/history.toml"));
    let mut out = Vec::new();
    let mut id = None;
    for line in history.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("id = ") {
            id = Some(rest.parse().expect("id"));
        }
        if let Some(rest) = line.strip_prefix("name = ") {
            let name = rest.trim_matches('"').to_owned();
            out.push((id.expect("name without id"), name));
        }
    }
    out
}

proptest! {
    #![proptest_config(crate::common::prop_config(48))]

    #[test]
    fn prop_history_ids_and_names_unique(
        ids in prop::collection::vec(any::<u64>(), 1..12),
    ) {
        let mut history = History::new();
        let mut seen_ids = std::collections::HashSet::new();
        let mut seen_names = std::collections::HashSet::new();

        for (i, id) in ids.into_iter().enumerate() {
            if !seen_ids.insert(id) {
                continue;
            }
            let name = format!("{:04}_mig.sql", i);
            prop_assert!(seen_names.insert(name.clone()));
            history.add_entry(HistoryEntry {
                id,
                name: name.clone(),
                snapshot_name: format!("{:04}_snapshot.toml", i),
                checksum: None,
            });
        }

        let entries = history.entries();
        let mut ids_out = std::collections::HashSet::new();
        let mut names_out = std::collections::HashSet::new();
        for e in entries {
            prop_assert!(ids_out.insert(e.id));
            prop_assert!(names_out.insert(e.name.clone()));
        }
        prop_assert_eq!(ids_out.len(), entries.len());
        prop_assert_eq!(names_out.len(), entries.len());
    }

    #[test]
    fn prop_real_history_ids_names_unique_and_on_disk(
        idx in 0usize..64,
    ) {
        let entries = real_history_entries();
        prop_assume!(!entries.is_empty());
        let i = idx % entries.len();
        let (id, name) = &entries[i];
        let ids: std::collections::HashSet<u64> = entries.iter().map(|(id, _)| *id).collect();
        let names: std::collections::HashSet<&str> =
            entries.iter().map(|(_, n)| n.as_str()).collect();
        prop_assert_eq!(ids.len(), entries.len());
        prop_assert_eq!(names.len(), entries.len());
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("toasty/migrations")
            .join(name);
        prop_assert!(path.is_file(), "missing SQL for {id} {name}");
    }
}
