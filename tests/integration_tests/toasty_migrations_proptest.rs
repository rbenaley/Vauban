//! Property tests for migration history ordering / uniqueness.

use proptest::prelude::*;
use toasty::migration::{History, HistoryEntry};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

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
}
