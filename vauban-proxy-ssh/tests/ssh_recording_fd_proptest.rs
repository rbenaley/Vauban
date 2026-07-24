//! Property / shape pins for SSH FD recording seal wire.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn blake3_hex_shape_is_64_lowercase(bytes in prop::array::uniform32(any::<u8>())) {
        let hex = blake3::hash(&bytes).to_hex().to_string();
        prop_assert_eq!(hex.len(), 64);
        prop_assert!(hex.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
    }
}

#[test]
fn ssh_cast_writer_unit_tests_pin_disk_blake3() {
    let src = include_str!("../src/ssh_cast_writer.rs");
    assert!(
        src.contains("writer_seals_hash_and_stats_from_disk_bytes"),
        "ssh_cast_writer must pin blake3 == on-disk bytes"
    );
}
