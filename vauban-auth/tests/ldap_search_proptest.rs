//! Malformed search PDUs never panic; they fail closed as `io::Error`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use proptest::prelude::*;
use vauban_auth::ldap::{
    parse_search_request, parse_search_result_done, parse_search_result_entry, search_pdu_kind,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn malformed_search_pdus_are_io_errors(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        let _ = parse_search_result_entry(&bytes);
        let _ = parse_search_result_done(&bytes);
        let _ = parse_search_request(&bytes);
        let _ = search_pdu_kind(&bytes);
    }
}
