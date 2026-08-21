//! Token segment under `/releases/{eph_token}`.

pub(crate) mod eph_pkg;

use topcoat::router::path_param;

path_param!(pub(crate) eph_token);
