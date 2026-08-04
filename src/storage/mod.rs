//! Artifact storage: portable engine, IPC client/server, Capsicum hooks.
//!
//! See `docs/technical/VCP_Storage_Helper_Architecture_EN(1.0).md`.

pub mod capsicum;
pub mod client;
pub mod engine;
pub mod error;
pub mod ids;
pub mod ipc;
pub mod meta_db;
pub mod objects;
pub mod protocol;
pub mod server;
pub mod sniff;

pub use client::{StorageClient, write_and_hash};
pub use engine::{ObjectStat, PutBeginOk, StorageEngine, sha256_hex, write_abs_file};
pub use error::{StorageError, StorageErrorCode};
pub use ids::{StorageScope, is_uuid_key, normalize_image_ext};
pub use meta_db::{META_DB_FILE, MetaDb, MetaObject, ct_eq_hex};
pub use objects::{
    BlobDisplay, delete_org_objects, delete_release_object, find_image_object, find_release_object,
    release_blob_display, storage_http_status, upsert_image_object, upsert_release_object,
};
pub use protocol::{StorageRequest, StorageResponse};
