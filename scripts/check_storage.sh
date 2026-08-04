#!/usr/bin/env bash
# Structural invariants for vcp-store storage helper (architecture 1.2).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_storage: $*" >&2
  exit 1
}

ENGINE="src/storage/engine.rs"
CLIENT="src/storage/client.rs"
IPC="src/storage/ipc.rs"
CAP="src/storage/capsicum.rs"
IDS="src/storage/ids.rs"
OBJECTS="src/storage/objects.rs"
BIN="src/bin/vcp_store.rs"
DL="src/app/org/builds/download.rs"
IMG="src/app/org/images.rs"
MODELS="src/models/mod.rs"
CONF="config/vcp.conf"
STORE_CONF="config/vcp-store.conf"
CFG="src/config.rs"

[[ -f "$ENGINE" ]] || fail "missing $ENGINE"
[[ -f "$BIN" ]] || fail "missing $BIN"
[[ -f "$DL" ]] || fail "missing $DL"
[[ -f "$IMG" ]] || fail "missing $IMG"

META="src/storage/meta_db.rs"
ERR="src/storage/error.rs"
PROTO="src/storage/protocol.rs"

# Digests SoT = helper SQLite; Postgres storage_objects is mirror only.
[[ -f "$META" ]] || fail "missing $META"
grep -n 'META_DB_FILE\|meta.sqlite' "$META" >/dev/null \
  || fail "$META must open blob_path/meta.sqlite"
grep -n 'IntegrityMismatch\|integrity_mismatch' "$ERR" >/dev/null \
  || fail "$ERR must define IntegrityMismatch"
grep -n 'sha256: String' "$PROTO" >/dev/null \
  || fail "$PROTO Get/Stat must require expected sha256"
grep -n 'get_verified' "$ENGINE" >/dev/null \
  || fail "$ENGINE must implement get_verified (SoT + verify-on-read)"
grep -n 'MetaDb\|meta.sqlite' "$ENGINE" >/dev/null \
  || fail "$ENGINE must wire MetaDb on put_commit/get"

if grep -nE 'pub struct Release' -A40 "$MODELS" | grep -qE 'pub sha256|pub size_mb'; then
  fail "$MODELS Release must not carry sha256 / size_mb (mirror is storage_objects)"
fi
grep -n 'struct StorageObject' "$MODELS" >/dev/null \
  || fail "$MODELS must define StorageObject"
grep -n 'mirror\|SoT' "$MODELS" >/dev/null \
  || fail "$MODELS StorageObject docs must mention Postgres mirror / helper SoT"
grep -n 'STORAGE_SCOPE_RELEASE\|STORAGE_SCOPE_IMAGE' "$MODELS" >/dev/null \
  || fail "$MODELS must define storage scope constants"

# Download is wired to helper + mirror sha (no 501 stub).
grep -n 'find_release_object' "$DL" >/dev/null \
  || fail "$DL must require storage_objects row before IPC get"
grep -n 'get_release\|storage(' "$DL" >/dev/null \
  || fail "$DL must call storage helper get_release"
grep -n 'obj.sha256\|INTEGRITY_MISMATCH\|integrity mismatch' "$DL" >/dev/null \
  || fail "$DL must present mirror sha256 and handle integrity mismatch"
grep -n 'DOWNLOAD_UNAVAILABLE\|download unavailable' "$DL" >/dev/null \
  || fail "$DL must use stable download unavailable message"
if grep -nE 'NOT_IMPLEMENTED|download not configured' "$DL" >/dev/null; then
  fail "$DL must not return 501 download stub"
fi
grep -n 'X-Content-Type-Options' "$DL" >/dev/null \
  || fail "$DL must set nosniff on artifact responses"

# Images: tenancy before IPC + nosniff.
grep -n 'find_image_object' "$IMG" >/dev/null \
  || fail "$IMG GET must lookup storage_objects before IPC"
grep -n 'X-Content-Type-Options' "$IMG" >/dev/null \
  || fail "$IMG must set nosniff"
grep -n 'normalize_image_ext\|is_uuid_key' "$IMG" >/dev/null \
  || fail "$IMG must validate image id / ext"
grep -n 'require_org' "$IMG" >/dev/null || fail "$IMG must call require_org"

# No direct blob FS from product handlers.
if grep -rnE 'std::fs::(read|write|OpenOptions|create|remove)' src/app --include='*.rs' \
  | grep -vE '^\s*//' | grep -qiE 'storage|blob|releases/|images/'; then
  fail "src/app must not open storage blob paths via std::fs"
fi

# Peercred on named socket (prod).
grep -n 'fn peer_uid' "$IPC" >/dev/null || fail "$IPC must define peer_uid"
grep -nE 'getpeereid|PeerCredentials|peercred' "$IPC" >/dev/null \
  || fail "$IPC peer_uid must use peer credentials API"
grep -n 'peer_uid' "$BIN" >/dev/null || fail "$BIN must check peer_uid in socket mode"
grep -n 'peercred failed\|reject peer uid' "$BIN" >/dev/null \
  || fail "$BIN must log peercred failure / uid reject"

# Capsicum entry point (real on FreeBSD, WARN elsewhere).
grep -n 'fn enter_capability_mode' "$CAP" >/dev/null \
  || fail "$CAP must define enter_capability_mode"
grep -n 'enter_capability_mode' "$BIN" >/dev/null \
  || fail "$BIN must call enter_capability_mode at boot"
grep -n 'cap_enter' "$CAP" >/dev/null \
  || fail "$CAP must attempt cap_enter on FreeBSD (cfg)"

# ID / ext catalogue exports.
grep -n 'pub fn is_uuid_key' "$IDS" >/dev/null || fail "$IDS must export is_uuid_key"
grep -n 'pub fn normalize_image_ext' "$IDS" >/dev/null \
  || fail "$IDS must export normalize_image_ext"
grep -n 'png\|jpeg\|webp' "$IDS" >/dev/null || fail "$IDS must catalogue png/jpeg/webp"

# Prod portal: socket client only; helper owns blob_path in vcp-store.conf.
[[ -f "$STORE_CONF" ]] || fail "missing $STORE_CONF"
grep -n 'ipc = "socket"' "$CONF" >/dev/null \
  || fail "$CONF production storage.ipc must be socket"
grep -n 'socket_path' "$CONF" >/dev/null \
  || fail "$CONF production storage must set socket_path"
if grep -nE '^\s*blob_path\s*=' "$CONF" >/dev/null; then
  fail "$CONF must not set storage.blob_path (helper owns it in $STORE_CONF)"
fi
grep -n 'blob_path = "/var/db/vcp/storage"' "$STORE_CONF" >/dev/null \
  || fail "$STORE_CONF must set absolute production blob_path"
grep -n 'listen = "/var/run/vcp/store.sock"' "$STORE_CONF" >/dev/null \
  || fail "$STORE_CONF must set listen socket path"
grep -n 'expected_peer_uid = 800' "$STORE_CONF" >/dev/null \
  || fail "$STORE_CONF must pin expected_peer_uid = 800 (portal vcp)"
grep -n 'vcp-storage' "$STORE_CONF" >/dev/null \
  || fail "$STORE_CONF must document helper OS user vcp-storage (801)"
grep -n 'struct StoreHelperConfig' "$CFG" >/dev/null \
  || fail "$CFG must define StoreHelperConfig for vcp-store.conf"
grep -n 'storage.ipc=socket is required in production' "$CFG" >/dev/null \
  || fail "$CFG validate_storage must refuse non-socket ipc in production"
grep -n 'blob_path must be empty in production' "$CFG" >/dev/null \
  || fail "$CFG must refuse portal blob_path in production"

# Upsert helpers after put_commit.
grep -n 'upsert_release_object\|upsert_image_object' "$OBJECTS" >/dev/null \
  || fail "$OBJECTS must upsert storage_objects after commit"

# Engine uses cap-std Dir (soft fence).
grep -n 'cap_std\|Dir::' "$ENGINE" >/dev/null \
  || fail "$ENGINE must use cap-std Dir"

# Client supports inline (tests) + spawn + socket.
grep -n 'StorageIpcMode::Inline\|StorageIpcMode::Spawn\|StorageIpcMode::Socket' "$CLIENT" >/dev/null \
  || fail "$CLIENT must support spawn/socket/inline backends"

# Architecture 1.2 WebAuthn / CTAP2 (ADR 002–004).
WEBAUTHN="src/storage/webauthn.rs"
AUDIT="src/storage/audit.rs"
DOC12="docs/technical/VCP_Storage_Helper_Architecture_EN(1.2).md"
ADR002="docs/adr/002-storage-webauthn-ceremony-channel-c1.md"
ADR003="docs/adr/003-ctap2-enrol-revoke-asymmetry.md"
ADR004="docs/adr/004-webauthn-sign-count-policy.md"
[[ -f "$WEBAUTHN" ]] || fail "missing $WEBAUTHN"
[[ -f "$AUDIT" ]] || fail "missing $AUDIT"
[[ -f "$DOC12" ]] || fail "missing $DOC12"
[[ -f "$ADR002" ]] || fail "missing $ADR002"
[[ -f "$ADR003" ]] || fail "missing $ADR003"
[[ -f "$ADR004" ]] || fail "missing $ADR004"
grep -n 'webauthn_required\|webauthn_invalid\|webauthn_expired\|challenge_unknown\|object_modified' "$ERR" >/dev/null \
  || fail "$ERR must define WebAuthn closed error codes"
grep -n 'PutPrepare\|ChallengeBegin\|Ctap2EnrolStage\|Ctap2Revoke' "$PROTO" >/dev/null \
  || fail "$PROTO must define put_prepare / challenge_begin / ctap2 ops"
grep -n 'webauthn_credentials\|webauthn_challenges' "$META" >/dev/null \
  || fail "$META must define webauthn_* tables"
grep -n 'put_prepare\|validate_production_webauthn' "$ENGINE" >/dev/null \
  || fail "$ENGINE must implement put_prepare + production WebAuthn boot guard"
grep -n 'webauthn_required = true' "$STORE_CONF" >/dev/null \
  || fail "$STORE_CONF must set webauthn_required = true"
grep -n 'webauthn_strict_sign_count = false' "$STORE_CONF" >/dev/null \
  || fail "$STORE_CONF must default webauthn_strict_sign_count = false (ADR 004)"
grep -n 'webauthn_user_verification = "required"' "$STORE_CONF" >/dev/null \
  || fail "$STORE_CONF must require userVerification"
grep -n 'ctap2 pending\|ctap2 approve\|ctap2 list' "$BIN" >/dev/null \
  || fail "$BIN must implement ctap2 pending/list/approve CLI (ADR 003)"
grep -n 'list_pending_credentials_cli\|PENDING credentials' "$BIN" >/dev/null \
  || fail "$BIN ctap2 pending must list PENDING credentials (E2 queue), not only challenges"
grep -n 'list_all_credentials_cli\|format_ascii_table' "$BIN" >/dev/null \
  || fail "$BIN must table-format ctap2 list/pending output"
grep -n 'validate_production_webauthn\|webauthn_required=false' "$BIN" >/dev/null \
  || fail "$BIN must refuse production webauthn_required=false"
grep -n 'credential_fingerprint\|summary' "$WEBAUTHN" >/dev/null \
  || fail "$WEBAUTHN must implement fingerprint + canonical summary"

echo "check_storage: OK"
