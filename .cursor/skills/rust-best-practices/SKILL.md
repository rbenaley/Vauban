---
name: rust-best-practices
description: >-
  Rust conventions for VCP (Topcoat portal): organization, errors, async,
  security hygiene. Use when writing or reviewing Rust code in this repo.
---
# Rust Best Practices for VCP

Secure, maintainable Rust for the **Vauban Customer Portal** (Topcoat).
This is not the bastion: do not treat Capsicum, privsep, or proxy IPC as
default requirements. Prefer patterns that fit a customer-facing web
app; keep cryptography and auth boring and well-tested.

## 1. Code Organization and Structure

### 1.1. Directory Structure
```
vcp/
├── Cargo.toml
├── Cargo.lock
├── src/
│   ├── main.rs              # Binary entry point
│   ├── lib.rs               # Library entry point (if used)
│   ├── app.rs               # Topcoat root / routing discover
│   └── app/                 # Module-based routes (pages, layouts)
├── tests/                   # Integration / E2E tests
├── benches/                 # Criterion benchmarks (optional)
├── README.md
└── LICENSE
```
Follow the `web-stack` skill once the scaffold lands; adjust this tree
to match Topcoat’s module router rather than inventing a second layout.

### 1.2. Module Conventions
- Use `.rs` extension with snake_case for file names
- Declare modules with `mod`/`pub mod` in lib.rs or main.rs
- Create separate files for each module
- Use traits for component interfaces
- Apply dependency injection for testability
```rust
// lib.rs
pub mod crypto;
pub mod network;
pub mod auth;
mod internal;  // Private module
```

## 2. Patterns and Anti-patterns

### 2.1. Recommended Design Patterns
- **Builder Pattern**: Complex object construction with optional parameters
- **Factory Pattern**: Object creation without specifying concrete types
- **Strategy Pattern**: Runtime algorithm selection
- **Observer Pattern**: Event-driven systems implementation

### 2.2. Common Task Approaches
- **Data Structures**: `Vec`, `HashMap`, `HashSet`, `BTreeMap`/`BTreeSet` for sorted
- **Concurrency**: `Arc`+`Mutex` for shared state, channels for messaging, `rayon` for parallelism
- **Async**: `async`/`await` with `tokio` runtime
- **Errors**: `Result<T,E>`, `Option<T>`, `?` operator, `thiserror`/`anyhow` crates

### 2.3. Modern Rust Features (1.86–1.93)

MSRV is **Rust 1.93** (`rust-version` in the workspace `Cargo.toml`).

**Let Chains (Rust 1.88, Edition 2024):**
Chain `let` patterns with `&&` for cleaner conditional logic:
```rust
// Before (nested if let)
if let Some(x) = option {
    if x.is_valid() {
        process(x);
    }
}

// After (let chains)
if let Some(x) = option && x.is_valid() {
    process(x);
}
```

**LazyLock over lazy_static! (Rust 1.80+):**
Use `std::sync::LazyLock` instead of the `lazy_static!` macro:
```rust
use std::sync::LazyLock;

// Standard library - no external dependency
pub static CONFIG: LazyLock<Config> = LazyLock::new(|| {
    Config::load().expect("Failed to load config")
});
```

**HashMap/HashSet::extract_if (Rust 1.88):**
Extract and remove elements matching a predicate:
```rust
let expired: Vec<_> = cache
    .extract_if(|_, entry| entry.is_expired())
    .collect();
// `expired` contains removed items for logging/cleanup
```
For `DashMap` (no `extract_if`), collect stale keys then `remove` --
same ownership transfer and count semantics.

**Trait Upcasting (Rust 1.86):**
Coerce trait object references to supertrait references without manual casts.

**Safe target_feature (Rust 1.86):**
Safe functions can now use `#[target_feature]` for SIMD optimizations.

**File Locking (Rust 1.89):**
Native file locking without external crates:
```rust
use std::fs::File;
let file = File::open("data.lock")?;
file.lock()?;  // Exclusive lock
// or file.lock_shared()? for shared lock
```

**Path::with_added_extension / add_extension (Rust 1.91):**
Append an extension without replacing the existing one (unlike
`with_extension`). Use for legacy RDP sidecars:
```rust
// `uuid.mp4` -> `uuid.mp4.blake3` (does NOT become `uuid.blake3`)
let sidecar = media.with_added_extension("blake3");
```

**Duration::from_hours / from_mins (Rust 1.91):**
Prefer readable duration literals over `from_secs(3600)` /
`from_secs(60 * 60)`:
```rust
const BACKOFF_CAP: Duration = Duration::from_hours(1);
```

**VecDeque::pop_front_if (Rust 1.93):**
Evict a FIFO front while a predicate holds (TTL queues, replay caches):
```rust
while deque
    .pop_front_if(|e| now.duration_since(e.inserted_at) > ttl)
    .is_some()
{}
```

Adopting any of the APIs above on a security / IPC / recording /
session / rate-limit seam is a **behavioral** change: deliver the full
Vauban test pyramid (unit, invariants, proptest, battle, E2E, smoke
runbook) by default — see
[`vauban-test-pyramid.mdc`](mdc:.cursor/rules/vauban-test-pyramid.mdc)
and the `quality-assurance` skill §1. Pure `Duration::from_hours`
literal renames alone may stay unit-only.

### 2.4. Anti-patterns to Avoid
- **Unnecessary cloning**: Use references instead
- **Excessive `unwrap()`**: Handle errors properly with `Result`
- **Ignoring compiler warnings**: Treat as errors
- **Premature optimization**: Profile first, optimize second
- **Using `lazy_static!` macro**: Use `std::sync::LazyLock` instead (standard library)

### 2.5. Unsafe Code Guidelines
When `unsafe` is absolutely required:
- Isolate in dedicated, minimal modules
- Document with `// SAFETY:` comments explaining invariants
- Require code review for all unsafe additions
- Test with Miri for undefined behavior detection
```shell
cargo +nightly miri test
cargo install cargo-geiger && cargo geiger
```

### 2.6. State Management
- Prefer immutability by default
- Leverage Rust's ownership and borrowing system
- Use `Cell`, `RefCell`, `Mutex`, `RwLock` carefully for interior mutability

## 3. Performance Considerations

### 3.1. Optimization Techniques
- **Profiling**: Use `perf`, `cargo flamegraph` to identify bottlenecks
- **Benchmarking**: Use `criterion` for measuring performance changes
- **Zero-cost abstractions**: Leverage iterators, closures, generics
- **Inlining**: Apply `#[inline]` for hot functions
- **LTO**: Enable link-time optimization in release builds

### 3.2. Memory and Binary
- Minimize allocations, reuse buffers when possible
- Use references or `Box`/`Arc` to avoid copying large structures
- Strip debug symbols, enable LTO for smaller binaries
- Minimize dependencies to reduce attack surface and binary size

## 4. Security Best Practices

### 4.1. Common Vulnerabilities Prevention
- **Buffer overflows**: Use `get()`/`get_mut()`, validate input sizes
- **SQL Injection**: Use parameterized queries exclusively
- **Command Injection**: Never use `Command` with user input directly
- **Integer overflows**: Use `checked_add`, `checked_sub`, `checked_mul`
- **Data races**: Use `Mutex`, `RwLock`, channels appropriately

### 4.2. Input Validation
- Validate ALL input from external sources
- Use whitelist approach: define allowed values, reject others
- Sanitize input: remove or escape dangerous characters
- Limit input length before any processing
- Verify data types match expectations

### 4.3. Authentication and Authorization
- **Password hashing**: Argon2id with secure parameters (64MB memory, 3 iterations)
- **Sessions**: Prefer Topcoat session cookies (HttpOnly / Secure / SameSite); JWT only if a clear M2M need exists
- **Access control**: Casbin-backed `PermissionContext` + tenant checks (`casbin-permissions.mdc`)
- **2FA / step-up**: Require for sensitive account or billing operations when product requires it
- **Audits**: Regular security reviews of auth and tenancy seams

### 4.4. Data Protection
- Encrypt sensitive data at rest using AES-256-GCM
- Encrypt data in transit with TLS 1.3+ (mandatory)
- Never hardcode secrets in source code
- Use HashiCorp Vault or environment variables for secrets
- Mask and redact sensitive data in all outputs and logs

### 4.5. Assets and process isolation (VCP defaults)

**Default for this portal:** use Topcoat’s `asset!` / bundler pipeline
(content-hashed URLs, declared assets). Do **not** invent a bastion-style
`include_bytes!` static registry or Capsicum sandbox unless the user
explicitly asks for FreeBSD privsep-level isolation.

**Narrow exception:** well-known icon probe routes
(`/favicon.ico`, `/apple-touch-icon*.png`) may embed bytes with
`include_bytes!` and return them via `Response::builder`. OS / browser
probes hit fixed paths; hashed `asset!` URLs cannot. Layout `<link>`
icons stay on `asset!`. Do not expand this to a general static registry
(see `topcoat` skill §11 / `web-stack`).

Asset hygiene that still applies:

- Prefer declared assets over ad-hoc filesystem reads in request handlers
- Do not serve user-controlled paths from disk without a strict allowlist
- Keep CSP-friendly delivery (avoid sprinkling `unsafe-inline` scripts)
- Never log contents of private keys, session tokens, or raw license keys

Bastion Capsicum / FD-passing patterns live in `../Vauban` and stay out
of scope here by default (see `portal-security.mdc`).

```rust
// Prefer Topcoat asset declarations (illustrative)
// const LOGO: Asset = asset!("./assets/logo.svg");
```

### 4.6. Dependency Security
```shell
# Install security auditing tools
cargo install cargo-audit cargo-deny

# Check for known vulnerabilities
cargo audit

# Initialize and run comprehensive checks
cargo deny init
cargo deny check
```
```toml
# deny.toml configuration
[advisories]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"

[licenses]
unlicensed = "deny"
allow = ["MIT", "Apache-2.0", "BSD-3-Clause"]

[bans]
wildcards = "deny"
deny = [{ name = "openssl" }]  # Prefer rustls

[sources]
unknown-registry = "deny"
unknown-git = "deny"
```

**Rules:** Audit regularly, pin versions for critical deps, vendor for production, review transitive deps in `Cargo.lock`, minimize dependency tree.

### 4.7. Cryptography (Post-Quantum Resistant)

**Never implement custom cryptography.** Always use well-audited libraries.

#### Algorithm Selection Table

| Use Case | Classical (Deprecated) | Post-Quantum | Hybrid Recommendation |
|----------|----------------------|--------------|----------------------|
| Key Encapsulation | RSA, ECDH | ML-KEM (Kyber) | X25519 + ML-KEM-768 |
| Digital Signatures | RSA, ECDSA | ML-DSA (Dilithium) | Ed25519 + ML-DSA-65 |
| Hashing | SHA-256 | SHA-3, BLAKE3 | SHA3-256 or BLAKE3 |
| Symmetric Encryption | AES-128 | AES-256 | AES-256-GCM |
| Password Hashing | bcrypt | Argon2id | Argon2id |

#### NIST Post-Quantum Standards
- **ML-KEM**: FIPS 203 - Use ML-KEM-768 (128-bit) or ML-KEM-1024 (192-bit security)
- **ML-DSA**: FIPS 204 - Use ML-DSA-65 for 128-bit security level
- **SLH-DSA**: FIPS 205 - Hash-based, most conservative assumptions

#### Core Implementation
```rust
use pqcrypto_mlkem::mlkem768;
use x25519_dalek::{StaticSecret, PublicKey};
use hkdf::Hkdf;
use sha3::Sha3_256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Combine classical and post-quantum shared secrets using HKDF
pub fn combine_shared_secrets(classical: &[u8], pq: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut ikm = Vec::with_capacity(classical.len() + pq.len());
    ikm.extend_from_slice(classical);
    ikm.extend_from_slice(pq);
    
    let hkdf = Hkdf::<Sha3_256>::new(None, &ikm);
    let mut output = [0u8; 32];
    hkdf.expand(b"hybrid-kem-v1", &mut output)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    
    ikm.zeroize();  // Clear intermediate material
    Ok(output)
}

/// Constant-time comparison to prevent timing attacks
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Hybrid KEM secret key (X25519 + ML-KEM-768)
#[derive(ZeroizeOnDrop)]
pub struct HybridKemSecretKey {
    classical: StaticSecret,
    post_quantum: mlkem768::SecretKey,
}

pub struct HybridKemPublicKey {
    classical: PublicKey,
    post_quantum: mlkem768::PublicKey,
}

impl HybridKemSecretKey {
    pub fn generate() -> (HybridKemPublicKey, Self) {
        use rand::rngs::OsRng;
        let classical = StaticSecret::random_from_rng(OsRng);
        let classical_public = PublicKey::from(&classical);
        let (pq_public, pq_secret) = mlkem768::keypair();
        
        (HybridKemPublicKey { classical: classical_public, post_quantum: pq_public },
         Self { classical, post_quantum: pq_secret })
    }
}

/// Hash password using Argon2id with secure parameters
pub fn hash_password(password: &str) -> Result<String, CryptoError> {
    use argon2::{Argon2, Algorithm, Params, Version};
    use argon2::password_hash::{PasswordHasher, SaltString};
    use rand::rngs::OsRng;
    
    let params = Params::new(65536, 3, 4, Some(32))
        .map_err(|_| CryptoError::PasswordHashingFailed)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt = SaltString::generate(&mut OsRng);
    
    argon2.hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| CryptoError::PasswordHashingFailed)
}
```

#### Cryptography Dependencies
```toml
[dependencies]
pqcrypto-mlkem = "0.1"       # ML-KEM (FIPS 203)
pqcrypto-mldsa = "0.1"       # ML-DSA (FIPS 204)
pqcrypto-traits = "0.3"
x25519-dalek = { version = "2.0", features = ["static_secrets"] }
ed25519-dalek = { version = "2.1", features = ["rand_core"] }
aes-gcm = "0.10"
sha3 = "0.10"
blake3 = "1.5"
hkdf = "0.12"
argon2 = "0.5"
subtle = "2.5"
zeroize = { version = "1.8", features = ["derive"] }
rand = "0.8"
```

#### Post-Quantum Checklist
- [ ] All key exchanges use hybrid ML-KEM + X25519
- [ ] All signatures use hybrid ML-DSA + Ed25519
- [ ] RSA and ECDSA completely removed from codebase
- [ ] Symmetric keys minimum 256-bit (AES-256)
- [ ] SHA-3 or BLAKE3 for hashing (not SHA-256)
- [ ] All cryptographic material zeroized after use
- [ ] Constant-time comparison for all secret comparisons

### 4.8. Secret and Sensitive Data Handling
```rust
use secrecy::{Secret, ExposeSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Auto-zeroizing sensitive string wrapper
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SensitiveString(String);

impl SensitiveString {
    pub fn new(value: String) -> Self { Self(value) }
    pub fn expose(&self) -> &str { &self.0 }
}

/// Application configuration with protected secrets
pub struct Config {
    pub database_url: String,
    pub database_password: Secret<String>,
    pub api_key: Secret<String>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("database_url", &self.database_url)
            .field("database_password", &"[REDACTED]")
            .field("api_key", &"[REDACTED]")
            .finish()
    }
}
```

**Secret Handling Rules:**
- Use `Secret<T>` wrapper from `secrecy` crate for all sensitive values
- Implement `Zeroize` trait for all secret-containing types
- Redact secrets in `Debug` and `Display` implementations
- Never log, serialize, or display secrets
- Clear environment variables immediately after reading
- Keep secrets in memory for the shortest time possible

### 4.9. Network Hardening (Internet portal)

Normative rule: `.cursor/rules/tls-post-quantum.mdc`.

**Network security rules:**
- Public edge: **HTTPS only**, **TLS 1.3 minimum** (no TLS 1.2 fallback
  for app traffic)
- Prefer **rustls** in-process; if a reverse proxy terminates TLS, it
  must enforce the same policy and the app stays rustls-ready
- Ban OpenSSL by default via `cargo deny` (documented exceptions only)
- Set explicit timeouts on ALL operations (connect, read, write, idle)
- Enforce size limits BEFORE processing any input
- Rate-limit login and other sensitive endpoints (per-IP + global)
- Always validate certificates on outbound TLS (no
  `accept_invalid_certs` in production)
- Error messages must not leak internals / cross-tenant existence
- No WebSocket product endpoints

**Post-quantum TLS preparation:**
- Prefer hybrid groups (X25519 + ML-KEM-768 class) as soon as the pinned
  rustls / aws-lc stack exposes them stably
- Keep TLS config behind a small module so enabling hybrid KEMs is a
  pin + config change, not a rewrite
- Until hybrid TLS is on: classical TLS 1.3 is mandatory; app-level
  KEM/sign (license seals, etc.) still follow the hybrid table in §4.7
- Smoke-test negotiated protocol / groups in staging before production

### 4.10. Secure Logging

#### Process identity (mandatory)

Log lines must show **which process spoke**. Never invent ambiguous
targets.

| Surface | Allowed target prefix | Forbidden |
|---------|----------------------|-----------|
| Portal (`vcp` binary / portal library path) | `vcp:` or `vcp::…` | Custom names without `vcp` |
| Storage helper (`vcp-store` + helper-owned ops) | `vcp-store:` or `vcp-store::…` | `vcp_store`, `vcp_storage_*`, `vcp_storage_alert` |

- Use the **hyphenated** product name `vcp-store` in targets (crate
  name `vcp_store` is an implementation detail — always override with
  `target: "vcp-store"` in the helper binary).
- Helper security / ops ALERTs: `target: "vcp-store::alert"` via
  [`STORE_ALERT_TARGET`](../../../src/storage/mod.rs) /
  [`STORE_LOG_TARGET`](../../../src/storage/mod.rs).
- Portal code: default module path (`vcp::…`) is fine; do not reuse
  helper alert targets.
- Rule: `.cursor/rules/tracing-process-identity.mdc`.

```rust
// Helper binary / Capsicum / helper ALERTs
tracing::warn!(target: "vcp-store", "storage helper shares vcp uid (dev mode)");
tracing::warn!(target: "vcp-store::alert", cred = %hex, "ALERT ctap2_revoke");

// Portal — leave default module target (vcp::…)
tracing::info!("vcp listening on …");
```

```rust
use tracing::{info, warn, error};
use serde::Serialize;
use std::net::IpAddr;

/// Wrapper that automatically redacts on display/debug/serialize
#[derive(Clone)]
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    pub fn new(value: T) -> Self { Self(value) }
    pub fn expose(&self) -> &T { &self.0 }
}

impl<T> std::fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl<T> Serialize for Redacted<T> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str("[REDACTED]")
    }
}

/// Security events for audit logging
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event_type")]
pub enum SecurityEvent {
    AuthSuccess { user_id: String, source_ip: IpAddr },
    AuthFailure { user_id: Option<String>, source_ip: IpAddr, reason: String },
    RateLimitExceeded { source_ip: IpAddr, endpoint: String },
    AuthBypassAttempt { user_id: Option<String>, path: String },
    SuspiciousActivity { source_ip: IpAddr, description: String },
}

/// Log security event with correlation ID for tracing
pub fn log_security_event(event: &SecurityEvent, correlation_id: &str) {
    let event_json = serde_json::to_string(event).unwrap_or_default();
    match event {
        SecurityEvent::AuthBypassAttempt { .. } => {
            error!(correlation_id, event = %event_json, "Authorization bypass attempt");
        }
        SecurityEvent::AuthFailure { .. } | SecurityEvent::RateLimitExceeded { .. } => {
            warn!(correlation_id, event = %event_json, "Security warning");
        }
        _ => {
            info!(correlation_id, event = %event_json, "Security event");
        }
    }
}

/// Generate unique correlation ID for request tracing
pub fn generate_correlation_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
```

**Log Level Guidelines:**

| Level | Usage | Examples |
|-------|-------|----------|
| ERROR | Security incidents, system failures | Auth bypass attempts, data integrity failures |
| WARN | Anomalies, failed attempts | Auth failures, rate limits exceeded |
| INFO | Audit trail, normal operations | Successful auth, config changes |
| DEBUG | Development only | Never enable in production |

**Logging Rules:**
- Process identity first: `vcp` / `vcp::…` vs `vcp-store` / `vcp-store::…` (see above)
- Use JSON structured logging for SIEM integration (JSON: require to be enabled via configuration)
- Wrap sensitive data with `Redacted<T>`
- Include correlation IDs in all log entries
- Configure secure log rotation and deletion
- Forward logs to immutable storage

## 5. Testing Approaches

### 5.1. Testing Strategy
- **Unit tests**: `#[test]`, `assert!`/`assert_eq!`, table-driven tests
- **Integration tests**: Place in `tests/` directory, separate files per component
- **Security tests**: Miri for undefined behavior, cargo-geiger for unsafe audit
- **Mocking**: Use `mockall` crate, define traits for mockable interfaces

## 6. Common Pitfalls

- **Borrowing/Lifetimes**: Understand ownership rules, annotate lifetimes when needed
- **Move semantics**: Data moves by default in Rust, not copied
- **Integer overflow**: Use checked arithmetic in security-critical contexts
- **Unicode handling**: Be careful with string operations across platforms
- **File paths**: Use `std::path` for cross-platform compatibility
- **Concurrency**: Avoid data races and deadlocks with proper synchronization

## 7. Tooling and Environment

### 7.1. Required Development Tools
- `rustup` - Toolchain management
- `cargo` - Package manager and build tool
- `rust-analyzer` - IDE support (VS Code/Cursor)
- `clippy` - Linter for common mistakes
- `rustfmt` - Code formatter
- `cargo-audit`, `cargo-deny` - Security auditing
- `cargo-geiger` - Unsafe code tracking
- `lldb`/`gdb` - Debugging
- `cargo-flamegraph` - Performance profiling

### 7.2. Build Configuration
```toml
[package]
edition = "2024"
rust-version = "1.93"

[profile.release]
opt-level = 3
lto = true
debug = false
strip = true
```

### 7.3. Local validation cycle (before hand-off)

Mirror CI locally. Prefix diagnostics with `rtk` (`rtk-proxy.mdc`).
Full definition of done: `quality-assurance` skill §0 and
`.cursor/rules/dev-validation-cycle.mdc`.

**Clippy is not optional.** After every significant Rust edit, run
clippy on the touched crate **before** claiming done. `cargo test`
and `cargo check` never substitute for it.

```shell
rtk cargo fmt --all
# REQUIRED -- same turn as the edit (focused crate is enough mid-task):
rtk cargo clippy -p <crate> --all-targets -- -D warnings
# before hand-off / when blast radius is unclear:
rtk cargo clippy --workspace --all-targets -- -D warnings
rtk cargo clippy --manifest-path vauban-proxy-rdp/Cargo.toml --target-dir target --all-targets -- -D warnings
# plus relevant vauban-*/scripts/check_*.sh for the touched surface
# THEN tests -- mandatory after clippy/lints on every significant edit
rtk cargo test -p <crate> -- <filter> -- --test-threads=1
rtk cargo test --workspace -- --test-threads=1
rtk cargo test --manifest-path vauban-proxy-rdp/Cargo.toml --target-dir target -- --test-threads=1
rtk cargo audit   # when deps changed
rtk cargo deny check
```

Clippy warnings are blocking (`-D warnings`). Do not ship with
`too_many_arguments`, `unnecessary_min_or_max`, `unwrap_used`, or
other Clippy hits "to fix later". Prefer bundling deps in a `Ctx`
struct over `#[allow(clippy::too_many_arguments)]`.

**After a significant Rust change, do not stop once clippy and
`check_*.sh` are green** -- run the focused tests for that change in
the same turn, then the full two-command gate before hand-off.
**Symmetrically: do not stop once tests are green without clippy.**

### 7.4. CI/CD Pipeline
```shell
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo audit
cargo deny check
```

- **Target platform**: FreeBSD (use `vmactions/freebsd-vm` for GitHub Actions CI)
- **Deployment**: Ansible preferred (avoid Docker for security reasons)
- **Linking**: Static linking preferred for single binary deployment
- **Process manager**: Configure for automatic restart on FreeBSD

## Security Checklist Summary

**Cryptography:**
- [ ] Hybrid PQ schemes (ML-KEM+X25519, ML-DSA+Ed25519)
- [ ] No RSA/ECDSA/MD5/SHA1 in codebase
- [ ] Constant-time comparisons for secrets
- [ ] All secrets zeroized after use

**Network / TLS:**
- [ ] Public edge HTTPS-only, TLS 1.3 minimum (`tls-post-quantum.mdc`)
- [ ] rustls preferred; OpenSSL denied by default
- [ ] Hybrid PQ TLS groups enabled when the pinned stack supports them
- [ ] Outbound TLS verifies certificates
- [ ] Timeouts, input size limits, rate limiting on sensitive routes
- [ ] No WebSocket product endpoints

**Secrets:**
- [ ] `Secret<T>` wrapper used
- [ ] Debug/Display redacted
- [ ] Never logged or serialized

**Dependencies:**
- [ ] `cargo audit` clean
- [ ] `cargo deny` configured (incl. OpenSSL ban)
- [ ] Minimal dependency tree

**Assets:**
- [ ] Assets declared via Topcoat `asset!` / bundler (no ad-hoc path serving)
- [ ] No runtime filesystem reads for user-served content