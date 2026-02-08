# VAUBAN Vault

Cryptographic secrets management service for the VAUBAN security bastion platform. Provides encryption-at-rest for TOTP secrets, SSH credentials and more via IPC.

## Features

- **AES-256-GCM Encryption**: Authenticated encryption for all secrets stored in the database
- **HKDF-SHA3-256 Key Derivation**: PQC-aligned key derivation with domain separation and versioning
- **TOTP Management**: Generate, encrypt, and verify MFA secrets entirely within the vault (plaintext never leaves the process)
- **Versioned Key Rotation**: Seamless key rotation with backward-compatible decryption
- **Zero-Copy Secrets**: All key material is zeroized on drop via `zeroize` crate
- **Capsicum Sandboxing**: No filesystem, no network, no database access after startup

## Architecture

`vauban-vault` is a **synchronous, stateless, in-memory** cryptographic service:

- No async runtime (no `tokio`)
- No database (no `diesel`, no `sqlx`)
- No network access (no `reqwest`, no `hyper`)
- `poll(2)`-based event loop on Unix pipes
- Master key read from file once at startup, then sandboxed

See [Vauban_Vault_Architecture_EN(1.0).md](../docs/technical/Vauban_Vault_Architecture_EN(1.0).md) for the full design document.

## Prerequisites

- Rust 1.89+ (edition 2024)
- FreeBSD (for Capsicum sandbox in production) or Linux/macOS (development)

## Setup

### 1. Generate the Master Key

The master key is a 32-byte (256-bit) random key used to derive all encryption keys. It must be generated **once** and stored securely.

**Production (FreeBSD):**

```bash
# Create the vault directory
sudo mkdir -p /var/vauban/vault
sudo chown root:vauban /var/vauban/vault
sudo chmod 750 /var/vauban/vault

# Generate a 32-byte master key from the OS CSPRNG
dd if=/dev/random of=/var/vauban/vault/master.key bs=32 count=1

# Restrict permissions: readable only by root and the vauban group
sudo chown root:vauban /var/vauban/vault/master.key
sudo chmod 440 /var/vauban/vault/master.key
```

**Development (macOS/Linux):**

```bash
# Create a local master key for development
mkdir -p /var/vauban/vault
dd if=/dev/urandom of=/var/vauban/vault/master.key bs=32 count=1
chmod 400 /var/vauban/vault/master.key
```

Or use a custom path:

```bash
dd if=/dev/urandom of=./master.key bs=32 count=1
chmod 400 ./master.key
export VAUBAN_VAULT_MASTER_KEY_PATH=./master.key
```

### 2. Set the Key Version (Optional)

The key version file determines how many derived key versions are maintained. Version 1 is the default. Increment this when rotating keys.

```bash
echo "1" | sudo tee /var/vauban/vault/key_version
sudo chown root:vauban /var/vauban/vault/key_version
sudo chmod 440 /var/vauban/vault/key_version
```

Or via environment variable:

```bash
export VAUBAN_VAULT_KEY_VERSION=1
```

### 3. Verify the Setup

```bash
# Check the master key is exactly 32 bytes
wc -c /var/vauban/vault/master.key
# Expected output: 32 /var/vauban/vault/master.key

# Check permissions (should be 440 or 400)
ls -la /var/vauban/vault/master.key
# Expected: -r--r----- 1 root vauban 32 ... master.key
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VAUBAN_VAULT_MASTER_KEY_PATH` | `/var/vauban/vault/master.key` | Path to the 32-byte master key file |
| `VAUBAN_VAULT_KEY_VERSION` | Read from file, or `1` | Current key version (integer >= 1) |
| `VAUBAN_VAULT_KEY_VERSION_PATH` | `/var/vauban/vault/key_version` | Path to the key version file |
| `VAUBAN_IPC_READ` | `0` | Supervisor IPC read file descriptor |
| `VAUBAN_IPC_WRITE` | `1` | Supervisor IPC write file descriptor |
| `VAUBAN_WEB_IPC_READ` | _(optional)_ | Web service IPC read file descriptor |
| `VAUBAN_WEB_IPC_WRITE` | _(optional)_ | Web service IPC write file descriptor |

All environment variables are **cleared from memory** immediately after reading (before entering the Capsicum sandbox).

### File Layout (Production)

```
/var/vauban/vault/
    master.key      # 32 bytes, chmod 440, root:vauban
    key_version     # Text file containing "1" (or higher), chmod 440
```

## Running

`vauban-vault` is designed to run under `vauban-supervisor`, which manages IPC pipes and process lifecycle. It should not be run standalone in production.

**Under supervisor (production):**

The supervisor automatically sets up IPC file descriptors and starts the vault process. No manual intervention needed.

**Standalone (development/testing):**

```bash
# Generate a test master key
dd if=/dev/urandom of=./test-master.key bs=32 count=1

# Run with custom paths
VAUBAN_VAULT_MASTER_KEY_PATH=./test-master.key cargo run -p vauban-vault
```

Note: Without the supervisor providing IPC pipes, the vault will start but won't receive any messages.

## Cryptographic Design

### Key Hierarchy

```
master.key (32 bytes, read from file)
    |
    +-- HKDF-SHA3-256(info="vauban-mfa-v1")        --> AES-256-GCM key for MFA secrets
    +-- HKDF-SHA3-256(info="vauban-mfa-v2")        --> AES-256-GCM key for MFA (after rotation)
    +-- HKDF-SHA3-256(info="vauban-credentials-v1") --> AES-256-GCM key for SSH credentials
    +-- ...
```

### Ciphertext Format

All encrypted values are stored as:

```
v{VERSION}:{BASE64(NONCE || CIPHERTEXT || TAG)}
```

Example: `v1:SGVsbG8gV29ybGQ=`

- **VERSION**: Key version used for encryption (integer)
- **NONCE**: 12-byte random nonce (from OsRng)
- **CIPHERTEXT**: AES-256-GCM encrypted data
- **TAG**: 16-byte GCM authentication tag

### Domains

| Domain | Purpose | Typical Data |
|--------|---------|--------------|
| `mfa` | TOTP secrets | Base32-encoded TOTP seeds (~32 chars) |
| `credentials` | SSH/RDP credentials | Passwords, private keys, passphrases |

## Key Rotation

To rotate keys:

1. Increment the key version:
   ```bash
   echo "2" | sudo tee /var/vauban/vault/key_version
   ```

2. Restart the vault service. The new version is used for all new encryptions.

3. Old ciphertexts (prefixed `v1:`) remain decryptable -- the vault maintains all key versions from 1 to N.

4. Optionally, re-encrypt existing data using the `rewrap` operation to upgrade all ciphertexts to the latest version.

## Testing

```bash
# Run all vault unit tests (43 tests)
cargo test -p vauban-vault

# Run only crypto tests
cargo test -p vauban-vault crypto

# Run only keyring tests
cargo test -p vauban-vault keyring

# Run only transit (IPC handler) tests
cargo test -p vauban-vault transit

# Run structural security regression tests
cargo test -p vauban-web --test integration_tests -- test_vault
```

### Test Coverage

- **crypto.rs**: AES-256-GCM roundtrip, nonce uniqueness, wrong key, tampered data/nonce, empty/large plaintext
- **keyring.rs**: HKDF determinism, domain/version separation, encrypt/decrypt, old version decrypt, rewrap, cross-domain isolation, `VARCHAR(255)` budget, debug redaction
- **transit.rs**: Encrypt/decrypt roundtrip, MFA generate/verify/QR, secret never in plaintext, unknown domain, missing keyring
- **main.rs**: Control messages (ping/pong, drain), vault encrypt/decrypt via IPC, MFA generate via IPC, legacy message handling

## Security

- **No `unwrap()` in production code paths** (enforced by `#[warn(clippy::unwrap_used)]`)
- **Master key zeroized on drop** (`MasterKey` implements `Drop` with `zeroize()`)
- **Derived keys zeroized on drop** (`Keyring` implements `Drop` with key material zeroization)
- **Plaintext zeroized after every operation** (in `transit.rs` handlers)
- **Debug output redacted** (`MasterKey` and `SensitiveString` show `[REDACTED]`)
- **No network, no filesystem, no database** after Capsicum sandbox entry
- **HKDF-SHA3-256** for PQC-aligned key derivation
- **OsRng** for nonce generation (arc4random on FreeBSD)

## License

BSD-2-Clause
