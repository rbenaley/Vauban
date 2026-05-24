# Vauban

**A fortified bastion for privileged access management, built in Rust.**

Vauban is an open-source security bastion, developed in Rust, designed to protect and control access to critical infrastructure across enterprise, industrial, and defense environments. Its architecture leverages proven, cutting-edge technologies: privilege separation inspired by OpenSSH and Capsicum sandboxing, a confinement mechanism developed with funding from DARPA (U.S. Department of Defense). The solution includes multi-factor authentication (MFA), role-based access control (RBAC), full session recording, and real-time monitoring of SSH and RDP connections. Free and sovereignty-friendly, Vauban meets the traceability and audit requirements of sensitive environments while offering an open-source alternative to proprietary solutions.

## Project Structure

```
vauban-supervisor/    # Process orchestrator, watchdog, signal handling
vauban-web/           # HTTPS server, REST API, WebSocket handlers, frontend
vauban-auth/          # Authentication, MFA, SSO, LDAP integration
vauban-access/        # Access control, groups, and instance-level authorization (Casbin)
vauban-vault/         # Secrets management, encryption/decryption service
vauban-audit/         # Audit logging, session recording
vauban-proxy-ssh/     # SSH protocol proxy (russh)
vauban-proxy-rdp/     # RDP protocol proxy (IronRDP, H.264 encoding)
vauban-proxy-iacs/    # Industrial Automation and Control Systems (IACS) protocols proxy
vauban-db/            # Shared Diesel schema, migrations, table relationships
shared/               # IPC protocol, message types, common utilities
config/               # TOML configuration files
docs/                 # Technical architecture documentation
```

## Features

- **Secure Authentication**: JWT-based authentication with MFA (TOTP) support
- **RBAC Integration**: Role-based access control via IPC
- **Asset Management**: Manage SSH and RDP assets
- **Session Management**: Track and monitor proxy sessions
- **Post-Quantum Cryptography**: Hybrid classical + PQ crypto support
- **Type Safety**: Compile-time verified SQL queries (Diesel) and templates (Askama)

## Technology Stack

- **Web Framework**: Axum
- **Database**: PostgreSQL with Diesel ORM
- **Cache**: Valkey/Redis
- **Templates**: Askama (compile-time verified)
- **IPC**: Unix pipes for inter-service communication
- **Authentication**: JWT, Argon2id, TOTP

## Security

This application follows strict security practices:

- No `unwrap()` in production code paths
- All user input validated with `validator` crate
- Secrets managed with `secrecy` and `zeroize`
- Post-quantum cryptography ready
- Privilege separation via Unix pipes IPC
- Comprehensive audit logging

## Documentation

Detailed technical architecture documents are available in [`docs/technical/`](docs/technical/):

| Document | Description |
|----------|-------------|
| [Privilege Separation Architecture](docs/technical/Vauban_Privsep_Architecture_EN(1.2).md) | Process model, IPC protocol, Capsicum sandboxing, supervisor design |
| [Vault Architecture](docs/technical/Vauban_Vault_Architecture_EN(1.0).md) | Cryptographic design, key management, threat model |
| [RDP Session Architecture](docs/technical/Vauban_RDP_Architecture_EN(1.0).md) | H.264 encoding, WebCodecs decoding, dynamic resolution, input pipeline |
| [OpenH264 AVX2 Optimizations](docs/technical/Vauban_OpenH264_AVX2_Optimizations_EN(1.0).md) | Custom AVX2 assembly for SAD and intra prediction (~50% CPU reduction) |
| [ACME TLS Certificate Architecture](docs/technical/Vauban_ACME_TLS_Architecture_EN(1.0).md) | Automatic certificate renewal, TLS-ALPN-01, zero-downtime rotation |
| [Session Recording Architecture](docs/technical/Vauban_Recording_Architecture_EN(1.5).md) | RDP segmented fMP4 + SSH asciicast v2 + IACS PCAP bundle (`pcap-bundle`) with synthetic L3/L4 (Wireshark-compatible), input redaction, DASH/asciinema playback, ZIP download |
| [IAM Architecture](docs/technical/Vauban_IAM_Architecture_EN(1.0).md) | Two-layer authorization (Casbin RBAC + instance-level access rules), Argon2id auth service, JIT approval audit & separation of duties |
| [AccessGuard Architecture](docs/technical/Vauban_AccessGuard_Architecture_EN(1.0).md) | Shared `shared::access_guard` defense-in-depth RBAC re-check gate (fail-closed, 10s timeout, RAII pending-map) |
| [IACS Proxy Architecture](docs/technical/Vauban_IACS_Proxy_Architecture_EN(1.0).md) | EWS-facing russh sshd, per-asset target resolution, Capsicum-aware FD passing (listener + Ed25519 host key), anti-SSRF supervisor broker, BLAKE3 session-token gate |
| [IACS Inspect Capture](docs/technical/Vauban_IACS_Inspect_Capture_EN(1.0).md) | Admin-only inline PCAP analyzer for IACS recordings: industrial-protocol-aware dissectors (Modbus/TCP, IEC-104, passthrough), tree<->hex bidirectional highlight, server-rendered HTMX + Tailwind, no inline JavaScript |

## Security Model

Vauban's security is built on defense in depth:

1. **Process isolation**: Each service runs under a dedicated UID with no shared memory
2. **Capsicum confinement**: After initialization, processes cannot open files, create sockets, or access the filesystem
3. **Credential isolation**: Encryption keys are confined to `vauban-vault`; secrets are encrypted at rest in PostgreSQL and only decrypted transiently for session establishment, wrapped in zeroize-on-drop memory
4. **Network brokering**: Sandboxed proxies cannot establish TCP connections directly; the supervisor brokers all outbound connections via `SCM_RIGHTS` file descriptor passing
5. **Memory safety**: Rust's ownership model prevents buffer overflows, use-after-free, and data races
6. **Secret hygiene**: Environment variables destroyed after reading, `SensitiveString` zeroized on drop

## Building

### Prerequisites

- Rust 1.89+ (edition 2024)
- [just](https://github.com/casey/just) command runner
- NASM (for OpenH264 assembly compilation)
- PostgreSQL 18+
- Valkey/Redis (optional - for caching, can be disabled for development)
- FreeBSD (for Capsicum sandbox; builds on macOS/Linux without sandboxing)

### Build

```bash
# Build all crates (debug)
just build

# Build release binaries (optimized, LTO, stripped)
just build --release

# Run all tests
just test

# Run clippy lints
just clippy
```

### Run

```bash
# Start all services via the supervisor
cargo run
```

The supervisor reads `config/default.toml`, forks all 7 child processes, sets up IPC pipes, drops privileges, and enters the watchdog loop.

## Configuration

VAUBAN uses two distinct configuration strategies depending on how the binary
is compiled. The build profile (`--release` or not) determines the behavior
**at compile time** -- there is no runtime switch.

### Build Profiles

| | Debug (`just build`) | Release (`just build --release`) |
|---|---|---|
| **Environment** | Configurable via `VAUBAN_ENVIRONMENT` | Always **Production** |
| **Default env** | `development` | `production` |
| **`VAUBAN_ENVIRONMENT`** | Functional | **Ignored** (not compiled in) |
| **Config files** | `default.toml` + `{env}.toml` + `local.toml` | `vauban.conf` only |
| **Config directory** | `config/` (workspace root) | `/usr/local/etc/vauban/` |

### Debug Build (Development)

Configuration files are layered in this order:

```
config/
├── default.toml      # Base values shared across environments
├── development.toml  # Development overrides (default)
├── testing.toml      # Testing overrides (cargo test)
└── local.toml        # Personal overrides (gitignored, optional)
```

You can switch the environment with `VAUBAN_ENVIRONMENT`:

```bash
export VAUBAN_ENVIRONMENT=development  # default when absent
export VAUBAN_ENVIRONMENT=testing      # used by cargo test
export VAUBAN_ENVIRONMENT=production   # loads vauban.conf even in debug
```

### Release Build (Production)

The release binary loads a **single** self-contained configuration file:

```
/usr/local/etc/vauban/vauban.conf
```

`VAUBAN_ENVIRONMENT` is compiled out and has no effect. This guarantees that
a production binary always runs in production mode, regardless of the
runtime environment.

### Configuration Directory Lookup

Both profiles search for the config directory in this order:

1. `VAUBAN_CONFIG_DIR` environment variable (if set)
2. Workspace root `config/` directory (via `CARGO_MANIFEST_DIR`)
3. `/usr/local/etc/vauban/` (FreeBSD system path)

### Secret Key

The application secret key can be set in three ways (highest priority first):

1. **Environment variable** (cleared from memory after reading):
```bash
export VAUBAN_SECRET_KEY=$(openssl rand -base64 32)
```

2. **`local.toml`** (debug builds, gitignored):
```toml
secret_key = "your-secure-random-key-here"
```

3. **`vauban.conf`** (release builds, managed by `+POST_INSTALL`):
```toml
secret_key = "generated-at-install-time"
```

### Cache

Cache can be disabled for development in the TOML config:

```toml
[cache]
enabled = false
```

**Note**: If cache is disabled or Valkey/Redis is unavailable, the application automatically uses a mock (no-op) cache.

## Database Setup

1. Install Diesel CLI:
```bash
cargo install diesel_cli --no-default-features --features postgres
```

2. Create the database:
```bash
createdb vauban
psql -c "CREATE USER vauban WITH PASSWORD 'vauban';"
psql -c "GRANT ALL PRIVILEGES ON DATABASE vauban TO vauban;"
psql -U postgres -d vauban -c "GRANT ALL ON SCHEMA public TO vauban; ALTER SCHEMA public OWNER TO vauban;"
```

3. Run migrations:
```bash
diesel migration run --database-url postgresql://vauban:vauban@localhost/vauban
```

**Note**: Database URL is configured in `config/default.toml`. Adjust credentials as needed.

## CLI Utilities

VAUBAN CLI administration is centralized in the supervisor binary.
All utilities load their database configuration from `config/*.toml` (same as the main application).

### Create Superuser

Create the initial superuser account:

```bash
# Production (release binary)
vauban-supervisor create-superuser

# Development (supervisor is default-members)
cargo run -- create-superuser
```

### Reset Password

Reset a user's password:

```bash
# Production
vauban-supervisor reset-password <username>

# Development
cargo run -- reset-password <username>
```

### Reset 2FA

Disable two-factor authentication for a user (the only way to disable MFA):

```bash
# Production
vauban-supervisor reset-2fa <username>

# Development
cargo run -- reset-2fa <username>
```

### Seed Data

Populate the database with sample data for development:

```bash
# Production
vauban-supervisor seed-data

# Development
cargo run -- seed-data
```

### Migrate Secrets

Batch-encrypt all plaintext secrets in the database using vauban-vault's keyring.
This tool encrypts TOTP secrets and SSH credentials that would otherwise be stored in plaintext.

```bash
# Preview what would be migrated (no changes made)
vauban-supervisor migrate-secrets --dry-run
# or in development:
cargo run -- migrate-secrets --dry-run

# Run the migration
vauban-supervisor migrate-secrets
# or in development:
cargo run -- migrate-secrets
```

**Prerequisites**:
- The master key must be available at `/var/vauban/vault/master.key` (or set `VAUBAN_VAULT_MASTER_KEY_PATH`)
- The key version file at `/var/vauban/vault/key_version` (optional, defaults to 1)

**Environment variables**:

| Variable | Default | Description |
|----------|---------|-------------|
| `VAUBAN_VAULT_MASTER_KEY_PATH` | `/var/vauban/vault/master.key` | Path to the 32-byte master key |
| `VAUBAN_VAULT_KEY_VERSION` | Read from file | Override key version (must be >= 1) |
| `VAUBAN_VAULT_KEY_VERSION_PATH` | `/var/vauban/vault/key_version` | Path to key version file |

The tool is **idempotent**: already-encrypted values (`v{N}:...` format) are skipped automatically.
The `--dry-run` flag is recommended before any production migration.

**What it migrates**:
- `users.mfa_secret` - TOTP secrets
- `assets.connection_config` - Credential fields: `password`, `private_key`, `passphrase`

> **Note**: Encrypt-on-read is also built into the application itself. When a user logs in
> with a plaintext MFA secret, it is automatically encrypted and updated in the database.
> The `migrate-secrets` subcommand is useful for bulk migration of all secrets at once.

## API Endpoints

### Authentication
- `POST /api/v1/auth/login` - Login
- `POST /api/v1/auth/logout` - Logout

### Accounts
- `GET /api/v1/accounts` - List users
- `POST /api/v1/accounts` - Create user
- `GET /api/v1/accounts/:uuid` - Get user
- `PUT /api/v1/accounts/:uuid` - Update user
- `DELETE /api/v1/accounts/:uuid` - Delete user (501 Not Implemented)

### Groups (Read-Only)
- `GET /api/v1/groups/:uuid/members` - List group members

### Assets
- `GET /api/v1/assets` - List assets
- `POST /api/v1/assets` - Create asset
- `GET /api/v1/assets/:uuid` - Get asset
- `PUT /api/v1/assets/:uuid` - Update asset
- `DELETE /api/v1/assets/:uuid` - Delete asset (501 Not Implemented)

### SSH Host Key Verification (SSH assets only)
- `GET /api/v1/assets/:uuid/ssh-host-key` - Get host key status (`verified`, `mismatch`, or `no_key`)
- `POST /api/v1/assets/:uuid/ssh-host-key` - Fetch host key from remote server (detects key changes)
- `POST /api/v1/assets/:uuid/ssh-host-key?confirm=true` - Accept a changed host key

### Asset Groups (Read-Only)
- `GET /api/v1/assets/groups` - List asset groups
- `GET /api/v1/assets/groups/:uuid/assets` - List assets in a group

### Access Rules
- `GET /api/v1/access-rules` - List access rules
- `POST /api/v1/access-rules` - Create access rule
- `GET /api/v1/access-rules/:uuid` - Get access rule
- `PUT /api/v1/access-rules/:uuid` - Update access rule
- `DELETE /api/v1/access-rules/:uuid` - Delete access rule

### Sessions
- `GET /api/v1/sessions` - List sessions
- `POST /api/v1/sessions` - Create session
- `GET /api/v1/sessions/:uuid` - Get session
- `POST /api/v1/sessions/:id/terminate` - Terminate session
- `DELETE /api/v1/sessions/:uuid` - Delete session (501 Not Implemented)

## Testing

The project includes comprehensive tests following Rust best practices.

### Test Structure

```
tests/
├── common/
│   └── mod.rs           # Test utilities and fixtures
├── auth_test.rs         # Authentication integration tests
├── accounts_test.rs     # User management tests
├── assets_test.rs       # Asset management tests
├── sessions_test.rs     # Session management tests
├── middleware_test.rs   # Middleware tests
└── security/
    ├── mod.rs
    ├── auth_security.rs     # Authentication security tests
    ├── access_control.rs    # Access control tests
    └── input_validation.rs  # Input validation tests
```

### Setting Up Test Database

1. Run the setup script:
```bash
chmod +x scripts/setup_test_db.sh
./scripts/setup_test_db.sh
```

Or manually:
```bash
createdb vauban_test
psql -c "CREATE USER vauban_test WITH PASSWORD 'vauban_test';"
psql -c "GRANT ALL PRIVILEGES ON DATABASE vauban_test TO vauban_test;"
psql -U postgres -d vauban_test -c "GRANT ALL ON SCHEMA public TO vauban_test; ALTER SCHEMA public OWNER TO vauban_test;"
diesel migration run --database-url postgresql://vauban_test:vauban_test@localhost/vauban_test
```

**Note**: Test configuration is in `config/testing.toml`. No environment variables needed.

### Running Tests

```bash
# Run all tests
just test

# Run unit tests only
just test --lib

# Run integration tests only
just test --test integration_tests

# Run specific test file
just test --test auth_test

# Run tests with output
just test -- --nocapture

# Run security tests only
just test --test security_test
```

### Test Coverage

- **Unit Tests**: Services (auth, hash, JWT, TOTP), Models, Config, Error handling
- **Integration Tests**: All API handlers, Database operations
- **Security Tests**: Brute force protection, SQL injection, XSS prevention, Input validation

## License

BSD 2-Clause License. See [LICENSE](LICENSE) for details.

## Author

Richard Ben Aleya
