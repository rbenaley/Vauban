# VAUBAN Web (Rust)

Web interface and API for the VAUBAN security bastion platform, built with Rust using Axum, Diesel, and Askama.

## Features

- **Secure Authentication**: JWT-based authentication with MFA (TOTP) support
- **RBAC Integration**: Role-based access control via gRPC service
- **Asset Management**: Manage SSH, RDP, and VNC assets
- **Session Management**: Track and monitor proxy sessions
- **Post-Quantum Cryptography**: Hybrid classical + PQ crypto support
- **Type Safety**: Compile-time verified SQL queries (Diesel) and templates (Askama)

## Technology Stack

- **Web Framework**: Axum
- **Database**: PostgreSQL 18+ with Diesel ORM
- **Cache**: Valkey/Redis
- **Templates**: Askama (compile-time verified)
- **gRPC**: Tonic with mTLS support
- **Authentication**: JWT, Argon2id, TOTP

## Prerequisites

- Rust 1.92+ (edition 2024)
- PostgreSQL 18+
- Valkey/Redis (optional - for caching, can be disabled for development)

## Configuration

Configuration is managed through TOML files in the `config/` directory:

```
config/
├── default.toml      # Default values for all environments
├── development.toml  # Development environment overrides
├── testing.toml      # Testing environment overrides
├── production.toml   # Production environment overrides (template)
└── local.toml        # Local overrides (not versioned, create manually)
```

### Environment Selection

Set the environment via `VAUBAN_ENVIRONMENT`:

```bash
export VAUBAN_ENVIRONMENT=development  # or: testing, production
```

### Secret Key

For production, set the secret key via environment variable:

```bash
export VAUBAN_SECRET_KEY=`openssl rand -base64 32`
```

Or create a `config/local.toml` file (gitignored):

```toml
secret_key = "your-secure-random-key-here"
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

## Running

Development:
```bash
cargo run
```

Production:
```bash
cargo build --release
./target/release/vauban-web
```

## API Endpoints

### Authentication
- `POST /api/auth/login` - Login
- `POST /api/auth/logout` - Logout
- `POST /api/auth/mfa/setup` - Setup MFA

### Accounts
- `GET /api/v1/accounts` - List users
- `POST /api/v1/accounts` - Create user
- `GET /api/v1/accounts/:uuid` - Get user
- `PUT /api/v1/accounts/:uuid` - Update user

### Assets
- `GET /api/v1/assets` - List assets
- `POST /api/v1/assets` - Create asset
- `GET /api/v1/assets/:uuid` - Get asset
- `PUT /api/v1/assets/:uuid` - Update asset

### Sessions
- `GET /api/v1/sessions` - List sessions
- `POST /api/v1/sessions` - Create session
- `GET /api/v1/sessions/:uuid` - Get session

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
cargo test

# Run unit tests only
cargo test --lib

# Run integration tests only
cargo test --test '*'

# Run specific test file
cargo test --test auth_test

# Run tests with output
cargo test -- --nocapture

# Run tests sequentially (required for DB tests)
cargo test -- --test-threads=1

# Run security tests only
cargo test --test security_test
```

### Test Coverage

- **Unit Tests**: Services (auth, hash, JWT, TOTP), Models, Config, Error handling
- **Integration Tests**: All API handlers, Database operations
- **Security Tests**: Brute force protection, SQL injection, XSS prevention, Input validation

## Security

This application follows strict security practices:

- No `unwrap()` in production code paths
- All user input validated with `validator` crate
- Secrets managed with `secrecy` and `zeroize`
- Post-quantum cryptography ready
- mTLS for gRPC communication
- Comprehensive audit logging

## License

BSD-2-Clause

