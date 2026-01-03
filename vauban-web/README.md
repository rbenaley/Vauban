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

Copy `.env.example` to `.env` and configure:

```bash
ENVIRONMENT=development
SECRET_KEY=your-secret-key-here
DATABASE_URL=postgresql://user:password@localhost/vauban

# Cache (optional - set to false to disable, useful for development)
CACHE_ENABLED=false
CACHE_URL=redis://localhost:6379
CACHE_TTL_SECS=3600
```

**Note**: If `CACHE_ENABLED=false` or if Valkey/Redis is unavailable, the application will automatically use a mock (no-op) cache that allows development without external dependencies.

## Database Setup

1. Create the database:
```bash
createdb vauban
```

2. Run migrations:
```bash
diesel migration run
```

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

