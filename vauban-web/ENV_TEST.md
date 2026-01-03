# Test Environment Configuration

This file documents the environment variables needed for running tests.

## Setup

1. Create a `.env.test` file (gitignored) with the following content:

```bash
# Test environment configuration for vauban-web
DATABASE_URL=postgresql://vauban_test:vauban_test@localhost/vauban_test
SECRET_KEY=test-secret-key-for-testing-only-32chars
ENVIRONMENT=testing
CACHE_ENABLED=false

# Server configuration
SERVER_HOST=127.0.0.1
SERVER_PORT=8001

# JWT configuration
JWT_ACCESS_LIFETIME_MINUTES=15
JWT_REFRESH_LIFETIME_DAYS=1
JWT_ALGORITHM=HS256

# Security configuration
PASSWORD_MIN_LENGTH=12
MAX_FAILED_LOGIN_ATTEMPTS=5
SESSION_MAX_DURATION_SECS=28800
SESSION_IDLE_TIMEOUT_SECS=1800
RATE_LIMIT_PER_MINUTE=100
```

2. Run the database setup script:

```bash
chmod +x scripts/setup_test_db.sh
./scripts/setup_test_db.sh
```

3. Export environment variables and run tests:

```bash
export DATABASE_URL=postgresql://vauban_test:vauban_test@localhost/vauban_test
export SECRET_KEY=test-secret-key-for-testing-only-32chars
cargo test
```

## Test Commands

```bash
# Run all tests
cargo test

# Run unit tests only
cargo test --lib

# Run integration tests only
cargo test --test '*'

# Run a specific test file
cargo test --test auth_test

# Run tests with output
cargo test -- --nocapture

# Run tests in sequence (required for DB tests)
cargo test -- --test-threads=1
```

