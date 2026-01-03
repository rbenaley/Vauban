# Configuration Example

Copy these variables to your `.env` file:

```bash
# Environment
ENVIRONMENT=development

# Secret Key (generate a secure random key for production)
SECRET_KEY=change-me-in-production-use-a-secure-random-key

# Database
DATABASE_URL=postgresql://vauban:vauban@localhost/vauban
DATABASE_MAX_CONNECTIONS=10
DATABASE_MIN_CONNECTIONS=2
DATABASE_CONNECT_TIMEOUT=10

# Cache (Valkey/Redis) - OPTIONAL
# Set CACHE_ENABLED=false to disable cache (useful for development without Redis)
# If disabled or unavailable, a mock cache (no-op) will be used automatically
CACHE_ENABLED=false
CACHE_URL=redis://localhost:6379
CACHE_TTL_SECS=3600

# Server
SERVER_HOST=0.0.0.0
SERVER_PORT=8000
SERVER_WORKERS=

# JWT
JWT_ACCESS_LIFETIME_MINUTES=15
JWT_REFRESH_LIFETIME_DAYS=1
JWT_ALGORITHM=HS256

# gRPC Services
GRPC_RBAC_URL=http://localhost:50052
GRPC_VAULT_URL=http://localhost:50053
GRPC_AUTH_URL=http://localhost:50051
GRPC_PROXY_SSH_URL=http://localhost:50054
GRPC_PROXY_RDP_URL=http://localhost:50055
GRPC_AUDIT_URL=http://localhost:50056

# mTLS (Production only)
MTLS_ENABLED=false
MTLS_CA_CERT=
MTLS_CLIENT_CERT=
MTLS_CLIENT_KEY=

# Security
PASSWORD_MIN_LENGTH=12
MAX_FAILED_LOGIN_ATTEMPTS=5
SESSION_MAX_DURATION_SECS=28800
SESSION_IDLE_TIMEOUT_SECS=1800
RATE_LIMIT_PER_MINUTE=100
```

## Cache Configuration

The cache can be disabled for development:

- **`CACHE_ENABLED=false`**: Disables the cache, uses a mock (no-op)
- **`CACHE_ENABLED=true`** or undefined: Enables the cache, attempts to connect to Redis/Valkey
- If Redis/Valkey is unavailable even with `CACHE_ENABLED=true`, the application automatically falls back to the mock cache with a warning

This allows development without needing Redis/Valkey installed locally.
