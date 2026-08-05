#!/bin/bash
# Setup PostgreSQL database for VCP automated tests (vcp_test).
#
# Prerequisites:
#   - PostgreSQL server running
#   - Superuser access as postgres over the Unix-domain socket (password via
#     PGPASSWORD, VCP_PG_ADMIN_PASSWORD, or ~/.pgpass). Override user with
#     VCP_PG_ADMIN_USER if needed.
#
# Connections use the local Unix socket only (no TCP / no -h hostname).
# Optional: PGHOST=/path/to/socketdir to select a non-default socket directory.
#
# Usage:
#   ./scripts/setup_test_db.sh
#   just db-create-test
#   PGPASSWORD=… just db-create-test

set -euo pipefail

DB_NAME="vcp_test"
DB_USER="vcp_test"
DB_PASSWORD="vcp_test"

# Admin connection for CREATE ROLE / DATABASE (FreeBSD staging has no OS-user role).
ADMIN_USER="${VCP_PG_ADMIN_USER:-postgres}"
if [[ -n "${VCP_PG_ADMIN_PASSWORD:-}" ]]; then
    export PGPASSWORD="$VCP_PG_ADMIN_PASSWORD"
fi

# libpq: hostname => TCP; absolute path => socket dir; unset => default socket.
if [[ -n "${PGHOST:-}" && "${PGHOST}" != /* ]]; then
    echo "warning: ignoring PGHOST=${PGHOST} (TCP); using Unix-domain socket" >&2
    unset PGHOST
fi

export PGUSER="$ADMIN_USER"

psql_admin() {
    psql -U "$ADMIN_USER" "$@"
}

echo "=== Setting up test database for VCP ==="
echo "Admin: $ADMIN_USER via Unix socket"

if psql_admin -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
    echo "Database $DB_NAME already exists."
else
    echo "Creating database $DB_NAME..."
    createdb -U "$ADMIN_USER" "$DB_NAME"
fi

if psql_admin -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" | grep -q 1; then
    echo "User $DB_USER already exists."
else
    echo "Creating user $DB_USER..."
    psql_admin -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';"
fi

echo "Granting privileges..."
psql_admin -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"
psql_admin -d "$DB_NAME" -c "GRANT ALL ON SCHEMA public TO $DB_USER;"
psql_admin -d "$DB_NAME" -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO $DB_USER;"
psql_admin -d "$DB_NAME" -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO $DB_USER;"

# Ownership helps Toasty migrations on a fresh DB created by another role.
psql_admin -d "$DB_NAME" -c "ALTER DATABASE $DB_NAME OWNER TO $DB_USER;" 2>/dev/null || true
psql_admin -d "$DB_NAME" -c "ALTER SCHEMA public OWNER TO $DB_USER;" 2>/dev/null || true

echo ""
echo "=== Test database setup complete ==="
echo ""
echo "App URL (config/testing.toml, TCP):"
echo "  postgresql://$DB_USER:$DB_PASSWORD@localhost/$DB_NAME"
echo ""
echo "Schema is applied on first db::connect (Toasty migrations under toasty/)."
echo "Run tests:"
echo "  just test"
echo ""
