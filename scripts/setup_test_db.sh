#!/bin/bash
# Setup PostgreSQL database for VCP automated tests (vcp_test).
#
# Prerequisites:
#   - PostgreSQL server running
#   - Current user has createdb / createuser privileges
#
# Usage:
#   ./scripts/setup_test_db.sh
#   just db-create-test

set -euo pipefail

DB_NAME="vcp_test"
DB_USER="vcp_test"
DB_PASSWORD="vcp_test"
DB_HOST="localhost"

echo "=== Setting up test database for VCP ==="

if psql -h "$DB_HOST" -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
    echo "Database $DB_NAME already exists."
else
    echo "Creating database $DB_NAME..."
    createdb -h "$DB_HOST" "$DB_NAME"
fi

if psql -h "$DB_HOST" -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" | grep -q 1; then
    echo "User $DB_USER already exists."
else
    echo "Creating user $DB_USER..."
    psql -h "$DB_HOST" -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';"
fi

echo "Granting privileges..."
psql -h "$DB_HOST" -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"
psql -h "$DB_HOST" -d "$DB_NAME" -c "GRANT ALL ON SCHEMA public TO $DB_USER;"
psql -h "$DB_HOST" -d "$DB_NAME" -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO $DB_USER;"
psql -h "$DB_HOST" -d "$DB_NAME" -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO $DB_USER;"

# Ownership helps Toasty migrations on a fresh DB created by another role.
psql -h "$DB_HOST" -d "$DB_NAME" -c "ALTER DATABASE $DB_NAME OWNER TO $DB_USER;" 2>/dev/null || true
psql -h "$DB_HOST" -d "$DB_NAME" -c "ALTER SCHEMA public OWNER TO $DB_USER;" 2>/dev/null || true

echo ""
echo "=== Test database setup complete ==="
echo ""
echo "URL (also in config/testing.toml):"
echo "  postgresql://$DB_USER:$DB_PASSWORD@$DB_HOST/$DB_NAME"
echo ""
echo "Schema is applied on first db::connect (Toasty migrations under toasty/)."
echo "Run tests:"
echo "  just test"
echo ""
