#!/bin/bash
# Setup test database for vauban-web integration tests
#
# This script creates a separate PostgreSQL database for testing.
# Run this once before running integration tests.
#
# Prerequisites:
#   - PostgreSQL server running
#   - Current user has createdb/createuser privileges
#
# Usage:
#   ./scripts/setup_test_db.sh

set -e

DB_NAME="vauban_test"
DB_USER="vauban_test"
DB_PASSWORD="vauban_test"
DB_HOST="localhost"

echo "=== Setting up test database for vauban-web ==="

# Check if database exists
if psql -h $DB_HOST -lqt | cut -d \| -f 1 | grep -qw $DB_NAME; then
    echo "Database $DB_NAME already exists."
else
    echo "Creating database $DB_NAME..."
    createdb -h $DB_HOST $DB_NAME
fi

# Check if user exists and create if not
if psql -h $DB_HOST -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" | grep -q 1; then
    echo "User $DB_USER already exists."
else
    echo "Creating user $DB_USER..."
    psql -h $DB_HOST -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';"
fi

# Grant privileges
echo "Granting privileges..."
psql -h $DB_HOST -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"
psql -h $DB_HOST -d $DB_NAME -c "GRANT ALL ON SCHEMA public TO $DB_USER;"

# Run migrations
echo "Running migrations..."
export DATABASE_URL="postgresql://$DB_USER:$DB_PASSWORD@$DB_HOST/$DB_NAME"
diesel migration run

echo ""
echo "=== Test database setup complete ==="
echo ""
echo "Test database URL:"
echo "  DATABASE_URL=postgresql://$DB_USER:$DB_PASSWORD@$DB_HOST/$DB_NAME"
echo ""
echo "To run tests:"
echo "  export DATABASE_URL=postgresql://$DB_USER:$DB_PASSWORD@$DB_HOST/$DB_NAME"
echo "  export SECRET_KEY=test-secret-key-for-testing-only-32chars"
echo "  cargo test"

