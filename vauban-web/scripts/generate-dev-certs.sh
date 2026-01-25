#!/bin/bash
# VAUBAN Web - Generate self-signed certificates for development
#
# This script generates a self-signed TLS certificate for local development.
# These certificates should NOT be used in production.
#
# Usage: ./vauban-web/scripts/generate-dev-certs.sh (from workspace root)
#    or: ./scripts/generate-dev-certs.sh (from vauban-web directory)
#
# The generated certificates will be placed in vauban-web/certs/ directory.

set -e

# Determine script directory and workspace root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VAUBAN_WEB_DIR="$(dirname "$SCRIPT_DIR")"

# Certificates go in vauban-web/certs/
CERT_DIR="$VAUBAN_WEB_DIR/certs"
CERT_NAME="dev-server"
DAYS_VALID=365

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}VAUBAN Web - Development Certificate Generator${NC}"
echo "================================================"
echo ""

# Check if openssl is installed
if ! command -v openssl &> /dev/null; then
    echo -e "${RED}Error: openssl is not installed${NC}"
    echo "Please install openssl and try again."
    exit 1
fi

# Create certs directory if it doesn't exist
mkdir -p "$CERT_DIR"

# Check if certificates already exist
if [ -f "$CERT_DIR/$CERT_NAME.crt" ] && [ -f "$CERT_DIR/$CERT_NAME.key" ]; then
    echo -e "${YELLOW}Warning: Certificates already exist in $CERT_DIR/${NC}"
    read -p "Overwrite existing certificates? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
fi

echo "Generating self-signed certificate..."
echo "  - Valid for: $DAYS_VALID days"
echo "  - Subject Alternative Names: localhost, 127.0.0.1"
echo ""

# Generate certificate with SAN (Subject Alternative Name)
openssl req -x509 -newkey rsa:4096 -sha256 -days "$DAYS_VALID" \
    -nodes \
    -keyout "$CERT_DIR/$CERT_NAME.key" \
    -out "$CERT_DIR/$CERT_NAME.crt" \
    -subj "/CN=localhost/O=VAUBAN Development/C=US" \
    -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1,IP:::1"

# Set appropriate permissions
chmod 600 "$CERT_DIR/$CERT_NAME.key"
chmod 644 "$CERT_DIR/$CERT_NAME.crt"

echo ""
echo -e "${GREEN}Certificate generated successfully!${NC}"
echo ""
echo "Files created:"
echo "  - $CERT_DIR/$CERT_NAME.crt (certificate)"
echo "  - $CERT_DIR/$CERT_NAME.key (private key)"
echo ""
echo "Certificate details:"
openssl x509 -in "$CERT_DIR/$CERT_NAME.crt" -noout -subject -dates
echo ""
echo -e "${YELLOW}WARNING: Self-signed certificates are for development only!${NC}"
echo "         Browsers will show a security warning."
echo ""
echo "To trust this certificate on macOS:"
echo "  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $CERT_DIR/$CERT_NAME.crt"
echo ""
echo "To trust this certificate on Linux (Ubuntu/Debian):"
echo "  sudo cp $CERT_DIR/$CERT_NAME.crt /usr/local/share/ca-certificates/"
echo "  sudo update-ca-certificates"

