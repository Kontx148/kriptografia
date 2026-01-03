#!/bin/bash
set -e

# =============================================================================
# Certificate Generation Script for SSL Project
#
# This script creates a complete PKI (Public Key Infrastructure):
# - RootCA:  The root certificate authority
# - ClientCA: Signs client certificates (signed by RootCA)
# - ServerCA: Signs server certificates (signed by RootCA)
# - Client certificate (signed by ClientCA)
# - Server certificate (signed by ServerCA)
# - Fake BNR certificate (self-signed, for MITM simulation)
# =============================================================================

export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

SCS_ID="vnim2413"
HOSTNAME=$(hostname)
PASSWORD="asd123"

# Directory setup
CERTS_DIR="../certs"
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR" || exit 1

rm -rf certs

echo "==============================================================="
echo "  Certificate Generation Script"
echo "  SCS Identifier: $SCS_ID"
echo "  Hostname:  $HOSTNAME"
echo "==============================================================="

# =============================================================================
# TASK 2:  Create Fake BNR Certificate (Self-Signed)
# This simulates what an attacker would create for a MITM attack
# =============================================================================
echo ""
echo ">>> Creating Fake BNR Self-Signed Certificate (Task 2)..."

# Generate RSA private key for fake certificate
openssl genrsa -out fake-bnr.key 2048

# Create self-signed certificate claiming to be bnr.ro
# The SAN (Subject Alternative Name) includes DNS: bnr.ro to match the real cert
openssl req -new -x509 -key fake-bnr.key -out fake-bnr.crt -days 365 \
    -subj "/C=RO/ST=Bucuresti/L=Bucuresti/O=Banca Nationala a Romaniei/CN=bnr.ro" \
    -addext "subjectAltName=DNS:bnr.ro,DNS:www.bnr.ro"

# Convert to PKCS12 keystore format for Java
openssl pkcs12 -export -in fake-bnr.crt -inkey fake-bnr.key \
    -out fake-bnr-keystore.p12 -name "fake-bnr" \
    -password "pass:$PASSWORD"

echo "✓ Created fake-bnr-keystore.p12"

# =============================================================================
# TASK 3: Create Root CA (with Elliptic Curve key)
# The RootCA is the trust anchor of our PKI
# =============================================================================
echo ""
echo ">>> Creating Root CA (Task 3)..."

# Generate EC private key (256-bit, using prime256v1 curve aka secp256r1)
openssl ecparam -genkey -name prime256v1 -out "${SCS_ID}-RootCA.key"

# Create self-signed Root CA certificate
# Valid until 2025-02-28
openssl req -new -x509 -key "${SCS_ID}-RootCA.key" -out "${SCS_ID}-RootCA.crt" \
    -days 365 \
    -subj "/C=RO/ST=Kolozs/L=Kolozsvar/O=BBTE/CN=${SCS_ID}-RootCA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

echo "✓ Created ${SCS_ID}-RootCA.crt"

# =============================================================================
# TASK 3: Create Client CA (signed by RootCA)
# =============================================================================
echo ""
echo ">>> Creating Client CA (Task 3)..."

# Generate EC private key for ClientCA
openssl ecparam -genkey -name prime256v1 -out "${SCS_ID}-ClientCA.key"

# Create Certificate Signing Request (CSR)
openssl req -new -key "${SCS_ID}-ClientCA.key" -out "${SCS_ID}-ClientCA.csr" \
    -subj "/C=RO/ST=Kolozs/L=Kolozsvar/O=BBTE/CN=${SCS_ID}-ClientCA"

# Create extensions file for intermediate CA
cat > clientca-ext.cnf << EOF
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
EOF

# Sign ClientCA certificate with RootCA
openssl x509 -req -in "${SCS_ID}-ClientCA.csr" \
    -CA "${SCS_ID}-RootCA.crt" -CAkey "${SCS_ID}-RootCA.key" \
    -CAcreateserial -out "${SCS_ID}-ClientCA.crt" \
    -days 365 \
    -extfile clientca-ext.cnf

echo "✓ Created ${SCS_ID}-ClientCA.crt (signed by RootCA)"

# =============================================================================
# TASK 3: Create Server CA (signed by RootCA)
# =============================================================================
echo ""
echo ">>> Creating Server CA (Task 3)..."

# Generate EC private key for ServerCA
openssl ecparam -genkey -name prime256v1 -out "${SCS_ID}-ServerCA.key"

# Create CSR for ServerCA
openssl req -new -key "${SCS_ID}-ServerCA.key" -out "${SCS_ID}-ServerCA.csr" \
    -subj "/C=RO/ST=Kolozs/L=Kolozsvar/O=BBTE/CN=${SCS_ID}-ServerCA"

# Create extensions file
cat > serverca-ext.cnf << EOF
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
EOF

# Sign ServerCA certificate with RootCA
openssl x509 -req -in "${SCS_ID}-ServerCA.csr" \
    -CA "${SCS_ID}-RootCA.crt" -CAkey "${SCS_ID}-RootCA.key" \
    -CAcreateserial -out "${SCS_ID}-ServerCA.crt" \
    -days 365 \
    -extfile serverca-ext.cnf

echo "✓ Created ${SCS_ID}-ServerCA.crt (signed by RootCA)"

# =============================================================================
# TASK 4: Create Client Certificate (signed by ClientCA)
# =============================================================================
echo ""
echo ">>> Creating Client Certificate (Task 4)..."

# Generate EC private key for client (256-bit)
openssl ecparam -genkey -name prime256v1 -out "${SCS_ID}-client.key"

# Create CSR for client certificate
openssl req -new -key "${SCS_ID}-client.key" -out "${SCS_ID}-client.csr" \
    -subj "/C=RO/ST=Kolozs/L=Kolozsvar/O=BBTE/CN=${SCS_ID}-client"

# Create extensions for end-entity certificate (not a CA)
cat > client-ext.cnf << EOF
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
EOF

# Sign client certificate with ClientCA
openssl x509 -req -in "${SCS_ID}-client.csr" \
    -CA "${SCS_ID}-ClientCA.crt" -CAkey "${SCS_ID}-ClientCA.key" \
    -CAcreateserial -out "${SCS_ID}-client.crt" \
    -days 365 \
    -extfile client-ext.cnf

echo "✓ Created ${SCS_ID}-client.crt (signed by ClientCA)"

# Create client keystore (PKCS12) for Java
openssl pkcs12 -export -in "${SCS_ID}-client.crt" -inkey "${SCS_ID}-client.key" \
    -certfile "${SCS_ID}-ClientCA.crt" \
    -out client-keystore.p12 -name "client" \
    -password "pass:$PASSWORD"

echo "✓ Created client-keystore.p12"

# =============================================================================
# TASK 5: Create Server Certificate (signed by ServerCA)
# Note: This uses RSA 2048-bit key as required
# =============================================================================
echo ""
echo ">>> Creating Server Certificate (Task 5)..."

# Generate RSA private key for server (2048-bit as specified)
openssl genrsa -out "${SCS_ID}-server.key" 2048

# Create CSR for server certificate
openssl req -new -key "${SCS_ID}-server.key" -out "${SCS_ID}-server.csr" \
    -subj "/C=RO/ST=Kolozs/L=Kolozsvar/O=BBTE/CN=$HOSTNAME"

# Create extensions for server certificate
cat > server-ext.cnf << EOF
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:$HOSTNAME,DNS:localhost,IP:127.0.0.1
EOF

# Sign server certificate with ServerCA
openssl x509 -req -in "${SCS_ID}-server.csr" \
    -CA "${SCS_ID}-ServerCA.crt" -CAkey "${SCS_ID}-ServerCA.key" \
    -CAcreateserial -out "${SCS_ID}-server.crt" \
    -days 365 \
    -extfile server-ext.cnf

echo "✓ Created ${SCS_ID}-server.crt (signed by ServerCA)"

# Create server keystore (PKCS12) for Java
openssl pkcs12 -export -in "${SCS_ID}-server.crt" -inkey "${SCS_ID}-server.key" \
    -certfile "${SCS_ID}-ServerCA.crt" \
    -out server-keystore.p12 -name "server" \
    -password "pass:$PASSWORD"

echo "✓ Created server-keystore.p12"

# =============================================================================
# Create Trust Stores
# Trust stores contain CA certificates that we trust
# =============================================================================
echo ""
echo ">>> Creating Trust Stores..."

# Create certificate chain for client trust store (to verify server)
# Client needs to trust:  RootCA -> ServerCA -> server cert
cat "${SCS_ID}-RootCA.crt" "${SCS_ID}-ServerCA.crt" > server-chain.crt

# Create client trust store using keytool (contains RootCA)
keytool -importcert -alias "rootca" -file "${SCS_ID}-RootCA.crt" \
    -keystore client-truststore.p12 -storetype PKCS12 \
    -storepass "$PASSWORD" -noprompt

echo "✓ Created client-truststore.p12"

# Create server trust store (to verify clients)
# Server needs to trust: RootCA -> ClientCA -> client cert
keytool -importcert -alias "rootca" -file "${SCS_ID}-RootCA.crt" \
    -keystore server-truststore.p12 -storetype PKCS12 \
    -storepass "$PASSWORD" -noprompt

echo "✓ Created server-truststore.p12"

# =============================================================================
# Cleanup and Summary
# =============================================================================
rm -f *.csr *.cnf *.srl

echo ""
echo "==============================================================="
echo "  Certificate Generation Complete!"
echo "==============================================================="
echo ""
echo "Files created in $CERTS_DIR/:"
echo ""
echo "CA Certificates:"
echo "  • ${SCS_ID}-RootCA.crt/key    - Root Certificate Authority (EC 256-bit)"
echo "  • ${SCS_ID}-ClientCA.crt/key  - Client CA (EC 256-bit, signed by Root)"
echo "  • ${SCS_ID}-ServerCA.crt/key  - Server CA (EC 256-bit, signed by Root)"
echo ""
echo "End-Entity Certificates:"
echo "  • ${SCS_ID}-client.crt/key    - Client cert (EC 256-bit, signed by ClientCA)"
echo "  • ${SCS_ID}-server.crt/key    - Server cert (RSA 2048-bit, signed by ServerCA)"
echo "  • fake-bnr.crt/key            - Fake BNR cert (self-signed, for MITM test)"
echo ""
echo "Java Keystores (PKCS12):"
echo "  • client-keystore.p12         - Client's private key + certificate"
echo "  • server-keystore.p12         - Server's private key + certificate"
echo "  • client-truststore.p12       - Trusted CAs for client"
echo "  • server-truststore.p12       - Trusted CAs for server"
echo "  • fake-bnr-keystore.p12       - Fake BNR keystore"
echo ""
echo "All keystores use password: $PASSWORD"
echo "==============================================================="