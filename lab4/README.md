 ---
# OpenSSL Commands Documentation
# SSL Project - Certificate Generation
 ---

# 1.  FAKE BNR CERTIFICATE (Self-Signed) - For MITM Simulation


# Generate RSA 2048-bit private key
# This creates the private key that will be used for signing
openssl genrsa -out fake-bnr. key 2048

# Create self-signed certificate claiming to be bnr.ro
# -new -x509: Create a new self-signed certificate
# -key:  Use this private key
# -days 365: Valid for 1 year
# -subj: Certificate subject (organization info)
# -addext: Add Subject Alternative Names (SANs) for the domains
openssl req -new -x509 -key fake-bnr.key -out fake-bnr. crt -days 365 \
-subj "/C=RO/ST=Bucuresti/L=Bucuresti/O=Banca Nationala a Romaniei/CN=bnr. ro" \
-addext "subjectAltName=DNS:bnr. ro,DNS:www.bnr. ro"

# Convert to PKCS12 format for Java
# -export:  Export to PKCS12
# -in: Input certificate
# -inkey:  Private key
# -out: Output file
# -name:  Alias name in keystore
openssl pkcs12 -export -in fake-bnr.crt -inkey fake-bnr.key \
-out fake-bnr-keystore.p12 -name "fake-bnr" \
-password pass:changeit

# -----------------------------------------------------------------------------
# 2. ROOT CA (Elliptic Curve 256-bit)
# -----------------------------------------------------------------------------

# Generate EC private key using prime256v1 curve (also called secp256r1 or P-256)
# This is a 256-bit elliptic curve key
openssl ecparam -genkey -name prime256v1 -out rootca.key

# Create self-signed Root CA certificate
# basicConstraints=CA:TRUE marks this as a CA certificate
# keyUsage specifies this cert can only sign other certificates
openssl req -new -x509 -key rootca.key -out rootca.crt -days 365 \
-subj "/C=RO/ST=Kolozs/L=Kolozsvar/O=BBTE/CN=ID-RootCA" \
-addext "basicConstraints=critical,CA:TRUE" \
-addext "keyUsage=critical,keyCertSign,cRLSign"

# -----------------------------------------------------------------------------
# 3.  INTERMEDIATE CA (ClientCA and ServerCA)
# -----------------------------------------------------------------------------

# Generate EC key for intermediate CA
openssl ecparam -genkey -name prime256v1 -out clientca.key

# Create Certificate Signing Request (CSR)
# The CSR contains the public key and requested subject information
openssl req -new -key clientca.key -out clientca.csr \
-subj "/C=RO/ST=Kolozs/L=Kolozsvar/O=BBTE/CN=ID-ClientCA"

# Sign the CSR with Root CA to create the intermediate CA certificate
# -CA: The CA certificate to use for signing
# -CAkey: The CA's private key
# -CAcreateserial: Create a serial number file
openssl x509 -req -in clientca.csr \
-CA rootca.crt -CAkey rootca. key \
-CAcreateserial -out clientca.crt -days 365 \
-extfile <(echo "basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign")

# -----------------------------------------------------------------------------
# 4. CLIENT CERTIFICATE (EC 256-bit)
# -----------------------------------------------------------------------------

# Generate EC key for client
openssl ecparam -genkey -name prime256v1 -out client.key

# Create CSR
openssl req -new -key client.key -out client.csr \
-subj "/C=RO/ST=Kolozs/L=Kolozsvar/O=BBTE/CN=ID-client"

# Sign with ClientCA
# extendedKeyUsage=clientAuth specifies this is for client authentication
openssl x509 -req -in client.csr \
-CA clientca.crt -CAkey clientca.key \
-CAcreateserial -out client.crt -days 365 \
-extfile <(echo "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth")

# Create PKCS12 keystore with certificate chain
openssl pkcs12 -export -in client.crt -inkey client.key \
-certfile clientca.crt \
-out client-keystore.p12 -name "client" \
-password pass:changeit

# -----------------------------------------------------------------------------
# 5. SERVER CERTIFICATE (RSA 2048-bit)
# -----------------------------------------------------------------------------

# Generate RSA 2048-bit key for server
openssl genrsa -out server.key 2048

# Create CSR with hostname as CN
openssl req -new -key server.key -out server.csr \
-subj "/C=RO/ST=Kolozs/L=Kolozsvar/O=BBTE/CN=$(hostname)"

# Sign with ServerCA
# extendedKeyUsage=serverAuth specifies this is for server authentication
# subjectAltName includes DNS names and IP addresses the server can use
openssl x509 -req -in server.csr \
-CA serverca.crt -CAkey serverca. key \
-CAcreateserial -out server. crt -days 365 \
-extfile <(echo "basicConstraints=critical,CA: FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:$(hostname),DNS:localhost,IP:127.0.0.1")

# Create PKCS12 keystore
openssl pkcs12 -export -in server.crt -inkey server.key \
-certfile serverca.crt \
-out server-keystore.p12 -name "server" \
-password pass:changeit

# -----------------------------------------------------------------------------
# 6. TRUST STORES (using keytool)
# -----------------------------------------------------------------------------

# Create truststore with Root CA
# keytool is Java's certificate management tool
# -importcert: Import a certificate
# -alias: Name for the certificate in the store
# -keystore: The keystore file
# -storetype PKCS12: Use PKCS12 format (recommended over JKS)
keytool -importcert -alias "rootca" -file rootca.crt \
-keystore truststore.p12 -storetype PKCS12 \
-storepass changeit -noprompt

# -----------------------------------------------------------------------------
# 7. USEFUL VERIFICATION COMMANDS
# -----------------------------------------------------------------------------

# View certificate details
openssl x509 -in certificate.crt -text -noout

# Verify certificate chain
openssl verify -CAfile rootca.crt -untrusted intermediateca.crt certificate.crt

# View PKCS12 keystore contents
openssl pkcs12 -in keystore.p12 -info -nodes

# List keystore entries with keytool
keytool -list -keystore keystore.p12 -storepass changeit

# Test SSL connection
openssl s_client -connect localhost:8443 -CAfile rootca.crt

# -----------------------------------------------------------------------------
# 8. HOSTS FILE MODIFICATION (for MITM test)
# -----------------------------------------------------------------------------

# On Linux/Mac:  Edit /etc/hosts
# On Windows: Edit C:\Windows\System32\drivers\etc\hosts
# Add line: 127.0.0.1 bnr.ro

# Verify with ping
ping bnr.ro
# Should show: Reply from 127.0.0.1

# Remember to remove this line after testing!