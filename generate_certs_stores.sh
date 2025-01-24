#!/bin/bash

# Variables
STORE_PASSWORD="123456"
KEY_PASSWORD="123456"

CA_ALIAS="ca"
CLIENT_ALIAS="client"
SERVER_ALIAS="server"
DATABASE_ALIAS="database"

CLIENT_KEYSTORE="client-keystore.jks"
CLIENT_TRUSTSTORE="client-truststore.jks"

SERVER_KEYSTORE="server-keystore.jks"
SERVER_TRUSTSTORE="server-truststore.jks"

DATABASE_KEYSTORE="database-keystore.jks"
DATABASE_TRUSTSTORE="database-truststore.jks"

CA_KEYSTORE="ca-keystore.jks"
CA_CERT="ca-cert.pem"

SERVER_CERT="server-cert.pem"
SERVER_CSR="server-csr.pem"

DATABASE_CERT="database-cert.pem"
DATABASE_CSR="database-csr.pem"


# Step 1: Create Client Keystore
echo Creating Client Keystore...
keytool -genkeypair -alias keyRSA -keyalg RSA -keysize 2048 -validity 365 -keystore $CLIENT_KEYSTORE -storepass $STORE_PASSWORD -dname "CN=Placeholder, OU=IT, O=MyOrg, L=City, S=State, C=US"


# Step 2: Create Client Truststore
echo "[2/8] Creating client truststore"
keytool -genkeypair -alias keyRSA -keyalg RSA -keysize 2048 -validity 365 -keystore $CLIENT_TRUSTSTORE -storepass $STORE_PASSWORD -dname "CN=Placeholder, OU=IT, O=MyOrg, L=City, S=State, C=US"

# Step 3: Create Server Keystore
echo "[3/8] Creating server keystore..."
keytool -genkeypair -alias $SERVER_ALIAS \
    -keyalg RSA -keysize 2048 -validity 365 \
    -keystore $SERVER_KEYSTORE \
    -storepass $STORE_PASSWORD -keypass $KEY_PASSWORD \
    -dname "CN=Server, OU=IT, O=MyOrg, L=City, S=State, C=US"

# Step 4: Create Server Truststore
echo "[4/8] Creating server truststore with placeholder certificate..."
keytool -genkeypair -alias placeholder \
    -keyalg RSA -keysize 2048 -validity 365 \
    -keystore $SERVER_TRUSTSTORE \
    -storepass $STORE_PASSWORD \
    -dname "CN=Placeholder, OU=IT, O=MyOrg, L=City, S=State, C=US"

# Step 5: Create Database Keystore
echo "[3/8] Creating server keystore..."
keytool -genkeypair -alias $DATABASE_ALIAS \
    -keyalg RSA -keysize 2048 -validity 365 \
    -keystore $DATABASE_KEYSTORE \
    -storepass $STORE_PASSWORD -keypass $KEY_PASSWORD \
    -dname "CN=Server, OU=IT, O=MyOrg, L=City, S=State, C=US"

# Step 6: Create Database Truststore
echo "[4/8] Creating server truststore with placeholder certificate..."
keytool -genkeypair -alias placeholder \
    -keyalg RSA -keysize 2048 -validity 365 \
    -keystore $DATABASE_TRUSTSTORE \
    -storepass $STORE_PASSWORD \
    -dname "CN=Placeholder, OU=IT, O=MyOrg, L=City, S=State, C=US"

# Step 5: Create CA Certificate
echo "[5/8] Creating CA certificate..."
keytool -genkeypair -alias $CA_ALIAS \
    -keyalg RSA -keysize 2048 -validity 365 \
    -dname "CN=CA, OU=IT, O=MyOrg, L=City, S=State, C=US" \
    -keystore $CA_KEYSTORE \
    -storepass $STORE_PASSWORD \
    -ext bc=ca:true

echo "Exporting CA certificate..."
keytool -exportcert -alias $CA_ALIAS \
    -keystore $CA_KEYSTORE \
    -storepass $STORE_PASSWORD \
    -file $CA_CERT

# Step 6: Create Server Certificate Signing Request (CSR)
echo "[6/8] Creating server certificate signing request..."
keytool -certreq -alias $SERVER_ALIAS \
    -keystore $SERVER_KEYSTORE \
    -storepass $STORE_PASSWORD \
    -file $SERVER_CSR

# Sign Server Certificate with CA
echo "[6/8] Signing server certificate with CA..."
keytool -gencert -alias $CA_ALIAS \
    -keystore $CA_KEYSTORE \
    -storepass $STORE_PASSWORD \
    -infile $SERVER_CSR \
    -outfile $SERVER_CERT -validity 365

# Create Database Certificate Signing Request (CSR)
echo "[6/8] Creating database certificate signing request..."
keytool -certreq -alias $DATABASE_ALIAS \
    -keystore $DATABASE_KEYSTORE \
    -storepass $STORE_PASSWORD \
    -file $DATABASE_CSR

# Sign Database Certificate with CA
echo "[6/8] Signing server certificate with CA..."
keytool -gencert -alias $CA_ALIAS \
    -keystore $CA_KEYSTORE \
    -storepass $STORE_PASSWORD \
    -infile $DATABASE_CSR \
    -outfile $DATABASE_CERT -validity 365

# Step 7: Import CA Certificate into Client and Server Truststores
echo "[7/8] Importing CA certificate into client truststore..."
keytool -importcert -file $CA_CERT \
    -alias $CA_ALIAS \
    -keystore $CLIENT_TRUSTSTORE \
    -storepass $STORE_PASSWORD -noprompt

echo "[7/8] Importing CA certificate into server truststore..."
keytool -importcert -file $CA_CERT \
    -alias $CA_ALIAS \
    -keystore $SERVER_TRUSTSTORE \
    -storepass $STORE_PASSWORD -noprompt

echo "[7/8] Importing CA certificate into database truststore..."
keytool -importcert -file $CA_CERT \
    -alias $CA_ALIAS \
    -keystore $DATABASE_TRUSTSTORE \
    -storepass $STORE_PASSWORD -noprompt

# Import CA Certificate into Server Keystore (to establish chain)
echo "[7/8] Importing CA certificate into server keystore..."
keytool -importcert -file $CA_CERT \
    -alias $CA_ALIAS \
    -keystore $SERVER_KEYSTORE \
    -storepass $STORE_PASSWORD -noprompt

# Import CA Certificate into Server Keystore (to establish chain)
echo "[7/8] Importing CA certificate into database keystore..."
keytool -importcert -file $CA_CERT \
    -alias $CA_ALIAS \
    -keystore $DATABASE_KEYSTORE \
    -storepass $STORE_PASSWORD -noprompt

# Step 8: Import Signed Server Certificate into Server Keystore
echo "[8/8] Importing signed server certificate into server keystore..."
keytool -importcert -file $SERVER_CERT \
    -alias $SERVER_ALIAS \
    -keystore $SERVER_KEYSTORE \
    -storepass $STORE_PASSWORD -noprompt

# Step 8: Import Signed Database Certificate into Database Keystore
echo "[8/8] Importing signed database certificate into server keystore..."
keytool -importcert -file $DATABASE_CERT \
    -alias $DATABASE_ALIAS \
    -keystore $DATABASE_KEYSTORE \
    -storepass $STORE_PASSWORD -noprompt

# Cleanup temporary files
echo "[+] Cleaning up temporary files..."
rm -f $SERVER_CSR
rm -f $DATABASE_CSR

echo "[+] Keystore and truststore setup completed successfully!"
