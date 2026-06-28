#!/bin/bash
# =============================================================================
# AppViewX Pull Automation - Certificate Request Script
# =============================================================================
# Description : Requests and downloads a certificate from AppViewX CLM
#               using the pull method (server-initiated via REST API).
#               Designed to run on Linux servers as a cron job or on-demand.
#
# Usage       : ./appviewx_pull_cert.sh
# Cron Example: 0 6 * * * /opt/scripts/appviewx_pull_cert.sh >> /var/log/appviewx_cert.log 2>&1
#
# Requirements: curl, openssl, jq
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# CONFIGURATION — Update these values for your environment
# -----------------------------------------------------------------------------
AVX_HOST="https://<APPVIEWX_HOST_OR_IP>"   # AppViewX server hostname or IP
AVX_PORT="31443"                             # Default gateway port
AVX_BASE_URL="${AVX_HOST}:${AVX_PORT}/avxapi"

# Authentication — use Service Account (recommended for automation)
AVX_CLIENT_ID="<YOUR_CLIENT_ID>"
AVX_CLIENT_SECRET="<YOUR_CLIENT_SECRET>"

# Certificate Request Parameters
CERT_COMMON_NAME="$(hostname -f)"            # Defaults to the server's FQDN
CERT_SAN_DNS="$(hostname -f)"                # Subject Alternative Name (DNS)
CERT_ORG="Your Organization"
CERT_CA="<YOUR_CA_SETTING_NAME>"             # CA setting name configured in AppViewX
CERT_CA_TYPE="Microsoft Enterprise"          # e.g. Microsoft Enterprise, DigiCert, etc.
CERT_TEMPLATE="WebServer"                    # MS CA template or equivalent
CERT_VALIDITY_DAYS=365
CERT_GROUP="Linux-Servers"                   # Certificate group in AppViewX

# Certificate Install Paths
CERT_DIR="/etc/ssl/appviewx"
CERT_FILE="${CERT_DIR}/server.crt"
KEY_FILE="${CERT_DIR}/server.key"
CHAIN_FILE="${CERT_DIR}/chain.crt"

# Service to reload after certificate install (set to "" to skip)
SERVICE_RELOAD="nginx"                        # e.g. nginx, apache2, httpd

# Polling settings
POLL_INTERVAL=10    # seconds between status checks
POLL_MAX_ATTEMPTS=30

# Log file
LOG_FILE="/var/log/appviewx_pull_cert.log"

# -----------------------------------------------------------------------------
# FUNCTIONS
# -----------------------------------------------------------------------------

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "${LOG_FILE}"
}

check_dependencies() {
    for cmd in curl openssl jq; do
        if ! command -v "${cmd}" &>/dev/null; then
            log "ERROR: Required command '${cmd}' not found. Please install it."
            exit 1
        fi
    done
    log "Dependencies check passed."
}

setup_cert_dir() {
    if [ ! -d "${CERT_DIR}" ]; then
        mkdir -p "${CERT_DIR}"
        chmod 750 "${CERT_DIR}"
        log "Created certificate directory: ${CERT_DIR}"
    fi
}

# Step 1: Authenticate — obtain service token using Client ID + Client Secret
get_auth_token() {
    log "Step 1: Authenticating with AppViewX..."

    local credentials
    credentials=$(echo -n "${AVX_CLIENT_ID}:${AVX_CLIENT_SECRET}" | base64 -w 0)

    local response
    response=$(curl -sk -X POST \
        "${AVX_BASE_URL}/acctmgmt-get-service-token?gwsource=external" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Authorization: Basic ${credentials}")

    AUTH_TOKEN=$(echo "${response}" | jq -r '.response')

    if [ -z "${AUTH_TOKEN}" ] || [ "${AUTH_TOKEN}" == "null" ]; then
        log "ERROR: Failed to obtain auth token. Response: ${response}"
        exit 1
    fi

    log "Authentication successful. Token obtained."
}

# Step 2: Generate CSR locally on the Linux server
generate_csr() {
    log "Step 2: Generating private key and CSR locally..."

    openssl req -new -newkey rsa:2048 -nodes \
        -keyout "${KEY_FILE}" \
        -out /tmp/server.csr \
        -subj "/CN=${CERT_COMMON_NAME}/O=${CERT_ORG}" \
        -addext "subjectAltName=DNS:${CERT_SAN_DNS}" 2>/dev/null

    chmod 600 "${KEY_FILE}"
    CSR_CONTENT=$(cat /tmp/server.csr | tr -d '\n')
    log "CSR generated successfully for CN=${CERT_COMMON_NAME}"
}

# Step 3: Submit certificate request to AppViewX
request_certificate() {
    log "Step 3: Submitting certificate request to AppViewX..."

    local payload
    payload=$(cat <<EOF
{
  "payload": {
    "csrGenerationSource": "external",
    "csr": "${CSR_CONTENT}",
    "caConnectorInfo": {
      "certificateAuthority": "${CERT_CA_TYPE}",
      "caSettingName": "${CERT_CA}",
      "name": "${CERT_CA_TYPE} connector",
      "csrParameters": {
        "commonName": "${CERT_COMMON_NAME}",
        "certificateCategories": ["Server"],
        "enhancedSANTypes": {
          "dNSNames": ["${CERT_SAN_DNS}"]
        }
      },
      "vendorSpecificDetails": {
        "templateName": "${CERT_TEMPLATE}"
      },
      "validityInDays": ${CERT_VALIDITY_DAYS}
    },
    "certificateGroup": {
      "name": "${CERT_GROUP}"
    },
    "certificateFormat": {
      "format": "CRT",
      "password": ""
    }
  }
}
EOF
)

    local response
    response=$(curl -sk -X POST \
        "${AVX_BASE_URL}/certificate-requests?gwsource=external" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${AUTH_TOKEN}" \
        -d "${payload}")

    REQUEST_ID=$(echo "${response}" | jq -r '.response.requestId // .response.id // empty')

    if [ -z "${REQUEST_ID}" ]; then
        log "ERROR: Failed to submit certificate request. Response: ${response}"
        exit 1
    fi

    log "Certificate request submitted. Request ID: ${REQUEST_ID}"
}

# Step 4: Poll AppViewX until the certificate is issued
poll_certificate_status() {
    log "Step 4: Polling for certificate issuance (Request ID: ${REQUEST_ID})..."

    local attempt=0
    local status=""

    while [ "${attempt}" -lt "${POLL_MAX_ATTEMPTS}" ]; do
        attempt=$((attempt + 1))

        local response
        response=$(curl -sk -X GET \
            "${AVX_BASE_URL}/certificate-requests/${REQUEST_ID}?gwsource=external" \
            -H "Authorization: Bearer ${AUTH_TOKEN}")

        status=$(echo "${response}" | jq -r '.response.status // empty')

        log "  Attempt ${attempt}/${POLL_MAX_ATTEMPTS} — Status: ${status}"

        if [ "${status}" == "ISSUED" ] || [ "${status}" == "ACTIVE" ]; then
            CERT_SERIAL=$(echo "${response}" | jq -r '.response.serialNumber // empty')
            log "Certificate issued successfully. Serial: ${CERT_SERIAL}"
            return 0
        elif [ "${status}" == "REJECTED" ] || [ "${status}" == "FAILED" ]; then
            log "ERROR: Certificate request was ${status}. Response: ${response}"
            exit 1
        fi

        sleep "${POLL_INTERVAL}"
    done

    log "ERROR: Timed out waiting for certificate issuance after $((POLL_MAX_ATTEMPTS * POLL_INTERVAL)) seconds."
    exit 1
}

# Step 5: Download the issued certificate from AppViewX
download_certificate() {
    log "Step 5: Downloading certificate from AppViewX..."

    local payload
    payload=$(cat <<EOF
{
  "payload": {
    "serialNumber": "${CERT_SERIAL}",
    "commonName": "${CERT_COMMON_NAME}",
    "isChainRequired": "true",
    "isKeyRequired": "false",
    "format": "CRT"
  }
}
EOF
)

    local response
    response=$(curl -sk -X POST \
        "${AVX_BASE_URL}/certificate-download?gwsource=external" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${AUTH_TOKEN}" \
        -d "${payload}")

    # Extract certificate PEM content
    CERT_CONTENT=$(echo "${response}" | jq -r '.response.certificate // empty')
    CHAIN_CONTENT=$(echo "${response}" | jq -r '.response.chain // empty')

    if [ -z "${CERT_CONTENT}" ]; then
        log "ERROR: Failed to download certificate. Response: ${response}"
        exit 1
    fi

    log "Certificate downloaded successfully."
}

# Step 6: Install certificate and chain on the local server
install_certificate() {
    log "Step 6: Installing certificate to ${CERT_DIR}..."

    echo "${CERT_CONTENT}" > "${CERT_FILE}"
    chmod 644 "${CERT_FILE}"

    if [ -n "${CHAIN_CONTENT}" ]; then
        echo "${CHAIN_CONTENT}" > "${CHAIN_FILE}"
        chmod 644 "${CHAIN_FILE}"
        log "Certificate chain installed: ${CHAIN_FILE}"
    fi

    log "Certificate installed: ${CERT_FILE}"
    log "Private key location:   ${KEY_FILE}"

    # Verify the certificate matches the private key
    CERT_MD5=$(openssl x509 -noout -modulus -in "${CERT_FILE}" | md5sum)
    KEY_MD5=$(openssl rsa -noout -modulus -in "${KEY_FILE}" | md5sum)

    if [ "${CERT_MD5}" != "${KEY_MD5}" ]; then
        log "ERROR: Certificate and private key do not match!"
        exit 1
    fi

    log "Certificate and key pair verified successfully."
}

# Step 7: Reload the web service to apply the new certificate
reload_service() {
    if [ -z "${SERVICE_RELOAD}" ]; then
        log "Step 7: Service reload skipped (SERVICE_RELOAD not set)."
        return
    fi

    log "Step 7: Reloading service: ${SERVICE_RELOAD}..."

    if systemctl is-active --quiet "${SERVICE_RELOAD}"; then
        systemctl reload "${SERVICE_RELOAD}"
        log "Service '${SERVICE_RELOAD}' reloaded successfully."
    else
        log "WARNING: Service '${SERVICE_RELOAD}' is not running. Skipping reload."
    fi
}

# Cleanup temp files
cleanup() {
    rm -f /tmp/server.csr
}

# -----------------------------------------------------------------------------
# MAIN
# -----------------------------------------------------------------------------
log "======================================================"
log " AppViewX Pull Automation — Certificate Request Start "
log "======================================================"

check_dependencies
setup_cert_dir
get_auth_token
generate_csr
request_certificate
poll_certificate_status
download_certificate
install_certificate
reload_service
cleanup

log "======================================================"
log " Certificate lifecycle completed successfully."
log " CN   : ${CERT_COMMON_NAME}"
log " Cert : ${CERT_FILE}"
log " Key  : ${KEY_FILE}"
log "======================================================"
