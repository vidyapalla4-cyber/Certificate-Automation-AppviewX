#!/usr/bin/env python3
"""
=============================================================================
AppViewX Pull Automation - Certificate Request Script (Python)
=============================================================================
Description : Requests and downloads a certificate from AppViewX CLM
              using the pull method (server-initiated via REST API).
              Designed to run on Linux servers as a cron job or on-demand.

Usage       : python3 appviewx_pull_cert.py
              python3 appviewx_pull_cert.py --cn myserver.example.com
Cron Example: 0 6 * * * /usr/bin/python3 /opt/scripts/appviewx_pull_cert.py

Requirements: Python 3.6+, cryptography (pip install cryptography)
=============================================================================
"""

import argparse
import base64
import hashlib
import json
import logging
import os
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import urllib.request
import urllib.error
import ssl

# Try to import cryptography for CSR generation; fall back to openssl subprocess
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# =============================================================================
# CONFIGURATION — Update these values for your environment
# =============================================================================

CONFIG = {
    # AppViewX server
    "avx_host": "https://<APPVIEWX_HOST_OR_IP>",
    "avx_port": "31443",

    # Service Account credentials (recommended over username/password)
    "client_id": "<YOUR_CLIENT_ID>",
    "client_secret": "<YOUR_CLIENT_SECRET>",

    # Certificate parameters
    "common_name": socket.getfqdn(),         # Defaults to server FQDN
    "san_dns": [socket.getfqdn()],           # Subject Alternative Names
    "organization": "Your Organization",
    "ca_setting_name": "<YOUR_CA_SETTING_NAME>",
    "ca_type": "Microsoft Enterprise",       # e.g. Microsoft Enterprise, DigiCert
    "ca_template": "WebServer",              # MS CA template or equivalent
    "validity_days": 365,
    "cert_group": "Linux-Servers",

    # Install paths
    "cert_dir": "/etc/ssl/appviewx",
    "cert_file": "/etc/ssl/appviewx/server.crt",
    "key_file": "/etc/ssl/appviewx/server.key",
    "chain_file": "/etc/ssl/appviewx/chain.crt",

    # Service to reload after install (set to None to skip)
    "service_reload": "nginx",               # e.g. nginx, apache2, httpd

    # Polling
    "poll_interval": 10,                     # seconds between status checks
    "poll_max_attempts": 30,

    # Logging
    "log_file": "/var/log/appviewx_pull_cert.log",
    "verify_ssl": True,                      # Set False only for self-signed AVX certs
}

# =============================================================================
# LOGGING SETUP
# =============================================================================

def setup_logging(log_file: str) -> logging.Logger:
    logger = logging.getLogger("appviewx")
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("[%(asctime)s] %(levelname)s — %(message)s",
                                  datefmt="%Y-%m-%d %H:%M:%S")
    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    # File handler
    try:
        fh = logging.FileHandler(log_file)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    except PermissionError:
        logger.warning(f"Cannot write to log file {log_file}. Logging to console only.")
    return logger


# =============================================================================
# APPVIEWX API CLIENT
# =============================================================================

class AppViewXClient:
    """Handles all REST API interactions with AppViewX CLM."""

    def __init__(self, config: dict, logger: logging.Logger):
        self.base_url = f"{config['avx_host']}:{config['avx_port']}/avxapi"
        self.client_id = config["client_id"]
        self.client_secret = config["client_secret"]
        self.verify_ssl = config["verify_ssl"]
        self.logger = logger
        self.auth_token = None

        # SSL context
        self.ssl_context = ssl.create_default_context()
        if not self.verify_ssl:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE

    def _request(self, method: str, endpoint: str, payload: dict = None,
                 extra_headers: dict = None) -> dict:
        """Make an HTTPS request to the AppViewX API."""
        url = f"{self.base_url}/{endpoint}?gwsource=external"
        headers = {"Content-Type": "application/json"}

        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        if extra_headers:
            headers.update(extra_headers)

        body = json.dumps(payload).encode("utf-8") if payload else b""
        req = urllib.request.Request(url, data=body, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, context=self.ssl_context) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8")
            self.logger.error(f"HTTP {e.code} from {endpoint}: {body}")
            raise
        except urllib.error.URLError as e:
            self.logger.error(f"Connection error to AppViewX: {e.reason}")
            raise

    # Step 1: Authenticate using Service Account
    def authenticate(self) -> None:
        self.logger.info("Step 1: Authenticating with AppViewX (Service Account)...")

        credentials = base64.b64encode(
            f"{self.client_id}:{self.client_secret}".encode()
        ).decode()

        url = f"{self.base_url}/acctmgmt-get-service-token?gwsource=external"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {credentials}",
        }

        req = urllib.request.Request(url, data=b"", headers=headers, method="POST")
        with urllib.request.urlopen(req, context=self.ssl_context) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        self.auth_token = data.get("response")
        if not self.auth_token:
            raise RuntimeError(f"Authentication failed: {data}")

        self.logger.info("Authentication successful. Token obtained.")

    # Step 3: Submit certificate request
    def request_certificate(self, csr_pem: str, config: dict) -> str:
        self.logger.info("Step 3: Submitting certificate request to AppViewX...")

        # Strip PEM headers for the API payload
        csr_clean = csr_pem.replace("\n", "")

        payload = {
            "payload": {
                "csrGenerationSource": "external",
                "csr": csr_clean,
                "caConnectorInfo": {
                    "certificateAuthority": config["ca_type"],
                    "caSettingName": config["ca_setting_name"],
                    "name": f"{config['ca_type']} connector",
                    "csrParameters": {
                        "commonName": config["common_name"],
                        "certificateCategories": ["Server"],
                        "enhancedSANTypes": {
                            "dNSNames": config["san_dns"]
                        }
                    },
                    "vendorSpecificDetails": {
                        "templateName": config["ca_template"]
                    },
                    "validityInDays": config["validity_days"]
                },
                "certificateGroup": {
                    "name": config["cert_group"]
                },
                "certificateFormat": {
                    "format": "CRT",
                    "password": ""
                }
            }
        }

        response = self._request("POST", "certificate-requests", payload)
        request_id = (response.get("response", {}).get("requestId") or
                      response.get("response", {}).get("id"))

        if not request_id:
            raise RuntimeError(f"Failed to get request ID from response: {response}")

        self.logger.info(f"Certificate request submitted. Request ID: {request_id}")
        return request_id

    # Step 4: Poll for issuance
    def poll_for_certificate(self, request_id: str,
                             interval: int, max_attempts: int) -> str:
        self.logger.info(
            f"Step 4: Polling for certificate issuance (Request ID: {request_id})..."
        )

        for attempt in range(1, max_attempts + 1):
            response = self._request("GET", f"certificate-requests/{request_id}")
            status = response.get("response", {}).get("status", "UNKNOWN")
            self.logger.info(f"  Attempt {attempt}/{max_attempts} — Status: {status}")

            if status in ("ISSUED", "ACTIVE"):
                serial = response.get("response", {}).get("serialNumber", "")
                self.logger.info(f"Certificate issued. Serial: {serial}")
                return serial

            if status in ("REJECTED", "FAILED"):
                raise RuntimeError(f"Certificate request {status}: {response}")

            time.sleep(interval)

        raise TimeoutError(
            f"Certificate not issued after {max_attempts * interval} seconds."
        )

    # Step 5: Download certificate
    def download_certificate(self, serial: str, common_name: str) -> dict:
        self.logger.info("Step 5: Downloading certificate from AppViewX...")

        payload = {
            "payload": {
                "serialNumber": serial,
                "commonName": common_name,
                "isChainRequired": "true",
                "isKeyRequired": "false",
                "format": "CRT"
            }
        }

        response = self._request("POST", "certificate-download", payload)
        cert_data = response.get("response", {})

        if not cert_data.get("certificate"):
            raise RuntimeError(f"Certificate download failed: {response}")

        self.logger.info("Certificate downloaded successfully.")
        return cert_data


# =============================================================================
# CSR GENERATION
# =============================================================================

def generate_csr_with_cryptography(common_name: str, organization: str,
                                    san_dns: list, key_file: str,
                                    logger: logging.Logger) -> str:
    """Generate a private key and CSR using the cryptography library."""
    logger.info("Step 2: Generating private key and CSR (cryptography library)...")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Write private key
    Path(key_file).parent.mkdir(parents=True, exist_ok=True)
    with open(key_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    os.chmod(key_file, 0o600)

    # Build CSR
    san_list = [x509.DNSName(dns) for dns in san_dns]
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        ]))
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .sign(private_key, hashes.SHA256())
    )

    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    logger.info(f"CSR generated for CN={common_name}")
    return csr_pem


def generate_csr_with_openssl(common_name: str, organization: str,
                               san_dns: list, key_file: str,
                               logger: logging.Logger) -> str:
    """Fallback: generate CSR using openssl subprocess."""
    logger.info("Step 2: Generating private key and CSR (openssl)...")

    Path(key_file).parent.mkdir(parents=True, exist_ok=True)
    csr_file = "/tmp/appviewx_server.csr"
    san_string = ",".join([f"DNS:{d}" for d in san_dns])

    subprocess.run([
        "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
        "-keyout", key_file,
        "-out", csr_file,
        "-subj", f"/CN={common_name}/O={organization}",
        "-addext", f"subjectAltName={san_string}"
    ], check=True, capture_output=True)

    os.chmod(key_file, 0o600)

    with open(csr_file, "r") as f:
        csr_pem = f.read()

    os.remove(csr_file)
    logger.info(f"CSR generated for CN={common_name}")
    return csr_pem


# =============================================================================
# CERTIFICATE INSTALLATION
# =============================================================================

def install_certificate(cert_data: dict, config: dict,
                         logger: logging.Logger) -> None:
    """Write certificate and chain to disk and verify key pair."""
    logger.info(f"Step 6: Installing certificate to {config['cert_dir']}...")

    Path(config["cert_dir"]).mkdir(parents=True, exist_ok=True)

    # Write certificate
    with open(config["cert_file"], "w") as f:
        f.write(cert_data["certificate"])
    os.chmod(config["cert_file"], 0o644)

    # Write chain if present
    if cert_data.get("chain"):
        with open(config["chain_file"], "w") as f:
            f.write(cert_data["chain"])
        os.chmod(config["chain_file"], 0o644)
        logger.info(f"Chain installed: {config['chain_file']}")

    logger.info(f"Certificate installed: {config['cert_file']}")
    logger.info(f"Private key location:  {config['key_file']}")

    # Verify key pair matches
    cert_mod = subprocess.check_output(
        ["openssl", "x509", "-noout", "-modulus", "-in", config["cert_file"]]
    )
    key_mod = subprocess.check_output(
        ["openssl", "rsa", "-noout", "-modulus", "-in", config["key_file"]]
    )

    if hashlib.md5(cert_mod).digest() != hashlib.md5(key_mod).digest():
        raise RuntimeError("Certificate and private key modulus mismatch!")

    logger.info("Certificate and key pair verified successfully.")


def reload_service(service: str, logger: logging.Logger) -> None:
    """Reload the web service to apply the new certificate."""
    if not service:
        logger.info("Step 7: Service reload skipped (not configured).")
        return

    logger.info(f"Step 7: Reloading service: {service}...")

    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", service]
    )
    if result.returncode == 0:
        subprocess.run(["systemctl", "reload", service], check=True)
        logger.info(f"Service '{service}' reloaded successfully.")
    else:
        logger.warning(f"Service '{service}' is not running. Skipping reload.")


# =============================================================================
# MAIN
# =============================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="AppViewX Pull Automation — Certificate Request Script"
    )
    parser.add_argument("--cn", help="Override Common Name (default: server FQDN)")
    parser.add_argument("--ca", help="Override CA setting name")
    parser.add_argument("--group", help="Override certificate group")
    return parser.parse_args()


def main():
    args = parse_args()
    config = CONFIG.copy()

    # CLI overrides
    if args.cn:
        config["common_name"] = args.cn
        config["san_dns"] = [args.cn]
    if args.ca:
        config["ca_setting_name"] = args.ca
    if args.group:
        config["cert_group"] = args.group

    logger = setup_logging(config["log_file"])

    logger.info("=" * 60)
    logger.info(" AppViewX Pull Automation — Certificate Request Start")
    logger.info("=" * 60)

    try:
        # Step 2: Generate CSR
        if CRYPTO_AVAILABLE:
            csr_pem = generate_csr_with_cryptography(
                config["common_name"], config["organization"],
                config["san_dns"], config["key_file"], logger
            )
        else:
            logger.warning("cryptography library not found — using openssl subprocess.")
            csr_pem = generate_csr_with_openssl(
                config["common_name"], config["organization"],
                config["san_dns"], config["key_file"], logger
            )

        # Steps 1, 3, 4, 5 via API client
        client = AppViewXClient(config, logger)
        client.authenticate()                                          # Step 1
        request_id = client.request_certificate(csr_pem, config)      # Step 3
        serial = client.poll_for_certificate(                          # Step 4
            request_id,
            config["poll_interval"],
            config["poll_max_attempts"]
        )
        cert_data = client.download_certificate(                       # Step 5
            serial, config["common_name"]
        )

        install_certificate(cert_data, config, logger)                 # Step 6
        reload_service(config["service_reload"], logger)               # Step 7

        logger.info("=" * 60)
        logger.info(" Certificate lifecycle completed successfully.")
        logger.info(f" CN   : {config['common_name']}")
        logger.info(f" Cert : {config['cert_file']}")
        logger.info(f" Key  : {config['key_file']}")
        logger.info("=" * 60)

    except Exception as e:
        logger.error(f"FATAL: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()