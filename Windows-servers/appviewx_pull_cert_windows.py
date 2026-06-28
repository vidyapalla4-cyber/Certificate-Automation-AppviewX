#!/usr/bin/env python3
"""
=============================================================================
AppViewX Pull Automation - Certificate Request Script (Python / Windows)
=============================================================================
Description : Requests and downloads a certificate from AppViewX CLM
              using the pull method (server-initiated via REST API).
              Designed to run on Windows servers as a Scheduled Task
              or on-demand from the command line.

Usage       : python appviewx_pull_cert_windows.py
              python appviewx_pull_cert_windows.py --cn web01.example.com
              python appviewx_pull_cert_windows.py --cn web01.example.com --ca InternalCA-Prod

Requirements: Python 3.6+
              pip install cryptography pywin32 requests
              Run as Administrator (required for cert store and IIS operations)
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
import tempfile
import time
from pathlib import Path

import urllib.request
import urllib.error
import ssl

# Optional: cryptography library for CSR generation
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Optional: pywin32 for Windows certificate store operations
try:
    import win32con
    import wincertstore
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

# =============================================================================
# CONFIGURATION — Update these values for your environment
# =============================================================================

CONFIG = {
    # AppViewX server
    "avx_host": "https://<APPVIEWX_HOST_OR_IP>",
    "avx_port": "31443",

    # Service Account credentials
    "client_id": "<YOUR_CLIENT_ID>",
    "client_secret": "<YOUR_CLIENT_SECRET>",

    # Certificate parameters
    "common_name": socket.getfqdn(),
    "san_dns": [socket.getfqdn()],
    "organization": "Your Organization",
    "ca_setting_name": "<YOUR_CA_SETTING_NAME>",
    "ca_type": "Microsoft Enterprise",         # e.g. Microsoft Enterprise, DigiCert
    "ca_template": "WebServer",                # MS CA template or equivalent
    "validity_days": 365,
    "cert_group": "Windows-Servers",

    # Certificate install paths
    "cert_dir": r"C:\AppViewX\Certs",
    "cert_file": r"C:\AppViewX\Certs\server.crt",
    "key_file": r"C:\AppViewX\Certs\server.key",
    "chain_file": r"C:\AppViewX\Certs\chain.crt",
    "pfx_file": r"C:\AppViewX\Certs\server.pfx",
    "pfx_password": "ChangeMe123!",            # PFX export password

    # Windows Certificate Store
    "import_to_store": True,
    "cert_store": "MY",                        # MY = Personal, ROOT = Trusted Root

    # IIS binding update (set iis_site_name to "" to skip)
    "iis_site_name": "Default Web Site",
    "iis_port": 443,

    # Polling
    "poll_interval": 10,
    "poll_max_attempts": 30,

    # TLS — set to False only for self-signed AppViewX certs
    "verify_ssl": True,

    # Logging
    "log_file": r"C:\AppViewX\Logs\appviewx_pull_cert.log",
}

# =============================================================================
# LOGGING SETUP
# =============================================================================

def setup_logging(log_file: str) -> logging.Logger:
    logger = logging.getLogger("appviewx")
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    try:
        log_dir = os.path.dirname(log_file)
        os.makedirs(log_dir, exist_ok=True)
        fh = logging.FileHandler(log_file)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    except PermissionError:
        logger.warning(f"Cannot write log to {log_file}. Logging to console only.")
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

        self.ssl_context = ssl.create_default_context()
        if not self.verify_ssl:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE

    def _request(self, method: str, endpoint: str,
                 payload: dict = None, extra_headers: dict = None) -> dict:
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
            err_body = e.read().decode("utf-8")
            self.logger.error(f"HTTP {e.code} on {endpoint}: {err_body}")
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
        req = urllib.request.Request(
            url, data=b"",
            headers={
                "Authorization": f"Basic {credentials}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST"
        )
        with urllib.request.urlopen(req, context=self.ssl_context) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        self.auth_token = data.get("response")
        if not self.auth_token:
            raise RuntimeError(f"Authentication failed: {data}")

        self.logger.info("Authentication successful. Token obtained.")

    # Step 3: Submit certificate request
    def request_certificate(self, csr_pem: str, config: dict) -> str:
        self.logger.info("Step 3: Submitting certificate request to AppViewX...")

        csr_clean = csr_pem.replace("\r\n", "").replace("\n", "")
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
                "certificateGroup": {"name": config["cert_group"]},
                "certificateFormat": {"format": "CRT", "password": ""}
            }
        }

        response = self._request("POST", "certificate-requests", payload)
        request_id = (
            response.get("response", {}).get("requestId") or
            response.get("response", {}).get("id")
        )
        if not request_id:
            raise RuntimeError(f"No Request ID in response: {response}")

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
    """Generate private key and CSR using the cryptography library."""
    logger.info("Step 2: Generating private key and CSR (cryptography library)...")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    os.makedirs(os.path.dirname(key_file), exist_ok=True)
    with open(key_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

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


def generate_csr_with_certreq(common_name: str, organization: str,
                               san_dns: list, key_file: str,
                               logger: logging.Logger) -> str:
    """Fallback: generate CSR using Windows certreq.exe."""
    logger.info("Step 2: Generating private key and CSR (Windows certreq.exe)...")

    san_string = "&".join([f"dns={d}" for d in san_dns])
    inf_content = f"""[Version]
Signature = "$Windows NT$"

[NewRequest]
Subject               = "CN={common_name}, O={organization}"
KeySpec               = 1
KeyLength             = 2048
Exportable            = TRUE
MachineKeySet         = TRUE
ProviderName          = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType          = 12
RequestType           = PKCS10
KeyUsage              = 0xa0
HashAlgorithm         = SHA256

[EnhancedKeyUsageExtension]
OID = 1.3.6.1.5.5.7.3.1

[Extensions]
2.5.29.17 = "{{text}}"
_continue_ = "{san_string}"
"""

    os.makedirs(os.path.dirname(key_file) if os.path.dirname(key_file) else ".", exist_ok=True)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".inf", delete=False) as inf_f:
        inf_f.write(inf_content)
        inf_file = inf_f.name

    csr_file = inf_file.replace(".inf", ".csr")

    try:
        result = subprocess.run(
            ["certreq.exe", "-new", "-q", inf_file, csr_file],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            raise RuntimeError(f"certreq.exe failed: {result.stdout} {result.stderr}")

        with open(csr_file, "r") as f:
            csr_pem = f.read()

        # Write a placeholder key file for record-keeping
        # (actual key is managed by Windows key store via certreq)
        with open(key_file, "w") as f:
            f.write("# Private key managed by Windows CNG/CSP key store\n")
            f.write(f"# CN: {common_name}\n")
            f.write("# Use certreq -accept to bind the issued certificate\n")

        logger.info(f"CSR generated for CN={common_name}")
        return csr_pem

    finally:
        for f in [inf_file, csr_file]:
            try:
                os.remove(f)
            except OSError:
                pass


# =============================================================================
# CERTIFICATE INSTALLATION
# =============================================================================

def install_certificate(cert_data: dict, config: dict, logger: logging.Logger) -> str:
    """Write certificate and chain to disk, build PFX, import to Windows store."""
    logger.info(f"Step 6: Installing certificate to {config['cert_dir']}...")

    os.makedirs(config["cert_dir"], exist_ok=True)

    # Write PEM files
    with open(config["cert_file"], "w") as f:
        f.write(cert_data["certificate"])

    if cert_data.get("chain"):
        with open(config["chain_file"], "w") as f:
            f.write(cert_data["chain"])
        logger.info(f"Chain installed: {config['chain_file']}")

    logger.info(f"Certificate installed: {config['cert_file']}")

    thumbprint = None

    # Accept cert into Windows store via certreq (binds to pending private key)
    logger.info("Binding certificate to private key via certreq -accept...")
    result = subprocess.run(
        ["certreq.exe", "-accept", "-q", config["cert_file"]],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        logger.warning(f"certreq -accept warning: {result.stdout} {result.stderr}")

    # Find the newly imported cert and get its thumbprint
    ps_cmd = (
        f"(Get-ChildItem Cert:\\LocalMachine\\My | "
        f"Where-Object {{ $_.Subject -like '*{config['common_name']}*' }} | "
        f"Sort-Object NotAfter -Descending | Select-Object -First 1).Thumbprint"
    )
    ps_result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", ps_cmd],
        capture_output=True, text=True
    )
    thumbprint = ps_result.stdout.strip()

    if thumbprint:
        logger.info(f"Certificate thumbprint: {thumbprint}")

        # Export PFX
        export_cmd = (
            f"$pwd = ConvertTo-SecureString '{config['pfx_password']}' -AsPlainText -Force; "
            f"Export-PfxCertificate -Cert Cert:\\LocalMachine\\My\\{thumbprint} "
            f"-FilePath '{config['pfx_file']}' -Password $pwd"
        )
        subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", export_cmd],
            capture_output=True, check=True
        )
        logger.info(f"PFX exported: {config['pfx_file']}")
    else:
        logger.warning("Could not locate certificate thumbprint. Skipping PFX export.")

    return thumbprint or ""


def update_iis_binding(thumbprint: str, config: dict, logger: logging.Logger) -> None:
    """Update IIS SSL binding with the new certificate thumbprint."""
    if not config.get("iis_site_name"):
        logger.info("Step 7: IIS binding update skipped (iis_site_name not set).")
        return

    logger.info(f"Step 7: Updating IIS SSL binding for site '{config['iis_site_name']}'...")

    if not thumbprint:
        logger.warning("No thumbprint available. Skipping IIS binding update.")
        return

    ps_cmd = (
        f"Import-Module WebAdministration -ErrorAction Stop; "
        f"Remove-WebBinding -Name '{config['iis_site_name']}' "
        f"-Protocol https -Port {config['iis_port']} -ErrorAction SilentlyContinue; "
        f"New-WebBinding -Name '{config['iis_site_name']}' "
        f"-Protocol https -Port {config['iis_port']} -IPAddress '*'; "
        f"$binding = Get-WebBinding -Name '{config['iis_site_name']}' "
        f"-Protocol https -Port {config['iis_port']}; "
        f"$binding.AddSslCertificate('{thumbprint}', 'My')"
    )

    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", ps_cmd],
        capture_output=True, text=True
    )

    if result.returncode != 0:
        logger.warning(f"IIS binding update warning: {result.stderr}")
    else:
        logger.info(f"IIS SSL binding updated for '{config['iis_site_name']}' "
                    f"on port {config['iis_port']}.")


# =============================================================================
# MAIN
# =============================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="AppViewX Pull Automation — Certificate Request Script (Windows)"
    )
    parser.add_argument("--cn",    help="Override Common Name (default: server FQDN)")
    parser.add_argument("--ca",    help="Override CA setting name")
    parser.add_argument("--group", help="Override certificate group")
    return parser.parse_args()


def main():
    args = parse_args()
    config = CONFIG.copy()

    if args.cn:
        config["common_name"] = args.cn
        config["san_dns"] = [args.cn]
    if args.ca:
        config["ca_setting_name"] = args.ca
    if args.group:
        config["cert_group"] = args.group

    logger = setup_logging(config["log_file"])

    logger.info("=" * 60)
    logger.info(" AppViewX Pull Automation — Certificate Request Start (Windows)")
    logger.info("=" * 60)

    try:
        # Step 2: Generate CSR
        if CRYPTO_AVAILABLE:
            csr_pem = generate_csr_with_cryptography(
                config["common_name"], config["organization"],
                config["san_dns"], config["key_file"], logger
            )
        else:
            logger.warning("cryptography library not found — using certreq.exe fallback.")
            csr_pem = generate_csr_with_certreq(
                config["common_name"], config["organization"],
                config["san_dns"], config["key_file"], logger
            )

        # Steps 1, 3, 4, 5 via API client
        client = AppViewXClient(config, logger)
        client.authenticate()                                            # Step 1
        request_id = client.request_certificate(csr_pem, config)        # Step 3
        serial = client.poll_for_certificate(                            # Step 4
            request_id, config["poll_interval"], config["poll_max_attempts"]
        )
        cert_data = client.download_certificate(serial, config["common_name"])  # Step 5

        thumbprint = install_certificate(cert_data, config, logger)     # Step 6
        update_iis_binding(thumbprint, config, logger)                  # Step 7

        logger.info("=" * 60)
        logger.info(" Certificate lifecycle completed successfully.")
        logger.info(f" CN    : {config['common_name']}")
        logger.info(f" Cert  : {config['cert_file']}")
        logger.info(f" PFX   : {config['pfx_file']}")
        if thumbprint:
            logger.info(f" Thumb : {thumbprint}")
        logger.info("=" * 60)

    except Exception as e:
        logger.error(f"FATAL: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
