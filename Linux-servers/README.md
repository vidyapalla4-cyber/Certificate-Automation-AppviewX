# AppViewX CLM — Certificate Pull Automation for Linux Servers

Automate certificate lifecycle management on Linux servers using the **pull method** — the server initiates all requests to AppViewX CLM via REST APIs. No inbound network access from AppViewX to the server is required.

Two implementations are provided:

| Script | Language | Best For |
|--------|----------|----------|
| `appviewx_pull_cert.sh` | Bash | Simple cron jobs, minimal dependencies |
| `appviewx_pull_cert.py` | Python 3 | CI/CD pipelines, complex workflows |

---

## Table of Contents

- [Background: Push vs Pull Automation](#background-push-vs-pull-automation)
- [How Pull Automation Works](#how-pull-automation-works)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Usage](#usage)
- [Cron Scheduling](#cron-scheduling)
- [File Locations](#file-locations)
- [Troubleshooting](#troubleshooting)

---

## Background: Push vs Pull Automation

AppViewX CLM supports two methods for automating certificate deployment on Linux servers.

### Method 1: Push Automation (AppViewX-Initiated)

AppViewX centrally manages and pushes certificates to target Linux servers. The platform handles CSR generation, CA submission, and deploys the issued certificate directly to the configured file path — optionally triggering a service reload post-deployment.

**Best suited for:** environments where AppViewX has direct SSH/network access to Linux servers and centralized control is preferred.

### Method 2: Pull Automation — This Repository (Server-Initiated)

The Linux server itself initiates the certificate request by calling AppViewX REST APIs. A script running on the server handles the full flow — authenticating, requesting, polling, downloading, and installing the certificate — without AppViewX needing direct access to the server.

**Best suited for:**
- Air-gapped or DMZ servers
- Firewalled environments where inbound access from AppViewX is restricted
- Teams that prefer server-side control over certificate operations
- CI/CD and configuration management integration (Ansible, Puppet, Chef)

---

## How Pull Automation Works

```
Linux Server                           AppViewX CLM
─────────────────────────────────────────────────────────────────
Step 1: Authenticate      ──POST /acctmgmt-get-service-token──►
                          ◄────────────── Bearer Token ─────────

Step 2: Generate CSR locally (openssl / cryptography library)

Step 3: Submit Request    ──POST /certificate-requests ────────►
                          ◄────────────── Request ID ───────────

Step 4: Poll Status       ──GET /certificate-requests/{id} ────►  (repeat)
                          ◄────────────── Status: ISSUED ────────

Step 5: Download Cert     ──POST /certificate-download ─────────►
                          ◄────────────── CRT + Chain ───────────

Step 6: Install cert + key to /etc/ssl/appviewx/
        Verify cert ↔ key pair match

Step 7: Reload web service (nginx / apache2 / httpd)
```

---

## Prerequisites

### Shell Script (`appviewx_pull_cert.sh`)

| Requirement | Install Command |
|-------------|----------------|
| `curl` | `sudo apt install curl` / `sudo yum install curl` |
| `jq` | `sudo apt install jq` / `sudo yum install jq` |
| `openssl` | `sudo apt install openssl` / `sudo yum install openssl` |
| Bash 4+ | Pre-installed on most Linux distros |

### Python Script (`appviewx_pull_cert.py`)

| Requirement | Install Command |
|-------------|----------------|
| Python 3.6+ | Pre-installed on most Linux distros |
| `cryptography` | `pip3 install cryptography` (optional — falls back to `openssl`) |
| `openssl` binary | Required only if `cryptography` is not installed |

### AppViewX Requirements

- AppViewX CLM v2023.1.0_FP3 or later (for Service Account authentication)
- A **Service Account** configured in AppViewX (recommended over username/password)
- A CA connector configured and named in AppViewX CLM
- A Certificate Group created for Linux server certificates

---

## Configuration

Both scripts share the same configuration parameters. Edit the config section at the top of each file before running.

| Parameter | Description | Example |
|-----------|-------------|---------|
| `AVX_HOST` / `avx_host` | AppViewX server URL | `https://avx.example.com` |
| `AVX_PORT` / `avx_port` | AppViewX gateway port | `31443` |
| `AVX_CLIENT_ID` / `client_id` | Service Account Client ID | `521c3ad2-ea4e-...` |
| `AVX_CLIENT_SECRET` / `client_secret` | Service Account Client Secret | `55AU#NO8$*Z...` |
| `CERT_COMMON_NAME` / `common_name` | Certificate CN (defaults to server FQDN) | `web01.example.com` |
| `CERT_SAN_DNS` / `san_dns` | Subject Alternative Names | `web01.example.com` |
| `CERT_CA` / `ca_setting_name` | CA setting name in AppViewX | `InternalCA-Prod` |
| `CERT_CA_TYPE` / `ca_type` | Certificate Authority type | `Microsoft Enterprise` |
| `CERT_TEMPLATE` / `ca_template` | CA template name | `WebServer` |
| `CERT_VALIDITY_DAYS` / `validity_days` | Certificate validity in days | `365` |
| `CERT_GROUP` / `cert_group` | Certificate group in AppViewX | `Linux-Servers` |
| `SERVICE_RELOAD` / `service_reload` | Service to reload post-install | `nginx` |

### Obtaining Service Account Credentials

1. Log in to AppViewX CLM as an administrator
2. Navigate to **Settings → Account Management → Service Accounts**
3. Create a new Service Account and assign the required roles
4. Copy the **Client ID** and **Client Secret** into the script config

---

## Usage

### Shell Script

```bash
# Make executable
chmod +x appviewx_pull_cert.sh

# Run with defaults (uses server FQDN as CN)
sudo ./appviewx_pull_cert.sh

# View logs
tail -f /var/log/appviewx_pull_cert.log
```

### Python Script

```bash
# Run with defaults (uses server FQDN as CN)
sudo python3 appviewx_pull_cert.py

# Override Common Name
sudo python3 appviewx_pull_cert.py --cn web01.example.com

# Override CA setting
sudo python3 appviewx_pull_cert.py --cn web01.example.com --ca InternalCA-Prod

# Override certificate group
sudo python3 appviewx_pull_cert.py --group DMZ-Servers

# View logs
tail -f /var/log/appviewx_pull_cert.log
```

#### Python CLI Options

| Flag | Description |
|------|-------------|
| `--cn` | Override the certificate Common Name |
| `--ca` | Override the CA setting name |
| `--group` | Override the certificate group in AppViewX |

---

## Cron Scheduling

Run the script automatically before certificate expiry. The examples below check and renew 30 days before expiry by running monthly.

### Shell Script (cron)

```bash
# Edit crontab
sudo crontab -e

# Run every day at 06:00 — script handles expiry threshold internally
0 6 * * * /opt/scripts/appviewx_pull_cert.sh >> /var/log/appviewx_cert.log 2>&1
```

### Python Script (cron)

```bash
sudo crontab -e

0 6 * * * /usr/bin/python3 /opt/scripts/appviewx_pull_cert.py >> /var/log/appviewx_cert.log 2>&1
```

### Systemd Timer (alternative to cron)

```ini
# /etc/systemd/system/appviewx-cert.service
[Unit]
Description=AppViewX Certificate Pull Automation

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/scripts/appviewx_pull_cert.py
```

```ini
# /etc/systemd/system/appviewx-cert.timer
[Unit]
Description=Run AppViewX cert pull daily at 06:00

[Timer]
OnCalendar=*-*-* 06:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl enable --now appviewx-cert.timer
sudo systemctl list-timers appviewx-cert.timer
```

---

## File Locations

| File | Path | Permissions |
|------|------|-------------|
| Certificate | `/etc/ssl/appviewx/server.crt` | `644` |
| Private Key | `/etc/ssl/appviewx/server.key` | `600` |
| CA Chain | `/etc/ssl/appviewx/chain.crt` | `644` |
| Log file | `/var/log/appviewx_pull_cert.log` | `644` |

### Referencing in nginx

```nginx
server {
    listen 443 ssl;
    server_name web01.example.com;

    ssl_certificate     /etc/ssl/appviewx/server.crt;
    ssl_certificate_key /etc/ssl/appviewx/server.key;
    ssl_trusted_certificate /etc/ssl/appviewx/chain.crt;
}
```

### Referencing in Apache

```apache
<VirtualHost *:443>
    ServerName web01.example.com
    SSLEngine on
    SSLCertificateFile    /etc/ssl/appviewx/server.crt
    SSLCertificateKeyFile /etc/ssl/appviewx/server.key
    SSLCACertificateFile  /etc/ssl/appviewx/chain.crt
</VirtualHost>
```

---

## Troubleshooting

**Authentication fails with 401**
Verify `client_id` and `client_secret` are correct. Ensure the Service Account is active and has the `Certificate Request` and `Certificate Download` roles assigned in AppViewX.

**Certificate request stays in PENDING**
The CA may require manual approval. Log in to AppViewX CLM, navigate to **Certificate Requests**, and approve the pending request. Increase `POLL_MAX_ATTEMPTS` if approval takes longer than the default timeout.

**Certificate and key mismatch error**
The CSR generation or download may have partially failed. Delete `/etc/ssl/appviewx/server.key` and re-run the script to regenerate both from scratch.

**SSL verification errors connecting to AppViewX**
If AppViewX is using a self-signed certificate, set `verify_ssl: False` (Python) or add `-k` to curl calls (Shell). For production, install the AppViewX CA certificate into the system trust store instead:

```bash
sudo cp appviewx-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

**Service reload fails**
Ensure the script is run as root or a user with `sudo` privileges for `systemctl`. Verify the service name matches exactly: `systemctl status nginx`.

---

## AppViewX API Reference

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/avxapi/acctmgmt-get-service-token` | POST | Obtain Bearer token via Service Account |
| `/avxapi/certificate-requests` | POST | Submit a new certificate request |
| `/avxapi/certificate-requests/{id}` | GET | Poll request status |
| `/avxapi/certificate-download` | POST | Download issued certificate and chain |

All endpoints use the base URL format:
```
https://<AVX_HOST>:<PORT>/avxapi/<endpoint>?gwsource=external
```

For full API documentation, visit the [AppViewX Help Center](https://helpcenter.appviewx.com).
