# AppViewX CLM — Certificate Pull Automation for Windows Servers

Automate certificate lifecycle management on Windows servers using the **pull method** — the server initiates all requests to AppViewX CLM via REST APIs. No inbound network access from AppViewX to the server is required.

Two implementations are provided for Windows:

| Script | Language | Best For |
|--------|----------|----------|
| `appviewx_pull_cert.ps1` | PowerShell | Native Windows automation, Scheduled Tasks |
| `appviewx_pull_cert_windows.py` | Python 3 | CI/CD pipelines, cross-platform teams |

> **Linux users:** See the companion repository for Bash and Python scripts targeting Linux environments.

---

## Table of Contents

- [Background: Push vs Pull Automation](#background-push-vs-pull-automation)
- [How Pull Automation Works](#how-pull-automation-works)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Usage](#usage)
- [Scheduled Task Setup](#scheduled-task-setup)
- [File and Certificate Store Locations](#file-and-certificate-store-locations)
- [IIS SSL Binding](#iis-ssl-binding)
- [Troubleshooting](#troubleshooting)
- [AppViewX API Reference](#appviewx-api-reference)

---

## Background: Push vs Pull Automation

AppViewX CLM supports two methods for automating certificate deployment on Windows servers.

### Method 1: Push Automation (AppViewX-Initiated)

AppViewX centrally manages and pushes certificates to target Windows servers. The platform generates the CSR, submits it to the CA, and deploys the issued certificate — optionally updating IIS bindings post-deployment.

**Best suited for:** environments where AppViewX has network and WinRM/RPC access to Windows servers and centralized control is preferred.

### Method 2: Pull Automation — This Repository (Server-Initiated)

The Windows server itself initiates the certificate request by calling AppViewX REST APIs. The script handles authentication, CSR generation, request submission, polling, download, installation into the Windows certificate store, IIS binding updates, and optional service restarts — without AppViewX needing any access to the server.

**Best suited for:**
- Servers in DMZ, firewalled, or air-gapped environments
- Teams that prefer server-side control over certificate operations
- CI/CD pipelines and configuration management tools (Ansible, DSC, Chef)
- Environments where WinRM from AppViewX is restricted or blocked

---

## How Pull Automation Works

```
Windows Server                           AppViewX CLM
──────────────────────────────────────────────────────────────────
Step 1: Authenticate     ──POST /acctmgmt-get-service-token ────►
                         ◄─────────────── Bearer Token ──────────

Step 2: Generate CSR locally
        - PowerShell: certreq.exe (Windows CSP/CNG key store)
        - Python    : cryptography library or certreq.exe fallback

Step 3: Submit Request   ──POST /certificate-requests ──────────►
                         ◄─────────────── Request ID ────────────

Step 4: Poll Status      ──GET /certificate-requests/{id} ──────►  (repeat)
                         ◄─────────────── Status: ISSUED ─────────

Step 5: Download Cert    ──POST /certificate-download ───────────►
                         ◄─────────────── CRT + Chain ────────────

Step 6: Install certificate
        - Write .crt and chain.crt to C:\AppViewX\Certs\
        - Accept into Windows certificate store (Local Machine\My)
          via certreq -accept (binds to private key in CSP/CNG)
        - Export combined .pfx with password

Step 7: Update IIS SSL binding with new certificate thumbprint
        (Optional) Restart Windows service
```

---

## Prerequisites

### PowerShell Script (`appviewx_pull_cert.ps1`)

| Requirement | Details |
|-------------|---------|
| PowerShell 5.1+ or 7+ | Pre-installed on Windows Server 2016+ |
| `certreq.exe` | Pre-installed on all Windows Server editions |
| `WebAdministration` module | Pre-installed with IIS role (for IIS binding update) |
| Administrator privileges | Required for cert store and IIS operations |

Enable PowerShell script execution if not already done:
```powershell
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine
```

### Python Script (`appviewx_pull_cert_windows.py`)

| Requirement | Install Command |
|-------------|----------------|
| Python 3.6+ | [python.org](https://www.python.org/downloads/) |
| `cryptography` | `pip install cryptography` (optional — falls back to `certreq.exe`) |
| `certreq.exe` | Pre-installed on Windows Server |
| Administrator privileges | Required for cert store and IIS operations |

```powershell
pip install cryptography
```

### AppViewX Requirements

- AppViewX CLM v2023.1.0_FP3 or later
- A **Service Account** configured in AppViewX CLM (recommended over username/password)
- A CA connector configured and named in AppViewX
- A Certificate Group created for Windows server certificates

---

## Configuration

Edit the configuration section at the top of each script before running.

| Parameter | Description | Example |
|-----------|-------------|---------|
| `AvxHost` / `avx_host` | AppViewX server URL | `https://avx.example.com` |
| `AvxPort` / `avx_port` | AppViewX gateway port | `31443` |
| `ClientId` / `client_id` | Service Account Client ID | `521c3ad2-ea4e-...` |
| `ClientSecret` / `client_secret` | Service Account Client Secret | `55AU#NO8$*Z...` |
| `CommonName` / `common_name` | Certificate CN (defaults to server FQDN) | `web01.example.com` |
| `SanDns` / `san_dns` | Subject Alternative Names | `@("web01.example.com")` |
| `CaSettingName` / `ca_setting_name` | CA setting name in AppViewX | `InternalCA-Prod` |
| `CaType` / `ca_type` | Certificate Authority type | `Microsoft Enterprise` |
| `CaTemplate` / `ca_template` | CA template name | `WebServer` |
| `ValidityDays` / `validity_days` | Certificate validity in days | `365` |
| `CertGroup` / `cert_group` | Certificate group in AppViewX | `Windows-Servers` |
| `PfxPassword` / `pfx_password` | Password for exported PFX file | `ChangeMe123!` |
| `IISSiteName` / `iis_site_name` | IIS site to update SSL binding | `Default Web Site` |
| `IISPort` / `iis_port` | HTTPS port for IIS binding | `443` |
| `ServiceRestart` / `service_restart` | Windows service to restart post-install | `W3SVC` |
| `VerifyTls` / `verify_ssl` | Verify AppViewX TLS certificate | `$true` / `True` |

### Obtaining Service Account Credentials

1. Log in to AppViewX CLM as an administrator
2. Navigate to **Settings → Account Management → Service Accounts**
3. Create a Service Account and assign the `Certificate Request` and `Certificate Download` roles
4. Copy the **Client ID** and **Client Secret** into the script configuration

---

## Usage

> **Note:** Both scripts must be run as **Administrator**.

### PowerShell Script

```powershell
# Run with defaults (uses server FQDN as CN)
.\appviewx_pull_cert.ps1

# Override Common Name
.\appviewx_pull_cert.ps1 -CN "web01.example.com"

# Override CA setting and certificate group
.\appviewx_pull_cert.ps1 -CN "web01.example.com" -CA "InternalCA-Prod" -Group "DMZ-Servers"

# View logs
Get-Content "C:\AppViewX\Logs\appviewx_pull_cert.log" -Wait
```

### Python Script

```powershell
# Run with defaults (uses server FQDN as CN)
python appviewx_pull_cert_windows.py

# Override Common Name
python appviewx_pull_cert_windows.py --cn web01.example.com

# Override CA setting
python appviewx_pull_cert_windows.py --cn web01.example.com --ca InternalCA-Prod

# Override certificate group
python appviewx_pull_cert_windows.py --group DMZ-Servers

# View logs
Get-Content "C:\AppViewX\Logs\appviewx_pull_cert.log" -Wait
```

#### CLI Options (Python)

| Flag | Description |
|------|-------------|
| `--cn` | Override the certificate Common Name |
| `--ca` | Override the CA setting name |
| `--group` | Override the certificate group in AppViewX |

---

## Scheduled Task Setup

Run the script automatically to renew certificates before expiry.

### PowerShell Script via Task Scheduler (GUI)

1. Open **Task Scheduler** → Create Task
2. **General** tab → Name: `AppViewX Certificate Renewal` → Run whether user is logged on or not → Run with highest privileges
3. **Triggers** tab → New → Daily → Start: `06:00 AM`
4. **Actions** tab → New:
   - Program: `powershell.exe`
   - Arguments: `-NonInteractive -ExecutionPolicy Bypass -File "C:\Scripts\appviewx_pull_cert.ps1"`
5. **Settings** tab → Enable: If the task fails, restart every `1 hour`, up to `3 times`

### PowerShell Script via Task Scheduler (Command Line)

```powershell
$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument '-NonInteractive -ExecutionPolicy Bypass -File "C:\Scripts\appviewx_pull_cert.ps1"'

$trigger = New-ScheduledTaskTrigger -Daily -At "06:00AM"

$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

Register-ScheduledTask `
    -TaskName "AppViewX Certificate Renewal" `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Description "Automated certificate renewal via AppViewX pull automation"
```

### Python Script via Task Scheduler

```powershell
$action = New-ScheduledTaskAction `
    -Execute "python.exe" `
    -Argument "C:\Scripts\appviewx_pull_cert_windows.py"

$trigger = New-ScheduledTaskTrigger -Daily -At "06:00AM"

$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

Register-ScheduledTask `
    -TaskName "AppViewX Certificate Renewal (Python)" `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal
```

---

## File and Certificate Store Locations

### Files on Disk

| File | Default Path | Description |
|------|-------------|-------------|
| Certificate (PEM) | `C:\AppViewX\Certs\server.crt` | Issued certificate |
| Private Key | `C:\AppViewX\Certs\server.key` | Private key (PEM) |
| CA Chain (PEM) | `C:\AppViewX\Certs\chain.crt` | Intermediate CA chain |
| PFX Bundle | `C:\AppViewX\Certs\server.pfx` | Certificate + key for IIS/Windows |
| Log File | `C:\AppViewX\Logs\appviewx_pull_cert.log` | Execution log |

### Windows Certificate Store

After installation, the certificate is available at:

```
Certificates (Local Computer) → Personal → Certificates
```

To view via PowerShell:

```powershell
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*web01*" }
```

---

## IIS SSL Binding

The scripts automatically update the IIS HTTPS binding with the new certificate thumbprint after installation.

### Verify the IIS Binding

```powershell
# List all HTTPS bindings on the site
Get-WebBinding -Name "Default Web Site" -Protocol https

# Verify the certificate thumbprint bound to a port
netsh http show sslcert ipport=0.0.0.0:443
```

### Manual Binding Update (if needed)

```powershell
Import-Module WebAdministration

$thumbprint = (Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Subject -like "*web01.example.com*" } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1).Thumbprint

$binding = Get-WebBinding -Name "Default Web Site" -Protocol https -Port 443
$binding.AddSslCertificate($thumbprint, "My")
```

---

## Troubleshooting

**Authentication fails with 401 Unauthorized**
Verify `ClientId` and `ClientSecret` are correct and the Service Account is active. Confirm the account has `Certificate Request` and `Certificate Download` roles in AppViewX.

**Certificate request stays in PENDING**
The CA may require manual approval. Log in to AppViewX CLM → **Certificate Requests** and approve the pending request. Increase `PollMaxAttempts` or `PollInterval` if CA approval takes longer than the default timeout.

**`certreq.exe` fails with access denied**
Ensure the script is running as **Administrator**. Right-click PowerShell → Run as Administrator, or verify the Scheduled Task runs under SYSTEM with highest privileges.

**IIS binding not updating**
Ensure the `WebAdministration` module is installed (requires IIS role). Verify the `IISSiteName` matches exactly:

```powershell
Get-Website | Select-Object Name
```

**TLS/SSL verification errors connecting to AppViewX**
If AppViewX uses a self-signed certificate, set `VerifyTls = $false` (PowerShell) or `"verify_ssl": False` (Python) for testing only. For production, install the AppViewX root CA into the Windows Trusted Root store:

```powershell
Import-Certificate -FilePath "appviewx-ca.crt" `
    -CertStoreLocation Cert:\LocalMachine\Root
```

**PFX export fails**
Ensure `certreq -accept` completed successfully (the certificate was bound to its private key in the Windows CSP key store) before the PFX export step runs. Check the log for warnings from the accept step.

**Python script can't find `certreq.exe`**
`certreq.exe` is located at `C:\Windows\System32\certreq.exe` on all Windows Server editions. Ensure it is in the system `PATH` or invoke it with the full path.

---

## AppViewX API Reference

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/avxapi/acctmgmt-get-service-token` | POST | Obtain Bearer token via Service Account |
| `/avxapi/certificate-requests` | POST | Submit a new certificate request with CSR |
| `/avxapi/certificate-requests/{id}` | GET | Poll request status until ISSUED |
| `/avxapi/certificate-download` | POST | Download issued certificate and CA chain |

All endpoints follow the base URL pattern:

```
https://<AVX_HOST>:<PORT>/avxapi/<endpoint>?gwsource=external
```

For full API documentation, visit the [AppViewX Help Center](https://helpcenter.appviewx.com).

---

## Comparison: Linux vs Windows Scripts

| Feature | Linux (Bash/Python) | Windows (PowerShell/Python) |
|---------|--------------------|-----------------------------|
| CSR generation | `openssl` / `cryptography` | `certreq.exe` / `cryptography` |
| Key storage | PEM file on disk | Windows CSP/CNG key store |
| Certificate store | File system (`/etc/ssl/`) | Windows certificate store (`Cert:\LocalMachine\My`) |
| Certificate bundle | `.crt` + `.key` | `.pfx` (for IIS/Windows apps) |
| Web server binding | `nginx` / `apache2` reload | IIS SSL binding via `WebAdministration` |
| Scheduling | `cron` / `systemd timer` | Windows Task Scheduler |
| Log location | `/var/log/` | `C:\AppViewX\Logs\` |
