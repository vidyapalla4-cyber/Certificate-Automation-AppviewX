# =============================================================================
# AppViewX Pull Automation - Certificate Request Script (PowerShell)
# =============================================================================
# Description : Requests and downloads a certificate from AppViewX CLM
#               using the pull method (server-initiated via REST API).
#               Designed to run on Windows servers as a Scheduled Task
#               or on-demand.
#
# Usage       : .\appviewx_pull_cert.ps1
#               .\appviewx_pull_cert.ps1 -CN "web01.example.com"
#
# Requirements: PowerShell 5.1+ or PowerShell 7+
#               Run as Administrator (required for cert store and IIS reload)
# =============================================================================

[CmdletBinding()]
param(
    [string]$CN       = "",   # Override Common Name (default: server FQDN)
    [string]$CA       = "",   # Override CA setting name
    [string]$Group    = ""    # Override certificate group
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# =============================================================================
# CONFIGURATION — Update these values for your environment
# =============================================================================

$Config = @{
    # AppViewX server
    AvxHost             = "https://<APPVIEWX_HOST_OR_IP>"
    AvxPort             = "31443"

    # Service Account credentials
    ClientId            = "<YOUR_CLIENT_ID>"
    ClientSecret        = "<YOUR_CLIENT_SECRET>"

    # Certificate parameters
    CommonName          = if ($CN) { $CN } else { [System.Net.Dns]::GetHostEntry("").HostName }
    SanDns              = @( if ($CN) { $CN } else { [System.Net.Dns]::GetHostEntry("").HostName } )
    Organization        = "Your Organization"
    CaSettingName       = if ($CA) { $CA } else { "<YOUR_CA_SETTING_NAME>" }
    CaType              = "Microsoft Enterprise"   # e.g. Microsoft Enterprise, DigiCert
    CaTemplate          = "WebServer"              # MS CA template or equivalent
    ValidityDays        = 365
    CertGroup           = if ($Group) { $Group } else { "Windows-Servers" }

    # Certificate install paths
    CertDir             = "C:\AppViewX\Certs"
    CertFile            = "C:\AppViewX\Certs\server.crt"
    KeyFile             = "C:\AppViewX\Certs\server.key"
    ChainFile           = "C:\AppViewX\Certs\chain.crt"
    PfxFile             = "C:\AppViewX\Certs\server.pfx"
    PfxPassword         = "ChangeMe123!"           # PFX export password

    # Windows Certificate Store (optional — imports PFX into store after download)
    ImportToStore       = $true
    CertStore           = "LocalMachine"           # LocalMachine or CurrentUser
    CertStoreName       = "My"                     # My = Personal store

    # IIS binding update (set SiteName to "" to skip)
    IISSiteName         = "Default Web Site"       # IIS site to update SSL binding
    IISPort             = 443

    # Service to restart after cert install (set to "" to skip)
    ServiceRestart      = ""                       # e.g. "W3SVC" for IIS

    # Polling settings
    PollInterval        = 10                       # seconds between status checks
    PollMaxAttempts     = 30

    # TLS — set to $false only for self-signed AppViewX certificates
    VerifyTls           = $true

    # Log file
    LogFile             = "C:\AppViewX\Logs\appviewx_pull_cert.log"
}

# =============================================================================
# LOGGING
# =============================================================================

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] $Level — $Message"
    Write-Host $line
    $logDir = Split-Path $Config.LogFile -Parent
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    Add-Content -Path $Config.LogFile -Value $line
}

# =============================================================================
# TLS HANDLING
# =============================================================================

function Set-TlsPolicy {
    if (-not $Config.VerifyTls) {
        Write-Log "WARNING: TLS verification disabled. Do not use in production." "WARN"
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }
    # Ensure TLS 1.2 and 1.3 are enabled
    [System.Net.ServicePointManager]::SecurityProtocol = `
        [System.Net.SecurityProtocolType]::Tls12 -bor `
        [System.Net.SecurityProtocolType]::Tls13
}

# =============================================================================
# API HELPERS
# =============================================================================

function Invoke-AvxApi {
    param(
        [string]$Method,
        [string]$Endpoint,
        [hashtable]$Body = $null,
        [hashtable]$ExtraHeaders = @{}
    )

    $baseUrl = "$($Config.AvxHost):$($Config.AvxPort)/avxapi"
    $url = "${baseUrl}/${Endpoint}?gwsource=external"

    $headers = @{ "Content-Type" = "application/json" }
    if ($script:AuthToken) {
        $headers["Authorization"] = "Bearer $script:AuthToken"
    }
    foreach ($k in $ExtraHeaders.Keys) { $headers[$k] = $ExtraHeaders[$k] }

    $params = @{
        Uri             = $url
        Method          = $Method
        Headers         = $headers
        UseBasicParsing = $true
    }

    if ($Body) {
        $params["Body"] = ($Body | ConvertTo-Json -Depth 10)
    }

    try {
        $response = Invoke-RestMethod @params
        return $response
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.Value__
        Write-Log "HTTP $statusCode error on ${Endpoint}: $($_.Exception.Message)" "ERROR"
        throw
    }
}

# =============================================================================
# STEP 1 — AUTHENTICATE
# =============================================================================

function Get-AuthToken {
    Write-Log "Step 1: Authenticating with AppViewX (Service Account)..."

    $credentials = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes("$($Config.ClientId):$($Config.ClientSecret)")
    )

    $baseUrl = "$($Config.AvxHost):$($Config.AvxPort)/avxapi"
    $url = "${baseUrl}/acctmgmt-get-service-token?gwsource=external"

    $response = Invoke-RestMethod -Uri $url -Method POST `
        -Headers @{
            "Authorization"  = "Basic $credentials"
            "Content-Type"   = "application/x-www-form-urlencoded"
        } `
        -UseBasicParsing

    $script:AuthToken = $response.response
    if (-not $script:AuthToken) {
        throw "Authentication failed. Response: $($response | ConvertTo-Json)"
    }

    Write-Log "Authentication successful. Token obtained."
}

# =============================================================================
# STEP 2 — GENERATE CSR USING WINDOWS CERTREQ
# =============================================================================

function New-CsrAndKey {
    Write-Log "Step 2: Generating private key and CSR using Windows CertReq..."

    if (-not (Test-Path $Config.CertDir)) {
        New-Item -ItemType Directory -Path $Config.CertDir -Force | Out-Null
        Write-Log "Created certificate directory: $($Config.CertDir)"
    }

    $sanList = ($Config.SanDns | ForEach-Object { "dns=$_" }) -join "&"
    $infFile = "$env:TEMP\appviewx_request.inf"
    $csrFile = "$env:TEMP\appviewx_request.csr"

    $infContent = @"
[Version]
Signature = "`$Windows NT`$"

[NewRequest]
Subject               = "CN=$($Config.CommonName), O=$($Config.Organization)"
KeySpec               = 1
KeyLength             = 2048
Exportable            = TRUE
MachineKeySet         = TRUE
SMIME                 = FALSE
PrivateKeyArchive     = FALSE
UserProtected         = FALSE
UseExistingKeySet     = FALSE
ProviderName          = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType          = 12
RequestType           = PKCS10
KeyUsage              = 0xa0
HashAlgorithm         = SHA256

[EnhancedKeyUsageExtension]
OID = 1.3.6.1.5.5.7.3.1    ; Server Authentication

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "$sanList"
"@

    Set-Content -Path $infFile -Value $infContent -Encoding UTF8

    $certreqOutput = & certreq.exe -new -q $infFile $csrFile 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "certreq.exe failed: $certreqOutput"
    }

    $script:CsrContent = (Get-Content $csrFile -Raw).Replace("`r`n", "").Replace("`n", "")
    Write-Log "CSR generated successfully for CN=$($Config.CommonName)"

    # Cleanup temp files
    Remove-Item $infFile -Force -ErrorAction SilentlyContinue
    Remove-Item $csrFile -Force -ErrorAction SilentlyContinue
}

# =============================================================================
# STEP 3 — SUBMIT CERTIFICATE REQUEST
# =============================================================================

function Submit-CertificateRequest {
    Write-Log "Step 3: Submitting certificate request to AppViewX..."

    $body = @{
        payload = @{
            csrGenerationSource = "external"
            csr                 = $script:CsrContent
            caConnectorInfo     = @{
                certificateAuthority = $Config.CaType
                caSettingName        = $Config.CaSettingName
                name                 = "$($Config.CaType) connector"
                csrParameters        = @{
                    commonName              = $Config.CommonName
                    certificateCategories   = @("Server")
                    enhancedSANTypes        = @{
                        dNSNames = $Config.SanDns
                    }
                }
                vendorSpecificDetails = @{
                    templateName = $Config.CaTemplate
                }
                validityInDays = $Config.ValidityDays
            }
            certificateGroup    = @{ name = $Config.CertGroup }
            certificateFormat   = @{ format = "CRT"; password = "" }
        }
    }

    $response = Invoke-AvxApi -Method "POST" -Endpoint "certificate-requests" -Body $body

    $script:RequestId = $response.response.requestId
    if (-not $script:RequestId) {
        $script:RequestId = $response.response.id
    }
    if (-not $script:RequestId) {
        throw "Failed to retrieve Request ID. Response: $($response | ConvertTo-Json -Depth 5)"
    }

    Write-Log "Certificate request submitted. Request ID: $($script:RequestId)"
}

# =============================================================================
# STEP 4 — POLL FOR CERTIFICATE ISSUANCE
# =============================================================================

function Wait-ForCertificate {
    Write-Log "Step 4: Polling for certificate issuance (Request ID: $($script:RequestId))..."

    for ($i = 1; $i -le $Config.PollMaxAttempts; $i++) {
        $response = Invoke-AvxApi -Method "GET" `
            -Endpoint "certificate-requests/$($script:RequestId)"

        $status = $response.response.status
        Write-Log "  Attempt $i/$($Config.PollMaxAttempts) — Status: $status"

        if ($status -in @("ISSUED", "ACTIVE")) {
            $script:CertSerial = $response.response.serialNumber
            Write-Log "Certificate issued successfully. Serial: $($script:CertSerial)"
            return
        }

        if ($status -in @("REJECTED", "FAILED")) {
            throw "Certificate request $status. Response: $($response | ConvertTo-Json -Depth 5)"
        }

        Start-Sleep -Seconds $Config.PollInterval
    }

    throw "Timed out waiting for certificate issuance after $($Config.PollMaxAttempts * $Config.PollInterval) seconds."
}

# =============================================================================
# STEP 5 — DOWNLOAD CERTIFICATE
# =============================================================================

function Get-IssuedCertificate {
    Write-Log "Step 5: Downloading certificate from AppViewX..."

    $body = @{
        payload = @{
            serialNumber    = $script:CertSerial
            commonName      = $Config.CommonName
            isChainRequired = "true"
            isKeyRequired   = "false"
            format          = "CRT"
        }
    }

    $response = Invoke-AvxApi -Method "POST" -Endpoint "certificate-download" -Body $body

    $script:CertContent  = $response.response.certificate
    $script:ChainContent = $response.response.chain

    if (-not $script:CertContent) {
        throw "Certificate download failed. Response: $($response | ConvertTo-Json -Depth 5)"
    }

    Write-Log "Certificate downloaded successfully."
}

# =============================================================================
# STEP 6 — INSTALL CERTIFICATE
# =============================================================================

function Install-Certificate {
    Write-Log "Step 6: Installing certificate to $($Config.CertDir)..."

    # Write PEM files to disk
    Set-Content -Path $Config.CertFile  -Value $script:CertContent  -Encoding ASCII
    if ($script:ChainContent) {
        Set-Content -Path $Config.ChainFile -Value $script:ChainContent -Encoding ASCII
        Write-Log "Chain installed: $($Config.ChainFile)"
    }
    Write-Log "Certificate installed: $($Config.CertFile)"

    # Build PFX from cert + pending key in the Windows cert store
    Write-Log "Building PFX from pending certificate request..."
    $acceptOutput = & certreq.exe -accept -q $Config.CertFile 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "WARNING: certreq accept returned: $acceptOutput" "WARN"
    }

    # Export PFX from Windows certificate store
    $thumbprint = (Get-ChildItem -Path "Cert:\LocalMachine\My" |
        Where-Object { $_.Subject -like "*$($Config.CommonName)*" } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1).Thumbprint

    if ($thumbprint) {
        $pfxPassword = ConvertTo-SecureString -String $Config.PfxPassword -Force -AsPlainText
        Export-PfxCertificate `
            -Cert "Cert:\LocalMachine\My\$thumbprint" `
            -FilePath $Config.PfxFile `
            -Password $pfxPassword | Out-Null
        Write-Log "PFX exported: $($Config.PfxFile)"
        Write-Log "Certificate thumbprint: $thumbprint"
        $script:CertThumbprint = $thumbprint
    }
    else {
        Write-Log "WARNING: Could not locate certificate in store by CN. Skipping PFX export." "WARN"
    }
}

# =============================================================================
# STEP 7 — UPDATE IIS SSL BINDING
# =============================================================================

function Update-IisBinding {
    if (-not $Config.IISSiteName) {
        Write-Log "Step 7: IIS binding update skipped (IISSiteName not set)."
        return
    }

    Write-Log "Step 7: Updating IIS SSL binding for site '$($Config.IISSiteName)'..."

    # Check WebAdministration module
    if (-not (Get-Module -ListAvailable -Name WebAdministration)) {
        Write-Log "WARNING: WebAdministration module not available. Skipping IIS update." "WARN"
        return
    }

    Import-Module WebAdministration -ErrorAction SilentlyContinue

    if ($script:CertThumbprint) {
        # Remove old binding and add new one
        $bindingInfo = "*:$($Config.IISPort):"
        Remove-WebBinding -Name $Config.IISSiteName `
            -Protocol https -Port $Config.IISPort -ErrorAction SilentlyContinue

        New-WebBinding -Name $Config.IISSiteName `
            -Protocol https -Port $Config.IISPort -IPAddress "*"

        $binding = Get-WebBinding -Name $Config.IISSiteName `
            -Protocol https -Port $Config.IISPort
        $binding.AddSslCertificate($script:CertThumbprint, $Config.CertStoreName)

        Write-Log "IIS SSL binding updated for site '$($Config.IISSiteName)' on port $($Config.IISPort)."
    }
    else {
        Write-Log "WARNING: No thumbprint available. Skipping IIS binding update." "WARN"
    }
}

# =============================================================================
# OPTIONAL — RESTART WINDOWS SERVICE
# =============================================================================

function Restart-AppService {
    if (-not $Config.ServiceRestart) {
        Write-Log "Service restart skipped (ServiceRestart not configured)."
        return
    }

    Write-Log "Restarting service: $($Config.ServiceRestart)..."
    $svc = Get-Service -Name $Config.ServiceRestart -ErrorAction SilentlyContinue
    if ($svc) {
        Restart-Service -Name $Config.ServiceRestart -Force
        Write-Log "Service '$($Config.ServiceRestart)' restarted successfully."
    }
    else {
        Write-Log "WARNING: Service '$($Config.ServiceRestart)' not found. Skipping." "WARN"
    }
}

# =============================================================================
# MAIN
# =============================================================================

Write-Log "======================================================"
Write-Log " AppViewX Pull Automation — Certificate Request Start "
Write-Log "======================================================"

try {
    Set-TlsPolicy
    Get-AuthToken           # Step 1
    New-CsrAndKey           # Step 2
    Submit-CertificateRequest  # Step 3
    Wait-ForCertificate     # Step 4
    Get-IssuedCertificate   # Step 5
    Install-Certificate     # Step 6
    Update-IisBinding       # Step 7
    Restart-AppService      # Optional

    Write-Log "======================================================"
    Write-Log " Certificate lifecycle completed successfully."
    Write-Log " CN     : $($Config.CommonName)"
    Write-Log " Cert   : $($Config.CertFile)"
    Write-Log " PFX    : $($Config.PfxFile)"
    if ($script:CertThumbprint) {
        Write-Log " Thumb  : $script:CertThumbprint"
    }
    Write-Log "======================================================"
}
catch {
    Write-Log "FATAL: $_" "ERROR"
    exit 1
}
