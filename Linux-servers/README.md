## Automating Certificate Requests on Linux Servers

AppViewX CLM supports two methods for automating certificate requests 
and deployments on Linux servers.

---

### Method 1: Push Automation (AppViewX-Initiated)

AppViewX centrally manages and pushes certificates to target Linux 
servers. The platform handles CSR generation, CA submission, and 
deploys the issued certificate directly to the configured file path 
on the server — optionally triggering a service reload post-deployment.

Best suited for: environments where AppViewX has network access to 
Linux servers and centralized control is preferred.

---

### Method 2: Pull Automation (Server-Initiated) ← This Script

The Linux server itself initiates the certificate request by calling 
AppViewX REST APIs. A script running on the server handles the full 
flow — from requesting the certificate to downloading and installing 
it locally — without AppViewX needing direct access to the server.

Best suited for: air-gapped servers, DMZ environments, or teams that 
prefer server-side control over certificate operations.

#### How the Pull Flow Works

1. **Authenticate** — The script calls the AppViewX API to obtain 
   an auth token using service account credentials.

2. **Request Certificate** — A certificate request is submitted to 
   AppViewX via API, including the desired CN, SANs, key algorithm, 
   and target CA.

3. **Poll for Status** — The script polls the AppViewX API until 
   the certificate request is approved and issued by the CA.

4. **Download Certificate** — Once issued, the script pulls the 
   signed certificate and private key from AppViewX via API.

5. **Install Locally** — The certificate and key are written to the 
   appropriate paths on the Linux server (e.g., `/etc/ssl/certs/`, 
   `/etc/pki/tls/`).

6. **Reload Service** — The script restarts the relevant service 
   (e.g., `nginx`, `apache2`, `httpd`) to activate the new 
   certificate.

7. **Scheduled Renewal** — A cron job runs the script on a schedule 
   to check expiry and repeat the flow before the certificate expires.

#### Key Advantages of Pull Automation

- No inbound network access required from AppViewX to the Linux server
- Works across firewalled, DMZ, or air-gapped environments
- Server teams retain full control over when and how certificates 
  are installed
- Easily integrated into existing cron jobs, CI/CD pipelines, or 
  configuration management tools (Ansible, Chef, Puppet)
- Audit trail maintained in AppViewX for every API-triggered request
