# SOC Response Playbooks

Actionable triage, containment, eradication, and recovery runbooks mapped directly to the Sigma detection rules in `rules/` and **MITRE ATT&CK**.

| Playbook ID | Triggering Sigma Rule(s) | MITRE ATT&CK | Default Severity |
| :--- | :--- | :--- | :--- |
| **PB-001** | `ssh_brute_force.yml`, `ssh_compromise_correlation.yml` | `T1110.001`, `T1078` | High / Critical |
| **PB-002** | `web_sqli_attempt.yml`, `web_path_traversal.yml` | `T1190` | High |
| **PB-003** | `web_sensitive_file_scan.yml` | `T1595.003` | Medium |
| **PB-004** | `linux_reverse_shell.yml` | `T1059.004` | Critical |
| **PB-005** | `linux_credential_access.yml` | `T1003.008`, `T1552.004` | High |
| **PB-006** | `linux_backdoor_user.yml` | `T1136.001`, `T1548.003` | High |

---

## PB-001 — SSH Brute Force & Suspected Account Compromise
- **MITRE ATT&CK:** `T1110.001` (Password Guessing), `T1078` (Valid Accounts)
- **Triage (First 10 minutes):**
  1. Verify whether `source.ip` belongs to corporate VPN, bastion host, or known CI/CD runner.
  2. Check Threat Intelligence enrichment (`is_malicious`, category, threat actor tags).
  3. Confirm whether an `Accepted password` or `Accepted publickey` event followed the failed burst (critical escalation).
  4. Inspect subsequent host activity (`linux_audit.jsonl`, `w`, `last`, `~/.bash_history`) for the compromised `user.name`.
- **Containment:**
  1. Block `source.ip` at perimeter firewall / AWS Security Group / `iptables` / `fail2ban`.
  2. Lock compromised account immediately (`passwd -l <user>`) and terminate active SSH sessions (`pkill -KILL -u <user>`).
- **Eradication & Hardening:**
  1. Rotate passwords, SSH authorized keys (`~/.ssh/authorized_keys`), and any API tokens accessible to the account.
  2. Enforce SSH key-only authentication (`PasswordAuthentication no`, `PermitRootLogin no`) and restrict SSH to bastion/VPN CIDR blocks.

---

## PB-002 — Web Exploitation Attempt (SQL Injection / Path Traversal)
- **MITRE ATT&CK:** `T1190` (Exploit Public-Facing Application)
- **Triage:**
  1. Review full HTTP request (`url.original`, HTTP method, `user_agent.original`) and response status code (`200` vs `400/403/500`).
  2. Determine whether the attack originated from an authorized DAST scanner during an approved test window.
  3. Check backend application and database logs for SQL syntax errors, abnormal row dumps, or file-read exceptions.
- **Containment:**
  1. Add offending `source.ip` to WAF rate-limit / block list.
  2. If HTTP `200` with leaked data is observed, treat as active data breach and isolate affected service.
- **Eradication & Hardening:**
  1. Fix vulnerable endpoints using parameterized queries / ORM bindings and strict filename allowlists (`os.path.basename` + canonical path verification).
  2. Add regression tests in CI/CD (SAST + unit tests for injection payloads).

---

## PB-003 — Automated Reconnaissance of Sensitive Web Files
- **MITRE ATT&CK:** `T1595.003` (Active Scanning: Wordlist Scanning)
- **Triage:**
  1. Verify all probed paths (`/.env`, `/.git/config`, `/backup.sql`) returned `403` or `404`.
  2. If any sensitive file returned `200`, escalate immediately to **Critical** (exposed secrets).
- **Containment & Hardening:**
  1. Block automated scanner IP at WAF / reverse proxy.
  2. Configure Nginx/Apache to deny dotfiles (`location ~ /\. { deny all; }`) and remove backup archives from webroot.
  3. Rotate any credentials if a `.env` or `.git` file was accidentally exposed.

---

## PB-004 — Linux Reverse Shell / Piped Remote Script Execution
- **MITRE ATT&CK:** `T1059.004` (Command and Scripting Interpreter: Unix Shell)
- **Triage:**
  1. Extract remote IP/domain and port from `process.command_line` (e.g., `/dev/tcp/<ip>/<port>` or `curl http://<domain>`).
  2. Identify parent process (`ppid`), executing user, and active outbound TCP connections (`ss -tunap`).
- **Containment (Immediate — Critical Severity):**
  1. Network-isolate the affected host (quarantine security group / EDR host isolation) while preserving volatile memory and disk evidence.
  2. Block destination C2 IP and domain at egress firewall and DNS sinkhole.
- **Eradication & Recovery:**
  1. Capture forensic artifacts (process tree, `/tmp`, cron jobs, systemd units, SSH keys).
  2. Rebuild the host from a known-good immutable image / IaC template; rotate all host secrets.

---

## PB-005 — Credential File Access (`/etc/shadow` or SSH Keys)
- **MITRE ATT&CK:** `T1003.008` (OS Credential Dumping: `/etc/passwd` and `/etc/shadow`), `T1552.004` (Private Keys)
- **Triage:**
  1. Confirm whether the executing user is an authorized backup/monitoring service account.
  2. Check for follow-on exfiltration commands (`scp`, `curl -F`, `base64`, `nc`).
- **Containment & Eradication:**
  1. Assume all password hashes in `/etc/shadow` and exposed private SSH keys are compromised.
  2. Force password resets for all local accounts and revoke/reissue SSH key pairs across all servers trusting those keys.

---

## PB-006 — Unauthorized Local User Creation / Sudoers Escalation
- **MITRE ATT&CK:** `T1136.001` (Create Account: Local Account), `T1548.003` (Sudo and Sudo Caching)
- **Triage:**
  1. Cross-check the new account name (`useradd`, `usermod`) against IT change-management / IaC provisioning tickets.
  2. Inspect `/etc/passwd`, `/etc/group`, `/etc/sudoers`, and `/etc/sudoers.d/` for unauthorized entries.
- **Containment & Eradication:**
  1. Lock and remove unauthorized persistence accounts (`usermod -L` then `userdel -r` after forensic capture).
  2. Revert unauthorized `sudoers` edits and audit for secondary persistence mechanisms (`cron`, `systemd`, `authorized_keys`).
