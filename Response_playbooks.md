## Response Playbooks

### Table of Contents
- [Phishing Attack Response](#playbook-1-phishing-attack-response)
- [Malware Outbreak Response](#playbook-2-malware-outbreak-response)
- [Brute Force Attack Response](#playbook-3-brute-force-attack-response)
- [Data Exfiltration Response](#playbook-4-data-exfiltration-response)

### Incident Response Framework

All playbooks follow this structure:

```
1. PREPARATION
   ├─ Prerequisites
   ├─ Required tools
   └─ Team roles

2. DETECTION
   ├─ Alert triggers
   ├─ Evidence collection
   └─ Initial triage

3. ANALYSIS
   ├─ Scope determination
   ├─ IOC extraction
   └─ Timeline reconstruction

4. CONTAINMENT
   ├─ Isolation procedures
   ├─ Access revocation
   └─ Network segmentation

5. ERADICATION
   ├─ Malware removal
   ├─ Account cleanup
   └─ Vulnerability patching

6. RECOVERY
   ├─ System restoration
   ├─ Service resumption
   └─ Monitoring enhancement

7. POST-INCIDENT
   ├─ Lessons learned
   ├─ Metrics review
   └─ Playbook updates
```

---

### Playbook 1: Phishing Attack Response

#### Preparation
**Prerequisites:**
- Email gateway logs access
- EDR on endpoints
- SIEM correlation rules active
- Sandbox environment ready

**Team Roles:**
- **Incident Commander**: Coordinates response
- **T1 Analyst**: Triages reported emails
- **T2 Analyst**: Performs deep analysis
- **IT Admin**: Implements blocks/removals

#### Detection

**Trigger Scenarios:**
- User reports suspicious email
- Email gateway flags malicious attachment
- EDR detects malicious file execution
- SIEM correlates multiple phishing indicators

**Initial Actions:**
```bash
# 1. Collect the email
# Export full email with headers from mail server

# 2. Check sender reputation
curl -X GET "https://www.virustotal.com/api/v3/domains/{domain}" \
  -H "x-apikey: YOUR_API_KEY"

# 3. Analyze URLs
echo "suspicious-url.com" | \
  curl -X POST "https://urlscan.io/api/v1/scan/" \
  -H "API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d @-

# 4. Check attachment hash
sha256sum suspicious_file.pdf
# Search hash in VirusTotal, MISP
```

#### Analysis

**Email Header Analysis:**
```bash
# Extract and review headers
cat email.eml | grep -E "(From|Return-Path|Received|X-Originating-IP)"

# Check SPF/DKIM/DMARC
# Look for spoofing indicators
```

**Attachment Analysis:**
```bash
# Static analysis
file suspicious_file.pdf
strings suspicious_file.pdf | less
exiftool suspicious_file.pdf

# Sandbox analysis
# Upload to Cuckoo Sandbox or ANY.RUN
```

**Scope Determination:**
```sql
-- Query email logs (example for Exchange)
SELECT 
  Sender, 
  Recipient, 
  Subject, 
  Timestamp
FROM 
  EmailLogs
WHERE 
  (Sender LIKE '%attacker-domain.com%'
  OR Subject LIKE '%Invoice%')
  AND Timestamp > DATEADD(day, -7, GETDATE());
```

#### Containment

**Immediate Actions:**
```bash
# 1. Block sender domain at email gateway
# (Example for Postfix)
echo "attacker-domain.com REJECT" >> /etc/postfix/sender_access
postmap /etc/postfix/sender_access
postfix reload

# 2. Search and delete emails
# (Use PowerShell for O365/Exchange)
Search-Mailbox -Identity "All" \
  -SearchQuery 'Subject:"Malicious Subject"' \
  -DeleteContent -Force

# 3. Block malicious URLs at proxy/firewall
# Add to blocklist

# 4. Isolate affected endpoints (if malware executed)
# Via EDR: CrowdStrike example
falcon-cli contain-host --hostname INFECTED-PC-01
```

#### Eradication

```bash
# 1. Remove malware from infected endpoints
# Via EDR or manual cleanup
wazuh-control stop
rm -f /path/to/malicious/file
wazuh-control start

# 2. Reset compromised credentials
# Force password reset for affected users

# 3. Remove persistence mechanisms
# Check registry, scheduled tasks, startup items (Windows)
# Check cron, systemd services (Linux)
```

#### Recovery

```bash
# 1. Restore from backup if necessary
# Verify backup integrity before restoration

# 2. Update email filtering rules
# Add new indicators to detection

# 3. Security awareness notification
# Send warning email to all users

# 4. Enhanced monitoring
# Increase logging level for affected accounts
```

#### Post-Incident

**Metrics to Collect:**
- Time to detect (TTD)
- Time to respond (TTR)
- Number of users who clicked
- Number of infected systems
- Data exfiltrated (if any)

**Lessons Learned Questions:**
- How was the phishing email bypassed filters?
- What detection rules need tuning?
- What training gaps exist?
- What technical controls should be added?

**Follow-up Actions:**
- [ ] Update email filtering rules
- [ ] Conduct phishing awareness training
- [ ] Review and update playbook
- [ ] Share IOCs with community (MISP)

---

### Playbook 2: Malware Outbreak Response

#### Preparation

**Asset Inventory:**
```bash
# Generate current asset list
# Wazuh example
curl -u user:pass -XGET "https://wazuh:55000/agents?select=id,name,ip"

# Network scan for unmanaged devices
nmap -sn 192.168.1.0/24 -oG - | awk '/Up$/{print $2}'
```

**Baseline Establishment:**
- Document normal process trees
- Map typical network connections
- Record standard system file hashes

#### Detection

**IOC Identification:**
```bash
# 1. File hash detection (Wazuh example)
# Add malicious hash to database
echo "5d41402abc4b2a76b9719d911017c592" >> /var/ossec/etc/shared/malware_hashes.txt

# 2. YARA rule scanning
yara malware_rules.yar /path/to/scan/

# 3. Network IOC detection (Zeek)
# Check connections to known malicious IPs
zeek-cut id.orig_h id.resp_h < conn.log | grep "MALICIOUS_IP"
```

**Scope Assessment:**
```bash
# Find all infected hosts via SIEM
# Splunk example
index=* 
[search index=threat_intel malicious_hash=* | fields malicious_hash] 
| stats count by host

# Wazuh example
curl -u user:pass -XGET \
  "https://wazuh:55000/security/alerts?q=rule.id=87105"
```

#### Analysis

**Malware Analysis Workflow:**

```bash
# 1. Collect sample safely
# Copy from isolated system
dd if=/dev/sdb of=evidence.dd bs=4M status=progress
md5sum evidence.dd > evidence.dd.md5

# 2. Static analysis
file malware_sample.exe
strings malware_sample.exe | less
exiftool malware_sample.exe
pestudio malware_sample.exe  # Windows PE analysis

# 3. Dynamic analysis in sandbox
# Submit to Cuckoo Sandbox
cuckoo submit malware_sample.exe

# 4. Memory analysis (if memory dump available)
volatility -f memory.dump imageinfo
volatility -f memory.dump --profile=Win7SP1x64 pslist
volatility -f memory.dump --profile=Win7SP1x64 netscan
```

**Behavior Analysis:**
- Process creation patterns
- File modifications
- Registry changes (Windows)
- Network connections (C2 servers)
- Persistence mechanisms

#### Containment

**Network Isolation:**
```bash
# 1. Identify infected systems
infected_hosts="host1 host2 host3"

# 2. Isolate via firewall
for host in $infected_hosts; do
  iptables -I FORWARD -s $host -j DROP
  iptables -I FORWARD -d $host -j DROP
done

# 3. Or via VLAN isolation
# Move infected hosts to quarantine VLAN

# 4. Block C2 communications
# Add C2 IPs/domains to firewall blocklist
iptables -A OUTPUT -d MALICIOUS_C2_IP -j DROP
```

**Endpoint Isolation:**
```bash
# Via EDR (example commands vary by platform)
# CrowdStrike
falcon contain <hostname>

# Microsoft Defender
Invoke-WebRequest -Method Post \
  -Uri "https://api.securitycenter.microsoft.com/api/machines/{id}/isolate"

# Wazuh active response
# Configure in ossec.conf
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100100</rules_id>
</active-response>
```

#### Eradication

**Malware Removal:**
```bash
# 1. Stop malicious processes
# Identify via IOC matching
ps aux | grep -E "malicious_process|bad_service"
kill -9 <PID>

# 2. Remove malicious files
find / -name "malware*" -delete
find / -type f -exec md5sum {} + | grep "KNOWN_BAD_HASH"

# 3. Clean persistence mechanisms

# Windows:
# - Scheduled tasks
schtasks /query | findstr "Malware"
schtasks /delete /tn "MaliciousTask" /f

# - Registry Run keys
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run

# Linux:
# - Cron jobs
crontab -l
crontab -e  # Remove malicious entries

# - Systemd services
systemctl list-units --type=service | grep suspicious
systemctl disable malicious.service
rm /etc/systemd/system/malicious.service
```

**Account Cleanup:**
```bash
# 1. Identify compromised accounts
# Check for unusual account creation
# Windows
net user | findstr /V "Administrator Guest"

# Linux
awk -F: '$3 >= 1000 {print $1}' /etc/passwd

# 2. Disable suspicious accounts
# Windows
net user MaliciousUser /active:no

# Linux
usermod -L malicious_user

# 3. Force password resets for affected accounts
```

#### Recovery

**System Restoration:**
```bash
# Decision tree:
# - Minor infection → Clean in place
# - Severe infection → Reimage from known-good backup

# 1. Clean restoration
# Restore from backup (ensure backup is clean)
# Verify backup timestamp is before infection

# 2. Reimage procedure
# Boot from clean media
# Format and reinstall OS
# Restore data from clean backup
# Apply all security patches before network reconnection

# 3. Verification
# Scan restored system
clamscan -r /
# or
wazuh-control restart
```

**Hardening:**
```bash
# 1. Apply missing patches
# Windows
wuauclt /detectnow /updatenow

# Linux (Debian/Ubuntu)
apt update && apt upgrade -y

# 2. Disable unnecessary services
systemctl list-unit-files --type=service | grep enabled
systemctl disable <unnecessary-service>

# 3. Implement application whitelisting
# Windows AppLocker / Linux AppArmor

# 4. Enhance monitoring
# Increase log verbosity
# Add new detection rules based on IOCs
```

#### Post-Incident

**Root Cause Analysis:**
- Entry vector identification (email, web, USB, etc.)
- Vulnerability exploited
- Security control failures
- Detection gaps

**Remediation Tasks:**
- [ ] Patch exploited vulnerability
- [ ] Update AV/EDR signatures
- [ ] Create new detection rules
- [ ] Update firewall rules
- [ ] Enhance user training
- [ ] Review backup procedures

**Knowledge Sharing:**
```bash
# Export IOCs to MISP
# Document TTPs in MITRE ATT&CK format
# Share lessons learned with security community
```

---

### Playbook 3: Brute Force Attack Response

#### Detection

**Failed Login Monitoring:**
```bash
# Linux auth logs
grep "Failed password" /var/log/auth.log | \
  awk '{print $(NF-3)}' | sort | uniq -c | sort -nr

# Windows Event Logs (PowerShell)
Get-WinEvent -FilterHashtable @{
  LogName='Security'
  ID=4625
} | Group-Object -Property {$_.Properties[5].Value} -NoElement | \
  Sort-Object Count -Descending

# SIEM Correlation Rule (Splunk)
index=windows EventCode=4625 
| stats count by src_ip, user 
| where count > 5
```

#### Containment

```bash
# 1. Block attacker IP at firewall
iptables -A INPUT -s ATTACKER_IP -j DROP

# 2. Fail2Ban auto-blocking (if not already active)
fail2ban-client set sshd banip ATTACKER_IP

# 3. Disable compromised accounts (if any successful logins)
passwd -l compromised_user

# 4. Enable rate limiting
# Configure in application or firewall level
```

#### Eradication & Recovery

```bash
# 1. Review and strengthen password policy
# Enforce complexity requirements
# Implement account lockout

# 2. Force password resets for targeted accounts
echo "user1 user2 user3" | xargs -n1 passwd -e

# 3. Implement MFA
# Enable for all privileged accounts

# 4. Review successful logins from attack period
last -f /var/log/wtmp | grep "ATTACKER_IP"

# 5. Check for any privilege escalation or lateral movement
# Review sudo logs, SSH connections
```

---

### Playbook 4: Data Exfiltration Response

#### Detection

**Unusual Data Transfer Patterns:**
```bash
# Network flow analysis
# Zeek: Large outbound transfers
zeek-cut ts id.orig_h id.resp_h proto orig_bytes resp_bytes < conn.log | \
  awk '$5 > 100000000 || $6 > 100000000' | \
  sort -k5 -nr

# SIEM correlation for data exfil
# Look for:
# - Large file uploads
# - Connections to cloud storage
# - Off-hours large transfers
# - Data compression before transfer
```

#### Analysis

**Investigation Steps:**
1. Identify data source (database, file server, workstation)
2. Determine data type and sensitivity
3. Map exfiltration path (internal → external)
4. Identify attacker infrastructure (C2, staging servers)
5. Assess volume and timeline

```bash
# File access auditing (Linux)
auditctl -w /path/to/sensitive/data -p ra -k data_access
ausearch -k data_access

# Database audit logs
# Check query logs for large SELECT statements
# Review export operations
```

#### Containment

```bash
# 1. Block outbound connections to destination
iptables -A OUTPUT -d EXFIL_SERVER_IP -j DROP

# 2. Disable compromised accounts
# Revoke database access
# Disable cloud storage sync

# 3. Snapshot affected systems for forensics
# VM snapshot or disk image

# 4. Isolate affected systems
# Network isolation while preserving evidence
```