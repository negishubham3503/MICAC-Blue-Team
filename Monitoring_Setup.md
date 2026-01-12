# Wazuh & Suricata for Attack-Defense Exercises

---

## Wazuh: Configuration Tips and Best Practices

### Planning and Architecture

- **Define Monitoring Scope:** Identify critical assets (servers, endpoints, cloud workloads) and ensure Wazuh agents are deployed accordingly.
- **Choose the Right Architecture:** For scalability, use a distributed Wazuh deployment (manager, indexer, dashboard). For small labs, an all-in-one setup suffices.
- **Integration:** Plan integration with SIEMs, SOARs, and threat intelligence platforms (e.g., MISP, AbuseIPDB) for enriched detection and automated response.

A well-planned deployment ensures comprehensive coverage and avoids resource bottlenecks. Distributed architectures are recommended for exercises simulating enterprise-scale environments, while single-server setups are suitable for smaller labs or rapid prototyping.

---

### Core Configuration Files

- **ossec.conf:** Main configuration file for both manager and agents (`/var/ossec/etc/ossec.conf` on Linux, `C:\Program Files (x86)\ossec-agent\ossec.conf` on Windows).
- **agent.conf:** Used for centralized configuration distribution to agents, supporting group-based targeting.
- **internal_options.conf / local_internal_options.conf:** Advanced tuning and custom overrides.

**Tip:** Always back up configuration files before making changes. Use the built-in validation tools:

```bash
/var/ossec/bin/verify-agent-conf
/var/ossec/bin/wazuh-control configtest
```

Configuration changes can be hot-reloaded (Wazuh 4.13.0+) without restarting the manager:

```bash
# Via API
curl -X PUT "https://localhost:55000/manager/analysisd/reload" -H "Authorization: Bearer <TOKEN>"
```


---

### Agent Configuration

- **Custom Policies:** Tailor agent settings per OS or role using `<agent_config>` blocks in `agent.conf`.
- **Log Collection:** Use `<localfile>` entries to specify log sources (e.g., application logs, Suricata logs).
- **FIM (File Integrity Monitoring):** Enable and tune `<syscheck>` for critical file and directory monitoring.

**Example: Monitor Apache logs and a sensitive directory**
```xml
<ossec_config>
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>
  <syscheck>
    <directories check_all="yes" realtime="yes">/etc/ssh/</directories>
  </syscheck>
</ossec_config>
```


---

### Rule Management and Updates

- **Default Rules:** Wazuh ships with a comprehensive default ruleset, but these can be noisy or generic.
- **Community Rules:** Enhance detection fidelity by integrating advanced community rulesets such as [SOCFortress/Wazuh-Rules](https://github.com/socfortress/Wazuh-Rules).
- **Custom Rules:** Place custom rule files in `/var/ossec/etc/rules/` and include them in `ossec.conf`:

```xml
<rules>
  <include>custom-attack-signatures.xml</include>
</rules>
```

- **Hot Reload:** Use the Wazuh dashboard or API to reload rules without downtime (Wazuh 4.13.0+).

**Tip:** Always validate new rules for ID conflicts and syntax errors before applying.

---

### Alert Tuning

- **Alert Thresholds:** Adjust frequency and timeframe in rules to balance detection and false positives.
- **Rule Levels:** Use alert levels (1–16) to prioritize triage and automate responses for high-severity events.
- **Suppression:** Use `ignore` and `noalert` options to suppress known benign events.

**Example: Suppress repeated benign events**
```xml
<rule id="100200" level="3" frequency="10" timeframe="60" ignore="300">
  <description>Repeated benign event suppressed for 5 minutes</description>
</rule>
```


---

### Performance and Maintenance

- **Resource Allocation:** Monitor CPU, memory, and storage. Scale horizontally for large log volumes.
- **Log Rotation:** Implement log rotation and archiving to manage disk usage.
- **Regular Updates:** Keep Wazuh and all agents updated to the latest stable version for security and feature improvements.
- **Monitoring:** Use the Wazuh dashboard and `/var/ossec/bin/wazuh-control status` to monitor service health.

---

## Wazuh Detection Rules: Structure and Examples

### Rule Syntax Overview

Wazuh rules are XML-based and support rich matching logic:

- **Fields:** `match`, `regex`, `field`, `srcip`, `dstip`, `user`, etc.
- **Correlation:** `if_sid`, `if_group`, `frequency`, `timeframe` for event correlation.
- **MITRE Mapping:** `<mitre>` tags for ATT&CK technique mapping.
- **Groups:** For logical categorization and dashboard filtering.

**Example: Detect suspicious PowerShell execution from temp directory**
```xml
<group name="sysmon,powershell,attack,">
  <rule id="100001" level="10">
    <if_sid>60000</if_sid>
    <field name="win.eventdata.image" type="pcre2">\Temp\\</field>
    <field name="win.eventdata.image" type="pcre2">powershell\.exe</field>
    <description>Suspicious PowerShell execution from a temporary directory.</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>
</group>
```


---

### Suricata Alert Ingestion Rule Example

```xml
<group name="ids,suricata,">
  <rule id="86600" level="0">
    <decoded_as>json</decoded_as>
    <field name="timestamp">\.+</field>
    <field name="event_type">\.+</field>
    <description>Suricata messages.</description>
    <options>no_full_log</options>
  </rule>
  <rule id="86601" level="3">
    <if_sid>86600</if_sid>
    <field name="event_type">^alert$</field>
    <description>Suricata: Alert - $(alert.signature)</description>
    <options>no_full_log</options>
  </rule>
</group>
```
This rule set enables Wazuh to parse Suricata's EVE JSON alerts and generate actionable SIEM alerts.

---

### Brute-Force Detection Rule Example

```xml
<rule id="5763" level="10" frequency="8" timeframe="120" ignore="60">
  <if_group>sshd,authentication_failed</if_group>
  <description>SSHD brute force trying to get access to the system</description>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
```
This rule triggers after 8 failed SSH logins within 2 minutes, then ignores further matches for 1 minute to prevent alert flooding.

---

### Web Shell Detection Rule Example

```xml
<group>
  <rule id="100502" level="15">
    <if_sid>100501</if_sid>
    <field name="changed_content" type="pcre2">(?i)passthru|exec|eval|shell_exec|assert|str_rot13|system|phpinfo|base64_decode|chmod|mkdir|fopen|fclose|readfile|show_source|proc_open|pcntl_exec|execute|WScript.Shell|WScript.Network|FileSystemObject|Adodb.stream</field>
    <description>[File Modification]: File $(file) contains a web shell</description>
    <mitre>
      <id>T1105</id>
      <id>T1505.003</id>
    </mitre>
  </rule>
</group>
```
This rule inspects modified files for suspicious PHP functions, mapping to relevant MITRE ATT&CK techniques.

---

### Community and Advanced Rulesets

- **SOCFortress/Wazuh-Rules:** Download and deploy advanced rules for improved detection fidelity:

```bash
curl -so ~/wazuh_socfortress_rules.sh https://raw.githubusercontent.com/socfortress/Wazuh-Rules/main/wazuh_socfortress_rules.sh && bash ~/wazuh_socfortress_rules.sh
```
**Note:** Check for rule ID conflicts before applying community rulesets.

---

## Wazuh Configuration Files and Templates

### ossec.conf (Manager/Agent)

**Minimal Example for Suricata Integration and FIM:**
```xml
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>
  <syscheck>
    <directories check_all="yes" realtime="yes">/etc/ssh/</directories>
    <directories check_all="yes" realtime="yes">/var/www/html/</directories>
  </syscheck>
</ossec_config>
```
**Key Sections:**
- `<localfile>`: Log sources (Suricata, Apache, etc.)
- `<syscheck>`: File Integrity Monitoring
- `<active-response>`: Automated response actions
- `<integration>`: Threat intelligence and enrichment

---

### agent.conf (Centralized Agent Management)

**Example:**
```xml
<agent_config name="^web.*">
  <localfile>
    <location>/var/log/apache2/access.log</location>
    <log_format>apache</log_format>
  </localfile>
</agent_config>
```
This targets all agents with names starting with "web" for Apache log monitoring.

---

### internal_options.conf / local_internal_options.conf

- **Advanced tuning:** Debug levels, buffer sizes, performance parameters.
- **Custom overrides:** Place custom settings in `local_internal_options.conf` to persist across upgrades.

---

## Wazuh File Integrity Monitoring (FIM) Configuration Tips

- **Enable Real-Time Monitoring:** Use `realtime="yes"` for immediate detection of file changes.
- **Monitor Critical Paths:** Focus on system binaries, web directories, and configuration files.
- **Hash Algorithms:** Enable MD5, SHA1, and SHA256 for robust integrity checks.
- **Who-data:** On Linux, enable Auditd or eBPF-based who-data for user/process attribution.

**Example:**
```xml
<syscheck>
  <directories check_all="yes" realtime="yes" whodata="yes">/etc/ssh/</directories>
  <directories check_all="yes" realtime="yes">/var/www/html/</directories>
</syscheck>
```
**Restart agent after changes:**
```bash
systemctl restart wazuh-agent
```


---

## Wazuh Active Response Scripts and Automation

- **Default Scripts:** Located in `/var/ossec/active-response/bin/` (e.g., `firewall-drop` for Linux).
- **Custom Scripts:** Place in the same directory and define in `ossec.conf` under `<command>`.
- **Configuration Example:**
```xml
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5763</rules_id>
  <timeout>180</timeout>
</active-response>
```
- **Trigger:** When rule 5763 (SSH brute-force) fires, the attacker's IP is blocked for 180 seconds.

**Testing:**
- Simulate brute-force with Hydra or similar tools.
- Verify block by attempting to reconnect from the attacker's IP.

---

## Wazuh Decoders and Custom Decoders for Suricata

- **JSON Decoder:** Wazuh's built-in JSON decoder extracts fields from Suricata's EVE JSON logs.
- **Custom Decoder Example:**
```xml
<decoder name="suricata-custom">
  <program_name>suricata</program_name>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```
- **Use Case:** Required when Suricata logs are wrapped in syslog headers or forwarded via syslog-ng.

**Tip:** Use `/var/ossec/bin/wazuh-logtest` to test decoder and rule matching.

---

## Suricata: Configuration Tips and Deployment Best Practices

### Installation and Setup

- **Install Suricata:**
  ```bash
  sudo add-apt-repository ppa:oisf/suricata-stable -y
  sudo apt update
  sudo apt install suricata -y
  ```
- **Enable and Start:**
  ```bash
  sudo systemctl enable suricata
  sudo systemctl start suricata
  ```
- **Update Rules:**
  ```bash
  sudo suricata-update
  sudo systemctl restart suricata
  ```


---

### Key Configuration Files

- **Main Config:** `/etc/suricata/suricata.yaml`
- **Rules Directory:** `/etc/suricata/rules/`
- **Log Directory:** `/var/log/suricata/`
- **Custom Rules:** `/etc/suricata/rules/custom.rules`

---

### Performance Tuning

- **Packet Processing:**
  ```yaml
  max-pending-packets: 1024
  runmode: autofp
  default-packet-size: 1514
  packet-alert-max: 15
  ```
- **Threading:**
  ```yaml
  threading:
    set-cpu-affinity: yes
    detect-thread-ratio: 1.5
    stack-size: 8MB
    cpu-affinity:
      management-cpu-set:
        cpu: [0]
      receive-cpu-set:
        cpu: [0]
      worker-cpu-set:
        cpu: ["all"]
        mode: "exclusive"
  ```
- **NUMA Pinning:**
  ```yaml
  autopin: yes
  ```


---

### Logging and Output

- **EVE JSON Output:**
  ```yaml
  outputs:
    - eve-log:
        enabled: yes
        filetype: regular
        filename: eve.json
        community-id: true
        types:
          - alert
          - http
          - dns
          - tls
          - files
          - stats
  ```
- **Fast Log:**
  ```yaml
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  ```
- **Log Rotation:** Ensure log rotation is configured for `/var/log/suricata/` to prevent disk exhaustion.

---

### Rule Management and Updates

- **Default Rule Path:** `/etc/suricata/rules`
- **Rule Files:** `suricata.rules`, `custom.rules`
- **Update Rules:**
  ```bash
  sudo suricata-update
  ```
- **Emerging Threats Rules:** Download latest rulesets for current threat coverage:
  ```bash
  wget http://rules.emergingthreats.net/open/suricata-7.0.3/emerging-all.rules.tar.gz
  ```
  Extract and place in the rules directory.

- **Rule Reload:** Restart Suricata or use `kill -USR2 <pid>` for live reload.

---

### Key Suricata.yaml Sections

```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SSH_PORTS: 22

default-log-dir: /var/log/suricata
default-rule-path: /etc/suricata/rules
rule-files:
  - suricata.rules
  - custom.rules
classification-file: /etc/suricata/classification.config
threshold-file: /etc/suricata/threshold.config
```


---

### Application Layer Parsers

- **HTTP, DNS, TLS, SMB, SSH:** Enable and tune protocol parsers for deep inspection.
- **Example:**
  ```yaml
  app-layer:
    protocols:
      http:
        enabled: yes
      dns:
        udp:
          enabled: yes
          detection-ports:
            dp: 53
      tls:
        enabled: yes
        detection-ports:
          dp: 443
  ```

---

### IPS Mode (Inline Blocking)

- **Enable IPS Mode:** Use `nfqueue` on Linux for inline packet processing.
- **Example:**
  ```bash
  sudo suricata -c /etc/suricata/suricata.yaml -q 0
  ```
- **UFW Integration:** Update firewall rules to direct traffic through Suricata in IPS mode.

---

### Suricata Rule Example

```suricata
alert tcp $HOME_NET 21 -> $EXTERNAL_NET any (
  msg:"ET POLICY FTP Login Successful (non-anonymous)";
  flow:from_server,established;
  flowbits:isset,ET.ftp.user.login;
  flowbits:isnotset,ftp.user.logged_in;
  flowbits:set,ftp.user.logged_in;
  content:"230 ";
  pcre:!"/^230(\s+USER)?\s+(anonymous|ftp)/smi";
  classtype:misc-activity;
  sid:2003410;
  rev:7;
)
```


---

### Suricata Eve JSON Schema and MITRE Mapping

- **EVE JSON:** Suricata's EVE output is structured for SIEM ingestion and supports mapping to MITRE ATT&CK techniques.
- **Schema Reference:** [Suricata EVE JSON Schema](https://github.com/OISF/suricata/blob/main/etc/schema.json).
- **Tip:** Use `community-id: true` for flow correlation across tools.

---

## Integrating Suricata with Wazuh

### Log Ingestion and Parsing

- **Configure Suricata to Output EVE JSON:**
  ```yaml
  outputs:
    - eve-log:
        enabled: yes
        filetype: regular
        filename: eve.json
  ```
- **Configure Wazuh Agent to Monitor Suricata Logs:**
  ```xml
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>
  ```
- **Restart Services:**
  ```bash
  systemctl restart suricata
  systemctl restart wazuh-agent
  ```


---

### Custom Decoders for Suricata

- **Default JSON Decoder:** Handles standard EVE JSON logs.
- **Custom Decoder:** Required if logs are wrapped in syslog headers (e.g., forwarded via syslog-ng).
  ```xml
  <decoder name="suricata-custom">
    <program_name>suricata</program_name>
    <plugin_decoder>JSON_Decoder</plugin_decoder>
  </decoder>
  ```
- **Test Decoding:** Use `/var/ossec/bin/wazuh-logtest` with sample logs.

---

### Event Mapping to MITRE ATT&CK

- **Wazuh Rules:** Map Suricata alerts to MITRE ATT&CK techniques using `<mitre>` tags in custom rules.
- **Reference:** Use [nsm-attack](https://github.com/0xtf/nsm-attack) for mapping Suricata rules to ATT&CK techniques.

---

## Playbooks: Detection, Analysis, and Response

### Playbook Structure

Each playbook includes:

- **Prerequisites:** Required tooling, log sources, and detection rules.
- **Detection Steps:** How to identify the attack.
- **Analysis Steps:** Indicators to check, log queries, and context gathering.
- **Response Steps:** Containment, eradication, and recovery actions.

---

### Playbook: SSH Brute-Force Attack

#### Prerequisites

- Wazuh agent monitoring `/var/log/auth.log`
- Suricata monitoring SSH traffic
- Active response script (`firewall-drop`) enabled

#### Detection

- **Wazuh:** Rule 5763 triggers after 8 failed SSH logins in 2 minutes.
- **Suricata:** Alerts on repeated SSH connection attempts from the same IP.

#### Analysis

- Query Wazuh dashboard for:
  - `rule.id:5763`
  - Source IP, username, timestamps
- Review Suricata EVE logs for:
  - `event_type: alert`
  - `alert.signature: "ET SCAN SSH BruteForce attempt"`

#### Response

- **Automated:** Wazuh active response blocks attacker IP for 180 seconds.
- **Manual:**
  - Block IP at firewall
  - Review for successful logins from attacker IP
  - Reset affected credentials

#### Validation

- Attempt SSH from attacker IP; verify block.
- Review `/var/ossec/logs/active-responses.log` for action confirmation.

---

### Playbook: Web Shell Detection

#### Prerequisites

- Wazuh FIM monitoring web directories
- Custom rule for suspicious PHP function detection

#### Detection

- Wazuh FIM alert for file creation/modification in `/var/www/html/`
- Rule triggers on detection of functions like `eval`, `exec`, `base64_decode`

#### Analysis

- Review alert details: file path, user, timestamp
- Check web server logs for suspicious requests
- Validate file contents for web shell signatures

#### Response

- Quarantine or delete suspicious file
- Block attacker IP if identified
- Review for lateral movement or privilege escalation

#### Validation

- Confirm removal of web shell
- Monitor for recurring alerts

---

### Playbook: Data Exfiltration via LOTL Tools

#### Prerequisites

- Wazuh monitoring shell history and command execution
- Suricata monitoring outbound traffic

#### Detection

- Wazuh alert for use of `scp`, `curl`, `netcat`, `certutil`, `bitsadmin`
- Suricata alert for large outbound transfers or unusual destinations

#### Analysis

- Review command history and process logs
- Correlate with Suricata flow and alert logs
- Check for connections to known malicious IPs (enrich with AbuseIPDB)

#### Response

- Terminate suspicious processes
- Block outbound connections to suspicious destinations
- Investigate for compromised credentials

#### Validation

- Confirm containment of exfiltration vector
- Review for additional indicators of compromise

---

### Playbook: Credential Dumping (LSASS Access)

#### Prerequisites

- Sysmon installed and configured to log LSASS access (Event ID 10)
- Wazuh agent collecting Sysmon logs
- Custom Wazuh rule for LSASS access attempts

#### Detection

- Wazuh alert for process accessing `lsass.exe` (excluding known legitimate processes)
- Rule triggers on suspicious parent-child process relationships (e.g., `procdump.exe`, `rundll32.exe`, `nanodump.exe`)

#### Analysis

- Review Sysmon logs for process name, command line, user
- Correlate with Wazuh alert details
- Map to MITRE ATT&CK T1003.001

#### Response

- Isolate affected endpoint
- Reset credentials for affected accounts
- Investigate for lateral movement

#### Validation

- Simulate LSASS access using Atomic Red Team or custom script
- Confirm detection and alerting in Wazuh dashboard

---

### Playbook: Threat Intelligence Enrichment (MISP Integration)

#### Prerequisites

- Wazuh integration with MISP (custom Python script in `/var/ossec/integrations/`)
- FIM enabled for critical directories

#### Detection

- Wazuh FIM alert for new file creation
- Integration script queries MISP for file hash matches

#### Analysis

- Review alert for `misp_file_hashes.found: 1`
- Check MISP event details for context

#### Response

- Quarantine or delete file
- Block associated indicators (IP, domain, hash)
- Notify incident response team

#### Validation

- Add EICAR test file to monitored directory
- Confirm detection and MISP match alert

---

## Scripts and Commands for Quick Blue Team Actions

### Wazuh

- **Restart Wazuh Agent:**
  ```bash
  systemctl restart wazuh-agent
  ```
- **Validate Configuration:**
  ```bash
  /var/ossec/bin/verify-agent-conf
  ```
- **Test Log Decoding:**
  ```bash
  /var/ossec/bin/wazuh-logtest
  ```
- **Reload Rules (Wazuh 4.13.0+):**
  ```bash
  curl -X PUT "https://localhost:55000/manager/analysisd/reload" -H "Authorization: Bearer <TOKEN>"
  ```

### Suricata

- **Restart Suricata:**
  ```bash
  systemctl restart suricata
  ```
- **Update Rules:**
  ```bash
  suricata-update
  ```
- **Check Service Status:**
  ```bash
  systemctl status suricata
  ```
- **Test Configuration:**
  ```bash
  suricata -T -c /etc/suricata/suricata.yaml
  ```

---

## Dashboards, Alert Triage, and Prioritization

- **Wazuh Dashboard:** Use the Threat Hunting module for real-time alert review, filtering by rule ID, group, or MITRE technique.
- **Alert Triage:** Prioritize alerts by level and mapped MITRE technique. Use AI-driven workflows (e.g., n8n + GPT-4o-mini) for automated triage and contextual enrichment.
- **Noise Reduction:** Suppress known benign events and tune thresholds to minimize alert fatigue.

---

## Threat Intelligence Integration and Enrichment

- **MISP Integration:** Use custom integration scripts to query MISP for file hashes, domains, or IPs on alert.
- **AbuseIPDB:** Enrich alerts with reputation data for source IPs.
- **Automated Enrichment:** Configure integrations in `ossec.conf` and place scripts in `/var/ossec/integrations/`.

**Example Integration Block:**
```xml
<integration>
  <name>custom-misp_file_hashes.py</name>
  <hook_url>https://YOUR_MISP_INSTANCE</hook_url>
  <api_key>YOUR_API_KEY</api_key>
  <group>syscheck</group>
  <rule_id>554</rule_id>
  <alert_format>json</alert_format>
</integration>
```


---

## Testing, Validation, and Exercise Guidance

- **Simulate Attacks:** Use tools like Hydra (brute-force), Atomic Red Team (credential dumping), and custom scripts for scenario validation.
- **Monitor Detection:** Confirm alerts in Wazuh dashboard and Suricata logs.
- **Review Coverage:** Map detection rules to MITRE ATT&CK to identify gaps.
- **Iterate:** Tune rules and configurations based on exercise outcomes.

---

## Quick Reference Tables

### Wazuh Key Files and Directories

| File/Directory                        | Purpose                                 |
|---------------------------------------|-----------------------------------------|
| /var/ossec/etc/ossec.conf             | Main configuration (manager/agent)      |
| /var/ossec/etc/agent.conf             | Centralized agent config                |
| /var/ossec/etc/internal_options.conf  | Advanced tuning                         |
| /var/ossec/etc/rules/                 | Custom rule files                       |
| /var/ossec/active-response/bin/       | Active response scripts                 |
| /var/ossec/logs/alerts/alerts.log     | Alert log                               |
| /var/ossec/logs/active-responses.log  | Active response log                     |

---

### Suricata Key Files and Directories

| File/Directory                        | Purpose                                 |
|---------------------------------------|-----------------------------------------|
| /etc/suricata/suricata.yaml           | Main configuration                      |
| /etc/suricata/rules/                  | Rule files directory                    |
| /var/log/suricata/eve.json            | EVE JSON output                         |
| /var/log/suricata/fast.log            | Fast alert log                          |
| /etc/suricata/classification.config   | Rule classification                     |
| /etc/suricata/threshold.config        | Rule thresholding                       |

---

**For further details, consult the official documentation:**
- [Wazuh Documentation](https://documentation.wazuh.com/current/)
- [Suricata Documentation](https://docs.suricata.io/)
- [SOCFortress Wazuh Rules](https://github.com/socfortress/Wazuh-Rules)
- [Emerging Threats Rules](https://rules.emergingthreats.net/)