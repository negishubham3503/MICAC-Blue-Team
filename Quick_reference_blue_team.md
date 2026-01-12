## Quick Reference Cheat Sheets

### 🚀 Wazuh Commands

```bash
# Manager Control
systemctl status wazuh-manager
systemctl start wazuh-manager
systemctl stop wazuh-manager

# Agent Management
/var/ossec/bin/manage_agents  # Interactive mode
/var/ossec/bin/agent_control -l  # List agents
/var/ossec/bin/agent_control -i <ID>  # Agent info

# Rule Testing
/var/ossec/bin/wazuh-logtest  # Test log parsing

# Cluster Control
/var/ossec/bin/cluster_control -l  # List cluster nodes
/var/ossec/bin/cluster_control -i  # Cluster info

# API
curl -u user:pass -XGET "https://localhost:55000/manager/status"
```

### 🔍 Splunk Search Commands

```spl
# Basic searching
index=main sourcetype=access_combined error

# Time range
index=* earliest=-24h latest=now

# Field extraction
index=* | rex field=_raw "user=(?<username>\w+)"

# Statistics
index=* | stats count by host, status

# Correlation
index=* | transaction host startswith="Login" endswith="Logout"

# Alerting
index=* error | where count > 100
```

### 🌐 Zeek/Suricata Commands

```bash
# Zeek
zeek -i eth0 local                    # Live capture
zeek -r capture.pcap local            # Read pcap
zeek-cut < conn.log                   # Parse logs

# Suricata
suricata -c /etc/suricata/suricata.yaml -i eth0  # Live
suricata -c /etc/suricata/suricata.yaml -r capture.pcap  # Pcap
suricata-update                       # Update rules
```

### 🐧 Linux Security Commands

```bash
# User auditing
lastlog                               # Last login times
last                                  # Login history
who                                   # Current users
w                                     # Current activity

# Process monitoring
ps aux | grep <process>
top / htop
lsof -i                               # Network connections

# Network analysis
netstat -tulpn                        # Listening ports
ss -tulpn                             # Modern alternative
tcpdump -i eth0 -w capture.pcap       # Packet capture

# File integrity
find / -mtime -1                      # Files modified last day
md5sum file.txt                       # File hash
stat file.txt                         # File metadata

# Logs
tail -f /var/log/syslog
journalctl -xe                        # Systemd logs
grep "Failed password" /var/log/auth.log
```

### 🪟 Windows Security Commands

```powershell
# Event logs
Get-WinEvent -LogName Security -MaxEvents 100
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624}

# User activity
Get-LocalUser
Get-LocalGroupMember -Group "Administrators"
Get-EventLog -LogName Security -InstanceId 4720  # User created

# Process monitoring
Get-Process
Get-Process | Where-Object {$_.CPU -gt 100}
Get-NetTCPConnection                  # Network connections

# Services
Get-Service
Get-Service | Where-Object {$_.Status -eq "Running"}

# Scheduled tasks
Get-ScheduledTask
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"}

# File analysis
Get-FileHash file.exe -Algorithm SHA256
Get-Item -Path file.exe | Select-Object *
```

### 🔒 Incident Response Commands

```bash
# Quick triage
hostname && date && uptime
ps aux --forest                       # Process tree
netstat -anp | grep ESTABLISHED       # Active connections
find /tmp -type f -mtime -1           # Recent temp files

# Memory capture
# Linux
sudo dd if=/dev/mem of=memory.dump bs=1M
# Or use LiME kernel module

# Windows (requires tools)
# Use WinPmem, DumpIt, or FTK Imager

# Disk imaging
dd if=/dev/sda of=disk.img bs=4M status=progress
md5sum disk.img > disk.img.md5

# Network capture
tcpdump -i eth0 -w incident.pcap &
# Let run during incident, stop when done
```
