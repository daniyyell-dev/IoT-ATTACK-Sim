#!/bin/bash
# ============================================
# Cleanup Script for IoT Infection Lab
# Removes all artefacts, users, services, and logs
# Author: Daniel Jeremiah
# ============================================

set -euo pipefail

echo "[*] Cleaning up IoT infection artefacts..."

# --- Kill processes ---
pkill -f "nc -lvnp 31337" 2>/dev/null || true
pkill -f "/dev/tcp/203.0.113.10/4444" 2>/dev/null || true

# --- Remove systemd service ---
systemctl disable --now c2-client.service 2>/dev/null || true
rm -f /etc/systemd/system/c2-client.service
systemctl daemon-reload

# --- Remove cron job ---
sed -i '/cron_heartbeat/d' /etc/crontab || true
rm -f /tmp/cron_heartbeat

# --- Remove user ---
id hacker >/dev/null 2>&1 && userdel -r hacker 2>/dev/null || true

# --- Remove binaries ---
rm -f /usr/local/bin/suid-shell
rm -f /usr/local/bin/.update

# --- Remove /tmp artefacts ---
rm -f /tmp/exfil_data.txt
rm -f /tmp/clipboard_dump.txt
rm -f /tmp/largefile.bin
rm -f /tmp/kvbotnet_monitor.log
rm -f /tmp/cryptominer_heartbeat
rm -rf /tmp/pitstop

# --- Remove SSH key backdoor ---
rm -f /home/hacker/.ssh/authorized_keys 2>/dev/null || true

# --- Remove master logs and corpus ---
rm -f /var/log/iot__infection.log
rm -rf /var/log/iot__corpus

# --- Optional: reset system logs (comment out if you want to keep evidence) ---
# > /var/log/auth.log
# > /var/log/syslog

echo "[+] Cleanup complete. System back to baseline."
