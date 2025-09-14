

# IoT Infection Simulation v3.2 (Lightweight)

![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Ubuntu-blue.svg)
![ATTACK](https://img.shields.io/badge/MITRE%20ATT%26CK-Coverage-orange.svg)

## Overview

This project provides a **lightweight IoT infection simulation** designed for **classroom labs, SOC analyst training, and detection engineering**.
The script simulates attacker behaviour across the **MITRE ATT\&CK framework** by generating **synthetic but realistic system events and log entries**.

> ⚠️ No harmful actions are performed. All actions are simulated with safe commands, test IP addresses, and benign artefacts.

## Files

* `iot_infection_v3.2.sh` – Main simulation script (requires root).
* `iot_infection_v3.2.json` – Reference configuration / metadata file.
* `cleanup.sh` – Script to remove created artefacts (optional).
* `README.txt` – Plain-text quick instructions.

## Features

* Lightweight and fast (runs in seconds).
* Safe: uses TEST-NET IPs and harmless commands.
* Covers **all 14 ATT\&CK tactics** with at least one technique per category.
* Generates **synthetic logs and artefacts** for SIEM/SOC exercises.
* Extensible for research and teaching.

## MITRE ATT\&CK Coverage

| Tactic               | Technique(s) Simulated                                                                 | Example Artefact                                  |
| -------------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------- |
| Reconnaissance       | T1595 Active Scanning                                                                  | nmap scan entry in `/var/log/syslog`              |
| Resource Development | T1585 Establish Accounts                                                               | Local user `hacker` created                       |
| Initial Access       | T1078 Valid Accounts                                                                   | SSH login from TOR IP in `/var/log/auth.log`      |
| Execution            | T1059.004 Unix Shell, T1559 PITSTOP                                                    | Reverse shell attempt, Unix socket                |
| Persistence          | T1053.003 Cron, T1543.002 Systemd, T1098.004 SSH Keys, T1546 Event-Triggered Execution | Cron job, rogue SSH key, KV Botnet log            |
| Privilege Escalation | T1068 Exploitation for Privilege Escalation                                            | SUID backdoor binary                              |
| Defence Evasion      | T1070 Indicator Removal, T1036.005 Masquerading                                        | Log tampering, hidden `.update` binary            |
| Credential Access    | T1110 Brute Force                                                                      | Multiple failed SSH logins                        |
| Discovery            | T1083 File Discovery                                                                   | Enumeration log of `/etc/passwd`                  |
| Lateral Movement     | T1021.004 SSH, T1021.002 FTP                                                           | Internal SSH pivot, FTP login and file transfer   |
| Collection           | T1074.001 Local Data Staging, T1115 Clipboard Data                                     | Staged file `/tmp/exfil_data.txt`, clipboard dump |
| Exfiltration         | T1048.003 SCP, T1030 Transfer Size Limits                                              | Data transfer logs, large file abort              |
| Command & Control    | T1571 Non-Standard Port, T1071.004 DNS                                                 | Netcat listener on port 31337, DNS lookups        |
| Impact               | T1496 Resource Hijacking                                                               | Miner activity log entry                          |

## Requirements

* Ubuntu-based host (tested on Ubuntu 20.04/22.04).
* Root privileges (`sudo`).
* Standard Linux utilities: `bash`, `nc`, `dig`, `nmap`.

## Usage

1. Clone the repository:

```bash
git clone https://github.com/yourusername/iot--infection.git
cd iot--infection
```

2. Run the simulation (requires sudo):

```bash
sudo bash iot_infection_v3.2.sh
```

3. Review synthetic logs and artefacts:

* `/var/log/syslog`
* `/var/log/auth.log`
* `/tmp/` directory

4. (Optional) Clean up:

```bash
sudo bash cleanup.sh
```

## Example Output

```text
[*] Starting IoT infection setup...
[+] Recon: nmap scan log written to /var/log/syslog
[+] Resource Development: attacker account 'hacker' present
[+] Initial Access: successful SSH login for 'hacker' recorded
...
[*] IoT infection setup complete.
```

## Educational Use Cases

* SOC analyst training
* SIEM rule validation
* Threat hunting exercises
* Red vs Blue team demonstrations
* Teaching MITRE ATT\&CK tactics

## Safety Notes

* The script only **writes synthetic events**; it does not exploit, infect, or exfiltrate real data.
* All IPs are reserved TEST-NET or TOR examples.
* Use only in controlled environments (labs, VMs, classrooms).

