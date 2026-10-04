# Enterprise SOC & SOAR Laboratory: Real-Time Threat Detection & Automated Active Response with Wazuh

![Wazuh](https://img.shields.io/badge/SIEM%2FXDR-Wazuh%20v4.7.5-005571?style=for-the-badge&logo=wazuh)
![Ubuntu](https://img.shields.io/badge/Target-Ubuntu%2026.04.1%20LTS-E95420?style=for-the-badge&logo=ubuntu)
![Kali Linux](https://img.shields.io/badge/Red%20Team-Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux)
![Docker](https://img.shields.io/badge/Deployment-Docker-2496ED?style=for-the-badge&logo=docker)
![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red?style=for-the-badge)

## Table of Contents
1. [Executive Summary](#-executive-summary)
2. [Lab Network & Architecture](#️-lab-network--architecture)
3. [Technical Implementation & Configuration](#️-technical-implementation--configuration)
4. [Purple Team Scenarios: Attack & Detection Engineering](#️️-purple-team-scenarios-attack--detection-engineering)
   - [Scenario 1: Web Application Exploitation (SQLi & LFI — MITRE T1190)](#scenario-1-web-application-exploitation-sqli--lfi--mitre-t1190)
   - [Scenario 2: Credential Access via SSH Brute-Force (MITRE T1110)](#scenario-2-credential-access-via-ssh-brute-force-mitre-t1110)
5. [SOAR Implementation: Automated Kernel-Level Remediation](#-soar-implementation-automated-kernel-level-remediation)
   - [1. Network Isolation Proof (Attacker Perspective)](#1-network-isolation-proof-attacker-perspective)
   - [2. Netfilter/iptables & Forensic JSON Telemetry (Target Perspective)](#2-netfilteriptables--forensic-json-telemetry-target-perspective)
   - [3. SIEM Mean Time to Respond (MTTR) Verification](#3-siem-mean-time-to-respond-mttr-verification)
6. [Key Security Metrics & Results](#-key-security-metrics--results)
7. [Repository Structure](#-repository-structure)
8. [How to Reproduce This Lab](#-how-to-reproduce-this-lab)

---

## Executive Summary
Modern Security Operations Centers (SOCs) cannot rely solely on passive log aggregation; they require real-time detection engineering coupled with automated incident response (SOAR) to neutralize threats before lateral movement or data exfiltration occurs.

This project documents the end-to-end design, deployment, and validation of a virtualized **SIEM/XDR and SOAR laboratory** powered by **Wazuh**. Operating in a **Purple Team methodology**, realistic cyberattacks were launched from a **Kali Linux** offensive node against a hardened **Ubuntu 26.04.1 LTS** production server running **Nginx** and **OpenSSH**.

### Key Objectives Achieved:
* **Centralized Telemetry Ingestion:** Encrypted TCP log forwarding (1514/tcp, AES encryption) from the Ubuntu endpoint to the Dockerized Wazuh Manager, monitoring both web server access logs (/var/log/nginx/access.log) and system authentication journals (/var/log/auth.log via syslog).
* **Custom SIEM Detection Engineering:** Creation of high-fidelity XML correlation rules (ule.id: 100002, Severity Level 12) mapped to the **MITRE ATT&CK** matrix (T1190 & T1110).
* **Sub-Second SOAR Active Response:** Automated execution of the irewall-drop script via wazuh-execd, dynamically injecting iptables kernel drop rules to quarantine the attacker IP (192.168.100.235) in **429 milliseconds**.

---

## Lab Network & Architecture

```text
+---------------------------------------------------------------------------------------------------+
|                                   VIRTUALIZED SOC / SOAR NETWORK                                  |
|                                       Subnet: 192.168.100.0/24                                    |
|                                                                                                   |
|   +-------------------------------+                           +-------------------------------+   |
|   |      RED TEAM / ATTACKER      |                           |    MONITORED PROD ENDPOINT    |   |
|   |          Kali Linux           |                           |      ubuntu-prod-server       |   |
|   |     IP: 192.168.100.235       |                           |      IP: 192.168.100.240      |   |
|   |-------------------------------|                           |-------------------------------|   |
|   | - curl (SQLi / LFI / Nikto)   | ====[1] HTTP / SSH ====>  | - Ubuntu 26.04.1 LTS          |   |
|   | - Hydra (SSH Brute-Force)     |     Attack Payloads       | - Nginx 1.28.3 & OpenSSH      |   |
|   | - ICMP Ping                   |                           | - Wazuh Agent v4.7.5 (ID 001) |   |
|   +-------------------------------+                           | - Netfilter / iptables        |   |
|                   X                                           +-------------------------------+   |
|                   |                                                       |         ^             |
|         [4] 100% Packet Loss                                  [2] Telemetry         | [3] SOAR    |
|       (DROP all 192.168.100.235)                              (Port 1514/TCP)       | Command     |
|                   |                                           AES Encrypted         | firewall-drop|
|                   + - - - - - - - - - - - - - - - - - - - - - - - - - - - | - - - - +             |
|                                                                           v                       |
|                                                               +-------------------------------+   |
|                                                               |      SIEM / XDR PLATFORM      |   |
|                                                               |     Wazuh Single-Node Stack   |   |
|                                                               |      IP: 192.168.100.14       |   |
|                                                               |-------------------------------|   |
|                                                               | - Wazuh Manager (node01)      |   |
|                                                               | - Wazuh Indexer (OpenSearch)  |   |
|                                                               | - Wazuh Dashboard (HTTPS:443) |   |
|                                                               +-------------------------------+   |
+---------------------------------------------------------------------------------------------------+
```

### Infrastructure Inventory

| Component Role | Hostname / ID | Operating System | IP Address | Key Services & Daemons |
| :--- | :--- | :--- | :--- | :--- |
| **SIEM / XDR Server** | wazuh.manager (
ode01) | Docker Engine on Windows 11 | 192.168.100.14 | wazuh-manager, wazuh-indexer, wazuh-dashboard |
| **Monitored Target** | ubuntu-prod-server (ID: 001) | Ubuntu 26.04.1 LTS | 192.168.100.240 | wazuh-agent (v4.7.5), 
ginx (1.28.3), sshd, syslog, iptables |
| **Offensive Platform** | kali | Kali Linux Rolling | 192.168.100.235 | curl (8.20.0), THC-Hydra, openssh-client, iputils-ping |

### Endpoint Enrollment & Health Validation
The target server ubuntu-prod-server (192.168.100.240) was enrolled using key-based authentication (port 1515/tcp) and established an AES-encrypted telemetry channel (port 1514/tcp) with the Manager:

![Agent Active](screenshots/01-agent-active.png)

---

## Technical Implementation & Configuration

### 1. Endpoint Log Collection (configs/agent-ossec.conf)
On Ubuntu 26.04.1 LTS, syslog was deployed alongside the Wazuh Agent to ensure standard syslog serialization into /var/log/auth.log, while Nginx access logs were hooked into the agent configuration:

```xml
<!-- /var/ossec/etc/ossec.conf (Ubuntu Endpoint) -->
<ossec_config>
  <client>
    <server>
      <address>192.168.100.14</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
  </client>

  <!-- Web Server Telemetry Ingestion -->
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/nginx/access.log</location>
  </localfile>
</ossec_config>
```

### 2. Custom Detection Engineering (ules/local_rules.xml)
While Wazuh includes default web rules (31100–31106), a dedicated high-severity SOC rule (ule.id: 100002, **Level 12**) was engineered on the Manager to specifically flag SQL Injection (UNION SELECT) and sensitive file probing (/etc/passwd) with explicit **MITRE ATT&CK T1190** enrichment:

```xml
<!-- /var/ossec/etc/rules/local_rules.xml (Wazuh Manager) -->
<group name="local,syslog,sshd,web,">
  <rule id="100002" level="12">
    <if_sid>31100</if_sid>
    <url>UNION%20SELECT|SELECT.*FROM|/etc/passwd</url>
    <description>SOC Alert: SQL Injection (SQLi) attempt detected from $(srcip)</description>
    <mitre>
      <id>T1190</id>
    </mitre>
  </rule>
</group>
```

### 3. SOAR Active Response Configuration (configs/manager-active-response.xml)
To automate threat containment, the Wazuh Manager was configured to trigger the local irewall-drop binary on the affected agent for **600 seconds (10 minutes)** whenever critical web or SSH brute-force rules are triggered:

```xml
<!-- /var/ossec/etc/ossec.conf (Wazuh Manager) -->
<ossec_config>
  <active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>31103,100002,5712,5758,5760</rules_id>
    <timeout>600</timeout>
  </active-response>
</ossec_config>
```

---

## Purple Team Scenarios: Attack & Detection Engineering

### Scenario 1: Web Application Exploitation (SQLi & LFI — MITRE T1190)

#### Red Team Execution (Kali Linux — 192.168.100.235)
Three distinct web attacks were executed against the Ubuntu Nginx server (192.168.100.240):
1. **Union-Based SQL Injection (SQLi):** Attempting to extract credentials from the users table.
2. **Directory Traversal / Local File Inclusion (LFI):** Attempting to read /etc/passwd.
3. **Automated Vulnerability Scanner Emulation:** Spoofing the Nikto/2.1.6 User-Agent header.

```bash
curl -i "http://192.168.100.240/index.html?id=1%20UNION%20SELECT%20username,password%20FROM%20users--"
curl -i "http://192.168.100.240/../../../../etc/passwd"
curl -i -A "Nikto/2.1.6" "http://192.168.100.240/"
```

![Web Attacks from Kali](screenshots/02-web-attacks-kali.png)

#### Blue Team Detection Pipeline
* **Raw Log Captured (/var/log/nginx/access.log):**
  ```text
  192.168.100.235 - - [04/Oct/2026:15:14:20 +0000] "GET /index.html?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 404 162 "-" "curl/8.20.0"
  ```
* **Wazuh Decoder:** web-accesslog extracted srcip: 192.168.100.235, protocol: GET, id: 404, and url.
* **Triggered Rules:**
  * **ule.id: 100002 (Level 12 — High/Critical):** SOC Alert: SQL Injection (SQLi) attempt detected from 192.168.100.235 | **MITRE ATT&CK:** T1190 (*Initial Access -> Exploit Public-Facing Application*).
  * **ule.id: 31101 (Level 5):** Web server 400 error code.

---

### Scenario 2: Credential Access via SSH Brute-Force (MITRE T1110)

#### Red Team Execution (Kali Linux — 192.168.100.235)
A high-velocity password-guessing attack was launched against the OpenSSH daemon on 192.168.100.240:

```bash
hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt -t 4 ssh://192.168.100.240
```

#### Blue Team Multi-Stage Correlation
Wazuh ingested the /var/log/auth.log stream (**151 hits**) and escalated severity across multiple correlation tiers:

| Rule ID | Severity Level | Rule Description | Security Significance |
| :---: | :---: | :--- | :--- |
| 5503 / 5557 | **Level 5** | PAM: User login failed. / unix_chkpwd: Password check failed. | Host-level PAM authentication failure telemetry |
| 5760 | **Level 5** | sshd: authentication failed. | Individual failed SSH login attempt |
| 5758 | **Level 8** | Maximum authentication attempts exceeded. | SSH daemon connection threshold breached |
| 2502 | **Level 10** | syslog: User missed the password more than one time | Repeated authentication failure correlation |
| 40111 | **Level 10** | Multiple authentication failures. | High-confidence Brute-Force attack (**MITRE T1110**) |

![SSH Brute-Force Alerts](screenshots/03-ssh-bruteforce-alerts.png)

---

## SOAR Implementation: Automated Kernel-Level Remediation

### 1. Network Isolation Proof (Attacker Perspective)
Immediately after dispatching the SQL Injection payload at 15:14:20 GMT, Kali Linux attempted to verify connectivity to 192.168.100.240 via ICMP echo requests (ping -c 3). All packets were dropped (**100% packet loss**), confirming total network isolation:

![Kali Blocked Ping](screenshots/04-kali-blocked-ping.png)

### 2. Netfilter/iptables & Forensic JSON Telemetry (Target Perspective)
Inspecting the Ubuntu server's kernel firewall (sudo iptables -L INPUT -n -v) and the Wazuh Active Response audit log (/var/ossec/logs/active-responses.log) provides irrefutable forensic proof of automated containment:

* **Kernel Firewall Verification:**
  * Rule DROP all -- * * 192.168.100.235 0.0.0.0/0 dynamically inserted at the top of Chain INPUT.
  * Packet counter shows **3 pkts / 252 bytes** dropped (matching the 3 x 84 bytes = 252 bytes from Kali's ping -c 3 command).
* **Active Response Audit Log (ctive-responses.log):**
  * Displays the exact JSON payload sent by wazuh-execd on 
ode01, linking the irewall-drop execution directly to ule.id: 100002 and mitre.id: T1190.

![Iptables and Active Response Log](screenshots/05-iptables-active-response-log.png)

### 3. SIEM Mean Time to Respond (MTTR) Verification
In the Wazuh Threat Hunting dashboard, the chronological event stream demonstrates sub-second automated containment alongside full administrative auditability:

* **16:14:21.734** — ule.id: 100002 (Level 12): SOC Alert: SQL Injection (SQLi) attempt detected
* **16:14:22.163** — ule.id: 651 (Level 3): Host Blocked by firewall-drop Active Response
* **Measured Reaction Time (MTTR):** 16:14:22.163 - 16:14:21.734 = 429 ms
* **Post-Incident Administrative Audit (16:17:50 – 16:18:14):** Rules 5715 (sshd: authentication success), 5501 (PAM: Login session opened), and 5402 (Successful sudo to ROOT executed) logged the SOC analyst's SSH session used to inspect iptables.

![SOAR Correlation Dashboard](screenshots/06-soar-correlation-dashboard.png)

---

## Key Security Metrics & Results

| Metric | Measured Value | Details |
| :--- | :---: | :--- |
| **Mean Time to Detect (MTTD)** | **~1.0 second** | Nginx request (15:14:20) to Wazuh alert indexing (15:14:21.734) |
| **Mean Time to Respond (MTTR)** | **429 milliseconds** | Alert generation (16:14:21.734) to iptables block (16:14:22.163) |
| **Quarantine Duration** | **600 seconds (10 min)** | Configurable TTL with automatic unblocking (ule.id: 652) |
| **MITRE ATT&CK Coverage** | **T1190, T1110** | Initial Access (Web Exploitation) & Credential Access (Brute-Force) |

---

## Repository Structure

```text
wazuh-soc-soar-lab/
├── configs/
│   ├── agent-ossec.conf              # Ubuntu 26.04 Wazuh Agent log collection config
│   └── manager-active-response.xml   # Wazuh Manager SOAR firewall-drop configuration
├── rules/
│   └── local_rules.xml               # Custom Level 12 SQLi detection rule (ID 100002)
├── screenshots/
│   ├── 01-agent-active.png
│   ├── 02-web-attacks-kali.png
│   ├── 03-ssh-bruteforce-alerts.png
│   ├── 04-kali-blocked-ping.png
│   ├── 05-iptables-active-response-log.png
│   └── 06-soar-correlation-dashboard.png
└── README.md                         # Project documentation
```

---

## How to Reproduce This Lab

1. **Deploy Wazuh Server:**
   Deploy the official wazuh-docker single-node stack on the host machine (192.168.100.14).
2. **Provision & Enroll the Ubuntu Target (192.168.100.240):**
   ```bash
   sudo apt-get update && sudo apt-get install -y nginx openssh-server rsyslog
   sudo WAZUH_MANAGER="192.168.100.14" WAZUH_AGENT_NAME="ubuntu-prod-server" apt-get install -y wazuh-agent=4.7.5-1
   sudo systemctl enable --now rsyslog nginx ssh wazuh-agent
   ```
3. **Apply Custom Rules & Active Response on Wazuh Manager:**
   * Copy ules/local_rules.xml to /var/ossec/etc/rules/local_rules.xml.
   * Append configs/manager-active-response.xml into /var/ossec/etc/ossec.conf.
   * Restart the Manager: /var/ossec/bin/wazuh-control restart.
4. **Execute Offensive Tests from Kali (192.168.100.235):**
   Run the curl and hydra commands documented in the Purple Team Scenarios section and verify automatic isolation via sudo iptables -L INPUT -n -v.

---

## Author
**Walid** — *Cybersecurity & SOC/SOAR Engineering Lab*
