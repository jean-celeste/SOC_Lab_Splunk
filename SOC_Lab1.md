Great choice. This is **exactly** the kind of project that SOC interviewers love because it shows *end-to-end thinking* (telemetry → detection → investigation → response), even with limited resources.

Below is a **very detailed, SOC-analyst–grade plan** tailored to:

* ✅ **3 VMs only**
* ✅ **VirtualBox**
* ✅ **Splunk Free**
* ✅ **Splunk Universal Forwarder**
* ✅ **Sysmon**
* ✅ **Single laptop, 8 GB RAM**
* ✅ Portfolio-ready documentation

I’ll structure this like a **real lab runbook** you can later turn into a GitHub repo.

---

# 📌 Project 1: SOC Home Lab with Splunk SIEM (3-VM Setup)

## 🎯 Objective

Build a functional SOC environment to:

* Collect and normalize logs
* Detect malicious activity
* Investigate security incidents
* Create alerts, dashboards, and playbooks

---

## 🧠 High-Level Architecture

```
[Kali Linux]  --->  Attack Traffic
                     |
[Windows 10]  --->  Logs (Event Logs + Sysmon)
                     |
[Ubuntu Server] ---> Splunk SIEM (Indexer + Search Head)
```

---

## 🖥️ VM Setup & Resource Planning (IMPORTANT)

Since you only have **8 GB RAM**, keep it lean:

| VM   | OS                   | Role              | RAM  | CPU |
| ---- | -------------------- | ----------------- | ---- | --- |
| VM 1 | Ubuntu Server 22.04  | Splunk SIEM       | 3 GB | 2   |
| VM 2 | Windows 10           | Victim / Endpoint | 3 GB | 2   |
| VM 3 | Kali Linux (Minimal) | Attacker          | 2 GB | 1   |

💡 **Tip**: Disable GUI on Ubuntu Server (CLI only).

---

## 🔹 Phase 1: VirtualBox & Networking Setup

### Network Configuration

Use **NAT Network** so all VMs can talk but are isolated from the host network.

* VirtualBox → Settings → Network
* Adapter 1 → **NAT Network**
* Network Name: `192.168.1.0` (or create new NAT Network)

### IP Addressing (Static Recommended)

| VM              | IP             |
| --------------- | -------------- |
| Ubuntu (Splunk) | 192.168.1.7 |
| Windows 10      | 192.168.1.5 |
| Kali Linux      | 192.168.1.4 |

---

## 🔹 Phase 2: Ubuntu Server – Splunk SIEM

### 1️⃣ Install Ubuntu Server

* Choose **OpenSSH Server**
* No desktop environment

### 2️⃣ Install Splunk Enterprise (Free)

```bash
wget -O splunk.deb https://download.splunk.com/products/splunk/releases/9.x.x/linux/splunk-9.x.x-linux-amd64.deb
sudo dpkg -i splunk.deb
sudo /opt/splunk/bin/splunk start --accept-license
```

Enable boot start:

```bash
sudo /opt/splunk/bin/splunk enable boot-start
```

### 3️⃣ Access Splunk Web

From host browser:

```
http://192.168.1.7:8000
```

### 4️⃣ Create Indexes

Settings → Indexes → New Index

Create:

* `windows_security` (for Windows Security and System event logs)
* `sysmon` (for Sysmon operational logs)
* `linux`
* `kali`

---

## 🔹 Phase 3: Windows 10 – Endpoint & Telemetry

### 1️⃣ Install Splunk Universal Forwarder

* Download Windows UF
* During install:

  * Forward to: `192.168.1.7:9997`
  * Enable Local System account

### 2️⃣ Configure Forwarding

Enable receiving on Splunk:

```bash
sudo /opt/splunk/bin/splunk enable listen 9997
```

### 3️⃣ Install Sysmon

Download Sysmon from Sysinternals.

Install with SwiftOnSecurity config:

```powershell
sysmon.exe -accepteula -i sysmonconfig-export.xml
```

Verify:

```powershell
sysmon -c
```

### 4️⃣ Configure UF Inputs (CRITICAL)

Edit:

```
C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf
```

```ini
[WinEventLog://Security]
index = windows_security
disabled = false

[WinEventLog://System]
index = windows_security
disabled = false

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = sysmon
disabled = false
renderXml = true
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

Restart Forwarder:

```powershell
Restart-Service SplunkForwarder
```

---

## 🔹 Phase 4: Kali Linux – Attacker

### Install Splunk UF (Optional but Recommended)

```bash
wget -O splunkforwarder.deb https://download.splunk.com/products/universalforwarder/releases/9.x.x/linux/splunkforwarder-9.x.x-linux-amd64.deb
sudo dpkg -i splunkforwarder.deb
sudo /opt/splunkforwarder/bin/splunk start --accept-license
```

### Forward Logs:

```bash
sudo /opt/splunkforwarder/bin/splunk add forward-server 192.168.1.7:9997
```

Add auth logs:

```ini
[monitor:///var/log/auth.log]
index = kali
```

---

## 🔹 Phase 5: Attack Scenarios (Blue Team Focused)

### 🔴 Scenario 1: Brute Force (Credential Access)

**From Kali:**

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt rdp://192.168.1.5
```

**Detection Logic:**

* Windows Event ID **4625**
* Multiple failures from same IP

**Splunk SPL:**

```spl
index=windows_security EventCode=4625
| stats count by Account_Name, src_ip
| where count > 5
```

---

### 🔴 Scenario 2: Suspicious PowerShell

**On Windows:**

```powershell
powershell -enc SQBFAFgA
```

**Sysmon Event ID:** 1 (Process Creation)

**Detection:**

```spl
index=sysmon EventCode=1 Image="*powershell.exe" CommandLine="*-enc*"
```

---

### 🔴 Scenario 3: Privilege Escalation Attempt

**Simulate:**

```powershell
net localgroup administrators testuser /add
```

**Detection:**

* Event ID **4728** (Member added to security-enabled local group)

**Splunk SPL:**

```spl
index=windows_security EventCode=4728
| stats count by MemberName, SubjectUserName
```

---

### 🔴 Scenario 4: Lateral Movement (SMB)

**From Kali:**

```bash
smbclient -L //192.168.1.5 -U testuser
```

**Detection:**

* Event ID **4624** (Successful logon)
* Logon Type **3** (Network logon)

**Splunk SPL:**

```spl
index=windows_security EventCode=4624 Logon_Type=3
| stats count by src_ip, Account_Name
| sort -count
```

---

### 🔴 Scenario 5: Data Exfiltration Simulation

**On Windows:**

```powershell
Invoke-WebRequest -Uri http://192.168.1.4/upload
```

**Detection:**

* Sysmon Event ID **3 (Network Connection)**

**Splunk SPL:**

```spl
index=sysmon EventCode=3
| stats count by Image, DestinationIp, DestinationPort
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443
| sort -count
```

---

## 🔹 Phase 6: Alerts & Correlation Rules

Create Splunk alerts for:

* Brute force attempts
* Encoded PowerShell
* New admin creation
* Lateral SMB access
* Suspicious outbound traffic

Set:

* Trigger: Real-time or 5 min
* Action: Log event / email (optional)

---

## 🔹 Phase 7: SOC Dashboards

Create dashboards showing:

* Failed logins over time
* Top attacking IPs
* PowerShell executions
* Admin privilege changes
* Network connections by process

---

## 🔹 Phase 8: Incident Response Playbooks

Example format:

### 🛑 Incident: Brute Force Attack

**Detection**

* Alert: Multiple 4625 events

**Investigation**

* Identify source IP
* Affected accounts
* Timeline analysis

**Containment**

* Block IP
* Disable account

**Eradication**

* Reset credentials

**Recovery**

* Monitor logins

**Lessons Learned**

* Enable MFA
* Adjust thresholds

---

## 🔹 Phase 9: Documentation (Portfolio-Ready)

Your GitHub repo should include:

```
SOC-Splunk-Lab/
├── architecture-diagram.png
├── setup-guide.md
├── sysmon-config/
├── detection-rules/
├── dashboards/
├── incident-playbooks/
├── screenshots/
└── README.md
```

---

## 🧠 Why This Is STRONG for SOC Roles

You demonstrate:

* SIEM engineering
* Endpoint telemetry (Sysmon)
* Attack simulation
* Detection logic (SPL)
* Incident response mindset

This is **SOC Level 1 → Level 2 ready**.

---

### ✅ Next Steps

If you want, I can:

1. Create a **README.md** for this project
2. Write **Splunk SPL detection rules** in a separate file
3. Help you **optimize this for Sec+ / Blue Team interviews**
4. Convert this into a **resume bullet**

Just tell me 👍
