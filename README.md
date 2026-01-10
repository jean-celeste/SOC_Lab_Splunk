# 🛡️ SOC Home Lab with Splunk SIEM

A comprehensive Security Operations Center (SOC) homelab project demonstrating end-to-end security operations: **telemetry → detection → investigation → response**. This project showcases practical SOC analyst skills using Splunk SIEM, Sysmon, and incident response playbooks.

---

## 🎯 Project Overview

This homelab demonstrates a complete SOC workflow by:
- **Collecting and normalizing logs** from Windows endpoints using Sysmon and Windows Event Logs
- **Detecting malicious activity** through Splunk alerts and correlation rules
- **Investigating security incidents** using SPL queries and analysis techniques
- **Responding to incidents** with NIST-based incident response playbooks

**Key Achievement:** Built a functional SOC environment with 5 attack scenarios, detection rules, dashboards, and comprehensive incident response playbooks - all documented and ready for portfolio presentation.

---

## 🏗️ Architecture

```
┌─────────────────┐
│   Kali Linux    │ ───> Attack Traffic
│   (Attacker)    │
│   DHCP Assigned │
└─────────────────┘
         │
         │ Attack Scenarios
         │ (Brute Force, Lateral Movement, etc.)
         ▼
┌─────────────────┐
│   Windows 10    │ ───> Logs (Event Logs + Sysmon)
│   (Victim)      │
│   DHCP Assigned │
└─────────────────┘
         │
         │ Splunk Universal Forwarder
         │ (Port 9997)
         ▼
┌─────────────────┐
│ Ubuntu Server   │ ───> Splunk SIEM
│   (SIEM)        │      (Indexer + Search Head)
│   DHCP Assigned │
└─────────────────┘
```

**Technology Stack:**
- **SIEM:** Splunk Enterprise (Free tier)
- **Endpoint Monitoring:** Sysmon (SwiftOnSecurity config)
- **Log Forwarding:** Splunk Universal Forwarder
- **Virtualization:** VirtualBox
- **Attack Platform:** Kali Linux
- **Victim Platform:** Windows 10

---

## 📚 Project Structure

```
SOC_Lab_Splunk/
├── Phase5_Attack_Scenarios_Guide.md      # Attack scenario documentation
├── Phase6_Splunk_Alerts_Guide.md          # Alert configuration guide
├── Phase7_SOC_Dashboards_Guide.md        # Dashboard creation guide
├── Phase8_Incident_Response_Playbooks.md  # Main playbook overview
│
├── Playbooks/                             # Incident response playbooks
│   ├── Brute Force/
│   │   └── Playbook1_Brute_Force_Attack.md
│   ├── Powershell Execution/
│   │   └── Playbook2_Suspicious_PowerShell.md
│   ├── Privilege Escalation/
│   │   └── Playbook3_Privilege_Escalation.md
│   ├── Lateral Movement/
│   │   └── Playbook4_Lateral_Movement_SMB.md
│   ├── Data Exfiltration/
│   │   └── Playbook5_Data_Exfiltration.md
│   ├── Severity_Determination_Guide.md
│   ├── MITRE_ATTACK_Techniques_Reference.md
│   └── Terminology_Glossary.md
│
├── Scenarios/                              # Step-by-step attack scenarios
│   ├── scenario1/                         # Brute Force
│   ├── scenario2/                         # PowerShell
│   ├── scenario3/                         # Privilege Escalation
│   ├── scenario4/                         # Lateral Movement
│   └── scenario5/                         # Data Exfiltration
│
├── vm_config/                              # VM configuration files
│   ├── virtualbox_config.md
│   ├── ubuntuServer_VM/
│   ├── windows10_VM/
│   └── kali_VM/
│
└── memory-bank/                            # Project documentation
    ├── projectbrief.md
    ├── progress.md
    └── activeContext.md
```

---

## 🚀 Quick Start

### Prerequisites
- VirtualBox installed
- 8 GB RAM minimum
- Windows 10 VM, Ubuntu Server VM, Kali Linux VM

### Setup Steps

1. **Network Configuration**
   - Configure NAT Network in VirtualBox
   - IP addresses are assigned via DHCP (verify IPs using `ipconfig`/`ifconfig` on each VM)

2. **Splunk Setup**
   - Install Splunk Enterprise on Ubuntu Server
   - Create indexes: `windows_security`, `sysmon`
   - Access Splunk Web UI: `http://<Ubuntu_Server_IP>:8000` (check IP with `ifconfig`)

3. **Endpoint Configuration**
   - Install Sysmon on Windows 10 VM
   - Configure Splunk Universal Forwarder
   - Forward logs to Splunk (port 9997) - use Ubuntu Server's DHCP-assigned IP

4. **Attack Scenarios**
   - Execute 5 attack scenarios from Kali Linux
   - See `Phase5_Attack_Scenarios_Guide.md` for detailed steps

5. **Incident Response**
   - Follow playbooks in `Phase8_Incident_Response_Playbooks.md`
   - Use NIST-based response procedures

---

## 📖 Documentation Guide

### Phase Guides

- **[Phase 5: Attack Scenarios](Phase5_Attack_Scenarios_Guide.md)** - Detailed attack execution steps
- **[Phase 6: Splunk Alerts](Phase6_Splunk_Alerts_Guide.md)** - Alert configuration and thresholds
- **[Phase 7: SOC Dashboards](Phase7_SOC_Dashboards_Guide.md)** - Dashboard creation and visualization
- **[Phase 8: Incident Response Playbooks](Phase8_Incident_Response_Playbooks.md)** - Complete playbook overview

### Incident Response Playbooks

All playbooks follow the **NIST SP 800-61** Incident Response lifecycle:

1. **[Playbook 1: Brute Force Attack](Playbooks/Brute Force/Playbook1_Brute_Force_Attack.md)**
   - MITRE ATT&CK: T1110
   - Severity: Medium
   - Response Time: < 15 minutes

2. **[Playbook 2: Suspicious PowerShell Execution](Playbooks/Powershell Execution/Playbook2_Suspicious_PowerShell.md)**
   - MITRE ATT&CK: T1059.001
   - Severity: High
   - Response Time: < 10 minutes

3. **[Playbook 3: Privilege Escalation](Playbooks/Privilege Escalation/Playbook3_Privilege_Escalation.md)**
   - MITRE ATT&CK: T1078.003
   - Severity: Critical
   - Response Time: < 5 minutes

4. **[Playbook 4: Lateral Movement (SMB)](Playbooks/Lateral Movement/Playbook4_Lateral_Movement_SMB.md)**
   - MITRE ATT&CK: T1021.002
   - Severity: High
   - Response Time: < 10 minutes

5. **[Playbook 5: Data Exfiltration](Playbooks/Data Exfiltration/Playbook5_Data_Exfiltration.md)**
   - MITRE ATT&CK: T1041
   - Severity: High (Critical if sensitive data confirmed)
   - Response Time: < 10 minutes

### Supporting Documentation

- **[Severity Determination Guide](Playbooks/Severity_Determination_Guide.md)** - How to determine incident severity
- **[MITRE ATT&CK Techniques Reference](Playbooks/MITRE_ATTACK_Techniques_Reference.md)** - Detailed technique information
- **[Terminology Glossary](Playbooks/Terminology_Glossary.md)** - SOC and Splunk terminology
- **[Attack Chain Correlation Guide](Playbooks/Playbook0_Attack_Chain_Correlation_Guide.md)** - Correlating multi-stage attacks

---

## 🎓 Skills Demonstrated

### SIEM Engineering
- Splunk Enterprise installation and configuration
- Index creation and data normalization
- Universal Forwarder configuration
- Log source integration (Windows Event Logs, Sysmon)

### Detection Engineering
- SPL query development for threat detection
- Alert creation and threshold tuning
- Correlation rule development
- False positive reduction

### Incident Response
- NIST SP 800-61 framework implementation
- End-to-end incident response procedures
- Containment and recovery strategies
- Post-incident analysis and lessons learned

### Threat Intelligence
- MITRE ATT&CK framework mapping
- Attack technique identification
- Attack chain analysis
- TTP (Tactics, Techniques, Procedures) documentation

### Security Analysis
- Log analysis and investigation
- Process tree analysis
- Network connection analysis
- Timeline reconstruction

---

## 📊 Project Statistics

- **Total Playbooks:** 5 complete NIST-based incident response playbooks
- **Attack Scenarios:** 5 MITRE ATT&CK techniques covered
- **SPL Queries:** 50+ detection and analysis queries
- **Documentation:** 1,500+ pages of detailed guides and playbooks
- **MITRE ATT&CK Techniques:** 5 techniques documented (T1110, T1059.001, T1078.003, T1021.002, T1041)

---

## 🔧 Key Features

### Standardized Policies
- **Correlation Methodology:** Manual correlation preferred, `join` commands restricted to offline investigation
- **Response Time SLAs:** Standardized severity-based targets (Critical: <5min, High: <10min, Medium: <15min)
- **Port Filtering:** Context-dependent logic for common ports (3389, 445)
- **Containment/Recovery Symmetry:** Every containment action has corresponding recovery steps
- **Field Naming:** Global guidance for environment-specific field name verification

### Playbook Features
- Complete NIST SP 800-61 lifecycle coverage
- Step-by-step SPL queries with explanations
- PowerShell commands for Windows administration
- Learning notes from trial and error
- Escalation criteria and related playbook references
- Response time metrics (MTTD, MTTR, MTTC)

---

## 🎯 Use Cases

### For Learning
- Understand SOC operations end-to-end
- Learn Splunk SPL query development
- Practice incident response procedures
- Study MITRE ATT&CK framework in practice

### For Portfolio
- Demonstrate practical SOC skills
- Showcase documentation abilities
- Highlight problem-solving approach
- Display understanding of security frameworks

### For Interviews
- Discuss SIEM engineering experience
- Explain detection rule development
- Walk through incident response procedures
- Demonstrate analytical thinking

---

## 📝 Notes

- **Environment:** This is a homelab environment for learning purposes
- **Field Names:** Field names may vary in your Splunk environment - always verify using `fieldsummary`
- **Queries:** All SPL queries have been tested in this specific environment
- **Playbooks:** Based on NIST SP 800-61 and industry best practices, adapted for homelab use

---

## 🔗 Resources

- [NIST SP 800-61 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) - Computer Security Incident Handling Guide
- [MITRE ATT&CK Framework](https://attack.mitre.org/) - Adversarial Tactics, Techniques, and Common Knowledge
- [Splunk Documentation](https://docs.splunk.com/) - Splunk Enterprise documentation
- [Sysmon Documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) - System Monitor documentation

---

## 📄 License

This project is for educational and portfolio purposes.

---

## 👤 Author

Created as part of a SOC analyst learning journey to demonstrate practical security operations skills.

---

**Last Updated:** 2024

**Status:** ✅ All phases complete - Portfolio ready
