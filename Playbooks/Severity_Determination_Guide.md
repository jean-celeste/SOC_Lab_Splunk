# 📊 Severity Determination Guide for Incident Response Playbooks

This guide explains how to determine the severity level for security incidents in your SOC lab playbooks. Severity helps prioritize response efforts and allocate resources appropriately.

---

## 🎯 What is Severity?

**Severity** indicates the potential impact and urgency of a security incident. It helps answer:
- How quickly should we respond?
- What resources should be allocated?
- Who needs to be notified?
- What's the potential business impact?

---

## 📈 Common Severity Levels

Most organizations use a 4-tier severity system:

| Severity | Description | Response Time | Impact Level |
|----------|------------|---------------|--------------|
| **Critical** | Immediate threat to security, data, or operations | < 5 minutes | Severe - System compromise, data breach, service disruption |
| **High** | Significant security risk requiring urgent attention | < 15 minutes | Major - Potential for system compromise or data loss |
| **Medium** | Security concern that needs prompt investigation | < 1 hour | Moderate - Limited impact, contained threat |
| **Low** | Minor security event, routine investigation | < 4 hours | Minimal - No immediate threat, informational |

---

## 🔍 Factors for Determining Severity

Consider these factors when assigning severity:

### 1. **Impact on Confidentiality, Integrity, Availability (CIA Triad)**

**Confidentiality:**
- Is sensitive data at risk?
- Could credentials be compromised?
- Is data exfiltration possible?

**Integrity:**
- Could data be modified or deleted?
- Is system configuration at risk?
- Could logs be tampered with?

**Availability:**
- Could services be disrupted?
- Is system access compromised?
- Could the attack spread to other systems?

### 2. **Attack Success Status**

- **Critical/High:** Attack succeeded (credentials compromised, privilege escalation successful)
- **Medium:** Attack in progress but not yet successful
- **Low:** Attack detected but blocked/failed

### 3. **Scope and Scale**

- **Critical:** Multiple systems affected, widespread impact
- **High:** Single system but critical asset
- **Medium:** Limited scope, contained
- **Low:** Isolated incident, minimal scope

### 4. **Attack Technique (MITRE ATT&CK)**

Some techniques are inherently more severe:
- **Critical:** Privilege escalation, persistence, credential access (successful)
- **High:** Lateral movement, execution, defense evasion
- **Medium:** Discovery, collection, exfiltration attempts
- **Low:** Reconnaissance, initial access attempts (failed)

### 5. **Data Sensitivity**

- **Critical:** PII, financial data, intellectual property at risk
- **High:** Internal data, user credentials
- **Medium:** System logs, configuration data
- **Low:** Public information, non-sensitive data

### 6. **System Criticality**

- **Critical:** Domain controllers, database servers, payment systems
- **High:** Application servers, file servers
- **Medium:** Workstations, development systems
- **Low:** Test systems, isolated VMs

---

## 📋 Severity Assessment Framework

Use this decision tree to determine severity:

```
Is the attack successful?
├─ YES → Is it privilege escalation or credential compromise?
│   ├─ YES → CRITICAL
│   └─ NO → Is it lateral movement or data exfiltration?
│       ├─ YES → HIGH
│       └─ NO → MEDIUM
│
└─ NO → Is it targeting critical systems?
    ├─ YES → Is it a persistent attack pattern?
    │   ├─ YES → HIGH
    │   └─ NO → MEDIUM
    └─ NO → Is it a single failed attempt?
        ├─ YES → LOW
        └─ NO → MEDIUM (multiple attempts)
```

---

## 🎯 Severity Examples for Your Lab Scenarios

### Scenario 1: Brute Force Attack (T1110)

**Severity: MEDIUM** (or HIGH if successful)

**Reasoning:**
- ✅ Attack is **in progress** (not yet successful)
- ✅ Targets **authentication** (credential access)
- ✅ **Multiple attempts** indicate persistence
- ⚠️ **No immediate compromise** (failed logons)
- ⚠️ **Single system** affected (Windows 10 VM)
- ⚠️ **Limited scope** (RDP brute force)

**If attack succeeds (Event ID 4624 appears):**
- **Severity: HIGH** or **CRITICAL**
- Successful credential compromise
- Potential for further access

**Factors:**
- Number of attempts (> 20 = HIGH, < 20 = MEDIUM)
- Target accounts (admin accounts = HIGH)
- Attack duration (longer = HIGH)

---

### Scenario 2: Suspicious PowerShell (T1059.001)

**Severity: HIGH**

**Reasoning:**
- ✅ **Encoded commands** indicate obfuscation (defense evasion)
- ✅ **Execution technique** - attacker is running code
- ✅ **Potential for malicious payload** execution
- ⚠️ **Unknown intent** - could be reconnaissance or malware
- ⚠️ **User-level execution** (not yet escalated)

**If combined with other indicators:**
- **CRITICAL:** If privilege escalation follows
- **HIGH:** If network connections to suspicious IPs
- **MEDIUM:** If isolated, single execution

**Factors:**
- Command patterns (download, invoke, hidden = HIGH)
- User context (admin user = HIGH)
- Parent process (unusual parent = HIGH)

---

### Scenario 3: Privilege Escalation (T1078)

**Severity: CRITICAL**

**Reasoning:**
- ✅ **Attack succeeded** (user added to Administrators)
- ✅ **Critical technique** - grants full system access
- ✅ **High impact** - attacker now has admin rights
- ✅ **Enables further attacks** - persistence, lateral movement
- ✅ **Immediate threat** - system is compromised

**Always CRITICAL because:**
- Administrative access = full system control
- Can install persistence mechanisms
- Can access all data on system
- Can modify security controls
- Can perform lateral movement

**Response Time:** < 5 minutes (immediate containment required)

---

### Scenario 4: Lateral Movement - SMB (T1021.002)

**Severity: HIGH**

**Reasoning:**
- ✅ **Attack technique** - lateral movement indicates active compromise
- ✅ **Network access** - attacker is moving through environment
- ✅ **Potential for spread** - could affect multiple systems
- ⚠️ **May indicate** successful initial access
- ⚠️ **Reconnaissance** - attacker exploring network

**If multiple systems accessed:**
- **CRITICAL:** If critical systems accessed
- **HIGH:** If multiple workstations/servers
- **MEDIUM:** If single system, limited access

**Factors:**
- Number of systems accessed
- Type of systems (servers = HIGH, workstations = MEDIUM)
- Data accessed (sensitive shares = HIGH)
- Account used (admin account = CRITICAL)

---

### Scenario 5: Data Exfiltration (T1041)

**Severity: HIGH** (or CRITICAL if sensitive data)

**Reasoning:**
- ✅ **Attack technique** - data exfiltration indicates compromise
- ✅ **Confidentiality breach** - data leaving the network
- ✅ **Non-standard ports** - indicates malicious intent
- ⚠️ **Unknown data type** - could be sensitive
- ⚠️ **C2 communication** - potential for ongoing access

**If sensitive data confirmed:**
- **CRITICAL:** PII, credentials, financial data
- **HIGH:** Internal documents, system data
- **MEDIUM:** Logs, non-sensitive data

**Factors:**
- Data type (sensitive = CRITICAL)
- Volume of data (large = HIGH)
- Destination (known malicious IP = HIGH)
- Process making connection (suspicious = HIGH)

---

## 📊 Severity Decision Matrix

Use this matrix to quickly assess severity:

| Attack Status | Target Criticality | Data Sensitivity | Technique Severity | **Severity** |
|---------------|-------------------|-----------------|-------------------|--------------|
| Successful | Critical | High | Critical | **CRITICAL** |
| Successful | Critical | Medium | High | **CRITICAL** |
| Successful | Medium | High | High | **HIGH** |
| In Progress | Critical | High | High | **HIGH** |
| In Progress | Medium | Medium | Medium | **MEDIUM** |
| Failed | Any | Low | Low | **LOW** |
| Failed | Medium | Medium | Medium | **MEDIUM** |

---

## 🎯 Quick Reference: Severity by MITRE ATT&CK Technique

| Technique Category | Typical Severity | Notes |
|-------------------|------------------|-------|
| **Initial Access** (failed) | MEDIUM | Multiple attempts = HIGH |
| **Initial Access** (successful) | HIGH | Critical systems = CRITICAL |
| **Execution** | HIGH | Encoded/obfuscated = HIGH |
| **Persistence** | CRITICAL | System compromise |
| **Privilege Escalation** | CRITICAL | Always critical |
| **Defense Evasion** | HIGH | Indicates sophisticated attacker |
| **Credential Access** (successful) | CRITICAL | Credentials compromised |
| **Credential Access** (attempts) | MEDIUM | Multiple = HIGH |
| **Discovery** | MEDIUM | Reconnaissance phase |
| **Lateral Movement** | HIGH | Active compromise |
| **Collection** | HIGH | Preparing for exfiltration |
| **Exfiltration** | HIGH/CRITICAL | Depends on data sensitivity |
| **Command and Control** | HIGH | Ongoing compromise |

---

## 📝 How to Document Severity in Playbooks

### In the Playbook Header:

```markdown
**Severity:** HIGH
**Response Time Target:** < 15 minutes
```

### Justification Section (Optional but Recommended):

```markdown
**Severity Justification:**
- Attack technique: [Technique Name] - [Typical Severity]
- Attack status: [Successful/In Progress/Failed]
- Target: [System Type] - [Criticality Level]
- Impact: [CIA Triad impact]
- **Final Assessment:** [Severity Level]
```

### Example from Your Playbooks:

**Brute Force:**
```markdown
**Severity:** MEDIUM
**Justification:** Multiple failed login attempts (Event ID 4625) indicate 
credential access attempt. Attack is in progress but not yet successful. 
Single system affected. If attack succeeds (Event ID 4624), severity 
escalates to HIGH/CRITICAL.
```

**Privilege Escalation:**
```markdown
**Severity:** CRITICAL
**Justification:** User successfully added to Administrators group (Event ID 4732). 
Attack succeeded, granting full system access. Enables persistence, lateral 
movement, and data access. Immediate containment required.
```

---

## 🔄 Severity Escalation

Severity can change as you investigate:

1. **Initial Assessment:** Based on alert/indicator
2. **During Investigation:** May escalate if:
   - Attack succeeded
   - Multiple systems affected
   - Sensitive data accessed
   - Lateral movement detected

3. **Document Changes:** Note why severity changed

**Example:**
```
Initial Severity: MEDIUM (brute force detected)
Escalated to: HIGH (successful logon detected - Event ID 4624)
Reason: Attack succeeded, credentials compromised
```

---

## 💡 Best Practices

1. **Start Conservative:** If unsure, assign higher severity
2. **Reassess During Investigation:** Severity may change
3. **Document Reasoning:** Explain why you chose a severity level
4. **Consider Context:** Lab vs. production (production = higher severity)
5. **Use Frameworks:** Reference NIST, MITRE ATT&CK for guidance
6. **Review Regularly:** Update severity based on lessons learned

---

## 📚 References

- **NIST SP 800-61 Rev. 2:** Incident severity classification
- **MITRE ATT&CK:** Technique impact assessment
- **CIS Controls:** Incident response prioritization
- **ISO/IEC 27035:** Information security incident management

---

## 🎯 Summary

**Quick Severity Guide:**
- **CRITICAL:** Privilege escalation, successful credential compromise, data breach
- **HIGH:** Lateral movement, execution, exfiltration, active compromise
- **MEDIUM:** Attack attempts, reconnaissance, limited scope
- **LOW:** Single failed attempts, informational events

**Remember:** Severity is a tool for prioritization. When in doubt, err on the side of caution and assign a higher severity level.

---

**Return to:** [Playbook Template](./Playbook_Template.md) | [Phase 8 Overview](../Phase8_Incident_Response_Playbooks.md)








