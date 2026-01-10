# 🛡️ Phase 8: Incident Response Playbooks

This guide provides comprehensive incident response playbooks for each attack scenario detected in your SOC lab. These playbooks follow the NIST Incident Response lifecycle and provide step-by-step procedures for SOC analysts.

## 📋 Prerequisites Checklist

Before using these playbooks, verify:
- [/] All 5 attack scenarios have been executed and detected
- [/] Splunk alerts are configured and triggering (Phase 6)
- [/] You can access Splunk Web UI at `http://<Ubuntu_Server_IP>:8000` (check IP with `ifconfig`)
- [/] You have admin access to Windows 10 VM for containment actions
- [ ] You understand the MITRE ATT&CK framework mapping for each scenario

---

## 🎯 Overview: NIST Incident Response Framework

Each playbook follows the NIST SP 800-61 Incident Response lifecycle:

1. **Preparation** - Prerequisites, tools, and readiness measures
2. **Detection and Analysis** - Identifying and analyzing the incident
3. **Containment** - Immediate and long-term actions to prevent further damage
4. **Eradication** - Removing the threat from the environment
5. **Recovery** - Restoring systems to normal operations
6. **Post-Incident Activities** - Lessons learned and continuous improvement

**Note:** Assign steps to individuals or teams to work concurrently when possible; this playbook is not purely sequential. Use your best judgment.

---

## 🔗 Correlation Methodology: Manual vs. Automated

### Global Correlation Policy

**For this homelab:**

1. **Manual Correlation (Primary Method)**
   - Use separate queries and correlate results manually using shared indicators:
     - IP addresses (`Source_Network_Address`, `DestinationIp`)
     - Usernames (`Account_Name`, `User`)
     - Hostnames (`host`, `ComputerName`)
     - Process IDs (`ProcessId`)
     - Time windows (same time range across queries)
   - This approach is preferred because:
     - Lower performance impact on Splunk
     - More reliable with varying field names across indexes
     - Better suited for real-time alert investigation
     - Aligns with homelab learning objectives

2. **Automated Correlation with `join` (Restricted Use)**
   - **DO NOT use `join` in:**
     - Alert queries (real-time detection searches)
     - Production detection searches
     - High-frequency queries
   - **`join` may be used only in:**
     - Offline investigation queries
     - Threat hunting queries (non-alert)
     - Post-incident analysis
     - Advanced correlation examples (clearly marked as optional)

3. **Why This Policy?**
   - `join` commands can significantly impact Splunk performance
   - Field name mismatches between indexes (e.g., Windows Security vs. Sysmon) cause `join` failures
   - Manual correlation is more reliable and teaches better analysis skills

**Note:** Throughout these playbooks, you'll see learning notes like "I'll explore using `join` later." This reflects the learning journey, but the established policy is: **manual correlation is the standard approach.**

---

## ⏱️ Response Time Targets (SLA)

### Standardized Severity-Based Response Times

All playbooks follow these standardized response time targets based on incident severity:

| Severity | Response Time Target | Rationale | Industry Benchmark |
|----------|---------------------|-----------|-------------------|
| **Critical** | **< 5 minutes** | Immediate containment required to prevent system compromise, data breach, or service disruption | Immediate to 15 minutes |
| **High** | **< 10 minutes** | Urgent response needed to prevent escalation or significant impact | 15 minutes to 1 hour |
| **Medium** | **< 15 minutes** | Prompt investigation required to assess and contain potential threats | 1 to 4 hours |
| **Low** | **< 4 hours** | Routine investigation with minimal immediate impact | 4 to 24 hours |

**Note:** These targets are adapted for homelab learning environments. Production environments may have different SLAs based on business requirements, regulatory compliance, and available resources. The targets represent **Mean Time to Contain (MTTC)** - the time from alert detection to threat neutralization.

**Response Time Metrics:**
- **MTTD (Mean Time to Detect):** Time from attack start to alert trigger
- **MTTR (Mean Time to Respond):** Time from alert to containment actions initiated
- **MTTC (Mean Time to Contain):** Time from alert to threat neutralized (this is the target metric)

---

## 🔌 Port Filtering: Context-Dependent Logic

### Understanding Port Filtering in Detection Queries

Port filtering logic varies depending on the attack scenario and detection context. Some ports are **legitimate in one context but suspicious in another**.

**Common Ports and Their Context:**

| Port | Protocol | Legitimate Context | Suspicious Context |
|------|----------|-------------------|-------------------|
| **3389** | RDP | Normal remote desktop access | Brute force attacks, unauthorized access |
| **445** | SMB | File sharing, network shares | Lateral movement, unauthorized access |
| **53** | DNS | Domain name resolution | DNS tunneling, data exfiltration |
| **80** | HTTP | Web browsing, web services | Unencrypted data exfiltration |
| **443** | HTTPS | Secure web browsing, web services | Encrypted C2 communication, data exfiltration |

**How This Applies to Playbooks:**

1. **Data Exfiltration Playbook:**
   - **Excludes** ports 3389 and 445 from detection queries
   - **Rationale:** These ports are common in the lab environment for legitimate RDP and SMB access
   - **Focus:** Detecting connections to unusual ports that indicate C2 or data exfiltration

2. **Brute Force Playbook:**
   - **Monitors** port 3389 (RDP) as the attack vector
   - **Rationale:** RDP brute force attacks target port 3389 specifically
   - **Focus:** Detecting failed authentication attempts on RDP

3. **Lateral Movement Playbook:**
   - **Monitors** port 445 (SMB) as the attack vector
   - **Rationale:** SMB lateral movement uses port 445 for network share access
   - **Focus:** Detecting unauthorized SMB access and network logons

**Key Principle:** Port filtering is **context-dependent**. The same port can be:
- **Excluded** when it's a common legitimate service in your environment
- **Monitored** when it's the specific attack vector being investigated
- **Filtered** when looking for unusual activity patterns

**Adaptation for Your Environment:**
- Review which ports are commonly used for legitimate operations in your homelab
- Adjust port filtering in detection queries based on your specific environment
- Consider creating a baseline of normal port usage to inform filtering decisions

---

## 🔄 Containment and Recovery Symmetry

### Principle: Every Containment Action Should Have a Recovery Step

**Standard Rule:** For every containment action taken during an incident, there should be a corresponding recovery step documented in the Recovery section. This ensures that temporary security measures can be properly reversed when the threat is eliminated.

**Containment Actions and Their Recovery Counterparts:**

| Containment Action | Recovery Action | Notes |
|-------------------|----------------|-------|
| **Disable Service** (RDP, SMB, PowerShell) | **Re-enable Service** | Restore service with proper security configuration |
| **Block IP Address** (Firewall Rule) | **Remove Firewall Rule** | May be kept if IP is confirmed malicious |
| **Disable User Account** | **Re-enable User Account** | Only if account is determined legitimate |
| **Remove User from Group** | **Verify Removal** | Usually permanent (no re-addition) |
| **Isolate System** (Disable Network) | **Restore Network Connectivity** | Re-enable network adapter |
| **Revoke Share Access** | **Restore Share Access** | Grant access back to legitimate users |
| **Terminate Process** | **Monitor for Recurrence** | Process termination doesn't need reversal |

**Important Considerations:**

1. **Firewall Rules:**
   - Firewall rules blocking malicious IPs may be **kept intentionally** after the incident
   - Recovery section should include guidance on when to remove vs. keep firewall rules
   - Document the decision rationale (e.g., "Keep rule if IP is confirmed malicious")

2. **Account Actions:**
   - Disabled accounts should only be re-enabled after thorough investigation
   - If account is compromised, consider deletion rather than re-enabling
   - Document the decision process in recovery steps

3. **Service Restoration:**
   - When re-enabling services, ensure proper security configuration is applied
   - Review security controls before restoring services
   - Consider implementing additional security measures before restoration

4. **Verification Steps:**
   - Recovery steps should include verification that the action was successful
   - Use monitoring queries to confirm services are restored and functioning
   - Document any issues encountered during recovery

**Recovery Decision Framework:**

Before executing recovery actions, consider:
- ✅ Has the threat been fully eliminated?
- ✅ Is the system secure enough to restore services?
- ✅ Have security controls been reviewed and updated?
- ✅ Is there a business justification for restoration?
- ✅ Have stakeholders been notified of restoration?

**Note:** Some containment actions are **intentionally permanent** (e.g., removing unauthorized users from admin groups). These don't require reversal but should be verified in the recovery phase.

---

## 📋 Field Naming and Extraction

### Important: Field Names Vary by Environment

**Critical Understanding:** Field names in Splunk can vary between environments based on:
- Data source configuration (Windows Event Logs, Sysmon, etc.)
- Splunk version and field extraction rules
- Index configuration and sourcetype settings
- Custom field extractions or transforms

**Always verify field names in your environment before using queries from these playbooks.**

### Field Extraction Decision Process

When a query doesn't work as expected, follow this process:

1. **Try extracted field first:** Use the field name as shown in the playbook queries
   - Example: `| stats count by Account_Name, Source_Network_Address`

2. **If field is empty/incorrect:** Use `rex` to extract from `_raw` field
   - Example: `| rex field=_raw "Account Name:\s+(?<account_name>[^\r\n]+)"`

3. **If neither works:** Check `fieldsummary` for actual field names
   - Example: `index=windows_security EventCode=4625 | fieldsummary`

4. **Verify field names:** Use `table *` or `spath` to see all available fields
   - Example: `index=windows_security EventCode=4625 | head 1 | table *`
   - Example: `index=windows_security EventCode=4625 | head 1 | spath`

### Common Field Names in This Homelab

**Windows Security Event Logs:**
- `Source_Network_Address` (source IP address - **not** `src_ip`)
- `Account_Name`, `Account_Domain` (account information)
- `Group_Name`, `Group_Domain` (group membership)
- `Logon_Type` (type of logon: 3 = network, 10 = RDP)
- `EventCode` (Windows Event ID)

**Sysmon Event Logs:**
- `Image` (process image path)
- `CommandLine` (full command line)
- `User` (user context)
- `ProcessId`, `ParentProcessId` (process relationships)
- `DestinationIp`, `DestinationPort` (network connections)
- `TargetFilename` (file operations)
- `EventCode` (Sysmon Event ID: 1 = process creation, 3 = network connection, 11 = file creation)

**Note:** The member name (who was added to a group) in Event ID 4732 often requires `rex` extraction from `_raw` field, as it may not appear in extracted fields.

### Field Name Discovery Commands

**Quick Field Discovery:**
```spl
# See all fields for an event
index=windows_security EventCode=4625 | head 1 | table *

# Get field summary
index=windows_security EventCode=4625 | fieldsummary

# Extract from raw if needed
index=windows_security EventCode=4732 | rex field=_raw "Member:\s+Security ID:\s+(?<member_sid>[^\r\n]+)"
```

**Best Practice:** When adapting these playbooks to your environment, start by running `fieldsummary` on your actual data to verify field names before using the queries.

---

## 📊 Playbook Overview

We'll create playbooks for 5 incident types:

1. **Playbook 1: Brute Force Attack (Credential Access)**
   - MITRE ATT&CK: T1110 - Brute Force
   - Severity: Medium
   - Response Time: < 15 minutes (see [Response Time Targets](#-response-time-targets-sla))

2. **Playbook 2: Suspicious PowerShell Execution**
   - MITRE ATT&CK: T1059.001 - PowerShell
   - Severity: High
   - Response Time: < 10 minutes (see [Response Time Targets](#-response-time-targets-sla))

3. **Playbook 3: Privilege Escalation**
   - MITRE ATT&CK: T1078.002 - Local Accounts
   - Severity: Critical
   - Response Time: < 5 minutes (see [Response Time Targets](#-response-time-targets-sla))

4. **Playbook 4: Lateral Movement (SMB)**
   - MITRE ATT&CK: T1021.002 - SMB/Windows Admin Shares
   - Severity: High
   - Response Time: < 10 minutes (see [Response Time Targets](#-response-time-targets-sla))

5. **Playbook 5: Data Exfiltration**
   - MITRE ATT&CK: T1041 - Exfiltration Over C2 Channel
   - Severity: High (Critical if sensitive data confirmed)
   - Response Time: < 10 minutes (see [Response Time Targets](#-response-time-targets-sla))

---

## 🔴 Playbook 1: Brute Force Attack (Credential Access)

### MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Sub-Technique Name | Platforms | Permissions Required |
| ------ | ------------ | -------------- | ------------------ |---------- |--------------------- |
| Credential Access | T1110 | Brute Force | Password Spraying | Windows, Linux, Azure AD, Office 365 | User |

**Severity:** Medium  
**Response Time Target:** < 15 minutes  
**Alert Name:** "Brute Force Attack Detected"

---

### 1. Preparation

**Prerequisites and Readiness Measures:**

1. **Ensure logging is configured:**
   - Windows Event Logs forwarding to Splunk (Security and System logs)
   - Splunk Universal Forwarder running on Windows 10 VM
   - Verify logs are being received: `index=windows_security | head 10`

2. **Verify alerting is configured:**
   - Brute Force alert created in Splunk (Phase 6)
   - Alert threshold set to > 5 failed attempts
   - Summary index configured for alert logging

3. **Prepare tools and access:**
   - Admin access to Windows 10 VM (PowerShell)
   - Access to Splunk Web UI (`http://<Ubuntu_Server_IP>:8000`)
   - Network access to block IPs via firewall

4. **Security controls in place:**
   - Account lockout policy configured (if possible)
   - Firewall rules can be modified
   - RDP access controls documented

5. **Documentation ready:**
   - Incident tracking system/template
   - Contact information for escalation
   - Evidence collection procedures

---

### 2. Detection and Analysis

#### 2.1 Detection

**Alert Triggered:**
- **Alert Name:** Brute Force Attack Detected
- **Event ID:** 4625 (Failed logon attempt)
- **Threshold:** > 5 failed attempts from same IP
- **Time Range:** Last 5-15 minutes

**Manual Detection Query:**
```spl
index=windows_security EventCode=4625
| stats count by Account_Name, Source_Network_Address
| where count > 5
| sort -count
```

**What to Look For:**
- Multiple failed login attempts (Event ID 4625)
- Same source IP address
- Same or multiple target accounts
- Recent time window (last 5-15 minutes)
- Failed login attempts for default and common account names
- Failed login attempts for the same account across multiple systems
- Failed login attempts to multiple systems from the same source

#### 2.2 Analysis

**Step 1: Identify Attack Scope**

Determine the extent of the brute force attack:

```spl
index=windows_security EventCode=4625
| stats count, values(Account_Name) as targeted_accounts, 
         earliest(_time) as first_attempt, 
         latest(_time) as last_attempt 
  by Source_Network_Address
| eval duration_minutes=round((last_attempt - first_attempt)/60, 2)
| eval first_attempt_human=strftime(first_attempt, "%Y-%m-%d %H:%M:%S")
| eval last_attempt_human=strftime(last_attempt, "%Y-%m-%d %H:%M:%S")
| table Source_Network_Address, count, targeted_accounts, 
        first_attempt_human, last_attempt_human, duration_minutes
```

**Key Questions:**
- How many failed attempts occurred?
- What is the source IP address?
- Which accounts were targeted?
- How long has the attack been ongoing?

**Step 2: Check for Successful Logons**

**Critical:** Determine if the attack succeeded:

```spl
index=windows_security EventCode=4624 Source_Network_Address=<ATTACKER_IP>
| stats count by Account_Name, Logon_Type
| table Account_Name, Logon_Type, count
```

**If Event ID 4624 appears with the same source IP, the attack may have succeeded. Escalate immediately.**

**Step 3: Timeline Analysis**

Understand the attack pattern over time:

```spl
index=windows_security (EventCode=4625 OR EventCode=4624) Source_Network_Address=<ATTACKER_IP>
| eval event_type=case(EventCode=4624, "Successful Logon", EventCode=4625, "Failed Logon", 1=1, "Other")
| timechart count by event_type span=1m
```

**Step 4: Identify Target Accounts**

Determine which accounts are at highest risk:

```spl
index=windows_security EventCode=4625 Source_Network_Address=<ATTACKER_IP>
| stats count by Account_Name
| sort -count
| eval account_risk=case(count > 20, "HIGH", count > 10, "MEDIUM", 1=1, "LOW")
| table Account_Name, count, account_risk
```

**Step 5: Check Account Status**

**On Windows 10 VM (PowerShell as Administrator):**

```powershell
# Check if accounts are locked
Get-LocalUser | Where-Object {$_.Enabled -eq $true} | Select-Object Name, Enabled

# Check recent login attempts for specific account
Get-EventLog -LogName Security -InstanceId 4625 -Newest 50 | 
    Where-Object {$_.Message -like "*<ACCOUNT_NAME>*"}
```

**Step 6: Investigate All Associated Alerts**

- Review and clear ALL alerts associated with the impacted assets
- Check for related security events
- Document all findings

---

### 3. Containment

#### Immediate Actions (0-5 minutes)

1. **Block Source IP at Network Level**
   ```powershell
   # On Windows 10 VM (PowerShell as Administrator)
   New-NetFirewallRule -DisplayName "Block Brute Force IP" `
       -Direction Inbound -RemoteAddress <ATTACKER_IP> `
       -Action Block -Enabled True
   ```

2. **Enable Account Lockout (if not already enabled)**
   ```powershell
   # Check current lockout policy
   net accounts
   
   # Set lockout threshold (if needed)
   # Note: This requires Group Policy or local security policy
   ```

3. **Temporarily Disable RDP (if attack is ongoing)**
   ```powershell
   # Disable RDP
   Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
       -name "fDenyTSConnections" -Value 1
   ```

#### Short-term Containment (5-15 minutes)

1. **Review and Lock Compromised Accounts**
   ```powershell
   # Lock specific account
   net user <ACCOUNT_NAME> /active:no
   
   # Or disable account
   Disable-LocalUser -Name <ACCOUNT_NAME>
   ```

2. **Monitor for Continued Attempts**
   ```spl
   index=windows_security EventCode=4625 Source_Network_Address=<ATTACKER_IP>
   | stats count
   | eval status=if(count > 0, "ATTACK CONTINUING", "ATTACK STOPPED")
   ```

---

### 4. Eradication

**Plan eradication events** where these steps are launched together (or in coordinated fashion), with appropriate teams ready to respond to any disruption.

#### Step 1: Verify Attack Has Stopped
```spl
index=windows_security EventCode=4625 Source_Network_Address=<ATTACKER_IP>
| stats count
| where count = 0
```

#### Step 2: Document Attack Details
Create incident report with:
- Source IP address
- Target accounts
- Time range of attack
- Number of attempts
- Whether any logons succeeded

#### Step 3: Review Security Controls
- Verify firewall rules are in place
- Check account lockout policies
- Review RDP access controls

---

### 5. Recovery

#### Step 1: Restore RDP Access (if disabled)
```powershell
# Re-enable RDP (if it was disabled)
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
    -name "fDenyTSConnections" -Value 0
```

#### Step 2: Reset Affected Accounts
```powershell
# Reset password for affected account
net user <ACCOUNT_NAME> <NEW_STRONG_PASSWORD>

# Re-enable account (if it was disabled)
net user <ACCOUNT_NAME> /active:yes
```

#### Step 3: Monitor for Recurrence
```spl
index=windows_security EventCode=4625
| stats count by Source_Network_Address
| where count > 5
| sort -count
```

---

### 6. Post-Incident Activities

**Conduct post-incident review** to identify improvements and document lessons learned.

#### 6.1 Incident Documentation

Document the following:
- Incident ID and timeline
- Source IP address and target accounts
- Number of failed attempts
- Whether any logons succeeded
- Containment actions taken
- Eradication steps performed
- Recovery procedures executed
- Response time metrics (MTTD, MTTR, MTTC)

#### 6.2 Lessons Learned

**Detection Improvements:**
- [ ] Review alert threshold (is 5 attempts appropriate?)
- [ ] Consider adding geolocation checks
- [ ] Add correlation with successful logons
- [ ] Improve detection for password spraying patterns

**Prevention Measures:**
- [ ] Implement account lockout policy
- [ ] Enable MFA for RDP (if possible)
- [ ] Restrict RDP access to specific IPs
- [ ] Use strong password policies
- [ ] Patch asset vulnerabilities
- [ ] Perform routine inspections of controls
- [ ] Set up network segmentation and firewalls

**Response Improvements:**
- [ ] Document response time (MTTD, MTTR, MTTC)
- [ ] Review containment actions effectiveness
- [ ] Update playbook based on lessons learned
- [ ] Consider automating containment measures using orchestration tools

**Process Improvements:**
- [ ] Perform routine cyber hygiene due diligence
- [ ] Engage external cybersecurity-as-a-service providers if needed
- [ ] Update incident response plan based on findings

---

## 🔴 Playbook 2: Suspicious PowerShell Execution

### MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Sub-Technique Name | Platforms | Permissions Required |
| ------ | ------------ | -------------- | ------------------ |---------- |--------------------- |
| Execution | T1059.001 | Command and Scripting Interpreter | PowerShell | Windows | User |

**Severity:** High  
**Response Time Target:** < 10 minutes  
**Alert Name:** "Suspicious PowerShell Detection"

---

### 1. Preparation

**Prerequisites and Readiness Measures:**

1. **Ensure logging is configured:**
   - Sysmon installed and running on Windows 10 VM
   - Sysmon logs forwarding to Splunk (sysmon index)
   - Verify logs are being received: `index=sysmon | head 10`
   - PowerShell script block logging enabled (if possible)

2. **Verify alerting is configured:**
   - Suspicious PowerShell alert created in Splunk (Phase 6)
   - Alert configured to detect `-enc` parameter
   - Summary index configured for alert logging

3. **Prepare tools and access:**
   - Admin access to Windows 10 VM (PowerShell)
   - Access to Splunk Web UI (`http://<Ubuntu_Server_IP>:8000`)
   - Base64 decoding tools/scripts ready

4. **Security controls in place:**
   - PowerShell execution policy documented
   - Process monitoring via Sysmon
   - Network monitoring for suspicious connections

5. **Documentation ready:**
   - Incident tracking system/template
   - Contact information for escalation
   - Evidence collection procedures

---

### 2. Detection and Analysis

#### 2.1 Detection

**Alert Triggered:**
- **Alert Name:** Suspicious PowerShell Detection
- **Event ID:** 1 (Sysmon Process Creation)
- **Indicator:** Encoded PowerShell command (`-enc` parameter)
- **Time Range:** Real-time or last 5 minutes

**Manual Detection Query:**
```spl
index=sysmon EventCode=1 Image="*powershell.exe" CommandLine="*-enc*"
| table _time, User, Image, CommandLine, ProcessId, ParentProcessId
```

**What to Look For:**
- PowerShell process with `-enc` or `-encodedcommand` parameter
- Base64 encoded command line
- Unusual parent processes
- Execution from unusual locations
- PowerShell execution from non-standard paths

#### 2.2 Analysis

**Step 1: Decode the Command**

**Extract and decode the base64 command:**

```spl
index=sysmon EventCode=1 Image="*powershell.exe" CommandLine="*-enc*"
| rex field=CommandLine "-enc\s+(?<encoded_command>\S+)"
| eval decoded_command=base64decode(encoded_command)
| table _time, User, CommandLine, encoded_command, decoded_command
```

**Or manually decode in PowerShell:**
```powershell
# In PowerShell
$encoded = "SQBFAFgA"  # Example from scenario
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encoded))
```

**Key Questions:**
- What command was executed?
- What was the purpose of the command?
- Was it successful?

**Step 2: Identify Process Chain**

Understand how PowerShell was invoked:

```spl
index=sysmon EventCode=1 Image="*powershell.exe" CommandLine="*-enc*"
| eval process_chain=ParentImage." -> ".Image
| table _time, User, process_chain, CommandLine, ProcessId, ParentProcessId
```

**Step 3: Check for Network Connections**

Determine if the command established network connections:

```spl
index=sysmon EventCode=3 Image="*powershell.exe"
| join ProcessId [
    search index=sysmon EventCode=1 Image="*powershell.exe" CommandLine="*-enc*"
    | table ProcessId, CommandLine
]
| table _time, Image, SourceIp, DestinationIp, DestinationPort, Protocol
```

**Step 4: Check for File System Activity**

Identify files accessed or created:

```spl
index=sysmon EventCode=11 Image="*powershell.exe"
| join ProcessId [
    search index=sysmon EventCode=1 Image="*powershell.exe" CommandLine="*-enc*"
    | table ProcessId
]
| table _time, Image, TargetFilename
```

**Step 5: Identify User Context**

Determine who executed the command:

```spl
index=sysmon EventCode=1 Image="*powershell.exe" CommandLine="*-enc*"
| stats count, values(User) as users, values(CommandLine) as commands by Computer
| table Computer, users, commands, count
```

**Step 6: Investigate All Associated Alerts**

- Review and clear ALL alerts associated with the impacted assets
- Check for related security events
- Document all findings

---

### 3. Containment

**Plan containment events** where these steps are launched together (or in coordinated fashion), with appropriate teams ready to respond to any disruption. **Consider the timing and tradeoffs** of containment actions: your response has consequences.

#### 3.1 Immediate Containment (0-5 minutes)

1. **Terminate Suspicious PowerShell Process**
   ```powershell
   # On Windows 10 VM (PowerShell as Administrator)
   # Find the process
   Get-Process powershell | Where-Object {$_.CommandLine -like "*-enc*"}
   
   # Kill the process (replace <PID> with actual Process ID)
   Stop-Process -Id <PID> -Force
   ```

2. **Block PowerShell Execution (Temporary)**
   ```powershell
   # Set execution policy to Restricted (temporary measure)
   Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope Process -Force
   ```

3. **Isolate Affected System**
   - Consider disconnecting from network if data exfiltration is suspected

#### 3.2 Short-term Containment (5-15 minutes)

1. **Check for Persistence Mechanisms**
   ```powershell
   # Check startup programs
   Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location
   
   # Check scheduled tasks
   Get-ScheduledTask | Where-Object {$_.State -eq "Running"}
   
   # Check registry run keys
   Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
   Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
   ```

2. **Review Recent PowerShell History**
   ```powershell
   # Check PowerShell history
   Get-Content (Get-PSReadlineOption).HistorySavePath
   ```

---

### 4. Eradication

**Plan eradication events** where these steps are launched together (or in coordinated fashion), with appropriate teams ready to respond to any disruption.

#### Step 1: Analyze Decoded Command
- Determine what the command was attempting to do
- Check if any files were created/modified
- Verify if any network connections were established

#### Step 2: Remove Any Artifacts
```powershell
# If files were created, remove them
# (Replace with actual paths discovered during investigation)
Remove-Item -Path "<SUSPICIOUS_FILE_PATH>" -Force

# Check and remove registry entries if created
# (Based on investigation findings)
```

#### Step 3: Verify System Integrity
```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| stats count by User, CommandLine
| where CommandLine="*-enc*"
| eval status=if(count > 0, "STILL ACTIVE", "CLEANED")
```

---

### 5. Recovery

#### Step 1: Restore PowerShell Execution Policy
```powershell
# Restore to previous execution policy (if changed)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
```

#### Step 2: Monitor for Recurrence
```spl
index=sysmon EventCode=1 Image="*powershell.exe" CommandLine="*-enc*"
| stats count
| eval status=if(count > 0, "DETECTED", "CLEAN")
```

#### Step 3: Review Logging Configuration
- Verify Sysmon is still running
- Check Splunk forwarder is collecting logs
- Ensure PowerShell logging is enabled

---

### 6. Post-Incident Activities

**Conduct post-incident review** to identify improvements and document lessons learned.

#### 6.1 Incident Documentation

Document the following:
- Incident ID and timeline
- Decoded PowerShell command
- Process chain and parent process
- Network connections established
- Files accessed or created
- User context
- Containment actions taken
- Eradication steps performed
- Recovery procedures executed
- Response time metrics (MTTD, MTTR, MTTC)

#### 6.2 Lessons Learned

**Detection Improvements:**
- [ ] Add detection for other PowerShell obfuscation techniques
- [ ] Correlate with network connections
- [ ] Add parent process analysis
- [ ] Improve detection for encoded commands

**Prevention Measures:**
- [ ] Implement PowerShell constrained language mode
- [ ] Enable PowerShell script block logging
- [ ] Use application whitelisting
- [ ] Monitor PowerShell execution from unusual locations
- [ ] Patch asset vulnerabilities
- [ ] Perform routine inspections of controls

**Response Improvements:**
- [ ] Create automated script to decode base64 commands
- [ ] Document common PowerShell attack patterns
- [ ] Improve process chain analysis
- [ ] Document response time (MTTD, MTTR, MTTC)
- [ ] Consider automating containment measures using orchestration tools

**Process Improvements:**
- [ ] Perform routine cyber hygiene due diligence
- [ ] Engage external cybersecurity-as-a-service providers if needed
- [ ] Update incident response plan based on findings

---

## 🔴 Playbook 3: Privilege Escalation

### MITRE ATT&CK Mapping
- **Technique:** T1078.002 - Local Accounts
- **Tactic:** Privilege Escalation, Persistence
- **Severity:** Critical
- **Alert:** "Privilege Escalation Detection"

---

### 1. Detection

#### Alert Triggered
- **Alert Name:** Privilege Escalation Detection
- **Event ID:** 4732 (Member added to security-enabled local group)
- **Alternative Event ID:** 4728 (Member added to global group)
- **Critical:** This is a real-time alert

#### Manual Detection Query
```spl
index=windows_security (EventCode=4732 OR EventCode=4728)
| table _time, SubjectUserName, MemberName, TargetUserName, GroupName
```

#### What to Look For
- User added to Administrators group
- User added to Domain Admins (if applicable)
- Unauthorized privilege changes
- Changes outside of maintenance windows

---

### 2. Investigation

#### Step 1: Identify the Change
```spl
index=windows_security (EventCode=4732 OR EventCode=4728)
| eval change_type=case(EventCode=4732, "Local Group", EventCode=4728, "Global Group", 1=1, "Other")
| table _time, SubjectUserName, MemberName, TargetUserName, GroupName, change_type
```

#### Step 2: Check Who Made the Change
```spl
index=windows_security (EventCode=4732 OR EventCode=4728)
| stats count, values(SubjectUserName) as who_changed, 
         values(SubjectDomainName) as source_domain
  by MemberName, GroupName
| table MemberName, GroupName, who_changed, source_domain, count
```

#### Step 3: Verify Current Group Membership
**On Windows 10 VM (PowerShell as Administrator):**
```powershell
# Check current administrators group membership
Get-LocalGroupMember -Group "Administrators" | 
    Select-Object Name, PrincipalSource, ObjectClass

# Check if the user is still in the group
Get-LocalGroupMember -Group "Administrators" | 
    Where-Object {$_.Name -like "*<USERNAME>*"}
```

#### Step 4: Timeline Analysis
```spl
index=windows_security (EventCode=4732 OR EventCode=4728 OR EventCode=4624)
| eval event_type=case(EventCode=4732, "Privilege Escalation", 
                      EventCode=4728, "Group Membership Change",
                      EventCode=4624, "Logon", 1=1, "Other")
| timechart count by event_type span=5m
```

#### Step 5: Check for Related Activity
```spl
index=windows_security (EventCode=4732 OR EventCode=4728)
| eval target_user=MemberName
| join type=outer target_user [
    search index=windows_security EventCode=4624
    | eval target_user=Account_Name
    | stats count, values(Logon_Type) as logon_types by target_user
]
| table _time, MemberName, GroupName, SubjectUserName, count, logon_types
```

---

### 3. Containment

#### Immediate Actions (0-5 minutes)

1. **Remove User from Administrators Group**
   ```powershell
   # On Windows 10 VM (PowerShell as Administrator)
   # Remove user from Administrators group
   net localgroup administrators <USERNAME> /delete
   
   # Verify removal
   Get-LocalGroupMember -Group "Administrators" | 
       Where-Object {$_.Name -like "*<USERNAME>*"}
   ```

2. **Disable the Compromised Account**
   ```powershell
   # Disable the account immediately
   Disable-LocalUser -Name <USERNAME>
   
   # Or lock the account
   net user <USERNAME> /active:no
   ```

3. **Check for Active Sessions**
   ```powershell
   # Check for active RDP sessions
   query session
   
   # Check for active user sessions
   Get-CimInstance Win32_LogonSession | 
       Where-Object {$_.LogonType -eq 10} | 
       Select-Object LogonId, AuthenticationPackage
   ```

#### Short-term Containment (5-15 minutes)

1. **Review All Recent Privilege Changes**
   ```spl
   index=windows_security (EventCode=4732 OR EventCode=4728)
   | stats count by MemberName, GroupName
   | sort -count
   ```

2. **Check for Backdoor Accounts**
   ```powershell
   # List all local users
   Get-LocalUser | Select-Object Name, Enabled, LastLogon
   
   # Check for recently created accounts
   Get-LocalUser | Where-Object {$_.Enabled -eq $true} | 
       Select-Object Name, Enabled, Description
   ```

3. **Monitor for Continued Activity**
   ```spl
   index=windows_security EventCode=4624 Account_Name=<USERNAME>
   | stats count
   | eval status=if(count > 0, "ACTIVE", "INACTIVE")
   ```

---

### 4. Eradication

#### Step 1: Investigate How Privilege Escalation Occurred
```spl
index=windows_security (EventCode=4732 OR EventCode=4728)
| eval who=SubjectUserName
| join type=outer who [
    search index=windows_security EventCode=4624
    | eval who=Account_Name
    | stats count, values(Logon_Type) as logon_types, 
             earliest(_time) as first_logon by who
]
| table _time, SubjectUserName, MemberName, GroupName, 
        first_logon, logon_types
```

#### Step 2: Check for Persistence Mechanisms
```powershell
# Check scheduled tasks created by the user
Get-ScheduledTask | Where-Object {$_.Principal.UserId -like "*<USERNAME>*"}

# Check services
Get-Service | Where-Object {$_.StartName -like "*<USERNAME>*"}

# Check startup programs
Get-CimInstance Win32_StartupCommand | 
    Where-Object {$_.User -like "*<USERNAME>*"}
```

#### Step 3: Review Security Logs for Initial Compromise
```spl
index=windows_security EventCode=4624 Account_Name=<USERNAME>
| stats count, values(Logon_Type) as logon_types, 
         values(Source_Network_Address) as source_ips
  by Account_Name
| table Account_Name, logon_types, source_ips, count
```

---

### 5. Recovery

#### Step 1: Verify User Removed from Group
```powershell
# Confirm user is no longer in Administrators group
Get-LocalGroupMember -Group "Administrators" | 
    Select-Object Name | 
    Where-Object {$_.Name -like "*<USERNAME>*"}
# Should return nothing
```

#### Step 2: Reset Account Password (if account is kept)
```powershell
# Reset password with strong password
net user <USERNAME> <NEW_STRONG_PASSWORD>

# Re-enable account if needed (after password reset)
Enable-LocalUser -Name <USERNAME>
```

#### Step 3: Review Group Membership Policies
- Verify who has permission to modify group membership
- Review audit policies for group changes
- Consider implementing approval workflows

#### Step 4: Monitor for Recurrence
```spl
index=windows_security (EventCode=4732 OR EventCode=4728)
| stats count by MemberName, GroupName
| where GroupName="*Administrators*"
| eval status=if(count > 0, "DETECTED", "CLEAN")
```

---

### 6. Lessons Learned

#### Detection Improvements
- [ ] Ensure real-time alerting for privilege escalation
- [ ] Add correlation with account creation events
- [ ] Monitor for privilege changes outside business hours

#### Prevention Measures
- [ ] Implement least privilege principle
- [ ] Require approval workflow for admin group changes
- [ ] Enable detailed auditing for group membership changes
- [ ] Regular review of administrator group membership

#### Response Improvements
- [ ] Document response time (should be < 5 minutes for critical)
- [ ] Create automated script to remove users from groups
- [ ] Improve investigation queries for privilege escalation chains

---

## 🔴 Playbook 4: Lateral Movement (SMB)

### MITRE ATT&CK Mapping
- **Technique:** T1021.002 - SMB/Windows Admin Shares
- **Tactic:** Lateral Movement
- **Severity:** High
- **Alert:** "Lateral Movement Detection (SMB)"

---

### 1. Detection

#### Alert Triggered
- **Alert Name:** Lateral Movement Detection (SMB)
- **Event ID:** 4624 (Successful logon)
- **Logon Type:** 3 (Network logon)
- **Threshold:** Multiple logons from same IP

#### Manual Detection Query
```spl
index=windows_security EventCode=4624 Logon_Type=3
| stats count by Source_Network_Address, Account_Name
| where count > 3
| sort -count
```

#### What to Look For
- Multiple network logons (Logon Type 3) from same source IP
- SMB share access (C$, ADMIN$, IPC$)
- Unusual source IP addresses
- Access outside normal business hours

---

### 2. Investigation

#### Step 1: Identify Lateral Movement Activity
```spl
index=windows_security EventCode=4624 Logon_Type=3
| stats count, values(Account_Name) as accounts, 
         values(Workstation_Name) as workstations,
         earliest(_time) as first_logon, 
         latest(_time) as last_logon
  by Source_Network_Address
| eval duration_minutes=round((last_logon - first_logon)/60, 2)
| where count > 3
| sort -count
```

#### Step 2: Check What Shares Were Accessed
```spl
index=windows_security EventCode=5145
| join type=outer Source_Network_Address [
    search index=windows_security EventCode=4624 Logon_Type=3
    | eval Source_Network_Address=Source_Network_Address
    | table Source_Network_Address, Account_Name
]
| stats count, values(Share_Name) as shares_accessed by Account_Name, Source_Network_Address
| table Account_Name, Source_Network_Address, shares_accessed, count
```

#### Step 3: Identify Source System
```spl
index=windows_security EventCode=4624 Logon_Type=3
| stats count by Source_Network_Address, Workstation_Name
| table Source_Network_Address, Workstation_Name, count
```

#### Step 4: Check for File Access
```spl
index=sysmon EventCode=11 Image="*smb*" OR Image="*\\*"
| join ProcessId [
    search index=windows_security EventCode=4624 Logon_Type=3
    | eval source_ip=Source_Network_Address
    | table source_ip, Account_Name
]
| stats count, values(TargetFilename) as files_accessed by Account_Name
| table Account_Name, files_accessed, count
```

#### Step 5: Timeline Analysis
```spl
index=windows_security EventCode=4624 Logon_Type=3 Source_Network_Address=<ATTACKER_IP>
| timechart count by Account_Name span=5m
```

---

### 3. Containment

#### Immediate Actions (0-5 minutes)

1. **Block Source IP**
   ```powershell
   # On Windows 10 VM (PowerShell as Administrator)
   New-NetFirewallRule -DisplayName "Block Lateral Movement IP" `
       -Direction Inbound -RemoteAddress <ATTACKER_IP> `
       -Action Block -Enabled True
   ```

2. **Disable SMB Shares (Temporary)**
   ```powershell
   # Disable SMB Server (if not needed)
   Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
   
   # Or stop SMB service (more aggressive)
   Stop-Service LanmanServer
   Set-Service LanmanServer -StartupType Disabled
   ```

3. **Disconnect Active Sessions**
   ```powershell
   # List SMB sessions
   Get-SmbSession
   
   # Close specific session (replace <SessionId>)
   Close-SmbSession -SessionId <SessionId> -Force
   ```

#### Short-term Containment (5-15 minutes)

1. **Review Account Access**
   ```powershell
   # Check if account should have SMB access
   Get-SmbShareAccess -Name "C$" | Select-Object AccountName, AccessRight
   ```

2. **Monitor for Continued Access**
   ```spl
   index=windows_security EventCode=4624 Logon_Type=3 Source_Network_Address=<ATTACKER_IP>
   | stats count
   | eval status=if(count > 0, "ACTIVE", "BLOCKED")
   ```

---

### 4. Eradication

#### Step 1: Identify Initial Compromise
```spl
index=windows_security (EventCode=4624 OR EventCode=4625) Source_Network_Address=<ATTACKER_IP>
| eval event_type=case(EventCode=4624, "Successful", EventCode=4625, "Failed", 1=1, "Other")
| stats count, values(Account_Name) as accounts by event_type
| table event_type, accounts, count
```

#### Step 2: Review What Was Accessed
```spl
index=sysmon EventCode=11
| join ProcessId [
    search index=windows_security EventCode=4624 Logon_Type=3 Source_Network_Address=<ATTACKER_IP>
    | eval account=Account_Name
    | table account
]
| stats count, values(TargetFilename) as files by account
| table account, files, count
```

#### Step 3: Check for Data Exfiltration
```spl
index=sysmon EventCode=3 Image="*smb*" OR DestinationIp=<ATTACKER_IP>
| stats count, values(DestinationPort) as ports by Image, DestinationIp
| table Image, DestinationIp, ports, count
```

---

### 5. Recovery

#### Step 1: Restore SMB Access (if disabled)
```powershell
# Re-enable SMB Server (if it was disabled)
Start-Service LanmanServer
Set-Service LanmanServer -StartupType Automatic
```

#### Step 2: Review SMB Share Permissions
```powershell
# Review administrative share permissions
Get-SmbShareAccess -Name "C$" | Format-Table
Get-SmbShareAccess -Name "ADMIN$" | Format-Table

# Restrict access if needed
Revoke-SmbShareAccess -Name "C$" -AccountName <UNAUTHORIZED_USER> -Force
```

#### Step 3: Reset Compromised Account Credentials
```powershell
# Reset password for account used in lateral movement
net user <ACCOUNT_NAME> <NEW_STRONG_PASSWORD>
```

#### Step 4: Monitor for Recurrence
```spl
index=windows_security EventCode=4624 Logon_Type=3
| stats count by Source_Network_Address
| where count > 3
| sort -count
```

---

### 6. Lessons Learned

#### Detection Improvements
- [ ] Add detection for specific share access (C$, ADMIN$)
- [ ] Correlate with file access events
- [ ] Monitor for lateral movement patterns

#### Prevention Measures
- [ ] Disable unnecessary SMB shares
- [ ] Restrict administrative share access
- [ ] Implement network segmentation
- [ ] Use strong authentication for SMB

#### Response Improvements
- [ ] Create automated script to block lateral movement IPs
- [ ] Improve share access monitoring
- [ ] Document lateral movement patterns

---

## 🔴 Playbook 5: Data Exfiltration

### MITRE ATT&CK Mapping
- **Technique:** T1041 - Exfiltration Over C2 Channel
- **Tactic:** Exfiltration
- **Severity:** Critical
- **Alert:** "Data Exfiltration Detection"

---

### 1. Detection

#### Alert Triggered
- **Alert Name:** Data Exfiltration Detection
- **Event ID:** 3 (Sysmon Network Connection)
- **Indicator:** Suspicious outbound connections to non-standard ports

#### Manual Detection Query
```spl
index=sysmon EventCode=3
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443
| stats count by Image, DestinationIp, DestinationPort
| sort -count
```

#### What to Look For
- Outbound connections to unusual ports
- Connections to external IPs
- Large data transfers
- Connections from suspicious processes

---

### 2. Investigation

#### Step 1: Identify Exfiltration Activity
```spl
index=sysmon EventCode=3
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443
| eval is_suspicious=case(DestinationPort < 1024 AND DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443, "HIGH",
                          DestinationPort > 49152, "MEDIUM", 1=1, "LOW")
| stats count, values(DestinationPort) as ports, 
         values(DestinationIp) as destination_ips
  by Image, is_suspicious
| where count > 5
| sort -count
```

#### Step 2: Identify Source Process
```spl
index=sysmon EventCode=3
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443
| join ProcessId [
    search index=sysmon EventCode=1
    | table ProcessId, Image, CommandLine, User, ParentImage
]
| table _time, Image, CommandLine, User, ParentImage, DestinationIp, DestinationPort, Protocol
```

#### Step 3: Check Data Volume
```spl
index=sysmon EventCode=3
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443
| stats count, sum(SentBytes) as total_sent, 
         sum(ReceivedBytes) as total_received
  by Image, DestinationIp, DestinationPort
| eval total_mb=round((total_sent + total_received)/1048576, 2)
| sort -total_mb
```

#### Step 4: Timeline Analysis
```spl
index=sysmon EventCode=3
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443
| timechart count by DestinationIp span=5m
```

#### Step 5: Check for File Access Before Exfiltration
```spl
index=sysmon EventCode=11
| join ProcessId [
    search index=sysmon EventCode=3
    | where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443
    | eval exfil_process=Image
    | table ProcessId, exfil_process, DestinationIp
]
| stats count, values(TargetFilename) as files_accessed by exfil_process
| table exfil_process, files_accessed, count
```

---

### 3. Containment

#### Immediate Actions (0-5 minutes)

1. **Block Outbound Connection**
   ```powershell
   # On Windows 10 VM (PowerShell as Administrator)
   # Block outbound connection to destination IP
   New-NetFirewallRule -DisplayName "Block Exfiltration IP" `
       -Direction Outbound -RemoteAddress <DESTINATION_IP> `
       -Action Block -Enabled True
   ```

2. **Terminate Suspicious Process**
   ```powershell
   # Find and terminate the process
   Get-Process | Where-Object {$_.ProcessName -like "*<PROCESS_NAME>*"}
   Stop-Process -Name <PROCESS_NAME> -Force
   ```

3. **Isolate System from Network**
   ```powershell
   # Disable network adapter (if critical data exfiltration)
   Disable-NetAdapter -Name "Ethernet" -Confirm:$false
   ```

#### Short-term Containment (5-15 minutes)

1. **Monitor for Continued Exfiltration**
   ```spl
   index=sysmon EventCode=3 DestinationIp=<DESTINATION_IP>
   | stats count
   | eval status=if(count > 0, "CONTINUING", "BLOCKED")
   ```

2. **Check for Multiple Exfiltration Attempts**
   ```spl
   index=sysmon EventCode=3
   | where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443
   | stats count by DestinationIp
   | where count > 10
   ```

---

### 4. Eradication

#### Step 1: Identify What Data Was Exfiltrated
```spl
index=sysmon EventCode=11
| join ProcessId [
    search index=sysmon EventCode=3 DestinationIp=<DESTINATION_IP>
    | eval exfil_process=Image
    | table ProcessId, exfil_process
]
| stats count, values(TargetFilename) as files by exfil_process
| table exfil_process, files, count
```

#### Step 2: Check Data Volume Exfiltrated
```spl
index=sysmon EventCode=3 DestinationIp=<DESTINATION_IP>
| stats sum(SentBytes) as total_bytes_sent
| eval total_mb=round(total_bytes_sent/1048576, 2)
| eval total_gb=round(total_bytes_sent/1073741824, 2)
| table total_bytes_sent, total_mb, total_gb
```

#### Step 3: Identify Initial Compromise Vector
```spl
index=sysmon EventCode=1 Image="*<PROCESS_NAME>*"
| table _time, User, Image, CommandLine, ParentImage, ProcessId
| sort _time
```

---

### 5. Recovery

#### Step 1: Restore Network Connectivity (if disabled)
```powershell
# Re-enable network adapter
Enable-NetAdapter -Name "Ethernet" -Confirm:$false
```

#### Step 2: Remove Firewall Rule (if blocking legitimate traffic)
```powershell
# Remove the blocking rule (if no longer needed)
Remove-NetFirewallRule -DisplayName "Block Exfiltration IP"
```

#### Step 3: Review and Secure Data
- Identify what data was potentially exfiltrated
- Determine if data breach notification is required
- Review access controls on sensitive data

#### Step 4: Monitor for Recurrence
```spl
index=sysmon EventCode=3
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443
| stats count by DestinationIp
| where count > 5
| sort -count
```

---

### 6. Lessons Learned

#### Detection Improvements
- [ ] Add detection for large data transfers
- [ ] Monitor for connections to known C2 IPs
- [ ] Correlate file access with network connections

#### Prevention Measures
- [ ] Implement data loss prevention (DLP)
- [ ] Restrict outbound network connections
- [ ] Monitor for unusual data access patterns
- [ ] Encrypt sensitive data at rest

#### Response Improvements
- [ ] Create automated script to block exfiltration IPs
- [ ] Improve data volume monitoring
- [ ] Document exfiltration patterns and indicators

---

## ✅ General Incident Response Checklist

### For All Incidents

- [ ] Document incident ID and timestamp
- [ ] Assign severity level (Critical/High/Medium/Low)
- [ ] Notify stakeholders (if required)
- [ ] Preserve evidence (logs, screenshots)
- [ ] Document all actions taken
- [ ] Update incident tracking system
- [ ] Conduct post-incident review
- [ ] Update playbooks based on lessons learned

---

## 📝 Incident Documentation Template

### Incident Report Fields

```
Incident ID: [AUTO-GENERATED]
Date/Time Detected: [TIMESTAMP]
Date/Time Contained: [TIMESTAMP]
Severity: [Critical/High/Medium/Low]
Status: [Open/Contained/Resolved/Closed]

Attack Type: [Brute Force/PowerShell/Privilege Escalation/Lateral Movement/Exfiltration]
MITRE ATT&CK: [TECHNIQUE_ID]

Source IP: [IP_ADDRESS]
Target System: [SYSTEM_NAME]
Affected Accounts: [ACCOUNT_NAMES]

Detection Method: [Alert/Manual Search/Other]
Alert Name: [ALERT_NAME]

Timeline:
- [TIME] - Incident detected
- [TIME] - Investigation started
- [TIME] - Containment actions taken
- [TIME] - Eradication completed
- [TIME] - Recovery completed

Actions Taken:
1. [ACTION 1]
2. [ACTION 2]
3. [ACTION 3]

Impact Assessment:
- Systems Affected: [LIST]
- Data Compromised: [YES/NO/DETAILS]
- Business Impact: [DESCRIPTION]

Lessons Learned:
- [LESSON 1]
- [LESSON 2]
- [LESSON 3]

Follow-up Actions:
- [ACTION 1]
- [ACTION 2]
```

---

## 🎯 Next Steps After Phase 8

Once all playbooks are documented and tested:

1. **Practice Scenarios:** Execute attacks and follow playbooks step-by-step
2. **Refine Playbooks:** Update based on actual response experience
3. **Create Runbooks:** Convert playbooks to quick-reference guides
4. **Portfolio Documentation:** Include playbooks in your GitHub repo
5. **Interview Preparation:** Be ready to discuss incident response procedures

---

## 🐛 Troubleshooting

### Playbook Not Working?

1. **Verify Event IDs Match Your Environment**
   - Use `fieldsummary` to verify field names
   - Check if Event IDs are correct for your Windows version

2. **Check Splunk Index Configuration**
   - Verify indexes are receiving data
   - Check time ranges in queries

3. **Test Queries Manually**
   - Run each query in Splunk before following playbook
   - Adjust field names if needed

### Need to Customize Playbooks?

- Adapt queries to your environment
- Add organization-specific steps
- Include additional tools (EDR, network monitoring)
- Add escalation procedures

---

Good luck with your incident response! 🚀

