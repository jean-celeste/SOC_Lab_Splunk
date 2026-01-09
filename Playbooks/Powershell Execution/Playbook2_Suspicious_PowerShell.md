# 🔴 Playbook 2: Suspicious PowerShell Execution (Execution)

> **Note:** This playbook was created as part of my SOC lab learning project. I researched NIST SP 800-61 framework and industry best practices, then adapted them for my home lab environment. Some queries were refined through trial and error - I've noted where I encountered issues and how I resolved them.

### MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Sub-Technique Name | Platforms | Permissions Required |
| ------ | ------------ | -------------- | ------------------ |---------- |--------------------- |
| Execution | T1059.001 | Command and Scripting Interpreter | PowerShell | Windows | User |

> **Note on Platforms:** In my lab, the suspicious PowerShell execution occurs on Windows 10 VM. The attack uses encoded PowerShell commands (`-enc` flag) to obfuscate malicious activity. This technique is executed against Windows, requiring user-level permissions to run PowerShell commands.

**Severity:** High  
**Response Time Target:** < 10 minutes (see [Response Time Targets](../../Phase8_Incident_Response_Playbooks.md#-response-time-targets-sla))  
**Alert Name:** "Suspicious PowerShell Execution Detected"  
**Attack Vector:** Encoded PowerShell commands executed on Windows 10 (192.168.1.5) using base64-encoded strings to obfuscate malicious commands (e.g., (iex) `powershell -enc SQBFAFgA`)

> **Severity Justification:** Attack technique indicates execution of obfuscated commands. Attack status: in progress. Target: Windows 10 endpoint. Impact: High - PowerShell execution with obfuscation indicates potential malware execution, data exfiltration, or lateral movement. Encoded commands bypass basic signature detection and require immediate investigation. This represents a confidentiality, integrity, and availability risk as obfuscated execution can lead to system compromise, data theft, or further attack progression.

### Related Playbooks

**If PowerShell making network connections to non-standard ports:**
- → **Playbook 5: Data Exfiltration** - Check for outbound connections (Event ID 3) to suspicious destinations

**If privilege escalation detected:**
- → **Playbook 3: Privilege Escalation** - Monitor for admin group changes (Event ID 4732/4728)

**If network logons detected following PowerShell execution:**
- → **Playbook 4: Lateral Movement (SMB)** - Check for SMB access and lateral movement activity

**If initial access via brute force:**
- → **Playbook 1: Brute Force Attack** - Review credential access attempts (Event ID 4625)

---

### 1. Preparation

**Prerequisites and Readiness Measures:**

1. **Ensure logging is configured:**
   - Sysmon installed and running on Windows 10 VM
   - Sysmon operational logs forwarding to Splunk
   - Splunk Universal Forwarder running on Windows 10 VM
   - Verify logs are being received: `index=sysmon EventCode=1 | head 10`

2. **Verify alerting is configured:**
   - Suspicious PowerShell alert created in Splunk
   - Alert threshold set to detect any encoded PowerShell execution
   - Summary index configured for alert logging

3. **Prepare tools and access:**
   - Ubuntu server to host Splunk Web UI
   - Admin access to Windows 10 VM (PowerShell)
   - Access to Splunk Web UI ( `<Ubuntu_IP:8000>` OR `http://192.168.1.7:8000`)
   - Ability to investigate process trees and command lines

4. **Security controls in place:**
   - Sysmon monitoring process creation
   - PowerShell logging enabled
   - Script execution policies documented
   - Endpoint detection capabilities

5. **Documentation ready:**
   - Incident tracking system/template
   - Contact information for escalation
   - Evidence collection procedures

---

### 2. Detection and Analysis

#### 2.1 Detection

**Alert Triggered:**
- **Alert Name:** Suspicious PowerShell Execution Detected
- **Event ID:** 1 (Sysmon Process Creation)
- **Threshold:** Any PowerShell execution with `-enc` parameter or suspicious patterns
- **Time Range:** Last 5 minutes

**Manual Detection Query:**
```spl
index=sysmon EventCode=1 Image="*powershell.exe" CommandLine="*-enc*"
| stats count by Image, CommandLine, User
| where count > 0
```

> **Learning Note:** Initially, I had to verify that Sysmon was capturing the full command line, including encoded parameters. The `CommandLine` field in Sysmon Event ID 1 contains the complete command, even when base64-encoded. Always verify Sysmon is properly configured to capture command-line arguments.

> **Note:** Field names may vary in your environment. See [Field Naming and Extraction](../../Phase8_Incident_Response_Playbooks.md#-field-naming-and-extraction) for guidance on verifying field names using `fieldsummary`.

**What to Look For:**
- PowerShell process creation (Event ID 1)
- CommandLine field containing `-enc` or `-EncodedCommand` flags
- Base64-encoded strings in command line
- Suspicious patterns: `download`, `invoke`, `webrequest`, `hidden`, `noprofile`
- Unusual parent processes launching PowerShell
- PowerShell executed from non-standard locations
- Multiple PowerShell instances in short time period

#### 2.2 Analysis

**Step 1: Identify Attack Scope**

Determine the extent of the suspicious PowerShell activity:

```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| stats count, values(CommandLine) as commands, earliest(_time) as first_seen, latest(_time) as last_seen by User, host
| eval duration=round((last_seen - first_seen)/60, 2)
| convert ctime(first_seen) ctime(last_seen)
| sort -count
```

**This query provides:**
- User accounts executing PowerShell
- Number of PowerShell executions per user
- Command lines executed
- Timeline of PowerShell activity
- Duration of activity
- Host(s) affected

**Key Questions:**
- How many suspicious PowerShell executions occurred?
- Which user accounts are involved?
- What commands were executed?
- How long has this activity been ongoing?
- Are there patterns indicating automated execution?

**Step 2: Check for Encoded Commands**

**Critical:** Identify obfuscated PowerShell commands:

```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| where CommandLine LIKE "%-enc%" OR CommandLine LIKE "%-EncodedCommand%"
| stats count, values(CommandLine) as encoded_commands, values(User) as users by host
| table host, count, users, encoded_commands
| sort -count
```

**If encoded commands are detected, this indicates deliberate obfuscation. Escalate immediately.**

**Escalation Criteria:**
- ✅ **If PowerShell making connections to non-standard ports:** Immediately refer to **Playbook 5: Data Exfiltration** - check for outbound connections (Event ID 3) to suspicious destinations
- ✅ **If privilege escalation detected (Event ID 4732/4728):** Immediately refer to **Playbook 3: Privilege Escalation** - administrative access equals complete system compromise
- ✅ **If network logons detected following PowerShell execution:** Refer to **Playbook 4: Lateral Movement (SMB)** to check for SMB access and lateral movement activity
- ✅ **If initial access via brute force suspected:** Refer to **Playbook 1: Brute Force Attack** to review credential access attempts (Event ID 4625)

**Step 3: Analyze Command Patterns**

Understand what the PowerShell commands are attempting to do:

```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| eval suspicious_pattern=case(
    lower(CommandLine) LIKE "%enc%", "Encoded Command",
    lower(CommandLine) LIKE "%download%", "Download Activity",
    lower(CommandLine) LIKE "%invoke%", "Invoke Command",
    lower(CommandLine) LIKE "%webrequest%", "Web Request",
    lower(CommandLine) LIKE "%hidden%", "Hidden Execution",
    lower(CommandLine) LIKE "%noprofile%", "No Profile",
    1=1, "Other"
)
| stats count by suspicious_pattern, User
| sort -count
```

**Step 4: Examine Process Tree**

Determine what launched PowerShell and the execution chain:

```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| where CommandLine LIKE "%-enc%" OR CommandLine LIKE "%download%" OR CommandLine LIKE "%invoke%"
| table _time, Image, CommandLine, ParentImage, ParentCommandLine, User
| sort -_time
```

**This helps identify:**
- Parent process that launched PowerShell
- Full execution chain
- User context
- Timeline of events

**Step 5: Check for Network Activity**

Determine if PowerShell is making network connections:

```spl
index=sysmon EventCode=3 Image="*powershell.exe"
| stats count, values(DestinationIp) as dest_ips, values(DestinationPort) as dest_ports by User
| where count > 0
| table User, count, dest_ips, dest_ports
```

**If PowerShell is making network connections, this may indicate data exfiltration or C2 communication.**

**Step 6: Investigate All Associated Alerts**

- Review and clear ALL alerts associated with the impacted assets
- Check for related security events (network connections, file writes)
- Document all findings

---

### 3. Containment

**Plan containment events** where these steps are launched together (or in coordinated fashion), with appropriate teams ready to respond to any disruption. **Consider the timing and tradeoffs** of containment actions: your response has consequences.

#### 3.1 Immediate Containment (0-5 minutes)

1. **Terminate Suspicious PowerShell Processes**
   ```powershell
   # On Windows 10 VM (PowerShell as Administrator)
   # Find PowerShell processes with encoded commands
   # Note: Get-Process doesn't show CommandLine, use Get-CimInstance instead
   Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" | 
       Where-Object {$_.CommandLine -like "*-enc*"} | 
       Select-Object ProcessId, CommandLine
   
   # Terminate specific process (replace <PID> with actual process ID from above)
   Stop-Process -Id <PID> -Force
   
   # Alternative: Terminate all PowerShell processes with encoded commands at once
   Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" | 
       Where-Object {$_.CommandLine -like "*-enc*"} | 
       ForEach-Object {Stop-Process -Id $_.ProcessId -Force}
   ```

2. **Block Network Connections (if PowerShell is making connections)**
   ```powershell
   # Block outbound connections from PowerShell to specific IP
   New-NetFirewallRule -DisplayName "Block PowerShell Outbound" `
       -Direction Outbound -Program "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
       -Action Block -Enabled True
   ```

3. **Disable PowerShell Execution (if attack is ongoing)**
   ```powershell
   # Disable PowerShell execution via Group Policy (requires GPO)
   # OR restrict PowerShell execution policy
   Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine -Force
   ```
   
   > **Limitation:** In my home lab, I can restrict execution policy, but in production environments, this may impact legitimate PowerShell usage. Consider the business impact before disabling PowerShell entirely.

#### 3.2 Short-term Containment (5-15 minutes)

1. **Isolate Affected User Account**
   ```powershell
   # Disable user account if compromised
   Disable-LocalUser -Name <USERNAME>
   
   # Or lock the account
   net user <USERNAME> /active:no
   ```

2. **Monitor for Continued Activity**
   ```spl
   index=sysmon EventCode=1 Image="*powershell.exe" earliest=-2m@m
   | where CommandLine LIKE "%-enc%" OR CommandLine LIKE "%download%" OR CommandLine LIKE "%invoke%"
   | stats count
   | eval status=if(count > 0, "ACTIVITY CONTINUING", "ACTIVITY STOPPED")
   | table status, count
   ```

3. **Collect Evidence**
   ```powershell
   # Export PowerShell execution history
   Get-History | Export-Csv -Path "C:\temp\powershell_history.csv"
   
   # Check PowerShell transcript logs (if enabled)
   Get-ChildItem -Path "$env:USERPROFILE\Documents" -Filter "PowerShell_transcript*"
   ```

---

### 4. Eradication

**Plan eradication events** where these steps are launched together (or in coordinated fashion), with appropriate teams ready to respond to any disruption.

#### Step 1: Verify Activity Has Stopped
```spl
index=sysmon EventCode=1 Image="*powershell.exe" earliest=-2m@m
| where CommandLine LIKE "%-enc%" OR CommandLine LIKE "%download%" OR CommandLine LIKE "%invoke%"
| stats count
| eval status=if(count > 0, "ACTIVITY CONTINUING", "ACTIVITY STOPPED")
| table status, count
```

**What to look for:**
- **If `count = 0`:** No recent suspicious PowerShell activity - attack appears to have stopped
- **If `count > 0`:** Suspicious PowerShell activity is still occurring - attack is ongoing

#### Step 2: Document Attack Details
Create incident report with:
- User accounts involved
- Commands executed (decoded if possible)
- Timeline of activity
- Network connections made (if any)
- Parent processes that launched PowerShell
- Whether any data was exfiltrated

#### Step 3: Review Security Controls
- Verify Sysmon is capturing all process creation events
- Check PowerShell execution policies
- Review endpoint detection capabilities
- Assess if additional monitoring is needed

---

### 5. Recovery

#### Step 1: Restore PowerShell Access (if disabled)
```powershell
# Re-enable PowerShell execution (if it was restricted)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
```

#### Step 2: Reset Affected User Accounts
```powershell
# Reset password for affected account
net user <USERNAME> <NEW_STRONG_PASSWORD>

# Re-enable account (if it was disabled)
net user <USERNAME> /active:yes
```

#### Step 3: Review Firewall Rules

**Decision:** Firewall rules blocking PowerShell outbound connections may be kept or removed (see [Containment and Recovery Symmetry](../../Phase8_Incident_Response_Playbooks.md#-containment-and-recovery-symmetry)):

```powershell
# Review existing firewall rules
Get-NetFirewallRule -DisplayName "Block PowerShell Outbound" | Get-NetFirewallAddressFilter

# Option A: Remove firewall rule (if threat is eliminated and PowerShell needs to function normally)
Remove-NetFirewallRule -DisplayName "Block PowerShell Outbound"

# Option B: Keep firewall rule (if PowerShell restrictions are part of security policy)
# No action needed - rule remains active
```

**Decision Criteria:**
- **Remove rule if:** Threat is eliminated and legitimate PowerShell usage is required
- **Keep rule if:** PowerShell restrictions are part of security policy or threat persists

#### Step 4: Monitor for Recurrence
```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| where CommandLine LIKE "%-enc%" OR CommandLine LIKE "%download%" OR CommandLine LIKE "%invoke%"
| stats count by User, host
| where count > 0
| sort -count
```

---

### 6. Post-Incident Activities

**Conduct post-incident review** to identify improvements and document lessons learned.

#### 6.1 Incident Documentation

Document the following:
- Incident ID and timeline
- User accounts involved
- Commands executed (decoded)
- Network connections made
- Parent processes identified
- Containment actions taken
- Eradication steps performed
- Recovery procedures executed
- Response time metrics (MTTD, MTTR, MTTC)

#### 6.2 Lessons Learned

**Key Takeaways:**
- Sysmon Event ID 1 (Process Creation) is essential for detecting PowerShell execution
- Command-line argument analysis is critical - encoded commands require decoding for full understanding
- PowerShell obfuscation techniques (`-enc`, base64 encoding) are common in attacks
- Process tree analysis helps identify attack chains and parent processes
- Network activity correlation (Event ID 3) provides context for PowerShell execution

**Technical Considerations:**
- Sysmon captures full command lines even when base64-encoded
- The `CommandLine` field in Sysmon contains the complete command, including encoded parameters
- PowerShell execution policies can be used for containment but may impact legitimate operations
- Decoding base64-encoded commands helps understand attacker intent
- Process parent/child relationships reveal execution chains

**Detection Improvements:**
- [ ] Expand detection patterns beyond `-enc` to include other obfuscation techniques
- [ ] Add correlation with network connections (Event ID 3) for PowerShell
- [ ] Implement base64 decoding in detection queries
- [ ] Add detection for PowerShell execution from unusual parent processes
- [ ] Improve detection for PowerShell download and execute patterns

**Prevention Measures:**
- [ ] Implement PowerShell execution policies (Restricted or RemoteSigned)
- [ ] Enable PowerShell script block logging
- [ ] Configure Sysmon to capture all PowerShell executions
- [ ] Use application whitelisting to restrict PowerShell execution
- [ ] Implement network segmentation to limit PowerShell network access
- [ ] Enable PowerShell transcript logging for user sessions
- [ ] Patch PowerShell vulnerabilities

**Response Improvements:**
- [ ] Document response time (MTTD, MTTR, MTTC) - need to track these metrics
- [ ] Develop base64 decoding procedures for faster analysis
- [ ] Create automated containment scripts for PowerShell processes
- [ ] Update playbook based on lessons learned
- [ ] Practice incident response scenarios more frequently

**Process Improvements:**
- [ ] Perform routine cyber hygiene due diligence
- [ ] Learn more about PowerShell obfuscation techniques
- [ ] Update incident response plan based on findings
- [ ] Get feedback from experienced SOC analysts if possible

**Resources I Used:**
- NIST SP 800-61 Computer Security Incident Handling Guide
- Splunk documentation for SPL queries
- MITRE ATT&CK framework (T1059.001 - PowerShell)
- Sysmon documentation for process monitoring
- PowerShell security best practices
- Sample playbooks from AWS, Microsoft, and other organizations

---

## 📚 References and Learning Resources

**Resources I consulted while creating this playbook:**
- NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide
- Splunk SPL documentation and tutorials
- MITRE ATT&CK framework (T1059.001 - PowerShell)
- Sysmon documentation for process creation monitoring
- PowerShell security and obfuscation techniques
- Sample playbooks from AWS Security Incident Response Guide
- Microsoft Incident Response Playbook Workflows
- Various SPL query examples from Splunk community

**Tools I used:**
- Splunk Enterprise (Free tier)
- Sysmon for process monitoring
- Windows 10 VM with PowerShell
- PowerShell for Windows administration
- VirtualBox for lab environment

---

**Return to:** [Phase 8: Incident Response Playbooks Overview](../Phase8_Incident_Response_Playbooks.md)

