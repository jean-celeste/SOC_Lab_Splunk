# 🔴 Playbook Template: [INCIDENT TYPE NAME]

> **Note:** This playbook template follows NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide) framework. Fill in the sections below with specific details for your incident type. Delete this note and the instructions in brackets before finalizing.

### MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Sub-Technique Name | Platforms | Permissions Required |
| ------ | ------------ | -------------- | ------------------ |---------- |--------------------- |
| Credential Access | T110 | Brute Force | Password Spraying | Windows | None |

> **Note on Platforms:** In this homelab, I have a Windows 10 VM as the victim machine and Kali Linux VM as the attacker machine. The brute force attack comes from Kali using Hydra with rockyou.txt (first 100) wordlist and targets Windows 10 via Remote Desk Protocol (RDP). MITRE ATT&CK lists this technique for multiple platforms, but I am focusing on what's relevant to my lab environment so I list Windows 10 as it is the victim machine.

**Severity:** High  
**Response Time Target:** < 15 minutes  
**Alert Name:** "Brute Force Attack Detected-Windows"  
**Attack Vector:** RDP brute force from Kali Linux (192.168.1.4) against Windows 10 (192.168.1.5) using Hydra with rockyou.txt wordlist.

> **Severity Justification:** [Optional but recommended - explain why you chose this severity level. See [Severity Determination Guide](./Severity_Determination_Guide.md) for detailed guidance. Example: "Attack technique indicates [technique type]. Attack status: [successful/in progress/failed]. Target: [system type]. Impact: [CIA triad impact]."]

---

### 1. Preparation

**Prerequisites and Readiness Measures:**

1. **Ensure logging is configured:**
   - Windows Event Logs forwarding to Splunk (Security and System logs)
   - Splunk Universal Forwarder running on Windows 10 VM
   - Verify logs are being received by Splunk: `index=windows_security | head 10`

2. **Verify alerting is configured:**
   - Brute Force Attack Detected – Windows created in Splunk
   - Alert threshold set to > 5 failed attempts
   - Summary index configured for alert logging

3. **Prepare tools and access:**
   - Ubuntu server to host Splunk Web UI
   - Admin access to Windows 10 VM (PowerShell)
   - Access to Splunk Web UI (<Ubuntu_Server_IP>:8000)
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
- **Alert Name:** Brute Force Attack Detected-Windows
- **Event ID:** 4625 (Failed logon attempt)
- **Threshold:** > 5 failed attempts from same IP
- **Time Range:** Last 5

**Manual Detection Query:**
```spl
index=windows_security EventCode=4625
| stats count by Account_Name, Source_Network_Address
| where count > 5
| sort -count
```

> **Learning Note:** Initially, I had trouble finding the right field name for source IP. I used `fieldsummary` to discover it was `Source_Network_Address` in my environment, not `src_ip` as some documentation suggested. Always verify field names in your specific Splunk setup!

**What to Look For:**
- Multiple failed login attempts (Event ID 4625)
- Same source IP address
- Same or multiple target accounts
- Recent time window (last 5 minutes)
- Failed login attempts for default and common account names
- Failed login attempts for the same account across multiple systems
- Failed login attempts to multiple systems from the same source

#### 2.2 Analysis

**Step 1: Identify Attack Scope**

Determine the extent of the attack:

```spl
index=windows_security EventCode=4625
| stats count, values(Account_Name) as accounts, earliest(_time) as first_seen, latest(_time) as last_seen by Source_Network_Address, host
| eval duration=round((last_seen - first_seen)/60, 2)
| convert ctime(first_seen) ctime(last_seen)
| sort -count
```

**This query provides:**
- Source IP address of the attacker
- Host(s) affected
- Number of failed attempts per source IP
- Target accounts being attacked
- Attack timeline (first and last attempt)
- Duration of the attack in minutes


**Key Questions:**
- How many failed attempts occurred?
- What is the source IP address?
- Which accounts were targeted?
- How long has the attack been ongoing?

**Step 2: Check for [Related Activity]**

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

**Step 4: Identify [Specific Targets/Patterns]**

Determine which accounts are at highest risk. **Replace `<ATTACKER_IP>` with the actual source IP from Step 1:**

```spl
index=windows_security EventCode=4625 Source_Network_Address="192.168.1.4"
| stats count by Account_Name
| sort -count
| eval account_risk=case(count > 20, "HIGH", count > 10, "MEDIUM", 1=1, "LOW")
| table Account_Name, count, account_risk
```

**Step 5: Check [System/Account Status]**

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

**Plan containment events** where these steps are launched together (or in coordinated fashion), with appropriate teams ready to respond to any disruption. **Consider the timing and tradeoffs** of containment actions: your response has consequences.

#### 3.1 Immediate Containment (0-5 minutes)

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

---

### 4. Eradication

**Plan eradication events** where these steps are launched together (or in coordinated fashion), with appropriate teams ready to respond to any disruption.

#### Step 1: Verify Attack Has Stopped
```spl
index=windows_security EventCode=4625 Source_Network_Address=<ATTACKER_IP>
| stats count
| where count = 0
```

**What to look for:**
- **If `count = 0` :** No recent failed attempts - attack appears to have stopped
- **If `count > 0` :** Failed attempts are still occurring - attack is ongoing

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

**Key Takeaways:**
- Windows Event IDs 4625 (failed logon) and 4624 (successful logon) are critical indicators for credential access attacks
- SPL aggregation functions (`stats`, `eval`, `convert`) are essential for attack scope analysis
- Field names vary between Splunk environments - using `fieldsummary` ensures query accuracy
- PowerShell firewall management commands require proper privilege escalation understanding
- Clear distinction between immediate containment (0-5 min) and short-term containment (5-15 min) is essential for effective response

**Technical Considerations:**
- Event ID 4625 indicates failed authentication attempts, while 4624 indicates successful authentication
- Using `convert ctime()` is more efficient than manual timestamp formatting with `strftime()`
- Firewall rule creation requires Administrator privileges and understanding of Windows security policies
- Attack duration calculation using `earliest()` and `latest()` functions provides valuable timeline context

**Detection Improvements:**
- [ ] Review alert threshold (is 5 attempts appropriate? - I picked this based on research)
- [ ] Consider adding geolocation checks (beyond my current lab setup)
- [ ] Add correlation with successful logons
- [ ] Improve detection for password spraying patterns
- [ ] Learn more about SPL optimization for faster queries

**Prevention Measures:**
- [ ] Implement account lockout policy (need to learn Group Policy)
- [ ] Enable MFA for RDP (if possible - not sure how to do this yet)
- [ ] Restrict RDP access to specific IPs
- [ ] Use strong password policies
- [ ] Patch asset vulnerabilities
- [ ] Perform routine inspections of controls
- [ ] Set up network segmentation and firewalls

**Response Improvements:**
- [ ] Document response time (MTTD, MTTR, MTTC) - need to track these metrics
- [ ] Review containment actions effectiveness
- [ ] Update playbook based on lessons learned
- [ ] Consider automating containment measures (need to learn SOAR tools)
- [ ] Practice incident response scenarios more frequently

**Process Improvements:**
- [ ] Perform routine cyber hygiene due diligence
- [ ] Learn more about enterprise incident response tools
- [ ] Update incident response plan based on findings
- [ ] Get feedback from experienced SOC analysts if possible

---

## 📚 References and Learning Resources

**Resources I consulted while creating this playbook:**
- NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide
- Splunk SPL documentation and tutorials
- MITRE ATT&CK framework (T1110 - Brute Force)
- Sample playbooks from AWS Security Incident Response Guide
- Microsoft Incident Response Playbook Workflows
- Various SPL query examples from Splunk community

**Tools I used:**
- Splunk Enterprise (Free tier)
- Windows 10 VM with Event Logs
- PowerShell for Windows administration
- VirtualBox for lab environment

---

**Return to:** [Phase 8: Incident Response Playbooks Overview](../Phase8_Incident_Response_Playbooks.md)
