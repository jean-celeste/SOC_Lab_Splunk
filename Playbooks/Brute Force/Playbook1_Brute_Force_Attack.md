# 🔴 Playbook 1: Brute Force Attack (Credential Access)

> **Note:** This playbook was created as part of my SOC lab learning project. I researched NIST SP 800-61 framework and industry best practices, then adapted them for my home lab environment. Some queries were refined through trial and error - I've noted where I encountered issues and how I resolved them.

### MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Sub-Technique Name | Platforms | Permissions Required |
| ------ | ------------ | -------------- | ------------------ |---------- |--------------------- |
| Credential Access | T1110 | Brute Force | Password Spraying | Windows | None |

> **Note on Platforms:** In my lab, the brute force attack targets Windows 10 via RDP (Remote Desktop Protocol). The attack originates from Kali Linux using Hydra with rockyou.txt wordlist, but the technique is executed against Windows, so I list "Windows" as the platform. MITRE ATT&CK lists this technique for multiple platforms, but I'm focusing on what's relevant to my specific lab environment.

**Severity:** Medium  
**Response Time Target:** < 15 minutes (see [Response Time Targets](../../Phase8_Incident_Response_Playbooks.md#-response-time-targets-sla))  
**Alert Name:** "Brute Force Attack Detected"  
**Attack Vector:** RDP brute force from Kali Linux (192.168.1.4) against Windows 10 (192.168.1.5) using Hydra with rockyou.txt wordlist

> **Severity Justification:** Attack technique indicates credential access attempt. Attack status: in progress. Target: Windows 10 endpoint via RDP. Impact: Medium - Multiple failed authentication attempts indicate active credential access attack. If successful, this could lead to unauthorized access, privilege escalation, lateral movement, or data exfiltration. Attack is in progress but not yet successful, affecting a single system. If attack succeeds (Event ID 4624 detected), severity escalates to High or Critical.

### Related Playbooks

**If successful logon detected (Event ID 4624 from attacker IP):**
- → **Playbook 4: Lateral Movement (SMB)** - Check for network logons and SMB access following credential compromise

**If privilege escalation detected:**
- → **Playbook 3: Privilege Escalation** - Monitor for admin group changes (Event ID 4732/4728)

**If suspicious PowerShell execution detected:**
- → **Playbook 2: Suspicious PowerShell** - Check for encoded PowerShell commands

**If data exfiltration detected:**
- → **Playbook 5: Data Exfiltration** - Monitor for outbound connections to non-standard ports

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
   - Access to Splunk Web UI (`http://192.168.1.7:8000`)
   - Network access to block IPs via firewall

4. **Security controls in place:**
   - Account lockout policy configured (if possible)
   - Firewall rules can be modified
   - RDP access controls documented

5. **Documentation ready:**
   - Incident tracking system/template
   - Contact information for escalation

---

### 2. Detection and Analysis

#### 2.1 Detection

**Alert Triggered:**
- **Alert Name:** Brute Force Attack Detected
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

> **Learning Note:** Initially, I had trouble finding the right field name for source IP. I used `fieldsummary` to discover it was `Source_Network_Address` in my environment, not `src_ip` as some documentation suggested. 

> **Note:** Field names may vary in your environment. See [Field Naming and Extraction](../../Phase8_Incident_Response_Playbooks.md#-field-naming-and-extraction) for guidance on verifying field names using `fieldsummary`.

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
| stats count, values(Account_Name) as accounts, earliest(_time) as first_seen, latest(_time) as last_seen by Source_Network_Address, host
| eval duration=round((last_seen - first_seen)/60, 2)
| convert ctime(first_seen) ctime(last_seen)
| sort -count
```

**This query provides:**
- Source IP address of the attacker
- Number of failed attempts per source IP
- Target accounts being attacked
- Attack timeline (first and last attempt)
- Duration of the attack in minutes
- Host(s) affected

**Key Questions:**
- How many failed attempts occurred?
- What is the source IP address?
- Which accounts were targeted?
- How long has the attack been ongoing?

**Step 2: Check for Successful Logons**

**Critical:** Determine if the attack succeeded. **Replace `<ATTACKER_IP>` with the actual source IP from Step 1:**

**Primary Query (Check Specific IP):**
```spl
index=windows_security EventCode=4624 Source_Network_Address="192.168.1.4"
| stats count by Account_Name, Logon_Type
| table Account_Name, Logon_Type, count
```

**Alternative: Check for successful logons from any IP with recent brute force activity:**

**Step 2a: First, identify IPs with brute force activity:**
```spl
index=windows_security EventCode=4625
| stats count by Source_Network_Address
| where count > 5
| table Source_Network_Address
```

**Step 2b: Then check for successful logons from those IPs:**
```spl
index=windows_security EventCode=4624 Source_Network_Address="<IP_FROM_STEP_2A>"
| stats count by Account_Name, Logon_Type, Source_Network_Address
| table Account_Name, Logon_Type, Source_Network_Address, count
```

> **Learning Note:** I check these queries separately and manually correlate the results. I'll explore using `join` commands to automatically correlate brute force attempts with successful logons in a single query.

**If Event ID 4624 appears with the same source IP as brute force attempts, the attack may have succeeded. Escalate immediately.**

**Escalation Criteria:**
- ✅ **If successful logon detected (Event ID 4624 from attacker IP):** Immediately refer to **Playbook 4: Lateral Movement (SMB)** to check for network logons and SMB access following credential compromise
- ✅ **If privilege escalation detected (Event ID 4732/4728):** Immediately refer to **Playbook 3: Privilege Escalation** - administrative access equals complete system compromise
- ✅ **If suspicious PowerShell execution detected:** Refer to **Playbook 2: Suspicious PowerShell** to investigate encoded commands
- ✅ **If data exfiltration detected:** Refer to **Playbook 5: Data Exfiltration** to monitor outbound connections

**Step 3: Timeline Analysis**

Understand the attack pattern over time. **Replace `<ATTACKER_IP>` with the actual source IP from Step 1:**

```spl
index=windows_security (EventCode=4625 OR EventCode=4624) Source_Network_Address="192.168.1.4"
| eval event_type=case(EventCode=4624, "Successful Logon", EventCode=4625, "Failed Logon", 1=1, "Other")
| timechart count by event_type span=1m
```

**Alternative: Analyze all brute force activity without specifying IP:**
```spl
index=windows_security (EventCode=4625 OR EventCode=4624)
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| eval event_type=case(EventCode=4624, "Successful Logon", EventCode=4625, "Failed Logon", 1=1, "Other")
| timechart count by event_type, Source_Network_Address span=1m
```

**Step 4: Identify Target Accounts**

Determine which accounts are at highest risk. **Replace `<ATTACKER_IP>` with the actual source IP from Step 1:**

```spl
index=windows_security EventCode=4625 Source_Network_Address="192.168.1.4"
| stats count by Account_Name
| sort -count
| eval account_risk=case(count > 20, "HIGH", count > 10, "MEDIUM", 1=1, "LOW")
| table Account_Name, count, account_risk
```

**Alternative: Identify all target accounts across all attacking IPs:**
```spl
index=windows_security EventCode=4625
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| stats count, values(Source_Network_Address) as attacking_ips by Account_Name
| sort -count
| eval account_risk=case(count > 20, "HIGH", count > 10, "MEDIUM", 1=1, "LOW")
| table Account_Name, count, account_risk, attacking_ips
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

> **Troubleshooting:** In my lab, I don't have Active Directory, so `Get-ADUser` won't work. I use `Get-LocalUser` instead for local accounts. This is something I had to figure out when the AD command failed.

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
   
   > **Limitation:** In my home lab, I couldn't easily configure account lockout policy without Group Policy. This is something I'd need to set up properly in a production environment. **Specific Business Impacts:**
   > - **Account Lockout Policy:** Without proper configuration, accounts remain vulnerable to brute force attacks
   > - **Production Requirements:** Account lockout policy should be configured via:
   >   - Group Policy (Active Directory environments)
   >   - Local Security Policy (standalone systems)
   >   - Security baselines and compliance frameworks
   > - **Business Impact of Lockouts:** Account lockout policies can impact:
   >   - Legitimate users who mistype passwords
   >   - Service accounts that may trigger false lockouts
   >   - Automated systems that authenticate frequently
   > - **Communication Requirements:** Must coordinate with:
   >   - Active Directory administrators (for GPO configuration)
   >   - Security team (for policy approval)
   >   - Help desk (for lockout support procedures)
   > 
   > **Alternative Containment Options:**
   > - Manual firewall blocking (already done in step 1) - immediate but requires manual intervention
   > - Network-level blocking via firewall/IPS
   > - Rate limiting at network perimeter
   > - MFA implementation (prevents credential-based attacks even if passwords are compromised)
   > - RDP access restrictions to specific IPs/networks

3. **Temporarily Disable RDP (if attack is ongoing)**
   ```powershell
   # Disable RDP
   Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
       -name "fDenyTSConnections" -Value 1
   ```

#### 3.2 Short-term Containment (5-15 minutes)

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

#### Step 3: Review Firewall Rules

**Decision:** Firewall rules blocking malicious IPs may be kept or removed based on threat assessment (see [Containment and Recovery Symmetry](../../Phase8_Incident_Response_Playbooks.md#-containment-and-recovery-symmetry)):

```powershell
# Review existing firewall rules
Get-NetFirewallRule -DisplayName "Block Brute Force IP" | Get-NetFirewallAddressFilter

# Option A: Remove firewall rule (if threat is eliminated and IP is not confirmed malicious)
Remove-NetFirewallRule -DisplayName "Block Brute Force IP"

# Option B: Keep firewall rule (if IP is confirmed malicious or threat persists)
# No action needed - rule remains active
```

**Decision Criteria:**
- **Remove rule if:** Threat is eliminated, IP was a false positive, or blocking is no longer needed
- **Keep rule if:** IP is confirmed malicious, threat persists, or IP is from known bad actor

#### Step 4: Monitor for Recurrence
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

**Response Time Metrics Calculation:**

**MTTD (Mean Time to Detect):** Time from attack start to alert trigger
**MTTR (Mean Time to Respond):** Time from alert to containment complete
**MTTC (Mean Time to Contain):** Time from alert to threat neutralized

**Example Tracking:**
```
Attack Timeline:
- Attack Start: 10:15:00 (from log analysis - earliest Event ID 4625)
- Alert Triggered: 10:17:30 (Splunk alert fired)
- Containment Started: 10:18:00 (firewall rule created)
- Threat Contained: 10:22:00 (no new attempts detected)

Metrics:
- MTTD = 10:17:30 - 10:15:00 = 2 minutes 30 seconds
- MTTR = 10:18:00 - 10:17:30 = 30 seconds
- MTTC = 10:22:00 - 10:17:30 = 4 minutes 30 seconds

Target vs Actual:
- Target Response Time: < 15 minutes
- Actual MTTC: 4 minutes 30 seconds ✅ (within target)
```

**Documentation Template:**
- [ ] Record attack start time (earliest event timestamp)
- [ ] Record alert trigger time (Splunk alert timestamp)
- [ ] Record containment start time (first containment action)
- [ ] Record threat contained time (verification query shows no new activity)
- [ ] Calculate MTTD, MTTR, MTTC
- [ ] Compare against target response times
- [ ] Document any delays and root causes

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

**Resources I Used:**
- NIST SP 800-61 Computer Security Incident Handling Guide
- Splunk documentation for SPL queries
- MITRE ATT&CK framework for technique mapping
- Various online tutorials for PowerShell commands
- Sample playbooks from AWS, Microsoft, and other organizations (see research references)

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

