# 🔴 Playbook 4: Lateral Movement (SMB)

> **Note:** This playbook was created as part of my SOC lab learning project. I researched NIST SP 800-61 framework and industry best practices, then adapted them for my home lab environment. Some queries were refined through trial and error - I've noted where I encountered issues and how I resolved them.

### MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Sub-Technique Name | Platforms | Permissions Required |
| ------ | ------------ | -------------- | ------------------ |---------- |--------------------- |
| Lateral Movement | T1021.002 | Remote Services | SMB/Windows Admin Shares | Windows | User |

> **Note on Platforms:** In my lab, lateral movement occurs via SMB (Server Message Block) from Kali Linux (192.168.1.4) to Windows 10 (192.168.1.5). The attack uses SMB client tools to access network shares, requiring valid user credentials. This technique is executed against Windows, requiring user-level permissions to access SMB shares.

**Severity:** High  
**Response Time Target:** < 10 minutes (see [Response Time Targets](../../Phase8_Incident_Response_Playbooks.md#-response-time-targets-sla))  
**Alert Name:** "Lateral Movement Detection (SMB)"  
**Attack Vector:** SMB network logons from Kali Linux (192.168.1.4) to Windows 10 (192.168.1.5) using `smbclient` to access network shares

> **Severity Justification:** Attack technique indicates lateral movement activity. Attack status: in progress. Target: Windows 10 endpoint via SMB shares. Impact: High - Lateral movement enables attackers to access additional systems and resources, potentially leading to data access, privilege escalation, or further network compromise. SMB access can be used to enumerate shares, access files, and move through the network. This represents a confidentiality and integrity risk as unauthorized network access can lead to data theft, system compromise, or attack progression.

### Related Playbooks

**If preceded by credential access:**
- → **Playbook 1: Brute Force Attack** - Review initial credential compromise (Event ID 4625/4624)

**If privilege escalation detected following lateral movement:**
- → **Playbook 3: Privilege Escalation** - Monitor for admin group changes (Event ID 4732/4728) after network access

**If data exfiltration detected:**
- → **Playbook 5: Data Exfiltration** - Check for outbound connections (Event ID 3) to suspicious destinations

**If PowerShell execution detected:**
- → **Playbook 2: Suspicious PowerShell** - Check for encoded PowerShell commands used for lateral movement

---

### 1. Preparation

**Prerequisites and Readiness Measures:**

1. **Ensure logging is configured:**
   - Windows Event Logs forwarding to Splunk (Security logs)
   - Splunk Universal Forwarder running on Windows 10 VM
   - Verify logs are being received: `index=windows_security EventCode=4624 | head 10`
   - SMB auditing enabled (if possible)

2. **Verify alerting is configured:**
   - Lateral Movement alert created in Splunk (Phase 6)
   - Alert threshold set to detect multiple network logons (Logon Type 3)
   - Summary index configured for alert logging

3. **Prepare tools and access:**
   - Admin access to Windows 10 VM (PowerShell)
   - Access to Splunk Web UI (`http://192.168.1.7:8000`)
   - Network access to block IPs via firewall
   - Ability to manage SMB shares and firewall rules

4. **Security controls in place:**
   - SMB share access controls documented
   - Firewall rules can be modified
   - Network segmentation policies documented
   - SMB access monitoring enabled

5. **Documentation ready:**
   - Incident tracking system/template
   - Contact information for escalation
   - Network topology documentation

---

### 2. Detection and Analysis

#### 2.1 Detection

**Alert Triggered:**
- **Alert Name:** Lateral Movement Detection (SMB)
- **Event ID:** 4624 (Successful logon)
- **Logon Type:** 3 (Network logon)
- **Threshold:** Multiple network logons from same IP (> 3)
- **Time Range:** Last 5-15 minutes

**Manual Detection Query:**
```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| stats count by Source_Network_Address, Account_Name
| where count > 3
| sort -count
```

> **Learning Note:** Initially, I was confused about Logon Type 3 vs Logon Type 5. Logon Type 3 indicates network logons (SMB, RPC, etc.), while Logon Type 5 is for service logons (local). I also learned that `Source_Network_Address` can be "-" for local logons, so I must filter those out. Always check that `Source_Network_Address` contains an actual IP address, not "-", when looking for network-based lateral movement.

> **Note:** Field names may vary in your environment. See [Field Naming and Extraction](../../Phase8_Incident_Response_Playbooks.md#-field-naming-and-extraction) for guidance on verifying field names using `fieldsummary`. Account name extraction may require `rex` for accuracy, especially in complex event structures.

**What to Look For:**
- Multiple network logons (Event ID 4624, Logon Type 3)
- Same source IP address making multiple connections
- Source IP address is NOT "-" (indicates network logon)
- Unusual source IP addresses (external or unexpected internal IPs)
- Access to administrative shares (C$, ADMIN$, IPC$)
- Multiple accounts used from same source IP
- Access outside normal business hours
- Rapid succession of network logons

#### 2.2 Analysis

**Step 1: Identify Attack Scope**

Determine the extent of the lateral movement activity:

```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| stats count, values(Account_Name) as accounts, 
         earliest(_time) as first_seen, latest(_time) as last_seen 
  by Source_Network_Address, host
| eval duration=round((last_seen - first_seen)/60, 2)
| convert ctime(first_seen) ctime(last_seen)
| sort -count
```

**This query provides:**
- Source IP address of the attacker
- Number of network logons from that IP
- Accounts used for access
- Timeline of lateral movement activity
- Duration of activity
- Host(s) affected

**Key Questions:**
- How many network logons occurred?
- What is the source IP address?
- Which accounts were used?
- How long has this activity been ongoing?
- Are multiple accounts being used from the same IP?

**Step 2: Identify Accounts Used**

Determine which accounts are being used for lateral movement:

```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| rex field=_raw "(?i)New Logon:\s+Security ID:\s+[^\r\n]+\s+Account Name:\s+(?<account_name>[^\r\n\t]+)"
| stats count by Source_Network_Address, account_name
| sort -count
```

> **Note:** The `Account_Name` field may contain multiple values or may not extract correctly. Using `rex` to extract from `_raw` can be more reliable. I learned this after some queries didn't show the expected account names.

**Alternative Query (Using Extracted Field):**
```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| stats count by Source_Network_Address, Account_Name
| sort -count
```

**Step 3: Check for Specific Attacker IP**

If you know the attacker IP (e.g., from Kali Linux - 192.168.1.4):

```spl
index=windows_security EventCode=4624 Logon_Type=3 Source_Network_Address=192.168.1.4
| rex field=_raw "(?i)New Logon:\s+Security ID:\s+[^\r\n]+\s+Account Name:\s+(?<account_name>[^\r\n\t]+)"
| table _time, account_name, Source_Network_Address, Account_Domain, Process_Name
| sort -_time
```

**This helps identify:**
- All network logons from the specific attacker IP
- Which accounts were used
- Timeline of access attempts
- Process that initiated the logon

**Step 4: Timeline Analysis**

Understand the lateral movement pattern over time:

**Simple Timeline:**
```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| timechart count span=5m
```

**Timeline by Source IP:**
```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| timechart count by Source_Network_Address span=5m
```

**Timeline by Account:**
```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| rex field=_raw "(?i)New Logon:\s+Security ID:\s+[^\r\n]+\s+Account Name:\s+(?<account_name>[^\r\n\t]+)"
| timechart count by account_name span=5m
```

**This helps identify:**
- When lateral movement occurred
- Frequency of network logons
- Patterns of access (burst vs. steady)
- Which IPs or accounts are most active

**Step 5: Check for Failed Attempts**

Determine if there were failed logon attempts before successful lateral movement:

```spl
index=windows_security EventCode=4625 Source_Network_Address=192.168.1.4
| stats count by Account_Name, Source_Network_Address
| sort -count
```

**This helps identify:**
- Whether attacker tried multiple accounts
- If brute force preceded lateral movement
- Accounts that were targeted

**Step 6: Check for Share Access Events**

Look for specific share access events (if available):

```spl
index=windows_security (EventCode=5140 OR EventCode=5143)
| head 20
```

> **Note:** Event IDs 5140 (Network share accessed) and 5143 (Network share object modified) may not be enabled by default in Windows. I checked for these events but found they weren't available in my lab environment. The Logon Type 3 events are the primary indicator for SMB lateral movement.

**Step 7: Escalation Criteria**

**When to escalate to other playbooks:**
- ✅ **If privilege escalation detected (Event ID 4732/4728):** Immediately refer to **Playbook 3: Privilege Escalation** - monitor for admin group changes after network access
- ✅ **If data exfiltration detected:** Refer to **Playbook 5: Data Exfiltration** - check for outbound connections (Event ID 3) to suspicious destinations
- ✅ **If preceded by credential access:** Refer to **Playbook 1: Brute Force Attack** - review initial credential compromise (Event ID 4625/4624)
- ✅ **If PowerShell execution detected:** Refer to **Playbook 2: Suspicious PowerShell** - check for encoded PowerShell commands used for lateral movement

**Step 8: Investigate All Associated Alerts**

- Review and clear ALL alerts associated with the impacted assets
- Check for related security events (failed logons, privilege escalation)
- Document all findings

---

### 3. Containment

**Plan containment events** where these steps are launched together (or in coordinated fashion), with appropriate teams ready to respond to any disruption. **Consider the timing and tradeoffs** of containment actions: your response has consequences.

#### 3.1 Immediate Containment (0-5 minutes)

1. **Block Source IP at Network Level**
   ```powershell
   # On Windows 10 VM (PowerShell as Administrator)
   New-NetFirewallRule -DisplayName "Block Lateral Movement IP" `
       -Direction Inbound -RemoteAddress <ATTACKER_IP> `
       -Action Block -Enabled True
   ```

2. **Disconnect Active SMB Sessions**
   ```powershell
   # List active SMB sessions
   Get-SmbSession
   
   # Close specific session (replace <SessionId> with actual ID)
   Close-SmbSession -SessionId <SessionId> -Force
   
   # Close all sessions from specific IP (if possible)
   Get-SmbSession | Where-Object {$_.ClientComputerName -like "*<ATTACKER_IP>*"} | 
       ForEach-Object {Close-SmbSession -SessionId $_.SessionId -Force}
   ```

3. **Temporarily Disable SMB Shares (if attack is ongoing)**

**Decision Criteria:**
- **Use `Revoke-SmbShareAccess` (Targeted Containment)** when:
  - Only specific shares are being accessed
  - You can identify the exact share(s) under attack
  - Business operations require other shares to remain accessible
  - You can identify the specific account(s) being used
  
- **Use `Stop-Service LanmanServer` (Aggressive Containment)** when:
  - Multiple shares are being accessed
  - You cannot identify specific shares under attack
  - Attack is widespread across multiple accounts
  - Business impact assessment approves service shutdown
  - Immediate containment is critical and targeted approach is too slow

**Business Impact Assessment Required:**
- ✅ Identify all systems/users dependent on SMB file sharing
- ✅ Notify affected teams before stopping SMB service
- ✅ Document business justification for service shutdown
- ✅ Plan for service restoration timeline
- ✅ Consider alternative file sharing methods during containment

**Targeted Containment (Preferred):**
```powershell
# Disable specific share access for compromised account
Revoke-SmbShareAccess -Name TestShare -AccountName <USERNAME> -Force

# Or disable access to administrative shares
Revoke-SmbShareAccess -Name "C$" -AccountName <USERNAME> -Force
Revoke-SmbShareAccess -Name "ADMIN$" -AccountName <USERNAME> -Force
```

**Aggressive Containment (Use with Caution):**
```powershell
# Stop SMB service (affects ALL shares - use only if necessary)
Stop-Service LanmanServer

# Verify service is stopped
Get-Service LanmanServer
```

> **Limitation:** In my home lab, I can stop the SMB service, but in production environments, this may impact legitimate file sharing operations. Consider the business impact before disabling SMB entirely.

#### 3.2 Short-term Containment (5-15 minutes)

1. **Review and Lock Compromised Accounts**
   ```powershell
   # Disable account used for lateral movement
   Disable-LocalUser -Name <USERNAME>
   
   # Or lock the account
   net user <USERNAME> /active:no
   ```

2. **Monitor for Continued Activity**
   ```spl
   index=windows_security EventCode=4624 Logon_Type=3 Source_Network_Address=<ATTACKER_IP>
   | stats count
   | eval status=if(count > 0, "ACTIVITY CONTINUING", "ACTIVITY STOPPED")
   | table status, count
   ```

3. **Review SMB Share Permissions**
   ```powershell
   # List all SMB shares
   Get-SmbShare
   
   # Check share access permissions
   Get-SmbShareAccess -Name TestShare
   
   # Review who has access to administrative shares
   Get-SmbShareAccess -Name "C$"
   Get-SmbShareAccess -Name "ADMIN$"
   ```
---

### 4. Eradication

**Plan eradication events** where these steps are launched together (or in coordinated fashion), with appropriate teams ready to respond to any disruption.

#### Step 1: Verify Activity Has Stopped

```spl
index=windows_security EventCode=4624 Logon_Type=3 Source_Network_Address=<ATTACKER_IP>
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| stats count
| eval status=if(count > 0, "ACTIVITY CONTINUING", "ACTIVITY STOPPED")
| table status, count
```

**What to look for:**
- **If `count = 0`:** No recent network logons from attacker IP - lateral movement appears to have stopped
- **If `count > 0`:** Network logons are still occurring - attack is ongoing

#### Step 2: Investigate How Lateral Movement Occurred

**Check for initial access:**
```spl
index=windows_security EventCode=4624 Account_Name="<USERNAME>"
| stats count, values(Logon_Type) as logon_types, 
         values(Source_Network_Address) as source_ips,
         earliest(_time) as first_logon
  by Account_Name
| table Account_Name, logon_types, source_ips, first_logon, count
```

**Check for credential compromise:**
```spl
index=windows_security EventCode=4625 Account_Name="<USERNAME>"
| stats count by Source_Network_Address
| sort -count
```

**What to look for:**
- How the account initially gained access
- Whether credentials were compromised
- If brute force preceded lateral movement
- Timeline of events leading to lateral movement

#### Step 3: Document Attack Details

Create incident report with:
- Source IP address
- Accounts used for lateral movement
- Shares accessed (if known)
- Timeline of activity
- How initial access was gained
- Whether any data was accessed
- Files accessed (if file access auditing enabled)

#### Step 4: Review Security Controls**

- Verify firewall rules are in place
- Check SMB share permissions
- Review account access controls
- Assess if additional monitoring is needed
- Consider disabling unnecessary SMB shares

---

### 5. Recovery

#### Step 1: Restore SMB Access (if disabled)

```powershell
# Re-enable SMB service (if it was stopped)
Start-Service LanmanServer
Set-Service LanmanServer -StartupType Automatic

# Restore share access (if revoked)
Grant-SmbShareAccess -Name TestShare -AccountName <LEGITIMATE_USER> -AccessRight Read
```

#### Step 2: Reset Affected Accounts

```powershell
# Reset password for account used in lateral movement
net user <USERNAME> <NEW_STRONG_PASSWORD>

# Re-enable account (if it was disabled and determined to be legitimate)
net user <USERNAME> /active:yes
```

**Note:** Only re-enable the account after thorough investigation and if it's determined the account itself wasn't compromised. If the account was compromised, consider deleting it entirely.

#### Step 3: Review and Secure SMB Shares

```powershell
# Review administrative share permissions
Get-SmbShareAccess -Name "C$" | Format-Table
Get-SmbShareAccess -Name "ADMIN$" | Format-Table

# Restrict access if needed
Revoke-SmbShareAccess -Name "C$" -AccountName <UNAUTHORIZED_USER> -Force
```

#### Step 4: Review Firewall Rules

**Decision:** Firewall rules blocking lateral movement IPs may be kept or removed (see [Containment and Recovery Symmetry](../../Phase8_Incident_Response_Playbooks.md#-containment-and-recovery-symmetry)):

```powershell
# Review existing firewall rules
Get-NetFirewallRule -DisplayName "Block Lateral Movement IP" | Get-NetFirewallAddressFilter

# Option A: Remove firewall rule (if threat is eliminated and IP is not confirmed malicious)
Remove-NetFirewallRule -DisplayName "Block Lateral Movement IP"

# Option B: Keep firewall rule (if IP is confirmed malicious or threat persists)
# No action needed - rule remains active
```

**Decision Criteria:**
- **Remove rule if:** Threat is eliminated, IP was a false positive, or blocking is no longer needed
- **Keep rule if:** IP is confirmed malicious, threat persists, or IP is from known bad actor

#### Step 5: Monitor for Recurrence

```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| stats count by Source_Network_Address
| where count > 3
| sort -count
```

---

### 6. Post-Incident Activities

**Conduct post-incident review** to identify improvements and document lessons learned.

#### 6.1 Incident Documentation

Document the following:
- Incident ID and timeline
- Source IP address and accounts used
- Shares accessed (if known)
- Timeline of lateral movement activity
- How initial access was gained
- Containment actions taken
- Eradication steps performed
- Recovery procedures executed
- Response time metrics (MTTD, MTTR, MTTC)

#### 6.2 Lessons Learned

**Key Takeaways:**
- Windows Event ID 4624 with Logon Type 3 indicates network logons (SMB, RPC, etc.)
- Logon Type 3 is different from Logon Type 5 (service logon) - must filter correctly
- `Source_Network_Address` field can be "-" for local logons - must filter these out
- SMB lateral movement requires valid credentials but can be detected through logon events
- Multiple network logons from same IP indicate potential lateral movement
- Account name extraction may require `rex` from `_raw` field for accuracy

**Technical Considerations:**
- Event ID 4624 with Logon Type 3 = Network logon (SMB, RPC, network authentication)
- Event ID 4624 with Logon Type 5 = Service logon (local, not network)
- `Source_Network_Address` = "-" indicates local logon, not network logon
- Event IDs 5140 and 5143 (share access) may not be enabled by default
- SMB sessions can be listed and closed using PowerShell `Get-SmbSession` and `Close-SmbSession`
- Filtering for `Source_Network_Address != "-"` is critical for detecting network-based lateral movement

**Detection Improvements:**
- [ ] Enable Event IDs 5140 and 5143 for share access monitoring
- [ ] Add detection for access to administrative shares (C$, ADMIN$, IPC$)
- [ ] Correlate network logons with file access events
- [ ] Add detection for multiple accounts used from same IP
- [ ] Monitor for SMB access outside business hours
- [ ] Improve account name extraction reliability

**Prevention Measures:**
- [ ] Disable unnecessary SMB shares
- [ ] Restrict access to administrative shares (C$, ADMIN$)
- [ ] Implement network segmentation
- [ ] Use strong authentication for SMB
- [ ] Enable SMB signing and encryption
- [ ] Regularly review SMB share permissions
- [ ] Monitor for SMB access patterns
- [ ] Patch SMB vulnerabilities
- [ ] Perform routine inspections of controls

**Response Improvements:**
- [ ] Document response time (MTTD, MTTR, MTTC) - need to track these metrics
- [ ] Create automated script to block lateral movement IPs
- [ ] Improve share access monitoring
- [ ] Document lateral movement patterns
- [ ] Practice incident response scenarios more frequently
- [ ] Learn more about SMB security best practices

**Process Improvements:**
- [ ] Perform routine cyber hygiene due diligence
- [ ] Learn more about network segmentation
- [ ] Update incident response plan based on findings
- [ ] Get feedback from experienced SOC analysts if possible
- [ ] Review and update SMB access policies regularly

**Resources I Used:**
- NIST SP 800-61 Computer Security Incident Handling Guide
- Splunk documentation for SPL queries
- MITRE ATT&CK framework (T1021.002 - SMB/Windows Admin Shares)
- Windows Security Event Log documentation
- Sample playbooks from AWS, Microsoft, and other organizations

---

## 📚 References and Learning Resources

**Resources I consulted while creating this playbook:**
- NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide
- Splunk SPL documentation and tutorials
- MITRE ATT&CK framework (T1021.002 - SMB/Windows Admin Shares)
- Windows Security Event Log documentation (Event ID 4624, Logon Types)
- Sample playbooks from AWS Security Incident Response Guide
- Microsoft Incident Response Playbook Workflows
- Various SPL query examples from Splunk community

**Tools I used:**
- Splunk Enterprise (Free tier)
- Windows 10 VM with Event Logs
- PowerShell for Windows administration
- VirtualBox for lab environment

---

**Return to:** [Phase 8: Incident Response Playbooks Overview](../../Phase8_Incident_Response_Playbooks.md)

