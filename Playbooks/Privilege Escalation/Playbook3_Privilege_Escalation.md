# 🔴 Playbook 3: Privilege Escalation (Privilege Escalation, Persistence)

> **Note:** This playbook was created as part of my SOC lab learning project. I researched NIST SP 800-61 framework and industry best practices, then adapted them for my home lab environment. Some queries were refined through trial and error - I've noted where I encountered issues and how I resolved them.

### MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Sub-Technique Name | Platforms | Permissions Required |
| ------ | ------------ | -------------- | ------------------ |---------- |--------------------- |
| Privilege Escalation, Persistence | T1078.003 | Valid Accounts | Local Accounts | Windows | Administrator |

> **Note on Platforms:** In my lab, privilege escalation occurs on Windows 10 VM by adding a local user account to the Administrators group. The attack requires administrator-level permissions to modify group membership, but once successful, grants the elevated user full administrative access. This technique is executed against Windows, requiring administrator privileges to perform the escalation.

**Severity:** Critical  
**Response Time Target:** < 5 minutes (see [Response Time Targets](../../Phase8_Incident_Response_Playbooks.md#-response-time-targets-sla))  
**Alert Name:** "Privilege Escalation Detection"  
**Attack Vector:** Local user account (`testuser`) added to Administrators group on Windows 10 (192.168.1.5) using `net localgroup administrators` command

> **Severity Justification:** Attack technique indicates successful privilege escalation. Attack status: succeeded. Target: Windows 10 endpoint. Impact: Critical - Administrative access grants full system control, enabling persistence mechanisms, data access, security control modification, and lateral movement. This is always CRITICAL because administrative access equals complete system compromise, representing severe confidentiality, integrity, and availability risks.

### Related Playbooks

**Privilege escalation can follow ANY attack type. Check all related playbooks:**

**If preceded by credential access:**
- → **Playbook 1: Brute Force Attack** - Review initial credential compromise (Event ID 4625/4624)

**If preceded by execution:**
- → **Playbook 2: Suspicious PowerShell** - Check for PowerShell execution that led to escalation

**If followed by lateral movement:**
- → **Playbook 4: Lateral Movement (SMB)** - Monitor for network logons (Event ID 4624, Logon Type 3)

**If followed by data exfiltration:**
- → **Playbook 5: Data Exfiltration** - Check for outbound connections (Event ID 3) to suspicious destinations

---

### 1. Preparation

**Prerequisites and Readiness Measures:**

1. **Ensure logging is configured:**
   - Windows Event Logs forwarding to Splunk (Security logs)
   - Splunk Universal Forwarder running on Windows 10 VM
   - Verify logs are being received: `index=windows_security EventCode=4732 | head 10`
   - Audit policy enabled for group membership changes

2. **Verify alerting is configured:**
   - Privilege Escalation alert created in Splunk (Phase 6)
   - Alert threshold set to detect any Event ID 4732 or 4728
   - Real-time alerting enabled (critical severity)
   - Summary index configured for alert logging

3. **Prepare tools and access:**
   - Admin access to Windows 10 VM (PowerShell)
   - Access to Splunk Web UI (`http://192.168.1.7:8000`)
   - Ability to modify group membership
   - Ability to disable user accounts

4. **Security controls in place:**
   - Windows Security Event Log auditing enabled
   - Group membership change auditing configured
   - Account management policies documented
   - Least privilege principle implemented (where possible)

5. **Documentation ready:**
   - Incident tracking system/template
   - Contact information for escalation
   - Group membership baseline documentation

---

### 2. Detection and Analysis

#### 2.1 Detection

**Alert Triggered:**
- **Alert Name:** Privilege Escalation Detection
- **Event ID:** 4732 (Member added to security-enabled local group)
- **Alternative Event ID:** 4728 (Member added to security-enabled global group)
- **Threshold:** Any occurrence (real-time alert)
- **Time Range:** Real-time or last 5 minutes

**Manual Detection Query:**
```spl
index=windows_security (EventCode=4732 OR EventCode=4728)
| stats count by Account_Name, Account_Domain, Group_Name
| where count > 0
```

**Enhanced Detection Query (Administrators Group Only):**
```spl
index=windows_security EventCode=4732 Group_Name="Administrators"
| stats count by Account_Name, Account_Domain, Group_Name
| where count > 0
```

**Alert-Ready Query (For Splunk Alerts):**
```spl
index=windows_security EventCode=4732 Group_Name="Administrators"
| stats count, values(Account_Domain) as domains, values(Group_Domain) as group_domains by Account_Name, Group_Name
| where count > 0
| eval severity="CRITICAL"
| eval description="User " + Account_Name + " added member to " + Group_Name + " group"
```

> **Learning Note:** Initially, I had to verify the correct field names in my environment. Using `fieldsummary` revealed that my Splunk setup uses `Account_Name`, `Account_Domain`, `Group_Name`, and `Group_Domain` rather than `SubjectUserName` or `MemberName`. The member name (who was added) may not appear directly in extracted fields - use `rex` to extract from `_raw` if needed.

> **Note:** Field names may vary in your environment. See [Field Naming and Extraction](../../Phase8_Incident_Response_Playbooks.md#-field-naming-and-extraction) for guidance on verifying field names using `fieldsummary`.

**What to Look For:**
- Event ID 4732 or 4728 (group membership changes)
- User added to Administrators group
- User added to Domain Admins group (if applicable)
- Unauthorized privilege changes
- Changes outside of maintenance windows
- Unusual accounts being elevated
- Multiple privilege escalations in short time period

#### 2.2 Analysis

**Step 1: Identify Attack Scope**

Determine the extent of the privilege escalation:

```spl
index=windows_security (EventCode=4732 OR EventCode=4728)
| stats count, values(Account_Name) as accounts_who_changed, 
         values(Group_Name) as groups_modified,
         earliest(_time) as first_seen, latest(_time) as last_seen 
  by Account_Name, Account_Domain, Group_Name
| eval duration=round((last_seen - first_seen)/60, 2)
| convert ctime(first_seen) ctime(last_seen)
| sort -count
```

**This query provides:**
- Account that made the privilege change
- Group that was modified (e.g., "Administrators")
- Number of privilege escalations
- Timeline of privilege escalation activity
- Duration of activity
- Domain context

**Key Questions:**
- Which user account was elevated?
- Who made the change?
- Which group was modified?
- How many privilege escalations occurred?
- When did the escalation happen?
- Is this part of a larger attack chain?

**Step 2: Identify the Escalated User**

**Critical:** Determine which user account was granted elevated privileges:

**Primary Query (Extract Member from Raw Event):**
```spl
index=windows_security EventCode=4732 Group_Name="Administrators"
| rex field=_raw "Member:\s+Security ID:\s+(?<member_sid>[^\r\n]+)"
| rex field=_raw "Account Name:\s+(?<member_account>[^\r\n]+)" max_match=0
| table _time, Account_Name, Account_Domain, Group_Name, Group_Domain, member_sid, member_account
| sort -_time
```

> **Note:** The member name (who was added) may not appear directly in extracted fields. The `Account_Name` field shows who made the change (Subject), not who was added. Use `rex` to extract the member's Security ID and account name from the `_raw` field.

**Alternative Query (Who Made the Change):**
```spl
index=windows_security EventCode=4732 Group_Name="Administrators"
| stats count, values(Account_Name) as who_changed, 
         values(Account_Domain) as source_domain
  by Group_Name, Group_Domain
| table Group_Name, Group_Domain, who_changed, source_domain, count
```

**Detailed View (All Fields):**
```spl
index=windows_security EventCode=4732 Group_Name="Administrators"
| table _time, Account_Name, Account_Domain, Group_Name, Group_Domain, ComputerName
| sort -_time
```

**If a user was added to Administrators group, this indicates successful privilege escalation. Escalate immediately.**

**Escalation Criteria:**
- ✅ **Privilege escalation is CRITICAL and can follow ANY attack type.** Investigate all related playbooks:
  - **If preceded by credential access:** Refer to **Playbook 1: Brute Force Attack** - review initial credential compromise (Event ID 4625/4624)
  - **If preceded by execution:** Refer to **Playbook 2: Suspicious PowerShell** - check for PowerShell execution that led to escalation
  - **If followed by lateral movement:** Monitor **Playbook 4: Lateral Movement (SMB)** - check for network logons (Event ID 4624, Logon Type 3)
  - **If followed by data exfiltration:** Monitor **Playbook 5: Data Exfiltration** - check for outbound connections (Event ID 3) to suspicious destinations

**Step 3: Check Who Made the Change**

Identify the account that performed the escalation:

**Primary Query:**
```spl
index=windows_security EventCode=4732
| stats count by Account_Name, Account_Domain, Group_Name
| sort -count
```

**Enhanced Query (With Domain Context):**
```spl
index=windows_security (EventCode=4732 OR EventCode=4728)
| stats count by Account_Name, Account_Domain, Group_Name, Group_Domain
| sort -count
```

**This helps identify:**
- Whether the change was made by an authorized administrator
- Whether the change was made by a compromised account
- The source domain of the account making the change
- How many times each account made privilege changes
- Which groups were affected by each account

**Step 4: Timeline Analysis**

Understand the privilege escalation pattern over time:

```spl
index=windows_security (EventCode=4732 OR EventCode=4728 OR EventCode=4624)
| eval event_type=case(EventCode=4732, "Privilege Escalation", 
                      EventCode=4728, "Group Membership Change",
                      EventCode=4624, "Logon", 1=1, "Other")
| timechart count by event_type span=5m
```

**Alternative Timeline Views:**

**By Group Name:**
```spl
index=windows_security EventCode=4732
| timechart count by Group_Name span=5m
```

**By Account (Who Made Changes):**
```spl
index=windows_security EventCode=4732
| timechart count by Account_Name span=5m
```

**Simple Count Over Time:**
```spl
index=windows_security EventCode=4732
| timechart count span=5m
```

**This helps identify:**
- When privilege escalation occurred
- Correlation with logon events
- Attack timeline and sequence
- Whether escalation was part of a larger attack
- Frequency of privilege changes
- Which accounts are making changes

**Step 5: Check for Related Activity**

Determine if privilege escalation is part of a larger attack chain:

**Simple Approach (Start Here):**
First, check for other events around the same time period:

```spl
index=windows_security (EventCode=4732 OR EventCode=4624 OR EventCode=4648 OR EventCode=4672)
| table _time, EventCode, Account_Name, Account_Domain, Group_Name
| sort -_time
```

**Intermediate Approach (Categorize Events):**
Add event type labels to make it easier to understand:

```spl
index=windows_security (EventCode=4732 OR EventCode=4624 OR EventCode=4648 OR EventCode=4672)
| eval event_type=case(EventCode=4732, "Privilege Escalation", 
                      EventCode=4624, "Logon", 
                      EventCode=4648, "Explicit Credential", 
                      EventCode=4672, "Admin Logon", 1=1, "Other")
| table _time, EventCode, event_type, Account_Name, Account_Domain, Group_Name
| sort -_time
```

> **Learning Note:** When I first started, I would just look at Event ID 4732 by itself. As I learned more, I realized that privilege escalation rarely happens in isolation - it's usually part of an attack chain..

**Advanced Approach (Attack Chain Correlation):**
> **Advanced Note:** For deeper analysis, I think there is a better spl command for this.

**This helps identify:**
- Who logged in before making the change
- If there were other suspicious activities
- The full attack chain
- Timeline of events leading to escalation

**Step 6: Verify Current Group Membership**

**On Windows 10 VM (PowerShell as Administrator):**

```powershell
# Check current administrators group membership
Get-LocalGroupMember -Group "Administrators" | 
    Select-Object Name, PrincipalSource, ObjectClass

# Check if specific user is still in the group (replace <USERNAME>)
Get-LocalGroupMember -Group "Administrators" | 
    Where-Object {$_.Name -like "*<USERNAME>*"}
```

> **Troubleshooting:** In my lab, I use `Get-LocalGroupMember` for local accounts since I don't have Active Directory.

**Step 7: Investigate All Associated Alerts**

- Review and clear ALL alerts associated with the impacted assets
- Check for related security events (logons, credential usage, process execution)
- Document all findings

> **Note:** If queries don't work, see [Field Naming and Extraction](../../Phase8_Incident_Response_Playbooks.md#-field-naming-and-extraction) for the standard field discovery process.

**Confirmed Field Names for This Environment (Event ID 4732):**
- `Account_Name` - Who made the change (Subject)
- `Account_Domain` - Domain of the account
- `Group_Name` - Group that was modified (e.g., "Administrators")
- `Group_Domain` - Domain of the group (e.g., "Builtin")
- `ComputerName` - Computer where event occurred
- `EventCode` - Event ID (4732 or 4728)

**Note:** The member name (who was added) may need to be extracted from `_raw` using `rex` patterns.

---

### 3. Containment

**Plan containment events** where these steps are launched together (or in coordinated fashion), with appropriate teams ready to respond to any disruption. **Consider the timing and tradeoffs** of containment actions: your response has consequences.

#### 3.1 Immediate Containment (0-5 minutes)

1. **Remove User from Administrators Group**
   ```powershell
   # On Windows 10 VM (PowerShell as Administrator)
   # Remove user from Administrators group immediately
   net localgroup administrators <USERNAME> /delete
   
   # Verify removal
   Get-LocalGroupMember -Group "Administrators" | 
       Where-Object {$_.Name -like "*<USERNAME>*"}
   # Should return nothing if successful
   ```

2. **Disable the Compromised Account**
   ```powershell
   # Disable the account immediately to prevent further access
   Disable-LocalUser -Name <USERNAME>
   
   # Or lock the account
   net user <USERNAME> /active:no
   
   # Verify account is disabled
   Get-LocalUser -Name <USERNAME> | Select-Object Name, Enabled
   ```

3. **Check for Active Sessions**
   ```powershell
   # Check for active RDP sessions
   query session
   
   # Check for active user sessions
   Get-CimInstance Win32_LogonSession | 
       Where-Object {$_.LogonType -eq 10} | 
       Select-Object LogonId, AuthenticationPackage
   
   # If user has active session, disconnect it
   # logoff <SESSION_ID>
   ```

> **Critical Action:** Removing the user from Administrators group must be done immediately. Even a few minutes of administrative access can allow an attacker to install persistence mechanisms, access sensitive data, or modify security controls.

#### 3.2 Short-term Containment (5-15 minutes)

1. **Review All Recent Privilege Changes**
   ```spl
   index=windows_security (EventCode=4732 OR EventCode=4728)
   | stats count by Account_Name, Group_Name
   | sort -count
   ```

2. **Check for Backdoor Accounts**
   ```powershell
   # List all local users
   Get-LocalUser | Select-Object Name, Enabled, LastLogon
   
   # Check for recently created accounts
   Get-LocalUser | Where-Object {$_.Enabled -eq $true} | 
       Select-Object Name, Enabled, Description
   
   # Check for accounts with suspicious names
   Get-LocalUser | Where-Object {
       $_.Name -like "*admin*" -or 
       $_.Name -like "*test*" -or 
       $_.Name -like "*temp*"
   } | Select-Object Name, Enabled, Description
   ```

3. **Monitor for Continued Activity**
   ```spl
   index=windows_security EventCode=4624 Account_Name=<USERNAME>
   | stats count
   | eval status=if(count > 0, "ACTIVE", "INACTIVE")
   | table status, count
   ```

4. **Check for Persistence Mechanisms**
   ```powershell
   # Check scheduled tasks created by the user
   Get-ScheduledTask | Where-Object {$_.Principal.UserId -like "*<USERNAME>*"}
   
   # Check services
   Get-Service | Where-Object {$_.StartName -like "*<USERNAME>*"}
   
   # Check startup programs
   Get-CimInstance Win32_StartupCommand | 
       Where-Object {$_.User -like "*<USERNAME>*"}
   ```

---

### 4. Eradication

**Plan eradication events** where these steps are launched together (or in coordinated fashion), with appropriate teams ready to respond to any disruption.

#### Step 1: Investigate How Privilege Escalation Occurred

Determine the root cause and attack vector:

**Check for privilege escalation events:**
```spl
index=windows_security (EventCode=4732 OR EventCode=4728)
| table _time, Account_Name, Account_Domain, Group_Name, Group_Domain
| sort -_time
```

**Check for logon events from the same account:**
```spl
index=windows_security EventCode=4624 Account_Name="<ACCOUNT_NAME>"
| stats count, values(Logon_Type) as logon_types, 
         earliest(_time) as first_logon, 
         latest(_time) as last_logon by Account_Name
| table Account_Name, logon_types, first_logon, last_logon, count
```

> **Note:** I check these queries separately and manually correlate the results. This aligns with our [correlation methodology policy](../../Phase8_Incident_Response_Playbooks.md#-correlation-methodology-manual-vs-automated) - manual correlation is the preferred approach for this homelab.

**What to look for:**
- How the account that made the change initially gained access
- Whether the change was made by an authorized administrator
- Whether the account was compromised
- Timeline of events leading to escalation
- Correlation between logon events and privilege escalation

#### Step 2: Review Security Logs for Initial Compromise

Identify how the attacker gained initial access:

```spl
index=windows_security EventCode=4624 Account_Name=<USERNAME>
| stats count, values(Logon_Type) as logon_types, 
         values(Source_Network_Address) as source_ips
  by Account_Name
| table Account_Name, logon_types, source_ips, count
```

**Check for:**
- Unusual logon types
- Unusual source IP addresses
- Recent successful logons before escalation
- Correlation with brute force attacks (Event ID 4625)

#### Step 3: Document Attack Details**

Create incident report with:
- User account that was elevated
- Account that made the change
- Group that was modified
- Timeline of events
- How initial access was gained
- Whether any persistence mechanisms were installed
- Whether any data was accessed

#### Step 4: Review Security Controls**

- Verify audit policies are enabled for group membership changes
- Check who has permission to modify group membership
- Review account management policies
- Assess if additional monitoring is needed
- Verify least privilege principle is being followed

---

### 5. Recovery

#### Step 1: Verify User Removed from Group

**On Windows 10 VM (PowerShell as Administrator):**

```powershell
# Confirm user is no longer in Administrators group
Get-LocalGroupMember -Group "Administrators" | 
    Select-Object Name | 
    Where-Object {$_.Name -like "*<USERNAME>*"}
# Should return nothing if successful
```

#### Step 2: Reset Account Password (if account is kept)**

```powershell
# Reset password with strong password
net user <USERNAME> <NEW_STRONG_PASSWORD>

# Re-enable account if needed (after password reset and investigation)
Enable-LocalUser -Name <USERNAME>
```

**Note:** Only re-enable the account after thorough investigation and if it's determined the account itself wasn't compromised. If the account was compromised, consider deleting it entirely.

#### Step 3: Review Group Membership Policies**

- Verify who has permission to modify group membership
- Review audit policies for group changes
- Consider implementing approval workflows
- Document baseline group memberships
- Implement change management processes

#### Step 4: Monitor for Recurrence**

```spl
index=windows_security (EventCode=4732 OR EventCode=4728)
| stats count by Account_Name, Group_Name
| where Group_Name="*Administrators*"
| eval status=if(count > 0, "DETECTED", "CLEAN")
| table Account_Name, Group_Name, count, status
```

---

### 6. Post-Incident Activities

**Conduct post-incident review** to identify improvements and document lessons learned.

#### 6.1 Incident Documentation

Document the following:
- Incident ID and timeline
- User account that was elevated
- Account that made the change
- Group that was modified
- How initial access was gained
- Timeline of events
- Containment actions taken
- Eradication steps performed
- Recovery procedures executed
- Response time metrics (MTTD, MTTR, MTTC)

#### 6.2 Lessons Learned

**Key Takeaways:**
- Windows Event IDs 4732 (local group) and 4728 (global group) are critical indicators for privilege escalation
- Real-time alerting is essential for critical severity incidents
- Immediate containment (< 5 minutes) is required to prevent further compromise
- Group membership changes must be monitored continuously
- Privilege escalation often follows initial credential compromise
- Administrative access grants complete system control

**Technical Considerations:**
- Event ID 4732 indicates member added to security-enabled local group
- Event ID 4728 indicates member added to security-enabled global group
- Field names vary between Splunk environments - verify using `fieldsummary`
- `Get-LocalGroupMember` works for local accounts; `Get-ADGroupMember` for domain accounts
- Privilege escalation can occur through multiple vectors (local accounts, domain accounts, service accounts)
- Process of verifying current group membership on actual system is critical

**Detection Improvements:**
- [ ] Ensure real-time alerting for privilege escalation (critical severity)
- [ ] Add correlation with account creation events (Event ID 4720)
- [ ] Monitor for privilege changes outside business hours
- [ ] Add detection for multiple privilege escalations in short time period
- [ ] Correlate with successful logon events (Event ID 4624)
- [ ] Add detection for unusual accounts being elevated
- [ ] Implement baseline monitoring for group membership

**Prevention Measures:**
- [ ] Implement least privilege principle
- [ ] Require approval workflow for admin group changes
- [ ] Enable detailed auditing for group membership changes
- [ ] Regular review of administrator group membership
- [ ] Implement change management processes
- [ ] Document baseline group memberships
- [ ] Restrict who can modify group membership
- [ ] Use privileged access management (PAM) solutions
- [ ] Implement just-in-time (JIT) access for administrative privileges
- [ ] Patch asset vulnerabilities
- [ ] Perform routine inspections of controls

**Response Improvements:**
- [ ] Document response time (MTTD, MTTR, MTTC) - target < 5 minutes for critical
- [ ] Create automated script to remove users from groups
- [ ] Improve investigation queries for privilege escalation chains
- [ ] Develop playbook for different privilege escalation vectors
- [ ] Practice incident response scenarios more frequently
- [ ] Create runbook for quick reference during incidents
- [ ] Consider automating containment measures using orchestration tools

**Process Improvements:**
- [ ] Perform routine cyber hygiene due diligence
- [ ] Learn more about privilege escalation techniques (MITRE ATT&CK)
- [ ] Update incident response plan based on findings
- [ ] Get feedback from experienced SOC analysts if possible
- [ ] Review and update group membership policies regularly
- [ ] Conduct tabletop exercises for privilege escalation scenarios

**Resources I Used:**
- NIST SP 800-61 Computer Security Incident Handling Guide
- Splunk documentation for SPL queries
- MITRE ATT&CK framework (T1078.003 - Local Accounts)
- Windows Security Event Log documentation
- Sample playbooks from AWS, Microsoft, and other organizations

---

## 📚 References and Learning Resources

**Resources I consulted while creating this playbook:**
- NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide
- Splunk SPL documentation and tutorials
- MITRE ATT&CK framework (T1078.003 - Local Accounts)
- Windows Security Event Log documentation (Event IDs 4732, 4728)
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

