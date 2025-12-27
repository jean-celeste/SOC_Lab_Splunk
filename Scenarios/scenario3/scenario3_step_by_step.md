# Scenario 3: Privilege Escalation Attempt - Live Guide

## Overview
Simulate privilege escalation by adding a user to the administrators group. This is a critical security event that SOC analysts must detect immediately.

---

## Step 1: Prepare Windows 10 VM

### 1.1 Create a Test User (if not already exists)

**On Windows 10 VM:**

1. **Open PowerShell as Administrator**
   - Press `Windows Key + X`
   - Select "Windows PowerShell (Admin)" or "Terminal (Admin)"

2. **Create a test user:**
   ```powershell
   # Create test user
   net user testuser TestPass123! /add
   ```

3. **Verify the user was created:**
   ```powershell
   net user testuser
   ```

   **Expected output:** Should show user details including account active status

4. **Check current administrators group:**
   ```powershell
   net localgroup administrators
   ```

   **Note:** `testuser` should NOT be in the administrators list yet

---

## Step 2: Execute Privilege Escalation

### 2.1 Add User to Administrators Group

**Still in Admin PowerShell on Windows 10:**

1. **Add testuser to administrators group:**
   ```powershell
   net localgroup administrators testuser /add
   ```

   **Expected output:** `The command completed successfully.`

2. **Verify the change:**
   ```powershell
   net localgroup administrators
   ```

   **What to look for:**
   - `testuser` should now appear in the administrators list
   - This confirms the privilege escalation was successful

3. **Optional: Test the elevated privileges:**
   ```powershell
   # Switch to testuser context (if you want to test)
   runas /user:testuser cmd
   # Enter password: TestPass123!
   # Then try: net localgroup administrators
   ```

---

## Step 3: Verify in Splunk

### 3.1 Wait for Logs to Arrive

**Important:** Wait 1-2 minutes after adding the user for Windows Security events to be forwarded to Splunk.

### 3.2 Open Splunk Web UI

1. Open browser on your host machine
2. Navigate to: `http://192.168.1.7:8000`
3. Login with your Splunk credentials

### 3.3 Search for Privilege Escalation Events

**In Splunk Search bar, paste:**
```spl
index=windows_security EventCode=4732
| head 10
```

**What you should see:**
- Event ID 4732 (Member added to security-enabled global group)
- Recent timestamp (within last few minutes)
- MemberName should be `testuser`
- GroupName should be `Administrators`

### 3.4 Run Detection Query (CORRECTED - Based on Your Environment)

**Based on your field structure, use these queries:**

**Primary Detection Query (Using Actual Field Names):**
```spl
index=windows_security EventCode=4732
| stats count by Account_Name, Group_Name
```

**What this shows:**
- `Account_Name`: Who made the change (Subject - the person who ran the command)
- `Group_Name`: Which group was modified (e.g., "Administrators")
- `count`: Number of times this occurred

**Enhanced Detection Query (With Domain Info):**
```spl
index=windows_security EventCode=4732
| stats count by Account_Name, Account_Domain, Group_Name, Group_Domain
```

**What to look for:**
- Account_Name: Shows who made the change (e.g., "JC")
- Group_Name: Shows the group (e.g., "Administrators")
- Count: Should show 1 (or more if you ran it multiple times)

### 3.6 Detailed View (CORRECTED - Based on Your Environment)

**See all relevant fields using actual field names:**

**Primary Detailed View:**
```spl
index=windows_security EventCode=4732
| table _time, Account_Name, Account_Domain, Group_Name, Group_Domain, ComputerName
| sort -_time
```

**Enhanced View (Extract Member Name from Raw if needed):**
```spl
index=windows_security EventCode=4732
| rex field=_raw "Member:\s+Security ID:\s+(?<member_sid>[^\r\n]+)"
| rex field=_raw "Account Name:\s+(?<member_account>[^\r\n]+)" max_match=0
| table _time, Account_Name, Account_Domain, Group_Name, Group_Domain, member_sid, member_account
| sort -_time
```

**This shows:**
- `_time`: When the event occurred
- `Account_Name`: Who made the change (Subject)
- `Account_Domain`: Domain of the account
- `Group_Name`: Which group was modified (e.g., "Administrators")
- `Group_Domain`: Domain of the group (e.g., "Builtin")
- `member_sid`: Security ID of the member added (extracted from raw)

### 3.7 Enhanced Detection Query (CORRECTED - Administrators Only)

**Look for privilege escalation to Administrators specifically:**

**Primary Query (Using Actual Field Names):**
```spl
index=windows_security EventCode=4732 Group_Name="Administrators"
| table _time, Account_Name, Account_Domain, Group_Name, Group_Domain
| sort -_time
```

**Alternative (Case-insensitive search):**
```spl
index=windows_security EventCode=4732
| where Group_Name="Administrators" OR Group_Name="*Domain Admins*" OR _raw LIKE "%Administrators%"
| table _time, Account_Name, Account_Domain, Group_Name, Group_Domain
| sort -_time
```

**This filters for:**
- Only Administrators or Domain Admins group changes
- Most critical privilege escalations
- Shows who made the change and which group was affected

### 3.8 Timeline View (CORRECTED - Based on Your Environment)

**See privilege escalation events over time:**

**Primary Timeline (Using Actual Field Names):**
```spl
index=windows_security EventCode=4732
| timechart count by Group_Name
```

**Alternative: Count by Account (Who Made Changes)**
```spl
index=windows_security EventCode=4732
| timechart count by Account_Name
```

**Simple Count Over Time:**
```spl
index=windows_security EventCode=4732
| timechart count
```

**This visualizes:**
- When privilege escalations occurred
- Which groups were affected
- Frequency of changes
- Who is making the changes

---

## Step 4: Additional Analysis

### 4.1 Find Who Made the Change (CORRECTED)

**Identify the account that performed the escalation:**

**Primary Query (Using Actual Field Names):**
```spl
index=windows_security EventCode=4732
| stats count by Account_Name, Account_Domain, Group_Name
| sort -count
```

**Enhanced Query (With Domain Context):**
```spl
index=windows_security EventCode=4732
| stats count by Account_Name, Account_Domain, Group_Name, Group_Domain
| sort -count
```

**This shows:**
- Who made the privilege escalation changes
- How many times each account made changes
- Which groups were affected

### 4.2 Check for Related Events (CORRECTED)

**Look for other related security events around the same time:**

**Primary Correlation Query:**
```spl
index=windows_security (EventCode=4732 OR EventCode=4624 OR EventCode=4648 OR EventCode=4672)
| eval event_type=case(EventCode=4732, "Privilege Escalation", EventCode=4624, "Logon", EventCode=4648, "Explicit Credential", EventCode=4672, "Admin Logon")
| table _time, EventCode, event_type, Account_Name, Account_Domain, Group_Name
| sort -_time
```

**Enhanced Correlation (Shows Attack Chain):**
```spl
index=windows_security EventCode=4732
| eval privilege_escalation_time=_time
| eval account_who_changed=Account_Name
| join type=outer account_who_changed [
    search index=windows_security (EventCode=4624 OR EventCode=4648 OR EventCode=4672)
    | eval account_who_changed=Account_Name
]
| table _time, EventCode, Account_Name, Account_Domain, Group_Name, privilege_escalation_time
| sort -_time
```

**This helps identify:**
- Who logged in before making the change
- If there were other suspicious activities
- The full attack chain
- Timeline of events

### 4.3 Alert-Ready Query (CORRECTED - Ready for Splunk Alerts)

**Query formatted for Splunk alerts (using actual field names):**

**Primary Alert Query:**
```spl
index=windows_security EventCode=4732 Group_Name="Administrators"
| stats count by Account_Name, Account_Domain, Group_Name
| where count > 0
```

**Enhanced Alert Query (Includes Domain Admins):**
```spl
index=windows_security EventCode=4732
| where Group_Name="Administrators" OR Group_Name="*Domain Admins*" OR _raw LIKE "%Administrators%" OR _raw LIKE "%Domain Admins%"
| stats count by Account_Name, Account_Domain, Group_Name, Group_Domain
| where count > 0
```

**Alert Query with Context:**
```spl
index=windows_security EventCode=4732 Group_Name="Administrators"
| stats count, values(Account_Domain) as domains, values(Group_Domain) as group_domains by Account_Name, Group_Name
| where count > 0
| eval severity="HIGH"
| eval description="User " + Account_Name + " added member to " + Group_Name + " group"
```

**This query:**
- Focuses on critical groups only (Administrators)
- Shows who made the change
- Includes domain context
- Ready to convert to a Splunk alert
- Includes severity and description for alerting

---

## ✅ Success Checklist

- [/] Test user created on Windows 10
- [/] User successfully added to administrators group
- [/] Event ID 4732 visible in Splunk
- [/] Detection query shows the privilege escalation
- [/] MemberName shows `testuser`
- [/] SubjectUserName shows who made the change
- [/] GroupName shows `Administrators`

---

## 🐛 Troubleshooting

### No Event ID 4732 appearing?

1. **Check if the command actually worked:**
   ```powershell
   # On Windows, verify user is in administrators group
   net localgroup administrators
   # Should show testuser
   ```

2. **Check Windows Event Viewer directly:**
   - Open Event Viewer
   - Navigate to: Windows Logs → Security
   - Filter for Event ID 4732
   - If events are here but not in Splunk, check Splunk Forwarder

3. **Verify Splunk Forwarder is collecting Security logs:**
   ```powershell
   # Check inputs.conf
   type "C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf"
   # Should show [WinEventLog://Security] with disabled = false
   ```

4. **Check Splunk Forwarder service:**
   ```powershell
   Get-Service SplunkForwarder
   # Should show "Running"
   ```

### Field names not matching?

**CRITICAL: First discover the actual field names:**

**Step 1: View raw event**
```spl
index=windows_security EventCode=4732
| head 1
```

**Step 2: Get field summary**
```spl
index=windows_security EventCode=4732
| head 1
| fieldsummary
```

**Step 3: View all fields**
```spl
index=windows_security EventCode=4732
| head 1
| table *
```

**Step 4: If fields are in XML format, use spath**
```spl
index=windows_security EventCode=4732
| head 1
| spath
| table *
```

**✅ CONFIRMED FIELD NAMES FOR YOUR ENVIRONMENT:**
- **Who made change:** `Account_Name` (Subject - the person who ran the command)
- **Account domain:** `Account_Domain` (Domain of the account)
- **Group name:** `Group_Name` (e.g., "Administrators")
- **Group domain:** `Group_Domain` (e.g., "Builtin")
- **Computer:** `ComputerName`
- **Event code:** `EventCode`

**Note:** The member name (who was added) may show as "-" in Account_Name field. To extract the member's Security ID from raw:
```spl
index=windows_security EventCode=4732
| rex field=_raw "Member:\s+Security ID:\s+(?<member_sid>[^\r\n]+)"
| table _time, Account_Name, Group_Name, member_sid
```

### Event ID 4732 not showing up?

**Try searching for related events:**
```spl
# Search for any privilege-related events
index=windows_security (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| head 20
```

**Alternative: Search by group name:**
```spl
index=windows_security "*Administrators*"
| head 20
```

---

## 📊 What You Should See

### Expected Splunk Results:

1. **Basic Query Results:**
   - Event ID 4732 entries
   - Recent timestamps
   - MemberName: `testuser`
   - GroupName: `BUILTIN\Administrators` or `Administrators`

2. **Detection Query Results:**
   - Shows count of privilege escalations
   - MemberName and SubjectUserName clearly visible
   - Helps identify who was added and by whom

3. **Detailed View Results:**
   - All relevant fields displayed
   - Easy to see the full context
   - Sorted by most recent first

---

## 📸 Screenshot Tips

Take screenshots of:
1. PowerShell command adding user to administrators group
2. Verification showing testuser in administrators group
3. Splunk search results showing Event ID 4732
4. Detection query results showing the privilege escalation
5. Detailed view showing all relevant fields
6. Timeline chart showing when the escalation occurred

These demonstrate your ability to detect critical privilege escalation attacks!

---

## 🎓 Learning Points

**Why this matters:**
- Privilege escalation is a critical security event
- Adding users to Administrators group grants full system access
- Event ID 4732 is a high-priority alert in SOC environments
- Immediate detection and response is essential

**Real-world context:**
- Attackers often escalate privileges after initial access
- This is part of the MITRE ATT&CK framework (T1078)
- SOC analysts must detect this within minutes
- Often part of a larger attack chain

**Related MITRE ATT&CK Techniques:**
- **T1078:** Valid Accounts
- **T1078.002:** Domain Accounts
- **T1078.003:** Local Accounts

---

## 🔄 Cleanup (Optional)

**After testing, you may want to remove the test user:**

```powershell
# Remove testuser from administrators group
net localgroup administrators testuser /delete

# Optional: Delete the test user entirely
net user testuser /delete
```

**Note:** Only do this if you don't need the user for other scenarios!

---

## ✅ Ready for Next Scenario?

Once you've verified:
- [ ] Privilege escalation event is visible in Splunk
- [ ] Detection queries work correctly
- [ ] You understand what Event ID 4732 means
- [ ] You can identify who was added and by whom

You're ready for **Scenario 4: Lateral Movement (SMB)**!

---

## 💡 Pro Tips

1. **Event ID 4732 is critical** - This should trigger an immediate alert in production
2. **Check the SubjectUserName** - This tells you who made the change (could be an attacker)
3. **Look for patterns** - Multiple privilege escalations from the same account is suspicious
4. **Correlate with other events** - Check for failed logins or other suspicious activity around the same time
5. **Document everything** - Screenshots and notes help with incident response

Good luck! 🚀

