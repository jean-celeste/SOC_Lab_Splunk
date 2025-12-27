# 🔔 Phase 6: Splunk Alerts & Correlation Rules

This guide walks you through creating Splunk alerts for each attack scenario. Alerts automatically notify you when security events are detected, which is essential for SOC operations.

## 📋 Prerequisites Checklist

Before starting, verify:
- [ ] All 5 attack scenarios have been executed and verified
- [ ] Detection queries work correctly in Splunk
- [ ] You can access Splunk Web UI at `http://192.168.1.7:8000`
- [ ] You have admin access to Splunk (to create alerts)

---

## 🎯 Overview: What Are Splunk Alerts?

Splunk alerts are saved searches that run automatically on a schedule. When the search returns results, the alert "triggers" and can:
- Send email notifications
- Log to a summary index
- Execute scripts
- Display in the Splunk UI

For this lab, we'll create alerts that:
- Run every 5 minutes (or real-time for critical alerts)
- Trigger when attack patterns are detected
- Log to a summary index for tracking

---

## 📊 Alert Configuration Overview

We'll create 5 alerts, one for each attack scenario:

1. **Alert 1: Brute Force Attack Detection**
   - Detects multiple failed login attempts (Event ID 4625)
   - Threshold: > 5 failed attempts from same IP

2. **Alert 2: Suspicious PowerShell Detection**
   - Detects encoded PowerShell commands (Event ID 1)
   - Looks for `-enc` parameter or suspicious patterns

3. **Alert 3: Privilege Escalation Detection**
   - Detects users added to Administrators group (Event ID 4732)
   - Critical alert - should trigger immediately

4. **Alert 4: Lateral Movement Detection (SMB)**
   - Detects network logons via SMB (Event ID 4624, Logon_Type=3)
   - Threshold: Multiple logons from same IP

5. **Alert 5: Data Exfiltration Detection**
   - Detects suspicious outbound connections (Sysmon Event ID 3)
   - Filters out normal traffic (ports 53, 80, 443)

---

## 🔴 Alert 1: Brute Force Attack Detection

### Step 1: Create the Alert

1. **Open Splunk Web UI:** `http://192.168.1.7:8000`

2. **Navigate to Alerts:**
   - Click **Settings** (top right)
   - Under **Knowledge**, click **Searches, reports, and alerts**
   - Click **New Alert** button

3. **Configure the Alert:**

   **Search Query:**
   ```spl
   index=windows_security EventCode=4625
   | stats count by Account_Name, Source_Network_Address
   | where count > 5
   ```

   **Alert Settings:**
   - **Title:** `Brute Force Attack Detected`
   - **Description:** `Multiple failed login attempts detected from same source IP`
   - **Alert Type:** `Number of Results`
   - **Trigger Condition:** `Greater than 0`
   - **Trigger When:** `The number of results is greater than 0`

4. **Schedule:**
   - **Schedule:** `Run every 5 minutes`
   - **Time Range:** `Last 5 minutes`
   - **Earliest Time:** `-5m@m`
   - **Latest Time:** `now`

5. **Actions:**
   - **Add Actions:** Check `Add to Summary Index`
   - **Summary Index:** `summary` (or create new index `alerts`)
   - **Optional:** Add email action if configured

6. **Permissions:**
   - **App:** `search`
   - **Sharing:** `Private` (or share with your app)

7. **Click Save**

### Step 2: Test the Alert

1. **Manually run the search** to verify it works:
   ```spl
   index=windows_security EventCode=4625
   | stats count by Account_Name, Source_Network_Address
   | where count > 5
   ```

2. **Wait for the alert to trigger** (or trigger it manually by running Scenario 1 again)

3. **Check alert status:**
   - Go to **Activity** → **Triggered Alerts**
   - You should see the alert listed when it triggers

### Step 3: Enhanced Alert Query (Optional)

For more detailed information, use this enhanced query:

```spl
index=windows_security EventCode=4625
| stats count, values(Account_Name) as accounts, earliest(_time) as first_attempt, latest(_time) as last_attempt by Source_Network_Address
| where count > 5
| eval duration_minutes=round((last_attempt - first_attempt)/60, 2)
| eval severity=case(count > 20, "HIGH", count > 10, "MEDIUM", 1=1, "LOW")
| eval description="Brute force attack: " + count + " failed attempts from " + Source_Network_Address + " targeting accounts: " + accounts
```

---

## 🔴 Alert 2: Suspicious PowerShell Detection

### Step 1: Create the Alert

1. **Navigate to:** Settings → Searches, reports, and alerts → New Alert

2. **Configure the Alert:**

   **Search Query:**
   ```spl
   index=sysmon EventCode=1 Image="*powershell.exe" CommandLine="*-enc*"
   | stats count by Image, CommandLine, User
   | where count > 0
   ```

   **Alert Settings:**
   - **Title:** `Suspicious PowerShell Execution Detected`
   - **Description:** `PowerShell with encoded commands or suspicious patterns detected`
   - **Alert Type:** `Number of Results`
   - **Trigger Condition:** `Greater than 0`

3. **Schedule:**
   - **Schedule:** `Run every 5 minutes`
   - **Time Range:** `Last 5 minutes`

4. **Actions:**
   - **Add to Summary Index:** `summary` (or `alerts`)

5. **Click Save**

### Step 2: Enhanced Detection (Optional)

For broader PowerShell detection:

```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| where CommandLine LIKE "%enc%" OR CommandLine LIKE "%download%" OR CommandLine LIKE "%invoke%" OR CommandLine LIKE "%hidden%" OR CommandLine LIKE "%noprofile%"
| stats count, values(CommandLine) as commands by Image, User, ParentImage
| where count > 0
| eval severity="HIGH"
| eval description="Suspicious PowerShell activity: " + count + " instances with suspicious patterns"
```

---

## 🔴 Alert 3: Privilege Escalation Detection (CRITICAL)

### Step 1: Create the Alert

1. **Navigate to:** Settings → Searches, reports, and alerts → New Alert

2. **Configure the Alert:**

   **Search Query:**
   ```spl
   index=windows_security EventCode=4732 Group_Name="Administrators"
   | stats count by Account_Name, Account_Domain, Group_Name
   | where count > 0
   ```
   
   **Note:** This basic query shows who made the change (Account_Name). If you need to identify which member was added to the group, use the enhanced query in Step 2, which extracts the member Security ID (SID) from the raw event data.

   **Alert Settings:**
   - **Title:** `CRITICAL: Privilege Escalation Detected`
   - **Description:** `User added to Administrators group - IMMEDIATE ACTION REQUIRED`
   - **Alert Type:** `Number of Results`
   - **Trigger Condition:** `Greater than 0`

3. **Schedule:**
   - **Schedule:** `Run every 1 minute` (more frequent for critical alerts)
   - **Time Range:** `Last 1 minute`
   - **Earliest Time:** `-1m@m`
   - **Latest Time:** `now`

4. **Actions:**
   - **Add to Summary Index:** `summary` (or `alerts`)
   - **Severity:** `High` (if available)

5. **Click Save**

### Step 2: Enhanced Alert (Includes Domain Admins with Member SID Extraction)

**IMPORTANT:** EventCode 4732 may show member account name as "-" in the Account_Name field. This enhanced query extracts the member Security ID (SID) directly from the raw event data for accurate identification.

```spl
index=windows_security EventCode=4732
| rex field=_raw "(?s)Subject:.*?Account Name:\s+(?<subject_account>[^\r\n]+)"
| rex field=_raw "(?s)Member:.*?Security ID:\s+(?<member_sid>[^\r\n]+)"
| rex field=_raw "(?s)Group:.*?Group Name:\s+(?<group_name>[^\r\n]+)"
| where group_name="Administrators" OR group_name="Domain Admins" OR _raw LIKE "%Administrators%" OR _raw LIKE "%Domain Admins%"
| eval subject_account=trim(subject_account), 
     member_sid=trim(member_sid), 
     group_name=trim(group_name)
| stats count, 
        min(_time) as first_seen, 
        max(_time) as last_seen, 
        values(subject_account) as added_by, 
        values(member_sid) as member_sids
        by host, group_name
| where count > 0
| eval severity="CRITICAL"
| eval description="Privilege escalation: Member(s) " + member_sids + " added to " + group_name + " group by " + added_by
| convert ctime(first_seen) ctime(last_seen)
```

**What this query does:**
- Extracts subject account (who made the change) from raw event data
- Extracts member Security ID (SID) - reliable identifier even when account name shows "-"
- Extracts group name and filters for Administrators or Domain Admins
- Includes time context (first_seen, last_seen) with readable timestamps
- Aggregates by host and group name
- Provides severity and descriptive alert message

---

## 🔴 Alert 4: Lateral Movement Detection (SMB)

### Step 1: Create the Alert

1. **Navigate to:** Settings → Searches, reports, and alerts → New Alert

2. **Configure the Alert:**

   **Search Query:**
   ```spl
   index=windows_security EventCode=4624 Logon_Type=3
   | where Source_Network_Address != "-" AND Source_Network_Address != "" AND Source_Network_Address != "::1" AND Source_Network_Address != "127.0.0.1"
   | stats count by Source_Network_Address, Account_Name
   | where count > 5
   ```
   
   **Note:** This query filters for Logon_Type=3 (Network logon) and excludes service logons (Logon_Type=5) and localhost connections. The Account_Name field may contain multiple values separated by newlines - the stats command will aggregate them.

   **Alert Settings:**
   - **Title:** `Lateral Movement Detected (SMB)`
   - **Description:** `Multiple network logons via SMB from same source IP`
   - **Alert Type:** `Number of Results`
   - **Trigger Condition:** `Greater than 0`

3. **Schedule:**
   - **Schedule:** `Run every 5 minutes`
   - **Time Range:** `Last 5 minutes`

4. **Actions:**
   - **Add to Summary Index:** `summary` (or `alerts`)

5. **Click Save**

### Step 2: Enhanced Detection (Optional)

**IMPORTANT:** EventCode 4624 with Logon_Type=3 indicates network logons (SMB, RDP, etc.). This enhanced query includes time context and better account handling.

```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != "" AND Source_Network_Address != "::1" AND Source_Network_Address != "127.0.0.1"
| stats count, 
        min(_time) as first_seen, 
        max(_time) as last_seen, 
        values(Account_Name) as accounts, 
        values(Account_Domain) as domains 
        by Source_Network_Address
| where count > 5
| eval duration_minutes=round((last_seen - first_seen)/60, 2)
| eval severity=case(count > 10, "HIGH", count > 5, "MEDIUM", 1=1, "LOW")
| eval description="Lateral movement: " + count + " SMB logons from " + Source_Network_Address + " using accounts: " + accounts + " (Duration: " + duration_minutes + " minutes)"
| convert ctime(first_seen) ctime(last_seen)
```

**What this query does:**
- Filters for network logons only (Logon_Type=3) - excludes service logons (Logon_Type=5)
- Excludes localhost connections (127.0.0.1, ::1)
- Includes time context (first_seen, last_seen) with readable timestamps
- Aggregates multiple accounts used from same source IP
- Calculates duration of lateral movement activity
- Provides severity based on count threshold
- Creates descriptive alert message

---

## 🔴 Alert 5: Data Exfiltration Detection

### Step 1: Create the Alert

1. **Navigate to:** Settings → Searches, reports, and alerts → New Alert

2. **Configure the Alert:**

   **Search Query:**
   ```spl
   index=sysmon EventCode=3
   | where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443 AND DestinationPort != 3389 AND DestinationPort != 445
   | stats count by Image, DestinationIp, DestinationPort
   | where count > 10
   ```

   **Alert Settings:**
   - **Title:** `Suspicious Outbound Network Connections`
   - **Description:** `Data exfiltration or C2 communication detected via non-standard ports`
   - **Alert Type:** `Number of Results`
   - **Trigger Condition:** `Greater than 0`

3. **Schedule:**
   - **Schedule:** `Run every 5 minutes`
   - **Time Range:** `Last 5 minutes`

4. **Actions:**
   - **Add to Summary Index:** `summary` (or `alerts`)

5. **Click Save**

### Step 2: Enhanced Detection (Targets Attacker IP)

```spl
index=sysmon EventCode=3 DestinationIp=192.168.1.4
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443
| stats count, 
        min(_time) as first_seen, 
        max(_time) as last_seen,
        values(Image) as processes, 
        values(DestinationPort) as ports 
        by DestinationIp
| where count > 0
| eval ports_str=mvjoin(ports, ", ")
| eval processes_str=mvjoin(processes, ", ")
| eval severity="HIGH"
| eval description="Data exfiltration detected: " + count + " connections to attacker IP " + DestinationIp + " on ports: " + ports_str + " from processes: " + processes_str
| convert ctime(first_seen) ctime(last_seen)
```

**What this query does:**
- Filters for connections to specific attacker IP (192.168.1.4)
- Excludes common ports (53, 80, 443)
- Aggregates connections by destination IP
- Converts multivalue fields (ports, processes) to comma-separated strings using `mvjoin()`
- Includes time context (first_seen, last_seen)
- Creates descriptive alert message with all relevant details

---

## 📊 Viewing Alert Results

### Method 1: Triggered Alerts Dashboard

1. **Navigate to:** Activity → Triggered Alerts
2. **View all triggered alerts** with timestamps and details
3. **Click on an alert** to see the search results

### Method 2: Summary Index Query

Query the summary index to see all alert results:

```spl
index=summary
| stats count by search_name, _time
| sort -_time
```

Or see detailed results:

```spl
index=summary
| table _time, search_name, *
| sort -_time
```

### Method 3: Alert Manager

1. **Navigate to:** Settings → Searches, reports, and alerts
2. **Find your alerts** in the list
3. **Click on an alert** to view/edit configuration
4. **View trigger history** for each alert

---

## 🧪 Testing Your Alerts

### Test Each Alert

1. **Execute the corresponding attack scenario** (from Phase 5)
2. **Wait for the alert schedule** (1-5 minutes depending on alert)
3. **Check Triggered Alerts** to see if it fired
4. **Verify the results** match expected detection

### Manual Alert Testing

1. **Go to the alert** in Settings → Searches, reports, and alerts
2. **Click "Open in Search"** to run the query manually
3. **Verify results** appear as expected
4. **Check the schedule** is correct

---

## 📈 Alert Tuning and Optimization

### Adjust Thresholds

If alerts trigger too frequently (false positives):
- **Increase thresholds:** Change `count > 5` to `count > 10`
- **Add filters:** Exclude known-good IPs or accounts
- **Narrow time range:** Reduce the time window

If alerts don't trigger (false negatives):
- **Decrease thresholds:** Change `count > 10` to `count > 5`
- **Broaden time range:** Increase the time window
- **Check field names:** Verify fields exist in your environment

### Example: Whitelist Known Good IPs

```spl
index=windows_security EventCode=4625
| where Source_Network_Address != "192.168.1.7" AND Source_Network_Address != "192.168.1.5"
| stats count by Account_Name, Source_Network_Address
| where count > 5
```

---

## 🔍 Correlation Rules (Advanced)

### Multi-Event Correlation

Detect attack chains by correlating multiple events:

**Example: Brute Force → Privilege Escalation**

```spl
index=windows_security (EventCode=4625 OR EventCode=4732)
| eval attack_phase=case(EventCode=4625, "Brute Force", EventCode=4732, "Privilege Escalation", 1=1, "Other")
| stats count, values(attack_phase) as phases, values(Account_Name) as accounts by Source_Network_Address
| where count > 5 AND match(phases, "Privilege Escalation")
| eval severity="CRITICAL"
| eval description="Attack chain detected: Brute force followed by privilege escalation from " + Source_Network_Address
```

### Time-Based Correlation

Detect events within a time window:

```spl
index=windows_security EventCode=4625
| eval brute_force_time=_time
| eval source_ip=Source_Network_Address
| join type=outer source_ip [
    search index=windows_security EventCode=4624 Logon_Type=3
    | eval source_ip=Source_Network_Address
    | eval successful_logon_time=_time
]
| where successful_logon_time - brute_force_time < 300
| eval time_diff=successful_logon_time - brute_force_time
| table _time, source_ip, brute_force_time, successful_logon_time, time_diff
```

---

## ✅ Success Checklist

After creating all alerts, verify:

- [ ] All 5 alerts created successfully
- [ ] Each alert has correct search query
- [ ] Schedule configured (1-5 minutes)
- [ ] Summary index action enabled
- [ ] Alerts trigger when corresponding attack is executed
- [ ] Alert results appear in Triggered Alerts
- [ ] Summary index contains alert data

---

## 📝 Documentation

Document your alerts:

1. **Alert Name:** What it detects
2. **Search Query:** The SPL query used
3. **Schedule:** How often it runs
4. **Threshold:** What triggers it
5. **Severity:** Critical/High/Medium/Low
6. **Response:** What to do when it triggers

### Example Alert Documentation

**Alert:** Brute Force Attack Detection
- **Query:** `index=windows_security EventCode=4625 | stats count by Account_Name, Source_Network_Address | where count > 5`
- **Schedule:** Every 5 minutes
- **Threshold:** > 5 failed attempts
- **Severity:** Medium
- **Response:** Investigate source IP, check if account was compromised, block IP if necessary

---

## 🎯 Next Steps After Phase 6

Once all alerts are created and tested:

1. **Phase 7:** Build dashboards visualizing these alerts and attack patterns
2. **Phase 8:** Write incident response playbooks for each alert
3. **Phase 9:** Finalize portfolio documentation with alert screenshots

---

## 🐛 Troubleshooting

### Alert Not Triggering?

1. **Check the search query works manually:**
   - Open the alert in search
   - Verify it returns results

2. **Check the schedule:**
   - Verify time range matches schedule
   - Check if alert is enabled

3. **Check permissions:**
   - Ensure you have permission to run the search
   - Check index permissions

### Too Many False Positives?

1. **Increase thresholds**
2. **Add filters** for known-good activity
3. **Narrow time windows**
4. **Exclude specific IPs or accounts**

### Alert Triggering Too Late?

1. **Reduce schedule interval** (e.g., 1 minute instead of 5)
2. **Use real-time alerts** (if available in your Splunk version)
3. **Check log forwarding delays**

---

Good luck creating your SOC alerts! 🚀

