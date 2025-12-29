# 📊 Phase 7: SOC Dashboards & Visualization

This guide walks you through creating Splunk dashboards to visualize security events, alerts, and attack patterns. Dashboards provide real-time visibility into your SOC environment and are essential for security operations.

## 📋 Prerequisites Checklist

Before starting, verify:
- [/] All 5 alerts have been created and tested (Phase 6)
- [/] Attack scenarios have been executed and generate events
- [/] You can access Splunk Web UI at `http://192.168.1.7:8000`
- [/] You have admin access to Splunk (to create dashboards)
- [/] You have some historical data from executing scenarios

---

## 🎯 Overview: What Are Splunk Dashboards?

Splunk dashboards are visual interfaces that display:
- **Charts and graphs** showing security metrics over time
- **Tables** with detailed event data
- **Single value panels** showing key metrics
- **Real-time or scheduled updates** of security data

For this lab, we'll create dashboards that:
- Visualize attack patterns from all 5 scenarios
- Display alert activity and trends
- Show network activity and lateral movement
- Provide a security operations overview

---

## 📊 Dashboard Overview

We'll create 6 dashboards:

1. **Master Security Operations Dashboard**
   - Overview of all security activity
   - Active alerts summary
   - Attack timeline

2. **Brute Force Attack Dashboard**
   - Failed login attempts over time
   - Top attacking IPs
   - Accounts under attack

3. **PowerShell Activity Dashboard**
   - PowerShell executions timeline
   - Suspicious command patterns
   - User activity breakdown

4. **Privilege Escalation Dashboard**
   - Admin group changes timeline
   - Who made changes
   - Member SIDs added

5. **Lateral Movement Dashboard**
   - SMB network logons over time
   - Source IP analysis
   - Account usage patterns

6. **Data Exfiltration Dashboard**
   - Suspicious outbound connections
   - Top destination IPs
   - Process activity

---

## 🎨 Dashboard 1: Master Security Operations Dashboard

### Step 1: Create the Dashboard

1. **Open Splunk Web UI:** `http://192.168.1.7:8000`

2. **Navigate to Dashboards:**
   - Click **Dashboards** in the top menu
   - Click **Create New Dashboard** button
   - Choose **New Dashboard**

3. **Dashboard Settings:**
   - **Title:** `SOC Security Operations Dashboard`
   - **Description:** `Master dashboard for security operations monitoring`
   - **Permissions:** Private (or share with your app)

4. **Click Create**

### Step 2: Add Panels

#### Panel 1: Security Events Count (Single Value)

**Panel Title:** `Security Events Detected (Last 24 Hours)`

**Search Query:**
```spl
index=windows_security (EventCode=4625 OR EventCode=4732 OR EventCode=4624)
| where (EventCode=4624 AND Logon_Type=3 AND Source_Network_Address != "-") OR EventCode=4625 OR EventCode=4732
| stats count as event_count
```

**Visualization:** Single Value
**Format:** Number
**Time Range:** Last 24 hours

**Note:** This counts security events instead of triggered alerts. To view actual triggered alerts, go to **Activity → Triggered Alerts** in Splunk.

---

#### Panel 2: Recent Security Events (Table)

**Panel Title:** `Recent Security Events`

**Search Query:**
```spl
index=windows_security (EventCode=4625 OR EventCode=4732 OR EventCode=4624)
| where (EventCode=4624 AND Logon_Type=3 AND Source_Network_Address != "-") OR EventCode=4625 OR EventCode=4732
| eval event_type=case(EventCode=4625, "Brute Force", EventCode=4732, "Privilege Escalation", EventCode=4624, "Lateral Movement", 1=1, "Other")
| head 20
| table _time, event_type, Account_Name, Source_Network_Address, Group_Name
| sort -_time
```

**Visualization:** Table
**Format:** Table
**Time Range:** Last 24 hours

**Note:** This shows recent security events instead of triggered alerts. To view actual triggered alerts, go to **Activity → Triggered Alerts** in Splunk.

---

#### Panel 3: Attack Timeline (Timeline Chart)

**Panel Title:** `Security Events Timeline (Last 24 Hours)`

**Search Query:**
```spl
index=windows_security (EventCode=4625 OR EventCode=4732 OR EventCode=4624)
| eval event_type=case(EventCode=4625, "Brute Force", EventCode=4732, "Privilege Escalation", EventCode=4624 AND Logon_Type=3, "Lateral Movement", 1=1, "Other")
| timechart count by event_type
```

**Visualization:** Column Chart
**Format:** Timechart
**Time Range:** Last 24 hours

---

#### Panel 4: Top Attacking IPs (Bar Chart)

**Panel Title:** `Top Attacking IPs (Last 24 Hours)`

**Search Query:**
```spl
index=windows_security EventCode=4625
| stats count by Source_Network_Address
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| sort -count
| head 10
```

**Visualization:** Bar Chart
**Format:** Stats
**Time Range:** Last 24 hours

---

#### Panel 5: PowerShell Activity (Timeline)

**Panel Title:** `PowerShell Executions (Last 24 Hours)`

**Search Query:**
```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| timechart count
```

**Visualization:** Line Chart
**Format:** Timechart
**Time Range:** Last 24 hours

---

#### Panel 6: Network Connections Summary (Single Value)

**Panel Title:** `Suspicious Network Connections (Last 24 Hours)`

**Search Query:**
```spl
index=sysmon EventCode=3
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443 AND DestinationPort != 3389 AND DestinationPort != 445
| stats count
```

**Visualization:** Single Value
**Format:** Number
**Time Range:** Last 24 hours

---

## 🔴 Dashboard 2: Brute Force Attack Dashboard

### Step 1: Create the Dashboard

1. **Navigate to:** Dashboards → Create New Dashboard
2. **Title:** `Brute Force Attack Dashboard`
3. **Description:** `Visualization of brute force attack patterns and failed login attempts`

### Step 2: Add Panels

#### Panel 1: Failed Logins Over Time

**Panel Title:** `Failed Login Attempts Over Time`

**Search Query:**
```spl
index=windows_security EventCode=4625
| timechart count by Account_Name
```

**Visualization:** Area Chart
**Time Range:** Last 24 hours

---

#### Panel 2: Top Attacking IPs

**Panel Title:** `Top 10 Attacking IPs`

**Search Query:**
```spl
index=windows_security EventCode=4625
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| stats count as failures, 
        earliest(_time) as first_seen, 
        latest(_time) as last_seen 
        by Source_Network_Address
| sort -failures
| head 10
| convert ctime(first_seen) ctime(last_seen)
```

**Visualization:** Table
**Format:** Table with sortable columns
**Time Range:** Last 24 hours

---

#### Panel 3: Accounts Under Attack

**Panel Title:** `Accounts Targeted by Brute Force`

**Search Query:**
```spl
index=windows_security EventCode=4625
| stats count as failures, 
        values(Source_Network_Address) as attacking_ips 
        by Account_Name
| sort -failures
| head 10
```

**Visualization:** Bar Chart
**Format:** Stats
**Time Range:** Last 24 hours

---

#### Panel 4: Brute Force by Source IP (Heatmap)

**Panel Title:** `Brute Force Activity Heatmap`

**Search Query:**
```spl
index=windows_security EventCode=4625
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| timechart count by Source_Network_Address limit=10
```

**Visualization:** Column Chart
**Format:** Timechart
**Time Range:** Last 24 hours

---

#### Panel 5: Recent Failed Login Events

**Panel Title:** `Recent Failed Login Events`

**Search Query:**
```spl
index=windows_security EventCode=4625
| head 50
| table _time, Account_Name, Source_Network_Address, ComputerName
| sort -_time
```

**Visualization:** Table
**Format:** Table
**Time Range:** Last 24 hours

---

## 🔴 Dashboard 3: PowerShell Activity Dashboard

### Step 1: Create the Dashboard

1. **Navigate to:** Dashboards → Create New Dashboard
2. **Title:** `PowerShell Activity Dashboard`
3. **Description:** `Monitor PowerShell executions and detect suspicious activity`

### Step 2: Add Panels

#### Panel 1: PowerShell Executions Timeline

**Panel Title:** `PowerShell Executions Over Time`

**Search Query:**
```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| timechart count
```

**Visualization:** Line Chart
**Time Range:** Last 24 hours

---

#### Panel 2: Suspicious PowerShell Commands

**Panel Title:** `Suspicious PowerShell Commands Detected`

**Search Query:**
```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| where CommandLine LIKE "%-enc%" OR CommandLine LIKE "%-EncodedCommand%" OR CommandLine LIKE "%IEX%"
| stats count, 
        values(CommandLine) as commands, 
        values(User) as users 
        by Image
| sort -count
```

**Visualization:** Table
**Format:** Table
**Time Range:** Last 24 hours

---

#### Panel 3: PowerShell by User

**Panel Title:** `PowerShell Executions by User`

**Search Query:**
```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| stats count by User
| sort -count
| head 10
```

**Visualization:** Pie Chart
**Format:** Stats
**Time Range:** Last 24 hours

---

#### Panel 4: Encoded Commands Detection

**Panel Title:** `Encoded PowerShell Commands`

**Search Query:**
```spl
index=sysmon EventCode=1 Image="*powershell.exe" CommandLine="*-enc*"
| stats count, 
        earliest(_time) as first_seen, 
        latest(_time) as last_seen, 
        values(CommandLine) as commands 
        by User
| convert ctime(first_seen) ctime(last_seen)
| sort -count
```

**Visualization:** Table
**Format:** Table
**Time Range:** Last 24 hours

---

#### Panel 5: Recent PowerShell Activity

**Panel Title:** `Recent PowerShell Executions`

**Search Query:**
```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| head 30
| table _time, User, Image, CommandLine, ParentImage
| sort -_time
```

**Visualization:** Table
**Format:** Table
**Time Range:** Last 24 hours

---

## 🔴 Dashboard 4: Privilege Escalation Dashboard

### Step 1: Create the Dashboard

1. **Navigate to:** Dashboards → Create New Dashboard
2. **Title:** `Privilege Escalation Dashboard`
3. **Description:** `Monitor admin group changes and privilege escalations`

### Step 2: Add Panels

#### Panel 1: Admin Group Changes Timeline

**Panel Title:** `Administrator Group Changes Over Time`

**Search Query:**
```spl
index=windows_security EventCode=4732 Group_Name="Administrators"
| timechart count
```

**Visualization:** Column Chart
**Time Range:** Last 30 days

---

#### Panel 2: Who Made Changes

**Panel Title:** `Users Who Made Privilege Escalation Changes`

**Search Query:**
```spl
index=windows_security EventCode=4732 Group_Name="Administrators"
| rex field=_raw "(?s)Subject:.*?Account Name:\s+(?<subject_account>[^\r\n]+)"
| rex field=_raw "(?s)Member:.*?Security ID:\s+(?<member_sid>[^\r\n]+)"
| eval subject_account=trim(subject_account), member_sid=trim(member_sid)
| stats count, 
        values(member_sid) as members_added 
        by subject_account
| sort -count
```

**Visualization:** Table
**Format:** Table
**Time Range:** Last 30 days

---

#### Panel 3: Recent Privilege Escalations

**Panel Title:** `Recent Privilege Escalation Events`

**Search Query:**
```spl
index=windows_security EventCode=4732 Group_Name="Administrators"
| rex field=_raw "(?s)Subject:.*?Account Name:\s+(?<subject_account>[^\r\n]+)"
| rex field=_raw "(?s)Member:.*?Security ID:\s+(?<member_sid>[^\r\n]+)"
| eval subject_account=trim(subject_account), member_sid=trim(member_sid)
| table _time, subject_account, member_sid, Group_Name, ComputerName
| sort -_time
| head 20
```

**Visualization:** Table
**Format:** Table
**Time Range:** Last 30 days

---

#### Panel 4: Members Added to Admin Group

**Panel Title:** `Members Added to Administrators Group`

**Search Query:**
```spl
index=windows_security EventCode=4732 Group_Name="Administrators"
| rex field=_raw "(?s)Member:.*?Security ID:\s+(?<member_sid>[^\r\n]+)"
| eval member_sid=trim(member_sid)
| stats count, 
        earliest(_time) as first_added, 
        latest(_time) as last_added 
        by member_sid
| convert ctime(first_added) ctime(last_added)
| sort -count
```

**Visualization:** Table
**Format:** Table
**Time Range:** Last 30 days

---

## 🔴 Dashboard 5: Lateral Movement Dashboard

### Step 1: Create the Dashboard

1. **Navigate to:** Dashboards → Create New Dashboard
2. **Title:** `Lateral Movement Dashboard`
3. **Description:** `Monitor SMB network logons and lateral movement activity`

### Step 2: Add Panels

#### Panel 1: SMB Network Logons Timeline

**Panel Title:** `SMB Network Logons Over Time`

**Search Query:**
```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != "" AND Source_Network_Address != "::1" AND Source_Network_Address != "127.0.0.1"
| timechart count
```

**Visualization:** Line Chart
**Time Range:** Last 24 hours

---

#### Panel 2: Top Source IPs for Lateral Movement

**Panel Title:** `Top Source IPs for Network Logons`

**Search Query:**
```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != "" AND Source_Network_Address != "::1" AND Source_Network_Address != "127.0.0.1"
| stats count, 
        values(Account_Name) as accounts 
        by Source_Network_Address
| sort -count
| head 10
```

**Visualization:** Bar Chart
**Format:** Stats
**Time Range:** Last 24 hours

---

#### Panel 3: Accounts Used for Lateral Movement

**Panel Title:** `Accounts Used for Network Logons`

**Search Query:**
```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| stats count, 
        values(Source_Network_Address) as source_ips 
        by Account_Name
| sort -count
| head 10
```

**Visualization:** Table
**Format:** Table
**Time Range:** Last 24 hours

---

#### Panel 4: Recent SMB Network Logons

**Panel Title:** `Recent SMB Network Logons`

**Search Query:**
```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != "" AND Source_Network_Address != "::1" AND Source_Network_Address != "127.0.0.1"
| head 30
| table _time, Account_Name, Source_Network_Address, Account_Domain, ComputerName
| sort -_time
```

**Visualization:** Table
**Format:** Table
**Time Range:** Last 24 hours

---

## 🔴 Dashboard 6: Data Exfiltration Dashboard

### Step 1: Create the Dashboard

1. **Navigate to:** Dashboards → Create New Dashboard
2. **Title:** `Data Exfiltration Dashboard`
3. **Description:** `Monitor suspicious outbound network connections`

### Step 2: Add Panels

#### Panel 1: Suspicious Connections Timeline

**Panel Title:** `Suspicious Outbound Connections Over Time`

**Search Query:**
```spl
index=sysmon EventCode=3
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443 AND DestinationPort != 3389 AND DestinationPort != 445
| timechart count
```

**Visualization:** Area Chart
**Time Range:** Last 24 hours

---

#### Panel 2: Top Destination IPs

**Panel Title:** `Top Destination IPs (Suspicious Connections)`

**Search Query:**
```spl
index=sysmon EventCode=3
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443 AND DestinationPort != 3389 AND DestinationPort != 445
| stats count, 
        values(DestinationPort) as ports, 
        values(Image) as processes 
        by DestinationIp
| sort -count
| head 10
```

**Visualization:** Table
**Format:** Table
**Time Range:** Last 24 hours

---

#### Panel 3: Connections by Process

**Panel Title:** `Suspicious Connections by Process`

**Search Query:**
```spl
index=sysmon EventCode=3
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443 AND DestinationPort != 3389 AND DestinationPort != 445
| stats count by Image
| sort -count
| head 10
```

**Visualization:** Bar Chart
**Format:** Stats
**Time Range:** Last 24 hours

---

#### Panel 4: Connections to Attacker IP

**Panel Title:** `Connections to Attacker IP (192.168.1.4)`

**Search Query:**
```spl
index=sysmon EventCode=3 DestinationIp=192.168.1.4
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443
| stats count, 
        values(DestinationPort) as ports, 
        values(Image) as processes 
        by DestinationIp
| eval ports_str=mvjoin(ports, ", ")
| eval processes_str=mvjoin(processes, ", ")
```

**Visualization:** Table
**Format:** Table
**Time Range:** Last 24 hours

**Alternative (Single Value showing count only):**
If you prefer a single value showing just the connection count, use this query:
```spl
index=sysmon EventCode=3 DestinationIp=192.168.1.4
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443
| stats count
```
**Visualization:** Single Value
**Format:** Number

---

#### Panel 5: Recent Suspicious Connections

**Panel Title:** `Recent Suspicious Network Connections`

**Search Query:**
```spl
index=sysmon EventCode=3
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443 AND DestinationPort != 3389 AND DestinationPort != 445
| head 30
| table _time, Image, DestinationIp, DestinationPort, User
| sort -_time
```

**Visualization:** Table
**Format:** Table
**Time Range:** Last 24 hours

---

## 📸 Dashboard Best Practices

### Panel Layout Tips

1. **Top Row:** Key metrics (Single Value panels)
2. **Middle Rows:** Timeline charts showing trends
3. **Bottom Rows:** Detailed tables with event data

### Time Range Settings

- **Real-time dashboards:** Use "Last 15 minutes" or "Last 1 hour"
- **Historical analysis:** Use "Last 24 hours" or "Last 7 days"
- **Set default time range** in dashboard settings

### Visualization Types

- **Timechart:** Best for showing trends over time
- **Bar Chart:** Best for comparing values
- **Pie Chart:** Best for showing proportions
- **Table:** Best for detailed data
- **Single Value:** Best for key metrics

### Performance Tips

1. **Limit results:** Use `head` or `limit` in queries
2. **Use stats early:** Aggregate data before displaying
3. **Set appropriate time ranges:** Don't query more data than needed
4. **Index optimization:** Ensure proper indexing

---

## ✅ Success Checklist

After creating all dashboards, verify:

- [/] Master Security Operations Dashboard created
- [/] All 5 scenario-specific dashboards created
- [/] Each dashboard has 4-6 panels
- [/] Panels display data correctly
- [/] Time ranges are appropriate
- [/] Visualizations are clear and readable
- [/] Dashboards are saved and accessible
- [] Screenshots taken for portfolio

---

## 🎯 Next Steps After Phase 7

Once all dashboards are created:

1. **Phase 8:** Write incident response playbooks for each alert
2. **Phase 9:** Finalize portfolio documentation with dashboard screenshots

---

## 🐛 Troubleshooting

### Dashboard Not Showing Data?

1. **Check time range:** Ensure events exist in the selected time range
2. **Verify queries work:** Test each panel query individually
3. **Check index permissions:** Ensure you have access to the indexes
4. **Verify field names:** Field names may differ - use `fieldsummary` to check

### Panels Loading Slowly?

1. **Reduce time range:** Query less data
2. **Add limits:** Use `head` or `limit` in queries
3. **Optimize queries:** Use `stats` early to aggregate data
4. **Check data volume:** Large datasets take longer to process

### Visualizations Not Displaying Correctly?

1. **Check data format:** Ensure data matches visualization type
2. **Verify field types:** Numeric fields for charts, text for tables
3. **Review query syntax:** Ensure SPL syntax is correct
4. **Try different visualization:** Some data works better with different chart types

### Don't Have a Summary Index?

**If you only used "Add to Triggered Alerts" and don't have a summary index (common in Splunk Free):**

1. **The Master Dashboard queries security events directly** - this works perfectly and shows all security activity
2. **To view triggered alerts:** Navigate to **Activity → Triggered Alerts** in Splunk
3. **All dashboard queries in this guide** work without a summary index - they query the source indexes directly
4. **This is actually better for dashboards** as you get real-time data directly from the source

**Note:** The Master Security Operations Dashboard (Panels 1 and 2) have been configured to work without a summary index by querying security events directly.

---

Good luck creating your SOC dashboards! 🚀

