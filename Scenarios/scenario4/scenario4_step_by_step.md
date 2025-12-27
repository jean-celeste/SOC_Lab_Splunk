# Scenario 4: Lateral Movement (SMB Access) - Live Guide

## Overview
Simulate lateral movement by accessing Windows shares from Kali Linux via SMB. This demonstrates how attackers move through a network after initial compromise.

---

## Step 1: Prepare Windows 10 VM

### 1.1 Enable File and Printer Sharing

**On Windows 10 VM:**

1. **Open PowerShell as Administrator**
   - Press `Windows Key + X`
   - Select "Windows PowerShell (Admin)" or "Terminal (Admin)"

2. **Enable File and Printer Sharing through firewall:**
   ```powershell
   Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing"
   ```

3. **Verify SMB is enabled:**
   ```powershell
   Get-SmbServerConfiguration | Select EnableInsecureGuestLogons
   ```

4. **Check if SMB ports are listening:**
   ```powershell
   netstat -an | findstr "445"
   ```
   **Expected:** Should show port 445 listening

### 1.2 Create a Test Share

**Still in Admin PowerShell on Windows 10:**

1. **Create a test directory:**
   ```powershell
   New-Item -Path C:\TestShare -ItemType Directory -Force
   ```

2. **Create an SMB share:**
   ```powershell
   New-SmbShare -Name TestShare -Path C:\TestShare -FullAccess Everyone
   ```

3. **Verify the share was created:**
   ```powershell
   Get-SmbShare
   ```
   **Expected:** Should show "TestShare" in the list

4. **Optional: Add a test file to the share:**
   ```powershell
   "This is a test file" | Out-File C:\TestShare\test.txt
   ```

### 1.3 Create a Test User for SMB Access

**Still in Admin PowerShell:**

1. **Create a test user:**
   ```powershell
   net user smbuser TestPass123! /add
   ```

2. **Verify the user was created:**
   ```powershell
   net user smbuser
   ```

3. **Optional: Grant user access to the share:**
   ```powershell
   Grant-SmbShareAccess -Name TestShare -AccountName smbuser -AccessRight Full
   ```

---

## Step 2: Execute from Kali Linux

### 2.1 Install SMB Client (if needed)

**On Kali Linux VM:**

1. **Open terminal or SSH into Kali**

2. **Check if smbclient is installed:**
   ```bash
   which smbclient
   ```

3. **Install if not present:**
   ```bash
   sudo apt update
   sudo apt install smbclient -y
   ```

### 2.2 Test Network Connectivity

**From Kali, verify you can reach Windows:**

```bash
# Ping Windows 10
ping -c 3 192.168.1.5

# Check if SMB port is open
nmap -p 445 192.168.1.5
```

**Expected:** Port 445 should be open/filtered

**Note:** If port 445 is not open, go back to Windows and verify firewall rules are enabled.

### 2.3 Enumerate SMB Shares

**From Kali:**

**Important Note:** Windows by default does NOT allow anonymous SMB enumeration. You must use authentication.

1. **List shares with authentication (REQUIRED):**
   ```bash
   smbclient -L //192.168.1.5 -U smbuser
   # When prompted, enter password: TestPass123!
   ```

   **Expected output:** Should show available shares including "TestShare"

2. **Alternative: If smbuser doesn't work, try with testuser:**
   ```bash
   smbclient -L //192.168.1.5 -U testuser
   # Enter password: TestPass123!
   ```

3. **If you get "NT_STATUS_ACCESS_DENIED":**
   - This is normal - Windows blocks anonymous access
   - Make sure you're using the `-U` flag with a valid username
   - Verify the user exists and password is correct on Windows
   - Check that the user account is enabled

### 2.4 Connect to SMB Share

**From Kali:**

**Important:** Always use the `-U` flag with a username. Anonymous access (`-N`) will fail.

1. **Connect to the TestShare:**
   ```bash
   smbclient //192.168.1.5/TestShare -U smbuser
   # Enter password when prompted: TestPass123!
   ```

   **If connection fails:**
   - Verify the user exists: `net user smbuser` (on Windows)
   - Try with testuser: `smbclient //192.168.1.5/TestShare -U testuser`
   - Check share name: `Get-SmbShare` (on Windows)

2. **Once connected, try these commands:**
   ```bash
   # List files in the share
   ls
   
   # Get current directory
   pwd
   
   # Try to download a file (if test.txt exists)
   get test.txt
   
   # Exit SMB client
   exit
   ```

3. **Verify connection generated events:**
   - Even if you just connect and exit, this should generate Event ID 4624
   - The connection itself creates the network logon event

### 2.5 Alternative: Use Nmap to Enumerate SMB

**From Kali:**

**Note:** These nmap scripts may also require credentials or may not work if anonymous access is disabled.

```bash
# Enumerate SMB shares (may require credentials)
nmap --script smb-enum-shares.nse -p 445 192.168.1.5

# Enumerate SMB users (may require credentials)
nmap --script smb-enum-users.nse -p 445 192.168.1.5

# Get SMB system info (this one usually works without auth)
nmap --script smb-os-discovery.nse -p 445 192.168.1.5
```

**Note:** 
- These commands will generate network logon events (Event ID 4624) if they successfully connect
- If scripts fail due to authentication, that's normal - Windows blocks anonymous enumeration
- The `smbclient` connection method (Step 2.4) is more reliable for generating events

---

## Step 3: Verify in Splunk

### 3.1 Wait for Logs to Arrive

**Important:** Wait 1-2 minutes after SMB connections for Windows Security events to be forwarded to Splunk.

### 3.2 Open Splunk Web UI

1. Open browser on your host machine
2. Navigate to: `http://192.168.1.7:8000`
3. Login with your Splunk credentials

### 3.3 Discover Field Names (IMPORTANT)

**Before running detection queries, discover the actual field names:**

**Step 1: View raw event**
```spl
index=windows_security EventCode=4624
| head 1
```

**Step 2: Get field summary**
```spl
index=windows_security EventCode=4624
| head 1
| fieldsummary
```

**Step 3: View all fields**
```spl
index=windows_security EventCode=4624
| head 1
| table *
```

**✅ CONFIRMED FIELD NAMES FOR YOUR ENVIRONMENT:**
- **Logon Type:** `Logon_Type` (numeric field: 3 = Network, 5 = Service)
- **Source IP:** `Source_Network_Address` (may be "-" for local logons)
- **Account Name:** `Account_Name` (can contain multiple values separated by newlines)
- **Account Domain:** `Account_Domain`
- **Process Name:** `Process_Name`

**⚠️ IMPORTANT:** 
- Logon Type 5 = Service logon (local, not network)
- Logon Type 3 = Network logon (what we're looking for!)
- If `Source_Network_Address` is "-", it's NOT a network logon
- Look for events where `Source_Network_Address` contains an IP address

### 3.4 Search for Network Logons ( - Based on Your Environment)

**⚠️ CRITICAL: Filter for Logon Type 3 specifically!**

**In Splunk Search bar, paste:**

**Option A: Filter by Logon_Type field (RECOMMENDED)**
```spl
index=windows_security EventCode=4624 Logon_Type=3
| head 20
```

**Option B: Filter by Logon Type AND Source IP (MOST ACCURATE)**
```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| head 20
```

**Option C: Extract from raw if Logon_Type field filtering doesn't work**
```spl
index=windows_security EventCode=4624
| where _raw LIKE "%Logon Type:\t\t3%" OR _raw LIKE "%Logon Type: 3%"
| rex field=_raw "Source Network Address:\s+(?<src_ip>[^\r\n]+)"
| where src_ip != "-" AND src_ip != ""
| head 20
```

**What you should see:**
- Event ID 4624 (Successful logon)
- **Logon_Type = 3** (Network logon - NOT 5!)
- **Source_Network_Address** should contain an IP address (NOT "-")
- Recent timestamps (within last few minutes)
- Source IP should be `192.168.1.4` (Kali)
- Account name should be `smbuser` (or the user you used)

**❌ What you DON'T want to see:**
- Logon_Type = 5 (Service logon - local, not network)
- Source_Network_Address = "-" (empty - indicates local logon)
- Account_Name = "SYSTEM" (local system account)

### 3.5 Run Detection Query ( - Based on Your Environment)

**Primary Detection Query (Using Actual Field Names):**
```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| stats count by Source_Network_Address, Account_Name
| sort -count
```

**Enhanced Query (Extract Account Name from Raw - More Accurate):**
```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| rex field=_raw "New Logon:\s+Security ID:\s+[^\r\n]+\s+Account Name:\s+(?<new_account>[^\r\n]+)"
| stats count by Source_Network_Address, new_account
| sort -count
```

**Alternative: Extract Everything from Raw ()**
```spl
index=windows_security EventCode=4624
| where _raw LIKE "%Logon Type:%3%" OR _raw LIKE "%Logon Type: 3%"
| rex field=_raw "(?i)Source Network Address:\s+(?<src_ip>[^\r\n\t]+)"
| rex field=_raw "(?i)New Logon:\s+Security ID:\s+[^\r\n]+\s+Account Name:\s+(?<account_name>[^\r\n\t]+)"
| where src_ip != "-" AND src_ip != "" AND isnotnull(src_ip)
| stats count by src_ip, account_name
| sort -count
```

**Better Alternative: Use field-based approach (MORE RELIABLE)**
```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| rex field=_raw "(?i)New Logon:\s+Security ID:\s+[^\r\n]+\s+Account Name:\s+(?<account_name>[^\r\n\t]+)"
| stats count by Source_Network_Address, account_name
| sort -count
```

**What to look for:**
- **Source_Network_Address** should be `192.168.1.4` (Kali) - NOT "-"
- **Account_Name** should be `smbuser` (or the user you used) - NOT "SYSTEM"
- **Logon_Type** must be 3 (Network logon) - NOT 5
- Count shows number of network logons from that IP

### 3.6 Detailed View ( - Based on Your Environment)

**See all relevant fields for Network Logons (Logon Type 3):**

**Option A: Standard fields with Source IP filter**
```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| table _time, Account_Name, Account_Domain, Source_Network_Address, ComputerName, Process_Name
| sort -_time
```

**Option B: Extract from raw (More Reliable)**
```spl
index=windows_security EventCode=4624
| where _raw LIKE "%Logon Type:\t\t3%" OR _raw LIKE "%Logon Type: 3%"
| rex field=_raw "Source Network Address:\s+(?<src_ip>[^\r\n]+)"
| rex field=_raw "New Logon:\s+Security ID:\s+[^\r\n]+\s+Account Name:\s+(?<account_name>[^\r\n]+)"
| rex field=_raw "Account Domain:\s+(?<account_domain>[^\r\n]+)"
| where src_ip != "-" AND src_ip != ""
| table _time, account_name, account_domain, src_ip, Process_Name
| sort -_time
```

**Option C: Show both Subject and New Logon accounts**
```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| rex field=_raw "Subject:\s+Security ID:\s+[^\r\n]+\s+Account Name:\s+(?<subject_account>[^\r\n]+)"
| rex field=_raw "New Logon:\s+Security ID:\s+[^\r\n]+\s+Account Name:\s+(?<new_account>[^\r\n]+)"
| table _time, subject_account, new_account, Source_Network_Address, Account_Domain
| sort -_time
```

**This shows:**
- When the network logon occurred
- Which account was used (New Logon account)
- Source IP address (attacker IP) - should be 192.168.1.4
- Domain information
- Process that initiated the logon

### 3.7 Timeline of SMB Access ()

**See network logons over time (Logon Type 3 only):**

**Option A: By source IP (Filtered for Network Logons)**
```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| timechart count by Source_Network_Address
```

**Option B: Extract IP from raw ( - More Flexible)**
```spl
index=windows_security EventCode=4624
| where _raw LIKE "%Logon Type:%3%" OR _raw LIKE "%Logon Type: 3%"
| rex field=_raw "(?i)Source Network Address:\s+(?<src_ip>[^\r\n\t]+)"
| where src_ip != "-" AND src_ip != "" AND isnotnull(src_ip) AND match(src_ip, "^\d+\.\d+\.\d+\.\d+$")
| timechart count by src_ip
```

**Note:** If this doesn't work, the field-based approach (Option B Alternative) is more reliable.

**Option B Alternative: Use field-based approach (MORE RELIABLE)**
```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| timechart count by Source_Network_Address
```

**Option C: Simple count over time (Network Logons Only)**
```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| timechart count
```

**Option D: Compare Logon Types (3 vs 5)**
```spl
index=windows_security EventCode=4624
| eval logon_category=case(Logon_Type=3, "Network Logon", Logon_Type=5, "Service Logon", 1=1, "Other")
| timechart count by logon_category
```

**This visualizes:**
- When SMB access occurred (Logon Type 3)
- Frequency of network logons
- Which IP addresses are accessing shares
- Comparison between network and service logons

### 3.8 Filter for Kali IP Specifically ()

**Focus on attacks from Kali (Logon Type 3 with Source IP):**

**Option A: Using Source IP field**
```spl
index=windows_security EventCode=4624 Logon_Type=3 Source_Network_Address=192.168.1.4
| table _time, Account_Name, Account_Domain, Source_Network_Address, Process_Name
| sort -_time
```

**Option B: Extract from raw ( - More Flexible Regex)**
```spl
index=windows_security EventCode=4624
| where _raw LIKE "%Logon Type:%3%" AND _raw LIKE "%192.168.1.4%"
| rex field=_raw "(?i)New Logon:\s+Security ID:\s+[^\r\n]+\s+Account Name:\s+(?<account_name>[^\r\n\t]+)"
| rex field=_raw "(?i)Source Network Address:\s+(?<src_ip>[^\r\n\t]+)"
| where src_ip != "-" AND src_ip != "" AND isnotnull(src_ip) AND match(src_ip, "^\d+\.\d+\.\d+\.\d+$")
| table _time, account_name, src_ip, Process_Name
| sort -_time
```

**If regex extraction fails, use field-based approach:**
```spl
index=windows_security EventCode=4624 Logon_Type=3 Source_Network_Address=192.168.1.4
| rex field=_raw "(?i)New Logon:\s+Security ID:\s+[^\r\n]+\s+Account Name:\s+(?<account_name>[^\r\n\t]+)"
| table _time, account_name, Source_Network_Address, Process_Name
| sort -_time
```

**Option B Alternative: Use field-based approach (MORE RELIABLE)**
```spl
index=windows_security EventCode=4624 Logon_Type=3 Source_Network_Address=192.168.1.4
| rex field=_raw "(?i)New Logon:\s+Security ID:\s+[^\r\n]+\s+Account Name:\s+(?<account_name>[^\r\n\t]+)"
| table _time, account_name, Source_Network_Address, Process_Name
| sort -_time
```

**Option C: Filter for Network Logons from Any External IP**
```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != "" AND Source_Network_Address != "::1" AND Source_Network_Address != "127.0.0.1"
| table _time, Account_Name, Account_Domain, Source_Network_Address
| sort -_time
```

---

## Step 4: Advanced Analysis

### 4.1 Correlate SMB Access with Other Events ()

**Look for related security events:**

**Option A: Using field-based approach (MORE RELIABLE)**
```spl
index=windows_security (EventCode=4624 OR EventCode=4625 OR EventCode=5140 OR EventCode=5143)
| eval event_type=case(EventCode=4624, "Successful Logon", EventCode=4625, "Failed Logon", EventCode=5140, "Network Share Accessed", EventCode=5143, "Network Share Object Modified")
| eval is_network_logon=if(EventCode=4624 AND Logon_Type=3 AND Source_Network_Address != "-", "Yes", "No")
| where is_network_logon="Yes" OR EventCode=4625 OR EventCode=5140 OR EventCode=5143
| table _time, EventCode, event_type, Account_Name, Source_Network_Address
| sort -_time
```

**Option B: Separate queries for different event types**
```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| eval event_type="Successful Network Logon"
| table _time, EventCode, event_type, Account_Name, Source_Network_Address
| append [search index=windows_security EventCode=4625]
| eval event_type=coalesce(event_type, "Failed Logon")
| append [search index=windows_security EventCode=5140]
| eval event_type=coalesce(event_type, "Network Share Accessed")
| append [search index=windows_security EventCode=5143]
| eval event_type=coalesce(event_type, "Network Share Object Modified")
| table _time, EventCode, event_type, Account_Name, Source_Network_Address
| sort -_time
```

**Option C: Simple correlation (Network Logons + Failed Logons)**
```spl
index=windows_security (EventCode=4624 OR EventCode=4625)
| eval event_type=case(EventCode=4624 AND Logon_Type=3 AND Source_Network_Address != "-", "Successful Network Logon", EventCode=4625, "Failed Logon", 1=1, "Other Logon")
| where event_type="Successful Network Logon" OR event_type="Failed Logon"
| table _time, EventCode, event_type, Account_Name, Source_Network_Address
| sort -_time
```

**Option D: Check if EventCode 5140/5143 exist first**
```spl
index=windows_security (EventCode=5140 OR EventCode=5143)
| head 10
```

**If EventCode 5140/5143 don't exist, use this simpler version:**
```spl
index=windows_security (EventCode=4624 OR EventCode=4625)
| eval event_type=case(EventCode=4624 AND Logon_Type=3, "Successful Network Logon", EventCode=4625, "Failed Logon", 1=1, "Other")
| where Source_Network_Address != "-" OR EventCode=4625
| table _time, EventCode, event_type, Account_Name, Source_Network_Address
| sort -_time
```

**This helps identify:**
- Successful SMB connections (EventCode 4624, Logon Type 3)
- Failed attempts (EventCode 4625)
- File access on shares (EventCode 5140 - if enabled)
- Full attack timeline

### 4.2 Detect Suspicious SMB Activity

**Find unusual SMB access patterns:**

```spl
index=windows_security EventCode=4624 Logon_Type=3
| stats count, dc(Account_Name) as unique_accounts by Source_Network_Address
| where count > 5 OR unique_accounts > 3
| sort -count
```

**This detects:**
- Multiple SMB connections from same IP
- Multiple accounts used from same IP
- Potential brute force or enumeration

### 4.3 Alert-Ready Query ()

**Query formatted for Splunk alerts:**

**Option A: Basic Alert Query ( - Filters Empty IPs)**
```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| stats count by Source_Network_Address, Account_Name
| where count > 5
```

**Option B: Enhanced alert query ()**
```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| stats count, values(Account_Name) as accounts by Source_Network_Address
| where count > 5
| eval severity="MEDIUM"
| eval description="Multiple SMB network logons from " + Source_Network_Address + " using accounts: " + accounts
```

**Option C: Alert for Any Network Logon from External IP (Lower Threshold)**
```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != "" AND Source_Network_Address != "::1" AND Source_Network_Address != "127.0.0.1"
| stats count, values(Account_Name) as accounts, values(Account_Domain) as domains by Source_Network_Address
| where count > 0
| eval severity=case(count > 10, "HIGH", count > 5, "MEDIUM", 1=1, "LOW")
| eval description="Network logon from " + Source_Network_Address + " (" + count + " attempts) using accounts: " + accounts
| sort -count
```

**Option D: Test Query (See if you have any network logons)**
```spl
index=windows_security EventCode=4624 Logon_Type=3
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| stats count by Source_Network_Address, Account_Name
| sort -count
```

**Note:** 
- If Option D returns no results, you may not have any Logon Type 3 events with populated Source_Network_Address
- Try lowering the threshold (count > 1 or count > 0) for testing
- The SMB connection might not have generated the expected events

---

## ✅ Success Checklist

- [/] File and Printer Sharing enabled on Windows 10
- [/] Test share created successfully
- [/] SMB client installed on Kali
- [/] SMB connection successful from Kali to Windows
- [/] Event ID 4624 with Logon Type 3 visible in Splunk
- [/] Detection query shows network logons
- [/] Source IP matches Kali (192.168.1.4)
- [/] Account name matches the user used for SMB access

---

## 🐛 Troubleshooting

### No Event ID 4624 appearing?

1. **Check if SMB connection actually worked:**
   ```bash
   # On Kali, try connecting again
   smbclient //192.168.1.5/TestShare -U smbuser
   ```

2. **Check Windows Event Viewer directly:**
   - Open Event Viewer
   - Navigate to: Windows Logs → Security
   - Filter for Event ID 4624
   - Look for Logon Type 3 entries
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

### SMB connection failing?

**Common Error: "NT_STATUS_ACCESS_DENIED"**

This usually means:
- You're trying anonymous access (Windows blocks this by default)
- **Solution:** Always use `-U username` flag with credentials

**Troubleshooting Steps:**

1. **Verify user exists and is enabled:**
   ```powershell
   # On Windows, check the user
   net user smbuser
   # Look for "Account active: Yes"
   ```

2. **Try with a different user (if smbuser doesn't work):**
   ```bash
   # On Kali, try with testuser
   smbclient -L //192.168.1.5 -U testuser
   # Enter password: TestPass123!
   ```

3. **Check firewall rules:**
   ```powershell
   Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" | Select DisplayName, Enabled
   ```

4. **Verify SMB service is running:**
   ```powershell
   Get-Service LanmanServer
   # Should show "Running"
   ```

5. **Check share permissions:**
   ```powershell
   Get-SmbShareAccess -Name TestShare
   ```

6. **Test SMB from Windows itself:**
   ```powershell
   Test-NetConnection -ComputerName localhost -Port 445
   ```

7. **Verify SMB port is accessible from Kali:**
   ```bash
   # On Kali
   nmap -p 445 192.168.1.5
   # Should show port 445 as open
   ```

8. **If authentication still fails, recreate user with simpler password:**
   ```powershell
   # On Windows
   net user smbuser Password123 /add
   ```
   Then from Kali:
   ```bash
   smbclient -L //192.168.1.5 -U smbuser
   # Enter password: Password123
   ```

### Field names not matching?

**Check available fields:**
```spl
index=windows_security EventCode=4624
| head 1
| fieldsummary
```

**Common field name variations:**
- Source IP: `Source_Network_Address`, `src_ip`, `IpAddress`, `Source_IP`
- Account: `Account_Name`, `TargetUserName`, `Account`
- Logon Type: `Logon_Type`, `LogonType`, `Type`

**Extract from raw if needed:**
```spl
index=windows_security EventCode=4624
| where _raw LIKE "%Logon Type: 3%"
| rex field=_raw "Source Network Address:\s+(?<src_ip>[^\r\n]+)"
| rex field=_raw "Account Name:\s+(?<account_name>[^\r\n]+)"
| table _time, src_ip, account_name
```

---

## 📊 What You Should See

### Expected Splunk Results:

1. **Basic Query Results:**
   - Event ID 4624 entries
   - Logon Type 3 (Network logon)
   - Recent timestamps
   - Source IP: `192.168.1.4` (Kali)
   - Account Name: `smbuser` (or user you used)

2. **Detection Query Results:**
   - Shows count of network logons
   - Source IP and account name clearly visible
   - Helps identify lateral movement attempts

3. **Timeline Results:**
   - Shows when SMB access occurred
   - Frequency of connections
   - Patterns of access

---

## 📸 Screenshot Tips

Take screenshots of:
1. PowerShell commands creating SMB share
2. SMB client connection from Kali
3. Splunk search results showing Event ID 4624
4. Detection query results showing network logons
5. Timeline chart showing SMB access over time
6. Source IP analysis showing connections from Kali

These demonstrate your ability to detect lateral movement!

---

## 🎓 Learning Points

**Why this matters:**
- Lateral movement is a key attack technique
- SMB is commonly used for network file sharing
- Logon Type 3 indicates network authentication
- Detecting lateral movement helps stop attack progression

**Real-world context:**
- Attackers use SMB to move through networks
- This is part of the MITRE ATT&CK framework (T1021.002)
- SOC analysts must detect unauthorized SMB access
- Often follows initial compromise

**Related MITRE ATT&CK Techniques:**
- **T1021:** Remote Services
- **T1021.002:** SMB/Windows Admin Shares
- **T1078:** Valid Accounts

---

## ✅ Ready for Next Scenario?

Once you've verified:
- [ ] SMB connections are visible in Splunk
- [ ] Detection queries work correctly
- [ ] You understand what Logon Type 3 means
- [ ] You can identify lateral movement attempts

You're ready for **Scenario 5: Data Exfiltration**!

---

## 💡 Pro Tips

1. **Logon Type 3 is network logon** - Indicates SMB, RPC, or other network authentication
2. **Check the Source IP** - Should match your attacker machine (Kali)
3. **Look for patterns** - Multiple connections from same IP is suspicious
4. **Correlate with other events** - Check for file access events (5140, 5143) on shares
5. **Monitor share access** - Event ID 5140 shows when files are accessed on shares

Good luck! 🚀



