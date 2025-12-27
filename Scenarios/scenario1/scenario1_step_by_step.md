# Scenario 1: Brute Force Attack - Live Guide

## Step 1: Prepare Windows 10 VM

### 1.1 Enable RDP (Remote Desktop)

**On Windows 10 VM:**

1. Open PowerShell as Administrator (Right-click → Run as Administrator)

2. Run these commands:
```powershell
# Enable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0

# Enable RDP through firewall
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

3. Verify RDP is enabled:
```powershell
Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections"
# Should return: fDenyTSConnections : 0
```

### 1.2 Create a Test Account (Optional but Recommended)

**On Windows 10 VM (still in Admin PowerShell):**

```powershell
# Create test user
net user testuser TestPass123! /add

# Verify user was created
net user testuser
```

### 1.3 Verify RDP Port is Open

**On Kali Linux VM:**

```bash
# Check if port 3389 is open
nmap -p 3389 192.168.1.5
```

**Expected output:** Should show port 3389 as open/filtered

---

## Step 2: Execute Attack from Kali Linux

### 2.1 Open Terminal on Kali

- SSH into Kali, or
- Open terminal directly in Kali VM

### 2.2 Run Hydra Brute Force Attack

**Option A: Quick Test (Recommended for first try)**
```bash
# Create a small wordlist for testing
echo -e "password\n123456\nadmin\npassword123\ntest\nTestPass123!" > /tmp/small_wordlist.txt

# Run Hydra with small wordlist
hydra -l admin -P /tmp/small_wordlist.txt rdp://192.168.1.5 -t 4 -V
```

**Option B: Use Existing Account (if you created testuser)**
```bash
# Try to brute force the testuser account
echo -e "password\n123456\nTestPass123!\nadmin\ntest" > /tmp/small_wordlist.txt
hydra -l testuser -P /tmp/small_wordlist.txt rdp://192.168.1.5 -t 4 -V
```

**What to expect:**
- You'll see multiple login attempts
- Most will fail (generating Event ID 4625)
- Let it run for 30-60 seconds
- Press `Ctrl+C` to stop

**Note:** The `-V` flag shows verbose output so you can see each attempt

---

## Step 3: Verify in Splunk

### 3.1 Wait for Logs to Arrive

**Important:** Wait 1-2 minutes after stopping Hydra for logs to be forwarded to Splunk.

### 3.2 Open Splunk Web UI

1. Open browser on your host machine
2. Navigate to: `http://192.168.1.7:8000`
3. Login with your Splunk credentials

### 3.3 Search for Failed Logins

**In Splunk Search bar, paste:**
```spl
index=windows_security EventCode=4625
| head 20
```

**What you should see:**
- Multiple events with EventCode=4625
- Recent timestamps (within last few minutes)
- Source IP should be 192.168.1.4 (Kali)

### 3.4 Run Detection Query

**In Splunk Search bar:**
```spl
index=windows_security EventCode=4625
| stats count by Account_Name, src_ip
| where count > 5
```

**Alternative (if src_ip field doesn't exist, try this):**
```spl
index=windows_security EventCode=4625
| stats count by Account_Name, Source_Network_Address
| where count > 5
```

**Or check what fields are available:**
```spl
index=windows_security EventCode=4625
| head 1
| fieldsummary
```

### 3.5 Timeline View

**See the attack over time:**
```spl
index=windows_security EventCode=4625
| timechart count by Account_Name
```

---

## ✅ Success Checklist

- [/] RDP enabled on Windows 10
- [/] Hydra attack executed from Kali
- [/] Multiple Event ID 4625 events visible in Splunk
- [/] Detection query shows count > 5
- [/] Source IP matches Kali (192.168.1.4)

---

## 🐛 Troubleshooting

### No events in Splunk?

1. **Check if logs are flowing:**
   ```spl
   index=windows_security
   | head 10
   ```

2. **Check Splunk Forwarder on Windows:**
   ```powershell
   Get-Service SplunkForwarder
   # Should show "Running"
   ```

3. **Check recent Security events:**
   ```powershell
   # On Windows, check Event Viewer
   # Windows Logs → Security
   # Filter for Event ID 4625
   ```

### Field names not matching?

Run this to see available fields:
```spl
index=windows_security EventCode=4625
| head 1
| fieldsummary
```

Then adjust the query based on actual field names.

---

## 📸 Screenshot Tips

Take screenshots of:
1. Hydra attack running (showing attempts)
2. Splunk search results showing Event ID 4625
3. Detection query results showing count > 5
4. Timeline chart

These are great for your portfolio!

