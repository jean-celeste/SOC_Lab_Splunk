# 🔴 Playbook 5: Data Exfiltration (Exfiltration)

> **Note:** This playbook was created as part of my SOC lab learning project. I researched NIST SP 800-61 framework and industry best practices, then adapted them for my home lab environment. Some queries were refined through trial and error - I've noted where I encountered issues and how I resolved them.

### MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Sub-Technique Name | Platforms | Permissions Required |
| ------ | ------------ | -------------- | ------------------ |---------- |--------------------- |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | N/A | Windows | User |

> **Note on Platforms:** In my lab, data exfiltration occurs from Windows 10 VM (192.168.1.5) to Kali Linux (192.168.1.4) via outbound network connections to non-standard ports. The attack uses PowerShell and network tools to establish connections to an external C2 server, requiring user-level permissions to make outbound network connections.

**Severity:** High (Critical if sensitive data confirmed)  
**Response Time Target:** < 10 minutes (see [Response Time Targets](../../Phase8_Incident_Response_Playbooks.md#-response-time-targets-sla))  
**Alert Name:** "Data Exfiltration Detection"  
**Attack Vector:** Outbound network connections from Windows 10 (192.168.1.5) to Kali Linux (192.168.1.4) on non-standard ports (8080, 4444, 8001-8010) using PowerShell and network tools

> **Severity Justification:** Attack technique indicates data exfiltration activity. Attack status: in progress. Target: Windows 10 endpoint making connections to external system. Impact: High - Data exfiltration indicates confidentiality breach, potential data theft, and ongoing compromise. Non-standard ports indicate malicious intent. This represents a severe confidentiality risk as data is being transferred outside the network. If sensitive data (PII, credentials, financial) is confirmed, severity escalates to Critical.

### Related Playbooks

**If PowerShell is the exfiltration method:**
- → **Playbook 2: Suspicious PowerShell** - Review PowerShell execution patterns and encoded commands

**If preceded by lateral movement:**
- → **Playbook 4: Lateral Movement (SMB)** - Check for SMB access that enabled data access

**If privilege escalation detected:**
- → **Playbook 3: Privilege Escalation** - Monitor for admin group changes (Event ID 4732/4728) that enabled data access

**If preceded by credential access:**
- → **Playbook 1: Brute Force Attack** - Review initial credential compromise (Event ID 4625/4624)

---

### 1. Preparation

**Prerequisites and Readiness Measures:**

1. **Ensure logging is configured:**
   - Sysmon installed and running on Windows 10 VM
   - Sysmon operational logs forwarding to Splunk
   - Splunk Universal Forwarder running on Windows 10 VM
   - Verify logs are being received: `index=sysmon EventCode=3 | head 10`
   - Network connection logging enabled in Sysmon

2. **Verify alerting is configured:**
   - Data Exfiltration alert created in Splunk (Phase 6)
   - Alert threshold set to detect outbound connections to non-standard ports
   - Summary index configured for alert logging

3. **Prepare tools and access:**
   - Admin access to Windows 10 VM (PowerShell)
   - Access to Splunk Web UI (`http://192.168.1.7:8000`)
   - Network access to block outbound connections via firewall
   - Ability to investigate process trees and network connections

4. **Security controls in place:**
   - Sysmon monitoring network connections (Event ID 3)
   - Outbound firewall rules can be modified
   - Network monitoring capabilities
   - Process monitoring enabled

5. **Documentation ready:**
   - Incident tracking system/template
   - Contact information for escalation
   - Data classification policies

---

### 2. Detection and Analysis

#### 2.1 Detection

**Alert Triggered:**
- **Alert Name:** Data Exfiltration Detection
- **Event ID:** 3 (Sysmon Network Connection)
- **Indicator:** Outbound connections to non-standard ports
- **Threshold:** Connections to ports other than 53, 80, 443, 3389, 445
- **Time Range:** Last 5-10 minutes

**Manual Detection Query:**
```spl
index=sysmon EventCode=3
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443 AND DestinationPort != 3389 AND DestinationPort != 445
| stats count by Image, DestinationIp, DestinationPort
| sort -count
```

> **Learning Note:** Initially, I wasn't sure which ports to exclude. I learned that ports 53 (DNS), 80 (HTTP), and 443 (HTTPS) are usually legitimate, so I filter those out. I also exclude 3389 (RDP) and 445 (SMB) since those are common in my lab environment. This aligns with our [port filtering guidance](../../Phase8_Incident_Response_Playbooks.md#-port-filtering-context-dependent-logic) - ports 3389 and 445 are excluded in data exfiltration detection because they're legitimate services in this environment, but they would be monitored in brute force (RDP) or lateral movement (SMB) scenarios. The key is identifying connections to unusual ports that could indicate data exfiltration or C2 communication.

> **Note:** Field names may vary in your environment. See [Field Naming and Extraction](../../Phase8_Incident_Response_Playbooks.md#-field-naming-and-extraction) for guidance on verifying field names using `fieldsummary`. Sysmon Event ID 3 typically has well-extracted fields, but verify in your environment.

**What to Look For:**
- Outbound connections to unusual ports (not 53, 80, 443, 3389, 445)
- Connections to external IP addresses
- Multiple connections from same process
- Connections from suspicious processes (PowerShell, cmd.exe, etc.)
- Large number of connections in short time period
- Connections to known malicious IPs (if threat intelligence available)
- High data volume transfers (if SentBytes/ReceivedBytes fields available)

#### 2.2 Analysis

**Step 1: Identify Exfiltration Activity**

Determine the extent of suspicious outbound connections:

```spl
index=sysmon EventCode=3
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443 AND DestinationPort != 3389 AND DestinationPort != 445
| stats count, values(DestinationPort) as ports, 
         values(DestinationIp) as destination_ips,
         earliest(_time) as first_seen, latest(_time) as last_seen 
  by Image, DestinationIp
| eval duration=round((last_seen - first_seen)/60, 2)
| convert ctime(first_seen) ctime(last_seen)
| sort -count
```

**This query provides:**
- Process making the connections
- Destination IP addresses
- Ports being used
- Number of connections
- Timeline of exfiltration activity
- Duration of activity

**Key Questions:**
- How many suspicious connections occurred?
- What is the destination IP address?
- Which ports are being used?
- What process is making the connections?
- How long has this activity been ongoing?

**Step 2: Identify Specific Attacker IP**

If you know the attacker IP (e.g., from Kali Linux - 192.168.1.4):

```spl
index=sysmon EventCode=3 DestinationIp=192.168.1.4
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443
| table _time, Image, DestinationIp, DestinationPort, Protocol, Initiated, User
| sort -_time
```

**This helps identify:**
- All connections to the specific attacker IP
- Which ports are being used
- Timeline of connections
- Process making connections
- Whether connections were initiated or received

**Step 3: Identify Source Process**

Determine which process is making the suspicious connections:

```spl
index=sysmon EventCode=3
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443 AND DestinationPort != 3389 AND DestinationPort != 445
| stats count, values(DestinationPort) as ports, values(DestinationIp) as dest_ips by Image
| sort -count
```

**Check for PowerShell connections:**
```spl
index=sysmon EventCode=3 Image="*powershell.exe"
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443
| stats count by DestinationIp, DestinationPort
| sort -count
```

**This helps identify:**
- Which processes are making suspicious connections
- Whether PowerShell is being used for exfiltration
- Patterns of process usage
- Most active processes

**Step 4: Timeline Analysis**

Understand the exfiltration pattern over time:

**Simple Timeline:**
```spl
index=sysmon EventCode=3 DestinationIp=192.168.1.4
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443
| timechart count span=5m
```

**Timeline by Destination IP:**
```spl
index=sysmon EventCode=3
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443 AND DestinationPort != 3389 AND DestinationPort != 445
| timechart count by DestinationIp span=5m
```

**Timeline by Port:**
```spl
index=sysmon EventCode=3 DestinationIp=192.168.1.4
| timechart count by DestinationPort
```

> **Learning Note:** I initially used `span=5m` but found it created phantom columns for ports that didn't exist in my data (like port 7800 showing all zeros). When I removed the `span` parameter, Splunk auto-determines the time interval and correctly shows only the ports that actually have connections (like port 8080). For sparse data with few connections, letting Splunk auto-determine the span works better than forcing a specific interval.

**This helps identify:**
- When data exfiltration occurred
- Frequency of connections
- Patterns of access (burst vs. steady)
- Which IPs or ports are most active

**Step 5: Check for Process Creation Before Connections**

Determine what process created the network connections:

**Simple Approach:**
Check for process creation events around the same time:

```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| table _time, Image, CommandLine, User, ParentImage, ProcessId
| sort -_time
```

**Check for related network connections:**
```spl
index=sysmon EventCode=3 DestinationIp=192.168.1.4
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443
| table _time, Image, ProcessId, DestinationIp, DestinationPort
| sort -_time
```

**This helps identify:**
- What process created the network connections
- Command line that initiated the connection
- Parent process that launched the exfiltrating process
- Full execution chain

**Step 6: Detect Suspicious Patterns**

Identify unusual outbound traffic patterns:

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
- High-volume exfiltration attempts

**Step 7: Escalation Criteria**

**When to escalate to other playbooks:**
- ✅ **If PowerShell is the exfiltration method:** Refer to **Playbook 2: Suspicious PowerShell** - review PowerShell execution patterns and encoded commands
- ✅ **If preceded by lateral movement:** Refer to **Playbook 4: Lateral Movement (SMB)** - check for SMB access that enabled data access
- ✅ **If privilege escalation detected (Event ID 4732/4728):** Refer to **Playbook 3: Privilege Escalation** - monitor for admin group changes that enabled data access
- ✅ **If preceded by credential access:** Refer to **Playbook 1: Brute Force Attack** - review initial credential compromise (Event ID 4625/4624)

**Step 8: Investigate All Associated Alerts**

- Review and clear ALL alerts associated with the impacted assets
- Check for related security events (process creation, file access)
- Document all findings

---

### 3. Containment

**Plan containment events** where these steps are launched together (or in coordinated fashion), with appropriate teams ready to respond to any disruption. **Consider the timing and tradeoffs** of containment actions: your response has consequences.

#### 3.1 Immediate Containment (0-5 minutes)

1. **Block Outbound Connection to Destination IP**
   ```powershell
   # On Windows 10 VM (PowerShell as Administrator)
   # Block outbound connection to destination IP
   New-NetFirewallRule -DisplayName "Block Exfiltration IP" `
       -Direction Outbound -RemoteAddress <DESTINATION_IP> `
       -Action Block -Enabled True
   ```

2. **Terminate Suspicious Process**
   ```powershell
   # On Windows 10 VM (PowerShell as Administrator)
   # Find the process making connections
   # Note: Get-Process doesn't show CommandLine, use Get-CimInstance instead
   Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" | 
       Where-Object {$_.CommandLine -like "*download*" -or $_.CommandLine -like "*invoke*" -or $_.CommandLine -like "*webrequest*"} | 
       Select-Object ProcessId, CommandLine
   
   # Terminate specific process (replace <PID> with actual process ID from above)
   Stop-Process -Id <PID> -Force
   
   # Alternative: Terminate all suspicious PowerShell processes at once
   Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" | 
       Where-Object {$_.CommandLine -like "*download*" -or $_.CommandLine -like "*invoke*" -or $_.CommandLine -like "*webrequest*"} | 
       ForEach-Object {Stop-Process -Id $_.ProcessId -Force}
   ```

3. **Isolate System from Network (if critical data exfiltration)**
   ```powershell
   # Disable network adapter (if critical data exfiltration suspected)
   Disable-NetAdapter -Name "Ethernet" -Confirm:$false
   ```

> **Critical Action:** Blocking outbound connections must be done immediately to prevent further data exfiltration. Even a few minutes can result in significant data loss. If sensitive data is confirmed, consider isolating the system from the network entirely.

#### 3.2 Short-term Containment (5-15 minutes)

1. **Monitor for Continued Exfiltration**
   ```spl
   index=sysmon EventCode=3 DestinationIp=<DESTINATION_IP>
   | where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443
   | stats count
   | eval status=if(count > 0, "EXFILTRATION CONTINUING", "EXFILTRATION STOPPED")
   | table status, count
   ```

2. **Check for Multiple Exfiltration Attempts**
   ```spl
   index=sysmon EventCode=3
   | where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443 AND DestinationPort != 3389 AND DestinationPort != 445
   | stats count by DestinationIp
   | where count > 10
   | sort -count
   ```

3. **Review Process Activity**
   ```powershell
   # Check for suspicious processes
   Get-Process | Where-Object {
       $_.ProcessName -like "*powershell*" -or 
       $_.ProcessName -like "*cmd*" -or
       $_.ProcessName -like "*wscript*"
   } | Select-Object ProcessName, Id, Path
   ```

4. **Check for Persistence Mechanisms**
   ```powershell
   # Check scheduled tasks
   Get-ScheduledTask | Where-Object {$_.State -eq "Running"}
   
   # Check services
   Get-Service | Where-Object {$_.Status -eq "Running"} | 
       Where-Object {$_.DisplayName -like "*suspicious*"}
   
   # Check startup programs
   Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location
   ```

5. **Collect Evidence**
   ```powershell
   # Export Sysmon network connection events
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[(EventID=3) and TimeCreated[@SystemTime>='<START_TIME>'] and TimeCreated[@SystemTime<='<END_TIME>']]]" | 
       Export-Csv -Path "C:\temp\exfiltration_network_connections.csv" -NoTypeInformation
   
   # Export process creation events for exfiltrating processes
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[(EventID=1) and TimeCreated[@SystemTime>='<START_TIME>'] and TimeCreated[@SystemTime<='<END_TIME>']]]" | 
       Where-Object {$_.Message -like "*powershell*" -or $_.Message -like "*cmd*"} | 
       Export-Csv -Path "C:\temp\exfiltration_processes.csv" -NoTypeInformation
   
   # Export file access events (if available)
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[(EventID=11) and TimeCreated[@SystemTime>='<START_TIME>'] and TimeCreated[@SystemTime<='<END_TIME>']]]" | 
       Export-Csv -Path "C:\temp\file_access_events.csv" -NoTypeInformation
   
   # Export PowerShell execution history (if available)
   Get-History | Export-Csv -Path "C:\temp\powershell_history.csv" -NoTypeInformation
   ```

---

### 4. Eradication

**Plan eradication events** where these steps are launched together (or in coordinated fashion), with appropriate teams ready to respond to any disruption.

#### Step 1: Verify Exfiltration Has Stopped

```spl
index=sysmon EventCode=3 DestinationIp=<DESTINATION_IP>
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443
| stats count
| eval status=if(count > 0, "EXFILTRATION CONTINUING", "EXFILTRATION STOPPED")
| table status, count
```

**What to look for:**
- **If `count = 0`:** No recent connections to attacker IP - exfiltration appears to have stopped
- **If `count > 0`:** Connections are still occurring - exfiltration is ongoing

#### Step 2: Investigate What Data Was Exfiltrated

**Check for file access before exfiltration:**

**Simple Approach:**
Check for file access events around the same time:

```spl
index=sysmon EventCode=11
| table _time, Image, TargetFilename, ProcessId
| sort -_time
```

**Check for network connections:**
```spl
index=sysmon EventCode=3 DestinationIp=192.168.1.4
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443
| table _time, Image, ProcessId, DestinationIp, DestinationPort
| sort -_time
```

> **Note:** I check these queries separately and manually correlate by ProcessId and time. This helps identify what files were accessed before network connections were made. This aligns with our [correlation methodology policy](../../Phase8_Incident_Response_Playbooks.md#-correlation-methodology-manual-vs-automated) - manual correlation is the preferred approach for this homelab.

**What to look for:**
- Files accessed before network connections
- File types accessed (documents, databases, etc.)
- File locations (sensitive directories)
- Correlation between file access and network connections

#### Step 3: Identify Initial Compromise Vector**

Determine how the attacker gained access:

```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| table _time, User, Image, CommandLine, ParentImage, ProcessId
| sort _time
```

**Check for related events:**
```spl
index=windows_security (EventCode=4624 OR EventCode=4625)
| table _time, EventCode, Account_Name, Source_Network_Address
| sort -_time
```

**What to look for:**
- How the exfiltrating process was launched
- Whether it was part of a larger attack chain
- Initial access method (brute force, phishing, etc.)
- Timeline of events leading to exfiltration

#### Step 4: Document Attack Details**

Create incident report with:
- Destination IP address
- Ports used for exfiltration
- Process that made connections
- Timeline of exfiltration activity
- Files accessed (if known)
- Data volume (if available)
- How initial access was gained
- Whether any data was confirmed exfiltrated

#### Step 5: Review Security Controls**

- Verify Sysmon is capturing all network connections
- Check firewall rules and outbound restrictions
- Review network monitoring capabilities
- Assess if additional monitoring is needed
- Consider implementing data loss prevention (DLP) solutions

---

### 5. Recovery

#### Step 1: Restore Network Connectivity (if disabled)

```powershell
# Re-enable network adapter (if it was disabled)
Enable-NetAdapter -Name "Ethernet" -Confirm:$false
```

#### Step 2: Remove Firewall Rule (if blocking legitimate traffic)

```powershell
# Remove the blocking rule (if no longer needed or if it blocks legitimate traffic)
Remove-NetFirewallRule -DisplayName "Block Exfiltration IP"
```

**Note:** Only remove the firewall rule after thorough investigation and if it's determined the threat has been eliminated. Consider keeping the rule if the destination IP is confirmed malicious.

#### Step 3: Review and Secure Data

- Identify what data was potentially exfiltrated
- Determine if data breach notification is required
- Review access controls on sensitive data
- Implement additional data protection measures
- Consider encrypting sensitive data at rest

#### Step 4: Monitor for Recurrence

```spl
index=sysmon EventCode=3
| where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443 AND DestinationPort != 3389 AND DestinationPort != 445
| stats count by DestinationIp
| where count > 5
| sort -count
```

---

### 6. Post-Incident Activities

**Conduct post-incident review** to identify improvements and document lessons learned.

#### 6.1 Incident Documentation

Document the following:
- Incident ID and timeline
- Destination IP address and ports used
- Process that made connections
- Timeline of exfiltration activity
- Files accessed (if known)
- Data volume exfiltrated (if available)
- How initial access was gained
- Containment actions taken
- Eradication steps performed
- Recovery procedures executed
- Response time metrics (MTTD, MTTR, MTTC)

#### 6.2 Lessons Learned

**Key Takeaways:**
- Sysmon Event ID 3 (Network Connection) is essential for detecting data exfiltration
- Filtering out common ports (53, 80, 443) helps identify suspicious connections
- Non-standard ports often indicate malicious activity or C2 communication
- Process correlation helps understand the full attack chain
- Outbound connection monitoring is critical for detecting data exfiltration
- Even failed connections generate Sysmon events (connection attempts are logged)

**Technical Considerations:**
- Event ID 3 captures both successful and failed connection attempts
- `DestinationIp` and `DestinationPort` fields are key for detection
- `Image` field shows which process made the connection
- Filtering common ports reduces false positives
- Process ID correlation helps link connections to process creation
- Data volume fields (SentBytes/ReceivedBytes) may not always be available

**Detection Improvements:**
- [ ] Add detection for large data transfers (if SentBytes/ReceivedBytes available)
- [ ] Monitor for connections to known C2 IPs (threat intelligence integration)
- [ ] Correlate file access with network connections
- [ ] Add detection for connections to unusual geographic locations
- [ ] Improve process chain analysis
- [ ] Add detection for encrypted connections to suspicious IPs
- [ ] Monitor for connections outside business hours

**Prevention Measures:**
- [ ] Implement data loss prevention (DLP) solutions
- [ ] Restrict outbound network connections where possible
- [ ] Monitor for unusual data access patterns
- [ ] Encrypt sensitive data at rest
- [ ] Implement network segmentation
- [ ] Use egress filtering and proxy servers
- [ ] Monitor for connections to known malicious IPs
- [ ] Patch asset vulnerabilities
- [ ] Perform routine inspections of controls

**Response Improvements:**
- [ ] Document response time (MTTD, MTTR, MTTC) - need to track these metrics
- [ ] Create automated script to block exfiltration IPs
- [ ] Improve data volume monitoring
- [ ] Document exfiltration patterns and indicators
- [ ] Practice incident response scenarios more frequently
- [ ] Learn more about data exfiltration techniques
- [ ] Develop better process correlation queries

**Process Improvements:**
- [ ] Perform routine cyber hygiene due diligence
- [ ] Learn more about data classification and protection
- [ ] Update incident response plan based on findings
- [ ] Get feedback from experienced SOC analysts if possible
- [ ] Review and update data protection policies regularly
- [ ] Consider implementing data loss prevention (DLP) tools

**Resources I Used:**
- NIST SP 800-61 Computer Security Incident Handling Guide
- Splunk documentation for SPL queries
- MITRE ATT&CK framework (T1041 - Exfiltration Over C2 Channel)
- Sysmon documentation for network connection monitoring
- Sample playbooks from AWS, Microsoft, and other organizations

---

## 📚 References and Learning Resources

**Resources I consulted while creating this playbook:**
- NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide
- Splunk SPL documentation and tutorials
- MITRE ATT&CK framework (T1041 - Exfiltration Over C2 Channel)
- Sysmon documentation for network connection monitoring (Event ID 3)
- Sample playbooks from AWS Security Incident Response Guide
- Microsoft Incident Response Playbook Workflows
- Various SPL query examples from Splunk community

**Tools I used:**
- Splunk Enterprise (Free tier)
- Sysmon for network monitoring
- Windows 10 VM with PowerShell
- PowerShell for Windows administration
- VirtualBox for lab environment

---

**Return to:** [Phase 8: Incident Response Playbooks Overview](../../Phase8_Incident_Response_Playbooks.md)
