# Unified Terminology Glossary

This glossary defines standard terms used across all incident response playbooks to ensure consistency and clarity.

---

## Incident Response Terms

### Response Time Metrics

**MTTD (Mean Time to Detect)**
- Definition: The average time from when an attack starts to when it is detected and an alert is triggered
- Calculation: Alert trigger time - Attack start time (from log analysis)
- Target: Varies by severity (Critical: < 5 min, High: < 10 min, Medium: < 15 min)

**MTTR (Mean Time to Respond)**
- Definition: The average time from when an alert is triggered to when containment actions begin
- Calculation: Containment start time - Alert trigger time
- Target: < 1 minute for Critical, < 2 minutes for High/Medium

**MTTC (Mean Time to Contain)**
- Definition: The average time from when an alert is triggered to when the threat is fully contained and neutralized
- Calculation: Threat contained time - Alert trigger time
- Target: Varies by severity (Critical: < 5 min, High: < 10 min, Medium: < 15 min)

---

## Containment Terms

### Containment Phases

**Immediate Containment (0-5 minutes)**
- Definition: Initial containment actions taken immediately upon detection to stop the attack
- Examples: Block IP addresses, terminate processes, disable services
- Goal: Stop the attack as quickly as possible

**Short-term Containment (5-15 minutes)**
- Definition: Secondary containment actions taken after immediate containment to secure the environment
- Examples: Disable accounts, review permissions, collect evidence, monitor for continued activity
- Goal: Prevent further compromise and gather evidence

---

## Event and Log Terms

### Windows Event IDs

**Event ID 4624**
- Definition: Successful logon event
- Logon Types:
  - Logon Type 3: Network logon (SMB, RPC, network authentication)
  - Logon Type 5: Service logon (local, not network)
  - Logon Type 10: Remote Interactive (RDP)

**Event ID 4625**
- Definition: Failed logon attempt
- Use: Detecting brute force attacks

**Event ID 4732**
- Definition: Member added to security-enabled local group
- Use: Detecting privilege escalation (local groups)

**Event ID 4728**
- Definition: Member added to security-enabled global group
- Use: Detecting privilege escalation (domain groups)

### Sysmon Event IDs

**Event ID 1**
- Definition: Process creation
- Use: Detecting process execution, including PowerShell

**Event ID 3**
- Definition: Network connection
- Use: Detecting data exfiltration and C2 communication

**Event ID 11**
- Definition: File creation
- Use: Detecting file access and modification

---

## Field Names (Splunk)

### Standard Field Names

**Account_Name**
- Definition: User account name involved in the event
- Context: May refer to subject (who performed action) or target (who was affected)
- Note: Verify context in each playbook

**Source_Network_Address**
- Definition: Source IP address of network-based events
- Values: IP address or "-" (for local events)
- Note: Filter out "-" when looking for network-based attacks

**EventCode**
- Definition: Windows Event ID or Sysmon Event ID
- Use: Primary field for filtering events by type

**Logon_Type**
- Definition: Type of logon (3 = network, 5 = service, 10 = RDP)
- Use: Distinguishing network logons from local logons

**CommandLine**
- Definition: Full command line including arguments
- Source: Sysmon Event ID 1
- Note: Contains encoded commands even when base64-encoded

**DestinationIp / DestinationPort**
- Definition: Network connection destination
- Source: Sysmon Event ID 3
- Use: Identifying exfiltration destinations

---

## Attack Terms

### Attack Types

**Brute Force Attack**
- Definition: Automated attempt to guess passwords by trying multiple combinations
- MITRE ATT&CK: T1110
- Severity: Medium
- Detection: Event ID 4625 (failed logons)

**Lateral Movement**
- Definition: Technique used by attackers to move through a network after initial compromise
- MITRE ATT&CK: T1021.002 (SMB)
- Severity: High
- Detection: Event ID 4624, Logon Type 3

**Privilege Escalation**
- Definition: Technique used to gain higher-level permissions (e.g., administrator access)
- MITRE ATT&CK: T1078.003 (Local Accounts)
- Severity: Critical
- Detection: Event ID 4732/4728

**Suspicious PowerShell Execution**
- Definition: Execution of PowerShell with obfuscation or suspicious patterns
- MITRE ATT&CK: T1059.001
- Severity: High
- Detection: Sysmon Event ID 1 with encoded commands

**Data Exfiltration**
- Definition: Unauthorized transfer of data from a system
- MITRE ATT&CK: T1041
- Severity: High (Critical if sensitive data)
- Detection: Sysmon Event ID 3 to non-standard ports

---

## Severity Levels

### Severity Definitions

**Critical**
- Definition: Complete system compromise or immediate threat to critical assets
- Response Time: < 5 minutes
- Examples: Privilege escalation, confirmed data breach of sensitive data

**High**
- Definition: Active attack in progress with significant impact potential
- Response Time: < 10 minutes
- Examples: Suspicious PowerShell, lateral movement, data exfiltration

**Medium**
- Definition: Attack detected but not yet successful or lower impact
- Response Time: < 15 minutes
- Examples: Brute force attempts, reconnaissance activity

---

## Containment Actions

### PowerShell Commands

**Get-CimInstance Win32_Process**
- Definition: PowerShell cmdlet to get process information including CommandLine
- Use: Finding processes with specific command-line arguments
- Note: Preferred over Get-Process because it shows CommandLine

**Get-Process**
- Definition: PowerShell cmdlet to get process information
- Limitation: Does not show CommandLine field
- Use: Basic process enumeration only

**Stop-Service**
- Definition: PowerShell cmdlet to stop Windows services
- Use: Stopping services for containment (e.g., SMB service)
- Note: Consider business impact before stopping services

**Revoke-SmbShareAccess**
- Definition: PowerShell cmdlet to revoke SMB share access
- Use: Targeted containment of SMB lateral movement
- Note: Preferred over stopping entire SMB service

---

## Field Extraction Terms

### Splunk Field Extraction

**Extracted Fields**
- Definition: Fields automatically extracted by Splunk from event data
- Use: Primary method for querying event data
- Example: `| stats count by Account_Name`

**rex (Regular Expression Extraction)**
- Definition: Splunk command to extract fields using regular expressions
- Use: When extracted fields are empty or incorrect
- Example: `| rex field=_raw "Account Name:\s+(?<account_name>[^\r\n]+)"`

**fieldsummary**
- Definition: Splunk command to discover available fields in events
- Use: When field names are unknown or need verification
- Example: `| fieldsummary`

**spath**
- Definition: Splunk command to extract fields from XML/JSON structures
- Use: When events are in structured format
- Example: `| spath`

---

## Decision Criteria Terms

### Containment Decision Criteria

**Targeted Containment**
- Definition: Containment actions that affect only specific resources
- Examples: Revoke share access, disable specific accounts, block specific IPs
- Preference: Preferred when possible to minimize business impact

**Aggressive Containment**
- Definition: Containment actions that affect broader resources or services
- Examples: Stop services, disable PowerShell entirely, isolate network segments
- Use: When targeted containment is insufficient or too slow
- Requirement: Business impact assessment and approval

**Business Impact Assessment**
- Definition: Evaluation of how containment actions will affect business operations
- Components:
  - Systems/users affected
  - Alternative workarounds
  - Communication requirements
  - Service restoration timeline
- Requirement: Required before aggressive containment actions

---

## Attack Chain Terms

### Attack Chain Components

**Initial Access**
- Definition: How the attacker first gained access to the system
- Examples: Brute force, phishing, vulnerability exploitation
- Detection: First successful logon or process execution

**Execution**
- Definition: Running malicious code or commands
- Examples: PowerShell execution, script execution
- Detection: Process creation events (Sysmon Event ID 1)

**Lateral Movement**
- Definition: Moving through the network to access additional systems
- Examples: SMB access, RDP connections, network logons
- Detection: Network logons (Event ID 4624, Logon Type 3)

**Privilege Escalation**
- Definition: Gaining higher-level permissions
- Examples: Adding user to Administrators group
- Detection: Group membership changes (Event ID 4732/4728)

**Exfiltration**
- Definition: Stealing data from the system
- Examples: Network connections to external systems, file transfers
- Detection: Outbound connections to non-standard ports (Sysmon Event ID 3)

---

## Evidence Collection Terms

### Evidence Types

**Event Log Exports**
- Definition: Exported Windows Event Log or Sysmon events
- Format: CSV, EVTX, or JSON
- Use: Preserving evidence for investigation and compliance

**Process Information**
- Definition: Details about running processes
- Includes: Process ID, command line, parent process, user context
- Use: Understanding execution chains

**Network Connection Information**
- Definition: Details about network connections
- Includes: Source/destination IPs, ports, protocols, timestamps
- Use: Identifying exfiltration and C2 communication

**File System Information**
- Definition: Details about file access and modifications
- Includes: File paths, timestamps, process IDs
- Use: Understanding data access patterns

---

## Common Abbreviations

**C2 (Command and Control)**
- Definition: Server used by attackers to control compromised systems
- Detection: Outbound connections to suspicious IPs/ports

**DLP (Data Loss Prevention)**
- Definition: Security technology to prevent unauthorized data exfiltration
- Use: Preventing data theft

**GPO (Group Policy Object)**
- Definition: Active Directory feature for managing Windows settings
- Use: Configuring security policies, including account lockout

**MFA (Multi-Factor Authentication)**
- Definition: Authentication requiring multiple factors (password + token, etc.)
- Use: Preventing credential-based attacks

**PAM (Privileged Access Management)**
- Definition: Security solution for managing privileged accounts
- Use: Controlling and monitoring administrative access

**RDP (Remote Desktop Protocol)**
- Definition: Microsoft protocol for remote desktop access
- Use: Remote system access (often targeted in brute force attacks)

**SMB (Server Message Block)**
- Definition: Network protocol for file sharing
- Use: File sharing and lateral movement

**SPL (Search Processing Language)**
- Definition: Splunk's query language
- Use: Searching and analyzing log data

---

**Return to:** [Phase 8: Incident Response Playbooks Overview](../Phase8_Incident_Response_Playbooks.md)
