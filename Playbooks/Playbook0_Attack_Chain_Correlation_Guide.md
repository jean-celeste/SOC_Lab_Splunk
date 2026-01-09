# 🔴 Playbook 0: Attack Chain Correlation Guide

> **Note:** This playbook provides guidance on correlating findings across multiple incident response playbooks. Use this guide when investigating complex attack chains that span multiple MITRE ATT&CK tactics.

### Purpose

This guide helps SOC analysts:
- Identify when multiple playbooks should be investigated in parallel
- Correlate findings across different attack types
- Understand common attack chain progressions
- Escalate appropriately between playbooks
- Build a complete picture of the attack lifecycle

---

## Common Attack Chains

### Chain 1: Credential Access → Lateral Movement → Privilege Escalation

**Typical Progression:**
1. **Brute Force Attack (Playbook 1)** - Attacker gains credentials
2. **Lateral Movement (Playbook 4)** - Attacker uses credentials to access other systems
3. **Privilege Escalation (Playbook 3)** - Attacker elevates privileges on compromised systems

**Investigation Flow:**
```
Start: Playbook 1 (Brute Force)
  ↓ (If Event ID 4624 detected from attacker IP)
Check: Playbook 4 (Lateral Movement)
  ↓ (If Event ID 4624, Logon Type 3 detected)
Check: Playbook 3 (Privilege Escalation)
  ↓ (If Event ID 4732/4728 detected)
CRITICAL: Full system compromise
```

**Correlation Queries:**

**Query 1: Brute Force → Successful Logon → Lateral Movement**
```spl
index=windows_security (EventCode=4625 OR EventCode=4624)
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| eval attack_phase=case(
    EventCode=4625, "Brute Force Attempt",
    EventCode=4624 AND Logon_Type=3, "Lateral Movement",
    EventCode=4624 AND Logon_Type != 3, "Successful Logon",
    1=1, "Other"
)
| stats count, values(Account_Name) as accounts by Source_Network_Address, attack_phase
| sort Source_Network_Address, attack_phase
```

**Query 2: Lateral Movement → Privilege Escalation**
```spl
index=windows_security (EventCode=4624 OR EventCode=4732 OR EventCode=4728)
| eval event_type=case(
    EventCode=4624 AND Logon_Type=3 AND Source_Network_Address != "-" AND Source_Network_Address != "", "Lateral Movement",
    EventCode=4732, "Privilege Escalation",
    EventCode=4728, "Privilege Escalation",
    1=1, "Other"
)
| where event_type="Lateral Movement" OR event_type="Privilege Escalation"
| eval source_ip=if(event_type="Lateral Movement", Source_Network_Address, "Local Action")
| stats count by Account_Name, event_type, source_ip
| sort Account_Name, _time
```

**Note:** Privilege Escalation events (4732/4728) are local administrative actions and don't have `Source_Network_Address` populated. The query now:
- Filters for network source addresses ONLY for Lateral Movement events (4624, Logon Type 3)
- Allows Privilege Escalation events to pass through regardless of Source_Network_Address
- Uses `source_ip` field to show network IPs for lateral movement and "Local Action" for privilege escalation

---

### Chain 2: Execution → Exfiltration

**Typical Progression:**
1. **Suspicious PowerShell (Playbook 2)** - Attacker executes malicious commands
2. **Data Exfiltration (Playbook 5)** - Attacker exfiltrates data via network connections

**Investigation Flow:**
```
Start: Playbook 2 (Suspicious PowerShell)
  ↓ (If PowerShell making network connections detected)
Check: Playbook 5 (Data Exfiltration)
  ↓ (If Event ID 3 to non-standard ports detected)
CONFIRMED: Data exfiltration in progress
```

**Correlation Queries:**

**Query 1: PowerShell Execution → Network Connections**
```spl
index=sysmon (EventCode=1 OR EventCode=3)
| where Image="*powershell.exe"
| eval event_type=case(
    EventCode=1, "PowerShell Execution",
    EventCode=3, "Network Connection",
    1=1, "Other"
)
| stats count, values(CommandLine) as commands, values(DestinationIp) as dest_ips by User, event_type
| where event_type="PowerShell Execution" OR event_type="Network Connection"
| sort User, event_type
```

**Query 2: PowerShell with Encoded Commands → Exfiltration**
```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| where CommandLine LIKE "%-enc%" OR CommandLine LIKE "%download%" OR CommandLine LIKE "%invoke%"
| join type=inner ProcessId [
    search index=sysmon EventCode=3
    | where DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443
]
| stats count by User, CommandLine, DestinationIp, DestinationPort
| sort -count
```

---

### Chain 3: Lateral Movement → Privilege Escalation → Exfiltration

**Typical Progression:**
1. **Lateral Movement (Playbook 4)** - Attacker moves through network
2. **Privilege Escalation (Playbook 3)** - Attacker gains admin access
3. **Data Exfiltration (Playbook 5)** - Attacker steals sensitive data

**Investigation Flow:**
```
Start: Playbook 4 (Lateral Movement)
  ↓ (If Event ID 4624, Logon Type 3 detected)
Check: Playbook 3 (Privilege Escalation)
  ↓ (If Event ID 4732/4728 detected)
Check: Playbook 5 (Data Exfiltration)
  ↓ (If Event ID 3 to non-standard ports detected)
CRITICAL: Full attack chain confirmed
```

**Correlation Queries:**

**Query 1: Complete Attack Chain Timeline**
```spl
index=windows_security (EventCode=4624 OR EventCode=4732 OR EventCode=4728)
| where Source_Network_Address != "-" AND Source_Network_Address != ""
| eval event_type=case(
    EventCode=4624 AND Logon_Type=3, "Lateral Movement",
    EventCode=4732, "Privilege Escalation",
    EventCode=4728, "Privilege Escalation",
    1=1, "Other"
)
| table _time, Account_Name, Source_Network_Address, event_type
| sort _time
```

---

### Chain 4: Credential Access → Execution → Privilege Escalation → Exfiltration

**Typical Progression:**
1. **Brute Force Attack (Playbook 1)** - Initial credential compromise
2. **Suspicious PowerShell (Playbook 2)** - Malicious execution
3. **Privilege Escalation (Playbook 3)** - Administrative access
4. **Data Exfiltration (Playbook 5)** - Data theft

**Investigation Flow:**
```
Start: Playbook 1 (Brute Force)
  ↓ (If Event ID 4624 detected)
Check: Playbook 2 (Suspicious PowerShell)
  ↓ (If Event ID 1 with encoded commands detected)
Check: Playbook 3 (Privilege Escalation)
  ↓ (If Event ID 4732/4728 detected)
Check: Playbook 5 (Data Exfiltration)
  ↓ (If Event ID 3 to non-standard ports detected)
CRITICAL: Complete attack lifecycle confirmed
```

**Correlation Queries:**

**Query 1: Complete Attack Lifecycle**
```spl
(index=windows_security (EventCode=4625 OR EventCode=4624 OR EventCode=4732 OR EventCode=4728)) OR
(index=sysmon (EventCode=1 OR EventCode=3))
| eval event_type=case(
    EventCode=4625, "Brute Force",
    EventCode=4624, "Successful Logon",
    EventCode=4732, "Privilege Escalation",
    EventCode=4728, "Privilege Escalation",
    EventCode=1 AND Image="*powershell.exe" AND CommandLine LIKE "%-enc%", "Suspicious PowerShell",
    EventCode=3 AND DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443, "Data Exfiltration",
    1=1, "Other"
)
| where event_type != "Other"
| stats count by event_type, Account_Name, Source_Network_Address
| sort event_type, Account_Name
```

---

## Master Correlation Queries

### Master Query: All Attack Types

**Purpose:** Identify all attack types in a single query to see the complete attack picture.

```spl
(index=windows_security (EventCode=4625 OR EventCode=4624 OR EventCode=4732 OR EventCode=4728)) OR
(index=sysmon (EventCode=1 OR EventCode=3))
| eval account=coalesce(Account_Name, User, "-")
| eval source_ip=coalesce(Source_Network_Address, "Local Action", "-")
| eval attack_type=case(
    EventCode=4625, "Brute Force",
    EventCode=4624 AND Logon_Type=3 AND source_ip != "-" AND source_ip != "", "Lateral Movement",
    EventCode=4624 AND Logon_Type != 3, "Successful Logon",
    EventCode=4732, "Privilege Escalation",
    EventCode=4728, "Privilege Escalation",
    EventCode=1 AND (Image LIKE "%powershell.exe" OR lower(Image) LIKE "%powershell.exe") AND (CommandLine LIKE "%-enc%" OR CommandLine LIKE "%EncodedCommand%" OR CommandLine LIKE "% -enc %" OR lower(CommandLine) LIKE "%encodedcommand%"), "Suspicious PowerShell",
    EventCode=3 AND DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443 AND DestinationPort != 3389 AND DestinationPort != 445, "Data Exfiltration",
    1=1, "Other"
)
| where attack_type != "Other"
| stats count, earliest(_time) as first_seen, latest(_time) as last_seen by attack_type, account, source_ip
| eval duration_minutes=round((last_seen - first_seen)/60, 2)
| convert ctime(first_seen) ctime(last_seen)
| sort attack_type, -count
```

**Note:** This query:
- Uses `coalesce()` to handle field differences between Windows Security and Sysmon events
- Normalizes account names (`Account_Name` for Windows events, `User` for Sysmon events)
- Handles `Source_Network_Address` being empty for local events (Privilege Escalation)
- Includes additional PowerShell detection patterns (`-EncodedCommand`)
- Filters out common ports (3389, 445) for Data Exfiltration detection

**Troubleshooting "Suspicious PowerShell" not appearing:**

If "Suspicious PowerShell" doesn't show up, run these diagnostic queries:

1. **Search for ALL PowerShell processes (including different paths):**
   ```spl
   index=sysmon EventCode=1 
   | where Image LIKE "%powershell%" OR Image LIKE "%PowerShell%"
   | head 20
   | table _time, Image, CommandLine, User
   ```

2. **Search specifically for commands with -enc flag (regardless of Image path):**
   ```spl
   index=sysmon EventCode=1 
   | where CommandLine LIKE "%-enc%" OR CommandLine LIKE "%EncodedCommand%" OR CommandLine LIKE "% -enc %"
   | table _time, Image, CommandLine, User
   | sort -_time
   ```

3. **Check what PowerShell Image paths actually exist:**
   ```spl
   index=sysmon EventCode=1 
   | where Image LIKE "%powershell%" OR Image LIKE "%PowerShell%"
   | stats count by Image
   | sort -count
   ```

4. **Search for PowerShell in CommandLine field (even if Image is different):**
   ```spl
   index=sysmon EventCode=1 
   | where CommandLine LIKE "%powershell%" AND (CommandLine LIKE "%-enc%" OR CommandLine LIKE "%EncodedCommand%")
   | table _time, Image, CommandLine, User
   | sort -_time
   ```

**Common reasons "Suspicious PowerShell" doesn't appear:**
- No PowerShell processes with `-enc` or `-EncodedCommand` flags were executed
- The `CommandLine` field is empty/null in Sysmon Event ID 1 events (check Sysmon configuration)
- PowerShell was executed but without encoded commands (normal PowerShell execution won't match)
- The `Image` field path might be different (e.g., `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` vs `powershell.exe`)

### Master Query: Attack Timeline

**Purpose:** Create a timeline of all attack activities to understand the sequence of events.

```spl
(index=windows_security (EventCode=4625 OR EventCode=4624 OR EventCode=4732 OR EventCode=4728)) OR
(index=sysmon (EventCode=1 OR EventCode=3))
| eval account=coalesce(Account_Name, User, "-")
| eval source_ip=coalesce(Source_Network_Address, "Local Action", "-")
| eval attack_type=case(
    EventCode=4625, "Brute Force",
    EventCode=4624 AND Logon_Type=3 AND source_ip != "-" AND source_ip != "", "Lateral Movement",
    EventCode=4624 AND Logon_Type != 3, "Successful Logon",
    EventCode=4732, "Privilege Escalation",
    EventCode=4728, "Privilege Escalation",
    EventCode=1 AND (Image LIKE "%powershell.exe" OR lower(Image) LIKE "%powershell.exe") AND (CommandLine LIKE "%-enc%" OR CommandLine LIKE "%EncodedCommand%" OR CommandLine LIKE "% -enc %" OR lower(CommandLine) LIKE "%encodedcommand%"), "Suspicious PowerShell",
    EventCode=3 AND DestinationPort != 53 AND DestinationPort != 80 AND DestinationPort != 443 AND DestinationPort != 3389 AND DestinationPort != 445, "Data Exfiltration",
    1=1, "Other"
)
| where attack_type != "Other"
| table _time, attack_type, account, source_ip, host
| sort _time
```

---

## Escalation Decision Tree

### When to Investigate Multiple Playbooks

**If you detect Brute Force (Playbook 1):**
- ✅ **Always check:** Playbook 4 (Lateral Movement) - successful logons may indicate lateral movement
- ✅ **If admin access detected:** Playbook 3 (Privilege Escalation)
- ✅ **If PowerShell detected:** Playbook 2 (Suspicious PowerShell)
- ✅ **If network connections detected:** Playbook 5 (Data Exfiltration)

**If you detect Suspicious PowerShell (Playbook 2):**
- ✅ **Always check:** Playbook 5 (Data Exfiltration) - PowerShell often used for exfiltration
- ✅ **If admin access detected:** Playbook 3 (Privilege Escalation)
- ✅ **If network logons detected:** Playbook 4 (Lateral Movement)
- ✅ **If preceded by failed logons:** Playbook 1 (Brute Force)

**If you detect Privilege Escalation (Playbook 3):**
- ✅ **CRITICAL - Check ALL playbooks:**
  - Playbook 1 (Brute Force) - how did they get initial access?
  - Playbook 2 (Suspicious PowerShell) - what execution led to escalation?
  - Playbook 4 (Lateral Movement) - did they move through network?
  - Playbook 5 (Data Exfiltration) - are they stealing data?

**If you detect Lateral Movement (Playbook 4):**
- ✅ **Always check:** Playbook 3 (Privilege Escalation) - lateral movement often leads to privilege escalation
- ✅ **If data exfiltration detected:** Playbook 5 (Data Exfiltration)
- ✅ **If preceded by failed logons:** Playbook 1 (Brute Force)
- ✅ **If PowerShell detected:** Playbook 2 (Suspicious PowerShell)

**If you detect Data Exfiltration (Playbook 5):**
- ✅ **Always check:** Playbook 2 (Suspicious PowerShell) - PowerShell often used for exfiltration
- ✅ **If preceded by lateral movement:** Playbook 4 (Lateral Movement)
- ✅ **If admin access detected:** Playbook 3 (Privilege Escalation)
- ✅ **If preceded by failed logons:** Playbook 1 (Brute Force)

---

## Severity Escalation Guidelines

### When to Escalate Severity

**Medium → High:**
- Brute Force (Medium) + Successful Logon → Escalate to High
- Brute Force (Medium) + Lateral Movement → Escalate to High

**High → Critical:**
- Any High severity attack + Privilege Escalation → Escalate to Critical
- Data Exfiltration (High) + Sensitive Data Confirmed → Escalate to Critical
- Multiple attack types detected simultaneously → Escalate to Critical

**Critical Indicators:**
- Privilege Escalation detected (always Critical)
- Multiple attack chains active simultaneously
- Data exfiltration of sensitive data (PII, credentials, financial)
- Administrative access combined with data exfiltration

---

## Investigation Workflow

### Step 1: Initial Detection
- Identify the initial alert/event
- Determine which playbook to start with
- Note the time, source IP, and affected accounts

### Step 2: Parallel Investigation
- Run correlation queries to identify related attack types
- Investigate all related playbooks in parallel
- Document findings from each playbook

### Step 3: Attack Chain Reconstruction
- Use timeline queries to understand attack sequence
- Identify the full attack lifecycle
- Map findings to MITRE ATT&CK framework

### Step 4: Severity Assessment
- Determine if severity needs escalation
- Consider all attack types in aggregate
- Assess total business impact

### Step 5: Coordinated Response
- Execute containment from all relevant playbooks
- Prioritize Critical severity actions
- Coordinate recovery across all affected systems

---

## Best Practices

1. **Always investigate related playbooks** - Attacks rarely occur in isolation
2. **Use correlation queries** - Don't rely on manual correlation alone
3. **Document the full attack chain** - Understanding the complete lifecycle is critical
4. **Escalate severity appropriately** - Multiple attack types increase overall severity
5. **Coordinate containment** - Actions from multiple playbooks may need coordination
6. **Track metrics across playbooks** - MTTD/MTTR/MTTC should account for the full attack chain

---

## Quick Reference

| Initial Detection | Always Check | If Detected |
|-------------------|--------------|-------------|
| Brute Force | Lateral Movement | Privilege Escalation, PowerShell, Exfiltration |
| Suspicious PowerShell | Data Exfiltration | Privilege Escalation, Lateral Movement |
| Privilege Escalation | **ALL PLAYBOOKS** | **CRITICAL - Full investigation required** |
| Lateral Movement | Privilege Escalation | Data Exfiltration, Brute Force |
| Data Exfiltration | Suspicious PowerShell | Privilege Escalation, Lateral Movement |

---

**Return to:** [Phase 8: Incident Response Playbooks Overview](../Phase8_Incident_Response_Playbooks.md)
