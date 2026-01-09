# Homelab Challenges and Learnings

> **Note:** This document captures the real challenges I faced while building this SOC lab and creating incident response playbooks. It's honest about what was difficult, what I learned, and what I'm still working on. This is part of my learning journey, not a polished final product.

---

## Table of Contents

1. [Technical Challenges](#technical-challenges)
2. [SPL Query Challenges](#spl-query-challenges)
3. [Lab Setup Challenges](#lab-setup-challenges)
4. [MITRE ATT&CK Learning Curve](#mitre-attack-learning-curve)
5. [Playbook Creation Challenges](#playbook-creation-challenges)
6. [Time and Resource Challenges](#time-and-resource-challenges)
7. [What I've Overcome](#what-ive-overcome)
8. [Ongoing Challenges](#ongoing-challenges)
9. [Lessons Learned](#lessons-learned)

---

## Technical Challenges

### Field Name Discovery

**Challenge:** Field names in Splunk didn't match documentation examples.

**What Happened:**
- Documentation said to use `src_ip` but my environment used `Source_Network_Address`
- Expected `SubjectUserName` but found `Account_Name`
- Expected `MemberName` but had to extract from `_raw` using `rex`

**How I Solved It:**
- Learned to use `fieldsummary` command to discover actual field names
- Used `head 1 | table *` to see all available fields
- Started checking actual events before writing queries

**Still Learning:**
- Understanding when to use `spath` for XML-formatted events
- Better regex patterns for `rex` extraction
- When field extraction happens automatically vs. manually

### Windows Event ID Confusion

**Challenge:** Understanding which Event IDs to use for different scenarios.

**What Happened:**
- Initially confused Event ID 4732 vs 4728 (local vs global groups)
- Didn't know Event ID 4648 (explicit credential use) existed
- Had to research which Event IDs are available in Windows 10 vs Server

**How I Solved It:**
- Created a reference list of relevant Event IDs
- Tested queries with actual events to verify
- Referenced Microsoft documentation for Event ID meanings

**Still Learning:**
- Understanding all the different logon types (Logon_Type field)
- When to use Security log vs System log
- Event ID differences between Windows versions

### Splunk Configuration

**Challenge:** Getting logs to forward correctly from Windows to Splunk.

**What Happened:**
- Logs weren't appearing in Splunk initially
- Had to verify `inputs.conf` configuration
- Sysmon logs needed special XML rendering configuration
- Time synchronization issues between VMs

**How I Solved It:**
- Read Splunk Universal Forwarder documentation carefully
- Verified service was running: `Get-Service SplunkForwarder`
- Checked `outputs.conf` to ensure forwarding to correct IP
- Waited 1-2 minutes for logs to appear (learned about indexing delay)

**Still Learning:**
- Optimizing index configurations
- Understanding sourcetype configuration
- Field extraction configuration

---

## SPL Query Challenges

### Starting Too Complex

**Challenge:** Trying to write complex queries before understanding basics.

**What Happened:**
- Jumped straight to `join` commands without mastering `stats`
- Tried to use `eval` with complex logic before understanding simple cases
- Got frustrated when queries didn't work

**How I Solved It:**
- Started with simple `table` and `stats` queries
- Built complexity gradually
- Tested each part of a query separately
- Used `head 10` to limit results while testing

**Still Learning:**
- `join` commands for correlation (acknowledged but not mastered)
- Advanced `eval` functions
- Subsearches and their performance implications
- Query optimization techniques

### Understanding SPL Syntax

**Challenge:** SPL syntax is different from SQL or other query languages.

**What Happened:**
- Confused by pipe (`|`) operators
- Didn't understand command order matters
- Struggled with `eval` vs `where` vs `search`
- Case sensitivity issues

**How I Solved It:**
- Practiced with simple queries first
- Read Splunk documentation examples
- Used Splunk's built-in query builder initially
- Learned that commands execute left to right

**Still Learning:**
- More efficient query patterns
- When to use `stats` vs `eventstats`
- Understanding query performance
- Using `rex` more effectively

### Query Testing and Debugging

**Challenge:** Queries not working and not knowing why.

**What Happened:**
- Queries returned no results
- Field names were wrong
- Time ranges were incorrect
- Syntax errors that weren't obvious

**How I Solved It:**
- Started queries with `head 10` to see if data exists
- Used `fieldsummary` to verify field names
- Checked time ranges (used `earliest=-24h@h` for testing)
- Broke complex queries into smaller parts
- Used `table *` to see all fields

**Still Learning:**
- Better debugging techniques
- Understanding query performance metrics
- Using `rex` for field extraction more confidently

### Correlation Query Challenges

**Challenge:** Creating queries that correlate events across different data sources (Windows Security vs Sysmon).

**What Happened:**
- Tried to use `join` commands to correlate privilege escalation with data exfiltration
- Field names didn't match: `Account_Name` (Windows Security) vs `User` (Sysmon)
- `Source_Network_Address` is empty for local events (privilege escalation)
- Join queries returned no results due to field mismatches
- Account names had different formats: `JC` vs `DESKTOP-LOEK43C\JC`

**How I Solved It:**
- Learned to use `coalesce()` to normalize fields before correlation
- Created normalized fields: `account=coalesce(Account_Name, User, "-")`
- Handled empty `Source_Network_Address` with `coalesce(Source_Network_Address, "Local Action", "-")`
- Simplified some correlation queries or removed ones that didn't work
- Focused on queries that work with actual data structure

**Still Learning:**
- Better `join` command techniques
- More sophisticated correlation patterns
- Understanding when correlation queries are too complex for the data structure
- Alternative approaches to correlation (timeline-based vs join-based)

### PowerShell Detection in Correlation Queries

**Challenge:** PowerShell events not appearing in correlation queries even when encoded commands were executed.

**What Happened:**
- Correlation queries showed no "Suspicious PowerShell" attack type
- Found that PowerShell events exist but Image field shows `splunk-powershell.exe` not `powershell.exe`
- Query was filtering for `Image="*powershell.exe"` which didn't match Splunk's PowerShell executable
- CommandLine field might be empty or formatted differently than expected
- Case sensitivity issues with PowerShell detection patterns

**How I Solved It:**
- Updated queries to use case-insensitive matching: `Image LIKE "%powershell.exe" OR lower(Image) LIKE "%powershell.exe"`
- Added multiple detection patterns: `-enc`, `EncodedCommand`, ` -enc `, `encodedcommand`
- Created diagnostic queries to verify PowerShell events exist
- Learned to check actual Image paths and CommandLine field population

**Still Learning:**
- Understanding Sysmon configuration for CommandLine capture
- Better PowerShell detection patterns
- Distinguishing between legitimate PowerShell (splunk-powershell.exe) and suspicious PowerShell
- When to filter by Image path vs CommandLine content

---

## Lab Setup Challenges

### VirtualBox Networking

**Challenge:** Getting VMs to communicate properly.

**What Happened:**
- VMs couldn't ping each other initially
- NAT Network configuration was confusing
- Had to learn about VirtualBox network types
- IP addresses kept changing

**How I Solved It:**
- Switched to NAT Network (not NAT)
- Set static IPs where possible
- Documented IP addresses: 192.168.1.4 (Kali), 192.168.1.5 (Windows), 192.168.1.7 (Ubuntu)
- Tested connectivity with `ping` before proceeding

**Still Learning:**
- More advanced network configurations
- Port forwarding if needed
- Network troubleshooting techniques

### Resource Management

**Challenge:** Running multiple VMs on limited hardware.

**What Happened:**
- System slowed down with 3 VMs running
- Had to allocate RAM carefully (8GB total)
- Splunk indexing was slow sometimes
- Had to close other applications

**How I Solved It:**
- Allocated resources based on needs:
  - Ubuntu: 3GB RAM, 2 CPU
  - Windows 10: 3GB RAM, 2 CPU
  - Kali: 2GB RAM, 1 CPU
- Only ran VMs when actively working
- Used snapshots to save state

**Still Learning:**
- Better resource allocation strategies
- Splunk performance tuning
- When to use lighter alternatives

### Splunk Installation and Configuration

**Challenge:** Installing and configuring Splunk on Ubuntu Server (CLI only).

**What Happened:**
- No GUI made it harder
- Had to use command line for everything
- Configuration files were confusing
- License limits (500MB/day free tier)

**How I Solved It:**
- Followed Splunk installation documentation step by step
- Used `nano` to edit configuration files
- Accessed web UI from host machine
- Monitored license usage

**Still Learning:**
- Advanced Splunk configuration
- Index management
- User and role management
- Backup and recovery

---

## MITRE ATT&CK Learning Curve

### Understanding Technique IDs

**Challenge:** Confusing technique IDs and sub-techniques.

**What Happened:**
- Initially used T1078.002 for Local Accounts (wrong!)
- T1078.002 is actually Domain Accounts
- T1078.003 is Local Accounts
- Had to correct this in Playbook 3

**How I Solved It:**
- Referenced official MITRE ATT&CK website
- Created a reference document
- Verified technique IDs before using them
- Learned to distinguish between sub-techniques

**Still Learning:**
- More MITRE ATT&CK techniques
- Understanding technique relationships
- Mapping techniques to detection methods
- Understanding tactics vs techniques

### Mapping Attacks to MITRE

**Challenge:** Understanding which MITRE technique applies to each scenario.

**What Happened:**
- Wasn't sure if brute force was T1110 or something else
- Confused about privilege escalation techniques
- Had to research each attack type

**How I Solved It:**
- Read MITRE ATT&CK descriptions carefully
- Looked at examples and procedures
- Matched my lab scenarios to techniques
- Created a reference document

**Still Learning:**
- More attack techniques
- Understanding attack chains
- How techniques relate to each other
- Detection strategies for each technique

---

## Playbook Creation Challenges

### Following NIST Framework

**Challenge:** Understanding and implementing NIST SP 800-61 lifecycle.

**What Happened:**
- Didn't know what should go in each phase
- Unclear about containment timing (immediate vs short-term)
- Struggled with what belongs in eradication vs recovery

**How I Solved It:**
- Read NIST SP 800-61 documentation
- Looked at sample playbooks from AWS, Microsoft
- Created a template structure
- Asked for feedback and researched best practices

**Still Learning:**
- Better understanding of containment tradeoffs
- When to escalate vs handle locally
- Documentation best practices
- Metrics and measurement

### Writing Realistic Queries

**Challenge:** Creating queries that actually work in my environment.

**What Happened:**
- Copied queries from documentation that didn't work
- Field names didn't match
- Had to test and modify every query
- Some queries were too complex for my skill level

**How I Solved It:**
- Tested every query before including it
- Used actual field names from my environment
- Simplified queries to match my skill level
- Added learning notes about what I'm still learning

**Still Learning:**
- More advanced query techniques
- Better query optimization
- Understanding when to use different approaches
- Creating reusable query templates

### Balancing Completeness with Honesty

**Challenge:** Wanting to show advanced skills vs. being honest about current level.

**What Happened:**
- Initially included complex `join` queries
- Realized this didn't match my actual skill level
- Had to revise to show realistic progression
- Wanted to show learning journey, not pretend expertise

**How I Solved It:**
- Removed queries I couldn't confidently explain
- Added learning notes about what I'm still learning
- Showed progression from simple to intermediate
- Acknowledged advanced techniques exist but aren't mastered yet

**Still Learning:**
- How to present skills honestly in portfolio
- Balancing what to include vs. exclude
- Showing growth without overstating ability

---

## Time and Resource Challenges

### Time Management

**Challenge:** Balancing lab work with other responsibilities.

**What Happened:**
- Lab setup took longer than expected
- Playbook creation is time-consuming
- Had to learn many new things simultaneously
- Progress was slower than hoped

**How I Solved It:**
- Broke work into smaller chunks
- Focused on one playbook at a time
- Documented as I went (easier than remembering later)
- Set realistic expectations

**Still Learning:**
- Better time management
- Prioritizing what to learn first
- When to move on vs. perfect something

### Information Overload

**Challenge:** Too much to learn at once.

**What Happened:**
- Splunk, SPL, Windows events, MITRE ATT&CK, NIST framework
- Felt overwhelmed at times
- Hard to know what to focus on
- Information scattered across many sources

**How I Solved It:**
- Focused on one topic at a time
- Created reference documents
- Took notes as I learned
- Revisited concepts as needed

**Still Learning:**
- Better organization of learning materials
- Creating better reference documents
- Knowing when I understand something well enough

---

## What I've Overcome

### ✅ Field Name Discovery
- Now always use `fieldsummary` before writing queries
- Understand that field names vary by environment
- Know when to extract from `_raw` vs. use extracted fields

### ✅ Basic SPL Queries
- Comfortable with `stats`, `eval`, `table`, `where`
- Can create detection queries
- Understand query structure and flow

### ✅ Lab Setup
- Successfully configured 3 VMs with networking
- Splunk forwarding logs correctly
- Can troubleshoot basic connectivity issues

### ✅ Playbook Structure
- Understand NIST lifecycle phases
- Can create structured playbooks
- Know what belongs in each section
- **Completed all 5 playbooks** (Brute Force, PowerShell, Privilege Escalation, Lateral Movement, Data Exfiltration)
- Created Playbook 0 (Attack Chain Correlation Guide)

### ✅ MITRE ATT&CK Basics
- Understand technique IDs and sub-techniques
- Can map attacks to MITRE techniques
- Created reference document for techniques used

### ✅ Cross-Playbook Correlation
- Learned to use `coalesce()` for field normalization
- Created correlation queries for attack chains
- Understand how to connect events across different data sources (Windows Security vs Sysmon)

---

## Ongoing Challenges

### 🔄 Advanced SPL Techniques
- **Still Learning:** `join` commands for correlation (encountered issues with field mismatches)
- **Still Learning:** Complex `eval` functions
- **Still Learning:** Query optimization
- **Still Learning:** Subsearches
- **New Challenge:** `join` queries failed due to field name differences between Windows Security and Sysmon events
- **Learning:** Using `coalesce()` to normalize fields before joining
- **Challenge:** Some correlation queries don't work as expected - need simpler approaches

### ✅ Playbooks 4 and 5 - COMPLETED
- **Completed:** Playbook 4 (Lateral Movement - T1021.002)
- **Completed:** Playbook 5 (Data Exfiltration - T1041)
- **Completed:** Playbook 0 (Attack Chain Correlation Guide)
- All playbooks standardized with consistent structure
- Cross-playbook references added

### 🔄 Real-World Application
- **Uncertain:** How well these playbooks would work in production
- **Uncertain:** What I'm missing that real SOCs have
- **Uncertain:** How to handle more complex scenarios
- **Uncertain:** What tools real SOCs use beyond Splunk

### 🔄 Advanced Concepts
- **Still Learning:** Attack chain analysis (created correlation guide but queries need refinement)
- **Still Learning:** Threat intelligence integration
- **Still Learning:** Automation and orchestration
- **Still Learning:** Metrics and KPIs for SOC

### 🔄 PowerShell Detection Challenges
- **Challenge:** PowerShell events not appearing in correlation queries
- **Issue:** `splunk-powershell.exe` vs `powershell.exe` - different Image paths
- **Issue:** CommandLine field may be empty in Sysmon Event ID 1
- **Learning:** Need to check actual Image paths and CommandLine field population
- **Still Learning:** Better PowerShell detection patterns

---

## Lessons Learned

### 1. Start Simple, Build Complexity
Don't try to write complex queries immediately. Start with `table` and `stats`, then add complexity as you understand the data better.

### 2. Test Everything
Never assume a query will work. Test it with actual data, verify field names, check time ranges.

### 3. Document as You Go
It's easier to document challenges and solutions while you're experiencing them than to remember later.

### 4. Be Honest About Skill Level
It's better to show realistic progression than to pretend expertise. Employers value honesty and growth mindset.

### 5. Field Names Are Environment-Specific
Always verify field names using `fieldsummary`. Don't assume documentation examples will work in your environment.

### 6. Learning Takes Time
Don't get discouraged when things don't work immediately. Each challenge is a learning opportunity.

### 7. Reference Documents Are Essential
Create reference documents for field names, Event IDs, technique IDs, etc. You'll refer to them constantly.

### 8. Break Problems Into Smaller Pieces
When overwhelmed, break the problem into smaller, manageable pieces. Solve one thing at a time.

### 9. Community Resources Help
Splunk documentation, MITRE ATT&CK website, sample playbooks - use all available resources.

### 10. Progress Over Perfection
It's better to have working playbooks that show learning than perfect playbooks that don't exist yet.

### 11. Field Normalization Is Critical
When correlating events from different sources (Windows Security vs Sysmon), field names differ. Using `coalesce()` to normalize fields before correlation is essential.

### 12. Some Queries Don't Work - That's OK
Not every correlation query will work perfectly. Sometimes simpler approaches or removing problematic queries is better than forcing complex joins that don't match your data structure.

---

## Future Goals

### Short-Term (Next Few Weeks)
- [x] Complete Playbook 4 (Lateral Movement) ✅
- [x] Complete Playbook 5 (Data Exfiltration) ✅
- [x] Create Playbook 0 (Attack Chain Correlation Guide) ✅
- [x] Standardize all playbooks with consistency improvements ✅
- [ ] Test all correlation queries with actual attack scenarios
- [ ] Refine correlation queries based on testing
- [ ] Troubleshoot PowerShell detection in correlation queries
- [ ] Update documentation based on learnings

### Medium-Term (Next Few Months)
- [ ] Learn `join` commands for correlation
- [ ] Understand query optimization
- [ ] Explore more MITRE ATT&CK techniques
- [ ] Practice with more complex scenarios
- [ ] Get feedback from experienced analysts if possible

### Long-Term (Career Goals)
- [ ] Apply these skills in a real SOC environment
- [ ] Learn additional SIEM platforms
- [ ] Understand threat intelligence integration
- [ ] Learn automation and orchestration
- [ ] Contribute to security community

---

## Resources That Helped

### Documentation
- Splunk SPL documentation
- MITRE ATT&CK framework
- NIST SP 800-61 Incident Response Guide
- Windows Security Event Log documentation
- Sysmon documentation

### Sample Playbooks
- AWS Security Incident Response Guide
- Microsoft Incident Response Playbook Workflows
- Various community playbooks

### Tools
- Splunk Enterprise (Free tier)
- VirtualBox
- Sysmon
- Windows Event Viewer
- PowerShell

---

## Conclusion

This homelab project has been challenging but incredibly educational. I've learned that:
- Real-world security work is complex and requires many skills
- It's okay to not know everything - learning is continuous
- Documentation and organization are crucial
- Starting simple and building complexity is the right approach
- Honesty about skill level is more valuable than pretending expertise

I'm proud of what I've accomplished so far (3 playbooks completed) and excited to continue learning. The challenges I've faced have taught me more than if everything had worked perfectly the first time.

---

**Last Updated:** January 2026  
**Status:** All 5 playbooks completed + Playbook 0 created  
**Recent Accomplishments:**
- Completed all 5 incident response playbooks
- Created Attack Chain Correlation Guide (Playbook 0)
- Standardized playbooks with consistency improvements
- Added cross-playbook references and escalation criteria
- Created unified terminology glossary

**Next Steps:** 
- Test correlation queries with actual attack scenarios
- Troubleshoot PowerShell detection issues
- Refine attack chain correlation queries
- Continue learning advanced SPL techniques

---

**Return to:** [Phase 8: Incident Response Playbooks Overview](../Phase8_Incident_Response_Playbooks.md)


