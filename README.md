# NTLM Enumeration Burst Detection
**MITRE ATT&CK:** T1046 - Network Service Discovery
T1078 - Valid Accounts
T1557 - Adversary-in-the-Middle
**Log Source:** Windows Security Events via AMA → Sentinel
**Event ID:** 4624 - Successful Logon

## Overview
When enumeration tools like enum4linux-ng or crackmapexec
hit a domain controller, they don't knock once — they
hammer it with rapid automated connections. This detection
catches that burst pattern by identifying source IPs that
generate more than 5 successful NTLM network logons within
a single minute window against a DC.

The key insight: legitimate users authenticate once.
Tools authenticate dozens of times per second.

## What This Catches
- enum4linux-ng unauthenticated and authenticated scans
- crackmapexec SMB enumeration
- Metasploit auxiliary enumeration modules
- Any tool making rapid automated NTLM connections
  to a domain controller

## The Attack This Detects
An attacker who has mapped the network via Nmap now
wants to extract the AD blueprint — user accounts,
groups, shares, password policies. They run an
enumeration tool against the DC. That tool makes
20 NTLM connections in 2 seconds. This rule catches
exactly that pattern.

## Detection Logic
- Filter to successful network logons (4624, LogonType 3)
- Filter to NTLM authentication only
- Target domain controller specifically
- Exclude localhost and system-generated traffic
- Group by source IP in 1 minute time windows
- Flag any IP exceeding 5 authentications per window
- Calculate burst duration and authentication rate
- Surface highest volume offenders first

## Key Detection Insight — NTLM vs Kerberos
Connecting to a DC via IP address forces NTLM
authentication and avoids generating Kerberos ticket
events (4768/4769). This is a known detection evasion
technique. Legitimate domain computers authenticate
via Kerberos using hostnames — NTLM network logons
to a DC from non-standard sources are inherently
suspicious.

## KQL Detection Rule
```kql
// Rapid NTLM Authentication Burst Detection
// Identifies automated enumeration tools via burst
// authentication patterns against domain controllers
// MITRE ATT&CK: T1046, T1078, T1557

let TimeWindow = 1m;      // Detection window
let AuthThreshold = 5;    // Min auths to trigger alert

SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624           // Successful logon
| where LogonType == 3            // Network logon
| where AuthenticationPackageName == "NTLM"
| where Computer has "DC01"       // Target DC only
| where IpAddress !in (           // Exclude system noise
    "127.0.0.1", "::1", "-")
| summarize
    AuthCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Accounts = make_set(Account),
    Computers = make_set(Computer)
    by IpAddress, bin(TimeGenerated, TimeWindow)
| where AuthCount >= AuthThreshold
| extend DurationSeconds = datetime_diff(
    'second', LastSeen, FirstSeen)
| extend AuthPerSecond = AuthCount /
    iif(DurationSeconds == 0, 1, DurationSeconds)
| project
    FirstSeen,
    LastSeen,
    IpAddress,
    AuthCount,
    DurationSeconds,
    AuthPerSecond,
    Accounts,
    Computers
| order by AuthCount desc
```

## Validation Results
Rule executed against live Sentinel data from
DC01.lab.local. Captured two real enumeration
sessions from Kali Linux (10.10.10.50):

Session 1 — enum4linux-ng unauthenticated scan:
- AuthCount: 20 connections
- Duration: 2 seconds
- Rate: 10 authentications per second
- Account: NT AUTHORITY\ANONYMOUS LOGON

Session 2 — Earlier enumeration session:
- AuthCount: 13 connections
- Duration: 3 seconds
- Rate: 4 authentications per second
- Account: NT AUTHORITY\ANONYMOUS LOGON

Both sessions correctly identified and surfaced
by the detection rule.

## So What
An enumeration tool running against your domain
controller is the clearest signal that an attacker
has moved past reconnaissance and is actively
mapping your environment. They know what's alive.
Now they want to know everything about it — user
accounts, groups, shares, password policies. This
rule fires within the first minute of that activity,
giving the SOC a response window before the attacker
obtains the intelligence they need to move laterally
or escalate privileges.

## Tuning Guidance

## False Positive Considerations
- Legitimate monitoring tools — add their IPs to exclusion list
- Vulnerability scanners — schedule during maintenance windows
- Service accounts making multiple connections — 
  investigate and whitelist if confirmed legitimate

## Additional Finding — Null Session Exposure
DC01 permits anonymous RPC null sessions allowing
unauthenticated enumeration of basic domain
information including Domain SID. This is what
generated the ANONYMOUS LOGON account entries
in our detection output.

Remediation:

## Identity & Trust Context
NTLM enumeration bursts represent a trust boundary
probe — an external entity testing what the domain
will reveal without proper authentication. The
anonymous logon pattern specifically shows the
attacker is exploiting the null session trust
relationship that DC01 permits by default.
Restricting null sessions closes this trust gap
and forces attackers to obtain credentials before
any enumeration is possible.

## Environment
- Attack tool: enum4linux-ng v1.3.10
- Attack machine: Kali Linux (10.10.10.50)
- Target: DC01.lab.local (Windows Server 2022)
- Pipeline: AMA → Azure Arc → DCR → 
            DetectionLab-LAW → Sentinel
- Validated against live production telemetry
- Lab: Isolated HyperV environment

- KQL detection identifying automated enumeration tool
behavior via NTLM authentication burst patterns against
domain controllers. Validated against live enum4linux-ng
sessions. Includes null session exposure finding.
MITRE T1046, T1078, T1557.
