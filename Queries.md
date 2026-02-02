# Azure Honeypot – KQL Threat Hunting Queries

This document contains **Kusto Query Language (KQL)** queries used for threat hunting and log analysis in an **Azure Honeypot** environment using **Microsoft Sentinel** and **Log Analytics**.

---
## General
🔹.show tables --> To list all the tables

## 1. Authentication & Brute-Force Attacks

### Failed Login Attempts (Event ID 4625)

```kql
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, IPAddress, Computer
```

### Brute-Force Detection from Same IP

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IPAddress
| where FailedAttempts > 10
| order by FailedAttempts desc
```

### High-Frequency Login Attempts (Automation Detection)

```kql
SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by IPAddress, bin(TimeGenerated, 1m)
| where Attempts > 30
```

---

## 2. Successful Login After Failures (Possible Compromise)

```kql
let FailedLogins =
    SecurityEvent
    | where EventID == 4625
    | project Account, IPAddress, TimeGenerated;

let SuccessfulLogins =
    SecurityEvent
    | where EventID == 4624
    | project Account, IPAddress, TimeGenerated;

FailedLogins
| join SuccessfulLogins on Account, IPAddress
| where SuccessfulLogins_TimeGenerated > FailedLogins_TimeGenerated
```

---

## 3.RDP Attack Detection

### Failed RDP Login Attempts (LogonType 10)

```kql
SecurityEvent
| where EventID == 4625
| where LogonType == 10
| summarize count() by IPAddress
| order by count_ desc
```

---

## 4.Network Reconnaissance & Port Scanning

### Detect Port Scanning Behavior

```kql
AzureNetworkAnalytics_CL
| summarize ConnectionCount = count() by SrcIP_s, DestPort_d
| where ConnectionCount > 20
| order by ConnectionCount desc
```

---

## 5.Process Execution & Post-Exploitation Activity

### Process Creation Events (Event ID 4688)

```kql
SecurityEvent
| where EventID == 4688
| project TimeGenerated, Account, NewProcessName, CommandLine
```

### Suspicious PowerShell Execution

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName has "powershell"
| project TimeGenerated, Account, CommandLine
```

---

## 6.Privilege Escalation & Credential Abuse

### Special Privilege Assignment

```kql
SecurityEvent
| where EventID == 4672
| project TimeGenerated, Account, PrivilegeList
```

### Sensitive Privilege Usage

```kql
SecurityEvent
| where EventID == 4673
| project TimeGenerated, Account, PrivilegeList
```

---

## 7.Persistence Techniques

### New User Account Creation

```kql
SecurityEvent
| where EventID == 4720
| project TimeGenerated, Account, SubjectUserName
```

---

## 8.Azure Control Plane & Cloud Events

### Azure Resource Activity

```kql
AzureActivity
| project TimeGenerated, OperationNameValue, ActivityStatusValue, Caller, ResourceGroup
```

---

## 9.Threat Intelligence Correlation

```kql
SecurityEvent
| summarize count() by IPAddress
| join kind=leftouter ThreatIntelligenceIndicator
on $left.IPAddress == $right.NetworkIP
```

---

## 10.Attack Timeline Analysis

```kql
SecurityEvent
| summarize count() by bin(TimeGenerated, 5m)
```

---

## 11.Noise vs Signal Classification (Advanced Analysis)

```kql
SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by IPAddress
| extend AttackType = case(
    Attempts > 100, "Automated Attack",
    Attempts between (20 .. 100), "Targeted Attack",
    "Low Noise"
)
```

---

## 12.Generic Search Across All Tables

```kql
search "4625"
```

---

## Usage Notes

* These queries can be converted into **Sentinel Analytics Rules**
* Suitable for **SOC alerting**, **threat hunting**, and **incident investigation**
* Recommended to store each query as a separate `.kql` file in GitHub

---

## Author

**Mohkith Balaji R B**
Azure Security | SOC Analyst Lab | Threat Hunting
