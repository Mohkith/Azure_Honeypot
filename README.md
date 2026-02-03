# Azure Honeypot using Microsoft Sentinel (SIEM)
![Azure Honeypot](/Architecture/Honeypot_Architecture.png)

## ◽Project Overview
This project demonstrates the design and deployment of a **cloud-based honeypot on Microsoft Azure** to simulate real-world cyber attacks and analyze them using **Azure Log Analytics** and **Microsoft Sentinel (SIEM)**.

A publicly exposed Azure Virtual Machine was intentionally configured with **all inbound ports open** to attract malicious traffic. The generated security logs were collected, analyzed, and visualized to identify attacker behavior, IP addresses, and event patterns using **KQL (Kusto Query Language)**.

---

## ◽Objectives
- Simulate real-world attack scenarios in a cloud environment  
- Collect and analyze security logs using SIEM  
- Identify attacker IPs, Event IDs, and attack trends  
- Gain hands-on experience with Azure security monitoring  

---

## ◽Technologies Used
- **Microsoft Azure**
  - Azure Virtual Machine (Windows Server 2025)
  - Network Security Groups (NSG --> Configure to allow all incoming connections on all ports)
  - Log Analytics Workspace( Used to collect and store logs)
- **Microsoft Sentinel (SIEM)**
- **KQL (Kusto Query Language)**
  
---

## ◽Architecture
1. Azure VM deployed with a public IP  
2. NSG configured to allow all inbound traffic  
3. Logs forwarded to Log Analytics Workspace  
4. Microsoft Sentinel connected to the workspace  
5. KQL queries used for log analysis

Check the `/architecture` folder for more detailed configuration

📷 *(Architecture diagram available in `/architecture` folder)*

---

## ◽Log Analysis & KQL Queries

### ◽Attacker IP Identification
```kql
SecurityEvent
| where EventLevelName == "Error"
| summarize count() by IPAddress
| order by count_ desc

