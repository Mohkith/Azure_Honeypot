## Architecture

## 🧱 Architecture Overview

Your honeypot setup consists of:

1. A **Publicly reachable Azure VM** with all inbound ports open  
2. A **Network Security Group (NSG)** that allows all traffic  
3. A **Log Analytics Workspace** to ingest logs  
4. **Microsoft Sentinel** connected to the workspace for SIEM analysis  
5. Optional **KQL queries** for threat hunting

---

## 1️⃣ Create an Azure Virtual Machine

1. Sign in to the Azure Portal  
2. Search for **Virtual Machines** → **Create** → **Azure Virtual Machine**  
3. Choose a subscription and resource group (e.g., `honeypot-lab`)  
4. Choose a VM name (e.g., `honeypot-vm`) and an OS (Windows or Linux)  
5. For size, choose a small instance (e.g., B1ms) — cost-effective  
6. Under **Inbound port rules**, choose **Allow selected ports** or **Expose all ports** later on

---

## 2️⃣ Configure the Network Security Group (NSG)

Once the VM is created:

1. Go to the **Network Interface** of your VM  
2. Under **Networking**, click the associated **NSG**  
3. In **Inbound security rules**:
   - Remove restrictive rules
   - **Add** a rule:
     - Source: `*`
     - Destination: `*`
     - Protocol: `Any`
     - Port range: `*`
     - Action: `Allow`
     - Priority: `100`
   This will accept all inbound traffic to attract attackers. 

---

## 3️⃣ Create a Log Analytics Workspace

1. Search for **Log Analytics Workspaces** in Azure  
2. Click **Create**  
3. Select the same subscription and resource group (`honeypot-lab`)  
4. Provide a name (e.g., `honeypot-law`) and region  
5. Click **Review + Create** and **Create**  
6. Wait until deployment completes

---

## 4️⃣ Connect the VM to Log Analytics

1. Open the **Virtual Machines** blade  
2. Select your honeypot VM  
3. Choose **Logs > Connect to Log Analytics Workspace**  
4. Select your workspace (`honeypot-law`)  
5. Confirm the connection

This will install the required agents and start sending VM logs into Log Analytics. 

---

## 5️⃣ Add Microsoft Sentinel to the Workspace

1. Search for **Microsoft Sentinel** in Azure  
2. Click **Create Microsoft Sentinel**  
3. Select the **Log Analytics Workspace** you created (`honeypot-law`)

This enables Sentinel (SIEM) in your workspace. 

---

## 6️⃣ Configure Data Connectors

Microsoft Sentinel uses **data connectors** to ingest logs from supported sources.

1. In Sentinel → **Content Management → Content Hub**  
2. For each relevant source (e.g., Azure Activity, Security events):
   - Select the connector
   - Click Install
   - After installing, click Manage and select the appropriate Connector( Choose Windows Security Events via AMA for Security Events)
   - Then Create a DCR(Data Collection Rule)

Sentinel supports many connectors, including Syslog, CEF, and application logs. 

---

## 7️⃣ Validate Log Ingestion

1. Go to **Logs** in Sentinel  
2. In the query pane, run:
   ```kql
   SecurityEvent
   | take 10
   
