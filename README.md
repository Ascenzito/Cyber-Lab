# Detection Lab – Microsoft Sentinel SIEM & Honeypot

## Objective

The Detection Lab project aimed to build a cloud-based Security Information and Event Management (SIEM) environment using Microsoft Sentinel, connected to a deliberately vulnerable Windows virtual machine acting as a honeypot. The VM was exposed to the public internet to attract real-world brute force attacks, with all failed login attempts forwarded to a central Log Analytics Workspace for analysis. The primary focus was to ingest and query live security event data using KQL (Kusto Query Language), enrich logs with geolocation data, and visualise attacker origins on an interactive world attack map. This hands-on project deepened practical understanding of how SOC analysts monitor networks, identify threats, and present security data in enterprise environments.

### Skills Learned

- Deployed and configured a cloud-based SIEM using Microsoft Sentinel on Azure.
- Created and configured a Windows 10 virtual machine in Azure as an intentionally exposed honeypot.
- Set up a Log Analytics Workspace to act as a centralised log repository and connected it to the honeypot VM.
- Configured Microsoft Sentinel to ingest logs from the Log Analytics Workspace for threat analysis.
- Queried failed RDP login attempts (Event ID 4625) from Windows Event Viewer using KQL.
- Uploaded geolocation data to Sentinel to enrich raw log entries with attacker location information.
- Built a custom Sentinel Workbook to visualise attack sources on an interactive world map.
- Gained practical experience reading and interpreting Windows Security Event Logs in a real-world threat context.
- Observed live brute force attack activity from multiple countries against an exposed Azure VM.

### Tools Used

- **Microsoft Azure** — Cloud platform used to host the honeypot VM and all associated resources.
- **Microsoft Sentinel** — Cloud-native SIEM used for log ingestion, KQL querying, and attack map visualisation.
- **Log Analytics Workspace** — Centralised log repository connecting the VM to Sentinel.
- **Windows 10 VM (Azure)** — Honeypot virtual machine deliberately exposed to inbound internet traffic.
- **KQL (Kusto Query Language)** — Used to query and filter security event logs within Sentinel.
- **Azure Network Security Groups (NSG)** — Configured to allow all inbound traffic, making the VM intentionally vulnerable.
- **Remote Desktop Protocol (RDP)** — Used to access and verify the honeypot VM during setup.

---

## Steps

### Step 1 – Create a Free Azure Subscription

Signed up for a free Azure account at [portal.azure.com](https://portal.azure.com). The free account provides $200 USD in credit for 30 days, which is sufficient to complete this lab. A credit card is required for sign-up but will not be charged within the free credit period.

---

### Step 2 – Create the Honeypot Virtual Machine

Navigated to **Virtual Machines** in the Azure portal and created a new Windows 10 VM with the following configuration:

- **Resource Group:** Created a new resource group (e.g. `honeypot-lab`)
- **Region:** East US
- **Image:** Windows 10 Pro
- **Size:** Standard B1s (sufficient for the lab)
- **Inbound Ports:** RDP (3389) allowed

During the networking step, configured the **Network Security Group (NSG)** to delete the default RDP inbound rule and replace it with a custom rule allowing **all inbound traffic on any port from any source** — making the VM maximally attractive to attackers on the internet.


---

### Step 3 – Verify Raw Logs on the Virtual Machine

Once the VM was deployed, connected via RDP using the public IP address. Opened **Windows Event Viewer** and navigated to:

`Windows Logs > Security`

Filtered for **Event ID 4625** (failed logon attempts) to confirm the VM was already receiving brute force login attempts from external sources. This verified that the honeypot was live and generating the security events needed for the lab.


---

### Step 4 – Create a Log Analytics Workspace

Back in the Azure portal, searched for **Log Analytics Workspaces** and created a new workspace in the same resource group and region as the VM. This workspace acts as the centralised log repository that Sentinel will query.


---

### Step 5 – Connect the VM to the Log Analytics Workspace

Inside the Log Analytics Workspace, navigated to **Virtual Machines** under the workspace settings and connected the honeypot VM. This enables the workspace to collect Windows Security Event logs directly from the VM.


---

### Step 6 – Set Up Microsoft Sentinel

Searched for **Microsoft Sentinel** in the Azure portal and added it to the Log Analytics Workspace created in Step 4. Sentinel is now connected to the log repository and ready to ingest and analyse security events.


---

### Step 7 – Query Logs with KQL

Inside Sentinel, navigated to **Logs** and used KQL to query the ingested security events. Queried for failed RDP login attempts using:

```kql
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, IpAddress, Computer, Activity
| order by TimeGenerated desc
```

Results showed real-world brute force attempts with attacker IP addresses, usernames attempted, and timestamps, confirming live data was flowing from the honeypot into Sentinel.


---

### Step 8 – Upload Geolocation Data to Sentinel

I found a geolocation watchlist file online which is a large CSV lookuptable that maps IP addresses to physical locations. I uploaded it to Sentinel via **Watchlists**. This file maps IP address ranges to countries, cities, latitude, and longitude adding to the raw log data with attacker location information.


---

### Step 9 – Query Enriched Logs to See Attacker Locations

With the geolocation watchlist in place, ran an updated KQL query joining the security events with the watchlist to surface attacker country and coordinates:

```kql
let GeoIPDB = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where EventID == 4625
    | where IpAddress != "-"
    | project IpAddress, Account, TimeGenerated;
WindowsEvents
| evaluate ipv4_lookup(GeoIPDB, IpAddress, network)
| project TimeGenerated, Account, IpAddress, country, latitude, longitude
| order by TimeGenerated desc
```

Results showed failed login attempts enriched with the attacker's country of origin, including countries from multiple continents.


---

### Step 10 – Build the Attack Map in Sentinel Workbooks

Navigated to **Microsoft Sentinel > Workbooks > Add Workbook**. Removed the default widgets and added a **query element** using the enriched KQL query from Step 9. Changed the visualisation type to **Map** and configured the map settings to plot attacks by latitude/longitude, with bubble size representing event count.

Saved the workbook as `Attack Map`. The result was a live, interactive world map showing real-time brute force attack origins against the honeypot VM.


---

## Key Takeaway

Within a short time of the VM being exposed to the internet, it began receiving hundreds of brute force login attempts from IP addresses across multiple countries. This lab demonstrates how quickly internet-exposed systems are discovered and targeted, and how a SIEM like Microsoft Sentinel can be used to collect, enrich, and visualise that threat data in a way that is actionable for a SOC analyst.

> ⚠️ **Note:** All Azure resources (VM, Log Analytics Workspace, Sentinel, Resource Group) were deleted after the lab was completed to avoid incurring charges beyond the free credit period.
