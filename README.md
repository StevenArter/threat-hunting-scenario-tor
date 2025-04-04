<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/StevenArter/threat-hunting-scenario-tor/tree/main)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

I investigated file events on the VM vm-part2-steven by filtering for activity initiated by the user alienbob977 after a specific timestamp. I targeted files with "tor" in the name to check for any potential Tor-related activity. I sorted the results by the most recent events and projected key fields like ActionType, FolderPath, SHA256, and the filename to focus on relevant details. This helped me quickly identify any suspicious file operations tied to that user and context. I came to the result that a file named Tor shopping list was created.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "vm-part2-steven"  
| where InitiatingProcessAccountName == "alienbob977"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2025-04-04T00:54:30.2101662Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/536f57eb-f4e0-4027-aa9e-1fc9302d3c8d)

---

### 2. Searched the `DeviceProcessEvents` Table

I investigated process events on vm-part2-steven, filtering for executions that included "tor-browser-windows-x86_64-portable-14.0.9.exe" in the command line at timestamp 2025-04-04T01:00:47.1132788Z. I focused on key details like the action type, device name, account name, file name, timestamp, and folder path to analyze the execution context. using a command that triggered a silent installation. 
**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "vm-part2-steven"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.9.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/18efe9de-0466-41bd-8340-77d405b10864)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

I reviewed process activity on the device VM-part2-steven to identify any attempts to run Tor or related applications. I focused on processes with filenames like tor.exe, firefox.exe, and tor-broswer.exe to catch any direct or disguised executions of the Tor browser. This helped me get a clear picture of what was executed, when, and how it was launched, allowing me to assess that suspicious activity occurred involving Tor software on Apr 3, 2025 8:02:06 PM.
**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "vm-part2-steven"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/5c3f56b9-8501-4a83-9443-c39be98d789b)

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Started with using DeviceNetworkEvents table for any sign of Tor being used to establish a connection using known Tor ports. Ex:"9001", "9030", "9050", "9051", "9150", "9151", "443", "80". On April 3, 2025 at 10:37 PM, the user account alienbob977 executed tor.exe from the folder path: makefile C:\Users\alienbob977\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe The process established a remote connection to the IP address 51.15.40.38 over port 9001, which is commonly used by Tor. Tor was also used to browse regular, clear net websites using port 443.


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "vm-part2-steven"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessAccountName == "alienbob977"
| where InitiatingProcessFileName == "tor.exe"
| where RemotePort in ("9001", "9030", "9050", "9051", "9150", "9151", "443", "80")
| project ActionType, DeviceName,Timestamp, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath

```
![image](https://github.com/user-attachments/assets/4b605503-ed9d-4acd-a2a8-8fc8184c5b5c)

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-04-04T00:54:30.2101662Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.9.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\alienbob977\Downloads\tor-browser-windows-x86_64-portable-14.0.9.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-04-04T01:00:47.1132788Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.9.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.9.exe /S`
- **File Path:** `C:\Users\alienbob977\Downloads\tor-browser-windows-x86_64-portable-14.0.9.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-04-04T01:01:36.1525128Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\alienbob977\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-04-04T01:02:19.9582296Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\alienbob977\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-04-04T01:02:16.918358Z` - Connected to `185.129.61.10` on port `443`.
  - `2025-04-04T01:02:20.3428921Z` - Local connection to `51.15.40.38` on port `9001`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-04-04T00:54:30.2101662Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\alienbob977\Desktop\tor-shopping-list.txt`

---

## Summary

I’ve been monitoring vm-part2-steven for any signs of TOR usage, specifically by the user alienbob977. My focus has been on tracking file and process activity related to TOR and similar applications, paying attention to command lines, timestamps, and network activity to spot any unauthorized TOR usage.

I noticed that the user launched the TOR browser, established connections within the TOR network, and created various files related to TOR on their desktop, including a file named tor-shopping-list.txt. This sequence of activities suggests the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the shopping list file.

---

## Response Taken

TOR usage was confirmed on the endpoint `vm-part2-steven` by the user `Alienbob977`. The device was isolated, and the user's direct manager was notified.

---
