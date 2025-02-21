![image](https://github.com/user-attachments/assets/08eea225-52df-4e7a-8dc0-7d2ec05a1521)

Threat Hunt Report: Unauthorized TOR Usage
Scenario Creation
Platforms and Languages Leveraged
Windows 10 Virtual Machines (Microsoft Azure)
EDR Platform: Microsoft Defender for Endpoint
Kusto Query Language (KQL)
Tor Browser
Scenario
Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.
High-Level TOR-Related IoC Discovery Plan
Check DeviceFileEvents for any tor(.exe) or firefox(.exe) file events.
Check DeviceProcessEvents for any signs of installation or usage.
Check DeviceNetworkEvents for any signs of outgoing connections over known TOR ports.

Steps Taken
1. Searched the DeviceFileEvents Table
Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “labuserz” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop at 2025-02-21T19:24:20.3314002Z. These events began at:
Query used to locate events “2025-02-21T18:58:20.2816109Z”




______
Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string: “tor-browser-windows-x86_64-portable-14.0.6.exe”. Based on the logs returned at 2025-02-21T18:58:20.2816109Z, an employee on the “sentinel-practi” device ran the file “tor-browser-windows-x86_64-portable-14.0.6.exe” from their Downloads folder, using a command that triggered a silent installation.


Query used to locate events:




__________

Searched the DeviceProcessEvents table for any indication that the user “labuserz” actually opened the Tor browser. There was evidence that they did open it on 2025-02-21T19:08:56.4551665Z. There were several instances of firefox.exe (Tor) as well as tor.exe spawned afterwards. 

Query used to locate events:




____

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. At 1:09:29 PM on February 21, 2025, an employee on the “sentinel-practi” device successfully established a connection to the remote IP address 127.0.0.1 on port 9150. The connection was initiated by the process firefox.exe located in the folder c:\users\labuserz\desktop\tor browser\browser\firefox.exe. In addition there were a few connections to sites over port 443.

Query used to locate events:




Chronological Event Timeline
1. File Download - TOR Installer
Timestamp: 2025-02-21T18:58:20.2816109Z
Event: The user "labuserz" downloaded a file named tor-browser-windows-x86_64-portable-14.0.6.exe to the Downloads folder.
Action: File download detected.
File Path: C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.6.exe
2. Process Execution - TOR Browser Installation
Timestamp: 2025-02-21T18:58:20.2816109Z
Event: The User "labuserz" executed the file tor-browser-windows-x86_64-portable-14.0.6.exe in silent mode, initiating a background installation of the TOR Browser.
Action: Process creation detected.
Command: tor-browser-windows-x86_64-portable-14.0.6.exe /S
File Path: C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.6.exe
3. Process Execution - TOR Browser Launch
Timestamp: 2025-02-21T19:08:56.4551665Z
Event: User "labuserz" opened the TOR browser. Subsequent processes associated with the TOR browser, such as firefox.exe and tor.exe, were also created, indicating that the browser launched successfully.
Action: Process creation of TOR browser-related executables detected.
File Path: C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe
4. Network Connection - TOR Network
Timestamp: 2025-02-21T19:08:56.4551665Z
Event: A network connection to IP 127.0.0.1 on port 9150 by User "labuserz" was established using firefox.exe, confirming TOR browser network activity.
Action: Connection success.
Process: firefox.exe
File Path: c:\users\labuserz\desktop\tor browser\browser\firefox.exe
5. Additional Network Connections - TOR Browser Activity
Timestamps:
2025-02-21T19:09:22.2838481Z - Connected to 217.160.49.126 on port 443.
2025-02-21T19:09:21.7258776Z - Connected to 94.16.121.91 on port 443.
Event: Additional TOR network connections were established, indicating ongoing activity by User "labuserz" through the TOR browser.
Action: Multiple successful connections detected.
6. File Creation - TOR Shopping List
Timestamp: 2025-02-21T19:24:20.3314002Z
Event: The user "labuserz" created a file named tor-shopping-list.txt on the desktop, potentially indicating a list or notes related to their TOR browser activities.
Action: File creation detected.
File Path: C:\Users\employee\Desktop\tor-shopping-list.txt

Summary
The user "labuserz" on the "sentinel-practi" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named tor-shopping-list.txt. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

Response Taken
TOR usage was confirmed on the endpoint sentinel-practi by the user labuserz. The device was isolated, and the user's direct manager was notified.
