
# Zeus Malware Detection Project
## Project Overview
This project focuses on the detection and analysis of Zeus malware artifacts in memory dumps, binaries, and network traffic using a combination of tools and techniques. The primary objective is to identify Zeus-specific patterns, behaviors, and indicators of compromise (IoCs) to understand its presence and impact on the system.
________________________________________
## Tools Used
### 1.Suricata: 
• Network monitoring tool used to detect Zeus command-and-control (C2) traffic patterns.
### 2.Splunk: 
• Log analysis and visualization tool to ingest and correlate network and system activity logs.
### 3.Volatility 3: 
- Memory forensics framework used for process analysis, network activity detection, and identifying malicious artifacts in memory dumps.
### 4.YARA: 
• Rule-based engine for scanning binaries, memory dumps, and configurations to detect Zeus-specific signatures.
________________________________________
## Project Steps
### 1. Network Traffic Monitoring with Suricata
• Configured default and custom Suricata rules to identify Zeus C2 traffic patterns. <br>
• Detected suspicious outbound traffic. <br>
### 2. Log Correlation and Visualization with Splunk <br>
• Ingested Suricata logs and memory analysis results into Splunk. <br>
• Correlated network anomalies with system process activity.<br>
• Created dashboards to visualize: <br>
      - Active network connections.<br>
      - Zeus-specific alerts.<br>
      - Process behaviors linked to network activity.<br>
### 3. Memory Dump Analysis with Volatility
• Extracted memory artifacts using Volatility plugins: <br>
      - windows.pslist: Verified process visibility to detect hidden processes.<br>
      - windows.pstree: Analyzed parent-child relationships of processes.<br>
      - windows.netscan: Identified active network connections and listening ports.<br>
### • Key Findings: 
      - Suspicious processes (services.exe, svchost.exe) exhibiting malicious behavior such as unusual listening ports and injected code.
## 4. YARA Rule Implementation
• Created a custom YARA rule (Zeus_Malware_General) to detect Zeus-specific patterns: <br>
      - NOP sleds, PE headers, shellcode patterns, and C2 traffic indicators.<br>
• Scanned memory dumps with the rule to identify Zeus-related artifacts.<br>
### • Key Matches: <br>
      - Multiple occurrences of MZ and PE headers, along with suspicious NOP sleds and C2 strings.<br>
________________________________________
## Key Findings
### 1. Malicious Processes: 
• services.exe and multiple svchost.exe instances exhibited injected code and unauthorized network activity.
### 2. C2 Communication: 
• Detected Zeus-related HTTP GET and POST requests originating from compromised processes.
### 3. Artifacts in Memory: 
• Identified multiple MZ headers, PE headers, and shellcode patterns consistent with Zeus malware.
### 4. Network Indicators: 
• Unusual listening ports and multicast DNS (port 5355) misuse.
________________________________________
## File Structure
project/<br>
├── suricata_logs/         # Suricata alerts and network traffic logs<br>
├── splunk_dashboards/     # Splunk dashboard JSON exports<br>
├── volatility_logs/       # Volatility output logs<br>
├── memory_dumps/          # Memory dumps for analysis<br>
├── yara_rules/            # YARA rule files<br>
│   └── yarazeus.yar       # Zeus-specific YARA rule<br>
├── README.md              # Project documentation (this file)<br>
└── results/               # Analysis results and summaries<br>
________________________________________
## How to Run the Analysis
### 1. Network Traffic Monitoring with Suricata
• Install and configure Suricata. <br>
• Add custom rules for Zeus detection.<br>
• Run Suricata to monitor network traffic and generate logs: <br>
• suricata -c /etc/suricata/suricata.yaml -i eth0<br>
• Analyze the generated logs in the suricata_logs/ directory for suspicious traffic patterns.<br>
### 2. Log Correlation and Visualization with Splunk
• Install Splunk and configure data ingestion.<br>
• Import logs from suricata_logs/ and volatility_logs/ into Splunk.<br>
• Create dashboards to correlate network and process activity. <br>
      - Visualize Zeus-specific alerts and behaviors.<br>
      - Identify anomalies linked to process behaviors.<br>
### 3. Memory Dump Analysis with Volatility
• Use Volatility to analyze memory dumps located in memory_dumps/: <br>
• volatility3 -f memory_dumps/zeus.mem windows.pslist<br>
• volatility3 -f memory_dumps/zeus.mem windows.pstree<br>
• volatility3 -f memory_dumps/zeus.mem windows.netscan<br>
• Document findings in the volatility_logs/ directory.<br>
### 4. YARA Rule Implementation
• Write or use custom YARA rules stored in yara_rules/.<br>
• Scan memory dumps for Zeus artifacts: <br>
• yara -r yara_rules/yarazeus.yar memory_dumps/zeus.mem<br>
• Save the analysis results in the results/ directory.<br>
________________________________________
## Contributors
• Menna Mohamed Islam 
• Haneen Amr Abdelhameed  <a href="https://github.com/haneennamr">Haneen Amr</a> <br>
• Tasneem Khaled El-Ashry <a href="https://github.com/tasneem1412">Tasneem Khaled</a> <br>
________________________________________
## Disclaimer
This project is for educational and research purposes only. Ensure all malware analysis is conducted in a secure, isolated environment to prevent accidental infection or data leaks.


