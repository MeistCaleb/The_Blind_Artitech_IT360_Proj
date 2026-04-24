 # The Blind Architects Project
 # Malware Analysis Tool

## Team Members
- Caleb Meister
- Nathan Sigulas
- Campbell Russo

## What It Detects
 
| Detector | What It Looks For |
|----------|-------------------|
| **IP Detector** | Known malicious IPs, Tor exit nodes, suspicious network ranges |
| **Domain Detector** | Blacklisted domains, phishing patterns, DGA-generated domains via entropy analysis |
| **Port Detector** | 20+ known malicious ports — Metasploit (4444), Back Orifice (31337), IRC C2 (6667), Tor (9001), SMB (445), Telnet (23), and more |
| **DNS Detector** | DNS tunneling, base32-encoded labels, TXT/NULL record abuse, oversized responses |
| **HTTP Detector** | Malicious User-Agents, webshell URIs, SQL injection, XSS, path traversal, suspicious HTTP methods |
| **Payload Detector** | PowerShell encoded commands, base64/hex blobs, shellcode, LOLBins (certutil, bitsadmin), Mimikatz, reverse shells |
 
Every finding includes a **MITRE ATT&CK technique ID** for reference.
 
After every scan, findings are automatically sent to an AI model which returns a plain-English threat summary and recommended actions.
 
---
 
## Requirements
 
- Python **3.8 or higher**
- No external packages needed for core functionality
Check your Python version before starting:
 
```bash
python3 --version
```
 
---
 
## Installation
 
### Step 1 — Clone the repository
 

git clone https://github.com/MeistCaleb/The_Blind_Artitech_IT360_Proj.git

 
### Step 2 — Enter the project folder
 
cd The_Blind_Artitech_Proj.git

 
### Step 3 — Verify the top-level files are present
 
ls
 
You should see:
 
main.py   core/   intel/   output/   tests/   sample_traffic.log   README.md
 
### Step 4 — Verify the core subfolders
 
ls core/
 
You should see:
 
__init__.py   analyzer.py   models.py   pcap_reader.py   detectors/
 
ls core/detectors/
 
You should see:
 
__init__.py   base.py   ip_detector.py   domain_detector.py   port_detector.py
dns_detector.py   http_detector.py   payload_detector.py
 
> If any files or folders are missing, re-clone the repository and check again.
 
### Step 5 — Run the Tool


# Options and Definitions
## All Command Options

| Base Scan |
python3 main.py filename
 
| Option | Description |
|--------|-------------|
| `logfile` | **(Required)** Path to the log or PCAP file to analyze |
| `--severity` | Filter by severity. Choices: `critical` `high` `medium` `low`. Multiple values allowed |
| `--format` | Output format. Choices: `terminal` `json` `html` `csv`. Default is `terminal` |
| `--output` / `-o` | Save the report to a file instead of printing to the terminal |
| `--no-color` | Disable colored terminal output |
| `--quiet` / `-q` | Hide the summary header, show only the findings list |
| `--api-url` | Override the default AI API base URL |
| `--api-key` | Override the default AI API key |
 
---
 
## Severity Levels
 
| Level | Meaning |
|-------|---------|
| **CRITICAL** | Known malicious IOC, active exploit, or confirmed C2 communication |
| **HIGH** | Strong indicator of compromise or offensive tool detected |
| **MEDIUM** | Anomalous pattern that warrants investigation |
| **LOW** | Informational — verify whether this traffic is expected |
 
