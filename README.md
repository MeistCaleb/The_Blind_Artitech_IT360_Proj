 # The Blind Artitech Project

## Team Members
- Caleb Meister
- Nathan Sigulas
- Campbell Russo

## Project Idea
### Malware Traffic investigation
Our project will be a malware traffic investigation tool designed to analyze network traffic and automatically identify indicators of compromise (IOCs). The tool will focus on detecting:
- Malicious or suspicious IP addresses and domains.
- Unusual or risky ports and protocols.
- Suspicious DNS queries and responses.
- Anomalous HTTP headers and traffic patterns.

### How it'll work
- Data Ingestion
	- It'll accept network traffic data.
	- Then parse traffic to extract IPs, domains, ports, DNS queries and http headers.
- Analysis Engine
	- Check IPs and domains against known bad/suspicious indicators.
	- Flag unusual port usage or uncommon protocols.
	- Inspect DNS behavior for tunneling, DGA-like patterns, or suspicious domains.
	- Analyze HTTP headers for anomalies (odd user agents, malformed headers, etc.).
- Correlation and Scoring
	- Combine multiple weak signals into a risk score.
	- Prioritize the most suspicious findings.
- Reporting
	- Generate a summarized report.

### AI Integration
- Anomaly Detection
	- Help detect patterns that deviate from the normal.
- Classification
	- Help classify traffic as benign, suspicious, or likely malicious based on features.
- Summary
	- Generate a human readable summary from the findings.

### Expected Results / Deliverables
- A working malware traffic analysis tool that:
		- Parses network traffic.
		- Flags suspicious IPs, domains, ports, DNS, and HTTP behavior.
		- Uses AI to assist with detection and summarization.
		- Produces a clear, concise investigation report.
