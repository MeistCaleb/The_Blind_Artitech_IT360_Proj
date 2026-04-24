"""
core/detectors/http_detector.py
Detects suspicious HTTP headers, user-agents, URIs, and traffic patterns.
"""

import re
from typing import List
from core.detectors.base import BaseDetector
from core.models import Finding

UA_RE     = re.compile(r'[Uu]ser-?[Aa]gent\s*:\s*(.+?)(?:\r?\n|$)')
HOST_RE   = re.compile(r'[Hh]ost\s*:\s*(.+?)(?:\r?\n|\s|$)')
URI_RE    = re.compile(r'(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)', re.I)
METHOD_RE = re.compile(r'\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\b')
HEADER_RE = re.compile(r'^([A-Za-z\-]+)\s*:\s*(.+)$', re.M)

# Known offensive / automated tool user-agents
MALICIOUS_UA_PATTERNS = [
    (re.compile(r'python-requests', re.I),   "critical", "Python Requests library — often used in automated attacks"),
    (re.compile(r'\bcurl\b', re.I),           "high",     "cURL command-line tool — verify if expected"),
    (re.compile(r'\bwget\b', re.I),           "high",     "Wget tool — verify if expected"),
    (re.compile(r'nmap', re.I),               "critical", "Nmap scanner user-agent"),
    (re.compile(r'masscan', re.I),            "critical", "Masscan port scanner"),
    (re.compile(r'nikto', re.I),              "critical", "Nikto web vulnerability scanner"),
    (re.compile(r'sqlmap', re.I),             "critical", "sqlmap SQL injection tool"),
    (re.compile(r'dirbuster|gobuster|ffuf|wfuzz', re.I), "critical", "Directory brute-force tool"),
    (re.compile(r'hydra|medusa|burpsuite',    re.I),      "critical", "Credential brute-force / proxy tool"),
    (re.compile(r'metasploit|msfvenom',       re.I),      "critical", "Metasploit Framework"),
    (re.compile(r'zgrab|zmap',                re.I),      "critical", "ZMap/ZGrab internet scanner"),
    (re.compile(r'go-http-client',            re.I),      "medium",   "Go HTTP client — common in malware implants"),
    (re.compile(r'apache-httpclient',         re.I),      "low",      "Apache HTTP client — verify if expected"),
    (re.compile(r'^-$|^\s*$'),                            "high",     "Empty or placeholder User-Agent — evasion attempt"),
]

# Suspicious URI patterns (C2, webshells, exploits)
SUSPICIOUS_URI_PATTERNS = [
    (re.compile(r'\.(php|aspx|jsp)\?[a-z]{1,4}=[A-Za-z0-9+/=]{16,}', re.I),
     "critical", "URI with encoded parameter — possible C2 beacon"),
    (re.compile(r'/(?:shell|cmd|exec|command|eval|phpinfo|webshell|backdoor)', re.I),
     "critical", "URI path matches common webshell pattern"),
    (re.compile(r'(?:select|union|insert|drop|xp_cmdshell).*(?:from|into|table)', re.I),
     "critical", "SQL injection payload in URI"),
    (re.compile(r'<script|javascript:|onerror=|onload=', re.I),
     "critical", "XSS payload in URI"),
    (re.compile(r'\.\./\.\./|%2e%2e%2f|\.\.%2f', re.I),
     "high", "Path traversal attempt in URI"),
    (re.compile(r'/(?:\.git|\.env|\.htaccess|wp-config\.php|config\.php)', re.I),
     "high", "Sensitive file enumeration attempt"),
    (re.compile(r'/(?:wp-login|wp-admin|phpmyadmin|adminer|manager/html)', re.I),
     "medium", "Admin panel brute-force or enumeration target"),
    (re.compile(r'\?(?:debug|test|phpinfo|diag)=', re.I),
     "medium", "Debug/diagnostic endpoint access"),
]

# Anomalous HTTP methods
SUSPICIOUS_METHODS = {"CONNECT", "TRACE", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"}


class HTTPDetector(BaseDetector):
    def analyze(self, line: str) -> List[Finding]:
        findings = []

        # --- User-Agent ---
        ua_match = UA_RE.search(line)
        if ua_match:
            ua = ua_match.group(1).strip()
            for pattern, severity, detail in MALICIOUS_UA_PATTERNS:
                if pattern.search(ua):
                    findings.append(self._finding(
                        severity, "SUSPICIOUS_USER_AGENT",
                        ua[:80], f"User-Agent: {detail}", mitre="T1071.001"
                    ))
                    break

        # --- URI analysis ---
        uri_match = URI_RE.search(line)
        if uri_match:
            uri = uri_match.group(1)
            for pattern, severity, detail in SUSPICIOUS_URI_PATTERNS:
                if pattern.search(uri):
                    findings.append(self._finding(
                        severity, "SUSPICIOUS_URI",
                        uri[:100], detail, mitre="T1071.001"
                    ))

            # Very long URI (possible overflow or exfil)
            if len(uri) > 2000:
                findings.append(self._finding(
                    "medium", "ABNORMAL_URI_LENGTH", f"{len(uri)} chars",
                    f"URI is {len(uri)} characters — abnormally long, possible data exfiltration",
                    mitre="T1041"
                ))

        # --- Suspicious HTTP method ---
        method_match = METHOD_RE.search(line)
        if method_match:
            method = method_match.group(1).upper()
            if method in SUSPICIOUS_METHODS:
                findings.append(self._finding(
                    "medium", "SUSPICIOUS_HTTP_METHOD", method,
                    f"HTTP method '{method}' is rarely used legitimately and may indicate probing",
                    mitre="T1071.001"
                ))

        # --- HTTP over unusual port (already covered by port_detector, but cross-check here) ---
        if HOST_RE.search(line):
            host_match = HOST_RE.search(line)
            host_val = host_match.group(1).strip()
            # Host header with IP address instead of domain (common in malware)
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', host_val):
                findings.append(self._finding(
                    "medium", "IP_IN_HOST_HEADER", host_val,
                    "HTTP Host header contains IP address instead of domain — common in malware C2",
                    mitre="T1071.001"
                ))

        return findings
