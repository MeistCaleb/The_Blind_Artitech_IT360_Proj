"""
core/detectors/port_detector.py
Detects suspicious and malicious port usage.
"""

import re
from typing import List
from core.detectors.base import BaseDetector
from core.models import Finding

PORT_REGEX = re.compile(r'(?:DPT|dport|dst_port|port|:)\s*[=:]?\s*(\d{2,5})\b', re.I)

# Port intelligence: (severity, description, MITRE)
KNOWN_MALICIOUS_PORTS = {
    4444:  ("critical", "Metasploit Framework default listener",          "T1059"),
    31337: ("critical", "Back Orifice RAT (classic)",                     "T1219"),
    12345: ("critical", "NetBus trojan default port",                     "T1219"),
    27374: ("critical", "Sub7 trojan default port",                       "T1219"),
    1243:  ("critical", "Sub7 variant trojan",                            "T1219"),
    6666:  ("high",     "IRC C2 channel / common malware callback",       "T1071.003"),
    6667:  ("high",     "IRC C2 (standard IRC port)",                     "T1071.003"),
    6668:  ("high",     "IRC C2 variant",                                 "T1071.003"),
    1337:  ("high",     "Common backdoor/hacker port",                    "T1219"),
    9001:  ("high",     "Tor relay port",                                 "T1090.003"),
    9030:  ("high",     "Tor directory authority port",                   "T1090.003"),
    9050:  ("high",     "Tor SOCKS proxy port",                           "T1090.003"),
    1080:  ("medium",   "SOCKS proxy — possible traffic anonymization",   "T1090"),
    3128:  ("medium",   "Squid proxy — possible traffic forwarding",      "T1090"),
    8080:  ("low",      "HTTP alternate port — verify if expected",       "T1071.001"),
    8443:  ("low",      "HTTPS alternate port — verify if expected",      "T1071.001"),
    2222:  ("medium",   "Alternate SSH port — possible lateral movement", "T1021.004"),
    5900:  ("medium",   "VNC remote desktop — possible unauthorized access","T1021.005"),
    5985:  ("medium",   "WinRM HTTP — possible remote execution",         "T1021.006"),
    5986:  ("medium",   "WinRM HTTPS — possible remote execution",        "T1021.006"),
    23:    ("high",     "Telnet — cleartext protocol, rarely legitimate", "T1021"),
    512:   ("high",     "rexec — legacy remote execution protocol",       "T1021"),
    513:   ("high",     "rlogin — legacy insecure remote login",          "T1021"),
    514:   ("medium",   "rsh/syslog — legacy protocol or log exfil",     "T1021"),
    69:    ("medium",   "TFTP — used for firmware/config exfiltration",   "T1041"),
    135:   ("medium",   "RPC endpoint mapper — lateral movement vector",  "T1021.003"),
    445:   ("high",     "SMB — common lateral movement and ransomware path","T1021.002"),
    139:   ("medium",   "NetBIOS session — legacy Windows file sharing",  "T1021.002"),
}


class PortDetector(BaseDetector):
    def analyze(self, line: str) -> List[Finding]:
        findings = []
        seen_ports = set()

        for match in PORT_REGEX.finditer(line):
            port = int(match.group(1))
            if port in seen_ports or port > 65535 or port == 0:
                continue
            seen_ports.add(port)

            if port in KNOWN_MALICIOUS_PORTS:
                severity, description, mitre = KNOWN_MALICIOUS_PORTS[port]
                findings.append(self._finding(
                    severity, "SUSPICIOUS_PORT", str(port),
                    f"Port {port}/tcp — {description}",
                    mitre=mitre
                ))

            # High ephemeral port range on destination — potential beaconing
            elif 49152 <= port <= 65535:
                findings.append(self._finding(
                    "low", "HIGH_EPHEMERAL_PORT", str(port),
                    f"Destination port {port} is in the high ephemeral range — verify if expected",
                ))

        return findings
