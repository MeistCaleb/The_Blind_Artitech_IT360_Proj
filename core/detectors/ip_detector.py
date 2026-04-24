"""
core/detectors/ip_detector.py
Detects malicious and suspicious IP addresses.
"""

import re
import ipaddress
from typing import List
from core.detectors.base import BaseDetector
from core.models import Finding
from intel.threat_feeds import ThreatFeeds

IP_REGEX = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

# Common Tor exit node ranges and known malicious CIDR blocks (abbreviated sample)
SUSPICIOUS_CIDRS = [
    "176.10.104.0/24",   # Tor exit
    "185.220.100.0/22",  # Tor exit
    "199.87.154.0/24",   # Known proxy/VPN abuse range
]

def _parse_cidrs(cidrs):
    result = []
    for c in cidrs:
        try:
            result.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            pass
    return result

SUSPICIOUS_NETWORKS = _parse_cidrs(SUSPICIOUS_CIDRS)


class IPDetector(BaseDetector):
    def __init__(self):
        self.feeds = ThreatFeeds()

    def analyze(self, line: str) -> List[Finding]:
        findings = []
        for match in IP_REGEX.finditer(line):
            ip_str = match.group(1)
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                continue

            # Skip private/loopback/link-local
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                continue

            # Check known malicious IPs
            if ip_str in self.feeds.malicious_ips:
                findings.append(self._finding(
                    "critical", "MALICIOUS_IP", ip_str,
                    f"IP {ip_str} is in the threat intelligence blacklist",
                    mitre="T1071"
                ))
                continue

            # Check suspicious CIDR ranges
            for network in SUSPICIOUS_NETWORKS:
                if ip in network:
                    findings.append(self._finding(
                        "high", "SUSPICIOUS_IP_RANGE", ip_str,
                        f"IP {ip_str} belongs to suspicious network {network} (Tor/proxy/abuse)",
                        mitre="T1090"
                    ))
                    break

            # Heuristic: traffic to broadcast/network addresses
            octets = [int(o) for o in ip_str.split(".")]
            if octets[3] == 255:
                findings.append(self._finding(
                    "medium", "BROADCAST_ADDRESS", ip_str,
                    "Traffic directed to broadcast address — possible scanning or amplification",
                    mitre="T1046"
                ))

        return findings
