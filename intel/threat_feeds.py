"""
intel/threat_feeds.py
Threat intelligence: known malicious IPs, domains, and IOC feeds.

In production, these sets would be populated from:
  - Abuse.ch (feodotracker, urlhaus, malwarebazaar)
  - Emerging Threats (ET) rules
  - AlienVault OTX
  - VirusTotal feeds
  - MISP instances
  - Commercial threat intel (Recorded Future, CrowdStrike, etc.)

This module provides a sample static dataset plus a structure to load
from external files or API feeds.
"""

import json
from pathlib import Path


# ── Static sample threat intel (abbreviated for illustration) ─────────────────

KNOWN_MALICIOUS_IPS = {
    # Tor exit nodes
    "176.10.104.240", "5.188.86.172", "89.234.157.254",
    # Known C2 infrastructure (sanitized examples)
    "185.220.101.1", "185.220.101.2", "185.220.101.3",
    "45.142.212.100", "194.165.16.11", "91.108.4.0",
    "198.51.100.1",   "203.0.113.99",  "192.0.2.200",
    "176.10.104.240", "193.169.245.79",
    # Mirai botnet C2 samples
    "95.211.198.118", "80.82.77.33",
    # Common scanner IPs
    "198.20.69.74", "198.20.69.98", "198.20.70.114",
}

KNOWN_MALICIOUS_DOMAINS = {
    # Phishing & malware distribution
    "malware.example.com",
    "phishing.tk",
    "evil.xyz",
    "c2.darkweb.su",
    "totally-not-malware.ru",
    "update-windows-now.tk",
    "secure-paypal.ml",
    "bankofamerica-login.ru",
    "microsoft-support-alert.tk",
    "freevirus.xyz",
    # Known C2 domains (sanitized)
    "gate.malicious.su",
    "cdn.update-checker.tk",
    # DNS tunneling test domains
    "dnscat.example.com",
    "iodine.tunnel.cc",
}


class ThreatFeeds:
    """
    Manages IOC lists. Can be extended to load from external files or APIs.

    Usage:
        feeds = ThreatFeeds()
        feeds.load_from_file("my_iocs.txt")  # optional
        if ip in feeds.malicious_ips: ...
    """

    def __init__(self):
        self.malicious_ips: set = set(KNOWN_MALICIOUS_IPS)
        self.malicious_domains: set = set(KNOWN_MALICIOUS_DOMAINS)

    def load_from_file(self, path: str) -> int:
        """
        Load IOCs from a plain text file (one per line).
        Lines starting with # are comments.
        IPs and domains are auto-detected.

        Returns number of IOCs loaded.
        """
        import ipaddress
        loaded = 0
        p = Path(path)
        if not p.exists():
            return 0

        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Strip CSV fields (e.g. "ip,category,date")
            value = line.split(",")[0].strip().lower()
            try:
                ipaddress.ip_address(value)
                self.malicious_ips.add(value)
                loaded += 1
            except ValueError:
                if "." in value and len(value) > 3:
                    self.malicious_domains.add(value)
                    loaded += 1

        return loaded

    def load_from_json(self, path: str) -> int:
        """
        Load IOCs from a JSON file with structure:
        {"ips": [...], "domains": [...]}
        """
        p = Path(path)
        if not p.exists():
            return 0
        data = json.loads(p.read_text())
        ips = set(data.get("ips", []))
        domains = set(data.get("domains", []))
        self.malicious_ips.update(ips)
        self.malicious_domains.update(domains)
        return len(ips) + len(domains)

    def stats(self) -> dict:
        return {
            "malicious_ips": len(self.malicious_ips),
            "malicious_domains": len(self.malicious_domains),
        }
