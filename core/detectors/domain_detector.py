"""
core/detectors/domain_detector.py
Detects malicious domains, phishing patterns, and DGA-generated domains.
"""

import re
import math
from typing import List
from core.detectors.base import BaseDetector
from core.models import Finding
from intel.threat_feeds import ThreatFeeds

DOMAIN_REGEX = re.compile(
    r'\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})\b'
)

# High-risk TLDs commonly used in malware campaigns
HIGH_RISK_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".ru", ".su",
                  ".cc", ".pw", ".top", ".click", ".download", ".stream"}

# Phishing keyword patterns
PHISHING_PATTERNS = [
    re.compile(r'(paypal|apple|amazon|microsoft|google|facebook|netflix|bank).{0,10}(secure|login|update|verify|alert|confirm)', re.I),
    re.compile(r'(secure|login|account|verify|update).{0,10}(paypal|apple|amazon|microsoft|google)', re.I),
    re.compile(r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}', ),  # IP-in-domain
]


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def looks_like_dga(label: str) -> bool:
    """Heuristic: high entropy + mostly lowercase alphanum + long = likely DGA."""
    if len(label) < 12:
        return False
    if not re.match(r'^[a-z0-9]+$', label):
        return False
    entropy = shannon_entropy(label)
    consonant_ratio = sum(1 for c in label if c in "bcdfghjklmnpqrstvwxyz") / len(label)
    # DGA domains tend to have high entropy and unnatural consonant clusters
    return entropy > 3.5 and consonant_ratio > 0.65


class DomainDetector(BaseDetector):
    def __init__(self):
        self.feeds = ThreatFeeds()

    def analyze(self, line: str) -> List[Finding]:
        findings = []
        seen = set()

        for match in DOMAIN_REGEX.finditer(line):
            domain = match.group(1).lower().rstrip(".")
            if domain in seen or len(domain) < 4:
                continue
            seen.add(domain)

            # Skip common benign domains
            if any(domain.endswith(safe) for safe in [
                "google.com", "amazonaws.com", "cloudflare.com",
                "microsoft.com", "apple.com", "akamai.net"
            ]):
                continue

            # Known malicious domain
            if domain in self.feeds.malicious_domains:
                findings.append(self._finding(
                    "critical", "MALICIOUS_DOMAIN", domain,
                    f"Domain '{domain}' is in the threat intelligence blacklist",
                    mitre="T1071.001"
                ))
                continue

            tld = "." + domain.rsplit(".", 1)[-1] if "." in domain else ""
            labels = domain.split(".")

            # High-risk TLD
            if tld in HIGH_RISK_TLDS:
                findings.append(self._finding(
                    "high", "HIGH_RISK_TLD", domain,
                    f"Domain uses high-risk TLD '{tld}' frequently abused in malware campaigns",
                    mitre="T1583.001"
                ))

            # Phishing pattern
            for pattern in PHISHING_PATTERNS:
                if pattern.search(domain):
                    findings.append(self._finding(
                        "critical", "PHISHING_DOMAIN", domain,
                        f"Domain matches known phishing keyword pattern",
                        mitre="T1566.002"
                    ))
                    break

            # DGA detection
            for label in labels[:-1]:  # Skip TLD
                if looks_like_dga(label):
                    findings.append(self._finding(
                        "high", "POSSIBLE_DGA", domain,
                        f"Label '{label}' has high entropy ({shannon_entropy(label):.2f} bits) — possible DGA domain",
                        mitre="T1568.002"
                    ))
                    break

            # Excessive subdomain depth (common in DNS tunneling)
            if len(labels) > 5:
                findings.append(self._finding(
                    "medium", "DNS_TUNNELING_SUSPECT", domain,
                    f"Domain has {len(labels)} labels — excessive depth may indicate DNS tunneling",
                    mitre="T1071.004"
                ))

        return findings
