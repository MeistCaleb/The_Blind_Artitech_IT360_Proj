"""
core/detectors/dns_detector.py
Detects suspicious DNS queries, DNS tunneling, and fast-flux patterns.
"""

import re
import math
from typing import List
from core.detectors.base import BaseDetector
from core.models import Finding

# Match common log formats that mention DNS queries
DNS_QUERY_RE = re.compile(
    r'(?:query(?:\s+for)?|DNS\s+(?:request|query|lookup)|QNAME|question)\s+["\']?([a-zA-Z0-9._\-]+\.[a-zA-Z]{2,})',
    re.I
)

# DNS over alternative ports (not 53) — tunneling indicator
DNS_ALT_PORT_RE = re.compile(r'(?:udp|tcp)\s+(?:53[1-9]|5[4-9]\d|[6-9]\d{2,})', re.I)

# Unusually large DNS response size (amplification / tunneling)
DNS_SIZE_RE = re.compile(r'(?:size|bytes|len|length)\s*[=:]\s*(\d+)', re.I)
DNS_TXT_RE  = re.compile(r'\bTXT\b')
DNS_NULL_RE = re.compile(r'\bNULL\b|\btype\s+10\b', re.I)

MAX_LABEL_LENGTH = 63  # RFC limit
TUNNELING_LABEL_THRESHOLD = 40  # labels this long in DNS are suspicious
TUNNELING_ENTROPY_THRESHOLD = 3.8


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s.lower():
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v/n) * math.log2(v/n) for v in freq.values())


class DNSDetector(BaseDetector):
    def analyze(self, line: str) -> List[Finding]:
        findings = []

        # --- Extract DNS queried domain ---
        for match in DNS_QUERY_RE.finditer(line):
            domain = match.group(1).lower().strip(".")
            labels = domain.split(".")

            # Long labels = possible base32/base64 encoding for tunneling
            for label in labels[:-1]:
                if len(label) >= TUNNELING_LABEL_THRESHOLD:
                    entropy = shannon_entropy(label)
                    findings.append(self._finding(
                        "high", "DNS_TUNNELING_LABEL", domain,
                        f"DNS label '{label[:30]}...' is {len(label)} chars long "
                        f"(entropy={entropy:.2f}) — possible DNS tunneling payload",
                        mitre="T1071.004"
                    ))

                # Base32 pattern (common in dnscat2, iodine)
                if re.match(r'^[a-z2-7]{20,}$', label):
                    findings.append(self._finding(
                        "high", "DNS_TUNNELING_BASE32", domain,
                        f"DNS label '{label[:30]}' matches Base32 encoding pattern — likely DNS tunnel",
                        mitre="T1071.004"
                    ))

            # Total domain length anomaly
            if len(domain) > 100:
                findings.append(self._finding(
                    "medium", "ABNORMAL_DNS_LENGTH", domain,
                    f"DNS query is {len(domain)} characters long — abnormally long domain",
                    mitre="T1071.004"
                ))

        # --- TXT record queries (common in tunneling & C2) ---
        if DNS_TXT_RE.search(line):
            findings.append(self._finding(
                "medium", "DNS_TXT_QUERY", "TXT record",
                "DNS TXT record query detected — commonly used for C2 instructions or data exfiltration",
                mitre="T1071.004"
            ))

        # --- NULL record queries (used by some DNS tunnels) ---
        if DNS_NULL_RE.search(line):
            findings.append(self._finding(
                "high", "DNS_NULL_QUERY", "NULL record",
                "DNS NULL/Type-10 record query — used by DNS tunneling tools (e.g. dnscat2)",
                mitre="T1071.004"
            ))

        # --- Large DNS response (amplification or tunneling) ---
        for size_match in DNS_SIZE_RE.finditer(line):
            size = int(size_match.group(1))
            if size > 512:
                severity = "high" if size > 2000 else "medium"
                findings.append(self._finding(
                    severity, "LARGE_DNS_RESPONSE", f"{size} bytes",
                    f"DNS response/payload size of {size} bytes exceeds normal limit — "
                    f"possible amplification attack or tunneling",
                    mitre="T1498.002" if size > 2000 else "T1071.004"
                ))

        return findings
