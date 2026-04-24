"""
core/detectors/payload_detector.py
Detects encoded payloads, shellcode patterns, and exfiltration indicators.
"""

import re
import base64
import math
from typing import List
from core.detectors.base import BaseDetector
from core.models import Finding

# Base64 blobs (40+ chars, valid alphabet)
B64_RE   = re.compile(r'(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/=])')
# Hex-encoded blobs
HEX_RE   = re.compile(r'\b([0-9a-fA-F]{64,})\b')
# PowerShell encoded command
PS_ENC   = re.compile(r'-[Ee]nc(?:odedCommand)?\s+([A-Za-z0-9+/=]{20,})', re.I)
# Common shellcode stubs
SHELLCODE_PATTERNS = [
    re.compile(r'\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){7,}'),  # \xNN\xNN...
    re.compile(r'(?:0x[0-9a-fA-F]{2},?\s*){8,}'),               # 0xNN, 0xNN, ...
]
# Common malware strings
MALWARE_STRINGS = [
    (re.compile(r'cmd\.exe\s*/[cCkK]', re.I),          "critical", "cmd.exe execution pattern"),
    (re.compile(r'powershell\s+-(?:nop|noni|ep|exec)', re.I), "critical", "PowerShell with execution bypass flags"),
    (re.compile(r'mshta\.exe|wscript\.exe|cscript\.exe', re.I), "high", "Windows script host execution"),
    (re.compile(r'certutil.*-decode|-urlcache', re.I),  "critical", "certutil download/decode — LOLBins abuse"),
    (re.compile(r'bitsadmin.*\/transfer', re.I),        "critical", "BITSAdmin file transfer — LOLBins abuse"),
    (re.compile(r'regsvr32.*scrobj|regsvr32.*/[siu]', re.I), "critical", "Regsvr32 COM scriptlet execution"),
    (re.compile(r'IEX\s*\(|Invoke-Expression', re.I),  "critical", "PowerShell Invoke-Expression — common in stagers"),
    (re.compile(r'DownloadString|DownloadFile|WebClient', re.I), "high", "PowerShell web download pattern"),
    (re.compile(r'VirtualAlloc|WriteProcessMemory|CreateRemoteThread', re.I), "critical", "Process injection API calls"),
    (re.compile(r'mimikatz|sekurlsa|lsadump', re.I),   "critical", "Mimikatz credential dumping tool"),
    (re.compile(r'/bin/sh|/bin/bash.*-[ic]', re.I),    "high", "Shell execution pattern"),
    (re.compile(r'nc\s+-[lnveLp]+\s+\d+', re.I),       "critical", "Netcat listener/reverse shell pattern"),
]


def try_decode_b64(s: str) -> str:
    """Try to decode base64 and return decoded string snippet."""
    try:
        # Pad if needed
        padded = s + "=" * (4 - len(s) % 4) if len(s) % 4 else s
        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
        return decoded[:100]
    except Exception:
        return ""


class PayloadDetector(BaseDetector):
    def analyze(self, line: str) -> List[Finding]:
        findings = []

        # --- PowerShell encoded command ---
        ps_match = PS_ENC.search(line)
        if ps_match:
            b64 = ps_match.group(1)
            decoded = try_decode_b64(b64)
            detail = f"PowerShell EncodedCommand detected"
            if decoded:
                detail += f" — decoded: '{decoded[:60]}...'"
            findings.append(self._finding(
                "critical", "POWERSHELL_ENCODED_CMD",
                b64[:60] + "...", detail, mitre="T1059.001"
            ))

        # --- Base64 blobs ---
        for match in B64_RE.finditer(line):
            blob = match.group(1)
            decoded = try_decode_b64(blob)
            # Only flag if decoded content looks interesting or blob is very long
            if len(blob) > 80 or (decoded and any(kw in decoded.lower() for kw in
                    ["http", "cmd", "exec", "bash", "shell", "download", "powershell"])):
                findings.append(self._finding(
                    "medium", "BASE64_ENCODED_DATA",
                    blob[:60] + "...",
                    f"Base64-encoded data ({len(blob)} chars)" + (f" — decoded hint: '{decoded[:50]}'" if decoded else ""),
                    mitre="T1027"
                ))

        # --- Hex blobs ---
        for match in HEX_RE.finditer(line):
            blob = match.group(1)
            if len(blob) >= 64:
                findings.append(self._finding(
                    "medium", "HEX_ENCODED_DATA",
                    blob[:60] + "...",
                    f"Large hex-encoded blob ({len(blob)} chars) — possible encoded payload",
                    mitre="T1027"
                ))

        # --- Shellcode patterns ---
        for pattern in SHELLCODE_PATTERNS:
            if pattern.search(line):
                findings.append(self._finding(
                    "critical", "SHELLCODE_PATTERN",
                    line[:80],
                    "Shellcode byte sequence pattern detected",
                    mitre="T1059"
                ))
                break

        # --- Malware string indicators ---
        for pattern, severity, detail in MALWARE_STRINGS:
            if pattern.search(line):
                findings.append(self._finding(
                    severity, "MALWARE_STRING",
                    line[:80], detail, mitre="T1059"
                ))

        return findings
