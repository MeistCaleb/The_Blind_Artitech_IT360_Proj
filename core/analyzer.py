"""
core/analyzer.py
Orchestrates all detection modules and returns structured results.
"""

from pathlib import Path
from typing import List

from core.models import Finding, LogLine, AnalysisResults
from core.pcap_reader import PCAPReader, is_pcap
from core.detectors.ip_detector import IPDetector
from core.detectors.domain_detector import DomainDetector
from core.detectors.port_detector import PortDetector
from core.detectors.dns_detector import DNSDetector
from core.detectors.http_detector import HTTPDetector
from core.detectors.payload_detector import PayloadDetector


class TrafficAnalyzer:
    """
    Main analysis engine. Runs each line through all detector modules
    and aggregates findings.
    """

    def __init__(self):
        self.detectors = [
            IPDetector(),
            DomainDetector(),
            PortDetector(),
            DNSDetector(),
            HTTPDetector(),
            PayloadDetector(),
        ]

    def analyze_file(self, path: Path) -> AnalysisResults:
        if is_pcap(str(path)):
            print(f"  [PCAP] Detected binary PCAP/PCAPNG — parsing packets...")
            reader = PCAPReader(str(path))
            lines = reader.to_log_lines()
            text = "\n".join(lines)
            print(f"  [PCAP] Extracted {len(lines)} log lines from packets")
        else:
            text = path.read_text(encoding="utf-8", errors="replace")
        return self.analyze_text(text, source=str(path))

    def analyze_text(self, text: str, source: str = "<stdin>") -> AnalysisResults:
        lines = text.splitlines()
        log_lines = []
        stats = {"critical": 0, "high": 0, "medium": 0, "low": 0,
                 "total_findings": 0, "total_lines": len(lines), "flagged_lines": 0}

        for line_num, raw in enumerate(lines, start=1):
            raw = raw.strip()
            if not raw or raw.startswith("#"):
                continue

            findings = []
            for detector in self.detectors:
                try:
                    findings.extend(detector.analyze(raw))
                except Exception:
                    pass  # Never let a single detector crash the whole run

            # Deduplicate: same type + value
            seen = set()
            unique = []
            for f in findings:
                key = (f.ioc_type, f.value)
                if key not in seen:
                    seen.add(key)
                    unique.append(f)

            log_line = LogLine(line_num=line_num, raw=raw, findings=sorted(unique))
            log_lines.append(log_line)

            for f in unique:
                stats[f.severity] = stats.get(f.severity, 0) + 1
                stats["total_findings"] += 1
            if unique:
                stats["flagged_lines"] += 1

        return AnalysisResults(log_lines=[l for l in log_lines if l.findings],
                               stats=stats, source_file=source)
