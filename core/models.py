"""
core/models.py
Data models shared across analyzer and detectors.
Separated to avoid circular imports.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Finding:
    """A single IOC finding from a log line."""
    severity: str           # critical | high | medium | low
    ioc_type: str           # MALICIOUS_IP, SUSPICIOUS_DOMAIN, etc.
    value: str              # The actual indicator value
    detail: str             # Human-readable explanation
    mitre_technique: Optional[str] = None

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    def __lt__(self, other):
        return self.SEVERITY_ORDER.get(self.severity, 9) < self.SEVERITY_ORDER.get(other.severity, 9)


@dataclass
class LogLine:
    """Parsed log line with all associated findings."""
    line_num: int
    raw: str
    findings: List[Finding] = field(default_factory=list)

    @property
    def max_severity(self) -> Optional[str]:
        if not self.findings:
            return None
        return min(self.findings).severity


@dataclass
class AnalysisResults:
    """Full analysis output."""
    log_lines: List[LogLine]
    stats: dict
    source_file: str

    def filter_by_severity(self, severities: List[str]) -> "AnalysisResults":
        filtered_lines = []
        for line in self.log_lines:
            filtered_findings = [f for f in line.findings if f.severity in severities]
            if filtered_findings:
                new_line = LogLine(line.line_num, line.raw, filtered_findings)
                filtered_lines.append(new_line)
        return AnalysisResults(filtered_lines, self.stats, self.source_file)
