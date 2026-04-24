"""
core/detectors/base.py
Abstract base class for all IOC detectors.
"""

from abc import ABC, abstractmethod
from typing import List
from core.models import Finding


class BaseDetector(ABC):
    """All detectors inherit from this. Implement analyze(line) -> [Finding]."""

    @abstractmethod
    def analyze(self, line: str) -> List[Finding]:
        """Analyze a single log line and return any findings."""
        ...

    def _finding(self, severity, ioc_type, value, detail, mitre=None) -> Finding:
        return Finding(
            severity=severity,
            ioc_type=ioc_type,
            value=str(value)[:120],
            detail=detail,
            mitre_technique=mitre,
        )
