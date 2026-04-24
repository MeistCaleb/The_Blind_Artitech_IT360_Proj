"""
output/reporter.py
Generates analysis reports in multiple formats:
  - terminal (colored ANSI)
  - json
  - html
  - csv
"""

import json
import csv
import io
from datetime import datetime
from core.models import AnalysisResults, Finding

VERSION = "2.4.0"

# ANSI color codes
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[38;5;196m"
    ORANGE  = "\033[38;5;208m"
    YELLOW  = "\033[38;5;226m"
    GREEN   = "\033[38;5;82m"
    CYAN    = "\033[38;5;51m"
    GRAY    = "\033[38;5;244m"
    WHITE   = "\033[97m"
    BG_RED  = "\033[41m"

SEV_COLOR = {
    "critical": C.RED,
    "high":     C.ORANGE,
    "medium":   C.YELLOW,
    "low":      C.GREEN,
}

SEV_LABEL = {
    "critical": "CRITICAL",
    "high":     "HIGH    ",
    "medium":   "MEDIUM  ",
    "low":      "LOW     ",
}

IOC_ICONS = {
    "MALICIOUS_IP":          "⚠",
    "SUSPICIOUS_IP_RANGE":   "◈",
    "BROADCAST_ADDRESS":     "○",
    "MALICIOUS_DOMAIN":      "☠",
    "SUSPICIOUS_DOMAIN":     "◉",
    "HIGH_RISK_TLD":         "⬡",
    "PHISHING_DOMAIN":       "◎",
    "POSSIBLE_DGA":          "⟁",
    "DNS_TUNNELING_SUSPECT": "⟁",
    "SUSPICIOUS_PORT":       "⬢",
    "HIGH_EPHEMERAL_PORT":   "○",
    "DNS_TUNNELING_LABEL":   "⟁",
    "DNS_TUNNELING_BASE32":  "⟁",
    "ABNORMAL_DNS_LENGTH":   "◈",
    "DNS_TXT_QUERY":         "▣",
    "DNS_NULL_QUERY":        "▪",
    "LARGE_DNS_RESPONSE":    "▲",
    "SUSPICIOUS_USER_AGENT": "◎",
    "SUSPICIOUS_URI":        "▶",
    "SUSPICIOUS_HTTP_METHOD":"▷",
    "ABNORMAL_URI_LENGTH":   "◈",
    "IP_IN_HOST_HEADER":     "◈",
    "POWERSHELL_ENCODED_CMD":"☣",
    "BASE64_ENCODED_DATA":   "⬟",
    "HEX_ENCODED_DATA":      "⬟",
    "SHELLCODE_PATTERN":     "☣",
    "MALWARE_STRING":        "☣",
    "C2_BEACON":             "☣",
}

BANNER = "  NetSentinel - Malware Traffic Investigation System v{version}"


class Reporter:
    def __init__(self, use_color=True, quiet=False, output_format="terminal"):
        self.use_color = use_color
        self.quiet = quiet
        self.format = output_format

    def _c(self, color: str, text: str) -> str:
        if not self.use_color:
            return text
        return f"{color}{text}{C.RESET}"

    def generate(self, results: AnalysisResults, stats: dict) -> str:
        if self.format == "json":
            return self._json(results, stats)
        elif self.format == "html":
            return self._html(results, stats)
        elif self.format == "csv":
            return self._csv(results, stats)
        else:
            return self._terminal(results, stats)

    # ── Terminal ──────────────────────────────────────────────────────────────

    def _terminal(self, results: AnalysisResults, stats: dict) -> str:
        lines = []

        if not self.quiet:
            lines.append(self._c(C.DIM, f"  Source: {results.source_file}"))
            lines.append(self._c(C.DIM, f"  Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
            lines.append("")
            lines.append(self._c(C.BOLD, "  -- SUMMARY --------------------------------------------------"))
            lines.append(f"  Lines scanned:   {self._c(C.WHITE, str(stats['total_lines']))}")
            lines.append(f"  Flagged lines:   {self._c(C.ORANGE if stats['flagged_lines'] else C.GREEN, str(stats['flagged_lines']))}")
            lines.append(f"  Total findings:  {self._c(C.WHITE, str(stats['total_findings']))}")
            lines.append(f"  Critical:        {self._c(C.RED, str(stats.get('critical', 0)))}")
            lines.append(f"  High:            {self._c(C.ORANGE, str(stats.get('high', 0)))}")
            lines.append(f"  Medium:          {self._c(C.YELLOW, str(stats.get('medium', 0)))}")
            lines.append(f"  Low:             {self._c(C.GREEN, str(stats.get('low', 0)))}")
            lines.append("")

        if not results.log_lines:
            lines.append(self._c(C.GREEN, "  [✓] No IOCs found in filtered results."))
            return "\n".join(lines)

        lines.append(self._c(C.BOLD, "  ── FINDINGS ─────────────────────────────────────────────"))
        lines.append("")

        for log_line in results.log_lines:
            # Line header
            lines.append(
                f"  {self._c(C.DIM, f'Line {log_line.line_num:04d}')}  "
                f"{self._c(C.GRAY, log_line.raw[:100])}"
                + (self._c(C.DIM, "…") if len(log_line.raw) > 100 else "")
            )

            for finding in log_line.findings:
                sev_color = SEV_COLOR.get(finding.severity, C.GRAY)
                icon = IOC_ICONS.get(finding.ioc_type, "●")
                mitre = f"  [{self._c(C.CYAN, finding.mitre_technique)}]" if finding.mitre_technique else ""
                lines.append(
                    f"    {self._c(sev_color, SEV_LABEL[finding.severity])} "
                    f"{icon} {self._c(C.BOLD, finding.ioc_type.replace('_', ' '))}  "
                    f"{self._c(sev_color, finding.value)}"
                )
                lines.append(
                    f"    {self._c(C.DIM, ' ' * 12)}{self._c(C.GRAY, finding.detail)}{mitre}"
                )
            lines.append("")

        return "\n".join(lines)

    # ── JSON ──────────────────────────────────────────────────────────────────

    def _json(self, results: AnalysisResults, stats: dict) -> str:
        data = {
            "meta": {
                "tool": "NetSentinel",
                "version": VERSION,
                "source": results.source_file,
                "timestamp": datetime.now().isoformat(),
                "stats": stats,
            },
            "findings": []
        }
        for log_line in results.log_lines:
            for f in log_line.findings:
                data["findings"].append({
                    "line_num": log_line.line_num,
                    "severity": f.severity,
                    "ioc_type": f.ioc_type,
                    "value": f.value,
                    "detail": f.detail,
                    "mitre_technique": f.mitre_technique,
                    "raw_line": log_line.raw,
                })
        return json.dumps(data, indent=2)

    # ── CSV ───────────────────────────────────────────────────────────────────

    def _csv(self, results: AnalysisResults, stats: dict) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["line_num", "severity", "ioc_type", "value", "detail",
                         "mitre_technique", "raw_line"])
        for log_line in results.log_lines:
            for f in log_line.findings:
                writer.writerow([log_line.line_num, f.severity, f.ioc_type,
                                  f.value, f.detail, f.mitre_technique or "", log_line.raw])
        return output.getvalue()

    # ── HTML ──────────────────────────────────────────────────────────────────

    def _html(self, results: AnalysisResults, stats: dict) -> str:
        sev_colors = {"critical": "#ff2d55", "high": "#ff9500", "medium": "#ffd60a", "low": "#30d158"}

        rows = []
        for log_line in results.log_lines:
            for f in log_line.findings:
                color = sev_colors.get(f.severity, "#999")
                mitre = f"<a href='https://attack.mitre.org/techniques/{f.mitre_technique}/' target='_blank' style='color:#51a8ff'>{f.mitre_technique}</a>" if f.mitre_technique else ""
                rows.append(f"""
                <tr>
                  <td style="color:#666">{log_line.line_num}</td>
                  <td><span style="color:{color};font-weight:bold;border:1px solid {color};padding:2px 6px;font-size:11px">{f.severity.upper()}</span></td>
                  <td style="color:#ccc">{f.ioc_type.replace("_", " ")}</td>
                  <td style="color:{color};font-family:monospace">{f.value}</td>
                  <td style="color:#999">{f.detail}</td>
                  <td>{mitre}</td>
                </tr>""")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NetSentinel Report — {results.source_file}</title>
<style>
  body {{ background:#0a0c0f; color:#c9d1d9; font-family:'JetBrains Mono',monospace; padding:32px; }}
  h1 {{ color:#00ff6a; letter-spacing:0.2em; font-size:18px; }}
  .stat {{ display:inline-block; margin:0 16px 16px 0; padding:12px 20px; border:1px solid #1e3a2e; text-align:center; }}
  .stat .n {{ font-size:28px; font-weight:bold; }}
  table {{ width:100%; border-collapse:collapse; font-size:12px; margin-top:24px; }}
  th {{ background:#0d1f15; color:#4a8a5c; text-align:left; padding:8px 12px; letter-spacing:0.15em; border-bottom:1px solid #1e3a2e; }}
  td {{ padding:8px 12px; border-bottom:1px solid #0d1a12; vertical-align:top; max-width:300px; overflow:hidden; text-overflow:ellipsis; }}
  tr:hover td {{ background:rgba(0,255,106,0.03); }}
</style>
</head>
<body>
<h1>☣ NETSENTINEL REPORT</h1>
<p style="color:#4a6741;font-size:11px">Source: {results.source_file} &nbsp;·&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<div class="stat"><div class="n">{stats['total_lines']}</div><div style="color:#4a6741;font-size:10px">LINES SCANNED</div></div>
<div class="stat"><div class="n" style="color:#ff2d55">{stats.get('critical',0)}</div><div style="color:#4a6741;font-size:10px">CRITICAL</div></div>
<div class="stat"><div class="n" style="color:#ff9500">{stats.get('high',0)}</div><div style="color:#4a6741;font-size:10px">HIGH</div></div>
<div class="stat"><div class="n" style="color:#ffd60a">{stats.get('medium',0)}</div><div style="color:#4a6741;font-size:10px">MEDIUM</div></div>
<div class="stat"><div class="n" style="color:#30d158">{stats.get('low',0)}</div><div style="color:#4a6741;font-size:10px">LOW</div></div>
<table>
<thead><tr><th>LINE</th><th>SEVERITY</th><th>TYPE</th><th>INDICATOR</th><th>DETAIL</th><th>MITRE</th></tr></thead>
<tbody>{"".join(rows) if rows else '<tr><td colspan="6" style="color:#30d158;text-align:center;padding:40px">✓ No findings</td></tr>'}</tbody>
</table>
</body>
</html>"""
