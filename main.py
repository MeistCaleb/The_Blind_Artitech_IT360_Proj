#!/usr/bin/env python3
"""
Malware Traffic Investigation Tool
Usage: python3 main.py [OPTIONS] <logfile>
"""

import argparse
import sys
import json
import urllib.request
import urllib.error
from pathlib import Path
from core.analyzer import TrafficAnalyzer
from output.reporter import Reporter

# ── Hardcoded API credentials ─────────────────────────────────────────────────
DEFAULT_API_URL = "http://sushi.it.ilstu.edu:8080"
DEFAULT_API_KEY = "sk-f91a6ca80916414d8ce86f7d75e3110a"
DEFAULT_MODEL   = "qwen3-vl:235b"
# ─────────────────────────────────────────────────────────────────────────────


def parse_args():
    parser = argparse.ArgumentParser(
        prog="MalwareTool",
        description="Malware Traffic Investigation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py sample_traffic.log
  python3 main.py traffic.log --severity critical high
  python3 main.py traffic.log --format html --output report.html
        """
    )
    parser.add_argument("logfile", help="Path to traffic log file")
    parser.add_argument("--severity", nargs="+", choices=["critical", "high", "medium", "low"],
                        default=["critical", "high", "medium", "low"],
                        help="Filter results by severity level(s)")
    parser.add_argument("--format", choices=["terminal", "json", "html", "csv"],
                        default="terminal", help="Output format (default: terminal)")
    parser.add_argument("--output", "-o", help="Write report to file instead of stdout")
    parser.add_argument("--no-color", action="store_true", help="Disable colored terminal output")
    parser.add_argument("--quiet", "-q", action="store_true", help="Only show findings, no summary header")
    parser.add_argument("--api-url", default=DEFAULT_API_URL, help="Override the AI API base URL")
    parser.add_argument("--api-key", default=DEFAULT_API_KEY, help="Override the AI API key")
    return parser.parse_args()


def build_summary_prompt(results, stats) -> str:
    lines = [
        "You are a cybersecurity analyst. Below are IOC findings from a network traffic log analysis tool.",
        "",
        "SCAN STATISTICS:",
        f"  Lines scanned: {stats['total_lines']}",
        f"  Flagged lines: {stats['flagged_lines']}",
        f"  Critical findings: {stats.get('critical', 0)}",
        f"  High findings: {stats.get('high', 0)}",
        f"  Medium findings: {stats.get('medium', 0)}",
        f"  Low findings: {stats.get('low', 0)}",
        "",
        "FINDINGS:",
    ]
    for log_line in results.log_lines:
        for f in log_line.findings:
            mitre = f" [MITRE: {f.mitre_technique}]" if f.mitre_technique else ""
            lines.append(f"  [{f.severity.upper()}] {f.ioc_type}: {f.value} -- {f.detail}{mitre}")
    lines += [
        "",
        "Please provide:",
        "1. A brief plain-English summary of what this traffic suggests (2-3 sentences).",
        "2. The most critical threats to address first.",
        "3. Recommended immediate actions.",
    ]
    return "\n".join(lines)


def call_ai_api(prompt: str, api_url: str, api_key: str) -> str:
    """
    Calls Open WebUI using the OpenAI-compatible /api/chat/completions endpoint.
    """
    endpoint = f"{api_url.rstrip('/')}/api/chat/completions"

    payload = {
        "model": DEFAULT_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 1024,
        "temperature": 0.3,
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if "choices" in data:
                return data["choices"][0]["message"]["content"]
            return json.dumps(data, indent=2)
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        return f"[API Error {e.code}] {error_body[:400]}"
    except urllib.error.URLError as e:
        return f"[Connection Error] Could not reach {endpoint}: {e.reason}"
    except Exception as e:
        return f"[Error] {e}"


def main():
    args = parse_args()

    log_path = Path(args.logfile)
    if not log_path.exists():
        print(f"[ERROR] File not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    # Run analysis
    analyzer = TrafficAnalyzer()
    results = analyzer.analyze_file(log_path)
    filtered = results.filter_by_severity(args.severity)

    # Generate and print/save report
    reporter = Reporter(
        use_color=not args.no_color,
        quiet=args.quiet,
        output_format=args.format,
    )
    report = reporter.generate(filtered, results.stats)

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"[OK] Report saved to {args.output}")
    else:
        print(report)

    # AI summarization — always runs
    print("\n  -- AI SUMMARY " + "-" * 44)
    print("  Contacting AI API (this may take 1-3 minutes)...")
    prompt = build_summary_prompt(filtered, results.stats)
    summary = call_ai_api(prompt, args.api_url, args.api_key)
    print()
    for line in summary.splitlines():
        print(f"  {line}")
    print()

    sys.exit(1 if results.stats.get("critical", 0) > 0 else 0)


if __name__ == "__main__":
    main()
