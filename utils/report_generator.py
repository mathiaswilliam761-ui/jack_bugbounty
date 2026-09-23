"""
Report generator for vulnerability scan results.
Generates detailed bug bounty reports in multiple formats.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
import logging

from pentest_scanner.utils.models import Vulnerability, ScanResult, Severity, VulnerabilityCategory

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate vulnerability reports in multiple formats."""
    
    def __init__(self, scan_result: ScanResult, config):
        self.scan_result = scan_result
        self.config = config
    
    def generate_all(self, output_dir: Path) -> Dict[str, Path]:
        """Generate all report formats."""
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"pentest_report_{self.scan_result.target_domain}_{timestamp}"
        
        reports = {}
        
        if "markdown" in self.config.report_format:
            md_path = output_dir / f"{base_name}.md"
            self.generate_markdown(md_path)
            reports["markdown"] = md_path
        
        if "json" in self.config.report_format:
            json_path = output_dir / f"{base_name}.json"
            self.generate_json(json_path)
            reports["json"] = json_path
        
        if "html" in self.config.report_format:
            html_path = output_dir / f"{base_name}.html"
            self.generate_html(html_path)
            reports["html"] = html_path
        
        return reports
    
    def generate_markdown(self, path: Path):
        """Generate detailed markdown report for bug bounty submissions."""
        vulns = self.scan_result.vulnerabilities
        
        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        vulns_sorted = sorted(vulns, key=lambda v: severity_order.get(v.severity, 5))
        
        md = f"""# Penetration Test Report

**Target:** {self.scan_result.target_url}
**Domain:** {self.scan_result.target_domain}
**Scan ID:** {self.scan_result.scan_id}
**Date:** {self.scan_result.started_at.strftime('%Y-%m-%d %H:%M:%S')}
**Scan Depth:** {self.scan_result.scan_depth}/3
**Modules Run:** {', '.join(self.scan_result.modules_run)}

---

## Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | {self.scan_result.stats.get('critical', 0)} |
| 🟠 High | {self.scan_result.stats.get('high', 0)} |
| 🟡 Medium | {self.scan_result.stats.get('medium', 0)} |
| 🔵 Low | {self.scan_result.stats.get('low', 0)} |
| ⚪ Info | {self.scan_result.stats.get('info', 0)} |
| **Total** | **{self.scan_result.stats.get('total', 0)}** |

**Overall Risk Rating:** {self._get_overall_risk()}

**Testing Coverage:**
- URLs Crawled: {len(self.scan_result.urls_crawled)}
- Endpoints Tested: {len(self.scan_result.endpoints_tested)}
- Parameters Tested: {len(self.scan_result.parameters_tested)}

---

## Vulnerability Details

"""
        
        for i, vuln in enumerate(vulns_sorted, 1):
            md += vuln.to_markdown()
        
        # Summary table
        md += "\n## Vulnerability Summary Table\n\n"
        md += "| # | Title | Severity | Category | URL |\n"
        md += "|---|-------|----------|----------|-----|\n"
        
        for i, vuln in enumerate(vulns_sorted, 1):
            md += f"| {i} | {vuln.title} | {vuln.severity.value.upper()} | {vuln.category.value} | {vuln.url[:80]}... |\n"
        
        # OWASP Top 10 Mapping
        md += "\n## OWASP Top 10 2021 Mapping\n\n"
        owasp_map = self._map_to_owasp(vulns)
        for owasp_id, owasp_vulns in owasp_map.items():
            if owasp_vulns:
                md += f"### {owasp_id}\n"
                for vuln in owasp_vulns:
                    md += f"- {vuln.title} ({vuln.severity.value.upper()})\n"
                md += "\n"
        
        # Remediation Priority
        md += "\n## Remediation Priority\n\n"
        md += "### Immediate (Critical/High)\n"
        for vuln in vulns_sorted:
            if vuln.severity in [Severity.CRITICAL, Severity.HIGH]:
                md += f"- **{vuln.title}** - {vuln.url}\n"
        
        md += "\n### Short-term (Medium)\n"
        for vuln in vulns_sorted:
            if vuln.severity == Severity.MEDIUM:
                md += f"- **{vuln.title}** - {vuln.url}\n"
        
        md += "\n### Long-term (Low/Info)\n"
        for vuln in vulns_sorted:
            if vuln.severity in [Severity.LOW, Severity.INFO]:
                md += f"- **{vuln.title}** - {vuln.url}\n"
        
        # Testing Methodology
        md += "\n## Testing Methodology\n\n"
        md += f"""This assessment was conducted using an automated vulnerability scanner with the following modules:

**Passive Reconnaissance:**
- Security header analysis
- SSL/TLS configuration review
- Sensitive file exposure checks
- Technology fingerprinting
- Cookie security analysis
- WAF detection

**Active Vulnerability Scanning:**
- Cross-Site Scripting (XSS) - Reflected, Stored, DOM
- SQL Injection - Error-based, Boolean-based, Time-based, Union-based
- Server-Side Request Forgery (SSRF)
- Insecure Direct Object References (IDOR)
- Open Redirect
- XML External Entity (XXE) Injection
- Server-Side Template Injection (SSTI)
- File Upload Vulnerabilities
- Authentication/Authorization flaws

**Scan Configuration:**
- Depth: {self.scan_result.scan_depth}/3
- Rate Limit: {self.config.requests_per_second} req/s
- Concurrent Requests: {self.config.concurrent_requests}
- Request Timeout: {self.config.request_timeout}s
"""

        if self.scan_result.errors:
            md += "\n## Errors and Limitations\n\n"
            for error in self.scan_result.errors:
                md += f"- {error}\n"
        
        md += f"\n---\n*Report generated by Pentest Scanner on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n"
        
        path.write_text(md)
        logger.info(f"Markdown report saved to {path}")
    
    def generate_json(self, path: Path):
        """Generate JSON report."""
        report = self.scan_result.to_dict()
        # Add metadata
        report["report_generated"] = datetime.now().isoformat()
        report["report_version"] = "1.0"
        
        path.write_text(json.dumps(report, indent=2))
        logger.info(f"JSON report saved to {path}")
    
    def generate_html(self, path: Path):
        """Generate HTML report."""
        vulns = self.scan_result.vulnerabilities
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        vulns_sorted = sorted(vulns, key=lambda v: severity_order.get(v.severity, 5))
        
        # Severity colors
        severity_colors = {
            Severity.CRITICAL: "#dc3545",
            Severity.HIGH: "#fd7e14",
            Severity.MEDIUM: "#ffc107",
            Severity.LOW: "#17a2b8",
            Severity.INFO: "#6c757d"
        }
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Penetration Test Report - {self.scan_result.target_domain}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; max-width: 1200px; margin: 0 auto; padding: 20px; background: #f8f9fa; }}
        .container {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; border-left: 4px solid #3498db; padding-left: 15px; margin-top: 40px; }}
        h3 {{ color: #2c3e50; }}
        .meta {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .meta-item {{ display: inline-block; margin-right: 20px; }}
        .meta-label {{ font-weight: bold; color: #6c757d; }}
        .summary-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        .summary-table th, .summary-table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }}
        .summary-table th {{ background: #343a40; color: white; }}
        .severity-badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.85em; font-weight: bold; color: white; }}
        .vuln-card {{ border: 1px solid #dee2e6; border-radius: 8px; padding: 20px; margin: 20px 0; background: white; }}
        .vuln-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }}
        .vuln-title {{ font-size: 1.2em; font-weight: bold; color: #2c3e50; }}
        .evidence {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; font-family: monospace; font-size: 0.9em; overflow-x: auto; }}
        .code-block {{ background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: 'Monaco', 'Menlo', monospace; font-size: 0.85em; }}
        .toc {{ background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 30px; }}
        .toc ul {{ list-style: none; padding-left: 0; }}
        .toc li {{ margin: 5px 0; }}
        .toc a {{ color: #3498db; text-decoration: none; }}
        .toc a:hover {{ text-decoration: underline; }}
        .remediation {{ background: #e8f5e9; border-left: 4px solid #4caf50; padding: 15px; margin: 15px 0; }}
        .references {{ background: #fff3e0; border-left: 4px solid #ff9800; padding: 15px; margin: 15px 0; }}
        .owasp-mapping {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }}
        .owasp-card {{ background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #3498db; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Penetration Test Report</h1>
        
        <div class="meta">
            <div class="meta-item"><span class="meta-label">Target:</span> {self.scan_result.target_url}</div>
            <div class="meta-item"><span class="meta-label">Domain:</span> {self.scan_result.target_domain}</div>
            <div class="meta-item"><span class="meta-label">Scan ID:</span> {self.scan_result.scan_id}</div>
            <div class="meta-item"><span class="meta-label">Date:</span> {self.scan_result.started_at.strftime('%Y-%m-%d %H:%M:%S')}</div>
            <div class="meta-item"><span class="meta-label">Depth:</span> {self.scan_result.scan_depth}/3</div>
        </div>
        
        <h2>Executive Summary</h2>
        
        <table class="summary-table">
            <thead>
                <tr><th>Severity</th><th>Count</th></tr>
            </thead>
            <tbody>
                <tr><td><span class="severity-badge" style="background: #dc3545;">Critical</span></td><td>{self.scan_result.stats.get('critical', 0)}</td></tr>
                <tr><td><span class="severity-badge" style="background: #fd7e14;">High</span></td><td>{self.scan_result.stats.get('high', 0)}</td></tr>
                <tr><td><span class="severity-badge" style="background: #ffc107; color: #212529;">Medium</span></td><td>{self.scan_result.stats.get('medium', 0)}</td></tr>
                <tr><td><span class="severity-badge" style="background: #17a2b8;">Low</span></td><td>{self.scan_result.stats.get('low', 0)}</td></tr>
                <tr><td><span class="severity-badge" style="background: #6c757d;">Info</span></td><td>{self.scan_result.stats.get('info', 0)}</td></tr>
                <tr style="font-weight: bold;"><td>Total</td><td>{self.scan_result.stats.get('total', 0)}</td></tr>
            </tbody>
        </table>
        
        <p><strong>Overall Risk Rating:</strong> {self._get_overall_risk()}</p>
        <p><strong>Testing Coverage:</strong> {len(self.scan_result.urls_crawled)} URLs crawled, {len(self.scan_result.endpoints_tested)} endpoints tested, {len(self.scan_result.parameters_tested)} parameters tested</p>
        
        <div class="toc">
            <h3>Table of Contents</h3>
            <ul>
"""
        
        for i, vuln in enumerate(vulns_sorted, 1):
            anchor = vuln.id.lower().replace('_', '-')
            html += f'                <li><a href="#{anchor}">{i}. {vuln.title}</a></li>\n'
        
        html += """            </ul>
        </div>
        
        <h2>Vulnerability Details</h2>
"""
        
        for vuln in vulns_sorted:
            color = severity_colors.get(vuln.severity, "#6c757d")
            anchor = vuln.id.lower().replace('_', '-')
            
            html += f"""
        <div class="vuln-card" id="{anchor}">
            <div class="vuln-header">
                <div class="vuln-title">{vuln.title}</div>
                <span class="severity-badge" style="background: {color};">{vuln.severity.value.upper()}</span>
            </div>
            
            <table class="summary-table" style="width: auto;">
                <tr><td><strong>ID</strong></td><td>{vuln.id}</td></tr>
                <tr><td><strong>Category</strong></td><td>{vuln.category.value}</td></tr>
                <tr><td><strong>OWASP Category</strong></td><td>{vuln.owasp_category or 'N/A'}</td></tr>
                <tr><td><strong>CVSS Score</strong></td><td>{vuln.cvss.base_score} ({vuln.cvss.vector})</td></tr>
                <tr><td><strong>URL</strong></td><td><a href="{vuln.url}" target="_blank">{vuln.url}</a></td></tr>
                <tr><td><strong>Parameter</strong></td><td>{vuln.parameter or 'N/A'}</td></tr>
                <tr><td><strong>Method</strong></td><td>{vuln.method}</td></tr>
                <tr><td><strong>Confirmed</strong></td><td>{'Yes' if vuln.confirmed else 'No'}</td></tr>
            </table>
            
            <h3>Description</h3>
            <p>{vuln.description}</p>
            
            <h3>Proof of Concept</h3>
            <div class="evidence">{vuln.poc or 'N/A'}</div>
            
            {f'<h3>PoC Code</h3><div class="code-block">{vuln.poc_code}</div>' if vuln.poc_code else ''}
            
            {f'<h3>Evidence</h3>' + ''.join([f'<div class="evidence"><strong>{e.type}:</strong> {e.description}<br><pre>{json.dumps(e.data, indent=2) if isinstance(e.data, dict) else e.data}</pre></div>' for e in vuln.evidence]) if vuln.evidence else ''}
            
            {f'<h3>Request</h3><div class="code-block">{vuln.request.method} {vuln.request.url}\n' + '\n'.join([f'{k}: {v}' for k, v in vuln.request.headers.items()]) + (f'\n\n{vuln.request.body}' if vuln.request.body else '') + '</div>' if vuln.request else ''}
            
            {f'<h3>Response</h3><div class="code-block">HTTP/1.1 {vuln.response.status_code}\n' + '\n'.join([f'{k}: {v}' for k, v in vuln.response.headers.items()]) + f'\n\n{vuln.response.body[:2000]}' + '</div>' if vuln.response else ''}
            
            <div class="remediation">
                <h3>Remediation</h3>
                <p>{vuln.remediation or 'No specific remediation provided.'}</p>
            </div>
            
            {f'<div class="references"><h3>References</h3><ul>' + ''.join([f'<li><a href="{r}" target="_blank">{r}</a></li>' for r in vuln.references]) + '</ul></div>' if vuln.references else ''}
        </div>
"""
        
        # OWASP Mapping
        owasp_map = self._map_to_owasp(vulns)
        html += """
        <h2>OWASP Top 10 2021 Mapping</h2>
        <div class="owasp-mapping">
"""
        for owasp_id, owasp_vulns in owasp_map.items():
            if owasp_vulns:
                html += f"""
            <div class="owasp-card">
                <h4>{owasp_id}</h4>
                <ul>
"""
                for vuln in owasp_vulns:
                    color = severity_colors.get(vuln.severity, "#6c757d")
                    html += f'<li><span class="severity-badge" style="background: {color}; font-size: 0.7em;">{vuln.severity.value.upper()}</span> {vuln.title}</li>\n'
                
                html += """                </ul>
            </div>
"""
        
        html += """        </div>
        
        <h2>Remediation Priority</h2>
        
        <h3>Immediate (Critical/High)</h3>
        <ul>
"""
        for vuln in vulns_sorted:
            if vuln.severity in [Severity.CRITICAL, Severity.HIGH]:
                html += f'            <li><strong>{vuln.title}</strong> - <a href="{vuln.url}" target="_blank">{vuln.url}</a></li>\n'
        
        html += """        </ul>
        
        <h3>Short-term (Medium)</h3>
        <ul>
"""
        for vuln in vulns_sorted:
            if vuln.severity == Severity.MEDIUM:
                html += f'            <li><strong>{vuln.title}</strong> - <a href="{vuln.url}" target="_blank">{vuln.url}</a></li>\n'
        
        html += """        </ul>
        
        <h3>Long-term (Low/Info)</h3>
        <ul>
"""
        for vuln in vulns_sorted:
            if vuln.severity in [Severity.LOW, Severity.INFO]:
                html += f'            <li><strong>{vuln.title}</strong> - <a href="{vuln.url}" target="_blank">{vuln.url}</a></li>\n'
        
        html += f"""        </ul>
        
        <h2>Testing Methodology</h2>
        <p>This assessment was conducted using an automated vulnerability scanner with the following modules:</p>
        <ul>
            <li><strong>Passive Reconnaissance:</strong> Security headers, SSL/TLS, sensitive files, technology fingerprinting, cookies, WAF detection</li>
            <li><strong>Active Scanning:</strong> XSS, SQLi, SSRF, IDOR, Open Redirect, XXE, SSTI, File Upload, Auth flaws</li>
        </ul>
        <p><strong>Scan Configuration:</strong> Depth: {self.scan_result.scan_depth}/3, Rate: {self.config.requests_per_second} req/s, Concurrency: {self.config.concurrent_requests}, Timeout: {self.config.request_timeout}s</p>
        
        <hr>
        <p><em>Report generated by Pentest Scanner on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</em></p>
    </div>
</body>
</html>
"""
        
        path.write_text(html)
        logger.info(f"HTML report saved to {path}")
    
    def _get_overall_risk(self) -> str:
        """Determine overall risk rating."""
        stats = self.scan_result.stats
        if stats.get('critical', 0) > 0:
            return "🔴 CRITICAL"
        elif stats.get('high', 0) > 0:
            return "🟠 HIGH"
        elif stats.get('medium', 0) > 0:
            return "🟡 MEDIUM"
        elif stats.get('low', 0) > 0:
            return "🔵 LOW"
        else:
            return "⚪ INFORMATIONAL"
    
    def _map_to_owasp(self, vulns: List[Vulnerability]) -> Dict[str, List[Vulnerability]]:
        """Map vulnerabilities to OWASP Top 10 categories."""
        owasp_mapping = {
            "A01:2021 – Broken Access Control": [],
            "A02:2021 – Cryptographic Failures": [],
            "A03:2021 – Injection": [],
            "A04:2021 – Insecure Design": [],
            "A05:2021 – Security Misconfiguration": [],
            "A06:2021 – Vulnerable and Outdated Components": [],
            "A07:2021 – Identification and Authentication Failures": [],
            "A08:2021 – Software and Data Integrity Failures": [],
            "A09:2021 – Security Logging and Monitoring Failures": [],
            "A10:2021 – Server-Side Request Forgery (SSRF)": [],
        }
        
        for vuln in vulns:
            if vuln.owasp_category and vuln.owasp_category in owasp_mapping:
                owasp_mapping[vuln.owasp_category].append(vuln)
            else:
                # Auto-map based on category
                category_map = {
                    VulnerabilityCategory.IDOR: "A01:2021 – Broken Access Control",
                    VulnerabilityCategory.OPEN_REDIRECT: "A01:2021 – Broken Access Control",
                    VulnerabilityCategory.BROKEN_ACCESS_CONTROL: "A01:2021 – Broken Access Control",
                    VulnerabilityCategory.SSL_TLS: "A02:2021 – Cryptographic Failures",
                    VulnerabilityCategory.CRYPTOGRAPHIC_FAILURES: "A02:2021 – Cryptographic Failures",
                    VulnerabilityCategory.XSS: "A03:2021 – Injection",
                    VulnerabilityCategory.SQLI: "A03:2021 – Injection",
                    VulnerabilityCategory.XXE: "A03:2021 – Injection",
                    VulnerabilityCategory.SSTI: "A03:2021 – Injection",
                    VulnerabilityCategory.INJECTION: "A03:2021 – Injection",
                    VulnerabilityCategory.SECURITY_MISCONFIGURATION: "A05:2021 – Security Misconfiguration",
                    VulnerabilityCategory.MISSING_SECURITY_HEADERS: "A05:2021 – Security Misconfiguration",
                    VulnerabilityCategory.CORS_MISCONFIGURATION: "A05:2021 – Security Misconfiguration",
                    VulnerabilityCategory.COOKIE_SECURITY: "A05:2021 – Security Misconfiguration",
                    VulnerabilityCategory.SSRF: "A10:2021 – Server-Side Request Forgery (SSRF)",
                    VulnerabilityCategory.VULNERABLE_COMPONENTS: "A06:2021 – Vulnerable and Outdated Components",
                    VulnerabilityCategory.AUTH_FAILURES: "A07:2021 – Identification and Authentication Failures",
                    VulnerabilityCategory.BROKEN_AUTHENTICATION: "A07:2021 – Identification and Authentication Failures",
                    VulnerabilityCategory.SESSION_MANAGEMENT: "A07:2021 – Identification and Authentication Failures",
                }
                
                mapped = category_map.get(vuln.category)
                if mapped and mapped in owasp_mapping:
                    owasp_mapping[mapped].append(vuln)
        
        return owasp_mapping