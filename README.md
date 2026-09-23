# Pentest Scanner

An automated vulnerability scanner designed for bug bounty programs and penetration testing. Features comprehensive scanning modules for OWASP Top 10 vulnerabilities with detailed reporting optimized for bug bounty submissions.

## Features

### Vulnerability Scanning Modules
- **Passive Reconnaissance**: Security headers, SSL/TLS, sensitive files, technology fingerprinting, cookie analysis, WAF detection
- **Cross-Site Scripting (XSS)**: Reflected, form-based with execution verification
- **SQL Injection**: Error-based, boolean-based, time-based blind, union-based
- **Server-Side Request Forgery (SSRF)**: Cloud metadata, internal services, file protocol, protocol handlers
- **Insecure Direct Object References (IDOR)**: Numeric, UUID, alphanumeric ID manipulation
- **Open Redirect**: Header-based, form-based, javascript:/data: protocol detection
- **XML External Entity (XXE)**: File read, SSRF, OOB XXE via XML parsing
- **Server-Side Template Injection (SSTI)**: Multi-engine detection (Jinja2, Twig, Freemarker, Velocity, Smarty, ERB, JSP, Thymeleaf)
- **File Upload**: Extension bypass, double extension, null byte, polyglot, .htaccess/web.config

### Report Generation
- **Markdown**: Detailed bug bounty-ready reports with PoC code
- **JSON**: Machine-readable format for CI/CD integration
- **HTML**: Professional visual reports with severity badges

### Bug Bounty Optimized
- CVSS v3.1 scoring for each finding
- OWASP Top 10 2021 mapping
- Proof of concept code for reproduction
- Remediation guidance with references
- Executive summary with risk rating

## Installation

```bash
cd /opt/data/pentest_scanner
pip install -r requirements.txt
```

## Usage

### Basic Scan
```bash
python -m pentest_scanner -u https://example.com
```

### Full Bug Bounty Scan
```bash
python -m pentest_scanner -u https://example.com \
  --depth 3 \
  --rate 10 \
  --threads 20 \
  --output ./reports \
  --format markdown,json,html
```

### Authenticated Scan
```bash
python -m pentest_scanner -u https://example.com \
  --auth-cookie "session=abc123" \
  --auth-header "X-CSRF-Token=xyz789" \
  --bearer-token "eyJhbGciOiJIUzI1NiIs..."
```

### With Proxy (Burp Suite)
```bash
python -m pentest_scanner -u https://example.com \
  --proxy http://127.0.0.1:8080 \
  --proxy-auth user:pass
```

### Custom Headers and WAF Evasion
```bash
python -m pentest_scanner -u https://example.com \
  --header "X-Forwarded-For: 127.0.0.1" \
  --header "X-Originating-IP: 127.0.0.1" \
  --waf-evasion
```

## Scan Depth Levels

| Depth | Description | Modules |
|-------|-------------|---------|
| 1 | Passive only | Recon, headers, SSL, files, tech detection |
| 2 | Passive + Light Active | Depth 1 + XSS, SQLi, SSRF, IDOR, Open Redirect |
| 3 | Full Scan | Depth 2 + XXE, SSTI, File Upload, Browser tests |

## Configuration

Create a `config.yaml` for persistent settings:

```yaml
target_url: "https://example.com"
scan_depth: 3
requests_per_second: 5.0
concurrent_requests: 10
request_timeout: 30
output_dir: "./reports"
report_format: ["markdown", "json", "html"]

# Authentication
auth_cookies:
  session: "your-session-cookie"
auth_headers:
  X-CSRF-Token: "your-csrf-token"
auth_bearer_token: "your-jwt-token"

# Proxy
proxy_url: "http://127.0.0.1:8080"
proxy_auth: "user:pass"

# Module toggles
enable_xss_checks: true
enable_sqli_checks: true
enable_ssrf_checks: true
enable_idor_checks: true
enable_open_redirect_checks: true
enable_xxe_checks: true
enable_ssti_checks: true
enable_file_upload_checks: true
```

## Output

Reports are saved to the output directory with timestamps:
- `pentest_report_example.com_20240115_143022.md`
- `pentest_report_example.com_20240115_143022.json`
- `pentest_report_example.com_20240115_143022.html`

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No vulnerabilities found |
| 1 | Critical/High severity findings |
| 2 | Medium/Low/Info findings only |
| 130 | Interrupted by user |

## Bug Bounty Tips

1. **Use authenticated scans** - Most critical bugs are in authenticated areas
2. **Adjust rate limits** - Respect program rules (often 1-5 req/s)
3. **Scope carefully** - Use `--exclude-path` and `--exclude-domain`
4. **Verify manually** - Always verify findings before submission
5. **Use the PoC code** - Reports include ready-to-run reproduction scripts

## Legal Disclaimer

This tool is for authorized security testing only. Only scan applications you have explicit permission to test. Unauthorized scanning is illegal in most jurisdictions.

## License

MIT License - See LICENSE file for details.