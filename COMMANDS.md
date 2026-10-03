# Penetest Scanner - Complete Command Reference

## 🚀 Quick Start

```bash
# Clone and setup
git clone https://github.com/mathiaswilliam761-ui/jack_bugbounty.git
cd jack_bugbounty
python3 -m venv venv
source venv/bin/activate
pip install -e .
pip install playwright pyyaml
playwright install chromium
```

## 📋 Basic Scan Commands

| Command | Description |
|---------|-------------|
| `pentest-scanner --help` | Show all options |
| `pentest-scanner --version` | Show version |
| `pentest-scanner -u https://target.com --depth 1 -o ./reports` | Passive recon only |
| `pentest-scanner -u https://target.com --depth 2 -o ./reports` | Standard scan |
| `pentest-scanner -u https://target.com --depth 3 -o ./reports` | Full scan with browser |

## 🎯 Scan Depth Levels

| Depth | Modules | Time | Use Case |
|-------|---------|------|----------|
| 1 | Passive recon only | ~30s | Initial reconnaissance |
| 2 | Passive + Active vulns | ~2-5 min | Standard vulnerability scan |
| 3 | All modules + browser | ~10-30 min | Comprehensive bug bounty scan |

## 🔐 Authentication

```bash
# Cookie-based auth
pentest-scanner -u https://target.com --depth 2 \
  --auth-cookie "sessionid=abc123; csrftoken=xyz789"

# Header-based auth (Bearer token, API keys)
pentest-scanner -u https://api.target.com --depth 2 \
  --header "Authorization: Bearer eyJhbG...s..." \
  --header "X-API-Key: ***"

# Multiple headers
pentest-scanner -u https://target.com --depth 2 \
  --header "X-CSRF-Token: token123" \
  --header "X-Requested-With: XMLHttpRequest" \
  --header "Referer: https://target.com/dashboard"
```

## ⚡ Rate Limiting & Performance

```bash
# Conservative (stealth)
pentest-scanner -u https://target.com --depth 2 --rate 1 --threads 2

# Balanced (default)
pentest-scanner -u https://target.com --depth 2 --rate 5 --threads 5

# Aggressive (fast, may trigger WAF)
pentest-scanner -u https://target.com --depth 2 --rate 20 --threads 15

# Custom timeout
pentest-scanner -u https://target.com --depth 2 --timeout 60
```

## 🔧 Module Selection

```bash
# Only passive recon
pentest-scanner -u https://target.com \
  --enable-passive-recon --disable-active-scan

# Specific vulnerability classes only
pentest-scanner -u https://target.com --depth 2 \
  --enable-xss-checks --enable-sqli-checks --enable-ssrf-checks \
  --disable-idor-checks --disable-xxe-checks --disable-ssti-checks

# Disable browser tests (faster)
pentest-scanner -u https://target.com --depth 3 --disable-browser-tests
```

## 🏢 Professional Modules (Advanced)

```bash
# Nuclei integration (10,000+ templates)
pentest-scanner -u https://target.com --depth 3 \
  --enable-nuclei \
  --nuclei-severity critical,high,medium \
  --nuclei-tags cve,rce,sqli,xss,ssrf \
  --nuclei-rate-limit 100

# OAST/Interactsh (blind vuln detection)
pentest-scanner -u https://target.com --depth 3 \
  --enable-oast \
  --oast-server https://oast.pro \
  --oast-poll-interval 5 \
  --oast-max-polls 15

# SPA Crawler (JavaScript-heavy apps)
pentest-scanner -u https://target.com --depth 3 \
  --enable-spa-crawler \
  --crawler-depth 5 \
  --crawler-max-pages 200 \
  --crawler-headless

# OpenAPI/Swagger API scanning
pentest-scanner -u https://api.target.com --depth 2 \
  --enable-openapi \
  --openapi-spec https://api.target.com/openapi.json \
  --openapi-base-url https://api.target.com

# Local OpenAPI spec file
pentest-scanner -u https://api.target.com --depth 2 \
  --enable-openapi \
  --openapi-spec ./openapi.json

# ALL PRO MODULES COMBINED
pentest-scanner -u https://target.com --depth 3 \
  --enable-nuclei --enable-oast --enable-spa-crawler --enable-openapi \
  --nuclei-severity critical,high --nuclei-tags rce,sqli,ssrf \
  --openapi-spec https://api.target.com/openapi.json \
  --crawler-depth 3 --crawler-max-pages 100 \
  -o ./reports --format markdown,json,html
```

## 🚫 Scope & Exclusions

```bash
# Exclude specific paths
pentest-scanner -u https://target.com --depth 2 \
  --exclude-path "/logout" --exclude-path "/signout" \
  --exclude-path "/admin/delete" --exclude-path "/api/v1/users/delete"

# Exclude domains (CDN, external services)
pentest-scanner -u https://target.com --depth 2 \
  --exclude-domain "cdn.target.com" \
  --exclude-domain "analytics.google.com" \
  --exclude-domain "fonts.googleapis.com"

# Combined exclusions
pentest-scanner -u https://target.com --depth 3 \
  --exclude-path "/logout" --exclude-path "/cart" --exclude-path "/checkout" \
  --exclude-domain "payments.stripe.com" --exclude-domain "api.segment.io"
```

## 🌐 Proxy & Network

```bash
# HTTP/HTTPS proxy
pentest-scanner -u https://target.com --depth 2 --proxy http://127.0.0.1:8080

# Proxy with authentication
pentest-scanner -u https://target.com --depth 2 --proxy http://user:pass@127.0.0.1:8080

# SOCKS5 proxy (Tor)
pentest-scanner -u https://target.com --depth 2 --proxy socks5://127.0.0.1:9050
```

## 🛡️ WAF Evasion

```bash
# Enable WAF evasion
pentest-scanner -u https://target.com --depth 2 \
  --waf-evasion \
  --evasion-techniques "case_toggle,url_encode,double_encode,whitespace"

# Available techniques:
# - case_toggle: Random case variation
# - url_encode: URL encoding
# - double_encode: Double URL encoding
# - whitespace: Random whitespace insertion
# - comment_injection: SQL comment injection
# - unicode: Unicode normalization bypass
```

## 🎯 Bug Bounty Optimized

```bash
# Bug bounty mode (all features)
pentest-scanner -u https://target.com --depth 3 \
  --bug-bounty-mode \
  --include-poc --include-cvss --include-remediation --include-references \
  --enable-nuclei --enable-oast --enable-spa-crawler \
  --nuclei-severity critical,high \
  --nuclei-tags cve,rce,sqli,xss,ssrf,idor,xxe,ssti \
  -o ./reports --format markdown,json,html

# Reconnaissance only
pentest-scanner -u https://target.com --depth 1 --bug-bounty-mode -o ./recon

# XSS hunting
pentest-scanner -u https://target.com --depth 2 \
  --enable-xss-checks --disable-sqli-checks --disable-ssrf-checks \
  --disable-idor-checks --disable-xxe-checks --disable-ssti-checks \
  --disable-file-upload-checks --disable-open-redirect-checks \
  -o ./xss-hunt

# SSRF hunting
pentest-scanner -u https://target.com --depth 2 \
  --enable-ssrf-checks --enable-oast \
  --disable-xss-checks --disable-sqli-checks \
  -o ./ssrf-hunt

# API security testing
pentest-scanner -u https://api.target.com --depth 2 \
  --enable-openapi --openapi-spec https://api.target.com/openapi.json \
  --enable-sqli-checks --enable-idor-checks --enable-broken-auth-checks \
  -o ./api-test
```

## 📊 Report Output

```bash
# Default (all formats)
pentest-scanner -u https://target.com --depth 2 -o ./reports

# Specific formats
pentest-scanner -u https://target.com --depth 2 --format markdown,json,html
pentest-scanner -u https://target.com --depth 2 --format json
pentest-scanner -u https://target.com --depth 2 --format markdown

# View reports
cat ./reports/pentest_report_*.md
cat ./reports/pentest_report_*.json | jq .
xdg-open ./reports/pentest_report_*.html
```

## 🧪 Testing & Development

```bash
# Run tests
cd /opt/data/pentest_scanner
source /opt/data/.venv/bin/activate
python -m pytest pentest_scanner/tests/ -v

# Test scan on httpbin.org
pentest-scanner -u http://httpbin.org --depth 1 -o ./test
pentest-scanner -u http://httpbin.org --depth 2 -o ./test2
```

## 🐳 OWASP Juice Shop Testing

```bash
# Start Juice Shop
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
sleep 15

# Comprehensive scan
pentest-scanner -u http://localhost:3000 --depth 3 \
  --enable-nuclei --enable-spa-crawler \
  --nuclei-tags xss,sqli,idor,ssrf,xxe,ssti \
  -o ./juice_shop_full --format markdown,json,html

# View results
cat ./juice_shop_full/*.md
xdg-open ./juice_shop_full/*.html
```

## 🔍 Complete Parameter Reference

| Parameter | Short | Type | Default | Description |
|-----------|-------|------|---------|-------------|
| `--url` / `--target` | `-u` | string | **required** | Target URL to scan |
| `--depth` | `-d` | int | `3` | Scan depth: 1=passive, 2=active, 3=full |
| `--output` | `-o` | string | `./reports` | Output directory |
| `--format` | `-f` | list | `markdown,json,html` | Report formats |
| `--rate` | `-r` | float | `5.0` | Requests per second |
| `--threads` | `-t` | int | `5` | Concurrent requests |
| `--timeout` | | int | `30` | Request timeout (seconds) |
| `--auth-cookie` | | string | | Cookie string for auth |
| `--header` | `-H` | string | | Custom header (repeatable) |
| `--proxy` | | string | | Proxy URL |
| `--proxy-auth` | | string | | Proxy auth (user:pass) |
| `--exclude-path` | | string | | Path to exclude (repeatable) |
| `--exclude-domain` | | string | | Domain to exclude (repeatable) |
| `--user-agent` | | string | Chrome UA | Custom User-Agent |
| `--waf-evasion` | | flag | `False` | Enable WAF evasion |
| `--evasion-techniques` | | list | | Evasion methods |
| `--bug-bounty-mode` | | flag | `True` | Enable all bug bounty features |

### Professional Module Flags

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `--enable-nuclei` | flag | `False` | Enable Nuclei scanner |
| `--nuclei-templates` | string | | Custom template path |
| `--nuclei-severity` | list | `critical,high,medium,low,info` | Severity filter |
| `--nuclei-tags` | list | | Tag filter |
| `--nuclei-rate-limit` | int | `150` | Nuclei rate limit |
| `--enable-oast` | flag | `False` | Enable OAST/Interactsh |
| `--oast-server` | string | `https://oast.pro` | OAST server URL |
| `--oast-poll-interval` | int | `3` | Poll interval (seconds) |
| `--oast-max-polls` | int | `10` | Max poll attempts |
| `--enable-spa-crawler` | flag | `False` | Enable SPA crawler |
| `--crawler-depth` | int | `3` | Crawl depth |
| `--crawler-max-pages` | int | `100` | Max pages to crawl |
| `--crawler-headless` | flag | `True` | Headless browser |
| `--enable-openapi` | flag | `False` | Enable OpenAPI parser |
| `--openapi-spec` | string | | OpenAPI spec URL/file |
| `--openapi-base-url` | string | | Base URL for API |

## 📁 Output Structure

```
./reports/
├── pentest_report_target.com_20261003_143022.md    # Markdown report
├── pentest_report_target.com_20261003_143022.json  # JSON report
├── pentest_report_target.com_20261003_143022.html  # HTML dashboard
└── scan_metadata.json                              # Scan metadata
```

## 📋 Report Sections

1. **Executive Summary** - Stats, risk rating, coverage
2. **Vulnerability Details** - Description, PoC, evidence, request/response
3. **Detailed Remediation Plans** - Step-by-step with code examples (7 languages)
4. **OWASP Top 10 2021 Mapping** - Categorized findings
5. **Remediation Priority** - Critical/High → Medium → Low/Info
6. **Testing Methodology** - Transparency on coverage

## 🔧 Common Workflows

```bash
# 1. INITIAL RECON (30 seconds)
pentest-scanner -u https://target.com --depth 1 -o ./recon

# 2. STANDARD VULN SCAN (2-5 minutes)
pentest-scanner -u https://target.com --depth 2 -o ./scan

# 3. COMPREHENSIVE BUG BOUNTY (10-30 minutes)
pentest-scanner -u https://target.com --depth 3 \
  --enable-nuclei --enable-oast --enable-spa-crawler \
  --bug-bounty-mode -o ./bugbounty --format markdown,json,html

# 4. API SECURITY TESTING
pentest-scanner -u https://api.target.com --depth 2 \
  --enable-openapi --openapi-spec ./openapi.json \
  --auth-cookie "token=..." -o ./api-scan

# 5. AUTHENTICATED SCAN
pentest-scanner -u https://target.com --depth 3 \
  --auth-cookie "session=abc; csrf=xyz" \
  --header "Authorization: Bearer ***" \
  -o ./auth-scan

# 6. STEALTH/LOW-NOISE SCAN
pentest-scanner -u https://target.com --depth 2 \
  --rate 1 --threads 2 --timeout 60 \
  --waf-evasion --evasion-techniques "case_toggle,url_encode" \
  -o ./stealth-scan

# 7. SPECIFIC VULN HUNTING
pentest-scanner -u https://target.com --depth 2 \
  --enable-ssrf-checks --enable-oast --enable-nuclei \
  --nuclei-tags ssrf,oast --disable-xss-checks --disable-sqli-checks \
  -o ./ssrf-hunt
```

## ⚠️ Legal & Ethics

- **Only scan targets you have explicit written permission to test**
- Respect `robots.txt`, `security.txt`, and program scope
- Rate limiting built-in (`--rate`, `--threads`)
- Built for **authorized** bug bounty programs (HackerOne, Bugcrowd, Intigriti, private programs)
- Not for unauthorized scanning

## 📚 Resources

- **GitHub:** https://github.com/mathiaswilliam761-ui/jack_bugbounty
- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **PayloadsAllTheThings:** https://github.com/swisskyrepo/PayloadsAllTheThings
- **PortSwigger:** https://portswigger.net/web-security
- **HackTricks:** https://book.hacktricks.xyz/

---

**Version:** 1.0.0  
**License:** MIT  
**Python:** 3.10+