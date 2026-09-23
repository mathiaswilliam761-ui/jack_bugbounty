"""
Passive reconnaissance module for information gathering.
"""

import asyncio
import ssl
import socket
import re
import json
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, urljoin
import logging

from pentest_scanner.utils.http_client import HTTPClient, ResponseWrapper
from pentest_scanner.utils.models import (
    Vulnerability, Severity, VulnerabilityCategory, CVSSScore,
    Evidence, Endpoint, Technology, ScanResult, HTTPRequest, HTTPResponse
)
from pentest_scanner.config.settings import (
    SECURITY_HEADERS, SENSITIVE_FILES, COMMON_PORTS,
    SEVERITY_CVSS_MAP, OWASP_TOP_10_2021
)

logger = logging.getLogger(__name__)


class PassiveReconScanner:
    """Passive reconnaissance and information gathering."""
    
    def __init__(self, client: HTTPClient, config, scan_result: ScanResult):
        self.client = client
        self.config = config
        self.scan_result = scan_result
        self.discovered_technologies: List[Technology] = []
        self.discovered_endpoints: List[Endpoint] = []
        self.session_cookies: Dict[str, str] = {}
    
    async def run(self) -> Dict[str, Any]:
        """Run all passive reconnaissance checks."""
        results = {
            "technologies": [],
            "security_headers": {},
            "ssl_info": {},
            "sensitive_files": [],
            "endpoints": [],
            "cookies": {},
            "dns_info": {},
            "robots_txt": "",
            "sitemap": [],
            "waf_detection": {},
        }
        
        # Run checks in parallel where possible
        tasks = [
            self._analyze_security_headers(),
            self._check_ssl_tls(),
            self._check_sensitive_files(),
            self._fetch_robots_txt(),
            self._fetch_sitemap(),
            self._detect_waf(),
            self._analyze_cookies(),
            self._extract_technologies_from_headers(),
        ]
        
        task_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        results["security_headers"] = task_results[0] if not isinstance(task_results[0], Exception) else {}
        results["ssl_info"] = task_results[1] if not isinstance(task_results[1], Exception) else {}
        results["sensitive_files"] = task_results[2] if not isinstance(task_results[2], Exception) else []
        results["robots_txt"] = task_results[3] if not isinstance(task_results[3], Exception) else ""
        results["sitemap"] = task_results[4] if not isinstance(task_results[4], Exception) else []
        results["waf_detection"] = task_results[5] if not isinstance(task_results[5], Exception) else {}
        results["cookies"] = task_results[6] if not isinstance(task_results[6], Exception) else {}
        
        # Technology detection from headers
        header_techs = task_results[7] if not isinstance(task_results[7], Exception) else []
        self.discovered_technologies.extend(header_techs)
        
        # Extract endpoints from robots.txt and sitemap
        await self._extract_endpoints_from_sources(results["robots_txt"], results["sitemap"])
        
        results["technologies"] = [t.to_dict() for t in self.discovered_technologies]
        results["endpoints"] = [e.to_dict() for e in self.discovered_endpoints]
        
        return results
    
    async def _analyze_security_headers(self) -> Dict[str, Any]:
        """Analyze security headers on the main page."""
        try:
            response = await self.client.get(self.config.target_url)
            wrapper = ResponseWrapper(response)
            await wrapper.text()  # Ensure body is read
            
            headers = wrapper.headers
            analysis = {
                "present": {},
                "missing": [],
                "misconfigured": [],
                "recommendations": []
            }
            
            for header_name, header_info in SECURITY_HEADERS.items():
                if wrapper.has_header(header_name):
                    value = wrapper.get_header(header_name)
                    analysis["present"][header_name] = {
                        "value": value,
                        "description": header_info["description"]
                    }
                    
                    # Check for common misconfigurations
                    if header_name == "Strict-Transport-Security":
                        if "max-age" not in value.lower():
                            analysis["misconfigured"].append({
                                "header": header_name,
                                "issue": "Missing max-age directive",
                                "recommendation": header_info["recommendation"]
                            })
                        elif "preload" not in value.lower() and "includesubdomains" not in value.lower():
                            analysis["misconfigured"].append({
                                "header": header_name,
                                "issue": "Missing includeSubDomains or preload",
                                "recommendation": header_info["recommendation"]
                            })
                    
                    elif header_name == "X-Frame-Options":
                        if value.upper() not in ["DENY", "SAMEORIGIN"]:
                            analysis["misconfigured"].append({
                                "header": header_name,
                                "issue": f"Weak value: {value}",
                                "recommendation": header_info["recommendation"]
                            })
                    
                    elif header_name == "Content-Security-Policy":
                        if "unsafe-inline" in value or "unsafe-eval" in value:
                            analysis["misconfigured"].append({
                                "header": header_name,
                                "issue": "Contains unsafe-inline or unsafe-eval",
                                "recommendation": "Remove unsafe directives from CSP"
                            })
                else:
                    if header_info["required"]:
                        analysis["missing"].append({
                            "header": header_name,
                            "description": header_info["description"],
                            "recommendation": header_info["recommendation"]
                        })
                        analysis["recommendations"].append(header_info["recommendation"])
            
            # Create vulnerabilities for missing required headers
            for missing in analysis["missing"]:
                vuln = Vulnerability(
                    id=f"MISSING_HEADER_{missing['header'].upper().replace('-', '_')}",
                    title=f"Missing Security Header: {missing['header']}",
                    description=f"The security header '{missing['header']}' is not present. {missing['description']}",
                    category=VulnerabilityCategory.MISSING_SECURITY_HEADERS,
                    severity=Severity.MEDIUM if missing["header"] in ["Content-Security-Policy", "Strict-Transport-Security"] else Severity.LOW,
                    cvss=CVSSScore(**SEVERITY_CVSS_MAP["medium" if missing["header"] in ["Content-Security-Policy", "Strict-Transport-Security"] else "low"]),
                    owasp_category="A05:2021 – Security Misconfiguration",
                    url=self.config.target_url,
                    remediation=missing["recommendation"],
                    references=[
                        f"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{missing['header']}",
                        "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration"
                    ],
                    tags=["passive", "header", "configuration"]
                )
                self.scan_result.add_vulnerability(vuln)
            
            # Create vulnerabilities for misconfigured headers
            for misconfig in analysis["misconfigured"]:
                vuln = Vulnerability(
                    id=f"MISCONFIGURED_HEADER_{misconfig['header'].upper().replace('-', '_')}",
                    title=f"Misconfigured Security Header: {misconfig['header']}",
                    description=f"The security header '{misconfig['header']}' is misconfigured: {misconfig['issue']}",
                    category=VulnerabilityCategory.MISSING_SECURITY_HEADERS,
                    severity=Severity.MEDIUM,
                    cvss=CVSSScore(**SEVERITY_CVSS_MAP["medium"]),
                    owasp_category="A05:2021 – Security Misconfiguration",
                    url=self.config.target_url,
                    remediation=misconfig["recommendation"],
                    references=[
                        f"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{misconfig['header']}",
                        "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration"
                    ],
                    tags=["passive", "header", "configuration"]
                )
                self.scan_result.add_vulnerability(vuln)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing security headers: {e}")
            return {"error": str(e)}
    
    async def _check_ssl_tls(self) -> Dict[str, Any]:
        """Check SSL/TLS configuration."""
        parsed = urlparse(self.config.target_url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        
        if parsed.scheme != "https":
            return {"error": "Not an HTTPS site", "ssl_enabled": False}
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
            
            # Parse certificate info
            ssl_info = {
                "ssl_enabled": True,
                "protocol_version": version,
                "cipher": cipher[0] if cipher else "Unknown",
                "cipher_version": cipher[1] if cipher else "Unknown",
                "cipher_bits": cipher[2] if cipher else 0,
                "certificate": {}
            }
            
            if cert:
                ssl_info["certificate"] = {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "version": cert.get("version"),
                    "serial_number": cert.get("serialNumber"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "subject_alt_names": cert.get("subjectAltName", []),
                }
                
                # Check certificate expiration
                from datetime import datetime
                not_after = datetime.strptime(cert.get("notAfter", ""), "%b %d %H:%M:%S %Y %Z")
                days_until_expiry = (not_after - datetime.now()).days
                
                ssl_info["certificate"]["days_until_expiry"] = days_until_expiry
                ssl_info["certificate"]["expired"] = days_until_expiry < 0
                ssl_info["certificate"]["expiring_soon"] = days_until_expiry < 30
                
                # Check for weak signature algorithms
                sig_alg = cert.get("signatureAlgorithm", "").lower()
                if "sha1" in sig_alg or "md5" in sig_alg:
                    vuln = Vulnerability(
                        id="WEAK_SSL_SIGNATURE",
                        title="Weak SSL Certificate Signature Algorithm",
                        description=f"SSL certificate uses weak signature algorithm: {sig_alg}",
                        category=VulnerabilityCategory.SSL_TLS,
                        severity=Severity.MEDIUM,
                        cvss=CVSSScore(**SEVERITY_CVSS_MAP["medium"]),
                        owasp_category="A02:2021 – Cryptographic Failures",
                        url=self.config.target_url,
                        remediation="Reissue certificate with SHA-256 or stronger signature algorithm",
                        references=[
                            "https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
                        ],
                        tags=["passive", "ssl", "certificate"]
                    )
                    self.scan_result.add_vulnerability(vuln)
            
            # Check for weak protocols/ciphers
            weak_protocols = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
            if version in weak_protocols:
                vuln = Vulnerability(
                    id="WEAK_SSL_PROTOCOL",
                    title=f"Weak SSL/TLS Protocol: {version}",
                    description=f"Server supports deprecated protocol version: {version}",
                    category=VulnerabilityCategory.SSL_TLS,
                    severity=Severity.HIGH,
                    cvss=CVSSScore(**SEVERITY_CVSS_MAP["high"]),
                    owasp_category="A02:2021 – Cryptographic Failures",
                    url=self.config.target_url,
                    remediation="Disable SSLv2, SSLv3, TLSv1.0, and TLSv1.1. Enable only TLSv1.2 and TLSv1.3.",
                    references=[
                        "https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
                    ],
                    tags=["passive", "ssl", "protocol"]
                )
                self.scan_result.add_vulnerability(vuln)
            
            return ssl_info
            
        except Exception as e:
            logger.error(f"Error checking SSL/TLS: {e}")
            return {"error": str(e), "ssl_enabled": False}
    
    async def _check_sensitive_files(self) -> List[Dict]:
        """Check for exposed sensitive files."""
        found_files = []
        
        # Test files in parallel with rate limiting
        semaphore = asyncio.Semaphore(self.config.concurrent_requests)
        
        async def check_file(path: str):
            async with semaphore:
                url = urljoin(self.config.target_url, path)
                try:
                    response = await self.client.head(url)
                    if response.status == 200:
                        wrapper = ResponseWrapper(response)
                        content_type = wrapper.content_type
                        content_length = wrapper.get_header("Content-Length", "Unknown")
                        
                        found_files.append({
                            "path": path,
                            "url": url,
                            "status_code": response.status,
                            "content_type": content_type,
                            "content_length": content_length
                        })
                        
                        # Create vulnerability
                        severity = Severity.HIGH if path in ["/.git/config", "/.env", "/wp-config.php", "/config.php"] else Severity.MEDIUM
                        vuln = Vulnerability(
                            id=f"EXPOSED_FILE_{path.replace('/', '_').replace('.', '_').upper()}",
                            title=f"Exposed Sensitive File: {path}",
                            description=f"Sensitive file accessible at {url}",
                            category=VulnerabilityCategory.SENSITIVE_DATA_EXPOSURE,
                            severity=severity,
                            cvss=CVSSScore(**SEVERITY_CVSS_MAP[severity.value]),
                            owasp_category="A02:2021 – Cryptographic Failures" if severity == Severity.HIGH else "A05:2021 – Security Misconfiguration",
                            url=url,
                            remediation=f"Restrict access to {path} via web server configuration or move outside web root",
                            references=[
                                "https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures",
                                "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration"
                            ],
                            tags=["passive", "information_disclosure", "file_exposure"]
                        )
                        self.scan_result.add_vulnerability(vuln)
                        
                except Exception:
                    pass  # Ignore errors for file checks
        
        await asyncio.gather(*[check_file(f) for f in SENSITIVE_FILES], return_exceptions=True)
        
        return found_files
    
    async def _fetch_robots_txt(self) -> str:
        """Fetch and parse robots.txt."""
        try:
            url = urljoin(self.config.target_url, "/robots.txt")
            response = await self.client.get(url)
            if response.status == 200:
                wrapper = ResponseWrapper(response)
                content = await wrapper.text()
                
                # Extract disallowed paths
                disallowed = []
                for line in content.split('\n'):
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            disallowed.append(path)
                
                # Create info vulnerability
                if disallowed:
                    vuln = Vulnerability(
                        id="ROBOTS_TXT_DISCLOSURE",
                        title="Information Disclosure via robots.txt",
                        description=f"robots.txt discloses {len(disallowed)} disallowed paths that may contain sensitive functionality",
                        category=VulnerabilityCategory.INFORMATION_DISCLOSURE,
                        severity=Severity.LOW,
                        cvss=CVSSScore(**SEVERITY_CVSS_MAP["low"]),
                        owasp_category="A05:2021 – Security Misconfiguration",
                        url=url,
                        poc=f"Disallowed paths: {', '.join(disallowed[:10])}{'...' if len(disallowed) > 10 else ''}",
                        remediation="Ensure robots.txt does not disclose sensitive paths. Use authentication instead of obscurity.",
                        references=[
                            "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration"
                        ],
                        tags=["passive", "information_disclosure", "robots_txt"]
                    )
                    self.scan_result.add_vulnerability(vuln)
                
                return content
        except Exception as e:
            logger.debug(f"Could not fetch robots.txt: {e}")
        return ""
    
    async def _fetch_sitemap(self) -> List[str]:
        """Fetch and parse sitemap.xml."""
        urls = []
        try:
            url = urljoin(self.config.target_url, "/sitemap.xml")
            response = await self.client.get(url)
            if response.status == 200:
                wrapper = ResponseWrapper(response)
                content = await wrapper.text()
                
                # Simple XML parsing for URLs
                import xml.etree.ElementTree as ET
                try:
                    root = ET.fromstring(content)
                    # Handle namespace
                    ns = {'sm': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
                    for elem in root.findall('.//sm:loc', ns) or root.findall('.//loc'):
                        if elem.text:
                            urls.append(elem.text)
                except ET.ParseError:
                    # Try regex fallback
                    urls = re.findall(r'<loc>(.*?)</loc>', content)
        except Exception as e:
            logger.debug(f"Could not fetch sitemap: {e}")
        return urls
    
    async def _detect_waf(self) -> Dict[str, Any]:
        """Detect Web Application Firewall."""
        waf_signatures = {
            "cloudflare": ["cloudflare", "cf-ray", "__cfduid", "cf-request-id"],
            "akamai": ["akamai", "akamai-ghost", "akamai-origin-hop"],
            "imperva": ["imperva", "incapsula", "_incap_"],
            "f5": ["f5", "bigip", "ASM"],
            "aws_waf": ["awselb", "aws-waf", "x-amzn-waf"],
            "sucuri": ["sucuri", "sucuri-cloudproxy"],
            "modsecurity": ["mod_security", "modsecurity", "NOYB"],
        }
        
        try:
            response = await self.client.get(self.config.target_url)
            wrapper = ResponseWrapper(response)
            await wrapper.text()
            
            headers_str = " ".join(f"{k}: {v}" for k, v in wrapper.headers.items()).lower()
            body = (await wrapper.text()).lower()
            
            detected = []
            for waf, signatures in waf_signatures.items():
                for sig in signatures:
                    if sig in headers_str or sig in body:
                        detected.append(waf)
                        break
            
            result = {
                "detected": len(detected) > 0,
                "wafs": list(set(detected)),
                "headers_analyzed": True
            }
            
            if detected:
                vuln = Vulnerability(
                    id="WAF_DETECTED",
                    title="Web Application Firewall Detected",
                    description=f"WAF detected: {', '.join(set(detected))}. This may affect scan accuracy.",
                    category=VulnerabilityCategory.SECURITY_MISCONFIGURATION,
                    severity=Severity.INFO,
                    cvss=CVSSScore(**SEVERITY_CVSS_MAP["info"]),
                    url=self.config.target_url,
                    remediation="Configure WAF to allow legitimate security testing. Consider allowlisting scanner IPs for authorized tests.",
                    references=[],
                    tags=["passive", "waf", "info"]
                )
                self.scan_result.add_vulnerability(vuln)
            
            return result
        except Exception as e:
            return {"error": str(e), "detected": False}
    
    async def _analyze_cookies(self) -> Dict[str, Any]:
        """Analyze cookie security attributes."""
        try:
            response = await self.client.get(self.config.target_url)
            wrapper = ResponseWrapper(response)
            await wrapper.text()
            
            cookies = wrapper.get_cookies()
            analysis = {
                "cookies": [],
                "issues": []
            }
            
            for name, value in cookies.items():
                cookie_info = {
                    "name": name,
                    "secure": False,
                    "httponly": False,
                    "samesite": "None",
                    "domain": "",
                    "path": "/",
                }
                
                # Parse Set-Cookie headers
                for header_name, header_value in wrapper.headers.items():
                    if header_name.lower() == "set-cookie" and header_value.startswith(f"{name}="):
                        parts = header_value.split(";")
                        for part in parts[1:]:
                            part = part.strip().lower()
                            if part == "secure":
                                cookie_info["secure"] = True
                            elif part == "httponly":
                                cookie_info["httponly"] = True
                            elif part.startswith("samesite="):
                                cookie_info["samesite"] = part.split("=", 1)[1].capitalize()
                            elif part.startswith("domain="):
                                cookie_info["domain"] = part.split("=", 1)[1]
                            elif part.startswith("path="):
                                cookie_info["path"] = part.split("=", 1)[1]
                        break
                
                # Check for issues
                if not cookie_info["secure"] and self.config.target_url.startswith("https"):
                    analysis["issues"].append({
                        "cookie": name,
                        "issue": "Missing Secure flag on HTTPS site",
                        "severity": "medium"
                    })
                
                if not cookie_info["httponly"]:
                    analysis["issues"].append({
                        "cookie": name,
                        "issue": "Missing HttpOnly flag",
                        "severity": "medium"
                    })
                
                if cookie_info["samesite"] == "None" and cookie_info["secure"]:
                    analysis["issues"].append({
                        "cookie": name,
                        "issue": "SameSite=None with Secure (cross-site cookie)",
                        "severity": "low"
                    })
                elif cookie_info["samesite"] not in ["Strict", "Lax"]:
                    analysis["issues"].append({
                        "cookie": name,
                        "issue": f"SameSite={cookie_info['samesite']} (should be Strict or Lax)",
                        "severity": "low"
                    })
                
                analysis["cookies"].append(cookie_info)
            
            # Create vulnerabilities for cookie issues
            for issue in analysis["issues"]:
                severity = Severity.MEDIUM if issue["severity"] == "medium" else Severity.LOW
                vuln = Vulnerability(
                    id=f"COOKIE_{issue['issue'].upper().replace(' ', '_').replace('-', '_')}_{issue['cookie'].upper()}",
                    title=f"Cookie Security Issue: {issue['cookie']}",
                    description=f"Cookie '{issue['cookie']}' has security issue: {issue['issue']}",
                    category=VulnerabilityCategory.COOKIE_SECURITY,
                    severity=severity,
                    cvss=CVSSScore(**SEVERITY_CVSS_MAP[severity.value]),
                    owasp_category="A05:2021 – Security Misconfiguration",
                    url=self.config.target_url,
                    remediation=f"Set Secure, HttpOnly, and SameSite=Strict/Lax flags for cookie '{issue['cookie']}'",
                    references=[
                        "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
                    ],
                    tags=["passive", "cookie", "session"]
                )
                self.scan_result.add_vulnerability(vuln)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing cookies: {e}")
            return {"error": str(e)}
    
    async def _extract_technologies_from_headers(self) -> List[Technology]:
        """Detect technologies from HTTP headers."""
        technologies = []
        
        try:
            response = await self.client.get(self.config.target_url)
            wrapper = ResponseWrapper(response)
            await wrapper.text()
            
            headers = {k.lower(): v for k, v in wrapper.headers.items()}
            
            # Server header
            if "server" in headers:
                server = headers["server"]
                technologies.append(Technology(
                    name=server.split("/")[0],
                    version=server.split("/")[1] if "/" in server else None,
                    category="server",
                    confidence=0.8,
                    evidence=[f"Server header: {server}"]
                ))
            
            # X-Powered-By
            if "x-powered-by" in headers:
                powered = headers["x-powered-by"]
                technologies.append(Technology(
                    name=powered.split("/")[0],
                    version=powered.split("/")[1] if "/" in powered else None,
                    category="framework",
                    confidence=0.9,
                    evidence=[f"X-Powered-By header: {powered}"]
                ))
            
            # X-AspNet-Version
            if "x-aspnet-version" in headers:
                technologies.append(Technology(
                    name="ASP.NET",
                    version=headers["x-aspnet-version"],
                    category="framework",
                    confidence=1.0,
                    evidence=[f"X-AspNet-Version header: {headers['x-aspnet-version']}"]
                ))
            
            # X-AspNetMvc-Version
            if "x-aspnetmvc-version" in headers:
                technologies.append(Technology(
                    name="ASP.NET MVC",
                    version=headers["x-aspnetmvc-version"],
                    category="framework",
                    confidence=1.0,
                    evidence=[f"X-AspNetMvc-Version header: {headers['x-aspnetmvc-version']}"]
                ))
            
            # X-Generator (WordPress, Drupal, etc.)
            if "x-generator" in headers:
                technologies.append(Technology(
                    name=headers["x-generator"].split(" ")[0],
                    version=" ".join(headers["x-generator"].split(" ")[1:]) if " " in headers["x-generator"] else None,
                    category="cms",
                    confidence=0.9,
                    evidence=[f"X-Generator header: {headers['x-generator']}"]
                ))
            
            # Via header (proxies/CDNs)
            if "via" in headers:
                via = headers["via"]
                for cdn in ["cloudflare", "akamai", "fastly", "cloudfront", "varnish", "nginx"]:
                    if cdn in via.lower():
                        technologies.append(Technology(
                            name=cdn.capitalize(),
                            category="cdn",
                            confidence=0.7,
                            evidence=[f"Via header: {via}"]
                        ))
            
            # CF-Ray (Cloudflare)
            if "cf-ray" in headers:
                technologies.append(Technology(
                    name="Cloudflare",
                    category="cdn",
                    confidence=1.0,
                    evidence=[f"CF-Ray header: {headers['cf-ray']}"]
                ))
            
        except Exception as e:
            logger.debug(f"Error extracting technologies from headers: {e}")
        
        return technologies
    
    async def _extract_endpoints_from_sources(self, robots_txt: str, sitemap_urls: List[str]):
        """Extract endpoints from robots.txt and sitemap."""
        endpoints = set()
        
        # From robots.txt
        for line in robots_txt.split('\n'):
            line = line.strip()
            if line.lower().startswith(("disallow:", "allow:")):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    full_url = urljoin(self.config.target_url, path)
                    endpoints.add(full_url)
        
        # From sitemap
        for url in sitemap_urls:
            endpoints.add(url)
        
        # Convert to Endpoint objects
        for url in endpoints:
            self.discovered_endpoints.append(Endpoint(
                url=url,
                method="GET",
                parameters=[],
                technologies=[],
                status_code=0
            ))
            self.scan_result.urls_crawled.append(url)