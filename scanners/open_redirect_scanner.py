"""
Active vulnerability scanner for Open Redirect.
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
    OPEN_REDIRECT_PAYLOADS, SEVERITY_CVSS_MAP
)

logger = logging.getLogger(__name__)


class OpenRedirectScanner:
    """Open Redirect vulnerability scanner."""
    
    def __init__(self, client: HTTPClient, config, scan_result: ScanResult):
        self.client = client
        self.config = config
        self.scan_result = scan_result
        self.tested_parameters: Set[str] = set()
    
    async def run(self, endpoints: List) -> Dict[str, Any]:
        """Run Open Redirect scans on discovered endpoints."""
        results = {
            "vulnerabilities_found": 0,
            "parameters_tested": 0,
            "open_redirects": [],
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
                # Only test parameters that look like redirect targets
                if not self._is_redirect_param(param_name):
                    continue
                    
                if param_name in self.tested_parameters:
                    continue
                self.tested_parameters.add(param_name)
                results["parameters_tested"] += 1
                
                # Test each payload
                for payload in OPEN_REDIRECT_PAYLOADS[:10]:
                    vuln = await self._test_open_redirect(url, param_name, payload)
                    if vuln:
                        results["vulnerabilities_found"] += 1
                        results["open_redirects"].append(vuln.to_dict())
                        break
            
            # Test form parameters
            if hasattr(endpoint, 'forms') and endpoint.forms:
                for form in endpoint.forms:
                    await self._test_form_open_redirect(url, form, results)
        
        return results
    
    def _is_redirect_param(self, param_name: str) -> bool:
        """Check if parameter name suggests it's a redirect target."""
        redirect_keywords = [
            'redirect', 'url', 'next', 'return', 'returnto', 'return_to',
            'goto', 'target', 'destination', 'continue', 'redirect_url',
            'redirect_to', 'forward', 'forward_to', 'url_next', 'next_url',
            'return_url', 'success_url', 'failure_url', 'callback', 'cb'
        ]
        param_lower = param_name.lower()
        return any(kw in param_lower for kw in redirect_keywords)
    
    async def _test_open_redirect(self, url: str, param_name: str, payload: str) -> Optional[Vulnerability]:
        """Test for open redirect in a URL parameter."""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param_name] = [payload]
            new_query = urlencode(params, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()
            
            # Don't follow redirects to detect them
            response = await self.client.get(test_url, allow_redirects=False)
            
            # Check for redirect status codes
            if response.status in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                
                # Check if redirect goes to our payload
                if self._is_redirect_to_payload(location, payload):
                    severity = self._assess_redirect_severity(payload, location)
                    
                    vuln = Vulnerability(
                        id=f"OPEN_REDIRECT_{uuid.uuid4().hex[:8].upper()}",
                        title=f"Open Redirect in parameter '{param_name}'",
                        description=f"Parameter '{param_name}' is vulnerable to open redirect. User-supplied URLs are used in redirects without validation, allowing phishing and malware distribution.",
                        category=VulnerabilityCategory.OPEN_REDIRECT,
                        severity=severity,
                        cvss=CVSSScore(**SEVERITY_CVSS_MAP[severity.value]),
                        owasp_category="A01:2021 – Broken Access Control",
                        url=test_url,
                        parameter=param_name,
                        method="GET",
                        poc=f"Payload: {payload} -> Redirects to: {location}",
                        poc_code=self._generate_open_redirect_poc(test_url, param_name, payload, location),
                        remediation="Validate redirect URLs against an allowlist. Use relative URLs only. Implement a redirect confirmation page. Avoid user-supplied redirect targets.",
                        references=[
                            "https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                            "https://portswigger.net/web-security/redirects"
                        ],
                        tags=["active", "open_redirect", "phishing"],
                        confirmed=True
                    )
                    
                    vuln.evidence.append(Evidence(
                        type="redirect",
                        description="Open redirect confirmed via Location header",
                        data={"payload": payload, "location": location, "status_code": response.status}
                    ))
                    vuln.request = HTTPRequest(method="GET", url=test_url)
                    vuln.response = HTTPResponse(
                        status_code=response.status,
                        headers=dict(response.headers),
                        body="",
                        url=test_url
                    )
                    
                    self.scan_result.add_vulnerability(vuln)
                    return vuln
                    
        except Exception as e:
            logger.debug(f"Error testing open redirect on {url} param {param_name}: {e}")
        
        return None
    
    def _is_redirect_to_payload(self, location: str, payload: str) -> bool:
        """Check if redirect location matches our payload."""
        if not location:
            return False
        
        # Direct match
        if payload in location:
            return True
        
        # Normalize for comparison
        payload_normalized = payload.replace('https://', '').replace('http://', '').replace('//', '')
        location_normalized = location.replace('https://', '').replace('http://', '').replace('//', '')
        
        if payload_normalized in location_normalized:
            return True
        
        # Check for javascript: and data: protocols
        if payload.startswith('javascript:') and location.startswith('javascript:'):
            return True
        if payload.startswith('data:') and location.startswith('data:'):
            return True
        
        return False
    
    def _assess_redirect_severity(self, payload: str, location: str) -> Severity:
        """Assess open redirect severity."""
        # Critical: javascript: or data: protocol (XSS potential)
        if payload.startswith('javascript:') or payload.startswith('data:'):
            return Severity.HIGH
        
        # High: External domain redirect
        if payload.startswith('http://') or payload.startswith('https://'):
            return Severity.MEDIUM
        
        # Medium: Protocol-relative or path-relative
        if payload.startswith('//') or payload.startswith('/'):
            return Severity.LOW
        
        return Severity.LOW
    
    async def _test_form_open_redirect(self, url: str, form: Dict, results: Dict):
        """Test open redirect in form inputs."""
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
            
            if not self._is_redirect_param(input_name):
                continue
            
            if input_name in self.tested_parameters:
                continue
            self.tested_parameters.add(input_name)
            results["parameters_tested"] += 1
            
            for payload in OPEN_REDIRECT_PAYLOADS[:5]:
                vuln = await self._test_form_input_open_redirect(action, method, input_name, payload, inputs)
                if vuln:
                    results["vulnerabilities_found"] += 1
                    results["open_redirects"].append(vuln.to_dict())
                    break
    
    async def _test_form_input_open_redirect(self, action: str, method: str, input_name: str, payload: str, all_inputs: List) -> Optional[Vulnerability]:
        """Test open redirect in a specific form input."""
        try:
            # Build form data
            form_data = {}
            for inp in all_inputs:
                name = inp.get('name', '')
                if name == input_name:
                    form_data[name] = payload
                elif inp.get('type') not in ['submit', 'button', 'image']:
                    form_data[name] = inp.get('value', 'test')
            
            # Make request without following redirects
            if method == "POST":
                response = await self.client.post(action, data=form_data, allow_redirects=False)
            else:
                response = await self.client.get(action, params=form_data, allow_redirects=False)
            
            location = response.headers.get('Location', '')
            
            if response.status in [301, 302, 303, 307, 308] and self._is_redirect_to_payload(location, payload):
                severity = self._assess_redirect_severity(payload, location)
                
                vuln = Vulnerability(
                    id=f"OPEN_REDIRECT_FORM_{uuid.uuid4().hex[:8].upper()}",
                    title=f"Open Redirect in form input '{input_name}'",
                    description=f"Form input '{input_name}' is vulnerable to open redirect via {method} request.",
                    category=VulnerabilityCategory.OPEN_REDIRECT,
                    severity=severity,
                    cvss=CVSSScore(**SEVERITY_CVSS_MAP[severity.value]),
                    owasp_category="A01:2021 – Broken Access Control",
                    url=action,
                    parameter=input_name,
                    method=method,
                    poc=f"Submit form to {action} with {input_name}={payload} -> Redirects to: {location}",
                    poc_code=self._generate_form_open_redirect_poc(action, method, input_name, payload, form_data, location),
                    remediation="Validate redirect URLs against an allowlist. Use relative URLs only. Implement a redirect confirmation page.",
                    references=[
                        "https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
                    ],
                    tags=["active", "open_redirect", "form", "phishing"],
                    confirmed=True
                )
                
                vuln.evidence.append(Evidence(
                    type="redirect",
                    description="Open redirect confirmed via form submission",
                    data={"payload": payload, "location": location, "status_code": response.status}
                ))
                vuln.request = HTTPRequest(method=method, url=action, body=str(form_data))
                vuln.response = HTTPResponse(
                    status_code=response.status,
                    headers=dict(response.headers),
                    body="",
                    url=str(response.url)
                )
                
                self.scan_result.add_vulnerability(vuln)
                return vuln
                
        except Exception as e:
            logger.debug(f"Error testing form open redirect: {e}")
        
        return None
    
    def _generate_open_redirect_poc(self, url: str, param: str, payload: str, location: str) -> str:
        """Generate proof of concept code for open redirect."""
        base_url = url.split('?')[0]
        return f"""#!/usr/bin/env python3
\"\"\"
Proof of Concept for Open Redirect
Target: {url}
Parameter: {param}
Payload: {payload}
Redirects to: {location}
\"\"\"

import requests
from urllib.parse import urlencode

# Target URL
base_url = "{base_url}"
param_name = "{param}"

# Open redirect payload
payload = "{payload}"

# Build test URL
params = {{param_name: payload}}
test_url = f"{{base_url}}?{{urlencode(params)}}"

print(f"[+] Testing Open Redirect on {{test_url}}")

# Don't follow redirects
response = requests.get(test_url, allow_redirects=False)

print(f"    Status Code: {{response.status_code}}")
print(f"    Location Header: {{response.headers.get('Location', 'None')}}")

if response.status_code in [301, 302, 303, 307, 308]:
    location = response.headers.get('Location', '')
    if "{payload}" in location:
        print("[+] Open Redirect Confirmed!")
        print(f"[+] Redirects to: {{location}}")
        
        # Check for dangerous protocols
        if location.startswith('javascript:'):
            print("[!!!] JAVASCRIPT PROTOCOL - XSS POSSIBLE - HIGH SEVERITY")
        elif location.startswith('data:'):
            print("[!!!] DATA PROTOCOL - XSS POSSIBLE - HIGH SEVERITY")
        elif location.startswith('http'):
            print("[!!!] EXTERNAL REDIRECT - PHISHING RISK - MEDIUM SEVERITY")
    else:
        print("[-] Redirect location doesn't match payload.")
else:
    print("[-] No redirect detected.")

print(f"\\n[+] Manual test: {{test_url}}")
print(f"[+] Phishing URL example: {{test_url}} (send to victim)")
"""
    
    def _generate_form_open_redirect_poc(self, action: str, method: str, input_name: str, payload: str, form_data: Dict, location: str) -> str:
        """Generate PoC code for form-based open redirect."""
        return f"""#!/usr/bin/env python3
\"\"\"
Proof of Concept for Form-based Open Redirect
Target: {action}
Method: {method}
Parameter: {input_name}
Payload: {payload}
Redirects to: {location}
\"\"\"

import requests

# Target URL
target_url = "{action}"
method = "{method}"

# Form data with redirect payload
form_data = {form_data}
form_data["{input_name}"] = "{payload}"

print(f"[+] Testing Open Redirect via form submission to {{target_url}}")

# Don't follow redirects
if method == "POST":
    response = requests.post(target_url, data=form_data, allow_redirects=False)
else:
    response = requests.get(target_url, params=form_data, allow_redirects=False)

print(f"    Status Code: {{response.status_code}}")
print(f"    Location Header: {{response.headers.get('Location', 'None')}}")

if response.status_code in [301, 302, 303, 307, 308]:
    location = response.headers.get('Location', '')
    if "{payload}" in location:
        print("[+] Open Redirect Confirmed!")
        print(f"[+] Redirects to: {{location}}")
    else:
        print("[-] Redirect location doesn't match payload.")
else:
    print("[-] No redirect detected.")

print(f"\\n[+] Manual test: Submit form to {{target_url}} with {input_name}={payload}")
"""