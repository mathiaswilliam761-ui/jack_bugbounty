"""
Active vulnerability scanner for XSS (Cross-Site Scripting).
"""

import asyncio
import re
import uuid
from typing import Dict, List, Optional, Set, Any
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
import logging

from pentest_scanner.utils.http_client import HTTPClient, ResponseWrapper, make_request
from pentest_scanner.utils.models import (
    Vulnerability, Severity, VulnerabilityCategory, CVSSScore,
    Evidence, ScanResult, HTTPRequest, HTTPResponse
)
from pentest_scanner.config.settings import (
    XSS_PAYLOADS, SEVERITY_CVSS_MAP, DEFAULT_CONFIG
)

logger = logging.getLogger(__name__)


class XSSScanner:
    """Cross-Site Scripting vulnerability scanner."""
    
    def __init__(self, client: HTTPClient, config, scan_result: ScanResult):
        self.client = client
        self.config = config
        self.scan_result = scan_result
        self.tested_parameters: Set[str] = set()
    
    async def run(self, endpoints: List) -> Dict[str, Any]:
        """Run XSS scans on discovered endpoints."""
        results = {
            "vulnerabilities_found": 0,
            "parameters_tested": 0,
            "reflected_xss": [],
            "stored_xss": [],
            "dom_xss": [],
        }
        
        # Test each endpoint
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
                
                # Test each payload
                for payload in XSS_PAYLOADS[:10]:  # Limit payloads for speed
                    vuln = await self._test_reflected_xss(url, param_name, payload)
                    if vuln:
                        results["vulnerabilities_found"] += 1
                        results["reflected_xss"].append(vuln.to_dict())
                        break  # Found XSS, move to next parameter
            
            # Test form parameters if endpoint has forms
            if hasattr(endpoint, 'forms') and endpoint.forms:
                for form in endpoint.forms:
                    await self._test_form_xss(url, form, results)
        
        return results
    
    async def _test_reflected_xss(self, url: str, param_name: str, payload: str) -> Optional[Vulnerability]:
        """Test for reflected XSS in a URL parameter."""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Inject payload
            params[param_name] = [payload]
            new_query = urlencode(params, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()
            
            # Make request
            response = await self.client.get(test_url)
            wrapper = ResponseWrapper(response)
            body = await wrapper.text()
            
            # Check if payload is reflected unencoded
            if self._is_payload_reflected(body, payload):
                # Verify it's actually executable (not just reflected)
                if await self._verify_xss_execution(test_url, param_name, payload):
                    vuln = Vulnerability(
                        id=f"XSS_REFLECTED_{uuid.uuid4().hex[:8].upper()}",
                        title=f"Reflected Cross-Site Scripting (XSS) in parameter '{param_name}'",
                        description=f"User input in parameter '{param_name}' is reflected in the response without proper encoding, allowing JavaScript execution.",
                        category=VulnerabilityCategory.XSS,
                        severity=Severity.HIGH,
                        cvss=CVSSScore(**SEVERITY_CVSS_MAP["high"]),
                        owasp_category="A03:2021 – Injection",
                        url=test_url,
                        parameter=param_name,
                        method="GET",
                        poc=f"Visit: {test_url}",
                        poc_code=self._generate_xss_poc(test_url, param_name, payload),
                        remediation="Implement proper output encoding/context-aware escaping. Use Content-Security-Policy header. Validate and sanitize all user inputs.",
                        references=[
                            "https://owasp.org/www-project-top-ten/2021/A03_2021-Injection",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                            "https://portswigger.net/web-security/cross-site-scripting"
                        ],
                        tags=["active", "xss", "reflected", "injection"],
                        confirmed=True
                    )
                    
                    # Add evidence
                    vuln.evidence.append(Evidence(
                        type="response",
                        description=f"Payload reflected in response",
                        data={"payload": payload, "reflected_in": "response_body"}
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
            logger.debug(f"Error testing XSS on {url} param {param_name}: {e}")
        
        return None
    
    async def _verify_xss_execution(self, url: str, param_name: str, payload: str) -> bool:
        """Verify XSS by checking if payload executes (using a unique marker)."""
        # Use a unique marker to confirm execution
        marker = f"XSS_MARKER_{uuid.uuid4().hex[:8]}"
        test_payload = f"<script>document.body.setAttribute('data-xss-marker', '{marker}')</script>"
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param_name] = [test_payload]
        new_query = urlencode(params, doseq=True)
        test_url = parsed._replace(query=new_query).geturl()
        
        try:
            response = await self.client.get(test_url)
            wrapper = ResponseWrapper(response)
            body = await wrapper.text()
            
            # Check if marker appears in response (indicating script executed)
            return marker in body
        except Exception:
            return False
    
    def _is_payload_reflected(self, body: str, payload: str) -> bool:
        """Check if payload is reflected in response body."""
        # Check for exact reflection
        if payload in body:
            return True
        
        # Check for partially encoded reflection
        encoded_variants = [
            payload.replace("<", "<").replace(">", ">"),
            payload.replace("<", "%3C").replace(">", "%3E"),
            payload.replace('"', '"').replace("'", "'"),
        ]
        
        for variant in encoded_variants:
            if variant in body:
                return True
        
        return False
    
    async def _test_form_xss(self, url: str, form: Dict, results: Dict):
        """Test XSS in form inputs."""
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
            
            for payload in XSS_PAYLOADS[:5]:
                vuln = await self._test_form_input_xss(action, method, input_name, payload, inputs)
                if vuln:
                    results["vulnerabilities_found"] += 1
                    results["reflected_xss"].append(vuln.to_dict())
                    break
    
    async def _test_form_input_xss(self, action: str, method: str, input_name: str, payload: str, all_inputs: List) -> Optional[Vulnerability]:
        """Test XSS in a specific form input."""
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
            
            if self._is_payload_reflected(body, payload):
                if await self._verify_xss_execution_form(action, method, input_name, payload, form_data):
                    vuln = Vulnerability(
                        id=f"XSS_FORM_{uuid.uuid4().hex[:8].upper()}",
                        title=f"Reflected XSS in form input '{input_name}'",
                        description=f"Form input '{input_name}' is vulnerable to reflected XSS via {method} request.",
                        category=VulnerabilityCategory.XSS,
                        severity=Severity.HIGH,
                        cvss=CVSSScore(**SEVERITY_CVSS_MAP["high"]),
                        owasp_category="A03:2021 – Injection",
                        url=action,
                        parameter=input_name,
                        method=method,
                        poc=f"Submit form to {action} with {input_name}={payload}",
                        poc_code=self._generate_form_xss_poc(action, method, input_name, payload, form_data),
                        remediation="Implement proper output encoding. Use CSP. Validate/sanitize inputs. Use CSRF tokens.",
                        references=[
                            "https://owasp.org/www-project-top-ten/2021/A03_2021-Injection",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                        ],
                        tags=["active", "xss", "reflected", "form", "injection"],
                        confirmed=True
                    )
                    
                    vuln.evidence.append(Evidence(
                        type="response",
                        description=f"Payload reflected in form response",
                        data={"payload": payload, "input": input_name}
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
            logger.debug(f"Error testing form XSS: {e}")
        
        return None
    
    async def _verify_xss_execution_form(self, action: str, method: str, input_name: str, payload: str, form_data: Dict) -> bool:
        """Verify XSS execution for form submission."""
        marker = f"XSS_MARKER_{uuid.uuid4().hex[:8]}"
        test_payload = f"<script>document.body.setAttribute('data-xss-marker', '{marker}')</script>"
        
        test_data = form_data.copy()
        test_data[input_name] = test_payload
        
        try:
            if method == "POST":
                response = await self.client.post(action, data=test_data)
            else:
                response = await self.client.get(action, params=test_data)
            
            wrapper = ResponseWrapper(response)
            body = await wrapper.text()
            return marker in body
        except Exception:
            return False
    
    def _generate_xss_poc(self, url: str, param: str, payload: str) -> str:
        """Generate proof of concept code for XSS."""
        return f"""#!/usr/bin/env python3
\"\"\"
Proof of Concept for Reflected XSS
Target: {url}
Parameter: {param}
\"\"\"

import requests

# Target URL with XSS payload
target_url = "{url}"

# The payload that executes JavaScript
payload = "{payload.replace('"', '\\"')}"

# Send request
response = requests.get(target_url)

# Check if payload is reflected
if payload in response.text:
    print("[+] XSS Confirmed! Payload reflected in response.")
    print(f"[+] Vulnerable URL: {target_url}")
else:
    print("[-] Payload not reflected (may be encoded)")

# For browser testing, simply visit the URL in a browser
print(f"\\n[+] Browser PoC: Open this URL in a browser:")
print(f"    {target_url}")
"""
    
    def _generate_form_xss_poc(self, action: str, method: str, input_name: str, payload: str, form_data: Dict) -> str:
        """Generate PoC code for form-based XSS."""
        return f"""#!/usr/bin/env python3
\"\"\"
Proof of Concept for Form-based Reflected XSS
Target: {action}
Method: {method}
Parameter: {input_name}
\"\"\"

import requests

# Target URL
target_url = "{action}"
method = "{method}"

# Form data with XSS payload
form_data = {form_data}
form_data["{input_name}"] = "{payload.replace('"', '\\"')}"

# Send request
if method == "POST":
    response = requests.post(target_url, data=form_data)
else:
    response = requests.get(target_url, params=form_data)

# Check if payload is reflected
if "{payload.replace('"', '\\"')}" in response.text:
    print("[+] XSS Confirmed! Payload reflected in response.")
else:
    print("[-] Payload not reflected (may be encoded)")

print(f"\\n[+] Browser PoC: Submit form to {target_url} with {input_name}={payload}")
"""