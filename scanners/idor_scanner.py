"""
Active vulnerability scanner for IDOR (Insecure Direct Object References).
"""

import asyncio
import uuid
import re
from typing import Dict, List, Optional, Set, Any
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
import logging

from pentest_scanner.utils.http_client import HTTPClient, ResponseWrapper
from pentest_scanner.utils.models import (
    Vulnerability, Severity, VulnerabilityCategory, CVSSScore,
    Evidence, ScanResult, HTTPRequest, HTTPResponse
)
from pentest_scanner.config.settings import (
    SEVERITY_CVSS_MAP
)

logger = logging.getLogger(__name__)


class IDORScanner:
    """Insecure Direct Object Reference vulnerability scanner."""
    
    def __init__(self, client: HTTPClient, config, scan_result: ScanResult):
        self.client = client
        self.config = config
        self.scan_result = scan_result
        self.tested_parameters: Set[str] = set()
        self.discovered_ids: Dict[str, List[str]] = {}  # param -> list of IDs
    
    async def run(self, endpoints: List) -> Dict[str, Any]:
        """Run IDOR scans on discovered endpoints."""
        results = {
            "vulnerabilities_found": 0,
            "parameters_tested": 0,
            "idor_findings": [],
        }
        
        # First pass: Discover object references (IDs) in responses
        await self._discover_object_references(endpoints)
        
        # Second pass: Test for IDOR by manipulating IDs
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
                
                # Test IDOR
                vuln = await self._test_idor(url, param_name, param_values[0])
                if vuln:
                    results["vulnerabilities_found"] += 1
                    results["idor_findings"].append(vuln.to_dict())
        
        return results
    
    async def _discover_object_references(self, endpoints: List):
        """Discover object references (IDs, UUIDs, etc.) in responses."""
        id_patterns = [
            (r'\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b', 'uuid'),
            (r'\b(\d{1,10})\b', 'numeric_id'),
            (r'\b([A-Za-z0-9]{20,})\b', 'alphanumeric_id'),
            (r'"id"\s*:\s*"([^"]+)"', 'json_id'),
            (r'"id"\s*:\s*(\d+)', 'json_numeric_id'),
            (r'user[_-]?id["\']?\s*[:=]\s*["\']?([^"\'&\s]+)', 'user_id'),
            (r'order[_-]?id["\']?\s*[:=]\s*["\']?([^"\'&\s]+)', 'order_id'),
            (r'document[_-]?id["\']?\s*[:=]\s*["\']?([^"\'&\s]+)', 'document_id'),
            (r'file[_-]?id["\']?\s*[:=]\s*["\']?([^"\'&\s]+)', 'file_id'),
            (r'account[_-]?id["\']?\s*[:=]\s*["\']?([^"\'&\s]+)', 'account_id'),
        ]
        
        for endpoint in endpoints[:20]:  # Limit to first 20 endpoints
            if hasattr(endpoint, 'url'):
                url = endpoint.url
            else:
                url = endpoint.get('url', '')
            
            if not url:
                continue
            
            try:
                response = await self.client.get(url)
                wrapper = ResponseWrapper(response)
                body = await wrapper.text()
                
                for pattern, id_type in id_patterns:
                    matches = re.findall(pattern, body, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0] if match else ''
                        if match and len(match) > 1:
                            param_key = f"{id_type}_ids"
                            if param_key not in self.discovered_ids:
                                self.discovered_ids[param_key] = []
                            if match not in self.discovered_ids[param_key]:
                                self.discovered_ids[param_key].append(match)
                                
            except Exception as e:
                logger.debug(f"Error discovering IDs from {url}: {e}")
    
    async def _test_idor(self, url: str, param_name: str, original_value: str) -> Optional[Vulnerability]:
        """Test for IDOR by manipulating object references."""
        # Determine ID type and generate test values
        test_values = self._generate_test_values(original_value)
        
        if not test_values:
            return None
        
        # Get baseline response
        try:
            response = await self.client.get(url)
            wrapper = ResponseWrapper(response)
            baseline_body = await wrapper.text()
            baseline_status = response.status
            baseline_length = len(baseline_body)
        except Exception:
            return None
        
        for test_value in test_values[:5]:  # Limit test values
            if test_value == original_value:
                continue
            
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param_name] = [test_value]
                new_query = urlencode(params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()
                
                response = await self.client.get(test_url)
                wrapper = ResponseWrapper(response)
                body = await wrapper.text()
                
                # Check if we got different data (potential IDOR)
                if self._is_potential_idor(baseline_body, body, baseline_status, response.status):
                    # Verify by checking if response contains data for the test ID
                    if await self._verify_idor_access(test_url, test_value, body):
                        severity = self._assess_idor_severity(param_name, test_value, body)
                        
                        vuln = Vulnerability(
                            id=f"IDOR_{uuid.uuid4().hex[:8].upper()}",
                            title=f"Insecure Direct Object Reference (IDOR) in parameter '{param_name}'",
                            description=f"Parameter '{param_name}' allows access to unauthorized objects. By changing the value from '{original_value}' to '{test_value}', different user data was accessible.",
                            category=VulnerabilityCategory.IDOR,
                            severity=severity,
                            cvss=CVSSScore(**SEVERITY_CVSS_MAP[severity.value]),
                            owasp_category="A01:2021 – Broken Access Control",
                            url=test_url,
                            parameter=param_name,
                            method="GET",
                            poc=f"Change {param_name} from {original_value} to {test_value}",
                            poc_code=self._generate_idor_poc(url, param_name, original_value, test_value),
                            remediation="Implement proper authorization checks. Verify user owns the requested object. Use indirect object references (random tokens). Implement row-level security in database.",
                            references=[
                                "https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
                                "https://portswigger.net/web-security/access-control/idor"
                            ],
                            tags=["active", "idor", "broken_access_control"],
                            confirmed=True
                        )
                        
                        vuln.evidence.append(Evidence(
                            type="comparison",
                            description="IDOR confirmed - different object data returned",
                            data={
                                "original_id": original_value,
                                "test_id": test_value,
                                "original_length": baseline_length,
                                "test_length": len(body),
                                "status_changed": baseline_status != response.status
                            }
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
                logger.debug(f"Error testing IDOR on {url} param {param_name}: {e}")
        
        return None
    
    def _generate_test_values(self, original_value: str) -> List[str]:
        """Generate test values based on the original value type."""
        test_values = []
        
        # Numeric ID
        if original_value.isdigit():
            num = int(original_value)
            test_values.extend([
                str(num - 1),
                str(num + 1),
                str(num - 10),
                str(num + 10),
                "1",
                "0",
                "-1",
                "999999",
            ])
        
        # UUID
        elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', original_value, re.IGNORECASE):
            # Can't easily generate valid UUIDs, but we can try known ones
            test_values.extend([
                "00000000-0000-0000-0000-000000000000",
                "11111111-1111-1111-1111-111111111111",
                "ffffffff-ffff-ffff-ffff-ffffffffffff",
            ])
        
        # Alphanumeric
        else:
            test_values.extend([
                "1",
                "2",
                "admin",
                "test",
                "0",
                "null",
                "undefined",
            ])
        
        return test_values
    
    def _is_potential_idor(self, baseline_body: str, test_body: str, baseline_status: int, test_status: int) -> bool:
        """Check if responses indicate potential IDOR."""
        # Status code changed (e.g., 404 -> 200 or 403 -> 200)
        if baseline_status != test_status:
            if test_status == 200 and baseline_status in [404, 403, 401]:
                return True
        
        # Significant content difference
        if abs(len(test_body) - len(baseline_body)) > max(len(baseline_body) * 0.3, 100):
            return True
        
        # Content similarity check (if very similar, might be same template)
        # If very different, could be different object
        return False
    
    async def _verify_idor_access(self, test_url: str, test_value: str, body: str) -> bool:
        """Verify that the test ID actually returns different user's data."""
        # Check for indicators that we're seeing another user's data
        indicators = [
            r'email["\']?\s*[:=]\s*["\'][^"\']+@[^"\']+',
            r'name["\']?\s*[:=]\s*["\'][^"\']+',
            r'address["\']?\s*[:=]\s*["\'][^"\']+',
            r'phone["\']?\s*[:=]\s*["\'][^"\']+',
            r'ssn["\']?\s*[:=]\s*["\'][^"\']+',
            r'credit[_-]?card["\']?\s*[:=]\s*["\'][^"\']+',
            r'balance["\']?\s*[:=]\s*["\']?\d+',
            r'account[_-]?number["\']?\s*[:=]\s*["\'][^"\']+',
        ]
        
        for pattern in indicators:
            if re.search(pattern, body, re.IGNORECASE):
                return True
        
        # If response is substantially different and successful, consider it potential IDOR
        return len(body) > 500 and "error" not in body.lower()[:100]
    
    def _assess_idor_severity(self, param_name: str, test_value: str, body: str) -> Severity:
        """Assess IDOR severity based on exposed data."""
        body_lower = body.lower()
        
        # Critical: PII, financial data, authentication tokens
        critical_keywords = [
            "password", "secret", "token", "api_key", "apikey",
            "ssn", "social_security", "credit_card", "cvv",
            "passport", "driver_license", "medical_record"
        ]
        
        for kw in critical_keywords:
            if kw in body_lower:
                return Severity.CRITICAL
        
        # High: Personal information, private messages, orders
        high_keywords = [
            "email", "phone", "address", "date_of_birth", "dob",
            "private", "message", "conversation", "order", "purchase",
            "invoice", "billing", "shipping"
        ]
        
        for kw in high_keywords:
            if kw in body_lower:
                return Severity.HIGH
        
        # Medium: User profiles, preferences, non-sensitive data
        medium_keywords = [
            "profile", "preference", "setting", "avatar", "username",
            "display_name", "bio", "description"
        ]
        
        for kw in medium_keywords:
            if kw in body_lower:
                return Severity.MEDIUM
        
        return Severity.LOW
    
    def _generate_idor_poc(self, url: str, param: str, original: str, test: str) -> str:
        """Generate proof of concept code for IDOR."""
        base_url = url.split('?')[0]
        return f"""#!/usr/bin/env python3
\"\"\"
Proof of Concept for Insecure Direct Object Reference (IDOR)
Target: {url}
Parameter: {param}
Original Value: {original}
Test Value: {test}
\"\"\"

import requests
from urllib.parse import urlencode

# Target URL
base_url = "{base_url}"
param_name = "{param}"

# Original and test values
original_value = "{original}"
test_value = "{test}"

print(f"[+] Testing IDOR on {{base_url}}")
print(f"[+] Parameter: {{param_name}}")
print(f"[+] Original value: {{original_value}}")
print(f"[+] Test value: {{test_value}}")

# Test original value
params = {{param_name: original_value}}
original_url = f"{{base_url}}?{{urlencode(params)}}"
print(f"\\n[+] Original URL: {{original_url}}")

response = requests.get(original_url)
print(f"    Status: {{response.status_code}}")
print(f"    Length: {{len(response.text)}}")

# Test manipulated value
params = {{param_name: test_value}}
test_url = f"{{base_url}}?{{urlencode(params)}}"
print(f"\\n[+] Test URL: {{test_url}}")

response = requests.get(test_url)
print(f"    Status: {{response.status_code}}")
print(f"    Length: {{len(response.text)}}")

# Check for data differences
if response.status_code == 200:
    print("\\n[+] Potential IDOR! Different object accessible.")
    print(f"[+] Compare responses to confirm unauthorized data access.")
else:
    print("\\n[-] Test value returned error.")

print(f"\\n[+] Manual test: {{test_url}}")
"""