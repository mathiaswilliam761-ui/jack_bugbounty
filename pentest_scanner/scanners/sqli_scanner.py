"""
Active vulnerability scanner for SQL Injection.
"""

import asyncio
import re
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
    SQLI_PAYLOADS, SEVERITY_CVSS_MAP
)

logger = logging.getLogger(__name__)


class SQLiScanner:
    """SQL Injection vulnerability scanner."""
    
    def __init__(self, client: HTTPClient, config, scan_result: ScanResult):
        self.client = client
        self.config = config
        self.scan_result = scan_result
        self.tested_parameters: Set[str] = set()
        
        # Error patterns for different databases
        self.error_patterns = {
            "mysql": [
                r"mysql_fetch_array\(\)",
                r"mysql_num_rows\(\)",
                r"mysql_query\(\)",
                r"mysql_result\(\)",
                r"mysql_error\(\)",
                r"mysql_errno\(\)",
                r"mysql_connect\(\)",
                r"mysql_select_db\(\)",
                r"mysql_real_escape_string\(\)",
                r"mysqli_query\(\)",
                r"mysqli_error\(\)",
                r"mysqli_errno\(\)",
                r"mysqli_connect\(\)",
                r"mysqli_select_db\(\)",
                r"mysqli_real_escape_string\(\)",
                r"PDOException",
                r"SQLSTATE\[",
                r"you have an error in your sql syntax",
                r"unknown column",
                r"supplied argument is not a valid mysql",
                r"mysql server version for the right syntax",
                r"check the manual that corresponds to your mysql server version",
            ],
            "postgresql": [
                r"pg_query\(\)",
                r"pg_exec\(\)",
                r"pg_fetch_",
                r"pg_num_rows\(\)",
                r"pg_affected_rows\(\)",
                r"pg_last_error\(\)",
                r"pg_result_error\(\)",
                r"pg_connect\(\)",
                r"postgresql",
                r"psql",
                r"syntax error at or near",
                r"unterminated quoted string",
                r"invalid input syntax for",
                r"column.*does not exist",
            ],
            "mssql": [
                r"mssql_query\(\)",
                r"mssql_fetch_",
                r"mssql_num_rows\(\)",
                r"mssql_get_last_message\(\)",
                r"mssql_connect\(\)",
                r"mssql_select_db\(\)",
                r"mssql_free_result\(\)",
                r"odbc_",
                r"sqlsrv_",
                r"microsoft ole db provider for sql server",
                r"sql server native client",
                r"unclosed quotation mark after the character string",
                r"incorrect syntax near",
                r"conversion failed when converting",
            ],
            "oracle": [
                r"ora-\d{5}",
                r"oracle error",
                r"oracle driver",
                r"oci_",
                r"oci_connect\(\)",
                r"oci_parse\(\)",
                r"oci_execute\(\)",
                r"oci_fetch_",
                r"oci_num_rows\(\)",
                r"oci_error\(\)",
                r"pl/sql",
                r"quoted string not properly terminated",
                r"invalid identifier",
            ],
            "sqlite": [
                r"sqlite_query\(\)",
                r"sqlite_fetch_",
                r"sqlite_num_rows\(\)",
                r"sqlite_error\(\)",
                r"sqlite_errno\(\)",
                r"sqlite_",
                r"sqlite3",
                r"unrecognized token",
                r"syntax error",
                r"no such column",
                r"no such table",
            ],
            "generic": [
                r"sql syntax",
                r"syntax error",
                r"unclosed quotation mark",
                r"quoted string not properly terminated",
                r"unknown column",
                r"invalid column",
                r"column.*not found",
                r"table.*not found",
                r"syntax error near",
                r"unexpected end of sql command",
                r"unterminated string",
                r"invalid character",
                r"data type mismatch",
                r"conversion failed",
                r"arithmetic overflow",
                r"divide by zero",
            ]
        }
        
        # Time-based detection thresholds (seconds)
        self.time_threshold = 4.0
    
    async def run(self, endpoints: List) -> Dict[str, Any]:
        """Run SQL injection scans on discovered endpoints."""
        results = {
            "vulnerabilities_found": 0,
            "parameters_tested": 0,
            "error_based": [],
            "boolean_based": [],
            "time_based": [],
            "union_based": [],
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
                
                # Test each payload type
                for payload in SQLI_PAYLOADS[:15]:  # Limit for speed
                    # Error-based detection
                    vuln = await self._test_error_based_sqli(url, param_name, payload)
                    if vuln:
                        results["vulnerabilities_found"] += 1
                        results["error_based"].append(vuln.to_dict())
                        break
                    
                    # Time-based detection (for blind SQLi)
                    vuln = await self._test_time_based_sqli(url, param_name)
                    if vuln:
                        results["vulnerabilities_found"] += 1
                        results["time_based"].append(vuln.to_dict())
                        break
                
                # Test boolean-based
                vuln = await self._test_boolean_based_sqli(url, param_name)
                if vuln:
                    results["vulnerabilities_found"] += 1
                    results["boolean_based"].append(vuln.to_dict())
        
        return results
    
    async def _test_error_based_sqli(self, url: str, param_name: str, payload: str) -> Optional[Vulnerability]:
        """Test for error-based SQL injection."""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param_name] = [payload]
            new_query = urlencode(params, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()
            
            response = await self.client.get(test_url)
            wrapper = ResponseWrapper(response)
            body = await wrapper.text()
            
            # Check for database errors in response
            db_type, error_match = self._detect_db_error(body)
            
            if error_match:
                vuln = Vulnerability(
                    id=f"SQLI_ERROR_{uuid.uuid4().hex[:8].upper()}",
                    title=f"Error-based SQL Injection in parameter '{param_name}'",
                    description=f"Parameter '{param_name}' is vulnerable to error-based SQL injection. Database error messages are exposed, revealing database structure.",
                    category=VulnerabilityCategory.INJECTION,
                    severity=Severity.HIGH,
                    cvss=CVSSScore(**SEVERITY_CVSS_MAP["high"]),
                    owasp_category="A03:2021 – Injection",
                    url=test_url,
                    parameter=param_name,
                    method="GET",
                    poc=f"Payload: {payload}",
                    poc_code=self._generate_sqli_poc(test_url, param_name, payload, "error"),
                    remediation="Use parameterized queries/prepared statements. Implement input validation. Disable detailed error messages in production. Use ORM frameworks.",
                    references=[
                        "https://owasp.org/www-project-top-ten/2021/A03_2021-Injection",
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                        "https://portswigger.net/web-security/sql-injection"
                    ],
                    tags=["active", "sqli", "error_based", "injection"],
                    confirmed=True
                )
                
                vuln.evidence.append(Evidence(
                    type="response",
                    description=f"Database error detected: {db_type}",
                    data={"payload": payload, "error_type": db_type, "error_match": error_match}
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
            logger.debug(f"Error testing error-based SQLi on {url} param {param_name}: {e}")
        
        return None
    
    def _detect_db_error(self, body: str) -> tuple:
        """Detect database type and error from response body."""
        body_lower = body.lower()
        
        for db_type, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, body_lower, re.IGNORECASE):
                    return db_type, pattern
        
        return None, None
    
    async def _test_time_based_sqli(self, url: str, param_name: str) -> Optional[Vulnerability]:
        """Test for time-based blind SQL injection."""
        # Use time-based payloads
        time_payloads = [
            "'; WAITFOR DELAY '0:0:5'--",
            "'; SELECT pg_sleep(5)--",
            "' OR SLEEP(5)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "'; EXEC xp_cmdshell('ping -n 5 127.0.0.1')--",
        ]
        
        # First, get baseline response time
        baseline_times = []
        for _ in range(3):
            start = asyncio.get_event_loop().time()
            try:
                response = await self.client.get(url)
                await response.read()
            except Exception:
                pass
            baseline_times.append(asyncio.get_event_loop().time() - start)
        
        avg_baseline = sum(baseline_times) / len(baseline_times) if baseline_times else 0
        
        for payload in time_payloads:
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param_name] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()
                
                start = asyncio.get_event_loop().time()
                response = await self.client.get(test_url)
                await response.read()
                elapsed = asyncio.get_event_loop().time() - start
                
                # Check if response time significantly increased
                if elapsed > avg_baseline + self.time_threshold:
                    vuln = Vulnerability(
                        id=f"SQLI_TIME_{uuid.uuid4().hex[:8].upper()}",
                        title=f"Time-based Blind SQL Injection in parameter '{param_name}'",
                        description=f"Parameter '{param_name}' is vulnerable to time-based blind SQL injection. The application executes time-delay payloads.",
                        category=VulnerabilityCategory.INJECTION,
                        severity=Severity.HIGH,
                        cvss=CVSSScore(**SEVERITY_CVSS_MAP["high"]),
                        owasp_category="A03:2021 – Injection",
                        url=test_url,
                        parameter=param_name,
                        method="GET",
                        poc=f"Time-based payload caused {elapsed:.2f}s delay (baseline: {avg_baseline:.2f}s)",
                        poc_code=self._generate_sqli_poc(test_url, param_name, payload, "time"),
                        remediation="Use parameterized queries/prepared statements. Implement input validation. Limit database permissions. Use WAF rules for SQLi detection.",
                        references=[
                            "https://owasp.org/www-project-top-ten/2021/A03_2021-Injection",
                            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                            "https://portswigger.net/web-security/sql-injection/blind"
                        ],
                        tags=["active", "sqli", "time_based", "blind", "injection"],
                        confirmed=True
                    )
                    
                    vuln.evidence.append(Evidence(
                        type="timing",
                        description=f"Response time delay detected",
                        data={"baseline": avg_baseline, "injected": elapsed, "delay": elapsed - avg_baseline, "payload": payload}
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
                logger.debug(f"Error testing time-based SQLi: {e}")
        
        return None
    
    async def _test_boolean_based_sqli(self, url: str, param_name: str) -> Optional[Vulnerability]:
        """Test for boolean-based blind SQL injection."""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            original_value = params[param_name][0] if params.get(param_name) else ""
            
            # Get baseline response
            response = await self.client.get(url)
            wrapper = ResponseWrapper(response)
            baseline_body = await wrapper.text()
            baseline_length = len(baseline_body)
            
            # Test true condition (should return same/similar content)
            true_payload = f"{original_value}' OR '1'='1"
            params[param_name] = [true_payload]
            new_query = urlencode(params, doseq=True)
            true_url = parsed._replace(query=new_query).geturl()
            
            response = await self.client.get(true_url)
            wrapper = ResponseWrapper(response)
            true_body = await wrapper.text()
            true_length = len(true_body)
            
            # Test false condition (should return different content)
            false_payload = f"{original_value}' OR '1'='2"
            params[param_name] = [false_payload]
            new_query = urlencode(params, doseq=True)
            false_url = parsed._replace(query=new_query).geturl()
            
            response = await self.client.get(false_url)
            wrapper = ResponseWrapper(response)
            false_body = await wrapper.text()
            false_length = len(false_body)
            
            # Check if true condition returns similar to baseline and false returns different
            true_similar = abs(true_length - baseline_length) < baseline_length * 0.3
            false_different = abs(false_length - baseline_length) > baseline_length * 0.3
            
            if true_similar and false_different:
                vuln = Vulnerability(
                    id=f"SQLI_BOOLEAN_{uuid.uuid4().hex[:8].upper()}",
                    title=f"Boolean-based Blind SQL Injection in parameter '{param_name}'",
                    description=f"Parameter '{param_name}' is vulnerable to boolean-based blind SQL injection. The application returns different content based on boolean conditions.",
                    category=VulnerabilityCategory.INJECTION,
                    severity=Severity.HIGH,
                    cvss=CVSSScore(**SEVERITY_CVSS_MAP["high"]),
                    owasp_category="A03:2021 – Injection",
                    url=url,
                    parameter=param_name,
                    method="GET",
                    poc=f"True condition: {true_payload} | False condition: {false_payload}",
                    poc_code=self._generate_sqli_poc(url, param_name, true_payload, "boolean"),
                    remediation="Use parameterized queries/prepared statements. Implement input validation. Limit database permissions.",
                    references=[
                        "https://owasp.org/www-project-top-ten/2021/A03_2021-Injection",
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                        "https://portswigger.net/web-security/sql-injection/blind"
                    ],
                    tags=["active", "sqli", "boolean_based", "blind", "injection"],
                    confirmed=True
                )
                
                vuln.evidence.append(Evidence(
                    type="comparison",
                    description="Boolean-based injection confirmed via response length differences",
                    data={
                        "baseline_length": baseline_length,
                        "true_length": true_length,
                        "false_length": false_length,
                        "true_similar": true_similar,
                        "false_different": false_different
                    }
                ))
                vuln.request = HTTPRequest(method="GET", url=true_url)
                vuln.response = HTTPResponse(
                    status_code=200,
                    headers={},
                    body=f"True: {true_body[:500]}\n\nFalse: {false_body[:500]}",
                    url=true_url
                )
                
                self.scan_result.add_vulnerability(vuln)
                return vuln
                
        except Exception as e:
            logger.debug(f"Error testing boolean-based SQLi: {e}")
        
        return None
    
    def _generate_sqli_poc(self, url: str, param: str, payload: str, sqli_type: str) -> str:
        """Generate proof of concept code for SQL injection."""
        return f"""#!/usr/bin/env python3
\"\"\"
Proof of Concept for {sqli_type.capitalize()}-based SQL Injection
Target: {url}
Parameter: {param}
Type: {sqli_type}
\"\"\"

import requests
import time

# Target URL
base_url = "{url.split('?')[0]}"
param_name = "{param}"

# {sqli_type.capitalize()}-based payload
payload = "{payload.replace('\"', '\\\\\"')}"

# Build test URL
from urllib.parse import urlencode
params = {{param_name: payload}}
test_url = f"{{base_url}}?{{urlencode(params)}}"

print(f"[+] Testing {sqli_type}-based SQLi on {{test_url}}")

if "{sqli_type}" == "time":
    # Time-based test
    start = time.time()
    response = requests.get(test_url, timeout=30)
    elapsed = time.time() - start
    print(f"[+] Response time: {{elapsed:.2f}}s")
    if elapsed > 4:
        print("[+] SQL Injection Confirmed! Time delay detected.")
    else:
        print("[-] No significant time delay.")
        
elif "{sqli_type}" == "error":
    # Error-based test
    response = requests.get(test_url)
    # Check for database errors
    error_patterns = [
        "mysql", "postgresql", "sqlserver", "oracle", "sqlite",
        "syntax error", "unknown column", "invalid"
    ]
    for pattern in error_patterns:
        if pattern in response.text.lower():
            print(f"[+] SQL Injection Confirmed! Database error detected: {{pattern}}")
            break
    else:
        print("[-] No database errors detected in response.")
        
elif "{sqli_type}" == "boolean":
    # Boolean-based test would require comparing responses
    print("[+] Boolean-based test: compare response with true/false conditions")
    print(f"[+] True condition: {{base_url}}?{param_name}={payload}")
    false_payload = payload.replace("1'='1", "1'='2")
    print(f"[+] False condition: {{base_url}}?{param_name}={false_payload}")

print(f"\\n[+] Manual test: {{test_url}}")
"""