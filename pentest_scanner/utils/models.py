"""
Data models for vulnerability scanning results.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Any
from enum import Enum
from pathlib import Path
import json


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityCategory(Enum):
    """Vulnerability categories based on OWASP and common classifications."""
    # OWASP Top 10 2021
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    CRYPTOGRAPHIC_FAILURES = "cryptographic_failures"
    INJECTION = "injection"
    INSECURE_DESIGN = "insecure_design"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    VULNERABLE_COMPONENTS = "vulnerable_components"
    AUTH_FAILURES = "auth_failures"
    INTEGRITY_FAILURES = "integrity_failures"
    LOGGING_FAILURES = "logging_failures"
    SSRF = "ssrf"
    
    # Additional categories
    XSS = "xss"
    SQLI = "sqli"
    OPEN_REDIRECT = "open_redirect"
    IDOR = "idor"
    XXE = "xxe"
    SSTI = "ssti"
    FILE_UPLOAD = "file_upload"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    MISSING_SECURITY_HEADERS = "missing_security_headers"
    COOKIE_SECURITY = "cookie_security"
    SSL_TLS = "ssl_tls"
    INFORMATION_DISCLOSURE = "information_disclosure"
    BROKEN_AUTHENTICATION = "broken_authentication"
    SESSION_MANAGEMENT = "session_management"
    CSRF = "csrf"
    CLICKJACKING = "clickjacking"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    DNS_MISCONFIGURATION = "dns_misconfiguration"


class ScanStatus(Enum):
    """Status of a scan or check."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class CVSSScore:
    """CVSS v3.1 score details."""
    base_score: float = 0.0
    vector: str = ""
    severity: Severity = Severity.INFO
    
    def to_dict(self) -> Dict:
        return {
            "base_score": self.base_score,
            "vector": self.vector,
            "severity": self.severity.value
        }


@dataclass
class Evidence:
    """Evidence for a vulnerability finding."""
    type: str  # "request", "response", "screenshot", "console_log", "poc"
    description: str
    data: Any
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            "type": self.type,
            "description": self.description,
            "data": self.data,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class HTTPRequest:
    """HTTP request representation."""
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    params: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body": self.body,
            "params": self.params
        }


@dataclass
class HTTPResponse:
    """HTTP response representation."""
    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    url: str = ""
    response_time: float = 0.0
    
    def to_dict(self) -> Dict:
        return {
            "status_code": self.status_code,
            "headers": self.headers,
            "body": self.body[:5000] if self.body else "",  # Truncate for storage
            "url": self.url,
            "response_time": self.response_time
        }


@dataclass
class Vulnerability:
    """A single vulnerability finding."""
    id: str
    title: str
    description: str
    category: VulnerabilityCategory
    severity: Severity
    cvss: CVSSScore
    owasp_category: Optional[str] = None
    
    # Location
    url: str = ""
    parameter: str = ""
    method: str = "GET"
    
    # Evidence
    evidence: List[Evidence] = field(default_factory=list)
    request: Optional[HTTPRequest] = None
    response: Optional[HTTPResponse] = None
    
    # Proof of concept
    poc: Optional[str] = None
    poc_code: Optional[str] = None
    
    # Remediation
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    
    # Metadata
    discovered_at: datetime = field(default_factory=datetime.now)
    confirmed: bool = False
    false_positive: bool = False
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "category": self.category.value,
            "severity": self.severity.value,
            "cvss": self.cvss.to_dict(),
            "owasp_category": self.owasp_category,
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "evidence": [e.to_dict() for e in self.evidence],
            "request": self.request.to_dict() if self.request else None,
            "response": self.response.to_dict() if self.response else None,
            "poc": self.poc,
            "poc_code": self.poc_code,
            "remediation": self.remediation,
            "references": self.references,
            "discovered_at": self.discovered_at.isoformat(),
            "confirmed": self.confirmed,
            "false_positive": self.false_positive,
            "tags": self.tags
        }
    
    def to_markdown(self) -> str:
        """Generate markdown representation for reports."""
        md = f"## {self.id}: {self.title}\n\n"
        md += f"**Severity:** {self.severity.value.upper()} | **CVSS:** {self.cvss.base_score} ({self.cvss.vector})\n"
        md += f"**Category:** {self.category.value}\n"
        if self.owasp_category:
            md += f"**OWASP Category:** {self.owasp_category}\n"
        md += f"**URL:** {self.url}\n"
        if self.parameter:
            md += f"**Parameter:** {self.parameter}\n"
        md += f"**Method:** {self.method}\n\n"
        
        md += f"### Description\n{self.description}\n\n"
        
        if self.poc:
            md += f"### Proof of Concept\n```\n{self.poc}\n```\n\n"
        
        if self.poc_code:
            md += f"### PoC Code\n```python\n{self.poc_code}\n```\n\n"
        
        if self.evidence:
            md += "### Evidence\n"
            for i, ev in enumerate(self.evidence, 1):
                md += f"**{i}. {ev.type}** - {ev.description}\n"
                if isinstance(ev.data, dict):
                    md += f"```json\n{json.dumps(ev.data, indent=2)}\n```\n"
                else:
                    md += f"```\n{ev.data}\n```\n"
                md += "\n"
        
        if self.request:
            md += "### Request\n"
            md += f"```\n{self.request.method} {self.request.url}\n"
            for k, v in self.request.headers.items():
                md += f"{k}: {v}\n"
            if self.request.body:
                md += f"\n{self.request.body}\n"
            md += "```\n\n"
        
        if self.response:
            md += "### Response\n"
            md += f"```\nHTTP/1.1 {self.response.status_code}\n"
            for k, v in self.response.headers.items():
                md += f"{k}: {v}\n"
            md += f"\n{self.response.body[:2000]}\n"
            md += "```\n\n"
        
        if self.remediation:
            md += f"### Remediation\n{self.remediation}\n\n"
        
        if self.references:
            md += "### References\n"
            for ref in self.references:
                md += f"- {ref}\n"
            md += "\n"
        
        md += "---\n\n"
        return md


@dataclass
class ScanResult:
    """Complete scan result."""
    target_url: str
    target_domain: str
    scan_id: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: ScanStatus = ScanStatus.PENDING
    
    # Configuration used
    scan_depth: int = 3
    modules_run: List[str] = field(default_factory=list)
    
    # Findings
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    
    # Statistics
    stats: Dict[str, int] = field(default_factory=lambda: {
        "total": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    })
    
    # Coverage
    urls_crawled: List[str] = field(default_factory=list)
    endpoints_tested: List[str] = field(default_factory=list)
    parameters_tested: List[str] = field(default_factory=list)
    
    # Errors
    errors: List[str] = field(default_factory=list)
    
    def add_vulnerability(self, vuln: Vulnerability):
        """Add a vulnerability and update statistics."""
        self.vulnerabilities.append(vuln)
        self.stats["total"] += 1
        self.stats[vuln.severity.value] += 1
    
    def get_vulns_by_severity(self, severity: Severity) -> List[Vulnerability]:
        """Get vulnerabilities filtered by severity."""
        return [v for v in self.vulnerabilities if v.severity == severity]
    
    def get_vulns_by_category(self, category: VulnerabilityCategory) -> List[Vulnerability]:
        """Get vulnerabilities filtered by category."""
        return [v for v in self.vulnerabilities if v.category == category]
    
    def complete(self):
        """Mark scan as completed."""
        self.completed_at = datetime.now()
        self.status = ScanStatus.COMPLETED
    
    def fail(self, error: str):
        """Mark scan as failed."""
        self.completed_at = datetime.now()
        self.status = ScanStatus.FAILED
        self.errors.append(error)
    
    def to_dict(self) -> Dict:
        return {
            "target_url": self.target_url,
            "target_domain": self.target_domain,
            "scan_id": self.scan_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "status": self.status.value,
            "scan_depth": self.scan_depth,
            "modules_run": self.modules_run,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "stats": self.stats,
            "urls_crawled": self.urls_crawled,
            "endpoints_tested": self.endpoints_tested,
            "parameters_tested": self.parameters_tested,
            "errors": self.errors
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Export as JSON string."""
        return json.dumps(self.to_dict(), indent=indent)
    
    def save_json(self, path: Path):
        """Save results to JSON file."""
        path.write_text(self.to_json())


@dataclass
class Endpoint:
    """Discovered endpoint."""
    url: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    status_code: int = 0
    content_type: str = ""
    response_length: int = 0
    discovered_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "method": self.method,
            "parameters": self.parameters,
            "forms": self.forms,
            "technologies": self.technologies,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "response_length": self.response_length,
            "discovered_at": self.discovered_at.isoformat()
        }


@dataclass
class Technology:
    """Detected technology."""
    name: str
    version: Optional[str] = None
    category: str = ""  # "cms", "framework", "server", "language", "database", "cdn", "waf"
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "version": self.version,
            "category": self.category,
            "confidence": self.confidence,
            "evidence": self.evidence
        }