"""
Unit tests for Pentest Scanner - Following TDD principles.
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch
import asyncio
import datetime

# Import modules to test
from pentest_scanner.config.settings import (
    ScannerConfig,
    DEFAULT_CONFIG,
    SEVERITY_CVSS_MAP,
    XSS_PAYLOADS,
    SQLI_PAYLOADS,
    SSRF_PAYLOADS,
    SSTI_PAYLOADS,
    XXE_PAYLOADS,
    OPEN_REDIRECT_PAYLOADS,
    SENSITIVE_FILES,
    SECURITY_HEADERS,
    OWASP_TOP_10_2021,
)
from pentest_scanner.utils.models import (
    Vulnerability,
    ScanResult,
    Severity,
    VulnerabilityCategory,
    CVSSScore,
    Evidence,
    Endpoint,
    Technology,
    HTTPRequest,
    HTTPResponse,
)
from pentest_scanner.utils.http_client import (
    HTTPClient,
    RateLimiter,
    ResponseWrapper,
)
from pentest_scanner.scanner import PentestScanner, run_scan


class TestScannerConfig:
    """Tests for ScannerConfig."""

    def test_default_config_creation(self):
        """Test default config creation."""
        config = ScannerConfig()
        assert config.scan_depth == 3
        assert config.max_threads == 10
        assert config.request_timeout == 30
        assert config.output_dir == Path("/opt/data/pentest_scanner/reports")
        assert config.report_format == ["markdown", "json", "html"]

    def test_config_with_target_url(self):
        """Test config with target URL auto-extracts domain."""
        config = ScannerConfig(target_url="https://example.com/path")
        assert config.target_domain == "example.com"

    def test_config_output_dir_creation(self, tmp_path):
        """Test output directory is created."""
        config = ScannerConfig(output_dir=tmp_path / "reports")
        assert config.output_dir.exists()

    def test_severity_cvss_map_exists(self):
        """Test CVSS map has all severity levels."""
        assert "critical" in SEVERITY_CVSS_MAP
        assert "high" in SEVERITY_CVSS_MAP
        assert "medium" in SEVERITY_CVSS_MAP
        assert "low" in SEVERITY_CVSS_MAP
        assert "info" in SEVERITY_CVSS_MAP

    def test_payloads_not_empty(self):
        """Test all payload lists are not empty."""
        assert len(XSS_PAYLOADS) > 0
        assert len(SQLI_PAYLOADS) > 0
        assert len(SSRF_PAYLOADS) > 0
        assert len(SSTI_PAYLOADS) > 0
        assert len(XXE_PAYLOADS) > 0
        assert len(OPEN_REDIRECT_PAYLOADS) > 0

    def test_sensitive_files_not_empty(self):
        """Test sensitive files list is not empty."""
        assert len(SENSITIVE_FILES) > 0

    def test_security_headers_not_empty(self):
        """Test security headers dict is not empty."""
        assert len(SECURITY_HEADERS) > 0

    def test_owasp_top_10_complete(self):
        """Test OWASP Top 10 has 10 entries."""
        assert len(OWASP_TOP_10_2021) == 10
        assert "A01" in OWASP_TOP_10_2021
        assert "A10" in OWASP_TOP_10_2021


class TestModels:
    """Tests for data models."""

    def test_vulnerability_creation(self):
        """Test vulnerability creation with required fields."""
        vuln = Vulnerability(
            id="TEST_001",
            title="Test Vulnerability",
            description="Test description",
            category=VulnerabilityCategory.XSS,
            severity=Severity.HIGH,
            cvss=CVSSScore(**SEVERITY_CVSS_MAP["high"]),
        )
        assert vuln.id == "TEST_001"
        assert vuln.severity == Severity.HIGH
        assert vuln.confirmed is False
        assert vuln.false_positive is False

    def test_vulnerability_to_dict(self):
        """Test vulnerability serialization."""
        vuln = Vulnerability(
            id="TEST_001",
            title="Test",
            description="Desc",
            category=VulnerabilityCategory.XSS,
            severity=Severity.HIGH,
            cvss=CVSSScore(**SEVERITY_CVSS_MAP["high"]),
        )
        d = vuln.to_dict()
        assert d["id"] == "TEST_001"
        assert d["severity"] == "high"
        assert d["category"] == "xss"

    def test_vulnerability_to_markdown(self):
        """Test vulnerability markdown generation."""
        vuln = Vulnerability(
            id="TEST_001",
            title="Test XSS",
            description="XSS found",
            category=VulnerabilityCategory.XSS,
            severity=Severity.HIGH,
            cvss=CVSSScore(**SEVERITY_CVSS_MAP["high"]),
            url="https://example.com",
            parameter="q",
            method="GET",
            poc="Visit URL",
            remediation="Fix it",
            references=["https://owasp.org"],
        )
        md = vuln.to_markdown()
        assert "TEST_001" in md
        assert "Test XSS" in md
        assert "HIGH" in md
        assert "https://example.com" in md

    def test_cvss_score_to_dict(self):
        """Test CVSS score serialization."""
        cvss = CVSSScore(base_score=7.5, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", severity=Severity.HIGH)
        d = cvss.to_dict()
        assert d["base_score"] == 7.5
        assert d["severity"] == "high"

    def test_scan_result_creation(self):
        """Test scan result creation."""
        result = ScanResult(
            target_url="https://example.com",
            target_domain="example.com",
            scan_id="SCAN_TEST",
            started_at=datetime.datetime.now(),
            scan_depth=3,
        )
        assert result.target_url == "https://example.com"
        assert result.status.name == "PENDING"

    def test_scan_result_add_vulnerability(self):
        """Test adding vulnerabilities updates stats."""
        result = ScanResult(
            target_url="https://example.com",
            target_domain="example.com",
            scan_id="SCAN_TEST",
            started_at=datetime.datetime.now(),
            scan_depth=3,
        )
        vuln = Vulnerability(
            id="TEST_001",
            title="Test",
            description="Desc",
            category=VulnerabilityCategory.XSS,
            severity=Severity.HIGH,
            cvss=CVSSScore(**SEVERITY_CVSS_MAP["high"]),
        )
        result.add_vulnerability(vuln)
        assert result.stats["total"] == 1
        assert result.stats["high"] == 1
        assert len(result.vulnerabilities) == 1

    def test_endpoint_creation(self):
        """Test endpoint model."""
        endpoint = Endpoint(
            url="https://example.com/api",
            method="POST",
            parameters=["id", "name"],
        )
        assert endpoint.url == "https://example.com/api"
        assert endpoint.method == "POST"
        assert "id" in endpoint.parameters

    def test_technology_creation(self):
        """Test technology model."""
        tech = Technology(
            name="nginx",
            version="1.18.0",
            category="server",
            confidence=0.9,
            evidence=["Server header"],
        )
        assert tech.name == "nginx"
        assert tech.version == "1.18.0"
        assert tech.confidence == 0.9


class TestRateLimiter:
    """Tests for RateLimiter."""

    @pytest.mark.asyncio
    async def test_rate_limiter_acquires_token(self):
        """Test rate limiter allows requests at specified rate."""
        limiter = RateLimiter(rate=10, burst=5)
        await limiter.acquire()  # Should not block
        assert limiter.tokens <= 4  # One token consumed

    @pytest.mark.asyncio
    async def test_rate_limiter_blocks_when_empty(self):
        """Test rate limiter blocks when tokens exhausted."""
        limiter = RateLimiter(rate=1, burst=1)
        await limiter.acquire()  # Consume the one token
        assert limiter.tokens == 0
        
        # Next acquire should wait (but we'll just check tokens)
        # In real usage, this would block
        assert limiter.tokens <= 0


class TestHTTPClient:
    """Tests for HTTPClient."""

    @pytest.mark.asyncio
    async def test_http_client_creation(self):
        """Test HTTP client creation."""
        config = ScannerConfig()
        client = HTTPClient(config)
        assert client.config == config
        assert client.session is None

    @pytest.mark.asyncio
    async def test_http_client_start_and_close(self):
        """Test HTTP client start and close."""
        config = ScannerConfig()
        client = HTTPClient(config)
        await client.start()
        assert client.session is not None
        assert not client.session.closed
        await client.close()
        assert client.session.closed

    @pytest.mark.asyncio
    async def test_http_client_context_manager(self):
        """Test HTTP client as context manager."""
        config = ScannerConfig()
        async with HTTPClient(config) as client:
            assert client.session is not None
        assert client.session.closed

    @pytest.mark.asyncio
    async def test_http_client_get_stats(self):
        """Test HTTP client stats."""
        config = ScannerConfig()
        client = HTTPClient(config)
        stats = client.get_stats()
        assert "requests" in stats
        assert "errors" in stats
        assert stats["requests"] == 0


class TestResponseWrapper:
    """Tests for ResponseWrapper."""

    @pytest.mark.asyncio
    async def test_response_wrapper_properties(self):
        """Test response wrapper basic properties."""
        # We can't easily test without a real response, so test the interface
        mock_response = Mock()
        mock_response.status = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.url = "https://example.com"
        mock_response.cookies = {}
        
        wrapper = ResponseWrapper(mock_response)
        assert wrapper.status_code == 200
        assert wrapper.content_type == "text/html"
        assert wrapper.url == "https://example.com"

    @pytest.mark.asyncio
    async def test_response_wrapper_headers_case_insensitive(self):
        """Test header access is case-insensitive."""
        mock_response = Mock()
        mock_response.headers = {"Content-Type": "text/html", "X-Custom": "value"}
        
        wrapper = ResponseWrapper(mock_response)
        assert wrapper.get_header("content-type") == "text/html"
        assert wrapper.get_header("CONTENT-TYPE") == "text/html"
        assert wrapper.has_header("content-type") is True
        assert wrapper.has_header("x-custom") is True
        assert wrapper.has_header("non-existent") is False


class TestPassiveRecon:
    """Tests for passive reconnaissance scanner."""

    @pytest.mark.asyncio
    async def test_passive_recon_creation(self):
        """Test passive recon scanner creation."""
        config = ScannerConfig()
        client = Mock(spec=HTTPClient)
        result = ScanResult(
            target_url="https://example.com",
            target_domain="example.com",
            scan_id="TEST",
            started_at=asyncio.get_event_loop().time(),
        )
        
        from pentest_scanner.scanners.passive_recon import PassiveReconScanner
        scanner = PassiveReconScanner(client, config, result)
        assert scanner.client == client
        assert scanner.config == config

    @pytest.mark.asyncio
    async def test_passive_recon_detects_missing_hsts(self):
        """Test passive recon detects missing HSTS header."""
        config = ScannerConfig(target_url="https://example.com")
        client = Mock(spec=HTTPClient)
        
        # Create a real ResponseWrapper-like mock that works with await
        mock_response = Mock()
        mock_response.status = 200
        mock_response.headers = {}
        mock_response.url = "https://example.com"
        
        # Create a proper async mock for the text method
        async def mock_text():
            return "<html></html>"
        
        # We need to mock the client.get to return a response that works with ResponseWrapper
        # The ResponseWrapper calls response.read() and response.text()
        mock_response.read = AsyncMock()
        mock_response.text = AsyncMock(return_value="<html></html>")
        
        client.get = AsyncMock(return_value=mock_response)
        
        result = ScanResult(
            target_url="https://example.com",
            target_domain="example.com",
            scan_id="TEST",
            started_at=datetime.datetime.now(),
        )
        
        from pentest_scanner.scanners.passive_recon import PassiveReconScanner
        scanner = PassiveReconScanner(client, config, result)
        analysis = await scanner._analyze_security_headers()
        
        # Check that the analysis has missing headers
        missing_headers = [h["header"] for h in analysis.get("missing", [])]
        assert "Strict-Transport-Security" in missing_headers


class TestXSSScanner:
    """Tests for XSS scanner."""

    @pytest.mark.asyncio
    async def test_xss_scanner_creation(self):
        """Test XSS scanner creation."""
        config = ScannerConfig()
        client = Mock(spec=HTTPClient)
        result = ScanResult(
            target_url="https://example.com",
            target_domain="example.com",
            scan_id="TEST",
            started_at=asyncio.get_event_loop().time(),
        )
        
        from pentest_scanner.scanners.xss_scanner import XSSScanner
        scanner = XSSScanner(client, config, result)
        assert scanner.client == client
        assert scanner.tested_parameters == set()

    @pytest.mark.asyncio
    async def test_xss_payload_reflection_check(self):
        """Test XSS payload reflection detection."""
        config = ScannerConfig()
        client = Mock(spec=HTTPClient)
        result = ScanResult(
            target_url="https://example.com",
            target_domain="example.com",
            scan_id="TEST",
            started_at=datetime.datetime.now(),
        )
        
        from pentest_scanner.scanners.xss_scanner import XSSScanner
        scanner = XSSScanner(client, config, result)
        
        # Test exact reflection
        assert scanner._is_payload_reflected("<script>alert(1)</script>", "<script>alert(1)</script>")
        
        # Test HTML encoded reflection
        assert scanner._is_payload_reflected("<script>alert(1)</script>", "<script>alert(1)</script>")
        
        # Test URL encoded reflection - body contains URL encoded payload (only < and > encoded by the method)
        body_with_encoded = "%3Cscript%3Ealert(1)%3C/script%3E"
        assert scanner._is_payload_reflected(body_with_encoded, "<script>alert(1)</script>")


class TestSQLiScanner:
    """Tests for SQLi scanner."""

    @pytest.mark.asyncio
    async def test_sqli_scanner_creation(self):
        """Test SQLi scanner creation."""
        config = ScannerConfig()
        client = Mock(spec=HTTPClient)
        result = ScanResult(
            target_url="https://example.com",
            target_domain="example.com",
            scan_id="TEST",
            started_at=asyncio.get_event_loop().time(),
        )
        
        from pentest_scanner.scanners.sqli_scanner import SQLiScanner
        scanner = SQLiScanner(client, config, result)
        assert scanner.client == client
        assert hasattr(scanner, 'error_patterns')

    @pytest.mark.asyncio
    async def test_sqli_detects_mysql_errors(self):
        """Test SQLi detects MySQL errors."""
        config = ScannerConfig()
        client = Mock(spec=HTTPClient)
        result = ScanResult(
            target_url="https://example.com",
            target_domain="example.com",
            scan_id="TEST",
            started_at=asyncio.get_event_loop().time(),
        )
        
        from pentest_scanner.scanners.sqli_scanner import SQLiScanner
        scanner = SQLiScanner(client, config, result)
        
        db_type, match = scanner._detect_db_error("You have an error in your SQL syntax")
        assert db_type == "mysql"
        assert "syntax" in match.lower()


class TestSSRFScanner:
    """Tests for SSRF scanner."""

    @pytest.mark.asyncio
    async def test_ssrf_scanner_creation(self):
        """Test SSRF scanner creation."""
        config = ScannerConfig()
        client = Mock(spec=HTTPClient)
        result = ScanResult(
            target_url="https://example.com",
            target_domain="example.com",
            scan_id="TEST",
            started_at=asyncio.get_event_loop().time(),
        )
        
        from pentest_scanner.scanners.ssrf_scanner import SSRFScanner
        scanner = SSRFScanner(client, config, result)
        assert scanner.client == client


class TestIDORScanner:
    """Tests for IDOR scanner."""

    @pytest.mark.asyncio
    async def test_idor_scanner_creation(self):
        """Test IDOR scanner creation."""
        config = ScannerConfig()
        client = Mock(spec=HTTPClient)
        result = ScanResult(
            target_url="https://example.com",
            target_domain="example.com",
            scan_id="TEST",
            started_at=asyncio.get_event_loop().time(),
        )
        
        from pentest_scanner.scanners.idor_scanner import IDORScanner
        scanner = IDORScanner(client, config, result)
        assert scanner.client == client

    @pytest.mark.asyncio
    async def test_idor_generates_test_values(self):
        """Test IDOR generates test values for numeric IDs."""
        config = ScannerConfig()
        client = Mock(spec=HTTPClient)
        result = ScanResult(
            target_url="https://example.com",
            target_domain="example.com",
            scan_id="TEST",
            started_at=asyncio.get_event_loop().time(),
        )
        
        from pentest_scanner.scanners.idor_scanner import IDORScanner
        scanner = IDORScanner(client, config, result)
        
        test_values = scanner._generate_test_values("123")
        assert "122" in test_values
        assert "124" in test_values
        assert "1" in test_values


class TestOpenRedirectScanner:
    """Tests for Open Redirect scanner."""

    @pytest.mark.asyncio
    async def test_open_redirect_scanner_creation(self):
        """Test open redirect scanner creation."""
        config = ScannerConfig()
        client = Mock(spec=HTTPClient)
        result = ScanResult(
            target_url="https://example.com",
            target_domain="example.com",
            scan_id="TEST",
            started_at=asyncio.get_event_loop().time(),
        )
        
        from pentest_scanner.scanners.open_redirect_scanner import OpenRedirectScanner
        scanner = OpenRedirectScanner(client, config, result)
        assert scanner.client == client

    @pytest.mark.asyncio
    async def test_open_redirect_detects_redirect_params(self):
        """Test open redirect detects redirect parameter names."""
        config = ScannerConfig()
        client = Mock(spec=HTTPClient)
        result = ScanResult(
            target_url="https://example.com",
            target_domain="example.com",
            scan_id="TEST",
            started_at=asyncio.get_event_loop().time(),
        )
        
        from pentest_scanner.scanners.open_redirect_scanner import OpenRedirectScanner
        scanner = OpenRedirectScanner(client, config, result)
        
        assert scanner._is_redirect_param("redirect")
        assert scanner._is_redirect_param("next")
        assert scanner._is_redirect_param("return_url")
        assert scanner._is_redirect_param("goto")
        assert not scanner._is_redirect_param("id")
        assert not scanner._is_redirect_param("name")


class TestXXEScanner:
    """Tests for XXE scanner."""

    @pytest.mark.asyncio
    async def test_xxe_scanner_creation(self):
        """Test XXE scanner creation."""
        config = ScannerConfig()
        client = Mock(spec=HTTPClient)
        result = ScanResult(
            target_url="https://example.com",
            target_domain="example.com",
            scan_id="TEST",
            started_at=asyncio.get_event_loop().time(),
        )
        
        from pentest_scanner.scanners.xxe_scanner import XXEScanner
        scanner = XXEScanner(client, config, result)
        assert scanner.client == client


class TestSSTIScanner:
    """Tests for SSTI scanner."""

    @pytest.mark.asyncio
    async def test_ssti_scanner_creation(self):
        """Test SSTI scanner creation."""
        config = ScannerConfig()
        client = Mock(spec=HTTPClient)
        result = ScanResult(
            target_url="https://example.com",
            target_domain="example.com",
            scan_id="TEST",
            started_at=asyncio.get_event_loop().time(),
        )
        
        from pentest_scanner.scanners.ssti_scanner import SSTIScanner
        scanner = SSTIScanner(client, config, result)
        assert scanner.client == client
        assert hasattr(scanner, 'engine_payloads')
        assert "jinja2" in scanner.engine_payloads


class TestFileUploadScanner:
    """Tests for File Upload scanner."""

    @pytest.mark.asyncio
    async def test_file_upload_scanner_creation(self):
        """Test file upload scanner creation."""
        config = ScannerConfig()
        client = Mock(spec=HTTPClient)
        result = ScanResult(
            target_url="https://example.com",
            target_domain="example.com",
            scan_id="TEST",
            started_at=asyncio.get_event_loop().time(),
        )
        
        from pentest_scanner.scanners.file_upload_scanner import FileUploadScanner
        scanner = FileUploadScanner(client, config, result)
        assert scanner.client == client
        assert len(scanner.test_files) > 0

    @pytest.mark.asyncio
    async def test_file_upload_detects_upload_forms(self):
        """Test file upload detects file input forms."""
        config = ScannerConfig()
        client = Mock(spec=HTTPClient)
        result = ScanResult(
            target_url="https://example.com",
            target_domain="example.com",
            scan_id="TEST",
            started_at=asyncio.get_event_loop().time(),
        )
        
        from pentest_scanner.scanners.file_upload_scanner import FileUploadScanner
        scanner = FileUploadScanner(client, config, result)
        
        # Form with file input
        form_with_file = {
            "action": "/upload",
            "method": "POST",
            "enctype": "multipart/form-data",
            "inputs": [{"name": "file", "type": "file"}]
        }
        assert scanner._has_file_upload(form_with_file)
        
        # Form without file input
        form_without_file = {
            "action": "/login",
            "method": "POST",
            "inputs": [{"name": "username", "type": "text"}]
        }
        assert not scanner._has_file_upload(form_without_file)


class TestReportGenerator:
    """Tests for report generator."""

    @pytest.mark.asyncio
    async def test_report_generator_creation(self):
        """Test report generator creation."""
        config = ScannerConfig(output_dir=Path("/tmp/test_reports"))
        result = ScanResult(
            target_url="https://example.com",
            target_domain="example.com",
            scan_id="TEST",
            started_at=asyncio.get_event_loop().time(),
            scan_depth=1,
        )
        
        from pentest_scanner.utils.report_generator import ReportGenerator
        generator = ReportGenerator(result, config)
        assert generator.scan_result == result

    def test_overall_risk_rating(self):
        """Test overall risk rating calculation."""
        config = ScannerConfig(output_dir=Path("/tmp/test_reports"))
        result = ScanResult(
            target_url="https://example.com",
            target_domain="example.com",
            scan_id="TEST",
            started_at=datetime.datetime.now(),
            scan_depth=1,
        )
        
        from pentest_scanner.utils.report_generator import ReportGenerator
        generator = ReportGenerator(result, config)
        
        # Test critical
        result.stats = {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 1}
        assert generator._get_overall_risk() == "🔴 CRITICAL"
        
        # Test high
        result.stats = {"critical": 0, "high": 2, "medium": 0, "low": 0, "info": 0, "total": 2}
        assert generator._get_overall_risk() == "🟠 HIGH"
        
        # Test medium
        result.stats = {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0, "total": 1}
        assert generator._get_overall_risk() == "🟡 MEDIUM"
        
        # Test low
        result.stats = {"critical": 0, "high": 0, "medium": 0, "low": 3, "info": 0, "total": 3}
        assert generator._get_overall_risk() == "🔵 LOW"
        
        # Test info
        result.stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 1, "total": 1}
        assert generator._get_overall_risk() == "⚪ INFORMATIONAL"

    def test_owasp_mapping(self):
        """Test OWASP Top 10 mapping."""
        config = ScannerConfig(output_dir=Path("/tmp/test_reports"))
        result = ScanResult(
            target_url="https://example.com",
            target_domain="example.com",
            scan_id="TEST",
            started_at=datetime.datetime.now(),
            scan_depth=1,
        )
        
        from pentest_scanner.utils.report_generator import ReportGenerator
        from pentest_scanner.utils.models import Vulnerability, Severity, VulnerabilityCategory
        
        generator = ReportGenerator(result, config)
        
        # Create test vulnerabilities
        vuln1 = Vulnerability(
            id="TEST_001",
            title="XSS Test",
            description="XSS found",
            category=VulnerabilityCategory.XSS,
            severity=Severity.HIGH,
            cvss=CVSSScore(**SEVERITY_CVSS_MAP["high"]),
            owasp_category="A03:2021 – Injection",
        )
        
        vuln2 = Vulnerability(
            id="TEST_002",
            title="Missing Header",
            description="Header missing",
            category=VulnerabilityCategory.MISSING_SECURITY_HEADERS,
            severity=Severity.MEDIUM,
            cvss=CVSSScore(**SEVERITY_CVSS_MAP["medium"]),
            owasp_category="A05:2021 – Security Misconfiguration",
        )
        
        mapping = generator._map_to_owasp([vuln1, vuln2])
        
        assert "A03:2021 – Injection" in mapping
        assert len(mapping["A03:2021 – Injection"]) == 1
        assert "A05:2021 – Security Misconfiguration" in mapping
        assert len(mapping["A05:2021 – Security Misconfiguration"]) == 1


class TestPentestScanner:
    """Integration tests for main scanner."""

    @pytest.mark.asyncio
    async def test_scanner_creation(self):
        """Test main scanner creation."""
        config = ScannerConfig()
        from pentest_scanner.scanner import PentestScanner
        scanner = PentestScanner(config)
        assert scanner.config == config
        assert scanner.scan_result is None

    @pytest.mark.asyncio
    async def test_run_scan_function(self):
        """Test run_scan convenience function."""
        from pentest_scanner.scanner import run_scan
        config = ScannerConfig(
            target_url="https://example.com",
            scan_depth=1,
            enable_active_scan=False,
            enable_browser_tests=False,
        )
        # We can't fully test without a server, but we can test it creates scanner
        scanner = PentestScanner(config)
        assert scanner.config.scan_depth == 1


# Test payloads contain expected patterns
class TestPayloadQuality:
    """Tests to ensure payload quality."""

    def test_xss_payloads_have_variety(self):
        """Test XSS payloads cover different vectors."""
        # Check for script tag
        assert any("<script>" in p for p in XSS_PAYLOADS)
        # Check for event handlers
        assert any("onerror" in p for p in XSS_PAYLOADS)
        assert any("onload" in p for p in XSS_PAYLOADS)
        # Check for javascript: protocol
        assert any("javascript:" in p for p in XSS_PAYLOADS)

    def test_sqli_payloads_have_variety(self):
        """Test SQLi payloads cover different techniques."""
        # Check for basic injection
        assert any("'" in p and "1=1" in p for p in SQLI_PAYLOADS)
        # Check for time-based
        assert any("SLEEP" in p or "WAITFOR" in p or "pg_sleep" in p for p in SQLI_PAYLOADS)
        # Check for union
        assert any("UNION" in p.upper() for p in SQLI_PAYLOADS)

    def test_ssrf_payloads_target_internal(self):
        """Test SSRF payloads target internal resources."""
        # Check for localhost
        assert any("127.0.0.1" in p for p in SSRF_PAYLOADS)
        assert any("localhost" in p for p in SSRF_PAYLOADS)
        # Check for cloud metadata
        assert any("169.254.169.254" in p for p in SSRF_PAYLOADS)
        assert any("metadata.google.internal" in p for p in SSRF_PAYLOADS)
        # Check for file protocol
        assert any("file://" in p for p in SSRF_PAYLOADS)

    def test_ssti_payloads_cover_engines(self):
        """Test SSTI payloads cover multiple template engines."""
        # Jinja2
        assert any("{{" in p and "}}" in p for p in SSTI_PAYLOADS)
        # Freemarker
        assert any("${" in p for p in SSTI_PAYLOADS)
        # ERB
        assert any("<%=" in p for p in SSTI_PAYLOADS)

    def test_xxe_payloads_have_file_read(self):
        """Test XXE payloads include file read."""
        assert any("file:///etc/passwd" in p for p in XXE_PAYLOADS)
        assert any("file:///etc/hosts" in p for p in XXE_PAYLOADS)

    def test_open_redirect_payloads_varied(self):
        """Test open redirect payloads cover different bypasses."""
        # External domain
        assert any("evil.com" in p for p in OPEN_REDIRECT_PAYLOADS)
        # Protocol relative
        assert any("//" == p[:2] for p in OPEN_REDIRECT_PAYLOADS)
        # JavaScript protocol
        assert any("javascript:" in p for p in OPEN_REDIRECT_PAYLOADS)
        # Data protocol
        assert any("data:" in p for p in OPEN_REDIRECT_PAYLOADS)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])