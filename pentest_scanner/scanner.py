"""
Main scanner orchestrator that coordinates all scanning modules.
"""

import asyncio
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
import logging

from pentest_scanner.utils.http_client import HTTPClient
from pentest_scanner.utils.models import ScanResult, Endpoint, Severity
from pentest_scanner.config.settings import ScannerConfig, DEFAULT_CONFIG
from pentest_scanner.scanners.passive_recon import PassiveReconScanner
from pentest_scanner.scanners.xss_scanner import XSSScanner
from pentest_scanner.scanners.sqli_scanner import SQLiScanner
from pentest_scanner.scanners.ssrf_scanner import SSRFScanner
from pentest_scanner.scanners.idor_scanner import IDORScanner
from pentest_scanner.scanners.open_redirect_scanner import OpenRedirectScanner
from pentest_scanner.scanners.xxe_scanner import XXEScanner
from pentest_scanner.scanners.ssti_scanner import SSTIScanner
from pentest_scanner.scanners.file_upload_scanner import FileUploadScanner
from pentest_scanner.utils.report_generator import ReportGenerator

logger = logging.getLogger(__name__)


class PentestScanner:
    """Main penetration testing scanner orchestrator."""
    
    def __init__(self, config: ScannerConfig = None):
        self.config = config or DEFAULT_CONFIG
        self.scan_result: Optional[ScanResult] = None
        self.client: Optional[HTTPClient] = None
        self.discovered_endpoints: List[Endpoint] = []
    
    async def scan(self, target_url: str) -> ScanResult:
        """Run complete vulnerability scan on target."""
        # Initialize scan result
        self.scan_result = ScanResult(
            target_url=target_url,
            target_domain=self.config.target_domain,
            scan_id=f"SCAN_{uuid.uuid4().hex[:12].upper()}",
            started_at=datetime.now(),
            scan_depth=self.config.scan_depth,
        )
        
        # Initialize HTTP client
        self.client = HTTPClient(self.config)
        
        try:
            await self.client.start()
            
            # Phase 1: Passive Reconnaissance
            if self.config.enable_passive_recon:
                logger.info("Starting passive reconnaissance...")
                self.scan_result.modules_run.append("passive_recon")
                recon_results = await self._run_passive_recon()
                logger.info(f"Passive recon completed. Found {len(self.discovered_endpoints)} endpoints.")
            
            # Phase 2: Active Vulnerability Scanning
            if self.config.enable_active_scan and self.config.scan_depth >= 2:
                logger.info("Starting active vulnerability scanning...")
                await self._run_active_scans()
            
            # Phase 3: Browser-based tests (if enabled)
            if self.config.enable_browser_tests and self.config.scan_depth >= 3:
                logger.info("Starting browser-based tests...")
                await self._run_browser_tests()
            
            # Complete scan
            self.scan_result.complete()
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            self.scan_result.fail(str(e))
        finally:
            await self.client.close()
        
        return self.scan_result
    
    async def _run_passive_recon(self) -> Dict[str, Any]:
        """Run passive reconnaissance."""
        scanner = PassiveReconScanner(self.client, self.config, self.scan_result)
        results = await scanner.run()
        
        # Store discovered endpoints
        self.discovered_endpoints = scanner.discovered_endpoints
        self.scan_result.endpoints_tested = [e.url for e in self.discovered_endpoints]
        
        return results
    
    async def _run_active_scans(self):
        """Run all active vulnerability scanners."""
        scanners = []
        
        if self.config.enable_xss_checks:
            scanners.append(("xss", XSSScanner(self.client, self.config, self.scan_result)))
        if self.config.enable_sqli_checks:
            scanners.append(("sqli", SQLiScanner(self.client, self.config, self.scan_result)))
        if self.config.enable_ssrf_checks:
            scanners.append(("ssrf", SSRFScanner(self.client, self.config, self.scan_result)))
        if self.config.enable_idor_checks:
            scanners.append(("idor", IDORScanner(self.client, self.config, self.scan_result)))
        if self.config.enable_open_redirect_checks:
            scanners.append(("open_redirect", OpenRedirectScanner(self.client, self.config, self.scan_result)))
        if self.config.enable_xxe_checks:
            scanners.append(("xxe", XXEScanner(self.client, self.config, self.scan_result)))
        if self.config.enable_ssti_checks:
            scanners.append(("ssti", SSTIScanner(self.client, self.config, self.scan_result)))
        if self.config.enable_file_upload_checks:
            scanners.append(("file_upload", FileUploadScanner(self.client, self.config, self.scan_result)))
        
        # Run scanners
        for name, scanner in scanners:
            try:
                logger.info(f"Running {name} scanner...")
                self.scan_result.modules_run.append(name)
                results = await scanner.run(self.discovered_endpoints)
                logger.info(f"{name} scanner completed. Found {results.get('vulnerabilities_found', 0)} vulnerabilities.")
            except Exception as e:
                logger.error(f"Error in {name} scanner: {e}")
                self.scan_result.errors.append(f"{name} scanner error: {e}")
    
    async def _run_browser_tests(self):
        """Run browser-based tests for complex vulnerabilities."""
        # This would integrate with browser automation for:
        # - DOM-based XSS
        # - Complex authentication flows
        # - JavaScript-heavy applications
        # - CSP bypasses
        # For now, we'll note this as a future enhancement
        self.scan_result.modules_run.append("browser_tests")
        self.scan_result.errors.append("Browser-based tests not yet implemented")
    
    def generate_reports(self, output_dir: Path = None) -> Dict[str, Path]:
        """Generate reports in all configured formats."""
        if output_dir is None:
            output_dir = self.config.output_dir
        
        generator = ReportGenerator(self.scan_result, self.config)
        return generator.generate_all(output_dir)
    
    def print_summary(self):
        """Print scan summary to console."""
        if not self.scan_result:
            print("No scan results available.")
            return
        
        print("\n" + "="*60)
        print("PENETRATION TEST SCAN SUMMARY")
        print("="*60)
        print(f"Target: {self.scan_result.target_url}")
        print(f"Scan ID: {self.scan_result.scan_id}")
        print(f"Duration: {(self.scan_result.completed_at - self.scan_result.started_at).total_seconds():.1f}s" if self.scan_result.completed_at else "N/A")
        print(f"Modules: {', '.join(self.scan_result.modules_run)}")
        print()
        print("VULNERABILITIES FOUND:")
        print(f"  🔴 Critical: {self.scan_result.stats.get('critical', 0)}")
        print(f"  🟠 High:     {self.scan_result.stats.get('high', 0)}")
        print(f"  🟡 Medium:   {self.scan_result.stats.get('medium', 0)}")
        print(f"  🔵 Low:      {self.scan_result.stats.get('low', 0)}")
        print(f"  ⚪ Info:     {self.scan_result.stats.get('info', 0)}")
        print(f"  ─────────────────────")
        print(f"  Total:       {self.scan_result.stats.get('total', 0)}")
        print()
        
        if self.scan_result.vulnerabilities:
            print("TOP FINDINGS:")
            # Show top 5 by severity
            severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
            top_vulns = sorted(self.scan_result.vulnerabilities, key=lambda v: severity_order.get(v.severity, 5))[:5]
            for i, vuln in enumerate(top_vulns, 1):
                print(f"  {i}. [{vuln.severity.value.upper()}] {vuln.title}")
        
        print("="*60)


async def run_scan(target_url: str, config: ScannerConfig = None) -> ScanResult:
    """Convenience function to run a scan."""
    scanner = PentestScanner(config)
    return await scanner.scan(target_url)