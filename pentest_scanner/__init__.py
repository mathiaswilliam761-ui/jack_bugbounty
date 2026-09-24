"""
Pentest Scanner Package
"""

__version__ = "1.0.0"
__author__ = "Pentest Scanner Team"
__description__ = "Automated vulnerability scanner for bug bounty programs"

from .scanner import PentestScanner, run_scan
from .cli import main
from .config.settings import ScannerConfig, DEFAULT_CONFIG
from .utils.models import Vulnerability, ScanResult, Severity, VulnerabilityCategory

__all__ = [
    "PentestScanner",
    "run_scan",
    "main",
    "ScannerConfig",
    "DEFAULT_CONFIG",
    "Vulnerability",
    "ScanResult",
    "Severity",
    "VulnerabilityCategory",
]