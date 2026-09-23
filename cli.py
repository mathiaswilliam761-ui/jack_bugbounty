"""
CLI interface for the Pentest Scanner.
"""

import asyncio
import argparse
import sys
from pathlib import Path
from typing import Optional

from pentest_scanner.config.settings import ScannerConfig, DEFAULT_CONFIG
from pentest_scanner.scanner import PentestScanner, run_scan

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Pentest Scanner - Automated vulnerability scanner for bug bounty programs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://example.com
  %(prog)s -u https://example.com --depth 3 --output ./reports
  %(prog)s -u https://example.com --format markdown,json,html --threads 20
  %(prog)s -u https://example.com --auth-cookie "session=abc123" --header "X-Custom: value"
  %(prog)s -u https://example.com --proxy http://127.0.0.1:8080 --waf-evasion
        """
    )
    
    # Target
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
    
    # Scan depth
    parser.add_argument("--depth", type=int, choices=[1, 2, 3], default=3,
                        help="Scan depth: 1=passive only, 2=passive+light active, 3=full scan (default: 3)")
    
    # Output
    parser.add_argument("-o", "--output", default="./reports", help="Output directory for reports (default: ./reports)")
    parser.add_argument("--format", default="markdown,json,html",
                        help="Report formats: markdown,json,html (comma-separated, default: all)")
    
    # Rate limiting
    parser.add_argument("--rate", type=float, default=5.0, help="Requests per second (default: 5.0)")
    parser.add_argument("--threads", type=int, default=10, help="Concurrent requests (default: 10)")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds (default: 30)")
    
    # Authentication
    parser.add_argument("--auth-cookie", action="append", help="Authentication cookie (format: name=value)")
    parser.add_argument("--auth-header", action="append", help="Authentication header (format: name=value)")
    parser.add_argument("--bearer-token", help="Bearer token for Authorization header")
    
    # Custom headers
    parser.add_argument("--header", action="append", help="Custom header (format: name=value)")
    
    # Proxy
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--proxy-auth", help="Proxy authentication (format: user:pass)")
    
    # User agent
    parser.add_argument("--user-agent", help="Custom User-Agent string")
    
    # WAF evasion
    parser.add_argument("--waf-evasion", action="store_true", help="Enable WAF evasion techniques")
    
    # Module toggles
    parser.add_argument("--no-passive", action="store_true", help="Disable passive reconnaissance")
    parser.add_argument("--no-active", action="store_true", help="Disable active scanning")
    parser.add_argument("--no-browser", action="store_true", help="Disable browser tests")
    parser.add_argument("--no-ssl", action="store_true", help="Disable SSL checks")
    
    # Exclusions
    parser.add_argument("--exclude-path", action="append", help="Path to exclude from scanning")
    parser.add_argument("--exclude-domain", action="append", help="Domain to exclude from scanning")
    
    # Bug bounty mode
    parser.add_argument("--no-bugbounty", action="store_true", help="Disable bug bounty specific features")
    parser.add_argument("--no-poc", action="store_true", help="Don't include proof of concept code in reports")
    parser.add_argument("--no-cvss", action="store_true", help="Don't include CVSS scores in reports")
    parser.add_argument("--no-remediation", action="store_true", help="Don't include remediation in reports")
    
    # Verbosity
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (only summary)")
    
    return parser.parse_args()


def build_config(args) -> ScannerConfig:
    """Build scanner configuration from parsed arguments."""
    config = ScannerConfig(
        target_url=args.url,
        scan_depth=args.depth,
        max_threads=args.threads,
        request_timeout=args.timeout,
        requests_per_second=args.rate,
        concurrent_requests=args.threads,
        output_dir=Path(args.output),
        report_format=args.format.split(","),
        
        # Module toggles
        enable_passive_recon=not args.no_passive,
        enable_active_scan=not args.no_active,
        enable_browser_tests=not args.no_browser,
        enable_ssl_checks=not args.no_ssl,
        
        # Bug bounty features
        bug_bounty_mode=not args.no_bugbounty,
        include_poc=not args.no_poc,
        include_cvss=not args.no_cvss,
        include_remediation=not args.no_remediation,
        
        # WAF evasion
        waf_evasion=args.waf_evasion,
    )
    
    # Parse auth cookies
    if args.auth_cookie:
        for cookie in args.auth_cookie:
            if "=" in cookie:
                name, value = cookie.split("=", 1)
                config.auth_cookies[name] = value
    
    # Parse auth headers
    if args.auth_header:
        for header in args.auth_header:
            if "=" in header:
                name, value = header.split("=", 1)
                config.auth_headers[name] = value
    
    # Bearer token
    if args.bearer_token:
        config.auth_bearer_token = args.bearer_token
    
    # Custom headers
    if args.header:
        for header in args.header:
            if "=" in header:
                name, value = header.split("=", 1)
                config.custom_headers[name] = value
    
    # Proxy
    if args.proxy:
        config.proxy_url = args.proxy
        if args.proxy_auth:
            config.proxy_auth = args.proxy_auth
    
    # User agent
    if args.user_agent:
        config.user_agent = args.user_agent
    
    # Exclusions
    if args.exclude_path:
        config.excluded_paths.extend(args.exclude_path)
    if args.exclude_domain:
        config.excluded_domains.extend(args.exclude_domain)
    
    return config


async def main():
    """Main entry point."""
    args = parse_args()
    
    # Setup logging
    import logging
    log_level = logging.DEBUG if args.verbose else (logging.WARNING if args.quiet else logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S"
    )
    
    # Reduce noise from libraries
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    
    # Build configuration
    config = build_config(args)
    
    # Print banner
    if not args.quiet:
        print("""
╔══════════════════════════════════════════════════════════════╗
║                    PENTEST SCANNER v1.0                       ║
║         Automated Vulnerability Scanner for Bug Bounty        ║
╚══════════════════════════════════════════════════════════════╝
        """)
        print(f"Target: {config.target_url}")
        print(f"Scan Depth: {config.scan_depth}/3")
        print(f"Rate Limit: {config.requests_per_second} req/s")
        print(f"Concurrency: {config.concurrent_requests}")
        print(f"Output: {config.output_dir}")
        print(f"Formats: {', '.join(config.report_format)}")
        print()
    
    try:
        # Run scan
        scanner = PentestScanner(config)
        scan_result = await scanner.scan(config.target_url)
        
        # Generate reports
        if not args.quiet:
            print("\nGenerating reports...")
        report_paths = scanner.generate_reports()
        
        # Print summary
        scanner.print_summary()
        
        if not args.quiet:
            print("\nReports generated:")
            for fmt, path in report_paths.items():
                print(f"  {fmt.upper()}: {path}")
        
        # Exit with appropriate code
        if scan_result.stats.get('critical', 0) > 0 or scan_result.stats.get('high', 0) > 0:
            sys.exit(1)  # High severity findings
        elif scan_result.stats.get('total', 0) > 0:
            sys.exit(2)  # Other findings
        else:
            sys.exit(0)  # Clean
            
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\nError: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())