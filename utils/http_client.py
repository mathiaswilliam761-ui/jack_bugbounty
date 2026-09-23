"""
HTTP client with rate limiting, retry logic, and session management.
"""

import asyncio
import aiohttp
import time
import random
from typing import Dict, Optional, List, Any, Union
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
import logging
from pathlib import Path

from pentest_scanner.config.settings import DEFAULT_CONFIG, DEFAULT_HEADERS, ScannerConfig

logger = logging.getLogger(__name__)


@dataclass
class RateLimiter:
    """Token bucket rate limiter."""
    rate: float  # requests per second
    burst: int = 10
    tokens: float = field(init=False)
    last_update: float = field(init=False)
    
    def __post_init__(self):
        self.tokens = self.burst
        self.last_update = time.monotonic()
    
    async def acquire(self):
        """Acquire a token, blocking until available."""
        while True:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_update = now
            
            if self.tokens >= 1:
                self.tokens -= 1
                return
            
            # Wait for next token
            wait_time = (1 - self.tokens) / self.rate
            await asyncio.sleep(wait_time)


class HTTPClient:
    """Async HTTP client with rate limiting, retries, and session management."""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.rate_limiter = RateLimiter(config.requests_per_second, config.concurrent_requests)
        self.connector: Optional[aiohttp.TCPConnector] = None
        self._request_count = 0
        self._error_count = 0
    
    async def __aenter__(self):
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    async def start(self):
        """Initialize the HTTP session."""
        if self.session is None or self.session.closed:
            # Configure connector
            self.connector = aiohttp.TCPConnector(
                limit=self.config.concurrent_requests,
                limit_per_host=self.config.concurrent_requests,
                ttl_dns_cache=300,
                enable_cleanup_closed=True,
                force_close=False,
            )
            
            # Configure timeout
            timeout = aiohttp.ClientTimeout(
                total=self.config.request_timeout,
                connect=10,
                sock_read=self.config.request_timeout,
            )
            
            # Build headers
            headers = DEFAULT_HEADERS.copy()
            headers["User-Agent"] = self.config.user_agent
            headers.update(self.config.custom_headers)
            
            # Cookie jar for session persistence
            cookie_jar = aiohttp.CookieJar(unsafe=True)
            
            # Add auth cookies if provided
            self.session = aiohttp.ClientSession(
                connector=self.connector,
                timeout=timeout,
                headers=headers,
                cookie_jar=cookie_jar,
                trust_env=True,
            )
            
            # Set auth cookies
            if self.config.auth_cookies:
                for name, value in self.config.auth_cookies.items():
                    self.session.cookie_jar.update_cookies({name: value})
            
            # Set auth headers
            if self.config.auth_headers:
                self.session.headers.update(self.config.auth_headers)
            
            if self.config.auth_bearer_token:
                self.session.headers["Authorization"] = f"Bearer {self.config.auth_bearer_token}"
            
            # Configure proxy
            if self.config.proxy_url:
                self.session._default_proxy = self.config.proxy_url
                if self.config.proxy_auth:
                    self.session._default_proxy_auth = aiohttp.BasicAuth(*self.config.proxy_auth.split(":", 1))
    
    async def close(self):
        """Close the HTTP session."""
        if self.session and not self.session.closed:
            await self.session.close()
        if self.connector and not self.connector.closed:
            await self.connector.close()
    
    def _prepare_request(self, method: str, url: str, **kwargs) -> Dict:
        """Prepare request parameters."""
        # Rate limiting
        asyncio.create_task(self.rate_limiter.acquire())
        
        # Merge headers
        headers = kwargs.pop("headers", {})
        if self.config.auth_headers:
            headers.update(self.config.auth_headers)
        
        # Prepare request data
        request_data = {
            "method": method.upper(),
            "url": url,
            "headers": headers,
            "allow_redirects": kwargs.pop("allow_redirects", True),
            "max_redirects": self.config.max_redirects,
        }
        
        # Handle body/data/json
        if "json" in kwargs:
            request_data["json"] = kwargs.pop("json")
            if "Content-Type" not in headers:
                request_data["headers"]["Content-Type"] = "application/json"
        elif "data" in kwargs:
            request_data["data"] = kwargs.pop("data")
        elif "params" in kwargs:
            request_data["params"] = kwargs.pop("params")
        
        # Add remaining kwargs
        request_data.update(kwargs)
        
        return request_data
    
    async def request(
        self,
        method: str,
        url: str,
        max_retries: int = 3,
        **kwargs
    ) -> aiohttp.ClientResponse:
        """Make an HTTP request with retries."""
        await self.start()
        
        request_data = self._prepare_request(method, url, **kwargs)
        
        last_exception = None
        for attempt in range(max_retries):
            try:
                self._request_count += 1
                
                # Apply WAF evasion if enabled
                if self.config.waf_evasion and attempt > 0:
                    request_data = self._apply_waf_evasion(request_data)
                
                async with self.session.request(**request_data) as response:
                    # Read response body
                    await response.read()
                    return response
                    
            except asyncio.TimeoutError as e:
                last_exception = e
                logger.warning(f"Timeout on {method} {url} (attempt {attempt + 1}/{max_retries})")
            except aiohttp.ClientError as e:
                last_exception = e
                logger.warning(f"Client error on {method} {url}: {e} (attempt {attempt + 1}/{max_retries})")
            except Exception as e:
                last_exception = e
                logger.error(f"Unexpected error on {method} {url}: {e} (attempt {attempt + 1}/{max_retries})")
            
            # Exponential backoff with jitter
            if attempt < max_retries - 1:
                wait_time = (2 ** attempt) + random.uniform(0, 1)
                await asyncio.sleep(wait_time)
        
        self._error_count += 1
        raise last_exception
    
    def _apply_waf_evasion(self, request_data: Dict) -> Dict:
        """Apply WAF evasion techniques."""
        # This is a placeholder for WAF evasion techniques
        # Could include: header manipulation, parameter pollution, encoding, etc.
        return request_data
    
    async def get(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """GET request."""
        return await self.request("GET", url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """POST request."""
        return await self.request("POST", url, **kwargs)
    
    async def put(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """PUT request."""
        return await self.request("PUT", url, **kwargs)
    
    async def delete(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """DELETE request."""
        return await self.request("DELETE", url, **kwargs)
    
    async def head(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """HEAD request."""
        return await self.request("HEAD", url, **kwargs)
    
    async def options(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """OPTIONS request."""
        return await self.request("OPTIONS", url, **kwargs)
    
    async def patch(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """PATCH request."""
        return await self.request("PATCH", url, **kwargs)
    
    def get_stats(self) -> Dict[str, int]:
        """Get client statistics."""
        return {
            "requests": self._request_count,
            "errors": self._error_count,
        }


class ResponseWrapper:
    """Wrapper for aiohttp response with additional utilities."""
    
    def __init__(self, response: aiohttp.ClientResponse):
        self.response = response
        self._body: Optional[str] = None
        self._json: Optional[Dict] = None
    
    @property
    def status_code(self) -> int:
        return self.response.status
    
    @property
    def headers(self) -> Dict[str, str]:
        return dict(self.response.headers)
    
    @property
    def url(self) -> str:
        return str(self.response.url)
    
    @property
    def content_type(self) -> str:
        return self.response.headers.get("Content-Type", "")
    
    async def text(self) -> str:
        """Get response body as text."""
        if self._body is None:
            self._body = await self.response.text()
        return self._body
    
    async def json(self) -> Dict:
        """Get response body as JSON."""
        if self._json is None:
            self._json = await self.response.json()
        return self._json
    
    async def bytes(self) -> bytes:
        """Get response body as bytes."""
        return await self.response.read()
    
    def get_header(self, name: str, default: str = "") -> str:
        """Get a header value (case-insensitive)."""
        for k, v in self.response.headers.items():
            if k.lower() == name.lower():
                return v
        return default
    
    def has_header(self, name: str) -> bool:
        """Check if header exists (case-insensitive)."""
        return any(k.lower() == name.lower() for k in self.response.headers)
    
    def get_cookies(self) -> Dict[str, str]:
        """Get cookies from response."""
        cookies = {}
        for cookie in self.response.cookies.values():
            cookies[cookie.key] = cookie.value
        return cookies


async def make_request(
    client: HTTPClient,
    method: str,
    url: str,
    **kwargs
) -> ResponseWrapper:
    """Convenience function to make a request and wrap the response."""
    response = await client.request(method, url, **kwargs)
    return ResponseWrapper(response)