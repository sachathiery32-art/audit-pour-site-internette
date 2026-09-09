"""HTTP client wrapper with rate limiting, retry, and caching.

All scanner modules use :class:`HttpClient` to ensure consistent, polite
request behavior toward the target.
"""
from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


@dataclass
class HttpResponse:
    """Normalized response object."""
    url: str
    status: int
    headers: Dict[str, str]
    body: str
    elapsed: float
    redirected: bool
    final_url: str

    def header(self, name: str) -> str:
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return ""


class HttpClient:
    """Thread-safe HTTP client with rate limiting, retry, and caching."""

    def __init__(self, timeout: int = 10, rate_limit: int = 2,
                 retries: int = 2, cache: bool = True,
                 user_agent: str = "AutoSecAudit/1.0 (+authorized-testing)"):
        self.timeout = timeout
        self.rate_limit = max(1, rate_limit)
        self.retries = max(0, retries)
        self.cache_enabled = cache
        self._cache: Dict[str, HttpResponse] = {}
        self._lock = threading.Lock()
        self._last_request_time = 0.0
        self._min_interval = 1.0 / self.rate_limit
        self.requests_count = 0
        self.failures_count = 0

        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": user_agent,
            "Accept": "*/*",
        })
        retry = Retry(
            total=self.retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD", "OPTIONS"],
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

    @staticmethod
    def _cache_key(method: str, url: str) -> str:
        return hashlib.sha256(f"{method}:{url}".encode()).hexdigest()

    def _throttle(self) -> None:
        with self._lock:
            elapsed = time.monotonic() - self._last_request_time
            if elapsed < self._min_interval:
                time.sleep(self._min_interval - elapsed)
            self._last_request_time = time.monotonic()

    def request(self, method: str, url: str, **kwargs) -> Optional[HttpResponse]:
        """Perform an HTTP request with throttling, retry, and caching."""
        method = method.upper()
        key = self._cache_key(method, url)
        if self.cache_enabled and method == "GET" and key in self._cache:
            return self._cache[key]

        self._throttle()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        try:
            resp = self._session.request(method, url, **kwargs)
        except requests.RequestException:
            with self._lock:
                self.requests_count += 1
                self.failures_count += 1
            return None

        with self._lock:
            self.requests_count += 1

        result = HttpResponse(
            url=url,
            status=resp.status_code,
            headers=dict(resp.headers),
            body=resp.text,
            elapsed=resp.elapsed.total_seconds(),
            redirected=(resp.url != url),
            final_url=resp.url,
        )

        if self.cache_enabled and method == "GET":
            with self._lock:
                self._cache[key] = result
        return result

    def get(self, url: str, **kwargs) -> Optional[HttpResponse]:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Optional[HttpResponse]:
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs) -> Optional[HttpResponse]:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> Optional[HttpResponse]:
        return self.request("OPTIONS", url, **kwargs)

    def close(self) -> None:
        self._session.close()
