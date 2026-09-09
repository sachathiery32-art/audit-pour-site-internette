"""Tests for the HTTP client wrapper."""
import unittest
from unittest.mock import patch, MagicMock

from modules.http_client import HttpClient, HttpResponse


class TestHttpClient(unittest.TestCase):
    def test_cache_key_stable(self):
        k1 = HttpClient._cache_key("GET", "https://example.com")
        k2 = HttpClient._cache_key("GET", "https://example.com")
        self.assertEqual(k1, k2)

    def test_cache_key_differs_by_method(self):
        k1 = HttpClient._cache_key("GET", "https://example.com")
        k2 = HttpClient._cache_key("POST", "https://example.com")
        self.assertNotEqual(k1, k2)

    @patch("modules.http_client.requests.Session")
    def test_request_returns_none_on_failure(self, mock_session_cls):
        mock_session = MagicMock()
        import requests
        mock_session.request.side_effect = requests.RequestException("fail")
        mock_session_cls.return_value = mock_session

        client = HttpClient(timeout=1, rate_limit=100, cache=False)
        result = client.get("https://nonexistent.example")
        self.assertIsNone(result)

    @patch("modules.http_client.requests.Session")
    def test_get_caches_response(self, mock_session_cls):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.text = "hello"
        mock_resp.elapsed.total_seconds.return_value = 0.1
        mock_resp.url = "https://example.com"
        mock_session.request.return_value = mock_resp
        mock_session_cls.return_value = mock_session

        client = HttpClient(timeout=1, rate_limit=1000, cache=True)
        r1 = client.get("https://example.com")
        r2 = client.get("https://example.com")
        self.assertIsNotNone(r1)
        self.assertIsNotNone(r2)
        # second call should hit cache, not the session
        self.assertEqual(mock_session.request.call_count, 1)


class TestHttpResponse(unittest.TestCase):
    def test_header_case_insensitive(self):
        r = HttpResponse(
            url="https://example.com", status=200,
            headers={"Content-Type": "text/html"},
            body="", elapsed=0.1, redirected=False, final_url="https://example.com",
        )
        self.assertEqual(r.header("content-type"), "text/html")
        self.assertEqual(r.header("CONTENT-TYPE"), "text/html")
        self.assertEqual(r.header("missing"), "")


if __name__ == "__main__":
    unittest.main()
