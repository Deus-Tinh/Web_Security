import asyncio
import re
import time
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl
import aiohttp
from app.core.config import settings
from app.crawler.models import CrawlResult
from app.models.scan import Severity
from app.scanners.base import Finding


SQL_ERRORS = re.compile(r"(sql syntax|mysql|postgresql|sqlite|ora-\d+|odbc|unclosed quotation)", re.I)


class SQLInjectionScanner:
    payloads = ["' OR '1'='1", "admin' --", "UNION SELECT NULL,NULL", "'; SELECT SLEEP(5)--"]

    async def scan(self, crawl: CrawlResult) -> list[Finding]:
        findings: list[Finding] = []
        timeout = aiohttp.ClientTimeout(total=settings.scan_request_timeout + 6)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            tasks = [
                self._test_param(session, url, param)
                for url, params in crawl.parameters.items()
                for param in params
            ]
            for result in await asyncio.gather(*tasks, return_exceptions=True):
                if isinstance(result, Finding):
                    findings.append(result)
        return findings

    async def _test_param(self, session: aiohttp.ClientSession, url: str, param: str) -> Finding | None:
        baseline_text, baseline_time = await self._fetch(session, url)
        for payload in self.payloads:
            target = self._inject(url, param, payload)
            body, elapsed = await self._fetch(session, target)
            if SQL_ERRORS.search(body):
                return Finding(
                    "Error-based SQL Injection",
                    "SQL Injection",
                    Severity.CRITICAL,
                    target,
                    param,
                    "Database error signature appeared after payload injection.",
                    "Use parameterized queries, typed query builders, and centralized input validation.",
                    90,
                    {"payload": payload},
                )
            if abs(len(body) - len(baseline_text)) > max(80, len(baseline_text) * 0.35):
                return Finding(
                    "Boolean/response differential SQL Injection",
                    "SQL Injection",
                    Severity.HIGH,
                    target,
                    param,
                    "Injected request produced a materially different response length.",
                    "Use prepared statements and avoid string-concatenated SQL.",
                    70,
                    {"payload": payload},
                )
            if "SLEEP" in payload and elapsed - baseline_time > 4:
                return Finding(
                    "Time-based SQL Injection",
                    "SQL Injection",
                    Severity.CRITICAL,
                    target,
                    param,
                    f"Response delayed by {elapsed:.1f}s after time-delay payload.",
                    "Disable stacked queries and use parameterized database access.",
                    85,
                    {"payload": payload},
                )
        return None

    async def _fetch(self, session: aiohttp.ClientSession, url: str) -> tuple[str, float]:
        started = time.perf_counter()
        async with session.get(url, allow_redirects=False) as response:
            return await response.text(errors="ignore"), time.perf_counter() - started

    def _inject(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query[param] = payload
        return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))

