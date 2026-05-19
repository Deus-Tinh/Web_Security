import re
from pathlib import Path
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl
import aiohttp
from app.core.config import settings
from app.crawler.models import CrawlResult
from app.models.scan import Severity
from app.scanners.base import Finding


class XSSScanner:
    payload = "<script>alert(1)</script>"
    screenshot_dir = Path("storage/screenshots")

    async def scan(self, crawl: CrawlResult) -> list[Finding]:
        findings: list[Finding] = []
        timeout = aiohttp.ClientTimeout(total=settings.scan_request_timeout)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for url, params in crawl.parameters.items():
                for param in params:
                    try:
                        finding = await self._test_reflection(session, url, param)
                    except Exception:
                        continue
                    if finding:
                        findings.append(finding)
        return findings

    async def _test_reflection(self, session: aiohttp.ClientSession, url: str, param: str) -> Finding | None:
        target = self._inject(url, param, self.payload)
        async with session.get(target, allow_redirects=False) as response:
            body = await response.text(errors="ignore")
        if self.payload in body or re.search(r"<script[^>]*>\s*alert\(1\)\s*</script>", body, re.I):
            browser_evidence = await self._validate_dom_execution(target)
            return Finding(
                "Reflected Cross-Site Scripting",
                "XSS",
                Severity.HIGH,
                target,
                param,
                "Payload was reflected unencoded in the HTTP response.",
                "Contextually encode output, apply a restrictive CSP, and validate input by allowlist.",
                80,
                {"payload": self.payload, **browser_evidence},
            )
        return None

    async def _validate_dom_execution(self, url: str) -> dict:
        try:
            from playwright.async_api import async_playwright

            self.screenshot_dir.mkdir(parents=True, exist_ok=True)
            screenshot_path = self.screenshot_dir / f"xss-{abs(hash(url))}.png"
            executed = False
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(headless=True)
                page = await browser.new_page()

                async def on_dialog(dialog):
                    nonlocal executed
                    executed = True
                    await dialog.dismiss()

                page.on("dialog", on_dialog)
                await page.goto(url, wait_until="domcontentloaded", timeout=settings.scan_request_timeout * 1000)
                await page.screenshot(path=str(screenshot_path), full_page=True)
                await browser.close()
            return {"dom_executed": executed, "screenshot": str(screenshot_path)}
        except Exception as exc:
            return {"dom_executed": False, "browser_validation_error": str(exc)}

    def _inject(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query[param] = payload
        return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
