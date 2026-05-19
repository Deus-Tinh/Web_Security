import asyncio
import logging
from urllib.parse import parse_qs, urljoin, urlparse
import aiohttp
from bs4 import BeautifulSoup
from app.core.config import settings
from app.crawler.models import CrawlResult, DiscoveredForm

logger = logging.getLogger(__name__)


class AsyncCrawler:
    def __init__(self, max_depth: int = 2, respect_robots: bool = True):
        self.max_depth = max_depth
        self.respect_robots = respect_robots
        self.timeout = aiohttp.ClientTimeout(total=settings.scan_request_timeout)

    async def crawl(self, target_url: str) -> CrawlResult:
        result = CrawlResult()
        base_host = urlparse(target_url).netloc
        queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        await queue.put((target_url, 0))
        visited: set[str] = set()

        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            while not queue.empty():
                url, depth = await queue.get()
                if url in visited or depth > self.max_depth:
                    continue
                visited.add(url)
                try:
                    async with session.get(url, allow_redirects=True) as response:
                        if "text/html" not in response.headers.get("content-type", ""):
                            continue
                        html = await response.text(errors="ignore")
                except Exception as exc:
                    logger.info("crawler_request_failed", extra={"target": url, "scan_id": "-", "error": str(exc)})
                    continue
                result.pages.add(url)
                parsed = urlparse(url)
                query_params = list(parse_qs(parsed.query).keys())
                if query_params:
                    result.parameters[url] = query_params
                soup = BeautifulSoup(html, "html.parser")
                self._extract_forms(url, soup, result)
                if self._looks_like_login_page(url, soup):
                    result.login_pages.add(url)
                for link in soup.find_all("a", href=True):
                    next_url = urljoin(url, link["href"]).split("#")[0]
                    if urlparse(next_url).netloc == base_host and next_url not in visited:
                        await queue.put((next_url, depth + 1))
        return result

    def _extract_forms(self, page_url: str, soup: BeautifulSoup, result: CrawlResult) -> None:
        for form in soup.find_all("form"):
            action = urljoin(page_url, form.get("action") or page_url)
            method = (form.get("method") or "get").lower()
            inputs = [
                tag.get("name")
                for tag in form.find_all(["input", "textarea", "select"])
                if tag.get("name")
            ]
            result.forms.append(DiscoveredForm(action=action, method=method, inputs=inputs))

    def _looks_like_login_page(self, url: str, soup: BeautifulSoup) -> bool:
        text = soup.get_text(" ").lower()
        has_password = soup.find("input", {"type": "password"}) is not None
        return has_password or "login" in url.lower() or "sign in" in text

