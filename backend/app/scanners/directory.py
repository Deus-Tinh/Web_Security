from urllib.parse import urljoin
import aiohttp
from app.core.config import settings
from app.models.scan import Severity
from app.scanners.base import Finding


COMMON_PATHS = ["admin", ".git/", ".env", "backup", "phpmyadmin", "config.php", "server-status"]


class DirectoryDiscoveryScanner:
    async def scan(self, target_url: str) -> list[Finding]:
        timeout = aiohttp.ClientTimeout(total=settings.scan_request_timeout)
        findings: list[Finding] = []
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for path in COMMON_PATHS:
                url = urljoin(str(target_url).rstrip("/") + "/", path)
                try:
                    async with session.get(url, allow_redirects=False) as response:
                        if response.status in {200, 401, 403}:
                            findings.append(
                                Finding(
                                    "Sensitive Path Exposed",
                                    "Directory Discovery",
                                    Severity.MEDIUM if response.status == 200 else Severity.LOW,
                                    url,
                                    None,
                                    f"Path responded with HTTP {response.status}.",
                                    "Restrict access, remove sensitive files, and disable directory exposure.",
                                    65,
                                    {"status_code": response.status},
                                )
                            )
                except Exception:
                    continue
        return findings

