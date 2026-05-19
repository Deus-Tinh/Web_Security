import aiohttp
from app.core.config import settings
from app.models.scan import Severity
from app.scanners.base import Finding


REQUIRED_HEADERS = {
    "content-security-policy": ("Missing Content-Security-Policy", Severity.MEDIUM),
    "x-frame-options": ("Missing X-Frame-Options", Severity.MEDIUM),
    "strict-transport-security": ("Missing HTTP Strict-Transport-Security", Severity.HIGH),
    "x-content-type-options": ("Missing X-Content-Type-Options", Severity.LOW),
    "referrer-policy": ("Missing Referrer-Policy", Severity.LOW),
}


class SecurityHeaderAnalyzer:
    async def scan(self, target_url: str) -> list[Finding]:
        timeout = aiohttp.ClientTimeout(total=settings.scan_request_timeout)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(target_url, allow_redirects=True) as response:
                headers = {key.lower(): value for key, value in response.headers.items()}
        findings: list[Finding] = []
        for header, (title, severity) in REQUIRED_HEADERS.items():
            if header not in headers:
                findings.append(
                    Finding(
                        title,
                        "Security Headers",
                        severity,
                        target_url,
                        None,
                        f"HTTP response does not include {header}.",
                        "Add the missing header with a policy appropriate to the application.",
                        95,
                    )
                )
        return findings

