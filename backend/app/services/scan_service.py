import asyncio
from urllib.parse import urlparse
from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import settings
from app.crawler.async_crawler import AsyncCrawler
from app.models.scan import Report, Scan, ScanLog, ScanStatus, Vulnerability
from app.models.user import User
from app.scanners.directory import DirectoryDiscoveryScanner
from app.scanners.headers import SecurityHeaderAnalyzer
from app.scanners.sqli import SQLInjectionScanner
from app.scanners.xss import XSSScanner
from app.services.ai_analysis import AIAnalysisEngine
from app.services.report_service import ReportService
from app.services.websocket_manager import ws_manager


class ScanService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_scan(self, target_url: str, owner: User, max_depth: int, respect_robots: bool) -> Scan:
        self._validate_target(target_url)
        scan = Scan(
            target_url=target_url,
            owner_id=owner.id,
            scope={"max_depth": max_depth, "respect_robots": respect_robots},
        )
        self.db.add(scan)
        await self.db.commit()
        await self.db.refresh(scan)
        return scan

    async def run_scan(self, scan_id: int) -> None:
        scan = await self.db.get(Scan, scan_id)
        if not scan:
            return
        try:
            await self._update(scan, ScanStatus.RUNNING, 5, "Scan started")
            crawler = AsyncCrawler(max_depth=scan.scope.get("max_depth", settings.scan_max_depth))
            crawl = await crawler.crawl(scan.target_url)
            await self._log(scan.id, f"Crawled {len(crawl.pages)} pages and {len(crawl.forms)} forms")
            await self._update(scan, ScanStatus.RUNNING, 30, "Crawling completed")

            scanner_results = await asyncio.gather(
                SQLInjectionScanner().scan(crawl),
                XSSScanner().scan(crawl),
                SecurityHeaderAnalyzer().scan(scan.target_url),
                DirectoryDiscoveryScanner().scan(scan.target_url),
            )
            findings = [item for group in scanner_results for item in group]
            ai = AIAnalysisEngine()
            enriched = [await ai.enrich(item) for item in findings]
            for finding in enriched:
                self.db.add(
                    Vulnerability(
                        scan_id=scan.id,
                        title=finding.title,
                        category=finding.category,
                        severity=finding.severity,
                        endpoint=finding.endpoint,
                        parameter=finding.parameter,
                        evidence=finding.evidence,
                        recommendation=finding.recommendation,
                        confidence=finding.confidence,
                        metadata_json=finding.metadata or {},
                    )
                )
            scan.risk_score = await ai.summarize_risk([item.severity for item in enriched])
            await self._update(scan, ScanStatus.RUNNING, 85, f"Detected {len(enriched)} findings")
            await self.db.flush()

            vulnerabilities = (
                await self.db.execute(select(Vulnerability).where(Vulnerability.scan_id == scan.id))
            ).scalars().all()
            reporter = ReportService()
            json_path = reporter.write_json(scan, list(vulnerabilities))
            pdf_path = reporter.write_pdf(scan, list(vulnerabilities))
            self.db.add(Report(scan_id=scan.id, format="json", file_path=str(json_path), summary={}))
            self.db.add(Report(scan_id=scan.id, format="pdf", file_path=str(pdf_path), summary={}))
            await self._update(scan, ScanStatus.COMPLETED, 100, "Scan completed")
        except Exception as exc:
            await self._log(scan.id, f"Scan failed: {exc}", level="error")
            await self._update(scan, ScanStatus.FAILED, scan.progress, "Scan failed")

    async def dashboard_stats(self, owner: User) -> dict:
        total = await self.db.scalar(select(func.count(Scan.id)).where(Scan.owner_id == owner.id))
        vuln_count = await self.db.scalar(
            select(func.count(Vulnerability.id)).join(Scan).where(Scan.owner_id == owner.id)
        )
        active = await self.db.scalar(
            select(func.count(Scan.id)).where(Scan.owner_id == owner.id, Scan.status == ScanStatus.RUNNING)
        )
        recent = (
            await self.db.execute(
                select(Scan).where(Scan.owner_id == owner.id).order_by(Scan.created_at.desc()).limit(6)
            )
        ).scalars().all()
        return {"total_scans": total or 0, "vulnerabilities": vuln_count or 0, "active_scans": active or 0, "recent": recent}

    async def _update(self, scan: Scan, status_value: ScanStatus, progress: int, message: str) -> None:
        scan.status = status_value
        scan.progress = progress
        await self._log(scan.id, message)
        await self.db.commit()
        await ws_manager.broadcast(scan.id, {"status": status_value.value, "progress": progress, "message": message})

    async def _log(self, scan_id: int, message: str, level: str = "info") -> None:
        self.db.add(ScanLog(scan_id=scan_id, level=level, message=message, context={}))
        await self.db.flush()

    def _validate_target(self, target_url: str) -> None:
        parsed = urlparse(target_url)
        if parsed.scheme not in {"http", "https"}:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Only HTTP(S) targets are supported")
        host = parsed.hostname or ""
        allowed = settings.allowed_target_hosts
        if allowed and host not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Target is outside the configured authorized scanning scope",
            )

