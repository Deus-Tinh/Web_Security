import json
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from app.models.scan import Scan, Vulnerability


REPORT_DIR = Path("storage/reports")


class ReportService:
    def __init__(self) -> None:
        REPORT_DIR.mkdir(parents=True, exist_ok=True)

    def write_json(self, scan: Scan, vulnerabilities: list[Vulnerability]) -> Path:
        path = REPORT_DIR / f"scan-{scan.id}.json"
        payload = {
            "scan_id": scan.id,
            "target": scan.target_url,
            "risk_score": scan.risk_score,
            "vulnerabilities": [
                {
                    "title": vuln.title,
                    "severity": vuln.severity.value,
                    "endpoint": vuln.endpoint,
                    "evidence": vuln.evidence,
                    "recommendation": vuln.recommendation,
                }
                for vuln in vulnerabilities
            ],
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path

    def write_pdf(self, scan: Scan, vulnerabilities: list[Vulnerability]) -> Path:
        path = REPORT_DIR / f"scan-{scan.id}.pdf"
        pdf = canvas.Canvas(str(path), pagesize=letter)
        pdf.setTitle(f"SentinelAI Scan Report #{scan.id}")
        pdf.setFont("Helvetica-Bold", 16)
        pdf.drawString(48, 750, "SentinelAI Web Vulnerability Report")
        pdf.setFont("Helvetica", 10)
        pdf.drawString(48, 728, f"Target: {scan.target_url}")
        pdf.drawString(48, 712, f"Risk score: {scan.risk_score}/100")
        y = 680
        for vuln in vulnerabilities[:18]:
            pdf.setFont("Helvetica-Bold", 11)
            pdf.drawString(48, y, f"[{vuln.severity.value.upper()}] {vuln.title}")
            y -= 14
            pdf.setFont("Helvetica", 9)
            pdf.drawString(60, y, vuln.endpoint[:105])
            y -= 22
            if y < 80:
                pdf.showPage()
                y = 750
        pdf.save()
        return path

