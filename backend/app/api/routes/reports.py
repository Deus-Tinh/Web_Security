from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.dependencies import get_current_user
from app.database.session import get_db
from app.models.scan import Report, Scan
from app.models.user import User
from app.schemas.report import ReportResponse

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("", response_model=list[ReportResponse])
async def list_reports(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[ReportResponse]:
    result = await db.execute(
        select(Report, Scan.target_url)
        .join(Scan)
        .where(Scan.owner_id == user.id)
        .order_by(Report.created_at.desc())
    )
    return [
        ReportResponse(
            id=report.id,
            scan_id=report.scan_id,
            target_url=target_url,
            format=report.format,
            file_path=report.file_path,
            created_at=report.created_at,
        )
        for report, target_url in result.all()
    ]


@router.get("/{report_id}/download")
async def download_report(
    report_id: int,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> FileResponse:
    result = await db.execute(
        select(Report)
        .join(Scan)
        .where(Report.id == report_id, Scan.owner_id == user.id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    path = Path(report.file_path)
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report file is missing")

    media_type = "application/pdf" if report.format == "pdf" else "application/json"
    return FileResponse(
        path=path,
        media_type=media_type,
        filename=f"sentinel-scan-{report.scan_id}.{report.format}",
    )

