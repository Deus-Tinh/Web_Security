from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.dependencies import get_current_user
from app.database.session import get_db
from app.models.user import User
from app.services.scan_service import ScanService

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats")
async def stats(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)) -> dict:
    data = await ScanService(db).dashboard_stats(user)
    data["recent"] = [
        {
            "id": scan.id,
            "target_url": scan.target_url,
            "status": scan.status.value,
            "progress": scan.progress,
            "risk_score": scan.risk_score,
        }
        for scan in data["recent"]
    ]
    return data

