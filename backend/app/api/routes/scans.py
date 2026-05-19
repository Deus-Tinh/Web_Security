import asyncio
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.dependencies import get_current_user
from app.database.session import get_db, AsyncSessionLocal
from app.models.scan import Scan, ScanLog, Vulnerability
from app.models.user import User
from app.schemas.scan import ScanCreate, ScanLogResponse, ScanResponse, VulnerabilityResponse
from app.services.scan_service import ScanService
from app.services.websocket_manager import ws_manager

router = APIRouter(prefix="/scans", tags=["scans"])


async def run_scan_background(scan_id: int) -> None:
    async with AsyncSessionLocal() as db:
        await ScanService(db).run_scan(scan_id)


@router.post("", response_model=ScanResponse, status_code=201)
async def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Scan:
    scan = await ScanService(db).create_scan(str(payload.target_url), user, payload.max_depth, payload.respect_robots)
    background_tasks.add_task(run_scan_background, scan.id)
    return scan


@router.get("", response_model=list[ScanResponse])
async def list_scans(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[Scan]:
    result = await db.execute(
        select(Scan).where(Scan.owner_id == user.id).order_by(Scan.created_at.desc()).limit(limit).offset(offset)
    )
    return list(result.scalars())


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)) -> Scan:
    result = await db.execute(select(Scan).where(Scan.id == scan_id, Scan.owner_id == user.id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


@router.get("/{scan_id}/vulnerabilities", response_model=list[VulnerabilityResponse])
async def scan_vulnerabilities(scan_id: int, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(Vulnerability).where(Vulnerability.scan_id == scan_id).order_by(Vulnerability.created_at.desc()))
    return list(result.scalars())


@router.get("/vulnerabilities/{vulnerability_id}", response_model=VulnerabilityResponse)
async def vulnerability_detail(
    vulnerability_id: int,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Vulnerability:
    result = await db.execute(
        select(Vulnerability)
        .join(Scan)
        .where(Vulnerability.id == vulnerability_id, Scan.owner_id == user.id)
    )
    vulnerability = result.scalar_one_or_none()
    if not vulnerability:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")
    return vulnerability


@router.get("/{scan_id}/logs", response_model=list[ScanLogResponse])
async def scan_logs(scan_id: int, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(ScanLog).where(ScanLog.scan_id == scan_id).order_by(ScanLog.created_at.asc()))
    return list(result.scalars())


@router.websocket("/{scan_id}/ws")
async def scan_updates(scan_id: int, websocket: WebSocket) -> None:
    await ws_manager.connect(scan_id, websocket)
    try:
        while True:
            await asyncio.sleep(30)
            await websocket.send_json({"type": "heartbeat"})
    except WebSocketDisconnect:
        ws_manager.disconnect(scan_id, websocket)
