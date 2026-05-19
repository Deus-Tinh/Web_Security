from datetime import datetime
from pydantic import AnyHttpUrl, BaseModel, Field
from app.models.scan import ScanStatus, Severity


class ScanCreate(BaseModel):
    target_url: AnyHttpUrl
    max_depth: int = Field(default=2, ge=1, le=5)
    respect_robots: bool = True


class ScanResponse(BaseModel):
    id: int
    target_url: str
    status: ScanStatus
    progress: int
    risk_score: int
    created_at: datetime

    class Config:
        from_attributes = True


class VulnerabilityResponse(BaseModel):
    id: int
    scan_id: int
    title: str
    category: str
    severity: Severity
    endpoint: str
    parameter: str | None
    evidence: str
    recommendation: str
    confidence: int
    created_at: datetime

    class Config:
        from_attributes = True


class ScanLogResponse(BaseModel):
    id: int
    level: str
    message: str
    context: dict
    created_at: datetime

    class Config:
        from_attributes = True

