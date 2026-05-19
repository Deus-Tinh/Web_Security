from datetime import datetime
from pydantic import BaseModel


class ReportResponse(BaseModel):
    id: int
    scan_id: int
    target_url: str
    format: str
    file_path: str
    created_at: datetime

