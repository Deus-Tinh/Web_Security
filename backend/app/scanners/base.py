from dataclasses import dataclass
from app.models.scan import Severity


@dataclass(slots=True)
class Finding:
    title: str
    category: str
    severity: Severity
    endpoint: str
    parameter: str | None
    evidence: str
    recommendation: str
    confidence: int = 70
    metadata: dict | None = None

