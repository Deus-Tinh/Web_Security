from enum import StrEnum
from sqlalchemy import Enum, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, TimestampMixin


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"
    __table_args__ = (Index("ix_scans_status", "status"), Index("ix_scans_target", "target_url"))

    id: Mapped[int] = mapped_column(primary_key=True)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.QUEUED)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    scope: Mapped[dict] = mapped_column(JSONB, default=dict)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    owner = relationship("User", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    logs = relationship("ScanLog", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")


class Vulnerability(Base, TimestampMixin):
    __tablename__ = "vulnerabilities"
    __table_args__ = (Index("ix_vulnerabilities_severity", "severity"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(80), nullable=False)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(2048), nullable=False)
    parameter: Mapped[str | None] = mapped_column(String(120))
    evidence: Mapped[str] = mapped_column(Text, default="")
    recommendation: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[int] = mapped_column(Integer, default=70)
    metadata_json: Mapped[dict] = mapped_column(JSONB, default=dict)

    scan = relationship("Scan", back_populates="vulnerabilities")


class ScanLog(Base, TimestampMixin):
    __tablename__ = "scan_logs"
    __table_args__ = (Index("ix_scan_logs_scan_id", "scan_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    level: Mapped[str] = mapped_column(String(20), default="info")
    message: Mapped[str] = mapped_column(Text, nullable=False)
    context: Mapped[dict] = mapped_column(JSONB, default=dict)

    scan = relationship("Scan", back_populates="logs")


class Report(Base, TimestampMixin):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    format: Mapped[str] = mapped_column(String(20), default="json")
    file_path: Mapped[str] = mapped_column(String(512), nullable=False)
    summary: Mapped[dict] = mapped_column(JSONB, default=dict)

    scan = relationship("Scan", back_populates="reports")

