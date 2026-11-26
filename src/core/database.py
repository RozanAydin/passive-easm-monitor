"""SQLAlchemy ORM models and database session management (SQLite & PostgreSQL)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker


def utc_now() -> datetime:
    """Return current UTC timestamp."""
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    scan_runs: Mapped[list["ScanRun"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    subdomains: Mapped[list["Subdomain"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    typosquats: Mapped[list["TyposquatDomain"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="target", cascade="all, delete-orphan")


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="RUNNING")
    total_subdomains: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    new_findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    target: Mapped["Target"] = relationship(back_populates="scan_runs")
    enrichments: Mapped[list["IPEnrichment"]] = relationship(back_populates="scan_run", cascade="all, delete-orphan")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="scan_run", cascade="all, delete-orphan")


class Subdomain(Base):
    __tablename__ = "subdomains"
    __table_args__ = (UniqueConstraint("target_id", "fqdn", name="uq_target_fqdn"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    fqdn: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    cname_record: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mx_records: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_resolving: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    first_seen_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), nullable=False)
    last_seen_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    target: Mapped["Target"] = relationship(back_populates="subdomains")


class IPEnrichment(Base):
    __tablename__ = "ip_enrichments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    open_ports: Mapped[str | None] = mapped_column(Text, nullable=True)
    cves: Mapped[str | None] = mapped_column(Text, nullable=True)
    cpes: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[str | None] = mapped_column(Text, nullable=True)
    enriched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    scan_run: Mapped["ScanRun"] = relationship(back_populates="enrichments")


class TyposquatDomain(Base):
    __tablename__ = "typosquat_domains"
    __table_args__ = (UniqueConstraint("target_id", "spoof_domain", name="uq_target_spoof_domain"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    spoof_domain: Mapped[str] = mapped_column(String(255), nullable=False)
    permutation_type: Mapped[str] = mapped_column(String(50), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    has_mx_record: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    registrar: Mapped[str | None] = mapped_column(String(255), nullable=True)
    registration_date: Mapped[str | None] = mapped_column(String(50), nullable=True)
    first_seen_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), nullable=False)
    last_seen_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), nullable=False)

    target: Mapped["Target"] = relationship(back_populates="typosquats")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), nullable=False)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    indicator: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    is_notified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    scan_run: Mapped["ScanRun"] = relationship(back_populates="alerts")
    target: Mapped["Target"] = relationship(back_populates="alerts")


def _ensure_sqlite_parent_dir(database_url: str) -> None:
    """Create parent directory for file-backed SQLite databases if needed."""
    if database_url.startswith("sqlite:///") and not database_url.endswith(":memory:"):
        raw_path = database_url[len("sqlite:///"):]
        if raw_path and raw_path != ":memory:":
            db_path = Path(raw_path)
            db_path.parent.mkdir(parents=True, exist_ok=True)


class DatabaseManager:
    """Manages SQLAlchemy engine, schema initialization, and sessions."""

    def __init__(self, database_url: str) -> None:
        _ensure_sqlite_parent_dir(database_url)
        connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
        self.engine: Engine = create_engine(
            database_url,
            connect_args=connect_args,
            future=True,
        )
        self.SessionLocal = sessionmaker(
            bind=self.engine,
            autoflush=False,
            expire_on_commit=False,
        )

    def init_db(self) -> None:
        """Create all tables if they do not exist."""
        Base.metadata.create_all(bind=self.engine)

    def get_session(self) -> Session:
        """Return a new SQLAlchemy session."""
        return self.SessionLocal()

    def session_scope(self) -> Iterator[Session]:
        """Context generator yielding a session with commit/rollback handling."""
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
