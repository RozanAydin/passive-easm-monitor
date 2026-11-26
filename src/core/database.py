"""SQLAlchemy ORM models, SQLite WAL concurrency setup, and target auto-seeding."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import yaml
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    event,
    func,
    inspect,
    select,
    text,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

from src.logger import get_logger
from src.utils.validators import parse_allowlist_input, validate_and_normalize_domain

logger = get_logger("core.database")


def utc_now() -> datetime:
    """Return current UTC timestamp."""
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    allowlist: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    scan_status: Mapped[str] = mapped_column(String(20), default="idle", nullable=False)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    scan_runs: Mapped[list["ScanRun"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    subdomains: Mapped[list["Subdomain"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    typosquats: Mapped[list["TyposquatDomain"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="target", cascade="all, delete-orphan")

    def get_allowlist(self) -> list[str]:
        """Return parsed list of allowlisted domains/subdomains."""
        if not self.allowlist:
            return []
        try:
            data = json.loads(self.allowlist)
            return [str(x).lower() for x in data] if isinstance(data, list) else []
        except ValueError:
            return []

    def set_allowlist(self, items: list[str]) -> None:
        """Persist validated allowlist entries as JSON text."""
        self.allowlist = json.dumps(items)


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


def _configure_sqlite_pragmas(engine: Engine) -> None:
    """Enable WAL mode and busy timeout for safe concurrent CLI + Web SQLite access."""

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA busy_timeout=30000;")
            cursor.execute("PRAGMA foreign_keys=ON;")
        finally:
            cursor.close()


class DatabaseManager:
    """Manages SQLAlchemy engine, WAL mode, schema migrations, and sessions."""

    def __init__(self, database_url: str) -> None:
        _ensure_sqlite_parent_dir(database_url)
        is_sqlite = database_url.startswith("sqlite")
        connect_args = {"check_same_thread": False, "timeout": 30} if is_sqlite else {}
        self.engine: Engine = create_engine(
            database_url,
            connect_args=connect_args,
            future=True,
        )
        if is_sqlite:
            _configure_sqlite_pragmas(self.engine)

        self.SessionLocal = sessionmaker(
            bind=self.engine,
            autoflush=False,
            expire_on_commit=False,
        )

    def _migrate_targets_columns(self) -> None:
        """Safely add new Target columns to existing SQLite databases if missing."""
        inspector = inspect(self.engine)
        if not inspector.has_table("targets"):
            return
        existing_cols = {col["name"] for col in inspector.get_columns("targets")}
        migrations: list[str] = []
        if "allowlist" not in existing_cols:
            migrations.append("ALTER TABLE targets ADD COLUMN allowlist TEXT NOT NULL DEFAULT '[]'")
        if "scan_status" not in existing_cols:
            migrations.append("ALTER TABLE targets ADD COLUMN scan_status VARCHAR(20) NOT NULL DEFAULT 'idle'")
        if "last_scanned_at" not in existing_cols:
            migrations.append("ALTER TABLE targets ADD COLUMN last_scanned_at DATETIME")
        if "last_error" not in existing_cols:
            migrations.append("ALTER TABLE targets ADD COLUMN last_error TEXT")

        if migrations:
            with self.engine.begin() as conn:
                for stmt in migrations:
                    conn.execute(text(stmt))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_targets_domain ON targets (domain)"))

    def init_db(self) -> None:
        """Create all tables and apply non-destructive migrations."""
        Base.metadata.create_all(bind=self.engine)
        self._migrate_targets_columns()

    def seed_initial_targets(
        self,
        targets_yaml_path: str | Path = "config/targets.yaml",
        fallback_config_path: str | Path = "config/config.yaml",
    ) -> int:
        """Seed initial targets from config/targets.yaml when targets table is empty."""
        with self.get_session() as session:
            count = session.scalar(select(func.count(Target.id))) or 0
            if count > 0:
                return 0

            seed_entries: list[dict] = []
            targets_file = Path(targets_yaml_path)
            fallback_file = Path(fallback_config_path)

            if targets_file.exists():
                raw = yaml.safe_load(targets_file.read_text(encoding="utf-8")) or {}
                seed_entries = raw.get("targets", []) if isinstance(raw, dict) else []
            elif fallback_file.exists():
                raw = yaml.safe_load(fallback_file.read_text(encoding="utf-8")) or {}
                seed_entries = raw.get("targets", []) if isinstance(raw, dict) else []

            if not seed_entries:
                seed_entries = [{"domain": "example.com", "is_active": True, "allowlist": []}]

            inserted = 0
            for entry in seed_entries:
                if not isinstance(entry, dict) or not entry.get("domain"):
                    continue
                domain = validate_and_normalize_domain(str(entry["domain"]))
                raw_allow = entry.get("allowlist") or entry.get("exclude_subdomains") or []
                allowlist = parse_allowlist_input(raw_allow)
                is_active = bool(entry.get("is_active", True))

                existing = session.scalars(select(Target).where(Target.domain == domain)).first()
                if existing is None:
                    target = Target(
                        domain=domain,
                        is_active=is_active,
                        scan_status="idle",
                    )
                    target.set_allowlist(allowlist)
                    session.add(target)
                    inserted += 1

            session.commit()
            if inserted:
                logger.info("Seeded %d initial target(s) into SQLite database.", inserted)
            return inserted

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
