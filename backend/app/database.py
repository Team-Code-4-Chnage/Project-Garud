"""
SQLite database models — real persistence, not in-memory mock arrays.
Uses SQLAlchemy async with aiosqlite.

Schema additions (from audit fixes):
  - FlowRecordDB.source     : "live_capture" | "simulated" | "csv_upload" | "api"
  - SessionDB.source        : same, from first flow in the session
  - SessionDB.direction     : "inbound" | "outbound" | "internal" (RFC1918 classification)
  - SessionDB.max_stage_reached : highest MITRE stage index seen (monotonic, never decreases)
"""
import logging
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from .config import DATABASE_URL, DB_DIR

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


class FlowRecordDB(Base):
    __tablename__ = "flow_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_key = Column(String(128), index=True, nullable=False)
    src_ip = Column(String(45), nullable=True)
    dst_ip = Column(String(45), nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    source = Column(String(32), nullable=True, default="api")

    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(16), nullable=True, default="TCP")
    process_name = Column(String(64), nullable=True)
    app_name = Column(String(64), nullable=True)
    direction = Column(String(16), nullable=True)
    src_identity = Column(String(32), nullable=True)
    dst_identity = Column(String(32), nullable=True)

    flow_duration = Column(Float)
    tot_fwd_pkts = Column(Float)
    tot_bwd_pkts = Column(Float)
    fwd_pkt_len_mean = Column(Float)
    bwd_pkt_len_mean = Column(Float)
    flow_bytes_s = Column(Float)
    flow_pkts_s = Column(Float)
    flow_iat_mean = Column(Float)
    flow_iat_std = Column(Float)
    fwd_iat_mean = Column(Float)
    bwd_iat_mean = Column(Float)
    syn_flag_cnt = Column(Float)
    ack_flag_cnt = Column(Float)
    fin_flag_cnt = Column(Float)
    rst_flag_cnt = Column(Float)
    psh_flag_cnt = Column(Float)
    urg_flag_cnt = Column(Float)
    down_up_ratio = Column(Float)
    pkt_size_avg = Column(Float)
    ttl_variance = Column(Float)
    tcp_win_size = Column(Float)
    retransmit_cnt = Column(Float)

    infiltration_prob = Column(Float, nullable=True)
    predicted_stage = Column(String(32), nullable=True)


class SessionDB(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_key = Column(String(128), unique=True, index=True, nullable=False)
    src_ip = Column(String(45), nullable=True, index=True)
    dst_ip = Column(String(45), nullable=True, index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    flow_count = Column(Integer, default=0)
    latest_risk_score = Column(Float, default=0.0)
    latest_stage = Column(String(32), default="Benign")

    max_stage_reached = Column(String(32), default="Benign")

    direction = Column(String(16), default="unknown")

    process_name = Column(String(64), nullable=True)
    app_name = Column(String(64), nullable=True)
    tot_fwd_pkts = Column(Float, default=0.0)
    tot_bwd_pkts = Column(Float, default=0.0)
    src_identity = Column(String(32), nullable=True)
    dst_identity = Column(String(32), nullable=True)

    source = Column(String(32), nullable=True, default="api")

    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AlertDB(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_key = Column(String(128), index=True, nullable=False)
    severity = Column(String(16), nullable=False)
    infiltration_prob = Column(Float, nullable=False)
    predicted_stage = Column(String(32), nullable=False)
    recommended_action = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    acknowledged = Column(Boolean, default=False)


engine = create_async_engine(DATABASE_URL, echo=False)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db():
    """Create tables if they don't exist."""
    DB_DIR.mkdir(parents=True, exist_ok=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database initialized at %s", DATABASE_URL)


async def get_db() -> AsyncSession:
    """Dependency injection for FastAPI routes."""
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()
