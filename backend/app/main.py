import logging
import secrets
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import (
    ALLOWED_ORIGINS,
    API_KEY,
    ARTIFACTS_DIR,
    FLOW_FEATURES,
    N_FEATURES,
    STAGES,
)
from .database import init_db
from .model_loader import artifacts
from .routes import (
    alerts,
    explain,
    forecast,
    ingest,
    mitre,
    pcap,
    predict,
    reports,
    system,
    ws,
)
from .schemas import HealthResponse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 60)
    logger.info("Network Attack Forecasting Service — Starting")
    logger.info("=" * 60)

    try:
        artifacts.load()
    except Exception as e:
        logger.critical("FATAL: Failed to load model artifacts: %s", e)
        logger.critical("The service CANNOT run without valid artifacts.")
        logger.critical("Expected artifacts in: %s", ARTIFACTS_DIR)
        raise

    await init_db()
    await _migrate_db()

    from .routes.system import CycleState
    CycleState.initialize()
    logger.info("Active monitoring cycle initialized: %s (started %s)", CycleState.cycle_id, CycleState.started_at.isoformat())

    if not API_KEY:
        logger.warning("=" * 60)
        logger.warning("SECURITY NOTICE: API_KEY is not configured in environment.")
        logger.warning("Running in unauthenticated evaluation mode. For production, set API_KEY.")
        logger.warning("=" * 60)
    else:
        logger.info("Security: API_KEY enforcement active.")

    logger.info("=" * 60)
    logger.info("Service ready — all systems operational")
    logger.info("=" * 60)

    yield

    logger.info("Shutting down... archiving active cycle to disk...")
    try:
        from .database import async_session
        from .routes.system import archive_and_reset_cycle
        async with async_session() as db:
            await archive_and_reset_cycle(db, reason="shutdown")
    except Exception as e:
        logger.warning("Shutdown cycle archival skipped: %s", e)


async def _migrate_db():
    """Add new columns to existing SQLite databases without dropping tables."""
    from .database import engine
    new_columns = [
        ("flow_records", "source", "VARCHAR(32) DEFAULT 'api'"),
        ("flow_records", "src_port", "INTEGER"),
        ("flow_records", "dst_port", "INTEGER"),
        ("flow_records", "protocol", "VARCHAR(16) DEFAULT 'TCP'"),
        ("flow_records", "process_name", "VARCHAR(64)"),
        ("flow_records", "app_name", "VARCHAR(64)"),
        ("flow_records", "direction", "VARCHAR(16)"),
        ("flow_records", "src_identity", "VARCHAR(32)"),
        ("flow_records", "dst_identity", "VARCHAR(32)"),
        ("sessions", "source", "VARCHAR(32) DEFAULT 'api'"),
        ("sessions", "direction", "VARCHAR(16) DEFAULT 'unknown'"),
        ("sessions", "max_stage_reached", "VARCHAR(32) DEFAULT 'Benign'"),
        ("sessions", "process_name", "VARCHAR(64)"),
        ("sessions", "app_name", "VARCHAR(64)"),
        ("sessions", "tot_fwd_pkts", "FLOAT DEFAULT 0.0"),
        ("sessions", "tot_bwd_pkts", "FLOAT DEFAULT 0.0"),
        ("sessions", "src_identity", "VARCHAR(32)"),
        ("sessions", "dst_identity", "VARCHAR(32)"),
    ]
    import sqlalchemy
    async with engine.begin() as conn:
        for table, col, col_def in new_columns:
            try:
                await conn.execute(
                    sqlalchemy.text(f"ALTER TABLE {table} ADD COLUMN {col} {col_def}")
                )
                logger.info("Migration: added column %s.%s", table, col)
            except Exception:
                pass


app = FastAPI(
    title="Network Attack Forecasting API",
    description=(
        "Network attack forecasting from live traffic data. "
        "LSTM-based stage classification and infiltration probability forecasting "
        "with feature attribution explainability."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded
    from slowapi.middleware import SlowAPIMiddleware
    from slowapi.util import get_remote_address

    limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"])
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)
    logger.info("SlowAPI rate limiter enabled (120 req/min default)")
except ImportError:
    logger.info("SlowAPI not installed — proceeding without rate limiter")


@app.middleware("http")
async def api_key_auth_middleware(request: Request, call_next):
    if API_KEY and not request.url.path.startswith(("/health", "/docs", "/openapi.json", "/redoc", "/ws")):
        key = request.headers.get("X-API-Key") or ""
        if not secrets.compare_digest(key.encode(), API_KEY.encode()):
            return JSONResponse(
                status_code=401,
                content={"detail": "Unauthorized: Invalid or missing X-API-Key header"},
            )
    return await call_next(request)


app.include_router(predict.router, tags=["Prediction"])
app.include_router(forecast.router, tags=["Forecasting"])
app.include_router(explain.router, tags=["Explainability"])
app.include_router(alerts.router, tags=["Alerts"])
app.include_router(ingest.router, tags=["Ingestion"])
app.include_router(pcap.router, tags=["PCAP Ingestion"])
app.include_router(reports.router, tags=["Reports"])
app.include_router(mitre.router, tags=["MITRE"])
app.include_router(system.router, tags=["System"])
app.include_router(ws.router, tags=["Live Feed"])


@app.get("/health", response_model=HealthResponse)
async def health_check():
    from .database import engine
    from .routes.system import SystemState
    db_ok = False
    try:
        async with engine.connect() as conn:
            await conn.execute(
                __import__("sqlalchemy").text("SELECT 1")
            )
            db_ok = True
    except Exception:
        pass

    model_ok = artifacts.is_loaded

    return HealthResponse(
        status="ok" if (model_ok and db_ok) else "degraded",
        model_loaded=model_ok,
        db_connected=db_ok,
        artifacts_path=str(ARTIFACTS_DIR),
        features_count=N_FEATURES,
        features=FLOW_FEATURES,
        stages=STAGES,
        device=str(artifacts.device) if model_ok else "unavailable",
        system_mode=SystemState.mode,
        model_version=artifacts.model_version if model_ok else None,
        model_hash=artifacts.model_hash if model_ok else None,
        scaler_hash=artifacts.scaler_hash if model_ok else None,
        hidden_size=artifacts.config.get("hidden_size") if model_ok and artifacts.config else None,
        num_layers=artifacts.config.get("num_layers") if model_ok and artifacts.config else None,
        dropout=artifacts.config.get("lstm_dropout") if model_ok and artifacts.config else None,
        window_size=artifacts.config.get("window") if model_ok and artifacts.config else None,
    )


@app.get("/")
async def root():
    return {
        "service": "Network Attack Forecasting API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
    }
