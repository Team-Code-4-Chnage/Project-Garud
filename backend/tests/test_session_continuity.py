"""
A continuous (src_ip, dst_ip) conversation must stay ONE tracked session even when it spans more
than one SESSION_TIME_BUCKET_SECONDS window. Before this fix, session_key was minted purely from
(src, dst, wall-clock-bucket), so any app with a connection open longer than 5 minutes -- a browser
tab, a music stream -- was split into a new "session" every time the bucket rolled over, and showed
up as duplicate rows (e.g. Chrome or Spotify appearing twice) in the tracked-sessions view. It also
reset the model's sliding window for that conversation on every rollover, losing temporal context.
"""
import asyncio
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from app.config import FLOW_FEATURES, SESSION_IDLE_TIMEOUT_SECONDS  # noqa: E402
from app.database import SessionDB, async_session, init_db  # noqa: E402
from app.ingestion import resolve_session_key  # noqa: E402
from app.model_loader import artifacts  # noqa: E402
from app.schemas import FlowRecord  # noqa: E402


def _setup():
    asyncio.run(init_db())
    if not artifacts.is_loaded:
        artifacts.load()


_setup()


def flow(src="203.0.113.5", dst="198.51.100.9"):
    return FlowRecord(**{k: 1.0 for k in FLOW_FEATURES}, src_ip=src, dst_ip=dst, src_port=51000,
                      dst_port=443, protocol="TCP", timestamp=datetime.now(timezone.utc), source="live_capture")


async def _seed_session(db, key, src, dst, last_seen):
    db.add(SessionDB(session_key=key, src_ip=src, dst_ip=dst, flow_count=1,
                     first_seen=last_seen, last_seen=last_seen))
    await db.commit()


def test_recent_activity_reuses_the_same_session_key():
    async def run():
        async with async_session() as db:
            key1 = await resolve_session_key(db, "203.0.113.6", "198.51.100.10", datetime.now(timezone.utc))
            await _seed_session(db, key1, "203.0.113.6", "198.51.100.10", datetime.now(timezone.utc))
            key2 = await resolve_session_key(db, "203.0.113.6", "198.51.100.10", datetime.now(timezone.utc))
        return key1, key2
    key1, key2 = asyncio.run(run())
    assert key1 == key2


def test_activity_spanning_a_bucket_rollover_still_reuses_the_key():
    src, dst = "203.0.113.7", "198.51.100.11"

    async def run():
        async with async_session() as db:
            key1 = await resolve_session_key(db, src, dst, datetime.now(timezone.utc))
            # last_seen is almost SESSION_IDLE_TIMEOUT_SECONDS in the past -- likely a different
            # calendar bucket by now -- but the gap is still under the idle timeout: a continuation
            long_ago = datetime.now(timezone.utc) - timedelta(seconds=SESSION_IDLE_TIMEOUT_SECONDS - 5)
            await _seed_session(db, key1, src, dst, long_ago)
            key2 = await resolve_session_key(db, src, dst, datetime.now(timezone.utc))
        return key1, key2
    key1, key2 = asyncio.run(run())
    assert key1 == key2


def test_a_real_gap_starts_a_new_session():
    src, dst = "203.0.113.8", "198.51.100.12"
    stale_key = "203.0.113.8->198.51.100.12@stale-marker"

    async def run():
        async with async_session() as db:
            stale = datetime.now(timezone.utc) - timedelta(seconds=SESSION_IDLE_TIMEOUT_SECONDS + 30)
            await _seed_session(db, stale_key, src, dst, stale)
            return await resolve_session_key(db, src, dst, datetime.now(timezone.utc))
    resolved = asyncio.run(run())
    assert resolved != stale_key


def test_different_destination_never_shares_a_session():
    async def run():
        async with async_session() as db:
            key_a = await resolve_session_key(db, "203.0.113.9", "198.51.100.13", datetime.now(timezone.utc))
            key_b = await resolve_session_key(db, "203.0.113.9", "198.51.100.14", datetime.now(timezone.utc))
        return key_a, key_b
    key_a, key_b = asyncio.run(run())
    assert key_a != key_b


def test_api_keeps_one_session_row_across_a_bucket_rollover():
    from fastapi.testclient import TestClient
    from sqlalchemy import select

    from app.main import app

    src, dst = "203.0.113.20", "198.51.100.20"
    with TestClient(app) as client:
        r1 = client.post("/ingest", json=flow(src, dst).model_dump(mode="json"))
        assert r1.status_code == 200
        key = r1.json()["session_key"]

        # the same conversation continues just under the idle timeout later: back-date the stored
        # session's last_seen, then send a second flow "now"
        async def backdate():
            async with async_session() as db:
                row = (await db.execute(select(SessionDB).where(SessionDB.session_key == key))).scalar_one()
                row.last_seen = datetime.now(timezone.utc) - timedelta(seconds=SESSION_IDLE_TIMEOUT_SECONDS - 10)
                await db.commit()
        asyncio.run(backdate())

        r2 = client.post("/ingest", json=flow(src, dst).model_dump(mode="json"))
        assert r2.status_code == 200
        assert r2.json()["session_key"] == key

        sessions = client.get("/sessions", params={"limit": 200}).json()
        matching = [s for s in sessions if s["src_ip"] == src and s["dst_ip"] == dst]
        assert len(matching) == 1
        assert matching[0]["flow_count"] == 2
