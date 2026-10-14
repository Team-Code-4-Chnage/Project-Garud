"""
Test database isolation.

Without this, every test run reads and writes backend/data/forecaster.db -- the same file a locally
running dev server uses. Session, flow and alert rows left behind by test runs (or by manual API
calls made while debugging, as happened during development of this fix) then show up mixed into the
real dashboard, which looks exactly like unexplained duplicate or stale sessions. Each test run now
gets its own throwaway sqlite file instead.

Must run before any `app.*` module is imported, since DB_DIR is read at import time in app/config.py.
Pytest imports a directory's conftest.py before collecting the test modules in that directory, so this
file has no imports of its own from the app package.
"""
import os
import tempfile

os.environ["DB_DIR"] = tempfile.mkdtemp(prefix="netforecast_test_db_")
os.environ["AUTO_START_CAPTURE"] = "0"  # tests must not sniff the developer machine
