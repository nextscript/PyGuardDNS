import os
import sys

import pytest

# Keep test runs away from a real database next to app.py.
os.environ.setdefault("LOCALDNSGUARD_DB_IN_MEMORY", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(scope="session", autouse=True)
def _app_schema():
    """Create the SQLite schema once, so tests that touch settings or the
    query log don't depend on another test having initialised the DB."""
    import app

    app.init_db()
    yield
