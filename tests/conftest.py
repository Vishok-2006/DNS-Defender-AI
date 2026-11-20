import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest.fixture()
def cfg(tmp_path):
    """SQLite by default; set TEST_DATABASE_URL=postgresql://... to run the suite on PostgreSQL."""
    url = os.environ.get("TEST_DATABASE_URL")
    if url:
        from app.db import Base, make_engine
        from app import models  # noqa: F401
        eng = make_engine(url)
        Base.metadata.drop_all(eng)     # clean slate for every test
        eng.dispose()
    else:
        url = f"sqlite:///{tmp_path / 'test.db'}"
    return Settings(DATABASE_URL=url,
                    DNS_BLOCKLIST_PATH=str(tmp_path / "rules" / "blocked.conf"),
                    CAPTURE_MODE="off", API_KEY=None)


@pytest.fixture()
def client(cfg):
    from fastapi.testclient import TestClient
    with TestClient(create_app(cfg)) as c:
        c.cfg = cfg
        yield c
