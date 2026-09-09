"""pytest 公共夹具：每会话独立临时 SQLite，避免污染开发库。"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

# 必须在导入 pivothub 之前设置（config 在导入期读取）
_TMPDIR = tempfile.mkdtemp(prefix="pivothub-test-")
os.environ["PIVOTHUB_DB_PATH"] = str(Path(_TMPDIR) / "test.db")
os.environ["PIVOTHUB_DATA_DIR"] = str(Path(__file__).resolve().parent.parent / "data")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from pivothub.app import app  # noqa: E402
from pivothub.db import init_db  # noqa: E402


@pytest.fixture(scope="session")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def project_id():
    return "proj-1"


@pytest.fixture()
def sandbox_project(client):
    """新建项目作为用例沙箱：避免真实链路/主机写入污染演示项目（proj-1）的断言。"""
    r = client.post("/api/projects", json={"name": "pytest 沙箱项目"})
    assert r.status_code == 200
    return r.json()["id"]
