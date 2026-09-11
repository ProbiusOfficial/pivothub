"""空库兜底：默认项目必须始终存在（移植换机后「WS 连接失败」的根因修复）。

前端启动第一步是拉 /api/projects/{id}/state；项目表为空时该接口 404，
前端会跳过 WS 连接并显示「后端不可用」。因此：
- init_db 播种失败（data/ 缺失）时必须回退为空白默认项目；
- 运行期 /state 命中空库必须自愈创建默认项目。
"""

from __future__ import annotations

import pytest

from pivothub.config import DEFAULT_PROJECT_ID
from pivothub.db import ensure_default_project, get_session_factory, init_db
from pivothub.models import (
    Credential, Flag, Host, Project, ProxyLink, Shell, TimelineEvent,
)


def _wipe_projects() -> None:
    """清空项目表模拟「移植到新机器的空库」（绕过 API 的至少保留一个保护）。"""
    db = get_session_factory()()
    try:
        for model in (TimelineEvent, Flag, Credential, Shell, ProxyLink, Host, Project):
            db.query(model).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _project_count() -> int:
    db = get_session_factory()()
    try:
        return db.query(Project).count()
    finally:
        db.close()


@pytest.fixture(autouse=True)
def _reseed_after():
    """本文件的用例会清空项目表；结束后重新播种演示库，不影响其他测试文件。"""
    yield
    _wipe_projects()
    init_db()


def test_state_route_self_heals_empty_db(client):
    """/state 命中空库：自动创建默认项目并正常返回 200（前端 WS 因此能连上）。"""
    _wipe_projects()
    assert _project_count() == 0
    r = client.get(f"/api/projects/{DEFAULT_PROJECT_ID}/state")
    assert r.status_code == 200, r.text
    body = r.json()
    assert any(p["id"] == DEFAULT_PROJECT_ID for p in body["projects"])
    # 最小工作区：攻击端本机节点存在（拓扑根）
    assert any(h.get("isLocal") for h in body["hosts"])
    assert _project_count() == 1


def test_state_missing_project_still_404_when_named_project_requested(client):
    """请求的是别的项目且库非空（默认项目已被兜底建出）：仍应 404，不误建。"""
    _wipe_projects()
    client.get(f"/api/projects/{DEFAULT_PROJECT_ID}/state")  # 触发兜底
    r = client.get("/api/projects/proj-nope/state")
    assert r.status_code == 404
    assert _project_count() == 1  # 只多了兜底默认项目


def test_ensure_default_project_noop_when_projects_exist(client):
    """默认项目已存在：幂等返回既有对象；库非空但缺默认项目时不凭空插手。"""
    before = _project_count()
    assert before >= 1
    db = get_session_factory()()
    try:
        # proj-1 已在（兜底/演示库）：幂等返回它，不新建
        p = ensure_default_project(db)
        assert p is not None and p.id == DEFAULT_PROJECT_ID
        db.rollback()
    finally:
        db.close()

    # 造一个非默认项目保住「库非空」，再删掉默认项目 → ensure 不得再造
    r = client.post("/api/projects", json={"name": "非空占位项目"})
    assert r.status_code == 200, r.text
    db2 = get_session_factory()()
    try:
        for model in (TimelineEvent, Flag, Credential, Shell, ProxyLink, Host):
            db2.query(model).filter(
                model.project_id == DEFAULT_PROJECT_ID
            ).delete(synchronize_session=False)
        proj = db2.get(Project, DEFAULT_PROJECT_ID)
        if proj is not None:
            db2.delete(proj)
            db2.commit()
        assert ensure_default_project(db2) is None
        db2.rollback()
    finally:
        db2.close()
    assert _project_count() >= 1


def test_init_db_seed_failure_falls_back_to_default_project(client, monkeypatch):
    """播种失败（移植后 data/ 缺失/损坏）：回退建空白默认项目。

    meta.json 一并缺失也在覆盖范围内 —— 旧实现在这条回退路径上会被
    default_attack → load_meta 的 FileNotFoundError 二次炸掉，面板直接起不来。
    """

    def _missing(path):
        raise FileNotFoundError(f"data/ not copied to this machine: {path}")

    import pivothub.db as dbmod

    _wipe_projects()
    # 底层文件读取全部失败 = 整个 data/ 目录没随项目复制（load_meta 自身须容错回退 {}）
    monkeypatch.setattr(dbmod, "_load_json", _missing)
    init_db()  # 不应抛异常
    db = get_session_factory()()
    try:
        p = db.get(Project, DEFAULT_PROJECT_ID)
        assert p is not None, "播种失败也必须兜底出默认项目"
        assert p.settings.get("attack", {}).get("ip"), "攻击机网络应有内置默认值"
        local = db.query(Host).filter(Host.project_id == p.id, Host.is_local.is_(True)).all()
        assert len(local) == 1, "默认项目应带攻击端本机节点（拓扑根）"
    finally:
        db.close()
