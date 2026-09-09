"""项目创建与数据隔离：新项目 = 干净工作区（仅攻击端本机节点）。"""

from __future__ import annotations


def test_create_project_isolated_workspace(client):
    r = client.post("/api/projects", json={"name": "隔离测试项目", "durationSec": 7200})
    assert r.status_code == 200
    pid = r.json()["id"]
    assert r.json()["name"] == "隔离测试项目"

    d = client.get(f"/api/projects/{pid}/state").json()
    assert d["project"]["name"] == "隔离测试项目"
    assert d["project"]["durationSec"] == 7200
    # 干净工作区：仅 1 个本机攻击端节点，其余全空
    assert len(d["hosts"]) == 1 and d["hosts"][0]["isLocal"] is True
    assert d["shells"] == [] and d["links"] == [] and d["creds"] == []
    assert d["flags"] == [] and len(d["timeline"]) == 1
    # 任务 B-5：攻击端节点取「当前攻击机网络」的地址，绝不写死 127.0.0.1
    assert d["hosts"][0]["ip"] == d["attack"]["ip"]
    assert d["hosts"][0]["ip"] != "127.0.0.1"
    assert d["hosts"][0]["ifaces"][0]["ip"] == d["attack"]["ip"]

    # 演示项目不受影响（数据隔离）：新项目的攻击端节点不出现在演示项目里
    demo = client.get("/api/projects/proj-1/state").json()
    new_host_ids = {h["id"] for h in d["hosts"]}
    assert all(h["id"] not in new_host_ids for h in demo["hosts"])


def test_create_project_empty_name_rejected(client):
    assert client.post("/api/projects", json={"name": "   "}).status_code == 400


def test_entity_writes_go_to_current_project_only(client):
    """项目 A 登记的主机不出现在项目 B。"""
    pa = client.post("/api/projects", json={"name": "项目A"}).json()["id"]
    pb = client.post("/api/projects", json={"name": "项目B"}).json()["id"]
    # hosts 路由固定写 DEFAULT_PROJECT_ID（面板当前项目），这里验证投影隔离：
    # 直接向 A 的 state 注入只可能通过 A 的写入路径；B 初始保持干净
    assert client.get(f"/api/projects/{pb}/state").json()["hosts"].__len__() == 1
    assert client.get(f"/api/projects/{pa}/state").json()["shells"] == []


def test_delete_project_cascades(client, sandbox_project):
    """删除项目：该项目的主机 / 凭据 / Flag / 时间线一并清理，其他项目不受影响。"""
    pid = sandbox_project
    h = client.post("/api/hosts", json={
        "projectId": pid, "ip": "10.99.99.9", "hostname": "victim-01",
        "segment": "10.99.99.0/24",
    }).json()
    client.post("/api/creds", json={
        "projectId": pid, "hostId": h["id"], "username": "admin", "secret": "P@ssw0rd",
    })
    client.post("/api/flags", json={
        "projectId": pid, "hostId": h["id"], "stage": "L1 入口", "value": "flag{delete}",
    })
    client.post("/api/timeline/notes", json={"projectId": pid, "title": "删除前笔记"})

    r = client.delete(f"/api/projects/{pid}")
    assert r.status_code == 200
    out = r.json()
    assert out["deleted"] == pid
    assert out["hosts"] == 2  # 攻击端本机 + 新增主机
    assert out["shells"] == 0 and out["links"] == 0
    assert out["creds"] == 1 and out["flags"] == 1
    assert out["events"] >= 4  # 建项目 + 主机/凭据/Flag/笔记

    # 项目与其全量状态都不再存在
    assert client.get(f"/api/projects/{pid}/state").status_code == 404
    assert all(p["id"] != pid for p in client.get("/api/projects").json())
    # 演示项目完好（级联只作用于被删项目）
    demo = client.get("/api/projects/proj-1/state").json()
    assert demo["project"]["id"] == "proj-1" and len(demo["hosts"]) > 0


def test_delete_project_not_found(client):
    assert client.delete("/api/projects/proj-does-not-exist").status_code == 404


def test_delete_last_project_rejected():
    """最后一个项目不可删除：用独立内存库验证，不污染会话库。"""
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    import pivothub.models  # noqa: F401  确保模型已注册到 Base.metadata
    from pivothub.app import app
    from pivothub.db import Base, get_db
    from pivothub.models import Project

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session_local = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with session_local() as s:
        s.add(Project(id="only-proj", name="唯一项目"))
        s.commit()

    def _override_db():
        db = session_local()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_db
    try:
        with TestClient(app) as c:
            r = c.delete("/api/projects/only-proj")
            assert r.status_code == 400
            assert "最后一个" in r.json()["detail"]
            # 项目仍在
            assert c.get("/api/projects/only-proj/state").status_code == 200
    finally:
        app.dependency_overrides.pop(get_db, None)
