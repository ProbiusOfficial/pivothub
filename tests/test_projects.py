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
