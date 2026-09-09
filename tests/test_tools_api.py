"""代理工具启用集（GET/PUT /api/tools）：MS4 仅 chisel 已接入，其余为下线状态。"""

from __future__ import annotations

ALL_TOOLS = {"frp", "nps", "Neo-reGeorg", "EW", "Stowaway", "Venom", "chisel", "ligolo-ng"}


def _enabled(tools: list[dict]) -> list[str]:
    return [t["name"] for t in tools if t["enabled"]]


def test_tools_default_only_chisel_enabled(client):
    r = client.get("/api/tools")
    assert r.status_code == 200
    tools = {t["name"]: t for t in r.json()}
    assert set(tools) == ALL_TOOLS
    assert tools["chisel"]["status"] == "online"
    assert tools["chisel"]["enabled"] is True
    for name, t in tools.items():
        if name == "chisel":
            continue
        assert t["status"] == "offline", name
        assert t["enabled"] is False, name
    # state.tools 与 /api/tools 同源（前端下拉只读 state）
    st = client.get("/api/projects/proj-1/state").json()
    assert _enabled(st["tools"]) == ["chisel"]


def test_tools_reject_offline_and_unknown(client):
    r = client.put("/api/tools", json={"enabled": ["frp"]})
    assert r.status_code == 422
    assert "chisel" in r.json()["detail"]
    r = client.put("/api/tools", json={"enabled": ["chisel", "ligolo-ng"]})
    assert r.status_code == 422
    r = client.put("/api/tools", json={"enabled": ["nope"]})
    assert r.status_code == 422
    assert "未知工具" in r.json()["detail"]
    # 被拒后现有启用集不变
    assert _enabled(client.get("/api/tools").json()) == ["chisel"]


def test_tools_toggle_persist_and_project_isolation(client, sandbox_project):
    # 关闭 chisel（下拉变空）→ 持久化到 state + 时间线留痕
    r = client.put("/api/tools", json={"enabled": []})
    assert r.status_code == 200
    assert _enabled(r.json()) == []
    st = client.get("/api/projects/proj-1/state").json()
    assert _enabled(st["tools"]) == []
    assert any(e["title"] == "代理工具设置更新" for e in st["timeline"])

    # 项目级设置：沙箱项目不受影响（回落到默认 chisel）
    st2 = client.get(f"/api/projects/{sandbox_project}/state").json()
    assert _enabled(st2["tools"]) == ["chisel"]

    # 恢复默认
    r = client.put("/api/tools", json={"enabled": ["chisel"]})
    assert r.status_code == 200
    assert _enabled(r.json()) == ["chisel"]
    assert _enabled(client.get("/api/projects/proj-1/state").json()["tools"]) == ["chisel"]


def test_tools_project_scoped_write(client, sandbox_project):
    # 对沙箱项目写入启用集，不污染默认项目
    r = client.put(f"/api/tools?projectId={sandbox_project}", json={"enabled": []})
    assert r.status_code == 200
    assert _enabled(r.json()) == []
    assert _enabled(client.get(f"/api/projects/{sandbox_project}/state").json()["tools"]) == []
    assert _enabled(client.get("/api/projects/proj-1/state").json()["tools"]) == ["chisel"]
    # 不存在的项目 → 404
    assert client.put("/api/tools?projectId=proj-nope", json={"enabled": ["chisel"]}).status_code == 404
