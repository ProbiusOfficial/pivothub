"""代理工具启用集（GET/PUT /api/tools）。

启用集 = status=online 的工具；期望值从 data/meta.json 派生，
避免每接入一个适配器就要手改断言（chisel / frp 已接入 → 在线）。
"""

from __future__ import annotations

import json
from pathlib import Path

_META = json.loads(
    (Path(__file__).resolve().parent.parent / "data" / "meta.json").read_text(encoding="utf-8")
)
_ORDER = [t["name"] for t in _META["tools"]]
ALL_TOOLS = set(_ORDER)
ONLINE_TOOLS = [t["name"] for t in _META["tools"] if t.get("status") == "online"]
OFFLINE_TOOLS = [t["name"] for t in _META["tools"] if t.get("status") != "online"]


def _enabled(tools: list[dict]) -> list[str]:
    return [t["name"] for t in tools if t["enabled"]]


def test_tools_default_only_online_enabled(client):
    r = client.get("/api/tools")
    assert r.status_code == 200
    tools = {t["name"]: t for t in r.json()}
    assert set(tools) == ALL_TOOLS
    for name in ONLINE_TOOLS:
        assert tools[name]["status"] == "online", name
        assert tools[name]["enabled"] is True, name
    for name in OFFLINE_TOOLS:
        assert tools[name]["status"] == "offline", name
        assert tools[name]["enabled"] is False, name
    # state.tools 与 /api/tools 同源（前端下拉只读 state）
    st = client.get("/api/projects/proj-1/state").json()
    assert _enabled(st["tools"]) == ONLINE_TOOLS


def test_tools_reject_offline_and_unknown(client):
    # 未接入（offline）工具拒绝
    r = client.put("/api/tools", json={"enabled": OFFLINE_TOOLS})
    assert r.status_code == 422
    assert OFFLINE_TOOLS[0] in r.json()["detail"]
    # 未知工具拒绝
    r = client.put("/api/tools", json={"enabled": ["nope"]})
    assert r.status_code == 422
    assert "未知工具" in r.json()["detail"]
    # 被拒后现有启用集不变（仍为在线工具）
    assert _enabled(client.get("/api/tools").json()) == ONLINE_TOOLS
    # 在线工具（frp / chisel）可正常启用
    assert client.put("/api/tools", json={"enabled": ONLINE_TOOLS}).status_code == 200


def test_tools_toggle_persist_and_project_isolation(client, sandbox_project):
    # 关闭全部（下拉变空）→ 持久化到 state + 时间线留痕
    r = client.put("/api/tools", json={"enabled": []})
    assert r.status_code == 200
    assert _enabled(r.json()) == []
    st = client.get("/api/projects/proj-1/state").json()
    assert _enabled(st["tools"]) == []
    assert any(e["title"] == "代理工具设置更新" for e in st["timeline"])

    # 项目级设置：沙箱项目不受影响（回落到默认在线集）
    st2 = client.get(f"/api/projects/{sandbox_project}/state").json()
    assert _enabled(st2["tools"]) == ONLINE_TOOLS

    # 恢复默认
    r = client.put("/api/tools", json={"enabled": ONLINE_TOOLS})
    assert r.status_code == 200
    assert _enabled(r.json()) == ONLINE_TOOLS
    assert _enabled(client.get("/api/projects/proj-1/state").json()["tools"]) == ONLINE_TOOLS


def test_tools_project_scoped_write(client, sandbox_project):
    # 对沙箱项目写入启用集，不污染默认项目
    r = client.put(f"/api/tools?projectId={sandbox_project}", json={"enabled": []})
    assert r.status_code == 200
    assert _enabled(r.json()) == []
    assert _enabled(client.get(f"/api/projects/{sandbox_project}/state").json()["tools"]) == []
    assert _enabled(client.get("/api/projects/proj-1/state").json()["tools"]) == ONLINE_TOOLS
    # 不存在的项目 → 404
    assert client.put("/api/tools?projectId=proj-nope",
                      json={"enabled": ONLINE_TOOLS}).status_code == 404
