"""阶段自定义（PUT /api/stages，A12）：项目级阶段名，Flag 墙分组统计的数据源。"""

from __future__ import annotations

import json
from pathlib import Path

_META = json.loads(
    (Path(__file__).resolve().parent.parent / "data" / "meta.json").read_text(encoding="utf-8")
)
DEFAULT_STAGES = _META["stageNames"]


def test_stages_default_from_meta(client, project_id):
    st = client.get(f"/api/projects/{project_id}/state").json()
    assert st["stageNames"] == DEFAULT_STAGES


def test_stages_set_and_reflect_in_state(client, sandbox_project):
    custom = ["打点", "横向", "提权", "拿旗"]
    r = client.put(f"/api/stages?projectId={sandbox_project}",
                   json={"projectId": sandbox_project, "stages": custom})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True and body["stages"] == custom
    # state 同步（Flag 墙读这个字段）
    st = client.get(f"/api/projects/{sandbox_project}/state").json()
    assert st["stageNames"] == custom


def test_stages_dedupe_and_trim(client, sandbox_project):
    r = client.put(f"/api/stages", json={
        "projectId": sandbox_project,
        "stages": ["  L1  ", "L1", "", "L2", " L2 ", "   "],
    })
    assert r.status_code == 200, r.text
    assert r.json()["stages"] == ["L1", "L2"]


def test_stages_empty_falls_back_to_default(client, sandbox_project):
    # 先设自定义
    client.put("/api/stages", json={"projectId": sandbox_project, "stages": ["X", "Y"]})
    assert client.get(f"/api/projects/{sandbox_project}/state").json()["stageNames"] == ["X", "Y"]
    # 空列表 = 恢复默认
    r = client.put("/api/stages", json={"projectId": sandbox_project, "stages": []})
    assert r.status_code == 200, r.text
    assert r.json()["stages"] == DEFAULT_STAGES
    assert client.get(f"/api/projects/{sandbox_project}/state").json()["stageNames"] == DEFAULT_STAGES


def test_stages_project_isolation(client, project_id, sandbox_project):
    client.put("/api/stages", json={"projectId": sandbox_project, "stages": ["仅沙箱"]})
    # 默认项目不受影响
    assert client.get(f"/api/projects/{project_id}/state").json()["stageNames"] == DEFAULT_STAGES


def test_stages_unknown_project_404(client):
    r = client.put("/api/stages", json={"projectId": "proj-nope", "stages": ["A"]})
    assert r.status_code == 404


def test_flag_accepts_custom_stage(client, sandbox_project):
    """阶段自定义后，Flag 可直接用新阶段名（Flag.stage 不限定枚举）。"""
    hid = client.post("/api/hosts", json={
        "projectId": sandbox_project, "ip": "10.98.7.7", "layer": "L1",
    }).json()["id"]
    r = client.post("/api/flags", json={
        "projectId": sandbox_project, "hostId": hid, "stage": "打点", "value": "flag{s}",
    })
    assert r.status_code == 200, r.text
    assert r.json()["stage"] == "打点"
