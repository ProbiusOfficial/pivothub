"""Flag 记录：增 / 改 / 删 + 导出拓扑真实化。

覆盖：
- 新建 → PATCH 改 value/stage/hostId/projectId/note → DELETE 全链路生效
- 删除不存在的 Flag → 404
- 改绑一致性校验：跨项目脏写 / 不存在主机 / 不存在项目 均如实报错
- 导出拓扑：不得出现硬编码 127.0.0.1；含主机 IP
"""

from __future__ import annotations


def _new_project(client) -> str:
    r = client.post("/api/projects", json={"name": "flag 测试项目"})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _new_host(client, project_id: str, ip: str, layer: str = "L1") -> str:
    r = client.post("/api/hosts", json={
        "projectId": project_id, "ip": ip, "hostname": f"h-{ip}",
        "layer": layer, "owned": True,
    })
    assert r.status_code == 200, r.text
    return r.json()["id"]


def test_flag_crud_lifecycle(client, sandbox_project):
    pid = sandbox_project
    hid = _new_host(client, pid, "10.99.1.11")

    # 新建（带备注）
    r = client.post("/api/flags", json={
        "projectId": pid, "hostId": hid, "stage": "L1 入口",
        "value": "flag{abc}", "submitted": False, "note": "初登记",
    })
    assert r.status_code == 200, r.text
    f = r.json()
    assert f["value"] == "flag{abc}"
    assert f["stage"] == "L1 入口"
    assert f["note"] == "初登记"
    fid = f["id"]

    # PATCH 改 value / stage / note（stage 允许任意字符串，不再限定四值枚举）
    r = client.patch(f"/api/flags/{fid}", json={
        "value": "flag{xyz}", "stage": "边界", "note": "改绑记录",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["value"] == "flag{xyz}"
    assert body["stage"] == "边界"
    assert body["note"] == "改绑记录"

    # PATCH 改 hostId（同项目内）
    hid2 = _new_host(client, pid, "10.99.1.12")
    r = client.patch(f"/api/flags/{fid}", json={"hostId": hid2})
    assert r.status_code == 200, r.text
    assert r.json()["hostId"] == hid2

    # PATCH 提交状态（A12：标记已交 / 撤销，前端「Flag 墙」直接切换）
    r = client.patch(f"/api/flags/{fid}", json={"submitted": True})
    assert r.status_code == 200, r.text
    assert r.json()["submitted"] is True
    r = client.patch(f"/api/flags/{fid}", json={"submitted": False})
    assert r.status_code == 200, r.text
    assert r.json()["submitted"] is False

    # PATCH 改 projectId + hostId（跨项目一致：目标项目存在且主机属于该项目）
    pid2 = _new_project(client)
    hid2b = _new_host(client, pid2, "10.99.2.21")
    r = client.patch(f"/api/flags/{fid}", json={"projectId": pid2, "hostId": hid2b})
    assert r.status_code == 200, r.text

    # 验证已从 pid 移除、落到 pid2
    st2 = client.get(f"/api/projects/{pid2}/state").json()
    fl = next((x for x in st2["flags"] if x["id"] == fid), None)
    assert fl is not None and fl["hostId"] == hid2b
    st1 = client.get(f"/api/projects/{pid}/state").json()
    assert all(x["id"] != fid for x in st1["flags"])

    # 一致性校验：仅改项目、未给该项目主机 → 400（不静默写坏）
    r = client.patch(f"/api/flags/{fid}", json={"projectId": pid})
    assert r.status_code == 400, r.text

    # 一致性校验：改绑到不存在的主机 → 400
    r = client.patch(f"/api/flags/{fid}", json={"hostId": "host-nope"})
    assert r.status_code == 400, r.text

    # 一致性校验：改绑到不存在的项目 → 404
    r = client.patch(f"/api/flags/{fid}", json={"projectId": "proj-none"})
    assert r.status_code == 404, r.text

    # 删除生效
    r = client.delete(f"/api/flags/{fid}")
    assert r.status_code == 200, r.text
    assert r.json()["deleted"] == fid

    # 删除不存在 → 404
    r = client.delete(f"/api/flags/{fid}")
    assert r.status_code == 404, r.text


def test_patch_nonexistent_flag_404(client, sandbox_project):
    r = client.patch("/api/flags/flag-nope", json={"value": "x"})
    assert r.status_code == 404


def test_export_topo_renders_hosts_no_hardcoded_ip(client, project_id):
    """导出拓扑：不得出现硬编码 127.0.0.1；拓扑段应包含攻击端根与主机 IP。"""
    r = client.get("/api/export", params={"format": "md", "projectId": project_id})
    assert r.status_code == 200
    md = r.text
    # 不得再出现写死的攻击端桩地址（127.0.0.11 这类真实种子主机 IP 不受影响）
    assert "攻击端 127.0.0.1" not in md

    # 切出拓扑段（## 1. 网络拓扑 … ## 2. 跳板链参数）
    topo = md.split("## 1. 网络拓扑")[1].split("## 2. 跳板链参数")[0]
    # 攻击端根节点应取全局设置的攻击机 IP（192.0.2.10），而非 127.0.0.1
    assert "攻击端 192.0.2.10" in topo
    # 种子项目含入口机 192.168.100.2，拓扑树应渲染其 IP
    assert "192.168.100.2" in topo
