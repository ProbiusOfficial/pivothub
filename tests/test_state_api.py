"""状态聚合接口契约测试：键与字段名必须与前端契约一致。"""

from __future__ import annotations

EXPECTED_KEYS = {
    "project", "projects", "segments", "attack", "hosts", "shells", "links", "creds",
    "flags", "timeline", "probes", "tools", "commands", "injectTips",
    "ttyFixes", "shellTypes", "encoders", "credKinds", "layers", "stageNames",
    "scanSample",
}


def test_state_top_level_keys(client, project_id):
    d = client.get(f"/api/projects/{project_id}/state").json()
    assert set(d.keys()) == EXPECTED_KEYS


def test_state_counts_match_seed(client):
    d = client.get(f"/api/projects/proj-1/state").json()
    assert len(d["hosts"]) >= 10  # 演示项目 10 台（含攻击端）
    assert len(d["shells"]) >= 5
    assert len(d["links"]) >= 5
    assert len(d["creds"]) >= 7
    assert len(d["flags"]) >= 5
    assert len(d["timeline"]) >= 17
    assert len(d["commands"]) >= 16
    assert len(d["ttyFixes"]) == 13
    assert len(d["tools"]) == 8


def test_host_fields_match_contract(client):
    d = client.get(f"/api/projects/proj-1/state").json()
    h = next(x for x in d["hosts"] if x["id"] == "h-l1-01")
    assert set(h.keys()) == {
        "id", "ip", "hostname", "os", "layer", "segment", "privilege", "owned",
        "ports", "services", "note", "discovery", "isLocal", "ifaces", "posX", "posY",
    }
    assert h["isLocal"] is False and h["owned"] is True
    assert h["ports"] == [80, 22]
    # 入口机双网卡：192.168.100.2 / 10.85.101.3（多级中继推导依赖）
    assert h["ifaces"] == [
        {"iface": "eth0", "ip": "192.168.100.2", "segment": "192.168.100.0/24"},
        {"iface": "eth1", "ip": "10.85.101.3", "segment": "10.85.101.0/24"},
    ]


def test_dual_homed_host_ifaces(client):
    """L2 双网卡机 10.85.101.4 / 172.56.102.4 各两块网卡。"""
    d = client.get("/api/projects/proj-1/state").json()
    h = next(x for x in d["hosts"] if x["id"] == "h-l2-01")
    assert [i["ip"] for i in h["ifaces"]] == ["10.85.101.4", "172.56.102.4"]
    assert [i["segment"] for i in h["ifaces"]] == ["10.85.101.0/24", "172.56.102.0/24"]


def test_shell_fields_match_contract(client):
    d = client.get(f"/api/projects/proj-1/state").json()
    s = next(x for x in d["shells"] if x["id"] == "s-1")
    assert set(s.keys()) == {
        "id", "hostId", "type", "url", "pass", "encoder", "alive", "latency",
        "lastBeat", "hostname", "privilege", "stable", "kind",
    }
    assert s["pass"] == "rebeyond" and s["stable"] is True
    assert s["kind"] == ""  # HTTP 马；反弹 Shell 通道为 'reverse'


def test_link_fields_match_contract(client):
    d = client.get(f"/api/projects/proj-1/state").json()
    l = next(x for x in d["links"] if x["id"] == "p-1")
    assert set(l.keys()) == {
        "id", "tool", "linkType", "direction", "fromHostId", "toHostId", "localSocks",
        "targetSegment", "status", "latency", "traffic", "conf", "createdBy", "note",
        "listenPort", "remoteBind", "localPort", "targetHost", "targetPort",
        "relayAddr", "relayPort", "hops", "pid", "pids",
    }
    assert l["fromHostId"] == "h-l1-01" and l["toHostId"] == "h-attacker"
    assert l["linkType"] == "socks"
    # localSocks 语义 = 攻击机IP:端口（不再是 127.0.0.1:端口）
    assert l["localSocks"] == "192.0.2.10:10006"
    assert l["listenPort"] == 1331 and l["localPort"] == 10006
    assert l["remoteBind"] == "0.0.0.0"
    assert len(l["hops"]) == 2 and {"role", "hostId", "cmd"} <= set(l["hops"][0].keys())
    assert l["status"] in ("alive", "error", "stopped")


def test_link_types_cover_three_kinds(client):
    """三种链路类型（socks / portfwd / relay）字段齐全，relay 带中继地址与三步命令。"""
    d = client.get("/api/projects/proj-1/state").json()
    by_id = {x["id"]: x for x in d["links"]}
    assert {by_id["p-1"]["linkType"], by_id["p-2"]["linkType"], by_id["p-3"]["linkType"]} == \
        {"socks", "portfwd", "relay"}
    fwd = by_id["p-2"]
    assert fwd["targetHost"] == "10.85.101.3" and fwd["targetPort"] == 80
    relay = by_id["p-3"]
    assert relay["relayAddr"] == "10.85.101.3" and relay["relayPort"] == 1331
    assert relay["localSocks"] == "192.0.2.10:10005"
    assert len(relay["hops"]) == 3


def test_state_attack_config(client):
    """attack 字段来源 data/meta.json 基线。"""
    d = client.get("/api/projects/proj-1/state").json()
    assert d["attack"] == {
        "ip": "192.0.2.10", "segment": "192.0.2.0/24", "iface": "tun0",
        "note": "攻击端通过 VPN 接入靶场网络；靶机需回连到该地址，而不是 127.0.0.1",
    }


def test_segments_match_topology_baseline(client):
    """契约：segments 与 data/meta.json 的配色基线一致（含 VPN 段）。"""
    d = client.get("/api/projects/proj-1/state").json()
    segs = {s["segment"]: s for s in d["segments"]}
    assert "LOCAL" not in segs  # 分区表不出现伪网段 LOCAL
    # 四段 + 顺序 + 配色 + 层级与基线逐条一致（会话内其他用例可能追加新网段，
    # 新网段按发现顺序排在基线四段之后，故只断言前四项）
    assert [(s["segment"], s["color"], s["layer"]) for s in d["segments"]][:4] == [
        ("192.0.2.0/24", "#00e5a0", "VPN"),
        ("192.168.100.0/24", "#3ba7ff", "L1"),
        ("10.85.101.0/24", "#a97bff", "L2"),
        ("172.56.102.0/24", "#ff8a3d", "L3"),
    ]
    # 攻击端本机计入 VPN 分区（layer=VPN，而非主机自己的 LOCAL）
    assert segs["192.0.2.0/24"]["count"] >= 1
    # 种子基线各 3 台（其他用例可能追加主机，故用下界断言）
    assert segs["192.168.100.0/24"]["count"] >= 3
    assert segs["10.85.101.0/24"]["count"] >= 3
    assert segs["172.56.102.0/24"]["count"] >= 3
    assert set(segs["192.168.100.0/24"].keys()) == {"segment", "color", "layer", "count"}


def test_timeline_shape(client):
    d = client.get(f"/api/projects/proj-1/state").json()
    t = d["timeline"][0]
    assert set(t.keys()) == {"id", "time", "kind", "title", "hostId", "detail", "cmd", "markdown"}
    assert len(t["time"]) == 5  # HH:MM


def test_position_persist_and_restore(client):
    r = client.patch("/api/hosts/h-l2-01/position", json={"x": 111.5, "y": 222.25})
    assert r.status_code == 200 and r.json()["posX"] == 111.5
    d = client.get(f"/api/projects/proj-1/state").json()
    h = next(x for x in d["hosts"] if x["id"] == "h-l2-01")
    assert h["posX"] == 111.5 and h["posY"] == 222.25


def test_add_host_flow(client):
    r = client.post("/api/hosts", json={
        "ip": "10.77.0.9", "hostname": "pytest-host", "os": "Linux", "layer": "L2",
        "services": "http,ssh", "note": "pytest",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["segment"] == "10.77.0.0/24" and body["services"] == ["http", "ssh"]
    # 重复 IP 拒绝
    assert client.post("/api/hosts", json={"ip": "10.77.0.9"}).status_code == 409
    # 非法 IP 拒绝
    assert client.post("/api/hosts", json={"ip": "999.1.1.1"}).status_code == 400


def test_scan_import_dedup(client):
    text = "10.66.0.1\t80,443\n10.66.0.2\t22\nbad-line\n10.66.0.1\t8080"
    r = client.post("/api/hosts/import", json={"text": text})
    assert r.status_code == 200
    body = r.json()
    assert body["added"] == 2 and body["skipped"] == 1
    d = client.get(f"/api/projects/proj-1/state").json()
    h = next(x for x in d["hosts"] if x["ip"] == "10.66.0.1")
    assert h["ports"] == [80, 443] and h["layer"] in ("L1", "L2", "L3")


def test_cred_flag_note_flow(client):
    r = client.post("/api/creds", json={
        "hostId": "h-l1-01", "username": "pytest-u", "secret": "pytest-p",
        "kind": "密码", "services": "ssh", "source": "pytest",
    })
    assert r.status_code == 200
    assert r.json()["time"]  # HH:MM 串

    r = client.post("/api/flags", json={
        "hostId": "h-l1-01", "stage": "L1 入口", "value": "flag{pytest}", "submitted": True,
    })
    assert r.status_code == 200 and r.json()["submitted"] is True

    r = client.post("/api/timeline/notes", json={"title": "pytest 笔记", "markdown": "**b**"})
    assert r.status_code == 200 and r.json()["id"]


def test_projects_list(client):
    ps = client.get("/api/projects").json()
    assert {"id": "proj-1", "name": "2026 春秋云镜 · 三层内网"} in ps


def test_placeholder_and_real_exec_contract(client):
    """exec/tty/files 已真实实现（带合法 body 返回结构化结果）；probe 已真实执行。
    全部 200（不用 5xx：浏览器会记控制台错误）。
    种子 s-1 指向不可达靶机 → 结构化诚实失败（探活快失败，不逐条等超时）。"""
    r = client.post("/api/shells/s-1/exec", json={"cmd": "echo hi"})
    assert r.status_code == 200
    assert r.json()["ok"] is False and "目标不可达" in r.json()["error"]
    r = client.get("/api/shells/s-1/files", params={"path": "/"})
    assert r.status_code == 200
    r = client.post("/api/shells/s-1/tty/detect", json={})
    assert r.status_code == 200 and r.json()["mode"] == "dumb"
    assert "目标不可达" in r.json()["summary"]
    r = client.post("/api/shells/s-1/tty/upgrade", json={"fixId": "lx-python"})
    assert r.status_code == 200 and r.json()["hasPty"] is False
    r = client.post("/api/shells/s-1/tty/finish", json={})
    assert r.status_code == 200 and r.json()["ok"] is False
    # 出网探测：死靶诚实失败（不伪造结论）
    r = client.post("/api/shells/s-1/probe", json={})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False and body["probes"] == [] and "目标不可达" in body["reason"]
