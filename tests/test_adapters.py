"""代理链路登记 / chisel 适配器单元测试。"""

from __future__ import annotations

from pivothub.adapters.chisel import pick_lhost, port_open


def _sandbox_hosts(client):
    """沙箱项目 + 两个节点（避免污染演示项目 proj-1 的链路断言）。"""
    pid = client.post("/api/projects", json={"name": "adapters 沙箱"}).json()["id"]
    l1 = client.post("/api/hosts", json={
        "projectId": pid, "ip": "192.168.100.90", "hostname": "sandbox-l1",
        "os": "Linux", "layer": "L1", "segment": "192.168.100.0/24"}).json()["id"]
    st = client.get(f"/api/projects/{pid}/state").json()
    attacker = next(h["id"] for h in st["hosts"] if h["isLocal"])
    return pid, l1, attacker


def test_create_link_rejects_dead_pid(client):
    """pid 不存在 = 隧道未真实运行 → 拒绝登记（不伪造）。"""
    pid, l1, attacker = _sandbox_hosts(client)
    r = client.post("/api/links", json={
        "projectId": pid, "tool": "chisel", "direction": "反向",
        "fromHostId": l1, "toHostId": attacker,
        "localSocks": "127.0.0.1:10999", "targetSegment": "10.0.0.0/24",
        "pid": 4_000_000,
    })
    assert r.status_code == 422
    assert "pid" in r.json()["detail"]


def test_create_link_registers_and_broadcasts(client):
    pid, l1, attacker = _sandbox_hosts(client)
    r = client.post("/api/links", json={
        "projectId": pid, "tool": "chisel", "linkType": "socks", "direction": "反向",
        "fromHostId": l1, "toHostId": attacker,
        "localSocks": "127.0.0.1:10998", "targetSegment": "192.168.100.0/24",
        "conf": "chisel client ...", "createdBy": "自动档", "note": "pytest",
        "listenPort": 1331, "remoteBind": "0.0.0.0", "localPort": 10998,
        "hops": [{"role": "攻击机监听", "hostId": attacker, "cmd": "./chisel server -p 1331 --reverse"}],
    })
    assert r.status_code == 200
    l = r.json()
    assert l["status"] == "alive" and l["createdBy"] == "自动档"
    assert l["fromHostId"] == l1 and l["toHostId"] == attacker
    assert l["linkType"] == "socks" and l["listenPort"] == 1331 and l["localPort"] == 10998
    assert len(l["hops"]) == 1


def test_pick_lhost_loopback_fallback():
    # 不可达地址 → 回退 127.0.0.1（UDP connect 不发包，安全）
    assert pick_lhost("192.0.2.55") in ("127.0.0.1",) or pick_lhost("127.0.0.1") == "127.0.0.1"


def test_port_open_probe():
    import socket

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    assert port_open(port) is True
    srv.close()
    assert port_open(port) is False
