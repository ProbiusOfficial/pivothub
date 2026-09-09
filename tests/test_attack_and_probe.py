"""攻击机网络配置（GET/PUT /api/attack）与出网探测（真实执行）契约测试。"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_port(port: int, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.4)
    return False


# ---------------------------------------------------------------------------
# 攻击机网络
# ---------------------------------------------------------------------------

def test_attack_get_put_roundtrip(client):
    r = client.get("/api/attack")
    assert r.status_code == 200
    assert r.json()["ip"] == "192.0.2.10"

    r = client.put("/api/attack", json={
        "ip": "10.0.17.77", "segment": "192.0.2.0/24", "iface": "tun0", "note": "pytest"})
    assert r.status_code == 200
    assert r.json()["ip"] == "10.0.17.77"

    # 持久化：state 与 GET 同步；攻击端本机节点同步
    st = client.get("/api/projects/proj-1/state").json()
    assert st["attack"]["ip"] == "10.0.17.77"
    local = next(h for h in st["hosts"] if h["isLocal"])
    assert local["ip"] == "10.0.17.77"
    assert local["ifaces"][0]["ip"] == "10.0.17.77"
    assert client.get("/api/attack").json()["ip"] == "10.0.17.77"

    # 恢复基线，避免影响其他用例
    client.put("/api/attack", json={
        "ip": "192.0.2.10", "segment": "192.0.2.0/24", "iface": "tun0",
        "note": "攻击端通过 VPN 接入靶场网络；靶机需回连到该地址，而不是 127.0.0.1"})
    assert client.get("/api/projects/proj-1/state").json()["attack"]["ip"] == "192.0.2.10"


def test_attack_invalid_ip_rejected(client):
    assert client.put("/api/attack", json={"ip": "999.1.1.1"}).status_code == 422
    assert client.put("/api/attack", json={"ip": "not-an-ip"}).status_code == 422


def test_attack_scoped_per_project(client):
    """新项目继承当前攻击机配置（新建项目攻击端节点不再写 127.0.0.1）。"""
    client.put("/api/attack", json={"ip": "10.0.17.55", "segment": "192.0.2.0/24",
                                    "iface": "tun0", "note": "scope"})
    pid = client.post("/api/projects", json={"name": "pytest-attack-scope"}).json()["id"]
    st = client.get(f"/api/projects/{pid}/state").json()
    assert st["attack"]["ip"] == "10.0.17.55"
    local = st["hosts"][0]
    assert local["isLocal"] is True and local["ip"] == "10.0.17.55"
    assert local["ip"] != "127.0.0.1"
    client.put("/api/attack", json={
        "ip": "192.0.2.10", "segment": "192.0.2.0/24", "iface": "tun0",
        "note": "攻击端通过 VPN 接入靶场网络；靶机需回连到该地址，而不是 127.0.0.1"})


# ---------------------------------------------------------------------------
# 出网探测：真实执行
# ---------------------------------------------------------------------------

class Miniweb:
    def __init__(self, port: int) -> None:
        self.port = port
        self.proc: subprocess.Popen | None = None

    def start(self) -> "Miniweb":
        self.proc = subprocess.Popen(
            [sys.executable, str(ROOT / "scripts/lab/miniweb/miniweb.py"),
             "--port", str(self.port), "--pwd", "cmd",
             "--dir", str(ROOT / "scripts/lab/wwwroot")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=(getattr(subprocess, "CREATE_NO_WINDOW", 0)),
        )
        assert _wait_port(self.port)
        return self

    def stop(self) -> None:
        if self.proc:
            try:
                self.proc.kill()
            except Exception:
                pass
            self.proc = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/shell.php"


@pytest.fixture()
def miniweb():
    mw = Miniweb(_free_port()).start()
    yield mw
    mw.stop()


def test_probe_real_execution(client, miniweb):
    """真实执行四类探针：解析真实回显 → verdict/recommend/alt/reason + 时间线。"""
    r = client.post("/api/hosts", json={
        "ip": "10.85.101.70", "hostname": "pytest-probe", "os": "Windows Server 2019",
        "layer": "L2", "segment": "10.85.101.0/24", "note": "probe"})
    host_id = r.json()["id"]
    r = client.post("/api/shells", json={
        "hostId": host_id, "type": "PHP 一句话马", "url": miniweb.url, "pass": "cmd",
        "encoder": "none", "projectId": "proj-1"})
    shell_id = r.json()["id"]

    before = len(client.get("/api/projects/proj-1/state").json()["timeline"])
    r = client.post(f"/api/shells/{shell_id}/probe", json={"httpUrl": "http://127.0.0.1:%d/"
                                                           % miniweb.port})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True, body
    assert [p["key"] for p in body["probes"]] == ["ICMP", "DNS", "HTTP", "TCP"]
    assert all(p["state"] in ("ok", "fail") for p in body["probes"])
    assert all(p["cmd"] for p in body["probes"])       # 真实执行的命令
    assert body["verdict"] and body["recommend"]       # 真实结论
    # 探针有真实证据（命令回显片段）
    assert any(p["evidence"] for p in body["probes"])
    # 事件入时间线
    after = client.get("/api/projects/proj-1/state").json()["timeline"]
    assert len(after) > before
    assert any("出网探测完成" in t["title"] for t in after)


def test_probe_parsers_real_samples():
    """解析器只认真实回显标记（不猜）。"""
    from pivothub.service.probe import _parse, conclude

    assert _parse("ICMP", "64 bytes from 8.8.8.8: icmp_seq=1 ttl=114 time=32.4 ms")[0] is True
    assert _parse("ICMP", "Destination Host Unreachable")[0] is False
    assert _parse("DNS", "www.baidu.com has address 110.242.68.3")[0] is True
    assert _parse("DNS", "** server can't find x: NXDOMAIN")[0] is False
    assert _parse("HTTP", "HTTP 200")[0] is True
    assert _parse("HTTP", "ERR 连接超时")[0] is False
    assert _parse("TCP", "TCP OPEN")[0] is True
    assert _parse("TCP", "TCP CLOSED")[0] is False

    class P:
        def __init__(self, k, s):
            self.key, self.state = k, s

    v, rec, _, _ = conclude([P("ICMP", "fail"), P("DNS", "ok"), P("HTTP", "fail"), P("TCP", "fail")])
    assert v == "仅 DNS 出网" and "iodine" in rec
    v, rec, alt, reason = conclude([P("ICMP", "fail"), P("DNS", "fail"),
                                    P("HTTP", "fail"), P("TCP", "fail")])
    assert v == "未发现可用出网通道" and "正向" in rec and reason
