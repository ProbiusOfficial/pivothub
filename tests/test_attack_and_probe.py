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


def test_probe_http_zero_is_not_reachable():
    """curl 的 HTTP 000 = 没拿到任何响应（连接被 DROP / 超时）→ 必须判失败。

    回归背景：旧实现 `int(code) < 500` 把 000 当成「HTTP 可达」，目标 TCP 全封
    却输出「仅 HTTP(S) 出网」并推荐 Neo-reGeorg（真实靶场 ② 的误判来源）。
    """
    from pivothub.service.probe import _parse

    assert _parse("HTTP", "HTTP 000")[0] is False
    assert _parse("HTTP", "HTTP 000curl: (28) Connection timed out after 6000 ms")[0] is False
    # 服务端回了状态码即证明 HTTP 通路存在（5xx 也算通）
    assert _parse("HTTP", "HTTP 200")[0] is True
    assert _parse("HTTP", "HTTP 502")[0] is True
    assert _parse("HTTP", "HTTP 404")[0] is True


def test_probe_targets_attack_machine_when_configured():
    """给了攻击机地址就探攻击机（回答「能否回连到我」），端口 / URL 一并跟随。"""
    from pivothub.service.probe import build_probes, _resolve_targets

    t = _resolve_targets({"attackIp": "10.8.0.14", "attackPort": 443})
    assert t["tcpHost"] == "10.8.0.14" and t["tcpPort"] == 443
    assert t["httpUrl"] == "http://10.8.0.14:443/"
    assert t["icmpHost"] == "10.8.0.14"

    cmds = {p.key: p.cmd for p in build_probes("linux", {"attackIp": "10.8.0.14"}, 12345)}
    assert "10.8.0.14" in cmds["TCP"] and "12345" in cmds["TCP"]      # 用回退端口，而非默认 443
    assert "10.8.0.14:12345" in cmds["HTTP"]

    # 未配置攻击机时保持公网基线（不改变既有语义）
    t2 = _resolve_targets({})
    assert t2["tcpHost"] == "www.baidu.com" and t2["tcpPort"] == 443


def test_probe_uses_panel_listening_port_when_no_attack_port():
    """未显式给端口时，回连探针打「面板自己确定在监听的端口」（暂存 HTTP 服务）。

    否则会拿一个没人监听的默认端口（443）探测，得出「TCP 全封」的假结论——
    而目标其实完全可以回连攻击机。
    """
    from pivothub.service import filestage as stage_svc
    from pivothub.service.probe import run_probes

    port = stage_svc.STAGE.start()          # 面板自身服务，确定在监听
    assert port > 0

    class FakeSession:
        platform = "linux"
        cmds: list[str] = []

        def exec(self, cmd, timeout=15.0):
            self.cmds.append(cmd)
            return type("R", (), {"ok": True, "output": "", "error": "", "ms": 3})()

    s = FakeSession()
    try:
        report = run_probes(s, opts={"attackIp": "127.0.0.1"})
        assert f"127.0.0.1/{port}" in report.probes[3].cmd   # TCP 探针 → 面板监听端口（/dev/tcp 语法）
        assert f"127.0.0.1:{port}" in report.probes[2].cmd   # HTTP 探针 → 同一端口
        assert "探针目标：攻击机 127.0.0.1" in report.reason
    finally:
        stage_svc.STAGE.stop()               # 单例服务：用完停掉，不留给其它用例/进程退出


def test_probe_rules_conflict_detection():
    """探测结论与防火墙留档矛盾时必须提示人工复核，而不是给出自信的错误结论。"""
    from pivothub.service.probe import _rules_conflict, _rules_policy

    rules = ("*filter\n:INPUT DROP [0:0]\n"
             "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
             "-A INPUT -p icmp -j ACCEPT\nCOMMIT\n")
    pol = _rules_policy(rules)
    assert pol["readable"] and pol["policyDrop"] and "tcp/22" in pol["ports"] and pol["icmp"]

    warn = _rules_conflict({"HTTP": True}, 443, 443, pol)   # 443 可达但留档只放行 22
    assert warn and "不一致" in warn and "443" in warn
    ok_pol = _rules_policy(":INPUT DROP [0:0]\n-A INPUT -p tcp --dport 80 -j ACCEPT\n")
    assert _rules_conflict({"HTTP": True}, 80, 80, ok_pol) == ""
    # 留档读不到 → 不做判断（不制造噪声）
    assert _rules_conflict({"HTTP": True}, 443, 443, _rules_policy("iptables: not found")) == ""
    assert _rules_conflict({"HTTP": True}, 443, 443, _rules_policy("")) == ""
