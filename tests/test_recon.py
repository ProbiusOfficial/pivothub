"""资产探测：解析单测 + 经 miniweb 靶的真实 API 流程（Windows 命令链）。

本机没有 Linux 靶，API 链路用 Windows 平台的 miniweb 会话验证：
`ipconfig /all` 采集、扫描器上传（二进制安全）→ cmd 执行 → 输出解析 → 导入去重分层。
"""

from __future__ import annotations

import base64
import os
import sys
import threading
import time
from http.server import ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts", "lab", "miniweb"))

import miniweb  # noqa: E402

from pivothub.service import recon as R  # noqa: E402

# ---------------------------------------------------------------------------
# 解析单测
# ---------------------------------------------------------------------------

IP_ADDR_OUT = (
    "2: eth0    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0\\       "
    "valid_lft forever preferred_lft forever\n"
    "3: eth1    inet 10.85.101.3/24 brd 10.85.101.255 scope global eth1\\       "
    "valid_lft forever preferred_lft forever\n"
)

IFCONFIG_OUT = """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.10  netmask 255.255.255.0  broadcast 192.168.1.255
eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.85.101.3  netmask 255.255.255.0  broadcast 10.85.101.255
"""

WIN_IPCONFIG = """以太网适配器 OpenVPN Data Channel Offload:

   连接特定的 DNS 后缀 . . . . . . . :
   IPv4 地址 . . . . . . . . . . . . : 10.8.0.14
   子网掩码  . . . . . . . . . . . . : 255.255.255.0

Ethernet adapter Ethernet:

   IPv4 Address. . . . . . . . . . . : 192.168.3.228
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
"""

HOSTS_OUT = """127.0.0.1   localhost localhost.localdomain
10.10.20.5  db.internal db    # 数据库
::1         localhost
"""

ROUTE_IP = """default via 10.8.0.1 dev tun0 proto static metric 50
10.8.0.0/24 dev tun0 proto kernel scope link src 10.8.0.14
10.10.20.0/24 via 10.8.0.1 dev tun0
"""

ROUTE_N = """Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         10.8.0.1        0.0.0.0         UG    0      0        0 tun0
10.10.20.0      10.8.0.1        255.255.255.0   UG    0      0        0 tun0
"""

ROUTE_WIN = """          0.0.0.0          0.0.0.0      10.8.0.1     10.8.0.14     25
       10.10.20.0    255.255.255.0         On-link      10.8.0.14    281
"""

ARP_NEIGH = "10.8.0.1 dev tun0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
ARP_A = "? (10.8.0.1) at aa:bb:cc:dd:ee:ff [ether] on tun0\n"
ARP_WIN = "  10.8.0.1           aa-bb-cc-dd-ee-ff     动态\n"

SCAN_FSCAN = """[*] 10.10.20.1:22 open
[+] 10.10.20.5:445 open
10.10.20.5:3389 open
[*] Alive: 10.10.20.9
10.10.20.0:80 open
10.10.20.255:80 open
"""

SCAN_NMAP = """Nmap scan report for web01 (10.10.20.5)
Host is up (0.0010s latency).
80/tcp  open  http
443/tcp open  ssl/https
Nmap scan report for 10.10.20.6
445/tcp open  microsoft-ds
"""

SCAN_GREPABLE = "Host: 10.10.20.5 () Ports: 80/open/tcp//http/,443/open/tcp//ssl/\n"


def test_parse_interfaces_variants():
    a = R.parse_interfaces(IP_ADDR_OUT)
    assert [(i["iface"], i["ip"], i["segment"]) for i in a] == [
        ("eth0", "192.168.1.10", "192.168.1.0/24"),
        ("eth1", "10.85.101.3", "10.85.101.0/24"),
    ]
    b = R.parse_interfaces(IFCONFIG_OUT)
    assert [(i["iface"], i["ip"]) for i in b] == [("eth0", "192.168.1.10"), ("eth1", "10.85.101.3")]
    c = R.parse_interfaces(WIN_IPCONFIG, "windows")
    assert [(i["iface"], i["ip"]) for i in c] == [
        ("OpenVPN Data Channel Offload", "10.8.0.14"), ("Ethernet", "192.168.3.228")]


def test_parse_hosts_file_skips_comments_and_ipv6():
    rows = R.parse_hosts_file(HOSTS_OUT)
    assert rows == [
        {"ip": "127.0.0.1", "names": ["localhost", "localhost.localdomain"]},
        {"ip": "10.10.20.5", "names": ["db.internal", "db"]},
    ]


def test_parse_routes_variants():
    a = R.parse_routes(ROUTE_IP)
    assert {"dst": "default", "via": "10.8.0.1", "dev": "tun0"} in a
    assert {"dst": "10.10.20.0/24", "via": "10.8.0.1", "dev": "tun0"} in a
    b = R.parse_routes(ROUTE_N)
    assert {"dst": "0.0.0.0", "via": "10.8.0.1", "dev": "tun0"} in b
    assert {"dst": "10.10.20.0", "via": "10.8.0.1", "dev": "tun0"} in b
    c = R.parse_routes(ROUTE_WIN)
    assert {"dst": "0.0.0.0", "via": "10.8.0.1", "dev": "10.8.0.14"} in c
    assert {"dst": "10.10.20.0", "via": "On-link", "dev": "10.8.0.14"} in c


def test_parse_arp_variants():
    assert R.parse_arp(ARP_NEIGH)[0]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert R.parse_arp(ARP_A)[0]["ip"] == "10.8.0.1"
    assert R.parse_arp(ARP_WIN)[0]["mac"] == "aa-bb-cc-dd-ee-ff"


def test_segments_of_dedup_and_size_guard():
    ifaces = [{"segment": "10.0.0.0/24"}, {"segment": "10.0.0.0/24"},
              {"segment": "127.0.0.0/8"}, {"segment": "169.254.0.0/16"}, {"segment": ""}]
    routes = [{"dst": "0.0.0.0/0"}, {"dst": "172.16.0.0/24"}, {"dst": "10.0.0.0/8"}]
    assert R.segments_of(ifaces, routes) == ["10.0.0.0/24", "172.16.0.0/24"]


def test_split_sections():
    text = "lo stuff\n---IPADDR---\neth0 1.2.3.4\n---HOSTS---\n1.1.1.1 a\n---ROUTE---\n---ARP---\n---END---\n"
    sec = R.split_sections(text)
    assert "eth0 1.2.3.4" in sec["ipaddr"]
    assert "1.1.1.1 a" in sec["hosts"]


def test_parse_scan_output_fscan_filters_net_and_broadcast():
    rows = {h["ip"]: h for h in R.parse_scan_output(SCAN_FSCAN)}
    assert set(rows) == {"10.10.20.1", "10.10.20.5", "10.10.20.9"}
    assert rows["10.10.20.5"]["ports"] == [445, 3389]
    assert rows["10.10.20.1"]["ports"] == [22]
    assert rows["10.10.20.9"]["ports"] == []  # 仅存活


def test_parse_scan_output_fscan_v2_chinese_alive():
    """fscan v2 中文输出：ICMP 存活主机也要进结果（否则「发现 N 台」比扫描器少）。"""
    text = (
        "[*] ICMP存活探测(1.2%)，开始TCP端口探测(251个端口)\n"
        "[*] 172.33.0.10 存活 (来源: ICMP)\n"
        "[*] 172.33.0.20 存活 (来源: ICMP)\n"
        "[*] 172.33.0.1:22                  ssh      [Product:OpenSSH]\n"
        "[*] 扫描完成，发现 2 个开放端口\n"
    )
    rows = {h["ip"]: h for h in R.parse_scan_output(text)}
    assert set(rows) == {"172.33.0.10", "172.33.0.20", "172.33.0.1"}
    assert rows["172.33.0.10"]["ports"] == []
    assert rows["172.33.0.1"]["ports"] == [22]


def test_parse_scan_output_nmap_normal_and_grepable():
    normal = {h["ip"]: h for h in R.parse_scan_output(SCAN_NMAP)}
    assert normal["10.10.20.5"]["hostname"] == "web01"
    assert normal["10.10.20.5"]["ports"] == [80, 443]
    assert normal["10.10.20.6"]["ports"] == [445]
    grep = {h["ip"]: h for h in R.parse_scan_output(SCAN_GREPABLE)}
    assert grep["10.10.20.5"]["ports"] == [80, 443]


def test_scanner_command_and_builtin():
    cmd = R.scanner_command("/tmp/.pivothub-recon/fscan", "10.0.0.0/24", "22,80")
    assert cmd == "/tmp/.pivothub-recon/fscan -h 10.0.0.0/24 -p 22,80"
    win = R.scanner_command(r"%TEMP%\.pivothub-recon\fscan.exe", "10.0.0.0/24", "80",
                            platform="windows")
    assert win == r'"%TEMP%\.pivothub-recon\fscan.exe" -h 10.0.0.0/24 -p 80'
    tpl = R.scanner_command("s", "10.0.0.0/24", "80", extra="-nobr",
                            template="{SCANNER} -h {SEGMENT} {EXTRA}")
    assert tpl == "s -h 10.0.0.0/24 -nobr"

    builtin = R.builtin_command("10.0.0.0/24", "22,80")
    assert "10.0.0.1 " in builtin and "10.0.0.254" in builtin and "ports='22 80'" in builtin
    assert R.builtin_command("10.0.0.0/16", "22") == ""      # 网段过大不内置扫
    assert R.builtin_command("10.0.0.0/24", "22", "windows") == ""


# ---------------------------------------------------------------------------
# API 链路（miniweb 靶，Windows 命令）
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def winlab(client):
    """Windows 指纹主机 + miniweb 会话：命令经 cmd 真实执行。"""
    miniweb.Handler.pwd = "cmd"
    srv = ThreadingHTTPServer(("127.0.0.1", 0), miniweb.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    r = client.post("/api/hosts", json={
        "ip": "127.0.0.10", "hostname": "recon-win-lab", "os": "Windows Server 2019",
        "layer": "L1", "note": "recon lab"})
    assert r.status_code == 200, r.text
    host_id = r.json()["id"]
    r = client.post("/api/shells", json={
        "hostId": host_id, "type": "PHP 一句话马",
        "url": f"http://127.0.0.1:{srv.server_address[1]}/shell.php",
        "pass": "cmd", "encoder": "none", "autoCollect": False})
    assert r.status_code == 200, r.text
    yield {"shellId": r.json()["id"], "hostId": host_id}
    srv.shutdown()


def test_recon_env_real_windows(client, winlab):
    r = client.post("/api/recon/env", json={"shellId": winlab["shellId"]})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True, body
    assert body["platform"] == "windows"
    assert body["ifaces"], body                       # 真实 ipconfig 解析出网卡
    assert any(i["segment"] for i in body["ifaces"])
    assert body["segments"]


def test_recon_scan_upload_exec_parse_and_cache(client, winlab, tmp_path):
    import uuid

    # 每次用唯一文件名：目标侧临时目录是持久的，避免上一轮缓存影响断言
    name = f"fscan-fake-{uuid.uuid4().hex[:6]}.bat"
    bat = tmp_path / name
    bat.write_bytes(
        b"@echo off\r\n"
        b"echo 10.10.20.5:22 open\r\n"
        b"echo 10.10.20.5:80 open http\r\n"
        b"echo 10.10.20.6:445 open\r\n"
        b"echo 10.10.20.0:80 open\r\n")
    body = {
        "shellId": winlab["shellId"], "segment": "10.10.20.0/24", "ports": "22,80",
        "scannerName": name,
        "scannerB64": base64.b64encode(bat.read_bytes()).decode(),
    }
    r = client.post("/api/recon/scan", json=body)
    assert r.status_code == 200
    out = r.json()
    assert out["ok"] is True, out
    rows = {h["ip"]: h for h in out["hosts"]}
    assert set(rows) == {"10.10.20.5", "10.10.20.6"}   # .0 网络号被过滤
    assert rows["10.10.20.5"]["ports"] == [22, 80]
    assert out["cached"] is False
    assert out["scannerPath"].endswith(name)

    r2 = client.post("/api/recon/scan", json=body)
    assert r2.json()["cached"] is True                 # 目标已存在 → 跳过重复上传
    r3 = client.post("/api/recon/scan", json={**body, "forceUpload": True})
    assert r3.json()["cached"] is False                # 强制重传

    client.post(f"/api/shells/{winlab['shellId']}/exec",
                json={"cmd": f'del "%TEMP%\\.pivothub-recon\\{name}"'})  # 清理靶侧临时文件


def test_recon_import_dedupe_and_layer(client, sandbox_project):
    r = client.post("/api/hosts", json={
        "projectId": sandbox_project, "ip": "192.168.50.10", "hostname": "jump",
        "os": "Ubuntu", "layer": "L1", "segment": "192.168.50.0/24", "note": "src"})
    src = r.json()["id"]
    r = client.post("/api/recon/import", json={
        "projectId": sandbox_project, "fromHostId": src,
        "hosts": [
            {"ip": "10.10.20.5", "ports": [22, 80], "hostname": "web01"},
            {"ip": "10.10.20.5", "ports": [443]},           # 载荷内重复
            {"ip": "192.168.50.11", "ports": []},           # 已知网段
            {"ip": "bad-ip"},
        ]})
    assert r.status_code == 200
    assert r.json()["added"] == 2 and r.json()["skipped"] == 2
    st = client.get(f"/api/projects/{sandbox_project}/state").json()
    by_ip = {h["ip"]: h for h in st["hosts"]}
    assert by_ip["10.10.20.5"]["layer"] == "L2"          # 新网段 = 来源层级下一层
    assert by_ip["10.10.20.5"]["ports"] == [22, 80]
    assert by_ip["10.10.20.5"]["discovery"] == "资产探测（经 Shell 扫描）"
    assert "192.168.50.10" in by_ip["10.10.20.5"]["note"]
    assert by_ip["192.168.50.11"]["layer"] == "L1"       # 已知网段继承层级


def test_recon_builtin_rejects_windows_target(client, winlab):
    r = client.post("/api/recon/scan", json={
        "shellId": winlab["shellId"], "segment": "10.10.20.0/24", "ports": "22"})
    body = r.json()
    assert body["ok"] is False and body["stage"] == "command"
    assert "上传" in body["error"]


# ---------------------------------------------------------------------------
# 流式扫描（后台任务 + 轮询快照）与自定义暂存目录
# ---------------------------------------------------------------------------

def _wait_job(client, job_id: str, timeout: float = 30.0) -> dict:
    deadline = time.time() + timeout
    snap = {}
    while time.time() < deadline:
        snap = client.get(f"/api/recon/scan/jobs/{job_id}").json()
        if snap.get("status") != "running":
            return snap
        time.sleep(0.2)
    return snap


def test_recon_scan_stream_and_custom_remote_dir(client, winlab, tmp_path):
    import uuid

    name = f"fscan-stream-{uuid.uuid4().hex[:6]}.bat"
    bat = tmp_path / name
    bat.write_bytes(
        b"@echo off\r\n"
        b"echo 10.10.20.7:22 open\r\n"
        b"echo 10.10.20.8:80 open http\r\n")
    body = {
        "shellId": winlab["shellId"], "segment": "10.10.20.0/24", "ports": "22,80",
        "scannerName": name,
        "scannerB64": base64.b64encode(bat.read_bytes()).decode(),
        "remoteDir": r"C:\Users\Public\.pivothub-recon",
    }
    r = client.post("/api/recon/scan/stream", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True
    job_id = r.json()["jobId"]

    snap = _wait_job(client, job_id)
    assert snap["status"] == "done", snap
    rows = {h["ip"]: h for h in snap["hosts"]}
    assert set(rows) == {"10.10.20.7", "10.10.20.8"}
    # 自定义目录生效（用户指定后不再落到 %TEMP%）
    assert snap["scannerPath"].startswith(r"C:\Users\Public\.pivothub-recon")
    assert any("已上传扫描器" in l["line"] for l in snap["lines"])
    assert any("扫描结束" in l["line"] for l in snap["lines"])
    assert client.get(f"/api/recon/scan/jobs/{job_id}").json()["status"] == "done"

    client.post(f"/api/shells/{winlab['shellId']}/exec",
                json={"cmd": f'del "C:\\Users\\Public\\.pivothub-recon\\{name}"'})  # 清理靶侧文件


def test_recon_scan_rejects_relative_remote_dir(client, winlab):
    body = {"shellId": winlab["shellId"], "segment": "10.10.20.0/24", "remoteDir": "relative/dir"}
    assert client.post("/api/recon/scan/stream", json=body).status_code == 400
    assert client.post("/api/recon/scan", json=body).status_code == 400


def test_recon_scan_job_unknown_404(client):
    assert client.get("/api/recon/scan/jobs/job-nope").status_code == 404
    assert client.post("/api/recon/scan/jobs/job-nope/cancel").status_code == 404


# ---------------------------------------------------------------------------
# 服务名 / Web 标题 / fscan v2 输出
# ---------------------------------------------------------------------------

SCAN_FSCAN_V2 = """[*] 服务插件: webtitle, webpoc, mqtt, jdwp
[*] 参数自适应: Timeout=1000ms, ModuleThread=30
[*] http://10.10.20.5:8080          dps-shell [Product:Destiny DPS Mini shell] Banner:(HTTP/1.1 400 Bad Request)
[*] 10.10.20.5:1883                 mqtt
[*] 10.10.20.5:5037
[*] http://10.10.20.5:8080          code:200 len:107287 title:PivotHub 面板 server:uvicorn
[*] 扫描完成，发现 3 个开放端口
"""


def test_service_of_known_and_fallback():
    assert R.service_of(22) == "SSH"
    assert R.service_of(3306) == "MySQL"
    assert R.service_of(6379) == "Redis"
    assert R.service_of(5037) == "ADB"
    assert R.service_of(12345) == "dynamic-port"
    assert R.service_name("mqtt", 1883) == "MQTT"
    assert R.service_name("", 445) == "SMB"          # 无标记回落端口表
    assert R.service_name("whatever", 9999) == "whatever"


def test_parse_fscan_v2_services_and_titles():
    rows = {h["ip"]: h for h in R.parse_scan_output(SCAN_FSCAN_V2)}
    h = rows["10.10.20.5"]
    assert h["ports"] == [1883, 5037, 8080]
    info = {p["port"]: p for p in h["portInfo"]}
    assert info[1883]["service"] == "MQTT"
    assert info[5037]["service"] == "ADB"
    assert info[8080]["service"] == "uvicorn"        # server: 字段优先
    assert info[8080]["title"] == "PivotHub 面板"
    assert "dps-shell" in h["note"]


def test_web_title_command_and_parse():
    cmd = R.web_title_command(["10.0.0.5:80", "10.0.0.6:8443"])
    assert "PIVOTHUB_TITLE" in cmd and "10.0.0.5:80" in cmd and "10.0.0.6:8443" in cmd
    assert "curl" in cmd and "wget" in cmd
    assert R.web_title_command(["1.1.1.1:80"], "windows") == ""

    titles = R.parse_title_output("noise\nPIVOTHUB_TITLE 10.0.0.5:80 登录页\n")
    assert titles == {"10.0.0.5:80": "登录页"}

    hosts = [{"ip": "10.0.0.5", "portInfo": [
        {"port": 80, "service": "HTTP", "title": ""},
        {"port": 22, "service": "SSH", "title": ""},
        {"port": 443, "service": "HTTPS", "title": "已有标题"},
    ]}]
    assert R.web_targets(hosts) == ["10.0.0.5:80"]   # 已有标题 / 非 Web 端口不重复抓


def test_recon_scanners_lists_local_fscan(client):
    r = client.get("/api/recon/scanners")
    assert r.status_code == 200
    body = r.json()
    keys = {t["key"]: t for t in body["tools"]}
    assert "fscan_linux" in keys and keys["fscan_linux"]["platform"] == "linux"
    assert "fscan.exe" in keys and keys["fscan.exe"]["platform"] == "windows"
    assert "-nobr" in keys["fscan_linux"]["template"]


def test_recon_scan_rejects_unknown_local_scanner(client, winlab):
    r = client.post("/api/recon/scan", json={
        "shellId": winlab["shellId"], "segment": "10.10.20.0/24",
        "localScanner": "../fscan.exe"})
    assert r.status_code == 404


def _scan_body(winlab, name: str, data: bytes, **extra) -> dict:
    body = {"shellId": winlab["shellId"], "segment": "10.10.20.0/24", "ports": "22,80",
            "scannerName": name, "scannerB64": base64.b64encode(data).decode(),
            "probeTitles": False}
    body.update(extra)
    return body


def test_recon_scan_transfer_modes(client, winlab):
    """扫描器传输：auto 小文件直接分片；http 走目标机 curl/wget 拉取 + 字节数校验。

    HTTP 拉取与「文件管理 → HTTP 拉取」同一通道（攻击机临时 HTTP 服务 + 目标机自取）：
    大二进制不必经 WebShell 分片；目标连不到攻击机时自动回退分片直传。
    """
    import uuid

    bat = b"@echo off\r\necho 10.10.20.30:22 open\r\n"

    # ① auto + 小文件 → 分片直传（不付可达性预检的代价）
    name = f"fscan-auto-{uuid.uuid4().hex[:6]}.bat"
    out = client.post("/api/recon/scan",
                      json=_scan_body(winlab, name, bat, transfer="auto")).json()
    assert out["ok"] is True, out
    assert any("文件较小" in l for l in out["log"]), out["log"]
    assert any("分片直传" in l for l in out["log"]), out["log"]

    # ② transfer=http → 真实 HTTP 拉取（回环可达；curl/wget 自取后按字节数校验）
    name2 = f"fscan-http-{uuid.uuid4().hex[:6]}.bat"
    out2 = client.post("/api/recon/scan",
                       json=_scan_body(winlab, name2, bat, transfer="http",
                                       forceUpload=True)).json()
    assert out2["ok"] is True, out2
    joined = "\n".join(out2["log"])
    assert "[http]" in joined, out2["log"]
    if "拉取通过" in joined:                      # 拉取成功：不得再出现分片上传
        assert not any("分片直传" in l for l in out2["log"]), out2["log"]
        assert any("校验通过" in l for l in out2["log"]), out2["log"]

    for n in (name, name2):
        client.post(f"/api/shells/{winlab['shellId']}/exec",
                    json={"cmd": f'del "%TEMP%\\.pivothub-recon\\{n}"'})
