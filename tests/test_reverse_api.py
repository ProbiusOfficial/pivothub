"""反弹 Shell 通道 API：监听 → 回连 → 登记（真实 socket 回连）。"""

from __future__ import annotations

import socket
import threading
import time


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _echo_client(port: int, ready: threading.Event,
                 output: bytes = b"file-a.txt\nfile-b.txt\n") -> None:
    """模拟靶机回连（PTY 行为）：逐行**先原样回显输入**，再执行。

    真实 PTY（socat/script/pty.spawn，或面板「获取 PTY」升级后的通道）会回显
    ``echo PH_xxx`` 这一行——哨兵判定必须靠「独占一行的 marker」，不能靠子串包含，
    否则命令尚未执行就会命中（历史表现：扫描 0 台主机 / cat 无输出）。
    非 echo 命令统一回 ``output``，模拟真实命令输出。
    """
    conn = None
    for _ in range(50):
        try:
            conn = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            break
        except OSError:
            time.sleep(0.1)
    ready.set()
    if conn is None:
        return
    try:
        conn.settimeout(0.5)
        buf = b""
        while True:
            try:
                data = conn.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            conn.sendall(data)              # ① PTY 回显（含 echo PH_x 这一行）
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                text = line.decode("utf-8", "replace").strip()
                if not text:
                    continue
                if text.startswith("echo "):
                    conn.sendall((text[5:] + "\n").encode())   # ② 执行哨兵
                else:
                    conn.sendall(output)
    finally:
        conn.close()


def _scan_client(port: int, ready: threading.Event) -> None:
    """模拟靶机回连：普通命令回两行扫描结果，echo 命令原样回显（哨兵同步用）。"""
    conn = None
    for _ in range(50):
        try:
            conn = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            break
        except OSError:
            time.sleep(0.1)
    ready.set()
    if conn is None:
        return
    try:
        conn.settimeout(0.5)
        buf = b""
        while True:
            try:
                data = conn.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                text = line.decode("utf-8", "replace").strip()
                if not text:
                    continue
                if text.startswith("echo "):
                    conn.sendall((text[5:] + "\n").encode())
                else:
                    conn.sendall(b"open 22\nopen 80\n")
    finally:
        conn.close()


def test_netinfo_returns_local_ipv4(client):
    r = client.get("/api/netinfo")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data.get("hostname"), str)
    assert isinstance(data.get("ips"), list)
    assert all(not ip.startswith("127.") for ip in data["ips"])
    # 网卡/网段下拉框数据源：每项含 name/ip/segment（psutil 缺失时为空列表）
    ifaces = data.get("interfaces")
    assert isinstance(ifaces, list)
    for it in ifaces:
        assert set(it) >= {"name", "ip", "segment"}
        assert it["name"] and it["ip"]
        assert not it["ip"].startswith(("127.", "169.254."))


def test_reverse_listen_connect_register(client, sandbox_project):
    port = _free_port()
    r = client.post("/api/shells/reverse/listen",
                    json={"bind": "127.0.0.1", "port": port, "label": "pytest", "waitS": 0})
    assert r.status_code == 200
    out = r.json()
    assert out["ok"] is True
    lid = out["listener"]["id"]
    assert out["listener"]["connected"] is False
    assert "dev/tcp" in out["payload"]  # 兼容旧契约：返回 bash 载荷

    ready = threading.Event()
    threading.Thread(target=_echo_client, args=(port, ready), daemon=True).start()
    assert ready.wait(3), "回连客户端未启动"

    deadline = time.time() + 5
    connected = False
    while time.time() < deadline:
        ls = client.get("/api/shells/reverse/listeners").json()["listeners"]
        me = next((x for x in ls if x["id"] == lid), None)
        if me and me["connected"]:
            connected = True
            break
        time.sleep(0.2)
    assert connected, "监听器未记录回连"

    host = client.get(f"/api/projects/{sandbox_project}/state").json()["hosts"][0]["id"]
    r = client.post("/api/shells/reverse/register", json={
        "projectId": sandbox_project, "listenerId": lid, "hostId": host,
        "type": "反弹 Shell（pytest）", "autoCollect": False})
    assert r.status_code == 200
    reg = r.json()
    assert reg["ok"] is True
    sh = reg["shell"]
    assert sh["kind"] == "reverse"
    assert sh["url"].startswith("reverse://127.0.0.1:")
    assert sh["alive"] is True  # 哨兵回显 → 真实探活成功

    st = client.get(f"/api/projects/{sandbox_project}/state").json()
    assert any(s["id"] == sh["id"] and s["kind"] == "reverse" for s in st["shells"])
    assert any(e["kind"] == "shell" and "回连成功" in e["title"] for e in st["timeline"])


def test_reverse_register_without_callback_fails_honestly(client, sandbox_project):
    port = _free_port()
    lid = client.post("/api/shells/reverse/listen",
                      json={"bind": "127.0.0.1", "port": port, "waitS": 0}).json()["listener"]["id"]
    host = client.get(f"/api/projects/{sandbox_project}/state").json()["hosts"][0]["id"]
    r = client.post("/api/shells/reverse/register", json={
        "projectId": sandbox_project, "listenerId": lid, "hostId": host})
    body = r.json()
    assert body["ok"] is False and body["stage"] == "callback"


def test_reverse_listen_bad_bind_fails_honestly(client):
    r = client.post("/api/shells/reverse/listen",
                    json={"bind": "203.0.113.9", "port": _free_port(), "waitS": 0})
    body = r.json()
    assert body["ok"] is False and body["stage"] == "bind"
    assert "本机当前没有地址" in body["error"]
    assert isinstance(body["localIps"], list)


def test_reverse_listen_replaces_stale_pending_listener(client):
    """休眠 / 断线后残留的「未回连」监听会占住端口：重开同端口应自动替换而不是报错。"""
    port = _free_port()
    first = client.post("/api/shells/reverse/listen",
                        json={"bind": "127.0.0.1", "port": port, "waitS": 0}).json()
    assert first["ok"] is True and first["replaced"] is False
    second = client.post("/api/shells/reverse/listen",
                         json={"bind": "127.0.0.1", "port": port, "waitS": 0}).json()
    assert second["ok"] is True and second["replaced"] is True
    ids = [x["id"] for x in client.get("/api/shells/reverse/listeners").json()["listeners"]]
    assert second["listener"]["id"] in ids
    assert first["listener"]["id"] not in ids
    assert client.delete(f"/api/shells/reverse/listeners/{second['listener']['id']}").json()["ok"] is True


def test_reverse_listen_refuses_to_replace_connected_listener(client):
    port = _free_port()
    first = client.post("/api/shells/reverse/listen",
                        json={"bind": "127.0.0.1", "port": port, "waitS": 0}).json()
    ready = threading.Event()
    threading.Thread(target=_echo_client, args=(port, ready), daemon=True).start()
    assert ready.wait(3)
    deadline = time.time() + 5
    while time.time() < deadline:
        me = next((x for x in client.get("/api/shells/reverse/listeners").json()["listeners"]
                   if x["id"] == first["listener"]["id"]), None)
        if me and me["connected"]:
            break
        time.sleep(0.2)
    r = client.post("/api/shells/reverse/listen",
                    json={"bind": "127.0.0.1", "port": port, "waitS": 0}).json()
    assert r["ok"] is False and "已有回连会话" in r["error"]
    assert client.delete("/api/shells/reverse/listeners").json()["closed"] >= 1


def test_reverse_exec_stream_yields_lines_before_marker(client, sandbox_project):
    """流式执行：输出行在哨兵标记之前就回调（扫描日志实时进终端的关键）。"""
    from pivothub.api.shells import REVERSE_CHANNELS

    port = _free_port()
    lid = client.post("/api/shells/reverse/listen",
                      json={"bind": "127.0.0.1", "port": port, "waitS": 0}).json()["listener"]["id"]
    ready = threading.Event()
    threading.Thread(target=_scan_client, args=(port, ready), daemon=True).start()
    assert ready.wait(3)

    deadline = time.time() + 5
    while time.time() < deadline:
        me = next((x for x in client.get("/api/shells/reverse/listeners").json()["listeners"]
                   if x["id"] == lid), None)
        if me and me["connected"]:
            break
        time.sleep(0.2)

    host = client.get(f"/api/projects/{sandbox_project}/state").json()["hosts"][0]["id"]
    reg = client.post("/api/shells/reverse/register", json={
        "projectId": sandbox_project, "listenerId": lid, "hostId": host,
        "type": "反弹 Shell（pytest stream）", "autoCollect": False}).json()
    assert reg["ok"] is True, reg
    ch = REVERSE_CHANNELS.get(reg["shell"]["id"])
    assert ch is not None

    lines: list[str] = []
    res = ch.exec_stream("fscan -h 10.0.0.0/24", lines.append, timeout=5)
    assert res.ok is True, res
    assert lines == ["open 22", "open 80"]
    assert res.output == "open 22\nopen 80"
    client.delete("/api/shells/reverse/listeners")


def _open_listener(client, port: int) -> str:
    return client.post("/api/shells/reverse/listen",
                       json={"bind": "127.0.0.1", "port": port, "waitS": 0}).json()["listener"]["id"]


def _wait_connected(client, listener_id: str, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        me = next((x for x in client.get("/api/shells/reverse/listeners").json()["listeners"]
                   if x["id"] == listener_id), None)
        if me and me["connected"]:
            return True
        time.sleep(0.2)
    return False


def _register_reverse(client, project_id: str, listener_id: str) -> tuple[str, object]:
    """把已回连的监听登记为会话，返回 (shellId, channel)。"""
    from pivothub.api.shells import REVERSE_CHANNELS

    host = client.get(f"/api/projects/{project_id}/state").json()["hosts"][0]["id"]
    reg = client.post("/api/shells/reverse/register", json={
        "projectId": project_id, "listenerId": listener_id, "hostId": host,
        "type": "反弹 Shell（pytest pty）", "autoCollect": False}).json()
    assert reg["ok"] is True, reg
    return reg["shell"]["id"], REVERSE_CHANNELS[reg["shell"]["id"]]


def test_reverse_pty_echo_channel_exec_gets_real_output(client, sandbox_project):
    """PTY 回显型通道：exec / exec_stream 必须拿到真实输出（哨兵不能被回显行提前触发）。

    回归背景：远端为 PTY 时会把 `echo PH_xxx` 原样回显，子串匹配哨兵会立即命中 →
    exec 返回「ok=True + 空输出」（历史表现：fscan 118ms 发现 0 台 / cat 无回显）。
    """
    port = _free_port()
    lid = _open_listener(client, port)
    ready = threading.Event()
    threading.Thread(target=_echo_client,
                     args=(port, ready, b"flag{from-pty-channel}\n"), daemon=True).start()
    assert ready.wait(3)
    assert _wait_connected(client, lid), "回连未建立"
    _sid, ch = _register_reverse(client, sandbox_project, lid)

    res = ch.exec("cat /tmp/hdr2", timeout=5)
    assert res.ok is True, res
    assert res.output == "flag{from-pty-channel}", res.output
    assert "PH_" not in res.output                  # 哨兵回显行不得混进输出

    lines: list[str] = []
    sres = ch.exec_stream("./fscan -h 10.0.0.0/24", lines.append, timeout=5)
    assert sres.ok is True, sres
    assert lines == ["flag{from-pty-channel}"], lines
    client.delete("/api/shells/reverse/listeners")


class _HangPTY:
    """假 PTY 靶机：命令卡住时不再处理后续输入（模拟 ping 占住 shell），Ctrl+C 可恢复。"""
    def __init__(self, conn: socket.socket) -> None:
        self.conn = conn
        self.buf = b""
        self.hung = False
        self.got_ctrlc = threading.Event()
        self.raw_seen = bytearray()
        self.lock = threading.Lock()

    def run(self) -> None:
        try:
            self.conn.settimeout(0.5)
            while True:
                try:
                    data = self.conn.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not data:
                    break
                with self.lock:
                    self.raw_seen += data
                if b"\x03" in data:
                    self.hung = False
                    self.buf = b""       # Ctrl+C 后 shell 丢弃输入缓冲
                    self.got_ctrlc.set()
                    self.conn.sendall(b"\r\n<prompt>$ ")
                    data = data.replace(b"\x03", b"")
                if self.hung:
                    continue  # 卡住的命令不读后续输入（真实 shell 就是这样）
                self.buf += data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
                while b"\n" in self.buf:
                    line, self.buf = self.buf.split(b"\n", 1)
                    text = line.decode("utf-8", "replace").strip()
                    if text == "hang":
                        self.hung = True
                        self.buf = b""   # 同批次后续行（含哨兵）一并丢弃
                        break
                    elif text.startswith("echo "):
                        self.conn.sendall((text[5:] + "\r\n").encode())
                    elif text:
                        self.conn.sendall((text + "\r\n<prompt>$ ").encode())
        finally:
            self.conn.close()


def _hang_pty_client(port: int, ready: threading.Event, holder: dict) -> None:
    conn = None
    for _ in range(50):
        try:
            conn = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            break
        except OSError:
            time.sleep(0.1)
    ready.set()
    if conn is None:
        return
    pty = _HangPTY(conn)
    holder["pty"] = pty
    pty.run()


def test_reverse_exec_timeout_sends_ctrlc_and_recovers(client, sandbox_project):
    """ping 类卡死命令：超时后自动 Ctrl+C，通道可继续用（不再永久卡住）。"""
    port = _free_port()
    lid = _open_listener(client, port)
    holder: dict = {}
    ready = threading.Event()
    threading.Thread(target=_hang_pty_client, args=(port, ready, holder), daemon=True).start()
    assert ready.wait(3)
    assert _wait_connected(client, lid)

    shell_id, ch = _register_reverse(client, sandbox_project, lid)
    pty = holder["pty"]

    res = ch.exec("hang", timeout=1.2)
    assert res.ok is False and res.timed_out is True, res
    assert pty.got_ctrlc.wait(3), "超时后没有向目标发送 Ctrl+C"

    # 通道恢复：后续哨兵命令仍可正常拿到回显
    res2 = ch.exec("echo alive", timeout=3)
    assert res2.ok is True, res2
    assert "alive" in res2.output
    assert client.delete("/api/shells/reverse/listeners").json()["closed"] >= 1


def test_reverse_raw_sink_streams_and_api_input(client, sandbox_project):
    """原始模式：目标输出逐块推给订阅者；/input 直接写 PTY。"""
    from pivothub.api.shells import RAW_SINKS

    port = _free_port()
    lid = _open_listener(client, port)
    holder: dict = {}
    ready = threading.Event()
    threading.Thread(target=_hang_pty_client, args=(port, ready, holder), daemon=True).start()
    assert ready.wait(3)
    assert _wait_connected(client, lid)

    shell_id, ch = _register_reverse(client, sandbox_project, lid)
    chunks: list[str] = []
    ch.add_raw_sink(chunks.append)

    r = client.post(f"/api/shells/{shell_id}/input", json={"data": "whoami\r"})
    assert r.status_code == 200 and r.json()["ok"] is True
    deadline = time.time() + 3
    while time.time() < deadline and not any("whoami" in c for c in chunks):
        time.sleep(0.1)
    assert any("whoami" in c for c in chunks), chunks      # 命令回显进原始流
    assert any("<prompt>$" in c for c in chunks), chunks   # 真实提示符也在原始流里

    # 控制键映射：Ctrl+C 写入 \x03
    r = client.post(f"/api/shells/{shell_id}/input", json={"key": "ctrl-c"})
    assert r.status_code == 200 and r.json()["ok"] is True
    assert holder["pty"].got_ctrlc.wait(3)

    # /raw 开关：注册与注销订阅
    assert client.post(f"/api/shells/{shell_id}/raw", json={"on": True}).json()["raw"] is True
    assert shell_id in RAW_SINKS
    assert client.post(f"/api/shells/{shell_id}/raw", json={"on": False}).json()["raw"] is False
    assert shell_id not in RAW_SINKS
    client.delete("/api/shells/reverse/listeners")


def test_reverse_raw_input_rejects_http_shell(client, sandbox_project):
    host = client.get(f"/api/projects/{sandbox_project}/state").json()["hosts"][0]["id"]
    r = client.post("/api/shells", json={
        "projectId": sandbox_project, "hostId": host, "type": "PHP 一句话马",
        "url": "http://127.0.0.1:1/shell.php", "pass": "x", "encoder": "none",
        "autoCollect": False})
    sid = r.json()["id"]
    assert client.post(f"/api/shells/{sid}/input", json={"data": "ls\r"}).status_code == 400
    assert client.post(f"/api/shells/{sid}/raw", json={"on": True}).status_code == 400
    client.delete(f"/api/shells/{sid}")


def test_reverse_recent_output_replays_banner_without_sentinels(client, sandbox_project):
    """终端打开时回放缓冲尾部：能看到连接横幅/提示符，但不泄露哨兵内部标记。"""
    port = _free_port()
    lid = _open_listener(client, port)
    holder: dict = {}
    ready = threading.Event()
    threading.Thread(target=_hang_pty_client, args=(port, ready, holder), daemon=True).start()
    assert ready.wait(3)
    assert _wait_connected(client, lid)

    shell_id, ch = _register_reverse(client, sandbox_project, lid)
    ch.exec("echo BANNER_MARK")
    ch.exec("whoami")
    hist = ch.recent_output()
    assert "BANNER_MARK" in hist
    assert "<prompt>$" in hist
    assert "PH_" not in hist
    client.delete("/api/shells/reverse/listeners")


def test_reverse_eof_marks_shell_dead(client, sandbox_project):
    """靶机断开后会话必须标记断线（列表绿点不能骗人）。"""
    port = _free_port()
    lid = _open_listener(client, port)
    holder: dict = {}
    ready = threading.Event()
    threading.Thread(target=_hang_pty_client, args=(port, ready, holder), daemon=True).start()
    assert ready.wait(3)
    assert _wait_connected(client, lid)

    shell_id, ch = _register_reverse(client, sandbox_project, lid)
    st = client.get(f"/api/projects/{sandbox_project}/state").json()
    assert next(s for s in st["shells"] if s["id"] == shell_id)["alive"] is True

    holder["pty"].conn.close()  # 靶机侧断开
    deadline = time.time() + 5
    alive = True
    while time.time() < deadline:
        st = client.get(f"/api/projects/{sandbox_project}/state").json()
        alive = next(s for s in st["shells"] if s["id"] == shell_id)["alive"]
        if not alive:
            break
        time.sleep(0.2)
    assert alive is False


def test_reverse_strip_ansi_charset_and_csi():
    """ANSI 清洗要覆盖 ESC(B 字符集指定与 OSC——mysql 输出常见，漏掉会显示乱码。"""
    from pivothub.session.reverse import ReverseShellChannel as C

    raw = "\x1b(B\x1b(Bmysql  Ver 15.1\x1b[32m OK\x1b[0m\x1b]0;title\x07 done"
    assert C._clean_line(raw) == "mysql  Ver 15.1 OK done"
    assert C._strip_echo("cmd\r\n\x1b(Bout\x1b[0m\r\n", "cmd") == "out"


def test_reverse_listener_persisted_and_restored(client):
    """监听落库，面板重启（进程内监听清空）后按持久表恢复，id 保持不变。"""
    from pivothub.api.shells import restore_reverse_listeners
    from pivothub.session.reverse import SERVICE

    port = _free_port()
    lid = _open_listener(client, port)
    listed = client.get("/api/shells/reverse/listeners").json()["listeners"]
    me = next(x for x in listed if x["id"] == lid)
    assert me["active"] is True and me["error"] == ""

    # 模拟面板重启：清空进程内监听（持久表仍在），再走启动恢复
    SERVICE.close_all()
    gone = client.get("/api/shells/reverse/listeners").json()["listeners"]
    me = next(x for x in gone if x["id"] == lid)
    assert me["active"] is False  # 记录还在，但进程内已无监听

    out = restore_reverse_listeners()
    assert out["restored"] >= 1
    back = client.get("/api/shells/reverse/listeners").json()["listeners"]
    me = next(x for x in back if x["id"] == lid)
    assert me["active"] is True and me["bind"] == "127.0.0.1" and me["port"] == port

    # 显式关闭 → 持久记录一并删除
    assert client.delete(f"/api/shells/reverse/listeners/{lid}").json()["ok"] is True
    assert all(x["id"] != lid for x in client.get("/api/shells/reverse/listeners").json()["listeners"])


def test_reverse_listener_restore_reports_failure(client):
    """地址已失效时恢复失败要如实上报（不静默、不删记录）。"""
    from pivothub.api.shells import restore_reverse_listeners
    from pivothub.db import get_session_factory
    from pivothub.models import ReverseListener

    port = _free_port()
    db = get_session_factory()()
    try:
        db.add(ReverseListener(id="rev-deadbeef", bind="10.255.255.254", port=port,
                               label="已失效地址", created_at="2026-09-09 00:00:00"))
        db.commit()
    finally:
        db.close()

    out = restore_reverse_listeners()
    assert any(f["id"] == "rev-deadbeef" for f in out["failed"])
    listed = client.get("/api/shells/reverse/listeners").json()["listeners"]
    me = next(x for x in listed if x["id"] == "rev-deadbeef")
    assert me["active"] is False and me["error"]

    # 清理：删除这条失败记录
    client.delete("/api/shells/reverse/listeners/rev-deadbeef")


def test_detect_platform_from_echo():
    """平台识别：Linux 的 uname 回显 / Windows 的命令不存在回显 / 识别不出返回空。"""
    from pivothub.session.base import ExecResult
    from pivothub.session.reverse import detect_platform

    class Fake:
        def __init__(self, table):
            self.table = table

        def exec(self, cmd, timeout=15.0):
            return ExecResult(ok=True, output=self.table.get(cmd, ""))

    assert detect_platform(Fake({"uname -s": "Linux"})) == "linux"
    assert detect_platform(Fake({"uname -s": "Darwin"})) == "linux"
    assert detect_platform(Fake({
        "uname -s": "'uname' 不是内部或外部命令，也不是可运行的程序或批处理文件。",
        "ver": "Microsoft Windows [版本 10.0.19045.2965]",
    })) == "windows"
    assert detect_platform(Fake({})) == ""


def test_listener_marked_consumed_after_register(client, sandbox_project):
    """登记后监听必须自报「已转为会话」：socket 已随 take() 关闭，不能再显示等待回连。"""
    port = _free_port()
    lid = client.post("/api/shells/reverse/listen",
                      json={"bind": "127.0.0.1", "port": port, "waitS": 0}).json()["listener"]["id"]
    ready = threading.Event()
    threading.Thread(target=_echo_client, args=(port, ready), daemon=True).start()
    assert ready.wait(3)

    deadline = time.time() + 5
    while time.time() < deadline:
        me = next((x for x in client.get("/api/shells/reverse/listeners").json()["listeners"]
                   if x["id"] == lid), None)
        if me and me["connected"]:
            break
        time.sleep(0.2)

    reg = client.post("/api/shells/reverse/register", json={
        "projectId": sandbox_project, "listenerId": lid, "hostIp": "127.0.0.1",
        "type": "反弹 Shell（pytest-consumed）", "autoCollect": False}).json()
    assert reg["ok"] is True

    me = next(x for x in client.get("/api/shells/reverse/listeners").json()["listeners"]
              if x["id"] == lid)
    assert me["connected"] is False
    assert me["consumed"] is True          # 面板据此显示「已转为会话」而不是「等待回连」

    # 清理：删掉监听记录与会话
    client.delete(f"/api/shells/reverse/listeners/{lid}")
    client.delete(f"/api/shells/{reg['shell']['id']}")
