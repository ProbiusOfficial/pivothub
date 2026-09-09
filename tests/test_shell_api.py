"""Shell API 真实化端到端测试（M1-3/M1-4/M1-8）：登记→执行→文件→固化流程。

通过 miniweb 真实执行靶验证 REST 层与会话层的贯通。
"""

from __future__ import annotations

import os
import sys
import threading
from http.server import ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts", "lab", "miniweb"))

import miniweb  # noqa: E402


@pytest.fixture(scope="module")
def lab(client, tmp_path_factory):
    """启动 miniweb + 经面板 API 真实登记主机与 Shell。"""
    docroot = tmp_path_factory.mktemp("lab-root")
    (docroot / "note.txt").write_text("lab-note-content", encoding="utf-8")

    miniweb.Handler.pwd = "cmd"
    srv = ThreadingHTTPServer(("127.0.0.1", 0), miniweb.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    # 登记主机（Linux 指纹 → 会话按 linux 平台处理）
    r = client.post("/api/hosts", json={
        "ip": "127.0.0.9", "hostname": "miniweb-lab", "os": "Ubuntu 20.04 (lab)",
        "layer": "L1", "note": "本机联调靶",
    })
    assert r.status_code == 200, r.text
    host_id = r.json()["id"]

    # 登记 Shell：触发真实连通测试 + autoCollect
    r = client.post("/api/shells", json={
        "hostId": host_id, "type": "PHP 一句话马",
        "url": f"http://127.0.0.1:{srv.server_address[1]}/shell.php",
        "pass": "cmd", "encoder": "none", "autoCollect": True,
    })
    assert r.status_code == 200, r.text
    shell = r.json()
    assert shell["alive"] is True, "miniweb 靶应通过真实协议探针"

    yield {"shellId": shell["id"], "hostId": host_id, "docroot": str(docroot)}
    srv.shutdown()


def test_registered_shell_alive_with_latency(client, lab):
    d = client.get("/api/projects/proj-1/state").json()
    s = next(x for x in d["shells"] if x["id"] == lab["shellId"])
    assert s["alive"] is True and s["latency"] >= 0
    assert s["lastBeat"]  # 心跳时间已落库


def test_exec_real_command(client, lab):
    r = client.post(f"/api/shells/{lab['shellId']}/exec", json={"cmd": "echo pivot-exec-42"})
    assert r.status_code == 200
    body = r.json()
    assert "pivothubFallback" not in body
    assert "pivot-exec-42" in body["output"]


def test_files_list_real_fs(client, lab):
    r = client.get(f"/api/shells/{lab['shellId']}/files", params={"path": lab["docroot"]})
    assert r.status_code == 200
    body = r.json()
    assert "pivothubFallback" not in body
    names = {e["name"] for e in body["entries"]}
    assert "note.txt" in names
    note = next(e for e in body["entries"] if e["name"] == "note.txt")
    assert note["dir"] is False and note["size"].endswith("B")


def test_files_list_hides_dot_entries(client, lab):
    """. / .. 由前端面包屑导航，不再作为条目下发。"""
    r = client.get(f"/api/shells/{lab['shellId']}/files", params={"path": lab["docroot"]})
    names = {e["name"] for e in r.json()["entries"]}
    assert "." not in names and ".." not in names


def test_files_list_missing_path_reports_error(client, lab):
    """路径不存在要如实报错，不能静默返回空目录（前端看起来像空目录）。"""
    missing = os.path.join(lab["docroot"], "no-such-dir-xyz")
    r = client.get(f"/api/shells/{lab['shellId']}/files", params={"path": missing})
    assert r.status_code == 200
    body = r.json()
    assert body.get("pivothubFallback") is True
    assert body.get("reason")  # 带出真实原因


def test_files_read_write_roundtrip(client, lab):
    p = os.path.join(lab["docroot"], "edit-me.txt")
    r = client.post(f"/api/shells/{lab['shellId']}/files/write",
                    json={"path": p, "content": "pivot-edit-round"})
    assert r.status_code == 200 and r.json()["ok"] is True
    r = client.get(f"/api/shells/{lab['shellId']}/files/content", params={"path": p})
    assert r.status_code == 200
    assert r.json()["content"] == "pivot-edit-round"


def test_files_upload_real(client, lab):
    import base64

    r = client.post(f"/api/shells/{lab['shellId']}/files/upload", json={
        "path": lab["docroot"], "name": "uploaded-by-panel.txt",
        "contentB64": base64.b64encode("panel-upload-77".encode()).decode(),
    })
    assert r.status_code == 200
    assert r.json()["ok"] is True
    raw = open(os.path.join(lab["docroot"], "uploaded-by-panel.txt"), "rb").read()
    assert raw == b"panel-upload-77"


def test_files_upload_binary_roundtrip(client, lab):
    """二进制上传必须逐字节一致（旧实现按 UTF-8 文本解码会损坏文件）。"""
    import base64

    data = bytes(range(256)) + b"\x00\xff\xfePivotHub"
    r = client.post(f"/api/shells/{lab['shellId']}/files/upload", json={
        "path": lab["docroot"], "name": "binary-blob.bin",
        "contentB64": base64.b64encode(data).decode(),
    })
    assert r.status_code == 200
    assert r.json()["ok"] is True
    raw = open(os.path.join(lab["docroot"], "binary-blob.bin"), "rb").read()
    assert raw == data


def test_tty_detect_real_probes(client, lab):
    """检测：真实执行探测命令并解析（本机 Windows 子进程 → 诚实报 dumb）。"""
    r = client.post(f"/api/shells/{lab['shellId']}/tty/detect")
    assert r.status_code == 200
    body = r.json()
    assert "pivothubFallback" not in body
    assert body["mode"] in ("dumb", "semi", "full")
    assert body["caps"]["os"] == "linux"
    # probeLines 含真实执行的命令（tty / echo $TERM / stty size / which）
    texts = [ln["text"] for ln in body["probeLines"]]
    assert "tty" in texts and "stty size" in texts
    assert body["summary"]


def test_tty_upgrade_honest_failure_on_non_pty_target(client, lab):
    """本机无 Linux pty → lx-python 技法诚实判定失败（不得伪造 hasPty）。"""
    r = client.post(f"/api/shells/{lab['shellId']}/tty/upgrade", json={"fixId": "lx-python"})
    assert r.status_code == 200
    body = r.json()
    assert "pivothubFallback" not in body
    assert body["hasPty"] is False
    assert body.get("reason")


def test_tty_finish_returns_verdict(client, lab):
    r = client.post(f"/api/shells/{lab['shellId']}/tty/finish", json={"rows": 40, "cols": 120})
    assert r.status_code == 200
    body = r.json()
    assert "pivothubFallback" not in body
    assert body["ok"] in (True, False)
    assert body["summary"]


def test_stable_persisted_after_full_loop(client, lab):
    """检测→固化→收尾 后 Shell.stable 正确落库（本机环境走诚实失败路径，
    Linux 靶机（scripts/lab 场景1）上为成功路径）。"""
    d = client.get("/api/projects/proj-1/state").json()
    s = next(x for x in d["shells"] if x["id"] == lab["shellId"])
    assert s["stable"] is False  # 本机靶无法建立 Linux PTY → 不允许虚标


# ---------------------------------------------------------------------------
# 列目录解析（JSP/ASPX 退化路径与反弹通道共用）：大小/时间/错误识别
# ---------------------------------------------------------------------------

def test_parse_ls_output_captures_size_and_dirs():
    from pivothub.session.base import parse_ls_output

    text = (
        "total 24\n"
        "drwxr-xr-x 1 root root 4096 2026-09-08 07:02 .\n"
        "drwxr-xr-x 1 root root 4096 2026-09-08 07:02 ..\n"
        "-rw-r--r-- 1 root root 1234 2026-09-09 06:39 flag1.txt\n"
        "drwxr-xr-x 2 root root 4096 2026-09-09 03:30 tmp\n"
    )
    entries = {e.name: e for e in parse_ls_output(text)}
    assert entries["flag1.txt"].size == 1234 and entries["flag1.txt"].is_dir is False
    assert entries["flag1.txt"].mtime == "2026-09-09 06:39"
    assert entries["tmp"].is_dir is True


def test_ls_error_text_flags_missing_path():
    from pivothub.session.base import ls_error_text

    err = ls_error_text("ls: cannot access '/no-such-dir': No such file or directory")
    assert "No such file" in err
    assert ls_error_text("total 0\ndrwxr-xr-x 1 root root 4096 2026-09-08 07:02 .\n") == ""
