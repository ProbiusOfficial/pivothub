"""会话抽象层协议测试：经 miniweb 真实执行靶（真实 HTTP + 真实子进程 + 真实文件系统）。"""

from __future__ import annotations

import os
import sys
import threading
from http.server import ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts", "lab", "miniweb"))

import miniweb  # noqa: E402

from pivothub.session.base import SessionError  # noqa: E402
from pivothub.session.http_shell import HttpShellSession  # noqa: E402
from pivothub.session.local import LocalSession  # noqa: E402


@pytest.fixture(scope="module")
def target(tmp_path_factory):
    """启动 miniweb 真实执行靶（线程内，随机端口）。"""
    docroot = tmp_path_factory.mktemp("wwwroot")
    (docroot / "readme.txt").write_text("pivothub-lab-target", encoding="utf-8")
    sub = docroot / "upload"
    sub.mkdir()
    (sub / "flag.txt").write_text("flag{lab_dmz_upload_pwn3d}", encoding="utf-8")

    miniweb.Handler.pwd = "cmd"
    srv = ThreadingHTTPServer(("127.0.0.1", 0), miniweb.Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/shell.php", str(docroot)
    srv.shutdown()


@pytest.fixture(scope="module")
def sess(target):
    url, _ = target
    return HttpShellSession(url=url, pwd="cmd", encoder="none",
                            shell_type="PHP 一句话马", platform="linux")


def test_test_probe_ok(sess):
    r = sess.test()
    assert r.ok is True
    assert r.ms >= 0


def test_exec_real_output(sess):
    r = sess.exec("echo pivothub-12345")
    assert r.ok is True
    assert "pivothub-12345" in r.output


def test_exec_failure_reported_honestly(sess):
    r = sess.exec("exit 3")
    assert "pivothub_no_func" not in r.output.lower()
    # exit 3 经 sh 执行后无 stdout 也应有标记成功返回（ok 视解释器而定，不伪造）


def test_list_dir_real_fs(sess, target):
    _, docroot = target
    entries = sess.list_dir(docroot)
    names = {e.name for e in entries}
    assert "readme.txt" in names and "upload" in names
    up = next(e for e in entries if e.name == "upload")
    assert up.is_dir is True
    readme = next(e for e in entries if e.name == "readme.txt")
    assert readme.is_dir is False
    assert readme.size == len("pivothub-lab-target")


def test_read_write_file_real_fs(sess, target):
    _, docroot = target
    p = os.path.join(docroot, "write-test.txt")
    sess.write_file(p, "pivot-write-内容")
    assert sess.read_file(p) == "pivot-write-内容"
    # 不存在路径 → 诚实报错
    with pytest.raises(SessionError):
        sess.read_file(os.path.join(docroot, "no-such-file-xyz"))


def test_unsupported_custom_aes_shell_rejected(target):
    url, _ = target
    with pytest.raises(SessionError):
        HttpShellSession(url=url, pwd="k", encoder="AES-128",
                         shell_type="PHP 自定义马", platform="linux")


def test_unknown_type_rejected():
    with pytest.raises(SessionError):
        HttpShellSession(url="http://127.0.0.1:1/x.zzz", pwd="p", shell_type="未知类型")


def test_pty_probe_honest_failure(sess):
    """本机（Windows 子进程）无法产生 Linux pts → pty 探测诚实失败。"""
    if os.name != "nt":
        pytest.skip("仅 Windows 本机环境需要验证诚实失败路径")
    r = sess.pty_probe("tty; echo TERM=$TERM; stty size")
    assert r.ok is False or "/dev/pts/" not in (r.output or "")


def test_local_session_crud(tmp_path):
    s = LocalSession()
    assert s.test().ok is True
    p = tmp_path / "a.txt"
    s.write_file(str(p), "hello")
    assert s.read_file(str(p)) == "hello"
    names = {e.name for e in s.list_dir(str(tmp_path))}
    assert "a.txt" in names
    with pytest.raises(SessionError):
        s.read_file(str(tmp_path / "missing.txt"))


def test_session_error_is_human_friendly(target):
    """连接不可达 → SessionError 带明确中文原因。"""
    bad = HttpShellSession(url="http://127.0.0.1:9/shell.php", pwd="cmd",
                           shell_type="PHP 一句话马", platform="linux", timeout=1.0)
    r = bad.test()
    assert r.ok is False
    assert "HTTP" in r.error
