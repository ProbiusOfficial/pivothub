"""A7：SSH 会话驱动 + 路由 + 入参校验测试（不依赖真实 SSH 服务）。

仅跑本文件：
    python -m pytest tests/test_ssh.py -q -p no:warnings
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from pivothub.models import Host, Shell
from pivothub.session import SshSession, get_session, HttpShellSession
from pivothub.session.ssh import parse_ssh_url
from pivothub.schemas import SshIn


# ---------------------------------------------------------------------------
# 1) ssh:// URL 解析
# ---------------------------------------------------------------------------

def test_parse_ssh_url_full():
    user, host, port = parse_ssh_url("ssh://root@10.0.0.5:2222")
    assert user == "root"
    assert host == "10.0.0.5"
    assert port == 2222


def test_parse_ssh_url_default_port():
    user, host, port = parse_ssh_url("ssh://admin@192.168.1.10")
    assert user == "admin"
    assert host == "192.168.1.10"
    assert port == 22  # 缺省端口 22


def test_parse_ssh_url_no_scheme():
    user, host, port = parse_ssh_url("ubuntu@10.0.0.1:2200")
    assert user == "ubuntu"
    assert host == "10.0.0.1"
    assert port == 2200


def test_parse_ssh_url_no_user():
    user, host, port = parse_ssh_url("ssh://10.0.0.9")
    assert user == ""
    assert host == "10.0.0.9"
    assert port == 22


# ---------------------------------------------------------------------------
# 2) get_session 对 kind=ssh 返回 SshSession 且参数正确
# ---------------------------------------------------------------------------

def test_get_session_ssh_returns_ssh_session():
    s = Shell(
        id="s1", project_id="p", host_id="h", kind="ssh",
        type="SSH 会话", url="ssh://root@10.0.0.5:2222", pwd="secret",
    )
    sess = get_session(s)
    assert isinstance(sess, SshSession)
    assert sess.host == "10.0.0.5"
    assert sess.port == 2222
    assert sess.username == "root"
    assert sess.password == "secret"


def test_get_session_ssh_via_type_contains_ssh():
    s = Shell(
        id="s2", project_id="p", host_id="h", kind="",  # kind 空，但 type 含 ssh
        type="SSH 会话", url="ssh://alice@10.0.0.6", pwd="pw",
    )
    sess = get_session(s)
    assert isinstance(sess, SshSession)
    assert sess.username == "alice"
    assert sess.port == 22


# ---------------------------------------------------------------------------
# 3) 无真实服务时 connect() 抛 SessionError（保留端口，不依赖外网）
# ---------------------------------------------------------------------------

def test_connect_refused_raises_session_error():
    sess = SshSession(host="127.0.0.1", port=1, username="x", password="y",
                      timeout=3)
    with pytest.raises(Exception) as exc:  # SessionError 或其子类均可
        sess.connect()
    # 兜底层也是 SessionError（连接失败应带真实原因，不静默）
    from pivothub.session import SessionError
    assert isinstance(exc.value, SessionError)


# ---------------------------------------------------------------------------
# 4) SshIn 入参校验（缺用户名/主机报错）
# ---------------------------------------------------------------------------

def test_ssh_in_missing_username():
    with pytest.raises(ValidationError):
        SshIn(host="10.0.0.7")  # 缺 username


def test_ssh_in_missing_host():
    with pytest.raises(ValidationError):
        SshIn(username="root")  # 缺 host


def test_ssh_in_ok():
    form = SshIn(host="10.0.0.7", username="root", port=2222, password="p")
    assert form.host == "10.0.0.7"
    assert form.username == "root"
    assert form.port == 2222


# ---------------------------------------------------------------------------
# 5) 既有 HTTP 马 / 反弹通道路由不被破坏
# ---------------------------------------------------------------------------

def test_get_session_php_returns_http_shell():
    s = Shell(
        id="s3", project_id="p", host_id="h", kind="",
        type="PHP 一句话马", url="http://10.0.0.9/cmd.php", pwd="x",
    )
    sess = get_session(s)
    assert isinstance(sess, HttpShellSession)


def test_get_session_reverse_not_routed_through_ssh():
    # kind=reverse 不应被误判为 ssh（生产里 reverse 由 _open_session 走通道表，
    # 这里只验证 get_session 不会把它当成 SSH 去连）
    s = Shell(
        id="s4", project_id="p", host_id="h", kind="reverse",
        type="反弹 Shell（/dev/tcp）", url="reverse://10.0.0.8:4444", pwd="",
    )
    # 既有逻辑：lang_of 对 reverse 返回 unknown 抛 SessionError（不连 SSH）
    from pivothub.session import SessionError
    with pytest.raises(SessionError):
        get_session(s)
