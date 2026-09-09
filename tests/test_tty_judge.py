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


def test_upgrade_reverse_technique_deferred_with_reason():
    from pivothub.service.tty import technique_kind, upgrade

    class Dummy:
        supports_pty_probe = False
        platform = "linux"

        def exec(self, cmd, timeout=15.0):
            raise AssertionError("reverse 技法不应执行命令")

    fix = {"id": "lx-socat", "name": "socat 全交互 PTY"}
    assert technique_kind(fix) == "reverse"
    out = upgrade(Dummy(), fix)
    assert out["hasPty"] is False
    assert "MS3" in out["reason"]


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
