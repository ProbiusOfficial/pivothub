"""终端固化服务（PRD M1-8，P0）。

全部判定基于真实回显：
- 交互能力检测：真实执行 `tty` / `echo $TERM` / `stty size` / `which` 工具探测并解析输出；
- PTY 判定：在目标侧真实拉起 PTY（python pty.spawn / script），在其内执行
  `tty; echo $TERM; stty size`，依据回显（/dev/pts/*、TERM≠dumb、rows cols）判定；
- 技法库：data/tty_fixes/*.json 插件，不在代码里写死；
- 收尾：真实执行 `stty sane` + `stty rows/cols`（窗口尺寸同步）并回读 `stty size` 验证。
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Optional

from ..session.base import ExecResult, SessionBase, SessionError

PTS_RE = re.compile(r"/dev/(pts/\d+|tty\w+|ttys\d+|console)")
NOT_A_TTY = "not a tty"
SIZE_RE = re.compile(r"(\d{1,4})\s+(\d{1,4})")

# 可真正建立 PTY 的技法 id（data/tty_fixes 插件中的 platform 语义标记）
PTY_TECHNIQUES = {"lx-python", "lx-python-alt", "lx-script", "lx-socat", "lx-nc-fifo"}
# 反向通道技法：需要攻击端监听，MS3 与回连监听一起启用
REVERSE_TECHNIQUES = {"lx-socat", "lx-nc-fifo", "win-ps"}


@dataclass
class TtyCaps:
    has_tty: bool = False
    term: str = ""
    shell: str = ""
    stty_size: Optional[tuple[int, int]] = None
    python: bool = False
    script: bool = False
    socat: bool = False
    nc: bool = False
    powershell: bool = False
    os: str = "linux"

    def to_dict(self) -> dict:
        return {
            "tty": self.has_tty, "term": self.term, "shell": self.shell,
            "python": self.python, "script": self.script, "socat": self.socat,
            "nc": self.nc, "powershell": self.powershell, "os": self.os,
            "sttySize": list(self.stty_size) if self.stty_size else None,
        }


# ---------------- 纯解析函数（可单测，输入=真实回显样本） ----------------

def parse_tty_output(output: str) -> bool:
    """`tty` 真实回显 → 是否有控制终端。"""
    if NOT_A_TTY in output.lower():
        return False
    return bool(PTS_RE.search(output))


def parse_term_output(output: str) -> str:
    """`echo $TERM` 真实回显 → TERM 值（去引号/空白）。"""
    t = output.strip().strip('"').strip("'")
    return t if t and "=" not in t else (t.split("=")[-1] if "=" in t else "")


def parse_stty_size(output: str) -> Optional[tuple[int, int]]:
    """`stty size` 真实回显 → (rows, cols)；失败返回 None。"""
    m = SIZE_RE.search(output)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


def parse_which_output(output: str) -> list[str]:
    """`which python3 python script socat nc` 回显 → 可用工具名列表。"""
    tools = []
    for line in output.splitlines():
        p = line.strip()
        if not p or " " in p and not p.startswith("/"):
            continue
        if "/" in p:
            tools.append(p.rsplit("/", 1)[-1])
    return tools


def judge_mode(has_tty: bool, term: str, stty_size: Optional[tuple], platform: str) -> str:
    """终端形态三态判定（真实依据：PTY / TERM / 窗口尺寸）。"""
    if platform == "windows":
        return "dumb"  # Windows cmd 无真实 TTY 概念（ConPTY 后续接入）
    if has_tty and term and term.lower() != "dumb":
        return "full"
    if has_tty:
        return "semi"
    return "dumb"


# ---------------- 交互能力检测（真实探测） ----------------

LINUX_PROBES = [
    ("tty", "tty"),
    ("term", "echo $TERM"),
    ("stty", "stty size"),
    ("shell", "echo $0"),
    ("tools", "which python3 python script socat nc 2>/dev/null"),
]
WINDOWS_PROBES = [
    ("comspec", "echo %COMSPEC%"),
    ("ps", "where powershell"),
    ("ver", "ver"),
]


def detect(session: SessionBase) -> dict:
    """真实交互能力检测。返回与前端契约一致的结论。"""
    platform = session.platform
    probes = WINDOWS_PROBES if platform == "windows" else LINUX_PROBES
    outputs: dict[str, str] = {}
    probe_lines: list[dict] = []
    for key, cmd in probes:
        probe_lines.append({"kind": "in", "text": cmd})
        try:
            res: ExecResult = session.exec(cmd)
            out = res.output or (res.error and f"[!] {res.error}") or ""
            if not res.ok and res.error and not res.output:
                out = res.error
        except SessionError as e:
            out = f"[!] {e}"
        outputs[key] = out or ""
        warn = bool(out) and (
            (NOT_A_TTY in out.lower())
            or ("dumb" in out.lower())
            or ("Inappropriate ioctl" in out)
            or (key == "stty" and not parse_stty_size(out))
        )
        probe_lines.append({"kind": "warn" if warn else "out", "text": out})

    caps = TtyCaps(os=platform)
    if platform == "windows":
        caps.powershell = "powershell" in (outputs.get("ps", "") or "").lower()
        caps.shell = (outputs.get("comspec", "") or "").strip() or "cmd.exe"
        mode = "dumb"
        tools_txt = "powershell 可用" if caps.powershell else "无"
        summary = f"Windows 主机 · cmd/powershell 探测完成 · 无真实 TTY（ConPTY 后续接入）"
    else:
        caps.has_tty = parse_tty_output(outputs.get("tty", ""))
        caps.term = parse_term_output(outputs.get("term", ""))
        caps.stty_size = parse_stty_size(outputs.get("stty", ""))
        caps.shell = (outputs.get("shell", "") or "").strip() or "/bin/sh"
        for tool in parse_which_output(outputs.get("tools", "")):
            if tool in ("python3", "python", "script", "socat", "nc"):
                setattr(caps, "python" if tool.startswith("python") else tool, True)
        mode = judge_mode(caps.has_tty, caps.term, caps.stty_size, platform)
        parts = []
        if not caps.has_tty:
            parts.append("无 TTY（tty = not a tty）")
        if not caps.term or caps.term.lower() == "dumb":
            parts.append("TERM=dumb")
        if not caps.stty_size:
            parts.append("stty size 不可用")
        summary = ("检测结论：" + (" · ".join(parts) if parts else "已具备交互终端要素")
                   + " · 可用工具：" + (
                       "/".join([n for n, ok in [
                           ("python3", caps.python), ("script", caps.script),
                           ("socat", caps.socat), ("nc", caps.nc)] if ok]) or "无"))
        tools_txt = ""

    return {
        "caps": caps.to_dict(),
        "mode": mode,
        "probeLines": probe_lines,
        "summary": summary,
        "toolsTxt": tools_txt,
    }


# ---------------- PTY 验证（固化判定的核心） ----------------

PTY_VERIFY_INNER = 'tty; echo "TERM=$TERM"; stty size; id'


def parse_pty_verify(output: str) -> dict:
    """从 PTY 内 `tty; echo TERM; stty size; id` 的真实回显判定是否拿到 PTY。"""
    has_tty = parse_tty_output(output)
    term = ""
    m = re.search(r'TERM=(.*)', output)
    if m:
        term = m.group(1).strip()
    size = parse_stty_size(output)
    uid_line = next((ln for ln in output.splitlines() if ln.startswith("uid=")), "")
    has_pty = has_tty and bool(term) and term.lower() != "dumb" and size is not None
    return {
        "hasPty": has_pty,
        "tty": (PTS_RE.search(output).group(0) if PTS_RE.search(output) else ""),
        "term": term,
        "sttySize": list(size) if size else None,
        "uid": uid_line,
        "raw": output,
    }


# ---------------- 技法执行 / 收尾 ----------------

def technique_kind(fix: dict) -> str:
    fid = fix.get("id", "")
    if fid in REVERSE_TECHNIQUES:
        return "reverse"
    if fid in PTY_TECHNIQUES:
        return "pty"
    if fix.get("manual"):
        return "manual"
    return "inline"


def is_reverse_session(session: SessionBase) -> bool:
    """是否反弹（回连）通道会话：这类通道本身就是交互 shell，PTY 技法直接下发即可。"""
    return getattr(session, "kind", "") in ("reverse", "reverse-shell")


def render_technique_cmd(cmd: str, lhost: str = "127.0.0.1", lport: int = 4444) -> str:
    """技法命令里的占位符按当前攻击机地址/端口渲染（注释行剔除后拼成单行）。"""
    lines = [ln.strip() for ln in (cmd or "").splitlines()
             if ln.strip() and not ln.strip().startswith("#")]
    text = "; ".join(lines) or (cmd or "")
    return (text.replace("$LHOST", str(lhost)).replace("$LPORT", str(lport))
                .replace("$IP", str(lhost)))


def _upgrade_via_channel(session: SessionBase, fix: dict) -> dict:
    """反弹通道上执行 PTY 技法：原始写入通道 → 等 PTY 起来 → 真实回读验证。

    为什么要走原始写入：该通道的目标侧已经被一个交互 shell 占着，PTY 技法是
    「在当前 shell 里套一层 PTY」（pty.spawn / script），经哨兵 exec 下发会与
    新拉起的 PTY 抢同一份输出；写入后统一用 PTY 验证探针回读判定。
    """
    write = getattr(session, "write_raw", None)
    if write is None:
        return {"hasPty": False, "reason": "该会话不支持原始通道写入", "summary": "通道不支持"}
    cmd = render_technique_cmd(fix.get("cmd", ""))
    if not cmd:
        return {"hasPty": False, "reason": "技法命令为空", "summary": "无可执行命令"}
    try:
        write(cmd + "\n")
    except OSError as e:
        return {"hasPty": False, "reason": f"通道写入失败：{e}", "summary": "通道写入失败"}
    time.sleep(1.2)  # 给目标侧把 PTY 拉起来的时间
    try:
        res = session.exec(PTY_VERIFY_INNER, timeout=12)
    except SessionError as e:
        return {"hasPty": False, "execOk": False, "cmd": cmd,
                "reason": str(e), "summary": "PTY 验证失败"}
    verdict = parse_pty_verify(res.output or "")
    verdict["execOk"] = res.ok
    verdict["viaChannel"] = True
    verdict["cmd"] = cmd
    if verdict["hasPty"]:
        verdict["summary"] = f"已在反弹通道内拉起 PTY（{verdict.get('tty') or 'pts'}）"
    else:
        verdict["reason"] = res.error or "PTY 内验证未通过（缺 pts / TERM=dumb / stty 不可用）"
    return verdict


def upgrade(session: SessionBase, fix: dict, lhost: str = "127.0.0.1", lport: int = 4444) -> dict:
    """执行固化技法并依据真实回显判定 PTY。

    - 反弹通道（kind=reverse-shell）：技法命令直接写进通道（它本身就是交互 shell），
      再用 PTY 验证探针回读判定；
    - pty 类（python/script）：在目标侧真实拉起 PTY 并在其内执行验证命令；
      判定依据 = PTY 内 `tty` 输出 pts、TERM≠dumb、`stty size` 返回行列。
    - inline 类（env 修正 / reset / cmd 加固）：真实执行 + 回显确认。
    - reverse 类（socat/nc/PowerShell 反向）：需要攻击机先开监听，返回按当前攻击机
      地址渲染好的命令与明确指引（不再是一句「待 MS3」的占位文案）。
    """
    kind = technique_kind(fix)
    fid = fix.get("id")

    if is_reverse_session(session):
        if kind in ("pty", "inline"):
            return _upgrade_via_channel(session, fix)
        if kind == "reverse":
            return {
                "hasPty": False, "fallback": "channel",
                "cmd": render_technique_cmd(fix.get("cmd", ""), lhost, lport),
                "reason": f"当前会话已是反弹交互通道，无需「{fix.get('name')}」再拉一条反向连接；"
                          "想要完整 PTY 请用 Python PTY / script 技法（会直接在当前通道内生效）。",
                "summary": "已是反弹通道，反向技法不适用",
            }

    if kind == "reverse":
        return {
            "hasPty": False, "execOk": False,
            "cmd": render_technique_cmd(fix.get("cmd", ""), lhost, lport),
            "reason": "该技法需要攻击机先开监听：到「反弹 Shell」页开好监听（地址/端口同上），"
                      "用「② 发送到该会话」下发即可自动登记会话。命令行已按当前攻击机地址渲染，"
                      "也可直接复制到本会话执行。",
            "summary": "反向技法需回连监听（命令已渲染）",
        }

    if kind == "pty":
        if not session.supports_pty_probe:
            return {
                "hasPty": False,
                "reason": "该会话驱动不支持 PTY 拉起（平台限制）",
                "summary": "目标平台无法拉起 PTY",
            }
        res = session.pty_probe(PTY_VERIFY_INNER)
        verdict = parse_pty_verify(res.output or "")
        verdict["execOk"] = res.ok
        if not verdict["hasPty"]:
            verdict["reason"] = res.error or "PTY 内验证未通过（缺 pts / TERM=dumb / stty 不可用）"
        return verdict

    # inline：真实执行技法命令
    exec_cmd = render_technique_cmd(fix.get("cmd", ""), lhost, lport)
    res = session.exec(exec_cmd)
    out: dict = {"hasPty": False, "execOk": res.ok, "raw": res.output, "error": res.error}
    if res.ok and fid == "lx-env":
        # env 修正后真实回读 TERM 验证
        chk = session.exec('echo "TERM=$TERM"')
        m = re.search(r"TERM=(\S+)", chk.output or "")
        out["term"] = m.group(1) if m else ""
        out["summary"] = f"TERM 已设为 {out['term']}" if m else "env 已更新（TERM 读取失败）"
    elif res.ok:
        out["summary"] = f"技法「{fix.get('name')}」已执行" + (f"：{res.output.strip()[:80]}" if res.output.strip() else "")
    else:
        out["reason"] = res.error or "执行失败"
    return out


def finish(session: SessionBase, rows: int = 40, cols: int = 120) -> dict:
    """收尾：真实执行 stty sane + 行列同步 + TERM 修正，并回读验证。

    说明：`stty raw -echo` 用于攻击端本地终端（反向通道场景，MS3 随回连监听处理）；
    面板会话的收尾在目标 PTY 内执行 sane + rows/cols，保证 vim/top 渲染与窗口同步。
    """
    inner = (
        f'stty sane 2>/dev/null; stty rows {rows} cols {cols} 2>/dev/null; '
        'stty size; echo "TERM=$TERM"'
    )
    try:
        if session.supports_pty_probe:
            res = session.pty_probe(inner)
        else:
            res = session.exec(inner)
    except SessionError as e:
        return {"ok": False, "reason": str(e)}
    size = parse_stty_size(res.output or "")
    m = re.search(r"TERM=(\S+)", res.output or "")
    return {
        "ok": res.ok and size is not None,
        "rows": size[0] if size else None,
        "cols": size[1] if size else None,
        "term": m.group(1) if m else "",
        "output": res.output,
        "summary": (
            f"stty sane 已生效 · 窗口尺寸同步 rows={size[0]} cols={size[1]}"
            + (f" · TERM={m.group(1)}" if m else "")
            if size else "收尾命令已执行，但未能回读 stty size（目标可能无 PTY）"
        ),
    }
