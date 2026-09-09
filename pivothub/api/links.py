"""代理链路：部署（三种链路类型）/ 登记 / 健康检查 / 重拉 / 销毁。

部署端点承接 Adapter 全自动编排（generate_config → start → upload → execute →
wait_callback → verify），成功后登记 ProxyLink 并落逐层 pid；销毁时逐层清理，
不留孤儿进程。路由层零 subprocess（全部经 Adapter / 会话层）。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..config import DEFAULT_PROJECT_ID
from ..db import get_attack, get_db, now
from ..models import Host, ProxyLink, Shell
from ..schemas import LinkOut
from ..schemas.common import rid
from ..adapters import AdapterError, get_adapter, port_open
from ..session import SessionError, get_session
from ..service import add_event, plan_relay, segments_of
from ..util import proc_alive, proc_kill
from ..ws import manager
from .deps import get_project
from .shells import _ensure_reachable

router = APIRouter()

#: 链路类型枚举（与 assets/js/views/proxy.js 的 LINK_TYPES 一致）
LINK_TYPE_KEYS = ("socks", "portfwd", "relay")


def _get_link(db: Session, link_id: str) -> ProxyLink:
    """链路 id 全局唯一：按实体定位（与项目解耦，便于跨项目销毁残链）。"""
    l = db.get(ProxyLink, link_id)
    if not l:
        raise HTTPException(404, f"链路不存在: {link_id}")
    return l


def _session_for(db: Session, shell_id: str, platform: str = ""):
    """按 shellId 打开会话（并挂上 hostId，供 Adapter 记录逐层进程归属）。"""
    s = db.get(Shell, shell_id)
    if not s:
        raise HTTPException(404, f"Shell 不存在: {shell_id}")
    host = db.get(Host, s.host_id)
    if not host:
        raise HTTPException(404, "Shell 所属主机不存在")
    sess = get_session(s, host, platform=platform or None)
    sess.timeout = 8.0
    sess.host_id = host.id  # 进程归属（销毁时按层定位会话）
    return s, host, sess


class LinkIn(BaseModel):
    projectId: str = ""
    tool: str
    linkType: str = "socks"
    direction: str = "反向"
    fromHostId: str
    toHostId: str = ""
    localSocks: str = ""
    targetSegment: str = ""
    conf: str = ""
    note: str = ""
    listenPort: int = 0
    remoteBind: str = ""
    localPort: int = 0
    targetHost: str = ""
    targetPort: int = 0
    relayAddr: str = ""
    relayPort: int = 0
    hops: list[dict] = []
    pid: int | None = None
    pids: list[dict] = []
    latency: int = 0
    createdBy: str = "半自动档"


class DeployIn(BaseModel):
    projectId: str = ""
    shellId: str
    tool: str = "chisel"
    linkType: str = "socks"
    #: 攻击机地址：缺省取 /api/attack 配置（禁止写死 127.0.0.1）
    attackIp: str = ""
    #: 攻击机侧隧道服务端绑定地址（本机验证场景可显式给 127.0.0.1；默认 0.0.0.0）
    bindHost: str = "0.0.0.0"
    listenPort: int = 1331
    bindAddr: str = "0.0.0.0"
    localPort: int = 10006
    targetHost: str = ""
    targetPort: int = 0
    relayAddr: str = ""
    relayPort: int = 0
    #: 多级中继第 ② 步所在会话（上层跳板机 Shell）
    relayShellId: str = ""
    #: 目标平台（自动档按平台选二进制与命令；缺省按主机 OS 推导）
    platform: str = ""
    #: 目标侧暂存目录（Windows 需绝对路径）
    remoteDir: str = ""
    targetSegment: str = ""
    waitS: int = 45
    verify: bool = True


@router.get("/links/relay-plan")
def relay_plan(fromHostId: str, projectId: str = "", listenPort: int = 1331,
               localPort: int = 0, bindAddr: str = "0.0.0.0",
               db: Session = Depends(get_db)):
    """多级中继推导（与前端 proxy.js 同一套规则）：中继地址取上一层跳板在
    本层网段里的 IP（来自 ifaces），目标网段取本层双网卡机的第二块网卡段。"""
    project = get_project(db, projectId or DEFAULT_PROJECT_ID)
    host = db.get(Host, fromHostId)
    if not host:
        raise HTTPException(404, f"主机不存在: {fromHostId}")
    hosts = db.query(Host).filter(Host.project_id == project.id).all()
    links = db.query(ProxyLink).filter(ProxyLink.project_id == project.id).all()
    segs = [s["segment"] for s in segments_of(hosts)]
    attack = get_attack(db, project.id)
    plan = plan_relay(host, {h.id: h for h in hosts}, links, segs,
                      lhost=attack.get("ip", ""), listen_port=listenPort)
    # 给出第 ③ 步命令（本层节点回连），与前端 relay 分支一致
    if plan.relayAddr and localPort:
        plan.hops = plan.hops[:2] + [{
            "role": "本层双网卡节点回连",
            "hostId": host.id,
            "cmd": (f"./chisel client {plan.relayAddr}:{plan.relayPort} "
                    f"R:{bindAddr or '0.0.0.0'}:{int(localPort)}:socks"),
        }]
    return plan.to_dict()


@router.post("/links/{link_id}/verify")
def verify_link(link_id: str, db: Session = Depends(get_db)):
    """隧道内真实性验证：连本机入口读目标服务回显（socks/relay 经 Socks5 CONNECT）。

    portfwd 额外在跳板机侧实测目标服务可达性（仅本机入口可连不足以证明目标可达）。
    """
    l = _get_link(db, link_id)
    from ..adapters import get_adapter

    try:
        adapter = get_adapter(l.tool)
    except AdapterError as e:
        return JSONResponse({"ok": False, "error": str(e)})
    sess = None
    try:
        sh = (db.query(Shell)
              .filter(Shell.host_id == l.from_host_id, Shell.alive.is_(True)).first())
        if sh:
            _, _, sess = _session_for(db, sh.id)
    except Exception:
        sess = None
    target_host = l.target_host or l.relay_addr
    check = adapter.verify_tunnel(link_type=l.link_type or "socks",
                                  local_port=l.local_port or 0,
                                  target_host=target_host,
                                  target_port=l.target_port or 0,
                                  session=sess)
    l.latency = check.ms or l.latency
    db.commit()
    return {"ok": check.ok, **check.to_dict()}


@router.post("/links/deploy")
def deploy_link(form: DeployIn, db: Session = Depends(get_db)):
    """一键部署（自动档，chisel 首个真实 Adapter）：三种链路类型真实建立。

    失败时返回真实阶段与原因（不伪造成功），前端据此降级半自动档。
    """
    project = get_project(db, form.projectId or DEFAULT_PROJECT_ID)
    link_type = (form.linkType or "socks").strip()
    if link_type not in LINK_TYPE_KEYS:
        return JSONResponse({"ok": False, "stage": "linkType",
                             "error": f"不支持的链路类型: {link_type}（可选 {'/'.join(LINK_TYPE_KEYS)}）"})

    attack = get_attack(db, project.id)
    lhost = (form.attackIp or attack.get("ip") or "").strip()

    try:
        s, host, sess = _session_for(db, form.shellId, platform=form.platform)
        _ensure_reachable(sess)
    except SessionError as e:
        return JSONResponse({"ok": False, "stage": "reachable", "error": str(e)})

    relay_session = None
    relay_shell = None
    relay_host = None
    if link_type == "relay":
        if not form.relayShellId:
            return JSONResponse({"ok": False, "stage": "relay",
                                 "error": "多级中继需要 relayShellId（上层跳板机 Shell）"})
        try:
            relay_shell, relay_host, relay_session = _session_for(
                db, form.relayShellId, platform=form.platform)
            _ensure_reachable(relay_session)
        except SessionError as e:
            return JSONResponse({"ok": False, "stage": "relay_reachable", "error": str(e)})

    try:
        adapter = get_adapter(form.tool)
    except AdapterError as e:
        return JSONResponse({"ok": False, "stage": "adapter", "error": str(e)})

    result = adapter.deploy(
        sess, target_ip=host.ip, link_type=link_type,
        lhost=lhost, server_port=form.listenPort, local_port=form.localPort,
        bind=form.bindAddr or "0.0.0.0", target_host=form.targetHost,
        target_port=form.targetPort, relay_addr=form.relayAddr,
        relay_port=form.relayPort or form.listenPort, relay_session=relay_session,
        wait_s=form.waitS, verify=form.verify,
        verify_target=form.targetHost or host.ip, verify_port=form.targetPort,
        remote_dir=form.remoteDir, bind_host=form.bindHost,
    )
    if not result.ok:
        add_event(db, project.id, "proxy", f"自动档部署失败：{form.tool}（{link_type}）",
                  host_id=host.id, detail=f"阶段 {result.stage} · {result.error}")
        db.commit()
        return JSONResponse({"ok": False, "stage": result.stage, "error": result.error,
                             "linkType": link_type, "pids": result.pid_dicts(),
                             "verify": result.verify.to_dict() if result.verify else None,
                             "log": result.log})

    # 出口 = 当前项目的攻击端本机（反向隧道语义）；多级中继出口 = 上一层跳板
    attacker = db.query(Host).filter(Host.project_id == project.id, Host.is_local.is_(True)).first()
    if not attacker:
        if result.pid:
            proc_kill(result.pid)
        return JSONResponse({"ok": False, "stage": "register",
                             "error": "当前项目缺少攻击端本机节点，已回滚隧道进程"})

    to_host_id = attacker.id
    if link_type == "relay" and relay_host is not None:
        to_host_id = relay_host.id

    conf_line = ""
    if result.hops:
        conf_line = str(result.hops[-1].get("cmd", ""))
    pid_ok = bool(result.pid) and proc_alive(result.pid)
    l = ProxyLink(
        id=rid("p"), project_id=project.id, tool=form.tool, link_type=link_type,
        direction="反向", from_host_id=host.id, to_host_id=to_host_id,
        local_socks=f"{lhost}:{result.local_port or form.localPort}",
        target_segment=form.targetSegment or "",
        status="alive" if pid_ok else "error",
        latency=int(result.verify.ms) if result.verify else 0, traffic="0 B",
        conf=conf_line, created_by="自动档",
        note=(f"自动档部署 · lhost={lhost}"
              + (f" · 隧道内验证 {result.verify.target} 回显: {result.verify.banner[:60]}"
                 if result.verify and result.verify.ok else "")
              + ("" if pid_ok else " · 隧道进程核验失败（状态标记为 error）")),
        listen_port=form.listenPort, remote_bind=form.bindAddr or "0.0.0.0",
        local_port=result.local_port or form.localPort,
        target_host=form.targetHost, target_port=form.targetPort,
        relay_addr=form.relayAddr, relay_port=form.relayPort or form.listenPort,
        hops=result.hops, pid=result.pid, pids=result.pid_dicts(), created_at=now(),
    )
    db.add(l)
    add_event(db, project.id, "proxy",
              f"{form.tool} {link_type} 链路建立成功，登记 ProxyLink",
              host_id=host.id, cmd=l.conf,
              detail=(f"自动档 · 入口 {l.local_socks} → {l.target_segment or l.target_host}"
                      + (f" · 隧道内验证通过（{result.verify.banner[:40]}）" if result.verify and result.verify.ok else "")
                      + f" · 进程 {[p['pid'] for p in result.pid_dicts()]}"))
    db.commit()
    out = LinkOut.of(l)
    manager.push("link.created", link=out.model_dump())
    return {"ok": True, "link": out.model_dump(),
            "verify": result.verify.to_dict() if result.verify else None,
            "pids": result.pid_dicts(), "log": result.log}


@router.post("/links", response_model=LinkOut)
def create_link(form: LinkIn, db: Session = Depends(get_db)):
    """登记代理链路（隧道已真实建立：回连成功、本地 Socks 可用）。

    有 pid 时健康检查会核验进程真实存活；销毁按钮将真实结束该进程。
    """
    project = get_project(db, form.projectId or DEFAULT_PROJECT_ID)
    if not db.get(Host, form.fromHostId):
        raise HTTPException(404, f"入口主机不存在: {form.fromHostId}")
    if form.toHostId and not db.get(Host, form.toHostId):
        raise HTTPException(404, f"出口主机不存在: {form.toHostId}")
    if form.pid and not proc_alive(form.pid):
        raise HTTPException(422, f"本地进程 pid={form.pid} 不存在：隧道未真实运行，拒绝登记")

    l = ProxyLink(
        id=rid("p"), project_id=project.id, tool=form.tool,
        link_type=form.linkType or "socks", direction=form.direction or "反向",
        from_host_id=form.fromHostId, to_host_id=form.toHostId, local_socks=form.localSocks,
        target_segment=form.targetSegment or "", status="alive",
        latency=int(form.latency or 0), traffic="0 B", conf=form.conf or "",
        created_by=form.createdBy or "半自动档", note=form.note or "",
        listen_port=form.listenPort, remote_bind=form.remoteBind,
        local_port=form.localPort, target_host=form.targetHost,
        target_port=form.targetPort, relay_addr=form.relayAddr,
        relay_port=form.relayPort, hops=form.hops, pid=form.pid,
        pids=form.pids, created_at=now(),
    )
    db.add(l)
    add_event(db, project.id, "proxy", f"{l.tool} {l.direction}隧道回连成功，登记 ProxyLink",
              host_id=l.from_host_id, cmd=l.conf,
              detail=f"统一 Socks 入口 {l.local_socks} → {l.target_segment}"
                     + (f"（本机进程 pid={l.pid}）" if l.pid else ""))
    db.commit()
    out = LinkOut.of(l)
    manager.push("link.created", link=out.model_dump())
    manager.push("link.state", linkId=l.id, status=l.status, latency=l.latency, traffic=l.traffic)
    return out


@router.post("/links/{link_id}/check", response_model=LinkOut)
def check_link(link_id: str, db: Session = Depends(get_db)):
    """健康检查：有 pid 的链路核验进程真实存活 + 本机入口端口可连。"""
    l = _get_link(db, link_id)

    if l.status == "alive" and l.pid:
        if not proc_alive(l.pid):
            l.status = "error"
            l.note = (l.note or "") + " | 健康检查发现进程失联"
        elif l.local_port:
            if port_open(l.local_port):
                l.latency = max(1, l.latency or 1)
            else:
                l.status = "error"
                l.note = (l.note or "") + f" | 本机入口 {l.local_port} 不可连"
    db.commit()
    return LinkOut.of(l)


@router.post("/links/{link_id}/restart", response_model=LinkOut)
def restart_link(link_id: str, db: Session = Depends(get_db)):
    """重拉链路：结束旧进程后按同一参数重新部署（需要原始 shellId 时由前端重新部署）。"""
    l = _get_link(db, link_id)
    project_id = l.project_id
    if l.pid and proc_alive(l.pid):
        proc_kill(l.pid)
    l.pid = None
    l.status = "error"
    l.note = "旧进程已结束；请在代理编排台按同参数重新部署（自动档）"
    db.commit()
    add_event(db, project_id, "proxy", f"重拉代理链路：{l.tool}", host_id=l.from_host_id,
              detail=f"统一 Socks 入口 {l.local_socks}", push=True)
    out = LinkOut.of(l)
    manager.push("link.state", linkId=l.id, status=l.status, latency=l.latency, traffic=l.traffic)
    return out


@router.delete("/links/{link_id}")
def stop_link(link_id: str, db: Session = Depends(get_db)):
    """销毁链路：逐层结束进程（本机服务端 + 各层客户端），不留孤儿。"""
    l = _get_link(db, link_id)
    project_id = l.project_id
    killed: list[dict] = []

    records = list(l.pids or [])
    if l.pid and not any(int(r.get("pid") or 0) == l.pid for r in records):
        records.insert(0, {"pid": l.pid, "role": "server", "hostId": "", "cmd": "", "port": l.listen_port})

    # 远端进程经会话层结束（按 hostId 找该主机存活 Shell）
    sessions: dict[str, object] = {}

    def _sess_for(host_id: str):
        if not host_id:
            return None
        if host_id not in sessions:
            sh = (db.query(Shell)
                  .filter(Shell.host_id == host_id, Shell.alive.is_(True)).first())
            sessions[host_id] = None
            if sh:
                try:
                    _, _, sess = _session_for(db, sh.id)
                    sessions[host_id] = sess
                except Exception:
                    sessions[host_id] = None
        return sessions[host_id]

    for rec in records:
        pid = int(rec.get("pid") or 0)
        if not pid:
            continue
        role = rec.get("role")
        host_id = rec.get("hostId") or ""
        done = False
        if role == "server" or not host_id:
            done = proc_kill(pid)
        else:
            sess = _sess_for(host_id)
            if sess is not None:
                try:
                    done = bool(sess.kill_pid(pid))
                except Exception:
                    done = False
        # 兜底：pid 定位可能不准（客户端重连/同名进程）→ 按该层监听端口再核一次
        port = int(rec.get("port") or 0)
        if port:
            sess = _sess_for(host_id) if host_id else None
            if sess is not None:
                try:
                    if port_open(port, timeout=0.6):
                        owner = sess.pid_of_port(port)
                        if owner and owner != pid:
                            done = bool(sess.kill_pid(owner)) or done
                            rec = {**rec, "pid": owner}
                except Exception:
                    pass
        killed.append({**rec, "killed": done})

    l.pid = None
    l.pids = []
    l.status = "stopped"
    db.commit()
    detail = ("逐层清理 " + ", ".join(
        f"{k['pid']}:{'已结束' if k['killed'] else '未确认'}" for k in killed)) if killed \
        else "无进程记录（仅复位状态）"
    add_event(db, project_id, "proxy", f"销毁代理链路：{l.tool}（{l.link_type}）",
              host_id=l.from_host_id, detail=detail)
    manager.push("link.state", linkId=l.id, status=l.status, latency=l.latency, traffic=l.traffic)
    return {"stopped": l.id, "killed": killed}


def purge_link(db: Session, link_id: str) -> dict | None:
    """删除链路：先按销毁逻辑逐层结束进程，再把记录从库里删掉。

    销毁（stop）只复位状态、保留记录用于复盘；删除用于清掉不再需要的链路，
    列表与拓扑都不再残留。主机被移除时也走这里，避免留下孤儿链路。
    """
    l = db.get(ProxyLink, link_id)
    if not l:
        return None
    project_id, tool, link_type = l.project_id, l.tool, l.link_type
    try:
        stop_link(link_id, db)
    except Exception:
        db.rollback()
    row = db.get(ProxyLink, link_id)
    if row is not None:
        db.delete(row)
        db.commit()
    add_event(db, project_id, "proxy", f"删除代理链路记录：{tool}（{link_type}）",
              host_id=None, detail="进程已按销毁流程清理，记录不再保留")
    db.commit()
    manager.push("link.removed", linkId=link_id, projectId=project_id)
    return {"deleted": link_id, "tool": tool, "linkType": link_type}


@router.delete("/links/{link_id}/record")
def remove_link(link_id: str, db: Session = Depends(get_db)):
    """删除链路记录（先停进程再删库）：编排台「删除」按钮使用。"""
    out = purge_link(db, link_id)
    if out is None:
        raise HTTPException(404, "链路不存在")
    return out
