"""项目：列表 / 全量状态 / 新建 / 删除。"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..config import DEFAULT_PROJECT_ID
from ..db import default_attack, get_attack, get_db, now, set_stages
from ..localinfo import iface_for, machine
from ..models import Credential, Flag, Host, Project, ProxyLink, Shell, TimelineEvent
from ..schemas import ProjectBrief, StateOut
from ..schemas.common import rid
from ..service import add_event
from ..ws import manager
from .deps import build_state, list_projects

router = APIRouter()


@router.get("/projects", response_model=list[ProjectBrief])
def projects(db: Session = Depends(get_db)):
    return list_projects(db)


class ProjectIn(BaseModel):
    name: str
    durationSec: int = 4 * 3600
    note: str = ""


def _inherit_attack(db: Session) -> dict:
    """新建项目的攻击机网络模板：优先取演示项目；演示项目已删则取任意现存项目。"""
    if db.get(Project, DEFAULT_PROJECT_ID) is not None:
        return get_attack(db, DEFAULT_PROJECT_ID)
    other = db.query(Project).first()
    return get_attack(db, other.id) if other is not None else default_attack()


@router.post("/projects", response_model=ProjectBrief)
def create_project(form: ProjectIn, db: Session = Depends(get_db)):
    """新建项目 = 干净工作区：仅带攻击端本机节点（拓扑根），其余全空。"""
    name = form.name.strip()
    if not name:
        raise HTTPException(400, "项目名称不能为空")
    pid = rid("proj")
    attack = _inherit_attack(db)
    info = machine()
    iface = iface_for(attack["ip"]) or attack.get("iface") or ""
    db.add(Project(id=pid, name=name, start_at=now().strftime("%H:%M"),
                   duration_sec=form.durationSec, note=form.note,
                   settings={"attack": dict(attack)}))
    db.add(Host(
        id=rid("h"), project_id=pid, ip=attack["ip"], hostname=info["hostname"],
        os=info["os"], layer="LOCAL", segment=attack.get("segment") or "LOCAL",
        privilege=info["privilege"], owned=True, ports=[], services=[],
        note=f"攻击端本机（{iface or 'iface'} · {attack['ip']}）· 面板运行位置",
        discovery="本地", is_local=True,
        ifaces=[{"iface": iface, "ip": attack["ip"],
                 "segment": attack.get("segment", "")}],
    ))
    add_event(db, pid, "host", f"新建项目：{name}",
              detail=f"已创建攻击端本机节点 {attack['ip']}（取当前攻击机网络配置）")
    db.commit()
    return ProjectBrief(id=pid, name=name)


@router.delete("/projects/{project_id}")
def delete_project(project_id: str, db: Session = Depends(get_db)):
    """删除项目：先按销毁流程清理链路进程与会话通道，再级联删除该项目全部数据。

    保护：至少保留一个项目（面板始终需要一个工作区）；攻击端本机节点随项目一并删除。
    """
    p = db.get(Project, project_id)
    if p is None:
        raise HTTPException(404, "项目不存在")
    if db.query(Project).count() <= 1:
        raise HTTPException(400, "至少保留一个项目，无法删除最后一个项目")
    name = p.name

    # 1) 链路：purge_link 内部按销毁流程逐层结束进程；逐层清理要借主机上的存活会话，
    #    因此必须在删除会话之前做（与 hosts 移除资产的顺序一致）
    links = db.query(ProxyLink).filter(ProxyLink.project_id == project_id).all()
    if links:
        from .links import purge_link  # 局部导入：links 路由依赖 hosts 的 valid_ip

        for l in list(links):
            try:
                purge_link(db, l.id)
            except Exception:  # 进程清理尽力而为，不能因此删不掉项目
                db.rollback()

    # 2) 会话：先关闭进程内反弹通道（含原始推送订阅），再删记录
    from .shells import close_channel

    shells = db.query(Shell).filter(Shell.project_id == project_id).all()
    for s in shells:
        close_channel(s.id)
        db.delete(s)

    # 3) 凭据 / Flag 随项目一并移除
    creds = db.query(Credential).filter(Credential.project_id == project_id).all()
    flags = db.query(Flag).filter(Flag.project_id == project_id).all()
    for row in creds + flags:
        db.delete(row)

    # 4) 时间线先删（host_id 是指向 hosts 的外键），再删主机，最后删项目本身
    events = db.query(TimelineEvent).filter(TimelineEvent.project_id == project_id).all()
    for ev in events:
        db.delete(ev)
    db.flush()

    hosts = db.query(Host).filter(Host.project_id == project_id).all()
    for h in hosts:
        db.delete(h)
    db.flush()

    db.delete(p)
    db.commit()

    manager.push("project.removed", projectId=project_id)
    return {
        "deleted": project_id, "name": name,
        "hosts": len(hosts), "shells": len(shells), "links": len(links),
        "creds": len(creds), "flags": len(flags), "events": len(events),
    }


@router.get("/projects/{project_id}/state", response_model=StateOut)
def project_state(project_id: str, db: Session = Depends(get_db)):
    """面板启动的第一步。空库时先兜底建默认项目再返回 —— 404 会让前端跳过
    WS 连接（表现为「WS 连接失败 / 后端不可用」），所以这里必须自愈。"""
    from ..db import ensure_default_project

    if db.get(Project, project_id) is None:
        if ensure_default_project(db) is not None:
            db.commit()
    return build_state(db, project_id)


class StagesIn(BaseModel):
    """阶段自定义（A12）：传空列表 = 恢复默认阶段名。"""

    projectId: str = ""
    stages: list[str] = []


@router.put("/stages")
def update_stages(form: StagesIn, projectId: str = "", db: Session = Depends(get_db)):
    """保存项目级阶段名（Flag 墙分阶段统计与下拉的数据源）。

    去重保序、自动去空白；空列表回落到 data/meta.json 的默认阶段名。
    阶段名只影响展示与分组，不约束 Flag 本身（Flag.stage 允许任意字符串）。
    """
    pid = form.projectId or projectId or DEFAULT_PROJECT_ID
    project = db.get(Project, pid)
    if project is None:
        raise HTTPException(404, f"项目不存在: {pid}")
    try:
        stages = set_stages(db, pid, form.stages)
    except KeyError:
        raise HTTPException(404, f"项目不存在: {pid}")
    add_event(db, pid, "flag", "阶段设置更新",
              detail="已设置: " + (", ".join(stages) if stages else "默认阶段"))
    db.commit()
    manager.push("stages.updated", stages=stages)
    return {"ok": True, "projectId": pid, "stages": stages}
