"""项目：列表 / 全量状态 / 新建。"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..config import DEFAULT_PROJECT_ID
from ..db import get_attack, get_db, now
from ..localinfo import iface_for, machine
from ..models import Host, Project
from ..schemas import ProjectBrief, StateOut
from ..schemas.common import rid
from ..service import add_event
from .deps import build_state, list_projects

router = APIRouter()


@router.get("/projects", response_model=list[ProjectBrief])
def projects(db: Session = Depends(get_db)):
    return list_projects(db)


class ProjectIn(BaseModel):
    name: str
    durationSec: int = 4 * 3600
    note: str = ""


@router.post("/projects", response_model=ProjectBrief)
def create_project(form: ProjectIn, db: Session = Depends(get_db)):
    """新建项目 = 干净工作区：仅带攻击端本机节点（拓扑根），其余全空。"""
    name = form.name.strip()
    if not name:
        from fastapi import HTTPException

        raise HTTPException(400, "项目名称不能为空")
    pid = rid("proj")
    attack = get_attack(db, DEFAULT_PROJECT_ID)
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


@router.get("/projects/{project_id}/state", response_model=StateOut)
def project_state(project_id: str, db: Session = Depends(get_db)):
    return build_state(db, project_id)
