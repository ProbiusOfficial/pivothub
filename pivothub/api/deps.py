"""路由公共依赖：项目解析 + 全量状态构建。"""

from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy.orm import Session

from ..db import get_attack, get_tools, load_meta, load_plugin_dir
from ..models import Credential, Flag, Host, Project, ProxyLink, Shell, TimelineEvent
from ..schemas import (
    AttackOut, CredOut, FlagOut, HostOut, LinkOut, ProjectBrief, ProjectOut, ShellOut,
    StateOut, TimelineOut, ToolOut,
)
from ..service import segments_of


def get_project(db: Session, project_id: str) -> Project:
    p = db.get(Project, project_id)
    if not p:
        raise HTTPException(status_code=404, detail=f"项目不存在: {project_id}")
    return p


def list_projects(db: Session) -> list[ProjectBrief]:
    rows = db.query(Project).order_by(Project.created_at, Project.id).all()
    seen: set[str] = set()
    out = []
    for p in rows:
        if p.id in seen:
            continue
        seen.add(p.id)
        out.append(ProjectBrief(id=p.id, name=p.name))
    return out


def build_state(db: Session, project_id: str) -> StateOut:
    """一次性聚合前端 store.init() 所需的全部数据。"""
    project = get_project(db, project_id)
    hosts = db.query(Host).filter(Host.project_id == project_id).all()
    shells = db.query(Shell).filter(Shell.project_id == project_id).all()
    links = db.query(ProxyLink).filter(ProxyLink.project_id == project_id).all()
    creds = db.query(Credential).filter(Credential.project_id == project_id).all()
    flags = db.query(Flag).filter(Flag.project_id == project_id).all()
    timeline = (
        db.query(TimelineEvent)
        .filter(TimelineEvent.project_id == project_id)
        .order_by(TimelineEvent.ts.desc(), TimelineEvent.id.desc())
        .all()
    )
    meta = load_meta()
    attack = get_attack(db, project_id)

    return StateOut(
        project=ProjectOut(
            id=project.id, name=project.name, startAt=project.start_at,
            durationSec=project.duration_sec, note=project.note,
        ),
        projects=list_projects(db),
        segments=segments_of(hosts),
        attack=AttackOut(**attack),
        hosts=[HostOut.of(h) for h in hosts],
        shells=[ShellOut.of(s) for s in shells],
        links=[LinkOut.of(l) for l in links],
        creds=[CredOut.of(c) for c in creds],
        flags=[FlagOut.of(f) for f in flags],
        timeline=[TimelineOut.of(t) for t in timeline],
        probes=meta.get("probes", []),
        tools=[ToolOut(**t) for t in get_tools(db, project_id)],
        commands=load_plugin_dir("commands"),
        injectTips=load_plugin_dir("payloads"),
        ttyFixes=load_plugin_dir("tty_fixes"),
        shellTypes=meta.get("shellTypes", []),
        encoders=meta.get("encoders", []),
        credKinds=meta.get("credKinds", []),
        layers=meta.get("layers", []),
        stageNames=meta.get("stageNames", []),
        scanSample=meta.get("scanSample", ""),
    )
