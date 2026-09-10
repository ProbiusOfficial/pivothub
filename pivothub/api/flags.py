"""Flag 收集墙：记录 / 修改 / 删除。

路由风格、依赖注入、响应模型与错误返回方式对齐同仓库其它 API
（creds.py / hosts.py 等）：项目解析走 `get_project`，404 用 HTTPException，
错误如实返回，不静默兜底。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..config import DEFAULT_PROJECT_ID
from ..db import get_db, now
from ..schemas.common import rid
from ..models import Flag, Host
from ..schemas import FlagIn, FlagOut, FlagPatch
from ..service import add_event
from .deps import get_project

router = APIRouter()


@router.post("/flags", response_model=FlagOut)
def add_flag(form: FlagIn, db: Session = Depends(get_db)):
    project = get_project(db, form.projectId or DEFAULT_PROJECT_ID)
    f = Flag(
        id=rid("f"), project_id=project.id, host_id=form.hostId, stage=form.stage,
        value=form.value, submitted=form.submitted, note=form.note, created_at=now(),
    )
    db.add(f)
    add_event(db, project.id, "flag", f"拿到 Flag：{f.stage}", host_id=f.host_id,
              detail=f.value + ("（已提交）" if f.submitted else ""))
    db.commit()
    return FlagOut.of(f)


@router.patch("/flags/{flag_id}", response_model=FlagOut)
def update_flag(flag_id: str, form: FlagPatch, db: Session = Depends(get_db)):
    """部分更新 Flag：value / stage / hostId / projectId / note 任意组合。

    - 改绑项目：目标项目必须存在（不存在 → 404）。
    - 改绑主机：目标主机必须属于目标项目（否则 → 400，绝不跨项目脏写）。
    - stage 允许任意字符串，不再限定固定四值枚举。
    """
    f = db.get(Flag, flag_id)
    if not f:
        raise HTTPException(404, "Flag 不存在")

    # 1) 解析目标项目（改绑项目时先校验存在性）
    target_project = f.project_id
    project_changed = form.projectId is not None and form.projectId != f.project_id
    if project_changed:
        project = get_project(db, form.projectId)  # 不存在 → 404
        target_project = project.id

    # 2) 改绑主机：必须属于目标项目（一致性强校验）
    if form.hostId is not None and form.hostId != f.host_id:
        host = db.get(Host, form.hostId)
        if not host:
            raise HTTPException(400, f"目标主机不存在: {form.hostId}")
        if host.project_id != target_project:
            raise HTTPException(400, f"目标主机不属于项目 {target_project}，无法跨项目改绑")
        f.host_id = form.hostId

    # 3) 仅改项目、未改主机时，现有主机本身必须落在目标项目内，否则构成跨项目脏数据
    if project_changed:
        owner = db.get(Host, f.host_id)
        if owner is None or owner.project_id != target_project:
            raise HTTPException(400, "改绑项目时主机必须属于目标项目（请一并指定该项目的 hostId）")
        f.project_id = target_project

    # 4) 其余字段直接更新
    if form.stage is not None:
        f.stage = form.stage
    if form.value is not None:
        f.value = form.value
    if form.note is not None:
        f.note = form.note
    if form.submitted is not None:
        f.submitted = bool(form.submitted)

    db.commit()
    return FlagOut.of(f)


@router.delete("/flags/{flag_id}")
def remove_flag(flag_id: str, db: Session = Depends(get_db)):
    """删除 Flag（不存在 → 404）。"""
    f = db.get(Flag, flag_id)
    if not f:
        raise HTTPException(404, "Flag 不存在")
    stage, project_id = f.stage, f.project_id
    db.delete(f)
    add_event(db, project_id, "flag", f"删除 Flag：{stage}", detail="已从收集墙移除")
    db.commit()
    return {"deleted": flag_id}
