"""代理工具：GET / PUT /api/tools（MS4 仅 chisel 已接入，其余为下线状态）。

目录来自 data/meta.json → tools；启用集是项目级设置（Project.settings["tools"]），
只允许启用 status=online 的工具——未接入适配器的工具必须诚实标记为「下线」，
不能让它出现在编排台的工具下拉里被误选。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..config import DEFAULT_PROJECT_ID
from ..db import get_db, get_tools, set_tools
from ..schemas import ToolOut, ToolsIn
from ..service import add_event
from ..ws import manager
from .deps import get_project

router = APIRouter()


@router.get("/tools", response_model=list[ToolOut])
def read_tools(projectId: str = "", db: Session = Depends(get_db)):
    project = get_project(db, projectId or DEFAULT_PROJECT_ID)
    return [ToolOut(**t) for t in get_tools(db, project.id)]


@router.put("/tools", response_model=list[ToolOut])
def update_tools(form: ToolsIn, projectId: str = "", db: Session = Depends(get_db)):
    """保存项目级启用集；下线 / 未知工具返回 422 并说明原因。"""
    project = get_project(db, projectId or DEFAULT_PROJECT_ID)
    try:
        tools = set_tools(db, project.id, form.enabled)
    except KeyError:
        raise HTTPException(404, f"项目不存在: {project.id}")
    except ValueError as e:
        raise HTTPException(422, str(e))

    enabled_names = [t["name"] for t in tools if t["enabled"]]
    add_event(db, project.id, "proxy", "代理工具设置更新",
              detail="已启用: " + (", ".join(enabled_names) if enabled_names else "无"))
    db.commit()
    out = [ToolOut(**t) for t in tools]
    manager.push("tools.updated", tools=[t.model_dump() for t in out])
    return out
