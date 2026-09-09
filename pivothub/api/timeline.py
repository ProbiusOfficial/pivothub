"""时间线：手动笔记（Markdown）+ 客户端事件入库。"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..config import DEFAULT_PROJECT_ID
from ..db import get_db
from ..schemas import NoteIn
from ..service import add_event
from .deps import get_project

router = APIRouter()


class EventIn(BaseModel):
    projectId: str = ""
    kind: str = "note"
    title: str
    hostId: str | None = None
    detail: str = ""
    cmd: str = ""
    markdown: str = ""


@router.post("/timeline/notes")
def add_note(form: NoteIn, db: Session = Depends(get_db)):
    project = get_project(db, form.projectId or DEFAULT_PROJECT_ID)
    ev = add_event(
        db, project.id, "note", form.title, host_id=form.hostId or None,
        cmd=form.cmd or "", markdown=form.markdown or "",
    )
    db.commit()
    return {"id": ev.id}


@router.post("/timeline/events")
def add_client_event(form: EventIn, db: Session = Depends(get_db)):
    """前端动作产生的自动事件入库（拓扑点选、探测发起等）。"""
    project = get_project(db, form.projectId or DEFAULT_PROJECT_ID)
    ev = add_event(
        db, project.id, form.kind, form.title, host_id=form.hostId or None,
        detail=form.detail, cmd=form.cmd, markdown=form.markdown,
    )
    db.commit()
    return {"id": ev.id}
