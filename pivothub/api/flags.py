"""Flag 收集墙：记录。"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..config import DEFAULT_PROJECT_ID
from ..db import get_db, now
from ..schemas.common import rid
from ..models import Flag
from ..schemas import FlagIn, FlagOut
from ..service import add_event
from .deps import get_project

router = APIRouter()


@router.post("/flags", response_model=FlagOut)
def add_flag(form: FlagIn, db: Session = Depends(get_db)):
    project = get_project(db, form.projectId or DEFAULT_PROJECT_ID)
    f = Flag(
        id=rid("f"), project_id=project.id, host_id=form.hostId, stage=form.stage,
        value=form.value, submitted=form.submitted, created_at=now(),
    )
    db.add(f)
    add_event(db, project.id, "flag", f"拿到 Flag：{f.stage}", host_id=f.host_id,
              detail=f.value + ("（已提交）" if f.submitted else ""))
    db.commit()
    return FlagOut.of(f)
