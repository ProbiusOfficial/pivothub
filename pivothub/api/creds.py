"""凭据库：登记。复用推荐算法在 MS5 服务化（当前前端本地打分逻辑保留为回退）。"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..config import DEFAULT_PROJECT_ID
from ..db import get_db, now
from ..schemas.common import rid
from ..models import Credential
from ..schemas import CredIn, CredOut
from ..service import add_event
from .deps import get_project

router = APIRouter()


def _normalize_services(v) -> list[str]:
    if isinstance(v, str):
        return [x.strip() for x in v.split(",") if x.strip()]
    return list(v or [])


@router.post("/creds", response_model=CredOut)
def add_cred(form: CredIn, db: Session = Depends(get_db)):
    project = get_project(db, form.projectId or DEFAULT_PROJECT_ID)
    c = Credential(
        id=rid("c"), project_id=project.id, host_id=form.hostId, username=form.username,
        secret=form.secret, kind=form.kind, services=_normalize_services(form.services),
        reuse=True, source=form.source or "手动登记", created_at=now(),
    )
    db.add(c)
    add_event(db, project.id, "cred", f"登记凭据 {c.username}", host_id=c.host_id,
              detail=f"{c.kind} · 来源 {c.source}")
    db.commit()
    return CredOut.of(c)
