"""导出：GET /api/export?format=md|html|json&projectId=&opts=。"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..config import DEFAULT_PROJECT_ID
from ..db import get_db
from ..service import export as export_svc
from .deps import get_project

router = APIRouter()


@router.get("/export")
def do_export(
    format: str = Query("md", pattern="^(md|html|json)$"),
    projectId: str = "",
    opts: str = Query("", description="JSON 字符串，如 {\"topo\":true}"),
    db: Session = Depends(get_db),
):
    pid = projectId or DEFAULT_PROJECT_ID
    project = get_project(db, pid)
    try:
        options = json.loads(opts) if opts else {}
    except json.JSONDecodeError:
        raise HTTPException(400, "opts 必须是合法 JSON")
    options = {k: bool(v) for k, v in options.items()}

    if format == "json":
        content = export_svc.build_json(db, pid)
        return Response(content, media_type="application/json; charset=utf-8",
                        headers={"Content-Disposition": "attachment; filename=pivothub-writeup.json"})
    md = export_svc.build_markdown(db, pid, options)
    if format == "html":
        content = export_svc.build_html(md, project.name)
        return Response(content, media_type="text/html; charset=utf-8",
                        headers={"Content-Disposition": "attachment; filename=pivothub-writeup.html"})
    return Response(md, media_type="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=pivothub-writeup.md"})
