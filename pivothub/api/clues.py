"""配置文件线索检索 API：一键在目标侧翻配置文件找口令 / Flag 等线索。

参考 recon.py 风格：会话经 shells._open_session 取回（复用「按 shellId 取会话实例」
逻辑，不重复实现）；检索失败如实返回 ok:false，路由层无 subprocess。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_db
from ..service import clues as clue_svc
from ..session import SessionError
from .shells import _get_shell, _open_session  # 复用既有「取会话」函数

router = APIRouter()  # 无 prefix，路径写全


class ClueScanIn(BaseModel):
    """检索入参：shellId 必填；roots / keywords 留空用内置默认字典。"""

    shellId: str
    roots: list[str] | None = None
    keywords: list[str] | None = None
    maxFiles: int = 200
    maxHits: int = 300


@router.post("/clues/scan")
def clues_scan(form: ClueScanIn, db: Session = Depends(get_db)):
    """在目标侧真实翻配置文件找线索（口令 / 连接串 / 私钥 / Flag 等）。

    命中内容明文返回（docs/ASSUMPTIONS.md A-23 有意设计，仅限本机授权 CTF / 靶场）。
    """
    s = _get_shell(db, form.shellId)
    try:
        sess = _open_session(db, s)
    except SessionError as e:
        return {"ok": False, "error": f"会话不可用：{e}"}
    try:
        return clue_svc.search_clues(
            sess, roots=form.roots, keywords=form.keywords,
            max_files=form.maxFiles, max_hits=form.maxHits, timeout=30.0)
    except SessionError as e:
        return {"ok": False, "error": f"检索失败：{e}"}
