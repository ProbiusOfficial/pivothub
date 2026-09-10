"""内网应用指纹探测 / 目录上下文发现：API 层。

全部经会话层真实执行，路由层零 subprocess；复用 shells 的「按 shellId 取会话」逻辑。
错误（会话不可用 / 执行失败 / 解析异常）如实返回 {ok:false, error}，不吞错。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Shell
from ..service import fingerprint as fp_svc
from ..session import SessionError
from .shells import _get_shell, _open_session

#: 不加 prefix：最终路径随 api_router 的 /api 前缀成为 /api/fingerprint/scan 等。
router = APIRouter()


class ScanIn(BaseModel):
    """应用指纹探测入参。"""

    shellId: str
    targets: list[str]
    timeout: float = 12.0


class DirIn(BaseModel):
    """目录/上下文发现入参。"""

    shellId: str
    baseUrls: list[str]
    wordlist: list[str] | None = None
    timeout: float = 12.0


def _session(db: Session, shell_id: str):
    """按 shellId 取会话实例（复用 shells 的既有实现，不自造）。"""
    s = _get_shell(db, shell_id)
    return _open_session(db, s)


def _err(stage: str, error: str, summary: dict) -> dict:
    """如实返回错误：HTTP 200 + ok:false + error（与现有端点一致，不静默兜底）。"""
    return {"ok": False, "stage": stage, "error": error, "items": [], "summary": summary}


@router.post("/fingerprint/scan")
def fingerprint_scan(form: ScanIn, db: Session = Depends(get_db)):
    """对每个目标的 host:port 做应用指纹探测（Shiro/Jenkins/Nacos/Registry/Actuator/Tomcat 等）。"""
    try:
        sess = _session(db, form.shellId)
    except SessionError as e:
        return _err("session", f"会话不可用：{e}", {})
    except Exception as e:
        return _err("session", str(e), {})
    try:
        result = fp_svc.scan_apps(sess, form.targets, timeout=form.timeout)
    except SessionError as e:
        return _err("exec", str(e), {})
    except Exception as e:
        return _err("parse", str(e), {})
    result["ok"] = True
    return result


@router.post("/fingerprint/dirs")
def fingerprint_dirs(form: DirIn, db: Session = Depends(get_db)):
    """对每个 base_url 批量探测路径，发现非 ROOT context、管理台与源码备份。"""
    try:
        sess = _session(db, form.shellId)
    except SessionError as e:
        return _err("session", f"会话不可用：{e}", {"total": 0, "hits": 0})
    except Exception as e:
        return _err("session", str(e), {"total": 0, "hits": 0})
    try:
        result = fp_svc.discover_dirs(
            sess, form.baseUrls, wordlist=form.wordlist, timeout=form.timeout)
    except SessionError as e:
        return _err("exec", str(e), {"total": 0, "hits": 0})
    except Exception as e:
        return _err("parse", str(e), {"total": 0, "hits": 0})
    result["ok"] = True
    return result
