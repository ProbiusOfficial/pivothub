"""提权智能匹配 API（PRD M5-2）：规则目录 + 一键扫描。

扫描经会话层在目标上真实执行采集命令（只读信息收集），再匹配规则库；
命中项只是「建议 + 命令」，需要用户显式点击才发送执行。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session as DBSession

from ..db import get_db
from ..models import Host
from ..session import SessionError
from ..service import privesc as privesc_svc
from .shells import _get_shell, _open_session

router = APIRouter()


@router.get("/privesc/rules")
def privesc_rules(platform: str = ""):
    """规则库目录（platform=linux|windows 可选过滤）。"""
    return {"rules": privesc_svc.load_rules(platform)}


@router.post("/shells/{shell_id}/privesc/scan")
def privesc_scan(shell_id: str, db: DBSession = Depends(get_db)):
    """采集目标事实并匹配提权路径（真实执行，只读；不自动利用）。"""
    s = _get_shell(db, shell_id)
    platform = (s.platform or "").lower()
    if platform not in ("linux", "windows"):
        host = db.get(Host, s.host_id)
        platform = "windows" if (host and host.os and "windows" in host.os.lower()) else "linux"

    try:
        sess = _open_session(db, s)
    except SessionError as e:
        return JSONResponse({"ok": False, "error": str(e)})

    cmd = privesc_svc.collect_command(platform)
    res = sess.exec(cmd, timeout=90)
    if not res.ok and not res.output:
        return JSONResponse({"ok": False, "error": res.error or "采集失败（会话不可达）"})

    facts = privesc_svc.parse_facts(res.output, platform)
    findings = privesc_svc.match_rules(platform, res.output, facts)
    return {
        "ok": True, "platform": platform, "facts": facts, "findings": findings,
        "cmd": cmd, "ms": res.ms, "raw": (res.output or "")[-8000:],
        "error": res.error if not res.ok else "",
    }
