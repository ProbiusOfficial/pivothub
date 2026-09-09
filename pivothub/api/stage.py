"""文件暂存管理：查看 / 清理攻击机上的临时 HTTP 暂存（上传「HTTP 拉取」通道）。

暂存条目在每次拉取结束后会自动撤下；本路由用于人工排查与手动清理残留。
"""

from __future__ import annotations

from fastapi import APIRouter

from ..service import filestage as stage_svc

router = APIRouter()


@router.get("/stage")
def list_stage():
    """暂存服务状态与当前条目（只读，不含文件内容）。"""
    return stage_svc.STAGE.snapshot()


@router.delete("/stage/{token}")
def drop_stage(token: str):
    """手动撤下某个暂存条目（立即删除磁盘文件）。"""
    return {"ok": stage_svc.STAGE.drop(token)}
