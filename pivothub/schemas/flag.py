from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict

from .common import hhmm_utc


class FlagOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    hostId: str
    stage: str
    value: str
    submitted: bool = False
    #: 备注（纠错 / 改绑记录），向后兼容：旧前端忽略此新增字段即可
    note: str = ""
    time: str = ""

    @classmethod
    def of(cls, f) -> "FlagOut":
        return cls(
            id=f.id, hostId=f.host_id, stage=f.stage, value=f.value,
            submitted=f.submitted, note=getattr(f, "note", "") or "",
            time=hhmm_utc(f.created_at),
        )


class FlagIn(BaseModel):
    projectId: str = ""
    hostId: str
    stage: str = "L1 入口"
    value: str
    submitted: bool = False
    #: 备注（可空）
    note: str = ""


class FlagPatch(BaseModel):
    """Flag 部分更新：value / stage / hostId / projectId / note 任意组合。

    stage 允许任意字符串（不再限定固定四值枚举）；projectId 与 hostId 改绑时
    由 API 层做一致性校验，校验失败如实报错，绝不静默写坏数据。
    """

    value: Optional[str] = None
    stage: Optional[str] = None
    hostId: Optional[str] = None
    projectId: Optional[str] = None
    note: Optional[str] = None
    #: 提交状态（标记已交 / 撤销），前端「Flag 墙」直接切换
    submitted: Optional[bool] = None
