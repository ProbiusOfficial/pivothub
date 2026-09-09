"""代理工具目录出参 / 启用集入参（MS4 仅 chisel 已接入，其余为下线状态）。"""

from __future__ import annotations

from pydantic import BaseModel


class ToolOut(BaseModel):
    name: str
    note: str = ""
    supports: list[str] = []
    type: str = ""
    #: online = 适配器已接入，可启用；offline = 未接入，面板显示「下线」且不可启用
    status: str = "offline"
    enabled: bool = False


class ToolsIn(BaseModel):
    #: 要启用的工具名集合（只允许 status=online 的工具）
    enabled: list[str] = []
