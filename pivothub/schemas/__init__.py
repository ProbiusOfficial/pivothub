"""Pydantic v2 输出/入参模型。

硬约束：对外 JSON 字段名即前端契约（store.js / views 直接消费，零字段改名适配）。
DB 规范形式 → 契约字符串的转换全部收敛在本包（lastBeat 相对时间 / time 的 HH:MM 等）。
"""

from __future__ import annotations

from .project import ProjectOut, ProjectBrief
from .attack import AttackIn, AttackOut
from .host import HostOut, HostIn, IfaceIn, ScanImportIn, PositionIn
from .shell import ShellOut, ShellIn
from .link import LinkOut
from .credential import CredOut, CredIn
from .flag import FlagOut, FlagIn
from .timeline import TimelineOut, NoteIn
from .tool import ToolOut, ToolsIn
from .state import StateOut, NewId

__all__ = [
    "ProjectOut", "ProjectBrief",
    "AttackIn", "AttackOut",
    "HostOut", "HostIn", "IfaceIn", "ScanImportIn", "PositionIn",
    "ShellOut", "ShellIn",
    "LinkOut",
    "CredOut", "CredIn",
    "FlagOut", "FlagIn",
    "TimelineOut", "NoteIn",
    "ToolOut", "ToolsIn",
    "StateOut", "NewId",
]
