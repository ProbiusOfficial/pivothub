"""GET /api/projects/{id}/state 全量聚合出参：前端 store.init() 一次拉齐。"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from .attack import AttackIn, AttackOut
from .credential import CredOut
from .flag import FlagOut
from .host import HostOut
from .link import LinkOut
from .project import ProjectBrief, ProjectOut
from .shell import ShellOut
from .timeline import TimelineOut
from .tool import ToolOut


class NewId(BaseModel):
    id: str


class StateOut(BaseModel):
    project: ProjectOut
    projects: list[ProjectBrief]
    segments: list[dict[str, Any]]
    #: 攻击机网络 {ip, segment, iface, note}
    attack: AttackOut = AttackOut()
    hosts: list[HostOut]
    shells: list[ShellOut]
    links: list[LinkOut]
    creds: list[CredOut]
    flags: list[FlagOut]
    timeline: list[TimelineOut]
    # 以下为静态目录 / 基线数据（由 data/ 插件文件提供）
    probes: list[dict[str, Any]] = []
    #: 代理工具目录（含 status=online/offline 与项目级 enabled 标记）
    tools: list[ToolOut] = []
    commands: list[dict[str, Any]] = []
    injectTips: list[dict[str, Any]] = []
    ttyFixes: list[dict[str, Any]] = []
    shellTypes: list[str] = []
    encoders: list[str] = []
    credKinds: list[str] = []
    layers: list[str] = []
    stageNames: list[str] = []
    scanSample: str = ""
