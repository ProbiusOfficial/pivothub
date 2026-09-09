from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class IfaceIn(BaseModel):
    """网卡：{iface, ip, segment}（多级中继推导依赖它）。"""

    iface: str = ""
    ip: str = ""
    segment: str = ""


class HostOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    ip: str
    hostname: str
    os: str
    layer: str
    segment: str
    privilege: str
    owned: bool
    ports: list[int] = []
    services: list[str] = []
    note: str = ""
    discovery: str = ""
    isLocal: bool = False
    #: 网卡列表（双网卡跳板 = 纵深入口）
    ifaces: list[dict] = []
    # 拓扑拖拽持久化（前端拓扑仅在存在时恢复，缺省不下发不影响契约）
    posX: float | None = None
    posY: float | None = None

    @classmethod
    def of(cls, h) -> "HostOut":
        return cls(
            id=h.id, ip=h.ip, hostname=h.hostname, os=h.os, layer=h.layer,
            segment=h.segment, privilege=h.privilege, owned=h.owned,
            ports=h.ports or [], services=h.services or [], note=h.note,
            discovery=h.discovery, isLocal=h.is_local, ifaces=h.ifaces or [],
            posX=h.pos_x, posY=h.pos_y,
        )


class HostIn(BaseModel):
    projectId: str = ""
    ip: str
    hostname: str = ""
    os: str = "未知（待指纹识别）"
    layer: str = "L2"
    segment: str = ""
    privilege: str = ""
    services: list[str] | str = []
    note: str = ""
    owned: bool = False
    ifaces: list[dict] = []


class ScanImportIn(BaseModel):
    projectId: str = ""
    text: str


class PositionIn(BaseModel):
    x: float
    y: float
