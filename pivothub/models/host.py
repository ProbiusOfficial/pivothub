from __future__ import annotations

from sqlalchemy import Boolean, Float, String, Text
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class Host(Base):
    """资产主机。pos_x/pos_y 为拓扑拖拽位置（可空 = 未手动布置）。"""

    __tablename__ = "hosts"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(40), index=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    hostname: Mapped[str] = mapped_column(String(200), default="")
    os: Mapped[str] = mapped_column(String(200), default="")
    layer: Mapped[str] = mapped_column(String(8), default="L1")
    segment: Mapped[str] = mapped_column(String(64), default="")
    privilege: Mapped[str] = mapped_column(String(64), default="")
    owned: Mapped[bool] = mapped_column(Boolean, default=False)
    ports: Mapped[list] = mapped_column(JSON, default=list)
    services: Mapped[list] = mapped_column(JSON, default=list)
    note: Mapped[str] = mapped_column(Text, default="")
    discovery: Mapped[str] = mapped_column(String(64), default="手动登记")
    is_local: Mapped[bool] = mapped_column(Boolean, default=False)
    #: 网卡列表：[{iface, ip, segment}]（双网卡跳板是多级中继推导的依据）
    ifaces: Mapped[list] = mapped_column(JSON, default=list)
    pos_x: Mapped[float | None] = mapped_column(Float, nullable=True)
    pos_y: Mapped[float | None] = mapped_column(Float, nullable=True)
