from __future__ import annotations

from sqlalchemy import Integer, String, Text
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class Project(Base):
    """一次比赛 / 一个靶场。"""

    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    start_at: Mapped[str] = mapped_column(String(8), default="10:00")
    duration_sec: Mapped[int] = mapped_column(Integer, default=4 * 3600)
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[str] = mapped_column(String(32), default="")
    #: 项目级设置：{"attack": {ip, segment, iface, note}}（攻击机网络，契约 /api/attack）
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
