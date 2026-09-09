from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class Shell(Base):
    """WebShell 会话。pwd 列即契约中的 pass 字段（pass 为 Python 关键字）。"""

    __tablename__ = "shells"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(40), index=True)
    host_id: Mapped[str] = mapped_column(String(40), ForeignKey("hosts.id"), index=True)
    type: Mapped[str] = mapped_column(String(64), default="PHP 一句话马")
    #: 驱动类型：'' = 按 type/url 推导的 HTTP 马；'reverse' = 反弹 Shell 通道
    kind: Mapped[str] = mapped_column(String(16), default="")
    url: Mapped[str] = mapped_column(String(500))
    pwd: Mapped[str] = mapped_column(String(200), default="")
    encoder: Mapped[str] = mapped_column(String(32), default="none")
    alive: Mapped[bool] = mapped_column(Boolean, default=True)
    latency: Mapped[int] = mapped_column(Integer, default=0)
    last_beat_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    hostname: Mapped[str] = mapped_column(String(200), default="")
    privilege: Mapped[str] = mapped_column(String(64), default="")
    stable: Mapped[bool] = mapped_column(Boolean, default=False)
