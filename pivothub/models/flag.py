from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class Flag(Base):
    __tablename__ = "flags"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(40), index=True)
    host_id: Mapped[str] = mapped_column(String(40), index=True)
    #: 阶段允许任意字符串（不再限定 L1 入口 / L2 内网 / L3 域 / 域控 固定四值）
    stage: Mapped[str] = mapped_column(String(32), default="L1 入口")
    value: Mapped[str] = mapped_column(String(200))
    submitted: Mapped[bool] = mapped_column(Boolean, default=False)
    #: 备注（改绑 / 纠错记录），可空
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
