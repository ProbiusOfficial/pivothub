from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class TimelineEvent(Base):
    """操作时间线：自动事件 + 手动笔记。kind ∈ shell|proxy|host|cred|flag|note。"""

    __tablename__ = "timeline_events"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(40), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=datetime.now, index=True)
    kind: Mapped[str] = mapped_column(String(16), default="note")
    title: Mapped[str] = mapped_column(String(300))
    host_id: Mapped[str | None] = mapped_column(String(40), ForeignKey("hosts.id"), nullable=True)
    detail: Mapped[str] = mapped_column(Text, default="")
    cmd: Mapped[str] = mapped_column(Text, default="")
    markdown: Mapped[str] = mapped_column(Text, default="")
