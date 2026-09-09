from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class Credential(Base):
    __tablename__ = "credentials"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(40), index=True)
    host_id: Mapped[str] = mapped_column(String(40), index=True)
    username: Mapped[str] = mapped_column(String(200))
    secret: Mapped[str] = mapped_column(String(500), default="")
    kind: Mapped[str] = mapped_column(String(32), default="密码")
    services: Mapped[list] = mapped_column(JSON, default=list)
    reuse: Mapped[bool] = mapped_column(Boolean, default=True)
    source: Mapped[str] = mapped_column(String(200), default="手动登记")
    created_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
