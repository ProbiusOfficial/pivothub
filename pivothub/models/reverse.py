from __future__ import annotations

from sqlalchemy import Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class ReverseListener(Base):
    """反弹监听持久化。

    反连通道（socket）不跨进程存活，但「用户开了哪些监听」需要记住：
    面板重启后按此表自动恢复监听端口，靶机再次回连即可登记会话。
    """

    __tablename__ = "reverse_listeners"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    bind: Mapped[str] = mapped_column(String(64), default="127.0.0.1")
    port: Mapped[int] = mapped_column(Integer)
    label: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[str] = mapped_column(String(32), default="")
