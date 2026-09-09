from __future__ import annotations

from sqlalchemy import Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class DbConnection(Base):
    """目标数据库连接。

    面板不直连数据库协议：命令经会话层在目标（或本机）执行客户端命令，
    因此无需为每种数据库引入 Python 驱动。密码按本工具既有约定明文存储
    （见 docs/ASSUMPTIONS.md A-23，仅本机授权场景）。
    """

    __tablename__ = "db_connections"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(40), index=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    #: mysql | postgres | sqlite | redis | mssql
    kind: Mapped[str] = mapped_column(String(16), default="mysql")
    host: Mapped[str] = mapped_column(String(200), default="127.0.0.1")
    port: Mapped[int] = mapped_column(Integer, default=0)
    username: Mapped[str] = mapped_column(String(120), default="")
    password: Mapped[str] = mapped_column(String(200), default="")
    db_name: Mapped[str] = mapped_column(String(120), default="")
    #: 在哪个会话上执行客户端命令（空 = 面板本机执行）
    shell_id: Mapped[str] = mapped_column(String(40), default="")
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[str] = mapped_column(String(32), default="")
