from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class ProxyLink(Base):
    """代理链路：入口 Host → 出口 Host 的有向边（跳板链一等公民）。

    字段（前端契约）：
      linkType   socks | portfwd | relay
      listenPort 攻击机隧道监听端口（chisel server -p）
      remoteBind 靶机侧回连时绑定的地址（R:<remoteBind>:<localPort>:...）
      localPort  攻击机上暴露的端口（socks 入口 / 端口转发入口）
      targetHost/targetPort  单端口转发目标
      relayAddr/relayPort    多级中继入口（上一层跳板在本层网段里的 IP）
      hops[]     分步命令回放（[{role, hostId, cmd}]）

    pid 记录本机适配器子进程号（服务端），pids 记录链路各层进程（多级中继逐层清理）。
    """

    __tablename__ = "proxy_links"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(40), index=True)
    tool: Mapped[str] = mapped_column(String(40))
    link_type: Mapped[str] = mapped_column(String(16), default="socks")
    direction: Mapped[str] = mapped_column(String(8), default="反向")
    from_host_id: Mapped[str] = mapped_column(String(40), index=True)
    to_host_id: Mapped[str] = mapped_column(String(40), index=True)
    local_socks: Mapped[str] = mapped_column(String(64), default="")
    target_segment: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[str] = mapped_column(String(16), default="stopped")  # alive|error|stopped
    latency: Mapped[int] = mapped_column(Integer, default=0)
    traffic: Mapped[str] = mapped_column(String(32), default="0 B")
    conf: Mapped[str] = mapped_column(String(200), default="")
    created_by: Mapped[str] = mapped_column(String(16), default="半自动档")
    note: Mapped[str] = mapped_column(Text, default="")
    listen_port: Mapped[int] = mapped_column(Integer, default=0)
    remote_bind: Mapped[str] = mapped_column(String(64), default="")
    local_port: Mapped[int] = mapped_column(Integer, default=0)
    target_host: Mapped[str] = mapped_column(String(64), default="")
    target_port: Mapped[int] = mapped_column(Integer, default=0)
    relay_addr: Mapped[str] = mapped_column(String(64), default="")
    relay_port: Mapped[int] = mapped_column(Integer, default=0)
    hops: Mapped[list] = mapped_column(JSON, default=list)
    pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    pids: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
