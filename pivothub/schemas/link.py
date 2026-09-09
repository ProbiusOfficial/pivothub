"""代理链路出参：前端契约字段（与 store.js / proxy.js 消费的字段名一致）。"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class LinkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tool: str
    linkType: str = "socks"
    direction: str
    fromHostId: str
    toHostId: str
    localSocks: str = ""
    targetSegment: str = ""
    status: str
    latency: int
    traffic: str = "0 B"
    conf: str = ""
    createdBy: str = "半自动档"
    note: str = ""
    # 链路参数（三种链路类型共用）
    listenPort: int = 0
    remoteBind: str = ""
    localPort: int = 0
    targetHost: str = ""
    targetPort: int = 0
    relayAddr: str = ""
    relayPort: int = 0
    hops: list[dict[str, Any]] = []
    # 进程：pid = 本机隧道服务端；pids = 逐层进程（多级中继销毁时逐层清理）
    pid: int | None = None
    pids: list[dict[str, Any]] = []

    @classmethod
    def of(cls, l) -> "LinkOut":
        return cls(
            id=l.id, tool=l.tool, linkType=l.link_type or "socks",
            direction=l.direction, fromHostId=l.from_host_id, toHostId=l.to_host_id,
            localSocks=l.local_socks, targetSegment=l.target_segment,
            status=l.status, latency=l.latency, traffic=l.traffic,
            conf=l.conf, createdBy=l.created_by, note=l.note or "",
            listenPort=l.listen_port or 0, remoteBind=l.remote_bind or "",
            localPort=l.local_port or 0, targetHost=l.target_host or "",
            targetPort=l.target_port or 0, relayAddr=l.relay_addr or "",
            relayPort=l.relay_port or 0, hops=l.hops or [],
            pid=l.pid, pids=l.pids or [],
        )
