from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .common import beat_text


class ShellOut(BaseModel):
    """Shell 会话出参；pass 用别名输出。"""

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: str
    hostId: str
    type: str
    url: str
    pass_: str = Field(default="", alias="pass")
    encoder: str = "none"
    alive: bool
    latency: int
    lastBeat: str = ""
    hostname: str = ""
    privilege: str = ""
    stable: bool = False
    #: 驱动类型（'' = HTTP 马；'reverse' = 反弹 Shell 通道）——前端不消费，仅服务端区分
    kind: str = ""
    #: 目标平台（'' = 未知，前端按主机 OS 推导；'linux' / 'windows'）
    platform: str = ""

    @classmethod
    def of(cls, s) -> "ShellOut":
        return cls(
            id=s.id, hostId=s.host_id, type=s.type, url=s.url, pass_=s.pwd,
            encoder=s.encoder, alive=s.alive, latency=s.latency,
            lastBeat=beat_text(s.last_beat_at, s.alive), hostname=s.hostname,
            privilege=s.privilege, stable=s.stable, kind=getattr(s, "kind", "") or "",
            platform=getattr(s, "platform", "") or "",
        )


class ShellIn(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    projectId: str = ""
    hostId: str
    type: str = "PHP 一句话马"
    url: str
    pass_: str = Field(default="", alias="pass")
    encoder: str = "base64"
    autoCollect: bool = True
    #: 驱动类型（'' = HTTP 马；'reverse' = 反弹 Shell 通道）
    kind: str = ""
    note: str = ""
