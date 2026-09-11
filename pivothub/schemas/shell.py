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
    #: 提权上下文：非空表示后续命令以该用户执行（WebShell 包装器）
    escalatedUser: str = ""

    @classmethod
    def of(cls, s) -> "ShellOut":
        return cls(
            id=s.id, hostId=s.host_id, type=s.type, url=s.url, pass_=s.pwd,
            encoder=s.encoder, alive=s.alive, latency=s.latency,
            lastBeat=beat_text(s.last_beat_at, s.alive), hostname=s.hostname,
            privilege=s.privilege, stable=s.stable, kind=getattr(s, "kind", "") or "",
            platform=getattr(s, "platform", "") or "",
            escalatedUser=getattr(s, "escalated_user", "") or "",
        )


class ShellIn(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    projectId: str = ""
    #: 可选：归属主机。留空时由后端按 URL 中的主机地址自动匹配/登记（与反弹回连同策略）
    hostId: str = ""
    type: str = "PHP 一句话马"
    url: str
    pass_: str = Field(default="", alias="pass")
    encoder: str = "base64"
    autoCollect: bool = True
    #: 驱动类型（'' = HTTP 马；'reverse' = 反弹 Shell 通道）
    kind: str = ""
    note: str = ""


class SshIn(BaseModel):
    """SSH 会话纳管入参（A7）。host / username 必填，缺失即校验失败。

    私钥认证为 SshSession 能力，但本期 API 不持久化私钥路径/口令
    （Shell 模型无相应列）；如需临时用私钥可经 keyPath/keyPassphrase 传入，
    仅用于当次连接测试，不落库。
    """

    model_config = ConfigDict(populate_by_name=True)

    projectId: str = ""
    hostId: str = ""          # 可选：显式绑定主机（须属于本项目）
    host: str                  # SSH 目标 IP / 主机名（必填）
    port: int = 22
    username: str              # 登录用户名（必填）
    password: str = ""
    keyPath: str = ""          # 可选：私钥路径（不持久化）
    keyPassphrase: str = ""    # 可选：私钥口令（不持久化）
    platform: str = ""         # 可选：显式平台（'' 则由 uname 探测）
    autoHost: bool = True      # 主机不存在时自动创建
    autoCollect: bool = True   # 连接成功后自动回传基础信息
