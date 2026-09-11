from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from .common import hhmm_utc


class CredOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    hostId: str
    username: str
    secret: str
    kind: str
    services: list[str] = []
    reuse: bool = True
    source: str = "手动登记"
    time: str = ""

    @classmethod
    def of(cls, c) -> "CredOut":
        return cls(
            id=c.id, hostId=c.host_id, username=c.username, secret=c.secret,
            kind=c.kind, services=c.services, reuse=c.reuse, source=c.source,
            time=hhmm_utc(c.created_at),
        )


class CredIn(BaseModel):
    projectId: str = ""
    hostId: str
    username: str
    secret: str
    kind: str = "密码"
    services: list[str] | str = []
    source: str = "手动登记"
