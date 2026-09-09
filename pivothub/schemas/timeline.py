from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from .common import hhmm


class TimelineOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    time: str = ""
    kind: str
    title: str
    hostId: str | None = None
    detail: str = ""
    cmd: str = ""
    markdown: str = ""

    @classmethod
    def of(cls, t) -> "TimelineOut":
        return cls(
            id=t.id, time=hhmm(t.ts), kind=t.kind, title=t.title,
            hostId=t.host_id, detail=t.detail, cmd=t.cmd, markdown=t.markdown,
        )


class NoteIn(BaseModel):
    projectId: str = ""
    title: str
    hostId: str | None = None
    cmd: str = ""
    markdown: str = ""
