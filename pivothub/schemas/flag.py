from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from .common import hhmm


class FlagOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    hostId: str
    stage: str
    value: str
    submitted: bool = False
    time: str = ""

    @classmethod
    def of(cls, f) -> "FlagOut":
        return cls(
            id=f.id, hostId=f.host_id, stage=f.stage, value=f.value,
            submitted=f.submitted, time=hhmm(f.created_at),
        )


class FlagIn(BaseModel):
    projectId: str = ""
    hostId: str
    stage: str = "L1 入口"
    value: str
    submitted: bool = False
