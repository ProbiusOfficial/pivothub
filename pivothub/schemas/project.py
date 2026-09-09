from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class ProjectBrief(BaseModel):
    id: str
    name: str


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    startAt: str
    durationSec: int
    note: str = ""
