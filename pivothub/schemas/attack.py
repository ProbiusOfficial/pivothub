"""攻击机网络契约（GET/PUT /api/attack）。

字段：{ip, segment, iface, note}，默认值来自 data/meta.json 基线。
"""

from __future__ import annotations

from pydantic import BaseModel, field_validator


class AttackOut(BaseModel):
    ip: str = "192.0.2.10"
    segment: str = "192.0.2.0/24"
    iface: str = "tun0"
    note: str = ""


class AttackIn(BaseModel):
    ip: str
    segment: str = ""
    iface: str = ""
    note: str = ""

    @field_validator("ip")
    @classmethod
    def _check_ip(cls, v: str) -> str:
        import re

        v = (v or "").strip()
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v):
            raise ValueError("攻击机 IP 格式不合法")
        if not all(0 <= int(x) <= 255 for x in v.split(".")):
            raise ValueError("攻击机 IP 超出范围")
        return v
