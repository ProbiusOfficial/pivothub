"""时间线服务：自动事件统一入口（同时广播 timeline.push）。"""

from __future__ import annotations

from sqlalchemy.orm import Session

from ..db import now
from ..schemas.common import rid
from ..models import TimelineEvent
from ..schemas import TimelineOut
from ..ws import manager


def add_event(
    db: Session,
    project_id: str,
    kind: str,
    title: str,
    host_id: str | None = None,
    detail: str = "",
    cmd: str = "",
    markdown: str = "",
    push: bool = True,
) -> TimelineEvent:
    ev = TimelineEvent(
        id=rid("t"), project_id=project_id, ts=now(), kind=kind, title=title,
        host_id=host_id, detail=detail, cmd=cmd, markdown=markdown,
    )
    db.add(ev)
    db.flush()
    if push:
        manager.push("timeline.push", event=TimelineOut.of(ev).model_dump())
    return ev


def segments_of(hosts: list) -> list[dict]:
    """按主机聚合网段分区（契约字段 segment/color/layer/count）。

    配色与顺序基线来自 data/meta.json → segmentColors（如 VPN / L1 / L2 / L3）。
    攻击端本机所在网段单列为 VPN 分区（其主机 layer 是 LOCAL，但分区 layer 是 VPN），
    未登记网段按出现顺序补默认色。
    """
    from ..db import load_meta

    palette = {}
    order = []
    try:
        for s in load_meta().get("segmentColors", []):
            palette[s["segment"]] = s["color"]
            order.append(s["segment"])
    except Exception:
        pass

    counts: dict[str, dict] = {}
    for h in hosts:
        seg = h.segment or "未知"
        if seg == "LOCAL":
            continue  # 老数据的伪网段不列
        if h.is_local:
            layer = "VPN" if seg != "未知" else "LOCAL"
        else:
            layer = h.layer if seg != "未知" else "LOCAL"
        if seg not in counts:
            counts[seg] = {
                "segment": seg,
                "color": palette.get(seg, "#3ba7ff"),
                "layer": layer,
                "count": 0,
            }
            if seg not in order:
                order.append(seg)
        counts[seg]["count"] += 1

    result = [counts[s] for s in order if s in counts]
    result += [v for k, v in counts.items() if k not in order]
    # 未知/LOCAL 分区排在最后，与原型观感一致
    result.sort(key=lambda x: 1 if x["layer"] == "LOCAL" else 0)
    return result
