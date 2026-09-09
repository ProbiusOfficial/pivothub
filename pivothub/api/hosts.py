"""主机：登记 / 扫描导入 / 移除 / 拓扑拖拽位置持久化。"""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..config import DEFAULT_PROJECT_ID
from ..db import get_db
from ..schemas.common import rid
from ..models import Credential, Flag, Host, ProxyLink, Shell, TimelineEvent
from ..schemas import HostIn, HostOut, PositionIn, ScanImportIn
from ..service import add_event
from ..ws import manager
from .deps import get_project

router = APIRouter()

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def valid_ip(ip: str) -> bool:
    if not IP_RE.match(ip):
        return False
    return all(0 <= int(x) <= 255 for x in ip.split("."))


def _normalize_services(v) -> list[str]:
    if isinstance(v, str):
        return [x.strip() for x in v.split(",") if x.strip()]
    return list(v or [])


def _seg_of(ip: str) -> str:
    parts = ip.split(".")
    return ".".join(parts[:3]) + ".0/24"


def _layer_of(segment: str, known: dict[str, str]) -> str:
    return known.get(segment, "L1")


def _ifaces_of(form) -> list[dict]:
    """入参网卡规范化：显式 ifaces 优先，否则按主 IP 造一块网卡。"""
    items = []
    for it in (form.ifaces or []):
        ip = str(it.get("ip") or "").strip()
        if not ip:
            continue
        items.append({
            "iface": str(it.get("iface") or "eth0"),
            "ip": ip,
            "segment": str(it.get("segment") or _seg_of(ip)),
        })
    if not items and form.ip:
        items.append({"iface": "eth0", "ip": form.ip, "segment": form.segment or _seg_of(form.ip)})
    return items


@router.post("/hosts", response_model=HostOut)
def add_host(form: HostIn, db: Session = Depends(get_db)):
    if not valid_ip(form.ip):
        raise HTTPException(400, "IP 格式不合法")
    project = get_project(db, form.projectId or DEFAULT_PROJECT_ID)
    if db.query(Host).filter(Host.project_id == project.id, Host.ip == form.ip).first():
        raise HTTPException(409, f"主机已存在: {form.ip}")
    seg = form.segment or _seg_of(form.ip)
    h = Host(
        id=rid("h"), project_id=project.id, ip=form.ip, hostname=form.hostname,
        os=form.os, layer=form.layer, segment=seg, privilege=form.privilege,
        owned=form.owned, services=_normalize_services(form.services),
        note=form.note, discovery="手动登记", ifaces=_ifaces_of(form),
    )
    db.add(h)
    add_event(db, project.id, "host", f"登记主机 {h.ip}", host_id=h.id, detail=h.note or "")
    db.commit()
    out = HostOut.of(h)
    manager.push("host.found", host=out.model_dump())
    return out


@router.post("/hosts/import")
def import_scan(form: ScanImportIn, db: Session = Depends(get_db)):
    """解析 nmap 风格扫描结果：`IP\t端口,端口` 每行一条。"""
    project = get_project(db, form.projectId or DEFAULT_PROJECT_ID)
    meta_layers = {
        "192.168.100.0/24": "L1", "10.85.101.0/24": "L2", "172.56.102.0/24": "L3",
        "192.0.2.0/24": "VPN",
    }
    added, skipped = 0, 0
    seen: set[str] = set()
    for line in str(form.text).splitlines():
        m = line.strip().split()
        if not m or not IP_RE.match(m[0]):
            continue
        if m[0] in seen or db.query(Host).filter(
            Host.project_id == project.id, Host.ip == m[0]
        ).first():
            seen.add(m[0])
            skipped += 1
            continue
        seen.add(m[0])
        seg = _seg_of(m[0])
        ports = [int(x) for x in (m[1] if len(m) > 1 else "").split(",") if x.strip().isdigit()]
        h = Host(
            id=rid("h"), project_id=project.id, ip=m[0], hostname="", os="未知（待指纹识别）",
            layer=_layer_of(seg, meta_layers), segment=seg, privilege="", owned=False,
            ports=ports, services=[], note="扫描导入", discovery="经代理扫描",
            ifaces=[{"iface": "eth0", "ip": m[0], "segment": seg}],
        )
        db.add(h)
        added += 1
    if added:
        add_event(db, project.id, "host", f"导入扫描结果，新增 {added} 台主机",
                  detail="来源：nmap grepable / 内嵌扫描器")
    db.commit()
    return {"added": added, "skipped": skipped}


@router.patch("/hosts/{host_id}/position", response_model=HostOut)
def save_position(host_id: str, pos: PositionIn, db: Session = Depends(get_db)):
    """拓扑节点拖拽位置持久化（完成标准：拖拽位置从 SQLite 恢复）。"""
    h = db.get(Host, host_id)
    if not h:
        raise HTTPException(404, "主机不存在")
    h.pos_x, h.pos_y = pos.x, pos.y
    db.commit()
    return HostOut.of(h)


@router.delete("/hosts/{host_id}")
def remove_host(host_id: str, db: Session = Depends(get_db)):
    """移除资产：连带清理挂在该主机上的会话 / 链路 / 凭据 / Flag。

    FK 已开启（PRAGMA foreign_keys=ON），所以必须先解绑时间线、再删依赖记录，最后删主机；
    历史时间线是复盘依据，只解绑 host_id，不删除事件本身。
    """
    h = db.get(Host, host_id)
    if not h:
        raise HTTPException(404, "主机不存在")
    if h.is_local:
        raise HTTPException(400, "本机节点（攻击机）不能移除")
    project_id, ip = h.project_id, h.ip

    # 1) 先停链路并删除记录（逐层结束进程需要借主机上的存活 Shell，必须在删会话之前做；
    #    只停不删会留下指向已删主机的孤儿链路，拓扑上仍会显示）
    links = db.query(ProxyLink).filter(
        ProxyLink.project_id == project_id,
        (ProxyLink.from_host_id == host_id) | (ProxyLink.to_host_id == host_id),
    ).all()
    if links:
        from .links import purge_link  # 局部导入：links 路由依赖 hosts 的 valid_ip

        for l in list(links):
            try:
                purge_link(db, l.id)
            except Exception:  # 进程清理尽力而为，不能因此删不掉资产
                db.rollback()

    # 2) 会话：先关闭进程内反弹通道（含原始推送订阅），再删记录
    from .shells import close_channel

    shells = db.query(Shell).filter(Shell.host_id == host_id).all()
    for s in shells:
        close_channel(s.id)
        db.delete(s)

    # 3) 凭据 / Flag 随主机一并移除
    creds = db.query(Credential).filter(Credential.host_id == host_id).all()
    flags = db.query(Flag).filter(Flag.host_id == host_id).all()
    for row in creds + flags:
        db.delete(row)

    # 4) 显式落子表删除，再解绑时间线、最后删主机（模型间没有 relationship，
    #    SQLAlchemy 不会自动推导删除顺序，必须自己保证 hosts 最后删）
    db.flush()
    db.query(TimelineEvent).filter(TimelineEvent.host_id == host_id).update(
        {"host_id": None}, synchronize_session=False
    )
    db.flush()

    db.delete(h)
    add_event(db, project_id, "host", f"移除资产 {ip}",
              detail=f"连带清理 {len(shells)} 个会话 / {len(links)} 条链路 / "
                     f"{len(creds)} 条凭据 / {len(flags)} 个 Flag")
    db.commit()
    manager.push("host.removed", hostId=host_id, projectId=project_id,
                 shellIds=[s.id for s in shells])
    return {
        "deleted": host_id, "ip": ip,
        "shells": len(shells), "links": len(links),
        "creds": len(creds), "flags": len(flags),
    }
